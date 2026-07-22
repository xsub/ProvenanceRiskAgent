"""Application-service integration tests with persistent state.

Covers investigation traces, clean and combined assessments, human review,
transient retry recording, and requested policy-profile application.
"""

from provenance_agent.contracts import InvestigationRequest, ReviewDecision
from provenance_agent.service import InvestigationService
from provenance_agent.store import InvestigationStore


def test_service_persists_suspicious_investigation_trace(tmp_path):
    store = InvestigationStore(tmp_path / "investigations.sqlite3")
    service = InvestigationService(store)

    result = service.run_investigation(
        InvestigationRequest(input_path="examples/suspicious-build.json")
    )

    assert result.status == "succeeded"
    assert result.decision_state == "REVIEW"
    assert result.risk_score == 93
    assert result.reliability.completeness_score == 100

    summary = service.get_investigation(result.investigation_id)
    assert summary is not None
    assert summary.result is not None
    assert summary.result.decision_state == "REVIEW"

    event_types = {event.event_type for event in service.list_events(result.investigation_id)}
    assert "investigation_started" in event_types
    assert "risk_scored" in event_types
    assert "reliability_assessed" in event_types
    assert "verdict_produced" in event_types

    evidence = service.list_evidence(result.investigation_id)
    assert {record.kind for record in evidence} == {"risk_evidence", "verified_fact"}
    assert any(record.code == "SIGNATURE_MISSING" for record in evidence)


def test_service_allows_clean_complete_fixture(tmp_path):
    service = InvestigationService(InvestigationStore(tmp_path / "clean.sqlite3"))

    result = service.run_investigation(
        InvestigationRequest(input_path="examples/clean-build.json")
    )

    assert result.status == "succeeded"
    assert result.decision_state == "ALLOW"
    assert result.risk_score == 0
    assert result.risk_level == "none"
    assert result.reliability.confidence_score == 75


def test_service_combined_fixture_records_albs_and_edgp_evidence(tmp_path):
    service = InvestigationService(InvestigationStore(tmp_path / "combined.sqlite3"))

    result = service.run_investigation(
        InvestigationRequest(input_path="examples/albs-edgp-risk-case.json")
    )

    codes = {record.code for record in service.list_evidence(result.investigation_id)}

    assert result.decision_state == "REVIEW"
    assert result.risk_score == 85
    assert "ALBS_SIGNATURE_MISSING" in codes
    assert "EDGP_RPM_ALBS_UNMATCHED_PACKAGES" in codes


def test_service_persists_and_resumes_human_review(tmp_path):
    database = tmp_path / "review.sqlite3"
    first_service = InvestigationService(InvestigationStore(database))
    waiting = first_service.run_investigation(
        InvestigationRequest(
            input_path="examples/suspicious-build.json",
            pause_before_review=True,
        )
    )

    assert waiting.status == "awaiting_review"
    assert waiting.review_request is not None
    assert waiting.review_request.evidence_ids

    resumed_service = InvestigationService(InvestigationStore(database))
    completed = resumed_service.resume_investigation(
        waiting.investigation_id,
        ReviewDecision(
            decision="DENY",
            reviewer="pytest",
            rationale="High deterministic risk confirmed.",
        ),
    )

    assert completed.status == "succeeded"
    assert completed.proposed_decision == "REVIEW"
    assert completed.decision_state == "DENY"
    assert completed.review_decision is not None
    records = resumed_service.list_evidence(waiting.investigation_id)
    assert len(records) == len({record.evidence_id for record in records})
    event_types = [event.event_type for event in completed.events]
    assert "review_requested" in event_types
    assert "review_completed" in event_types


def test_service_persists_transient_retry_attempt(tmp_path, monkeypatch):
    from provenance_agent import workflow

    original = workflow.load_export
    calls = 0

    def flaky_load(path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("temporary adapter timeout")
        return original(path)

    monkeypatch.setattr(workflow, "load_export", flaky_load)
    service = InvestigationService(InvestigationStore(tmp_path / "retry.sqlite3"))
    result = service.run_investigation(
        InvestigationRequest(input_path="examples/clean-build.json")
    )

    assert result.status == "succeeded"
    retries = [
        event
        for event in result.events
        if event.event_type == "execution_attempt_failed"
    ]
    assert calls == 2
    assert len(retries) == 1
    assert retries[0].details["retrying"] is True


def test_service_applies_requested_versioned_policy_profile(tmp_path):
    service = InvestigationService(InvestigationStore(tmp_path / "strict.sqlite3"))

    result = service.run_investigation(
        InvestigationRequest(
            input_path="examples/clean-build.json",
            policy_profile="enterprise-linux-strict@1.0.0",
        )
    )

    assert result.policy_evaluation is not None
    assert result.policy_evaluation.profile == "enterprise-linux-strict@1.0.0"
    assert result.policy_profile["version"] == "1.0.0"
    assert result.decision_state == "REVIEW"
