from provenance_agent.contracts import InvestigationRequest
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
    assert result.reliability.confidence_score == 100


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
