"""Focused tests for deterministic assessment and decision modules.

Verifies stable evidence identity, contradiction reduction, confidence impact,
cross-source mismatch handling, and fail-closed incomplete decisions.
"""

from copy import deepcopy

from provenance_agent.completeness import assess_completeness
from provenance_agent.confidence import assess_confidence
from provenance_agent.contracts import Contradiction, SourcePointer
from provenance_agent.contradictions import detect_contradictions
from provenance_agent.decision import decide
from provenance_agent.policy import evaluate_policy
from provenance_agent.repository import load_export
from provenance_agent.risk import assess_risk


def test_evidence_ids_and_source_pointers_are_stable():
    first = load_export("examples/suspicious-build.json")
    second = load_export("examples/suspicious-build.json")
    from provenance_agent.workflow import collect_evidence_node

    first_records = collect_evidence_node({"export": first})["evidence"]
    second_records = collect_evidence_node({"export": second})["evidence"]

    assert [item["evidence_id"] for item in first_records] == [
        item["evidence_id"] for item in second_records
    ]
    assert all(item["source_pointer"]["record_path"] for item in first_records)


def test_contradiction_changes_confidence_and_routes_to_review():
    export = load_export("eval/golden/contradictory-sources.json")
    contradictions = detect_contradictions(export)
    risk = assess_risk([])
    completeness = assess_completeness(export, contradictions)
    confidence = assess_confidence(
        completeness,
        contradictions,
        compatibility_fixture=False,
    )

    assert {item.code for item in contradictions} == {
        "CROSS_SOURCE_ARTIFACT_DIGEST_MISMATCH"
    }
    assert confidence.score == 75
    assert decide(
        risk=risk,
        completeness=completeness,
        confidence=confidence,
        contradictions=contradictions,
    ) == "REVIEW"


def test_critical_contradiction_reducer_is_deterministic():
    pointer = SourcePointer(
        source_system="albs",
        source_schema="albs-provenance-explorer/v1",
        source_path="fixture.json",
        record_path="nodes[0]",
    )
    contradiction = Contradiction(
        contradiction_id="ctr_test",
        code="CROSS_SOURCE_ARTIFACT_DIGEST_MISMATCH",
        category="artifact_digest",
        message="Digest mismatch.",
        severity="critical",
        values=["a", "b"],
        source_pointers=[pointer],
    )
    export = load_export("eval/golden/contradictory-sources.json")
    completeness = assess_completeness(export, [contradiction])
    confidence = assess_confidence(
        completeness,
        [contradiction],
        compatibility_fixture=False,
    )

    assert confidence.score == 75
    assert confidence.reducers == [
        "CROSS_SOURCE_ARTIFACT_DIGEST_MISMATCH: -25"
    ]


def test_single_mismatched_source_artifact_is_not_silently_skipped():
    export = load_export("eval/golden/contradictory-sources.json")
    changed = deepcopy(export)
    changed["source"]["sources"][1]["items"][0]["packageName"] = "other-name"

    codes = {item.code for item in detect_contradictions(changed)}

    assert "CROSS_SOURCE_ARTIFACT_NAME_MISMATCH" in codes


def test_zero_risk_with_missing_security_context_cannot_be_allowed():
    export = load_export("eval/golden/contradictory-sources.json")
    changed = deepcopy(export)
    albs_source = changed["source"]["sources"][0]
    binary = next(node for node in albs_source["nodes"] if node["type"] == "binary_rpm")
    binary["metadata"].pop("errata_status")
    inventory = changed["source"]["sources"][1]
    inventory["items"][0]["casHash"] = changed["artifact"]["digest"].split(":", 1)[1]
    contradictions = detect_contradictions(changed)
    risk = assess_risk([])
    completeness = assess_completeness(changed, contradictions)
    confidence = assess_confidence(
        completeness,
        contradictions,
        compatibility_fixture=False,
    )
    policy = evaluate_policy(
        risk=risk,
        completeness=completeness,
        contradictions=contradictions,
    )

    assert contradictions == []
    assert "security_context" in completeness.missing_categories
    assert "errata_coverage" in completeness.missing_categories
    assert "required-evidence" in policy.failed_rule_ids
    assert decide(
        risk=risk,
        completeness=completeness,
        confidence=confidence,
        contradictions=contradictions,
    ) == "REVIEW"
