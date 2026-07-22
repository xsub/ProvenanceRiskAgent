import asyncio

from fastapi.testclient import TestClient

from provenance_agent.api import create_app
from provenance_agent.mcp_server import mcp


def test_mcp_exposes_planned_normalized_capabilities():
    tools = asyncio.run(mcp.list_tools())
    names = {item.name for item in tools}

    assert names == {
        "resolve_artifact_identity",
        "inspect_build_provenance",
        "verify_signature_or_integrity",
        "query_dependencies",
        "query_reverse_dependencies",
        "calculate_blast_radius",
        "retrieve_vulnerabilities",
        "evaluate_policy",
        "evaluate_artifact_risk",
        "explain_decision",
    }


def test_mcp_risk_result_matches_deterministic_rest_fields(tmp_path):
    _, payload = asyncio.run(
        mcp.call_tool(
            "evaluate_artifact_risk",
            {"input_path": "examples/albs-edgp-risk-case.json"},
        )
    )
    rest = TestClient(create_app(db_path=tmp_path / "rest.sqlite3")).post(
        "/api/v1/evaluate",
        json={"input_path": "examples/albs-edgp-risk-case.json"},
    ).json()

    assert payload["decision_state"] == rest["decision_state"]
    assert payload["risk"] == rest["risk"]
    assert payload["completeness"] == rest["completeness"]
    assert payload["confidence"] == rest["confidence"]
    assert payload["policy_evaluation"] == rest["policy_evaluation"]
    assert payload["evidence"]


def test_mcp_blast_radius_is_bounded_and_traceable():
    _, payload = asyncio.run(
        mcp.call_tool(
            "calculate_blast_radius",
            {
                "input_path": "eval/golden/large-blast-radius.json",
                "limit": 6,
            },
        )
    )

    assert payload["count"] == 6
    assert payload["truncated"] is True
