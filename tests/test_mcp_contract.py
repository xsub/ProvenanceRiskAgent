"""Contract tests for LangChain and MCP tool surfaces.

Locks assessment-aware tool names, verifies the exposed MCP capability set,
and checks REST parity plus bounded dependency-impact reporting.
"""

import asyncio

from fastapi.testclient import TestClient

from provenance_agent.api import create_app
from provenance_agent.mcp_server import mcp
from provenance_agent.tools import EVIDENCE_TOOLS, OBSERVATION_TOOLS


def test_langchain_tools_name_their_assessment_boundary():
    assert {item.name for item in EVIDENCE_TOOLS} == {
        "evaluate_builder_policy",
        "validate_signature_evidence",
        "evaluate_reproducibility_policy",
        "interpret_vulnerability_assessment",
        "validate_albs_provenance_assessment",
        "validate_edgp_provenance_assessment",
        "validate_edgp_inventory_assessment",
        "validate_edgp_graph_assessment",
        "derive_edgp_blast_radius_finding",
    }
    assert {item.name for item in OBSERVATION_TOOLS} == {
        "summarize_assessment_coverage"
    }


def test_mcp_exposes_planned_normalized_capabilities():
    tools = asyncio.run(mcp.list_tools())
    names = {item.name for item in tools}

    assert names == {
        "resolve_artifact_identity",
        "get_build_provenance_assessment",
        "get_signature_integrity_assessment",
        "get_direct_dependencies",
        "get_reverse_dependencies",
        "calculate_blast_radius",
        "get_vulnerability_assessment",
        "evaluate_policy",
        "evaluate_artifact_risk",
        "evaluate_live_artifact",
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
