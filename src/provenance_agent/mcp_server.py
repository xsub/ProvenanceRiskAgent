from __future__ import annotations

from collections import deque
from typing import Any

from mcp.server.fastmcp import FastMCP

from .normalization import EDGP_GRAPH_SNAPSHOT_SCHEMA
from .repository import load_export
from .tools import expand_tool_exports
from .workflow import build_graph


mcp = FastMCP(
    "Enterprise Linux Provenance Risk Agent",
    instructions=(
        "Use these tools to investigate supplied ALBS and EDGP JSON exports. "
        "Risk, completeness, confidence, policy, and decision fields are "
        "deterministic; explanations may only summarize cited evidence."
    ),
)


@mcp.tool()
def resolve_artifact_identity(input_path: str) -> dict[str, Any]:
    """Resolve normalized artifact identity and source schema from an export."""
    export = load_export(input_path)
    return {
        "artifact": export["artifact"],
        "source_schema": export["source_schema"],
        "source_path": export["source_path"],
    }


@mcp.tool()
def inspect_build_provenance(input_path: str) -> dict[str, Any]:
    """Return build and provenance facts with stable evidence identifiers."""
    result = _analyze(input_path)
    records = [
        item
        for item in result.get("observations", []) + result.get("evidence", [])
        if item["code"].startswith("ALBS_")
        or item["code"] in {"BUILDER_NOT_ALLOWED", "SIMPLE_EXPORT_SCOPE"}
    ]
    return {"artifact": result["export"]["artifact"], "records": records}


@mcp.tool()
def verify_signature_or_integrity(input_path: str) -> dict[str, Any]:
    """Return signature and CAS/integrity findings from deterministic checks."""
    result = _analyze(input_path)
    records = [
        item
        for item in result.get("observations", []) + result.get("evidence", [])
        if any(token in item["code"] for token in ("SIGNATURE", "CAS", "INTEGRITY"))
    ]
    return {"artifact": result["export"]["artifact"], "records": records}


@mcp.tool()
def query_dependencies(input_path: str) -> dict[str, Any]:
    """Return direct dependency node identifiers from an EDGP graph snapshot."""
    graph = _edgp_graph(input_path)
    root = str(graph.get("root") or "")
    dependencies = sorted(
        {
            str(edge.get("target"))
            for edge in graph.get("edges", [])
            if str(edge.get("source")) == root
        }
    )
    return {"root": root, "dependencies": dependencies, "count": len(dependencies)}


@mcp.tool()
def query_reverse_dependencies(input_path: str) -> dict[str, Any]:
    """Return direct reverse dependency node identifiers for an EDGP root."""
    graph = _edgp_graph(input_path)
    root = str(graph.get("root") or "")
    dependents = sorted(
        {
            str(edge.get("source"))
            for edge in graph.get("edges", [])
            if str(edge.get("target")) == root
        }
    )
    return {"root": root, "dependents": dependents, "count": len(dependents)}


@mcp.tool()
def calculate_blast_radius(input_path: str, limit: int = 10_000) -> dict[str, Any]:
    """Calculate bounded transitive reverse-dependency impact for an EDGP root."""
    if limit < 1 or limit > 100_000:
        raise ValueError("limit must be between 1 and 100000")
    graph = _edgp_graph(input_path)
    root = str(graph.get("root") or "")
    incoming: dict[str, list[str]] = {}
    for edge in graph.get("edges", []):
        incoming.setdefault(str(edge.get("target")), []).append(
            str(edge.get("source"))
        )
    queue = deque([root])
    visited = {root}
    dependents: list[str] = []
    while queue and len(dependents) < limit:
        current = queue.popleft()
        for dependent in incoming.get(current, []):
            if dependent in visited:
                continue
            visited.add(dependent)
            dependents.append(dependent)
            queue.append(dependent)
            if len(dependents) >= limit:
                break
    return {
        "root": root,
        "transitive_dependents": sorted(dependents),
        "count": len(dependents),
        "truncated": bool(queue),
        "limit": limit,
    }


@mcp.tool()
def retrieve_vulnerabilities(input_path: str) -> dict[str, Any]:
    """Return deterministic vulnerability evidence without model-generated facts."""
    result = _analyze(input_path)
    records = [
        item
        for item in result.get("evidence", [])
        if "VULNERABILITY" in item["code"]
    ]
    return {"artifact": result["export"]["artifact"], "records": records}


@mcp.tool()
def evaluate_policy(input_path: str) -> dict[str, Any]:
    """Evaluate explicit policy rules over normalized evidence."""
    result = _analyze(input_path)
    return {
        "artifact": result["export"]["artifact"],
        "policy_evaluation": result["policy_evaluation"],
        "proposed_decision": result["proposed_decision"],
    }


@mcp.tool()
def evaluate_artifact_risk(input_path: str) -> dict[str, Any]:
    """Return the complete deterministic risk result used by REST and CLI."""
    return _result_payload(_analyze(input_path))


@mcp.tool()
def explain_decision(input_path: str) -> dict[str, Any]:
    """Explain a deterministic verdict using only collected evidence."""
    result = _analyze(input_path)
    return {
        "artifact": result["export"]["artifact"],
        "decision_state": result["decision_state"],
        "evidence_ids": [
            item["evidence_id"]
            for item in result.get("evidence", [])
            if item.get("evidence_id")
        ],
        "explanation": result["explanation"],
    }


def run(transport: str = "stdio") -> None:
    if transport not in {"stdio", "sse", "streamable-http"}:
        raise ValueError(f"Unsupported MCP transport: {transport}")
    mcp.run(transport=transport)


def _analyze(input_path: str) -> dict[str, Any]:
    return build_graph().invoke({"input_path": input_path})


def _result_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact": result["export"]["artifact"],
        "source_schema": result["export"]["source_schema"],
        "decision_state": result["decision_state"],
        "proposed_decision": result["proposed_decision"],
        "risk": result["risk"],
        "completeness": result["completeness"],
        "confidence": result["confidence"],
        "policy_evaluation": result["policy_evaluation"],
        "contradictions": result.get("contradictions", []),
        "observations": result.get("observations", []),
        "evidence": result.get("evidence", []),
        "explanation": result["explanation"],
    }


def _edgp_graph(input_path: str) -> dict[str, Any]:
    export = load_export(input_path)
    for candidate in expand_tool_exports(export):
        if candidate["source_schema"] == EDGP_GRAPH_SNAPSHOT_SCHEMA:
            return candidate["source"]
    raise ValueError("Input does not contain an EDGP graph snapshot.")


if __name__ == "__main__":
    run()
