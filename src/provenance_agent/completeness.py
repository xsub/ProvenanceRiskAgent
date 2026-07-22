from __future__ import annotations

from typing import Any

from .contracts import CompletenessAssessment, Contradiction
from .normalization import (
    ALBS_GRAPH_SCHEMA,
    COMBINED_SCHEMA,
    EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA,
    EDGP_GRAPH_SNAPSHOT_SCHEMA,
    EDGP_RPM_ALBS_PROVENANCE_SCHEMA,
    SIMPLE_SCHEMA,
)


def assess_completeness(
    export: dict[str, Any],
    contradictions: list[Contradiction],
) -> CompletenessAssessment:
    required = {"artifact_identity", "source_coverage"}
    present: set[str] = set()
    artifact = export.get("artifact") or {}
    if artifact.get("name"):
        present.add("artifact_identity")
    if export.get("source_schema"):
        present.add("source_coverage")

    _collect_source_coverage(export, required, present)
    missing = sorted(required - present)
    contradictory = sorted({item.category for item in contradictions})
    score = round(100 * len(present & required) / len(required)) if required else 100
    return CompletenessAssessment(
        score=score,
        required_categories=sorted(required),
        present_categories=sorted(present & required),
        missing_categories=missing,
        contradictory_categories=contradictory,
    )


def _collect_source_coverage(
    export: dict[str, Any],
    required: set[str],
    present: set[str],
) -> None:
    schema = export["source_schema"]
    source = export["source"]
    if schema == COMBINED_SCHEMA:
        for child in source.get("sources", []):
            _collect_source_coverage(
                {"source_schema": child.get("schema"), "source": child},
                required,
                present,
            )
        return
    if schema == SIMPLE_SCHEMA:
        required.update({"build_identity", "signature", "policy", "vulnerability_coverage"})
        if source.get("build", {}).get("builder"):
            present.add("build_identity")
        if "signed" in source.get("build", {}):
            present.add("signature")
        if isinstance(source.get("policy"), dict):
            present.add("policy")
        if isinstance(source.get("vulnerabilities"), list):
            present.add("vulnerability_coverage")
        return
    if schema == ALBS_GRAPH_SCHEMA:
        required.update(
            {"build_provenance", "artifact_integrity", "source_integrity", "signature", "release"}
        )
        nodes = source.get("nodes") or []
        edges = source.get("edges") or []
        node_by_id = {str(node.get("id")): node for node in nodes}
        binary_ids = {
            str(node.get("id")) for node in nodes if node.get("type") == "binary_rpm"
        }
        if binary_ids and any(
            edge.get("relation") == "produces" and str(edge.get("target")) in binary_ids
            for edge in edges
        ):
            present.add("build_provenance")
        if any(
            edge.get("relation") == "released_to" and str(edge.get("source")) in binary_ids
            for edge in edges
        ):
            present.add("release")
        if any(
            edge.get("relation") == "signed_as" and str(edge.get("source")) in binary_ids
            for edge in edges
        ):
            present.add("signature")
        if _has_cas_edge(edges, node_by_id, binary_ids):
            present.add("artifact_integrity")
        if _has_source_cas(nodes, edges, node_by_id, binary_ids):
            present.add("source_integrity")
        return
    if schema == EDGP_RPM_ALBS_PROVENANCE_SCHEMA:
        required.update({"dependency_mapping", "artifact_integrity", "build_identity", "release"})
        summary = source.get("summary")
        matches = source.get("matches") or []
        if isinstance(summary, dict) and "installedPackages" in summary:
            present.add("dependency_mapping")
        if matches and all((item.get("albsArtifact") or {}).get("casHash") for item in matches):
            present.add("artifact_integrity")
        if matches and all(str(item.get("buildId") or "") not in {"", "unknown"} for item in matches):
            present.add("build_identity")
        if matches and all(str(item.get("releaseId") or "") for item in matches):
            present.add("release")
        return
    if schema == EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA:
        required.update({"artifact_inventory", "artifact_integrity", "build_identity"})
        items = source.get("items") or []
        if items:
            present.add("artifact_inventory")
        if items and all(item.get("casHash") for item in items):
            present.add("artifact_integrity")
        if items and all(item.get("buildTaskId") for item in items):
            present.add("build_identity")
        return
    if schema == EDGP_GRAPH_SNAPSHOT_SCHEMA:
        required.update({"dependency_graph", "graph_integrity"})
        nodes = source.get("nodes") or []
        edges = source.get("edges") or []
        if nodes:
            present.add("dependency_graph")
        node_ids = {node.get("id") for node in nodes}
        stats = source.get("stats") or {}
        if (
            stats.get("nodes") == len(nodes)
            and stats.get("edges") == len(edges)
            and all(edge.get("source") in node_ids and edge.get("target") in node_ids for edge in edges)
        ):
            present.add("graph_integrity")


def _has_cas_edge(
    edges: list[dict[str, Any]],
    node_by_id: dict[str, dict[str, Any]],
    binary_ids: set[str],
) -> bool:
    for edge in edges:
        target = node_by_id.get(str(edge.get("target")), {})
        metadata = target.get("metadata") or {}
        if (
            edge.get("relation") == "authenticated_by"
            and str(edge.get("source")) in binary_ids
            and target.get("type") == "cas_attestation"
            and (
                metadata.get("cas_hash")
                or metadata.get("evidence_present")
                or metadata.get("albs_authenticated")
            )
        ):
            return True
    return False


def _has_source_cas(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    node_by_id: dict[str, dict[str, Any]],
    binary_ids: set[str],
) -> bool:
    build_ids = {
        str(edge.get("source"))
        for edge in edges
        if edge.get("relation") == "produces" and str(edge.get("target")) in binary_ids
    }
    source_cas_ids = {
        str(edge.get("source"))
        for edge in edges
        if edge.get("relation") == "built_by" and str(edge.get("target")) in build_ids
    }
    authenticated_targets = {
        str(edge.get("target"))
        for edge in edges
        if edge.get("relation") == "authenticated_by"
    }
    return any(
        node_by_id.get(node_id, {}).get("type") == "cas_attestation"
        and node_id in authenticated_targets
        for node_id in source_cas_ids
    ) and bool(nodes)
