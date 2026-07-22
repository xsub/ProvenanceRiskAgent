from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .contracts import CompletenessAssessment, Contradiction
from .normalization import (
    ALBS_GRAPH_SCHEMA,
    COMBINED_SCHEMA,
    EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA,
    EDGP_GRAPH_SNAPSHOT_SCHEMA,
    EDGP_RPM_ALBS_PROVENANCE_SCHEMA,
    EDGP_PUBLIC_ADVISORY_FEED_SCHEMA,
    SIMPLE_SCHEMA,
)


def assess_completeness(
    export: dict[str, Any],
    contradictions: list[Contradiction],
) -> CompletenessAssessment:
    required = {"artifact_identity", "security_context", "source_coverage"}
    present: set[str] = set()
    artifact = export.get("artifact") or {}
    if artifact.get("name"):
        present.add("artifact_identity")
    if export.get("source_schema"):
        present.add("source_coverage")

    _collect_source_coverage(export, required, present, artifact=artifact)
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
    *,
    artifact: dict[str, Any],
) -> None:
    schema = export["source_schema"]
    source = export["source"]
    if schema == COMBINED_SCHEMA:
        for child in source.get("sources", []):
            _collect_source_coverage(
                {"source_schema": child.get("schema"), "source": child},
                required,
                present,
                artifact=artifact,
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
            present.add("security_context")
        return
    if schema == ALBS_GRAPH_SCHEMA:
        required.update(
            {
                "artifact_integrity",
                "build_provenance",
                "errata_coverage",
                "release",
                "sbom",
                "signature",
                "source_integrity",
            }
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
        if _has_relation_to_type(
            edges,
            node_by_id,
            binary_ids,
            relation="described_by",
            target_type="sbom",
        ):
            present.add("sbom")
        if _has_errata_coverage(edges, node_by_id, binary_ids):
            present.add("errata_coverage")
        if {"sbom", "errata_coverage"} <= present:
            present.add("security_context")
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
        return
    if schema == EDGP_PUBLIC_ADVISORY_FEED_SCHEMA:
        required.update({"vulnerability_coverage", "advisory_freshness"})
        query = source.get("query") or {}
        matches_artifact = (
            str(query.get("package") or "") == str(artifact.get("name") or "")
            and str(query.get("version") or "") == str(artifact.get("version") or "")
        )
        if (
            query.get("status") == "complete"
            and not query.get("truncated", False)
            and matches_artifact
        ):
            present.add("vulnerability_coverage")
        if matches_artifact and _advisory_query_is_fresh(query):
            present.add("advisory_freshness")


def _advisory_query_is_fresh(query: dict[str, Any]) -> bool:
    if not query.get("fresh") or query.get("status") != "complete":
        return False
    try:
        retrieved_at = datetime.fromisoformat(str(query["retrieved_at"]))
        if retrieved_at.tzinfo is None:
            return False
        age = (datetime.now(UTC) - retrieved_at.astimezone(UTC)).total_seconds()
        return 0 <= age <= int(query["max_age_seconds"])
    except (KeyError, TypeError, ValueError):
        return False


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


def _has_relation_to_type(
    edges: list[dict[str, Any]],
    node_by_id: dict[str, dict[str, Any]],
    source_ids: set[str],
    *,
    relation: str,
    target_type: str,
) -> bool:
    covered = {
        str(edge.get("source"))
        for edge in edges
        if edge.get("relation") == relation
        and str(edge.get("source")) in source_ids
        and node_by_id.get(str(edge.get("target")), {}).get("type") == target_type
    }
    return bool(source_ids) and covered == source_ids


def _has_errata_coverage(
    edges: list[dict[str, Any]],
    node_by_id: dict[str, dict[str, Any]],
    binary_ids: set[str],
) -> bool:
    covered = {
        str(edge.get("source"))
        for edge in edges
        if edge.get("relation") in {"affected_by", "fixes"}
        and str(edge.get("source")) in binary_ids
    }
    covered.update(
        node_id
        for node_id in binary_ids
        if (node_by_id.get(node_id, {}).get("metadata") or {}).get("errata_status")
        == "confirmed_clean"
    )
    return bool(binary_ids) and covered == binary_ids
