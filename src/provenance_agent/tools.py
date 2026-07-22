from __future__ import annotations

from collections import deque
import json
from typing import Any

from langchain_core.tools import tool

from .models import Evidence, Observation, ProvenanceExport
from .normalization import (
    ALBS_GRAPH_SCHEMA,
    COMBINED_SCHEMA,
    EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA,
    EDGP_GRAPH_SNAPSHOT_SCHEMA,
    EDGP_RPM_ALBS_PROVENANCE_SCHEMA,
    NORMALIZED_SCHEMA,
    SIMPLE_SCHEMA,
)


@tool
def inspect_builder(export_json: str) -> list[dict]:
    """Check whether a simple artifact export used an allowed builder."""
    export = _loads(export_json)
    if export["source_schema"] != SIMPLE_SCHEMA:
        return []

    source = ProvenanceExport.model_validate(export["source"])
    allowed = source.policy.allowed_builders
    if allowed and source.build.builder not in allowed:
        return [_evidence(
            "BUILDER_NOT_ALLOWED",
            f"Builder '{source.build.builder}' is not in {allowed}.",
            35,
            "build.builder + policy.allowed_builders",
        )]
    return []


@tool
def inspect_signature(export_json: str) -> list[dict]:
    """Check required artifact signature evidence."""
    export = _loads(export_json)
    if export["source_schema"] == SIMPLE_SCHEMA:
        source = ProvenanceExport.model_validate(export["source"])
        if source.policy.require_signature and not source.build.signed:
            return [_evidence(
                "SIGNATURE_MISSING",
                "Policy requires a signature, but the build is unsigned.",
                40,
                "build.signed + policy.require_signature",
            )]
        return []

    if export["source_schema"] == ALBS_GRAPH_SCHEMA:
        return _inspect_albs_signatures(export["source"])

    return []


@tool
def inspect_reproducibility(export_json: str) -> list[dict]:
    """Check reproducible-build policy evidence for the simple export format."""
    export = _loads(export_json)
    if export["source_schema"] != SIMPLE_SCHEMA:
        return []

    source = ProvenanceExport.model_validate(export["source"])
    if source.policy.require_reproducible and not source.build.reproducible:
        return [_evidence(
            "NOT_REPRODUCIBLE",
            "Policy requires a reproducible build, but no match is recorded.",
            25,
            "build.reproducible + policy.require_reproducible",
        )]
    return []


@tool
def inspect_vulnerabilities(export_json: str) -> list[dict]:
    """Collect unresolved vulnerabilities or explicit affected-by graph edges."""
    export = _loads(export_json)
    if export["source_schema"] == SIMPLE_SCHEMA:
        source = ProvenanceExport.model_validate(export["source"])
        weights = {"none": 0, "low": 3, "medium": 8, "high": 18, "critical": 30}
        findings: list[dict] = []
        for index, vuln in enumerate(source.vulnerabilities):
            if not vuln.fixed:
                findings.append(_evidence(
                    "UNFIXED_VULNERABILITY",
                    f"{vuln.id} is unresolved with severity {vuln.severity}.",
                    weights[vuln.severity],
                    f"vulnerabilities[{index}]",
                ))
        return findings

    if export["source_schema"] == ALBS_GRAPH_SCHEMA:
        return _inspect_albs_vulnerabilities(export["source"])

    return []


@tool
def inspect_albs_trust_path(export_json: str) -> list[dict]:
    """Check ALBS provenance graph trust-path completeness."""
    export = _loads(export_json)
    if export["source_schema"] != ALBS_GRAPH_SCHEMA:
        return []

    graph = _albs_graph(export["source"])
    rpm_nodes = _nodes_by_type(graph, "binary_rpm")
    if not rpm_nodes:
        return [_evidence(
            "ALBS_NO_BINARY_RPMS",
            "ALBS provenance graph contains no binary RPM nodes.",
            20,
            "nodes[type=binary_rpm]",
        )]

    evidence: list[dict] = []
    missing_build = [
        node for node in rpm_nodes if not graph["incoming"][node["id"]].get("produces")
    ]
    missing_release = [
        node for node in rpm_nodes if not graph["outgoing"][node["id"]].get("released_to")
    ]
    missing_artifact_cas = [
        node for node in rpm_nodes if not _has_artifact_cas(graph, node["id"])
    ]
    missing_source_cas = [
        node for node in rpm_nodes if not _has_source_cas(graph, node["id"])
    ]

    if missing_build:
        evidence.append(_count_evidence(
            "ALBS_BUILD_TASK_MISSING",
            missing_build,
            "Binary RPMs are not linked from an ALBS build task.",
            35,
            "incoming produces edges",
        ))
    if missing_release:
        evidence.append(_count_evidence(
            "ALBS_RELEASE_MISSING",
            missing_release,
            "Binary RPMs are not linked to a repository release.",
            15,
            "outgoing released_to edges",
        ))
    if missing_artifact_cas:
        evidence.append(_count_evidence(
            "ALBS_ARTIFACT_CAS_MISSING",
            missing_artifact_cas,
            "Binary RPMs do not have artifact CAS attestation evidence.",
            30,
            "outgoing authenticated_by edges to cas_attestation",
        ))
    if missing_source_cas:
        evidence.append(_count_evidence(
            "ALBS_SOURCE_CAS_MISSING",
            missing_source_cas,
            "Binary RPMs do not have source CAS attestation in their build path.",
            30,
            "build task incoming built_by + source authenticated_by",
        ))
    return evidence


@tool
def inspect_edgp_rpm_albs_provenance(export_json: str) -> list[dict]:
    """Check EDGP installed-RPM to ALBS artifact provenance coverage."""
    export = _loads(export_json)
    if export["source_schema"] != EDGP_RPM_ALBS_PROVENANCE_SCHEMA:
        return []

    source = export["source"]
    summary = source.get("summary") or {}
    matches = source.get("matches") or []
    unmatched = source.get("unmatchedInstalledPackages") or []
    evidence: list[dict] = []

    if int(summary.get("unmatchedPackages") or len(unmatched)) > 0:
        evidence.append(_evidence(
            "EDGP_RPM_ALBS_UNMATCHED_PACKAGES",
            (
                f"{len(unmatched)} installed RPM package(s) were not matched "
                "to ALBS artifacts."
            ),
            45,
            "summary.unmatchedPackages + unmatchedInstalledPackages",
        ))

    missing_cas = [
        match for match in matches if not (match.get("albsArtifact") or {}).get("casHash")
    ]
    unknown_build = [
        match for match in matches if str(match.get("buildId") or "") in {"", "unknown"}
    ]
    missing_release = [match for match in matches if not str(match.get("releaseId") or "")]

    if missing_cas:
        evidence.append(_evidence(
            "EDGP_RPM_ALBS_CAS_MISSING",
            f"{len(missing_cas)} matched ALBS artifact(s) have no CAS hash.",
            25,
            "matches[].albsArtifact.casHash",
        ))
    if unknown_build:
        evidence.append(_evidence(
            "EDGP_RPM_ALBS_BUILD_UNKNOWN",
            f"{len(unknown_build)} matched package(s) have unknown ALBS build id.",
            20,
            "matches[].buildId",
        ))
    if missing_release:
        evidence.append(_evidence(
            "EDGP_RPM_ALBS_RELEASE_MISSING",
            f"{len(missing_release)} matched package(s) have no ALBS release id.",
            10,
            "matches[].releaseId",
        ))

    return evidence


@tool
def inspect_edgp_albs_inventory(export_json: str) -> list[dict]:
    """Check EDGP ALBS artifact inventory coverage fields."""
    export = _loads(export_json)
    if export["source_schema"] != EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA:
        return []

    source = export["source"]
    summary = source.get("summary") or {}
    items = source.get("items") or []
    evidence: list[dict] = []

    if int(summary.get("artifacts") or len(items)) == 0:
        evidence.append(_evidence(
            "EDGP_ALBS_INVENTORY_EMPTY",
            "ALBS artifact inventory contains no artifacts.",
            25,
            "summary.artifacts + items",
        ))
        return evidence

    missing_cas = [item for item in items if not item.get("casHash")]
    missing_build_task = [item for item in items if not item.get("buildTaskId")]
    if missing_cas:
        evidence.append(_evidence(
            "EDGP_ALBS_INVENTORY_CAS_MISSING",
            f"{len(missing_cas)} inventory item(s) have no CAS hash.",
            25,
            "items[].casHash",
        ))
    if missing_build_task:
        evidence.append(_evidence(
            "EDGP_ALBS_INVENTORY_BUILD_TASK_MISSING",
            f"{len(missing_build_task)} inventory item(s) have no build task id.",
            25,
            "items[].buildTaskId",
        ))

    return evidence


@tool
def inspect_edgp_graph_snapshot(export_json: str) -> list[dict]:
    """Check EDGP graph snapshot structural integrity."""
    export = _loads(export_json)
    if export["source_schema"] != EDGP_GRAPH_SNAPSHOT_SCHEMA:
        return []

    source = export["source"]
    nodes = source.get("nodes") or []
    edges = source.get("edges") or []
    node_ids = {node.get("id") for node in nodes}
    evidence: list[dict] = []

    stats = source.get("stats") or {}
    if stats.get("nodes") != len(nodes) or stats.get("edges") != len(edges):
        evidence.append(_evidence(
            "EDGP_GRAPH_STATS_MISMATCH",
            "Graph snapshot stats do not match node or edge counts.",
            30,
            "stats + nodes + edges",
        ))

    root = source.get("root")
    if root and root not in node_ids:
        evidence.append(_evidence(
            "EDGP_GRAPH_ROOT_MISSING",
            f"Graph root '{root}' is not present in nodes.",
            20,
            "root + nodes[].id",
        ))

    dangling = [
        edge
        for edge in edges
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids
    ]
    if dangling:
        evidence.append(_evidence(
            "EDGP_GRAPH_DANGLING_EDGES",
            f"{len(dangling)} graph edge(s) reference missing nodes.",
            35,
            "edges[].source + edges[].target + nodes[].id",
        ))

    return evidence


@tool
def calculate_edgp_blast_radius(export_json: str) -> list[dict]:
    """Calculate bounded reverse-dependency impact for an EDGP graph root."""
    export = _loads(export_json)
    if export["source_schema"] != EDGP_GRAPH_SNAPSHOT_SCHEMA:
        return []

    source = export["source"]
    root = source.get("root")
    if not root:
        return []
    dependents, truncated = _reverse_dependents(source, str(root), limit=10_000)
    if len(dependents) < 5:
        return []
    weight = 30 if len(dependents) >= 10 else 15
    suffix = " Traversal stopped at the 10000-node safety limit." if truncated else ""
    return [_evidence(
        "EDGP_LARGE_BLAST_RADIUS",
        (
            f"Graph root has {len(dependents)} transitive reverse dependent(s)."
            + suffix
        ),
        weight,
        "root + edges (bounded reverse traversal)",
    )]


@tool
def summarize_source_coverage(export_json: str) -> list[dict]:
    """Summarize deterministic source coverage facts without changing risk."""
    export = _loads(export_json)
    source_schema = export["source_schema"]
    source = export["source"]

    if source_schema == COMBINED_SCHEMA:
        schemas = [item.get("schema", "unknown") for item in source.get("sources", [])]
        return [_observation(
            "COMBINED_SOURCE_COVERAGE",
            "Combined investigation input with source schemas: " + ", ".join(schemas),
            "sources[].schema",
        )]
    if source_schema == ALBS_GRAPH_SCHEMA:
        return _summarize_albs_graph(source)
    if source_schema == EDGP_RPM_ALBS_PROVENANCE_SCHEMA:
        return _summarize_edgp_rpm_albs(source)
    if source_schema == EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA:
        return _summarize_edgp_albs_inventory(source)
    if source_schema == EDGP_GRAPH_SNAPSHOT_SCHEMA:
        return _summarize_edgp_graph_snapshot(source)
    if source_schema == SIMPLE_SCHEMA:
        return [_observation(
            "SIMPLE_EXPORT_SCOPE",
            (
                "Compatibility fixture with artifact/build/policy fields; "
                "not a real ALBS or EDGP export contract."
            ),
            "source_schema",
        )]
    return []


EVIDENCE_TOOLS = [
    inspect_builder,
    inspect_signature,
    inspect_reproducibility,
    inspect_vulnerabilities,
    inspect_albs_trust_path,
    inspect_edgp_rpm_albs_provenance,
    inspect_edgp_albs_inventory,
    inspect_edgp_graph_snapshot,
    calculate_edgp_blast_radius,
]


OBSERVATION_TOOLS = [
    summarize_source_coverage,
]


def expand_tool_exports(export: dict[str, Any]) -> list[dict[str, Any]]:
    if export["source_schema"] != COMBINED_SCHEMA:
        return [export]

    expanded = [export]
    for index, source in enumerate(export["source"].get("sources", [])):
        expanded.append(
            {
                "schema": NORMALIZED_SCHEMA,
                "source_schema": source["schema"],
                "source_path": f"{export['source_path']}#sources[{index}]",
                "artifact": export["artifact"],
                "source": source,
            }
        )
    return expanded


def _loads(export_json: str) -> dict[str, Any]:
    return json.loads(export_json)


def _evidence(code: str, finding: str, weight: int, source: str) -> dict:
    return Evidence(
        code=code,
        finding=finding,
        weight=weight,
        source=source,
    ).model_dump()


def _observation(code: str, finding: str, source: str) -> dict:
    return Observation(
        code=code,
        finding=finding,
        source=source,
    ).model_dump()


def _count_evidence(
    code: str,
    nodes: list[dict[str, Any]],
    finding: str,
    weight: int,
    source: str,
) -> dict:
    examples = ", ".join(_node_label(node) for node in nodes[:3])
    suffix = f" Examples: {examples}." if examples else ""
    return _evidence(code, f"{finding} Count: {len(nodes)}.{suffix}", weight, source)


def _summarize_albs_graph(source: dict[str, Any]) -> list[dict]:
    graph = _albs_graph(source)
    rpm_nodes = _nodes_by_type(graph, "binary_rpm")
    released = [
        node for node in rpm_nodes if graph["outgoing"][node["id"]].get("released_to")
    ]
    signed = [
        node for node in rpm_nodes if graph["outgoing"][node["id"]].get("signed_as")
    ]
    artifact_cas = [node for node in rpm_nodes if _has_artifact_cas(graph, node["id"])]
    source_cas = [node for node in rpm_nodes if _has_source_cas(graph, node["id"])]
    sbom = [
        node for node in rpm_nodes if graph["outgoing"][node["id"]].get("described_by")
    ]
    errata = [
        node
        for node in rpm_nodes
        if graph["outgoing"][node["id"]].get("affected_by")
        or graph["outgoing"][node["id"]].get("fixes")
        or (node.get("metadata") or {}).get("errata_status") == "confirmed_clean"
    ]
    build_tasks = _nodes_by_type(graph, "build_task")
    source_packages = _nodes_by_type(graph, "source_package")

    return [_observation(
        "ALBS_TRUST_COVERAGE",
        (
            f"{len(rpm_nodes)} binary RPM(s), {len(build_tasks)} build task node(s), "
            f"{len(source_packages)} source package node(s); "
            f"{len(released)}/{len(rpm_nodes)} binary RPM(s) have release edges, "
            f"{len(signed)}/{len(rpm_nodes)} have signature edges, "
            f"{len(artifact_cas)}/{len(rpm_nodes)} have artifact CAS evidence, "
            f"{len(source_cas)}/{len(rpm_nodes)} have source CAS evidence, "
            f"{len(sbom)}/{len(rpm_nodes)} have SBOM coverage, and "
            f"{len(errata)}/{len(rpm_nodes)} have checked errata status."
        ),
        "nodes + edges",
    )]


def _summarize_edgp_rpm_albs(source: dict[str, Any]) -> list[dict]:
    summary = source.get("summary") or {}
    matches = source.get("matches") or []
    unmatched = source.get("unmatchedInstalledPackages") or []
    cas_count = sum(
        1 for match in matches if (match.get("albsArtifact") or {}).get("casHash")
    )
    build_count = sum(
        1 for match in matches if str(match.get("buildId") or "") not in {"", "unknown"}
    )
    release_count = sum(1 for match in matches if str(match.get("releaseId") or ""))
    installed = int(summary.get("installedPackages") or len(matches) + len(unmatched))

    return [_observation(
        "EDGP_RPM_ALBS_COVERAGE",
        (
            f"{len(matches)}/{installed} installed RPM package(s) matched ALBS artifacts; "
            f"{len(unmatched)} unmatched package(s); {cas_count}/{len(matches)} match(es) "
            f"have CAS hash, {build_count}/{len(matches)} have build id, "
            f"{release_count}/{len(matches)} have release id."
        ),
        "summary + matches + unmatchedInstalledPackages",
    )]


def _summarize_edgp_albs_inventory(source: dict[str, Any]) -> list[dict]:
    summary = source.get("summary") or {}
    items = source.get("items") or []
    cas_count = sum(1 for item in items if item.get("casHash"))
    build_task_count = sum(1 for item in items if item.get("buildTaskId"))
    return [_observation(
        "EDGP_ALBS_INVENTORY_COVERAGE",
        (
            f"{summary.get('artifacts', len(items))} artifact(s), "
            f"{summary.get('binaryRpms', 0)} binary RPM(s), "
            f"{summary.get('sourceRpms', 0)} source RPM(s), "
            f"{summary.get('buildTasks', 0)} build task(s), "
            f"{summary.get('architectures', 0)} architecture(s), "
            f"{summary.get('packages', 0)} package name(s); "
            f"{cas_count}/{len(items)} item(s) have CAS hash and "
            f"{build_task_count}/{len(items)} item(s) have build task id."
        ),
        "summary + items",
    )]


def _summarize_edgp_graph_snapshot(source: dict[str, Any]) -> list[dict]:
    stats = source.get("stats") or {}
    rankings = source.get("rankings") or {}
    most_depended = rankings.get("mostDependedUpon") or []
    leader = most_depended[0] if most_depended else None
    leader_text = (
        f" Most depended-upon package: {leader['package']} "
        f"({leader['dependents']} dependent(s))."
        if leader
        else ""
    )
    return [_observation(
        "EDGP_GRAPH_SNAPSHOT_COVERAGE",
        (
            f"{stats.get('nodes', 0)} node(s), {stats.get('edges', 0)} edge(s), "
            f"root={source.get('root')!r}, ecosystem={source.get('ecosystem')!r}."
            f"{leader_text}"
        ),
        "stats + root + ecosystem + rankings",
    )]


def _inspect_albs_signatures(source: dict[str, Any]) -> list[dict]:
    graph = _albs_graph(source)
    released_rpms = [
        node
        for node in _nodes_by_type(graph, "binary_rpm")
        if graph["outgoing"][node["id"]].get("released_to")
    ]
    missing_signature = [
        node
        for node in released_rpms
        if not graph["outgoing"][node["id"]].get("signed_as")
    ]
    if not missing_signature:
        return []
    return [_count_evidence(
        "ALBS_SIGNATURE_MISSING",
        missing_signature,
        "Released binary RPMs do not have ALBS signature evidence.",
        40,
        "outgoing signed_as edges",
    )]


def _inspect_albs_vulnerabilities(source: dict[str, Any]) -> list[dict]:
    graph = _albs_graph(source)
    affected_edges = [
        edge
        for edge in source.get("edges", [])
        if edge.get("relation") == "affected_by"
        and graph["nodes"].get(edge.get("source"), {}).get("type") == "binary_rpm"
    ]
    if not affected_edges:
        return []
    return [_evidence(
        "ALBS_AFFECTED_BY_VULNERABILITY",
        f"{len(affected_edges)} binary RPM affected-by vulnerability edge(s) found.",
        30,
        "edges[relation=affected_by]",
    )]


def _albs_graph(source: dict[str, Any]) -> dict[str, Any]:
    nodes = {node["id"]: node for node in source.get("nodes", [])}
    outgoing: dict[str, dict[str, list[dict[str, Any]]]] = {
        node_id: {} for node_id in nodes
    }
    incoming: dict[str, dict[str, list[dict[str, Any]]]] = {
        node_id: {} for node_id in nodes
    }
    for edge in source.get("edges", []):
        relation = str(edge.get("relation"))
        source_id = str(edge.get("source"))
        target_id = str(edge.get("target"))
        outgoing.setdefault(source_id, {}).setdefault(relation, []).append(edge)
        incoming.setdefault(target_id, {}).setdefault(relation, []).append(edge)
    return {"nodes": nodes, "outgoing": outgoing, "incoming": incoming}


def _nodes_by_type(graph: dict[str, Any], node_type: str) -> list[dict[str, Any]]:
    return [
        node for node in graph["nodes"].values()
        if node.get("type") == node_type
    ]


def _has_artifact_cas(graph: dict[str, Any], rpm_node_id: str) -> bool:
    for edge in graph["outgoing"][rpm_node_id].get("authenticated_by", []):
        target = graph["nodes"].get(edge.get("target"))
        if target and target.get("type") == "cas_attestation" and _has_cas_evidence(target):
            return True
    return False


def _has_source_cas(graph: dict[str, Any], rpm_node_id: str) -> bool:
    for produce_edge in graph["incoming"][rpm_node_id].get("produces", []):
        build_task_id = str(produce_edge.get("source"))
        for cas_edge in graph["incoming"].get(build_task_id, {}).get("built_by", []):
            cas_node = graph["nodes"].get(cas_edge.get("source"))
            if not cas_node or cas_node.get("type") != "cas_attestation":
                continue
            if not _has_cas_evidence(cas_node):
                continue
            if graph["incoming"].get(str(cas_node.get("id")), {}).get("authenticated_by"):
                return True
    return False


def _has_cas_evidence(node: dict[str, Any]) -> bool:
    metadata = node.get("metadata") or {}
    return bool(
        metadata.get("cas_hash")
        or metadata.get("evidence_present")
        or metadata.get("albs_authenticated")
    )


def _node_label(node: dict[str, Any]) -> str:
    metadata = node.get("metadata") or {}
    return str(metadata.get("filename") or metadata.get("name") or node.get("label") or node["id"])


def _reverse_dependents(
    source: dict[str, Any],
    root: str,
    *,
    limit: int,
) -> tuple[set[str], bool]:
    incoming: dict[str, list[str]] = {}
    for edge in source.get("edges", []):
        target = str(edge.get("target"))
        incoming.setdefault(target, []).append(str(edge.get("source")))

    visited = {root}
    dependents: set[str] = set()
    queue = deque([root])
    while queue and len(dependents) < limit:
        current = queue.popleft()
        for dependent in incoming.get(current, []):
            if dependent in visited:
                continue
            visited.add(dependent)
            dependents.add(dependent)
            queue.append(dependent)
            if len(dependents) >= limit:
                break
    return dependents, bool(queue)
