from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import ProvenanceExport


NORMALIZED_SCHEMA = "provenance-risk-agent.normalized.v1"
SIMPLE_SCHEMA = "provenance-risk-agent.simple.v1"
COMBINED_SCHEMA = "provenance-risk-agent.combined.v1"
ALBS_GRAPH_SCHEMA = "albs-provenance-explorer/v1"
EDGP_RPM_ALBS_PROVENANCE_SCHEMA = "edgp.rpm.albs_provenance.v1"
EDGP_GRAPH_SNAPSHOT_SCHEMA = "edgp.graph.snapshot.v1"
EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA = "edgp.albs.artifact_inventory.v1"


def normalize_export(raw: dict[str, Any], source_path: Path) -> dict[str, Any]:
    schema = raw.get("schema")
    if schema == ALBS_GRAPH_SCHEMA:
        artifact = _artifact_from_albs_graph(raw)
    elif schema == EDGP_RPM_ALBS_PROVENANCE_SCHEMA:
        artifact = _artifact_from_rpm_albs_provenance(raw)
    elif schema == EDGP_GRAPH_SNAPSHOT_SCHEMA:
        artifact = _artifact_from_graph_snapshot(raw)
    elif schema == EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA:
        artifact = _artifact_from_albs_inventory(raw)
    elif schema == COMBINED_SCHEMA:
        _validate_combined_sources(raw)
        artifact = _artifact_from_combined(raw)
    elif "artifact" in raw and "build" in raw:
        simple = ProvenanceExport.model_validate(raw)
        raw = simple.model_dump(mode="json")
        schema = SIMPLE_SCHEMA
        artifact = raw["artifact"]
    else:
        raise ValueError(
            "Unsupported provenance export. Expected one of: "
            f"{SIMPLE_SCHEMA}, {COMBINED_SCHEMA}, {ALBS_GRAPH_SCHEMA}, "
            f"{EDGP_RPM_ALBS_PROVENANCE_SCHEMA}, {EDGP_GRAPH_SNAPSHOT_SCHEMA}, "
            f"{EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA}."
        )

    return {
        "schema": NORMALIZED_SCHEMA,
        "source_schema": schema,
        "source_path": str(source_path),
        "artifact": artifact,
        "source": raw,
    }


def _artifact_from_albs_graph(raw: dict[str, Any]) -> dict[str, str]:
    node = _preferred_albs_artifact_node(raw.get("nodes", []))
    if node is None:
        return {"name": "albs-provenance-graph", "version": "", "digest": ""}

    metadata = node.get("metadata", {})
    name = str(metadata.get("name") or node.get("label") or node.get("id"))
    version = _version_release(metadata.get("version"), metadata.get("release"))
    digest = str(metadata.get("cas_hash") or "")
    return {"name": name, "version": version, "digest": digest}


def _artifact_from_rpm_albs_provenance(raw: dict[str, Any]) -> dict[str, str]:
    matches = raw.get("matches") or []
    if matches:
        match = matches[0]
        installed = match.get("installedPackage") or {}
        artifact = match.get("albsArtifact") or {}
        name = str(installed.get("name") or artifact.get("packageName") or raw.get("root"))
        version = _version_release(installed.get("version"), installed.get("release"))
        digest = str(artifact.get("casHash") or "")
        return {"name": name, "version": version, "digest": digest}

    unmatched = raw.get("unmatchedInstalledPackages") or []
    if unmatched:
        package = unmatched[0]
        name = str(package.get("name") or package.get("nodeId") or raw.get("root"))
        version = _version_release(package.get("version"), package.get("release"))
        return {"name": name, "version": version, "digest": ""}

    return {"name": str(raw.get("root") or "rpm-albs-provenance"), "version": "", "digest": ""}


def _artifact_from_graph_snapshot(raw: dict[str, Any]) -> dict[str, str]:
    root = raw.get("root")
    nodes = raw.get("nodes") or []
    root_node = next((node for node in nodes if node.get("id") == root), None)
    if root_node is not None:
        package = root_node.get("package") or {}
        name = str(package.get("name") or root_node.get("name") or root)
        version = str(package.get("version") or root_node.get("version") or "")
        digest = str(package.get("checksum") or "")
        return {"name": name, "version": version, "digest": digest}

    return {"name": str(root or "edgp-graph-snapshot"), "version": "", "digest": ""}


def _artifact_from_albs_inventory(raw: dict[str, Any]) -> dict[str, str]:
    items = raw.get("items") or []
    item = _preferred_inventory_item(items)
    if item is None:
        return {"name": str(raw.get("root") or "albs-artifact-inventory"), "version": "", "digest": ""}

    return {
        "name": str(item.get("packageName") or item.get("filename") or item.get("artifactNodeId")),
        "version": _version_release(item.get("version"), item.get("release")),
        "digest": str(item.get("casHash") or ""),
    }


def _artifact_from_combined(raw: dict[str, Any]) -> dict[str, str]:
    artifact = raw.get("artifact") or {}
    return {
        "name": str(artifact.get("name") or "combined-artifact"),
        "version": str(artifact.get("version") or ""),
        "digest": str(artifact.get("digest") or ""),
    }


def _validate_combined_sources(raw: dict[str, Any]) -> None:
    sources = raw.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("Combined provenance export requires a non-empty sources list.")

    supported = {
        ALBS_GRAPH_SCHEMA,
        EDGP_RPM_ALBS_PROVENANCE_SCHEMA,
        EDGP_GRAPH_SNAPSHOT_SCHEMA,
        EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA,
    }
    for index, source in enumerate(sources):
        schema = source.get("schema") if isinstance(source, dict) else None
        if schema not in supported:
            raise ValueError(
                "Combined provenance export source "
                f"{index} has unsupported schema: {schema!r}."
            )


def _preferred_albs_artifact_node(nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
    source_names = {
        str(node.get("label"))
        for node in nodes
        if node.get("type") == "source_package" and node.get("label")
    }
    artifacts = [
        node
        for node in nodes
        if node.get("type") in {"binary_rpm", "srpm"}
    ]
    if not artifacts:
        return nodes[0] if nodes else None

    def key(node: dict[str, Any]) -> tuple[int, int, int, int, int, str]:
        metadata = node.get("metadata", {})
        name = str(metadata.get("name") or node.get("label") or "")
        is_binary = 0 if node.get("type") == "binary_rpm" else 1
        is_source_named = 0 if name in source_names else 1
        is_debug = 1 if _is_debug(name) else 0
        arch_rank = _arch_rank(metadata.get("arch"))
        artifact_id = _int_sort_key(metadata.get("artifact_id"))
        return (is_binary, is_source_named, is_debug, arch_rank, artifact_id, name)

    return sorted(artifacts, key=key)[0]


def _preferred_inventory_item(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not items:
        return None

    def key(item: dict[str, Any]) -> tuple[int, int, int, str]:
        kind = str(item.get("artifactKind") or "")
        name = str(item.get("packageName") or item.get("filename") or "")
        is_binary = 0 if kind in {"binary", "noarch"} and not _is_debug(name) else 1
        arch_rank = _arch_rank(item.get("artifactArch"))
        artifact_id = _int_sort_key(item.get("artifactId"))
        return (is_binary, arch_rank, artifact_id, name)

    return sorted(items, key=key)[0]


def _version_release(version: Any, release: Any) -> str:
    version_text = str(version or "")
    release_text = str(release or "")
    if version_text and release_text:
        return f"{version_text}-{release_text}"
    return version_text or release_text


def _arch_rank(value: Any) -> int:
    arch_preference = ("x86_64", "aarch64", "ppc64le", "s390x", "i686", "noarch", "src")
    arch = str(value or "")
    try:
        return arch_preference.index(arch)
    except ValueError:
        return len(arch_preference)


def _int_sort_key(value: Any) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 2**63 - 1


def _is_debug(name: str) -> bool:
    return (
        name.endswith("-debuginfo")
        or name.endswith("-debugsource")
        or "-debuginfo-" in name
        or "-debugsource-" in name
    )
