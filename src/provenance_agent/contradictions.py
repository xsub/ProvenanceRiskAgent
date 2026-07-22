"""Cross-source contradiction detection for normalized assessments.

Defines normalized claims and reducers that compare ALBS and EDGP artifact
identity, version, architecture, and digest assertions with source pointers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import Contradiction, SourcePointer
from .evidence import source_pointer, stable_contradiction_id
from .normalization import (
    ALBS_GRAPH_SCHEMA,
    COMBINED_SCHEMA,
    EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA,
    EDGP_RPM_ALBS_PROVENANCE_SCHEMA,
)


@dataclass(frozen=True)
class Claim:
    category: str
    value: str
    source_pointer: dict[str, Any]


def detect_contradictions(export: dict[str, Any]) -> list[Contradiction]:
    if export["source_schema"] != COMBINED_SCHEMA:
        return []
    claims = _artifact_claims(export)
    for index, child in enumerate(export["source"].get("sources", [])):
        child_export = {
            "source_schema": child["schema"],
            "source_path": f"{export['source_path']}#sources[{index}]",
            "artifact": export["artifact"],
            "source": child,
        }
        claims.extend(_source_claims(child_export))

    contradictions: list[Contradiction] = []
    for category in sorted({claim.category for claim in claims}):
        category_claims = [claim for claim in claims if claim.category == category]
        distinct = sorted({_normalized_value(category, claim.value) for claim in category_claims})
        if len(distinct) <= 1:
            continue
        payload = [
            {"value": claim.value, "source_pointer": claim.source_pointer}
            for claim in category_claims
        ]
        code = f"CROSS_SOURCE_{category.upper()}_MISMATCH"
        contradiction_id = stable_contradiction_id(
            code=code,
            category=category,
            claims=payload,
        )
        contradictions.append(
            Contradiction(
                contradiction_id=contradiction_id,
                code=code,
                category=category,
                message=(
                    f"Conflicting {category.replace('_', ' ')} values were observed: "
                    + ", ".join(distinct)
                    + "."
                ),
                severity=(
                    "critical" if category in {"artifact_name", "artifact_digest"} else "warning"
                ),
                values=distinct,
                source_pointers=[
                    SourcePointer.model_validate(claim.source_pointer)
                    for claim in category_claims
                ],
            )
        )
    return contradictions


def _artifact_claims(export: dict[str, Any]) -> list[Claim]:
    artifact = export.get("artifact") or {}
    claims: list[Claim] = []
    for category, field in (
        ("artifact_name", "name"),
        ("artifact_version", "version"),
        ("artifact_digest", "digest"),
    ):
        value = str(artifact.get(field) or "")
        if value:
            claims.append(
                Claim(
                    category,
                    value,
                    source_pointer(export, record_path=f"artifact.{field}"),
                )
            )
    return claims


def _source_claims(export: dict[str, Any]) -> list[Claim]:
    schema = export["source_schema"]
    source = export["source"]
    if schema == ALBS_GRAPH_SCHEMA:
        return _albs_claims(export, source)
    if schema == EDGP_RPM_ALBS_PROVENANCE_SCHEMA:
        return _edgp_match_claims(export, source)
    if schema == EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA:
        return _edgp_inventory_claims(export, source)
    return []


def _albs_claims(export: dict[str, Any], source: dict[str, Any]) -> list[Claim]:
    target_name = str((export.get("artifact") or {}).get("name") or "")
    candidates = [
        node
        for node in source.get("nodes", [])
        if node.get("type") == "binary_rpm"
    ]
    binary_nodes = _select_target_records(candidates, target_name, "name")
    claims: list[Claim] = []
    signed_binary_ids = {
        str(edge.get("source"))
        for edge in source.get("edges", [])
        if edge.get("relation") == "signed_as"
    }
    for node in binary_nodes:
        metadata = node.get("metadata") or {}
        record = f"nodes[id={node.get('id')}]"
        claims.extend(_identity_claims(export, metadata, record))
        claims.append(
            _claim(
                export,
                "artifact_signature",
                "present" if str(node.get("id")) in signed_binary_ids else "absent",
                f"{record}.signed_as",
            )
        )
    for node in source.get("nodes", []):
        metadata = node.get("metadata") or {}
        if node.get("type") == "build_task" and metadata.get("albs_build_id"):
            claims.append(_claim(export, "build_id", metadata["albs_build_id"], f"nodes[id={node.get('id')}].metadata.albs_build_id"))
        if node.get("type") == "repository_release" and metadata.get("release_id"):
            claims.append(_claim(export, "release_id", metadata["release_id"], f"nodes[id={node.get('id')}].metadata.release_id"))
    return claims


def _edgp_match_claims(export: dict[str, Any], source: dict[str, Any]) -> list[Claim]:
    target_name = str((export.get("artifact") or {}).get("name") or "")
    claims: list[Claim] = []
    matches = source.get("matches") or []
    selected = _select_edgp_matches(matches, target_name)
    for index, match in selected:
        installed = match.get("installedPackage") or {}
        artifact = match.get("albsArtifact") or {}
        name = str(installed.get("name") or artifact.get("packageName") or "")
        record = f"matches[{index}]"
        merged = {
            "name": name,
            "version": installed.get("version") or artifact.get("version"),
            "release": installed.get("release") or artifact.get("release"),
            "cas_hash": artifact.get("casHash"),
        }
        claims.extend(_identity_claims(export, merged, record))
        if match.get("buildId"):
            claims.append(_claim(export, "build_id", match["buildId"], f"{record}.buildId"))
        if match.get("releaseId"):
            claims.append(_claim(export, "release_id", match["releaseId"], f"{record}.releaseId"))
    return claims


def _edgp_inventory_claims(export: dict[str, Any], source: dict[str, Any]) -> list[Claim]:
    target_name = str((export.get("artifact") or {}).get("name") or "")
    claims: list[Claim] = []
    indexed_items = list(enumerate(source.get("items") or []))
    matches = [
        pair
        for pair in indexed_items
        if str(pair[1].get("packageName") or "") == target_name
    ]
    selected = matches or (indexed_items if len(indexed_items) == 1 else [])
    for index, item in selected:
        name = str(item.get("packageName") or "")
        claims.extend(
            _identity_claims(
                export,
                {
                    "name": name,
                    "version": item.get("version"),
                    "release": item.get("release"),
                    "cas_hash": item.get("casHash"),
                },
                f"items[{index}]",
            )
        )
    return claims


def _identity_claims(
    export: dict[str, Any],
    values: dict[str, Any],
    record: str,
) -> list[Claim]:
    claims: list[Claim] = []
    if values.get("name"):
        claims.append(_claim(export, "artifact_name", values["name"], f"{record}.name"))
    version = _version_release(values.get("version"), values.get("release"))
    if version:
        claims.append(_claim(export, "artifact_version", version, f"{record}.version_release"))
    digest = values.get("cas_hash") or values.get("digest")
    if digest:
        claims.append(_claim(export, "artifact_digest", digest, f"{record}.cas_hash"))
    return claims


def _claim(export: dict[str, Any], category: str, value: Any, record: str) -> Claim:
    return Claim(
        category=category,
        value=str(value),
        source_pointer=source_pointer(export, record_path=record),
    )


def _version_release(version: Any, release: Any) -> str:
    version_text = str(version or "")
    release_text = str(release or "")
    if version_text and release_text:
        return f"{version_text}-{release_text}"
    return version_text or release_text


def _normalized_value(category: str, value: str) -> str:
    text = value.strip().lower()
    if category == "artifact_digest":
        return text.split(":", 1)[-1]
    return text


def _select_target_records(
    records: list[dict[str, Any]],
    target_name: str,
    metadata_field: str,
) -> list[dict[str, Any]]:
    if not target_name:
        return records
    matches = [
        record
        for record in records
        if str((record.get("metadata") or {}).get(metadata_field) or "")
        == target_name
    ]
    return matches or (records if len(records) == 1 else [])


def _select_edgp_matches(
    matches: list[dict[str, Any]],
    target_name: str,
) -> list[tuple[int, dict[str, Any]]]:
    indexed = list(enumerate(matches))
    if not target_name:
        return indexed
    selected = []
    for pair in indexed:
        match = pair[1]
        installed = match.get("installedPackage") or {}
        artifact = match.get("albsArtifact") or {}
        name = str(installed.get("name") or artifact.get("packageName") or "")
        if name == target_name:
            selected.append(pair)
    return selected or (indexed if len(indexed) == 1 else [])
