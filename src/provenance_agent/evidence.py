"""Stable evidence identity and source-attribution helpers.

Enriches facts and findings with deterministic identifiers, normalized subject
coordinates, source systems, source pointers, and contradiction IDs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal


RecordKind = Literal["verified_fact", "risk_evidence"]


def enrich_record(
    record: dict[str, Any],
    *,
    export: dict[str, Any],
    kind: RecordKind,
) -> dict[str, Any]:
    pointer = source_pointer(
        export,
        record_path=str(record.get("source") or "source"),
    )
    evidence_id = stable_record_id(
        kind=kind,
        code=str(record["code"]),
        source_schema=pointer["source_schema"],
        record_path=pointer["record_path"],
        subject=pointer["subject"],
    )
    return {
        **record,
        "evidence_id": evidence_id,
        "source_pointer": pointer,
    }


def source_pointer(
    export: dict[str, Any],
    *,
    record_path: str,
    subject: dict[str, Any] | None = None,
) -> dict[str, Any]:
    schema = str(export.get("source_schema") or "unknown")
    return {
        "source_system": source_system(schema),
        "source_schema": schema,
        "source_path": str(export.get("source_path") or ""),
        "record_path": record_path,
        "subject": subject or dict(export.get("artifact") or {}),
    }


def stable_record_id(
    *,
    kind: str,
    code: str,
    source_schema: str,
    record_path: str,
    subject: dict[str, Any],
) -> str:
    identity = {
        "kind": kind,
        "code": code,
        "source_schema": source_schema,
        "record_path": record_path,
        "subject": _stable_subject(subject),
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:20]
    prefix = "obs" if kind == "verified_fact" else "evd"
    return f"{prefix}_{digest}"


def stable_contradiction_id(
    *,
    code: str,
    category: str,
    claims: list[dict[str, Any]],
) -> str:
    identity = {
        "code": code,
        "category": category,
        "claims": sorted(
            (
                {
                    "value": str(claim.get("value") or ""),
                    "source_schema": claim["source_pointer"]["source_schema"],
                    "record_path": claim["source_pointer"]["record_path"],
                }
                for claim in claims
            ),
            key=lambda item: (
                item["source_schema"],
                item["record_path"],
                item["value"],
            ),
        ),
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:20]
    return f"ctr_{digest}"


def source_system(schema: str) -> str:
    if schema.startswith("albs-"):
        return "albs"
    if schema.startswith("edgp."):
        return "edgp"
    if schema.endswith(".simple.v1"):
        return "simple"
    if schema.endswith(".combined.v1"):
        return "agent"
    return "unknown"


def _stable_subject(subject: dict[str, Any]) -> dict[str, str]:
    return {
        "name": str(subject.get("name") or ""),
        "version": str(subject.get("version") or ""),
        "digest": _normalize_digest(subject.get("digest")),
    }


def _normalize_digest(value: Any) -> str:
    text = str(value or "").lower()
    return text.split(":", 1)[-1]
