from __future__ import annotations

from langchain_core.tools import tool
from .models import Evidence, ProvenanceExport


@tool
def inspect_builder(export_json: str) -> list[dict]:
    """Check whether the artifact was produced by an allowed builder."""
    export = ProvenanceExport.model_validate_json(export_json)
    allowed = export.policy.allowed_builders
    if allowed and export.build.builder not in allowed:
        return [Evidence(
            code="BUILDER_NOT_ALLOWED",
            finding=f"Builder '{export.build.builder}' is not in {allowed}.",
            weight=35,
            source="build.builder + policy.allowed_builders",
        ).model_dump()]
    return []


@tool
def inspect_signature(export_json: str) -> list[dict]:
    """Check required artifact signature evidence."""
    export = ProvenanceExport.model_validate_json(export_json)
    if export.policy.require_signature and not export.build.signed:
        return [Evidence(
            code="SIGNATURE_MISSING",
            finding="Policy requires a signature, but the build is unsigned.",
            weight=40,
            source="build.signed + policy.require_signature",
        ).model_dump()]
    return []


@tool
def inspect_reproducibility(export_json: str) -> list[dict]:
    """Check reproducible-build policy evidence."""
    export = ProvenanceExport.model_validate_json(export_json)
    if export.policy.require_reproducible and not export.build.reproducible:
        return [Evidence(
            code="NOT_REPRODUCIBLE",
            finding="Policy requires a reproducible build, but no match is recorded.",
            weight=25,
            source="build.reproducible + policy.require_reproducible",
        ).model_dump()]
    return []


@tool
def inspect_vulnerabilities(export_json: str) -> list[dict]:
    """Collect unresolved vulnerabilities and assign deterministic weights."""
    export = ProvenanceExport.model_validate_json(export_json)
    weights = {"none": 0, "low": 3, "medium": 8, "high": 18, "critical": 30}
    findings: list[dict] = []
    for vuln in export.vulnerabilities:
        if not vuln.fixed:
            findings.append(Evidence(
                code="UNFIXED_VULNERABILITY",
                finding=f"{vuln.id} is unresolved with severity {vuln.severity}.",
                weight=weights[vuln.severity],
                source="vulnerabilities",
            ).model_dump())
    return findings


EVIDENCE_TOOLS = [
    inspect_builder,
    inspect_signature,
    inspect_reproducibility,
    inspect_vulnerabilities,
]
