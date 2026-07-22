from __future__ import annotations

from typing import Any, Literal, TypedDict
from pydantic import BaseModel, Field


Severity = Literal["none", "low", "medium", "high", "critical"]


class Artifact(BaseModel):
    name: str
    version: str
    digest: str


class Build(BaseModel):
    builder: str
    signed: bool
    reproducible: bool = False
    source_commit: str | None = None


class Dependency(BaseModel):
    name: str
    version: str
    direct: bool = True


class Vulnerability(BaseModel):
    id: str
    severity: Severity
    fixed: bool = False


class Policy(BaseModel):
    allowed_builders: list[str] = Field(default_factory=list)
    require_signature: bool = True
    require_reproducible: bool = False


class ProvenanceExport(BaseModel):
    artifact: Artifact
    build: Build
    dependencies: list[Dependency] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    policy: Policy = Field(default_factory=Policy)


class Evidence(BaseModel):
    evidence_id: str = ""
    code: str
    finding: str
    weight: int
    source: str
    source_pointer: dict[str, Any] = Field(default_factory=dict)
    severity: Severity | Literal["unknown"] | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class Observation(BaseModel):
    evidence_id: str = ""
    code: str
    finding: str
    source: str
    source_pointer: dict[str, Any] = Field(default_factory=dict)


class AnalysisState(TypedDict, total=False):
    input_path: str
    live: dict
    policy_profile_id: str
    policy_profile: dict
    acquisition: list[dict]
    export: dict
    observations: list[dict]
    evidence: list[dict]
    contradictions: list[dict]
    risk: dict
    completeness: dict
    confidence: dict
    policy_evaluation: dict
    risk_score: int
    risk_level: str
    requires_review: bool
    proposed_decision: str
    decision_state: str
    human_review: dict
    explanation: str
    report: str
