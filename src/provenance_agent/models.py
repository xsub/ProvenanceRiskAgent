from __future__ import annotations

from typing import Literal, TypedDict
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
    code: str
    finding: str
    weight: int
    source: str


class Observation(BaseModel):
    code: str
    finding: str
    source: str


class AnalysisState(TypedDict, total=False):
    input_path: str
    export: dict
    observations: list[dict]
    evidence: list[dict]
    risk_score: int
    risk_level: str
    requires_review: bool
    explanation: str
    report: str
