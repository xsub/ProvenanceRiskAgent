from __future__ import annotations

from datetime import UTC, datetime
import os
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from .profiles import DEFAULT_POLICY_PROFILE


DecisionState = Literal["ALLOW", "DENY", "REVIEW", "UNKNOWN", "ERROR"]
InvestigationStatus = Literal[
    "pending",
    "running",
    "awaiting_review",
    "succeeded",
    "failed",
]
EvidenceKind = Literal["verified_fact", "risk_evidence", "contradiction"]
RiskLevel = Literal["none", "low", "medium", "high", "critical", "error"]
ConfidenceLevel = Literal["low", "medium", "high"]
RuleStatus = Literal["pass", "fail", "skip"]
ContradictionSeverity = Literal["warning", "critical"]


DEFAULT_QUESTION = (
    "Why is this Enterprise Linux artifact risky, and is there enough evidence "
    "to trust the decision?"
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_investigation_id() -> str:
    return f"inv_{uuid4().hex}"


class LiveArtifactRequest(BaseModel):
    build_id: int = Field(gt=0)
    package: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+%-]*$",
    )
    arch: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_+-]+$")
    sbom_path: str | None = None
    albs_base_url: str = "https://build.almalinux.org"
    errata_url: str | None = None
    osv_api_url: str = "https://api.osv.dev"
    osv_ecosystem: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:-]*$",
    )
    refresh: bool = False
    command_timeout_seconds: float = Field(default=90.0, ge=1.0, le=600.0)
    max_output_bytes: int = Field(default=32 * 1024 * 1024, ge=1024, le=128 * 1024 * 1024)
    advisory_limit: int = Field(default=100, ge=1, le=1000)
    inventory_task_limit: int = Field(default=5000, ge=1, le=20000)
    inventory_artifact_limit: int = Field(default=5000, ge=1, le=20000)

    @field_validator("albs_base_url", "errata_url", "osv_api_url")
    @classmethod
    def validate_https_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("Live source URLs must use HTTPS.")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_live_hosts(self) -> LiveArtifactRequest:
        official = {
            "albs_base_url": "build.almalinux.org",
            "errata_url": "errata.almalinux.org",
            "osv_api_url": "api.osv.dev",
        }
        configured = {
            host.strip().lower()
            for host in os.environ.get(
                "PROVENANCE_AGENT_ALLOWED_LIVE_HOSTS",
                "",
            ).split(",")
            if host.strip()
        }
        for field, official_host in official.items():
            value = getattr(self, field)
            if value is None:
                continue
            parsed = urlparse(value)
            host = (parsed.hostname or "").lower()
            if parsed.username or parsed.password:
                raise ValueError("Live source URLs cannot contain credentials.")
            if host != official_host and host not in configured:
                raise ValueError(
                    f"{field} host {host!r} is not in the live-source allowlist."
                )
            if host == official_host and parsed.port not in {None, 443}:
                raise ValueError(f"{field} must use the official HTTPS port.")
        return self


class InvestigationRequest(BaseModel):
    input_path: str | None = "examples/suspicious-build.json"
    question: str = DEFAULT_QUESTION
    model: str | None = None
    pause_before_review: bool = False
    policy_profile: str = DEFAULT_POLICY_PROFILE
    live: LiveArtifactRequest | None = None

    @model_validator(mode="after")
    def validate_source(self) -> InvestigationRequest:
        if self.live is not None:
            if "input_path" in self.model_fields_set and self.input_path:
                raise ValueError("Specify either input_path or live, not both.")
            self.input_path = None
        elif not self.input_path:
            raise ValueError("input_path is required when live acquisition is absent.")
        return self

    @property
    def source_reference(self) -> str:
        if self.live is not None:
            return f"live://albs/build/{self.live.build_id}"
        return str(self.input_path)


class AdapterTrace(BaseModel):
    adapter: str
    operation: str
    source_uri: str
    status: Literal["succeeded", "failed"]
    duration_ms: float = Field(ge=0)
    response_sha256: str | None = None
    records: int | None = Field(default=None, ge=0)
    detail: str | None = None


class SourcePointer(BaseModel):
    source_system: str
    source_schema: str
    source_path: str
    record_path: str
    subject: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    evidence_ids: list[str] = Field(default_factory=list)


class CompletenessAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    required_categories: list[str] = Field(default_factory=list)
    present_categories: list[str] = Field(default_factory=list)
    missing_categories: list[str] = Field(default_factory=list)
    contradictory_categories: list[str] = Field(default_factory=list)


class ConfidenceAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: ConfidenceLevel
    reducers: list[str] = Field(default_factory=list)


class Contradiction(BaseModel):
    contradiction_id: str
    code: str
    category: str
    message: str
    severity: ContradictionSeverity
    values: list[str] = Field(default_factory=list)
    source_pointers: list[SourcePointer] = Field(default_factory=list)


class PolicyRuleResult(BaseModel):
    rule_id: str
    status: RuleStatus
    message: str
    evidence_ids: list[str] = Field(default_factory=list)


class PolicyEvaluation(BaseModel):
    profile: str
    rule_results: list[PolicyRuleResult] = Field(default_factory=list)
    failed_rule_ids: list[str] = Field(default_factory=list)


class ReviewRequest(BaseModel):
    interrupt_id: str
    reason: str
    proposed_decision: DecisionState
    risk_score: int = Field(ge=0, le=100)
    evidence_ids: list[str] = Field(default_factory=list)
    contradiction_ids: list[str] = Field(default_factory=list)


class ReviewDecision(BaseModel):
    decision: Literal["ALLOW", "DENY", "REVIEW", "UNKNOWN"]
    reviewer: str = Field(min_length=1)
    rationale: str = Field(min_length=1)


class ReliabilityAssessment(BaseModel):
    completeness_score: int = Field(ge=0, le=100)
    confidence_score: int = Field(ge=0, le=100)
    present_categories: list[str] = Field(default_factory=list)
    missing_categories: list[str] = Field(default_factory=list)
    contradictory_categories: list[str] = Field(default_factory=list)
    confidence_level: ConfidenceLevel = "low"
    reducers: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class InvestigationEvent(BaseModel):
    id: int | None = None
    investigation_id: str
    sequence: int
    event_type: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class EvidenceRecord(BaseModel):
    id: int | None = None
    evidence_id: str
    investigation_id: str
    kind: EvidenceKind
    code: str
    finding: str
    source: str
    weight: int = 0
    source_pointers: list[SourcePointer] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    investigation_id: str
    status: InvestigationStatus
    question: str
    input_path: str
    artifact: dict[str, Any]
    source_schema: str
    decision_state: DecisionState
    proposed_decision: DecisionState | None = None
    risk_score: int
    risk_level: str
    requires_review: bool
    reliability: ReliabilityAssessment
    risk: RiskAssessment | None = None
    completeness: CompletenessAssessment | None = None
    confidence: ConfidenceAssessment | None = None
    policy_evaluation: PolicyEvaluation | None = None
    policy_profile: dict[str, Any] = Field(default_factory=dict)
    acquisition: list[AdapterTrace] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    review_request: ReviewRequest | None = None
    review_decision: ReviewDecision | None = None
    observations: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    explanation: str = ""
    report: str = ""
    events: list[InvestigationEvent] = Field(default_factory=list)


class InvestigationSummary(BaseModel):
    investigation_id: str
    status: InvestigationStatus
    question: str
    input_path: str
    created_at: datetime
    updated_at: datetime
    result: InvestigationResult | None = None
