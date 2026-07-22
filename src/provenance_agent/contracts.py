from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


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


class InvestigationRequest(BaseModel):
    input_path: str = "examples/suspicious-build.json"
    question: str = DEFAULT_QUESTION
    model: str | None = None
    pause_before_review: bool = False


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
