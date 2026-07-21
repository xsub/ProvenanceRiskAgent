from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


DecisionState = Literal["ALLOW", "DENY", "REVIEW", "UNKNOWN", "ERROR"]
InvestigationStatus = Literal["pending", "running", "succeeded", "failed"]
EvidenceKind = Literal["verified_fact", "risk_evidence"]


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


class ReliabilityAssessment(BaseModel):
    completeness_score: int = Field(ge=0, le=100)
    confidence_score: int = Field(ge=0, le=100)
    present_categories: list[str] = Field(default_factory=list)
    missing_categories: list[str] = Field(default_factory=list)
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
    investigation_id: str
    kind: EvidenceKind
    code: str
    finding: str
    source: str
    weight: int = 0


class InvestigationResult(BaseModel):
    investigation_id: str
    status: InvestigationStatus
    question: str
    input_path: str
    artifact: dict[str, Any]
    source_schema: str
    decision_state: DecisionState
    risk_score: int
    risk_level: str
    requires_review: bool
    reliability: ReliabilityAssessment
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

