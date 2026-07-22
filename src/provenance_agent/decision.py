from __future__ import annotations

from .contracts import (
    CompletenessAssessment,
    ConfidenceAssessment,
    Contradiction,
    DecisionState,
    RiskAssessment,
)


def decide(
    *,
    risk: RiskAssessment,
    completeness: CompletenessAssessment,
    confidence: ConfidenceAssessment,
    contradictions: list[Contradiction],
) -> DecisionState:
    if completeness.score < 50 or confidence.score < 35:
        return "UNKNOWN"
    if contradictions:
        return "REVIEW"
    if risk.score == 0 and completeness.score >= 80 and confidence.score >= 70:
        return "ALLOW"
    return "REVIEW"
