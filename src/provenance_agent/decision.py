from __future__ import annotations

from .contracts import (
    CompletenessAssessment,
    ConfidenceAssessment,
    Contradiction,
    DecisionState,
    RiskAssessment,
)
from .profiles import PolicyProfile, load_policy_profile


def decide(
    *,
    risk: RiskAssessment,
    completeness: CompletenessAssessment,
    confidence: ConfidenceAssessment,
    contradictions: list[Contradiction],
    profile: PolicyProfile | None = None,
) -> DecisionState:
    profile = profile or load_policy_profile()
    if (
        completeness.score < profile.decision.unknown_below_completeness
        or confidence.score < profile.decision.unknown_below_confidence
    ):
        return "UNKNOWN"
    if contradictions:
        return "REVIEW"
    if (
        risk.score == 0
        and not completeness.missing_categories
        and completeness.score == 100
        and confidence.score >= profile.decision.allow_min_confidence
    ):
        return "ALLOW"
    return "REVIEW"
