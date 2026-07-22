"""Confidence assessment for deterministic investigation results.

Combines evidence completeness and contradiction severity while keeping
confidence independent from risk magnitude and policy outcome.
"""

from __future__ import annotations

from .contracts import (
    CompletenessAssessment,
    ConfidenceAssessment,
    Contradiction,
)


def assess_confidence(
    completeness: CompletenessAssessment,
    contradictions: list[Contradiction],
    *,
    compatibility_fixture: bool,
) -> ConfidenceAssessment:
    score = completeness.score
    reducers: list[str] = []
    if completeness.missing_categories:
        reducers.append(
            "Missing required evidence: " + ", ".join(completeness.missing_categories)
        )
    for contradiction in contradictions:
        reduction = 25 if contradiction.severity == "critical" else 10
        score -= reduction
        reducers.append(f"{contradiction.code}: -{reduction}")
    if compatibility_fixture and score > 75:
        score = 75
        reducers.append("Compatibility fixture input caps confidence at 75.")
    score = max(0, min(100, score))
    if score >= 80:
        level = "high"
    elif score >= 50:
        level = "medium"
    else:
        level = "low"
    return ConfidenceAssessment(score=score, level=level, reducers=reducers)
