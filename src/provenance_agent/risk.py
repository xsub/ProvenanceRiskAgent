"""Deterministic weighted-risk aggregation.

Maps evidence findings through a selected versioned policy profile and returns
capped scores, calibrated levels, and the contributing evidence identifiers.
"""

from __future__ import annotations

from typing import Any

from .contracts import RiskAssessment
from .profiles import PolicyProfile, load_policy_profile


def assess_risk(
    evidence: list[dict[str, Any]],
    profile: PolicyProfile | None = None,
) -> RiskAssessment:
    profile = profile or load_policy_profile()
    score = min(100, sum(max(0, int(item.get("weight") or 0)) for item in evidence))
    if score >= profile.risk_bands.critical:
        level = "critical"
    elif score >= profile.risk_bands.high:
        level = "high"
    elif score >= profile.risk_bands.medium:
        level = "medium"
    elif score >= profile.risk_bands.low:
        level = "low"
    else:
        level = "none"
    return RiskAssessment(
        score=score,
        level=level,
        evidence_ids=[
            str(item["evidence_id"])
            for item in evidence
            if item.get("evidence_id")
        ],
    )
