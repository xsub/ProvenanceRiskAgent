from __future__ import annotations

from typing import Any

from .contracts import RiskAssessment


def assess_risk(evidence: list[dict[str, Any]]) -> RiskAssessment:
    score = min(100, sum(max(0, int(item.get("weight") or 0)) for item in evidence))
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score > 0:
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
