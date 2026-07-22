from __future__ import annotations

from .contracts import (
    CompletenessAssessment,
    Contradiction,
    PolicyEvaluation,
    PolicyRuleResult,
    RiskAssessment,
)


def evaluate_policy(
    *,
    risk: RiskAssessment,
    completeness: CompletenessAssessment,
    contradictions: list[Contradiction],
    profile: str = "default",
) -> PolicyEvaluation:
    rules = [
        PolicyRuleResult(
            rule_id="required-evidence",
            status="pass" if completeness.score >= 80 else "fail",
            message=(
                "Required evidence coverage is sufficient."
                if completeness.score >= 80
                else "Required evidence coverage is below 80%."
            ),
        ),
        PolicyRuleResult(
            rule_id="cross-source-consistency",
            status="pass" if not contradictions else "fail",
            message=(
                "No cross-source contradictions were detected."
                if not contradictions
                else f"{len(contradictions)} cross-source contradiction(s) detected."
            ),
            evidence_ids=[item.contradiction_id for item in contradictions],
        ),
        PolicyRuleResult(
            rule_id="risk-review-threshold",
            status="fail" if risk.score >= 50 else "pass",
            message=(
                "Risk score requires review."
                if risk.score >= 50
                else "Risk score is below the review threshold."
            ),
            evidence_ids=risk.evidence_ids,
        ),
    ]
    return PolicyEvaluation(
        profile=profile,
        rule_results=rules,
        failed_rule_ids=[rule.rule_id for rule in rules if rule.status == "fail"],
    )
