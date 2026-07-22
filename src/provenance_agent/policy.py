from __future__ import annotations

from .contracts import (
    CompletenessAssessment,
    Contradiction,
    PolicyEvaluation,
    PolicyRuleResult,
    RiskAssessment,
)
from .profiles import PolicyProfile, load_policy_profile


def evaluate_policy(
    *,
    risk: RiskAssessment,
    completeness: CompletenessAssessment,
    contradictions: list[Contradiction],
    profile: PolicyProfile | None = None,
) -> PolicyEvaluation:
    profile = profile or load_policy_profile()
    evidence_complete = not completeness.missing_categories
    rules = [
        PolicyRuleResult(
            rule_id="required-evidence",
            status="pass" if evidence_complete else "fail",
            message=(
                "Required evidence coverage is sufficient."
                if evidence_complete
                else "One or more required evidence categories are missing."
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
            status=(
                "fail"
                if risk.score >= profile.decision.policy_review_risk_score
                else "pass"
            ),
            message=(
                "Risk score requires review."
                if risk.score >= profile.decision.policy_review_risk_score
                else "Risk score is below the review threshold."
            ),
            evidence_ids=risk.evidence_ids,
        ),
    ]
    return PolicyEvaluation(
        profile=profile.identifier,
        rule_results=rules,
        failed_rule_ids=[rule.rule_id for rule in rules if rule.status == "fail"],
    )
