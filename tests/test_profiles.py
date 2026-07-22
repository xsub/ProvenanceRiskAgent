"""Tests for versioned policy profiles and calibration invariants.

Verifies profile identity and sensitivity along with baseline compatibility and
default-versus-strict monotonicity over the golden corpus.
"""

from provenance_agent.calibration import calibrate_policy_profiles
from provenance_agent.profiles import list_policy_profiles, load_policy_profile


def test_policy_profiles_are_versioned_and_strict_is_more_sensitive():
    profiles = list_policy_profiles()
    identifiers = [profile.identifier for profile in profiles]
    default = load_policy_profile("enterprise-linux-default@1.0.0")
    strict = load_policy_profile("enterprise-linux-strict@1.0.0")

    assert identifiers == [
        "enterprise-linux-default@1.0.0",
        "enterprise-linux-strict@1.0.0",
    ]
    assert strict.weight_for(
        {"code": "EDGP_ADVISORY_AFFECTS_ARTIFACT", "severity": "critical"}
    ) > default.weight_for(
        {"code": "EDGP_ADVISORY_AFFECTS_ARTIFACT", "severity": "critical"}
    )
    assert strict.decision.allow_min_confidence > default.decision.allow_min_confidence


def test_policy_calibration_preserves_baseline_and_monotonicity():
    report = calibrate_policy_profiles()

    assert report["success"] is True
    assert report["baseline"] == {
        "profile": "enterprise-linux-default@1.0.0",
        "passed": 10,
        "total": 10,
        "success": True,
    }
    assert all(item["passed"] for item in report["comparisons"])
