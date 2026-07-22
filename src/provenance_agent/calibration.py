from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .contracts import InvestigationRequest
from .golden import DEFAULT_MANIFEST, run_golden_suite
from .profiles import list_policy_profiles
from .service import InvestigationService
from .store import InvestigationStore


def calibrate_policy_profiles(
    manifest_path: str | Path = DEFAULT_MANIFEST,
) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = [case for case in manifest["cases"] if case.get("input_path")]
    profiles = list_policy_profiles()
    runs: dict[str, dict[str, dict[str, Any]]] = {}

    with TemporaryDirectory(prefix="provenance-agent-calibration-") as directory:
        for profile in profiles:
            profile_runs: dict[str, dict[str, Any]] = {}
            for case in cases:
                service = InvestigationService(
                    InvestigationStore(
                        Path(directory) / f"{profile.profile_id}-{case['id']}.sqlite3"
                    )
                )
                result = service.run_investigation(
                    InvestigationRequest(
                        input_path=case["input_path"],
                        policy_profile=profile.identifier,
                    )
                )
                profile_runs[case["id"]] = {
                    "status": result.status,
                    "decision": result.decision_state,
                    "risk_score": result.risk_score,
                    "risk_level": result.risk_level,
                }
            runs[profile.identifier] = profile_runs

    default_id = "enterprise-linux-default@1.0.0"
    strict_id = "enterprise-linux-strict@1.0.0"
    comparisons: list[dict[str, Any]] = []
    for case in cases:
        default = runs[default_id][case["id"]]
        strict = runs[strict_id][case["id"]]
        comparable = default["status"] == strict["status"] == "succeeded"
        checks = {
            "strict_risk_not_lower": (
                strict["risk_score"] >= default["risk_score"] if comparable else True
            ),
            "strict_allow_implies_default_allow": not (
                strict["decision"] == "ALLOW" and default["decision"] != "ALLOW"
            ),
        }
        comparisons.append(
            {
                "case": case["id"],
                "default": default,
                "strict": strict,
                "checks": checks,
                "passed": all(checks.values()),
            }
        )

    baseline = run_golden_suite(manifest_path)
    success = baseline["success"] and all(item["passed"] for item in comparisons)
    return {
        "schema": "provenance-risk-agent.policy-calibration.v1",
        "manifest": str(manifest_path),
        "profiles": [profile.identifier for profile in profiles],
        "baseline": {
            "profile": default_id,
            "passed": baseline["passed"],
            "total": baseline["total"],
            "success": baseline["success"],
        },
        "comparisons": comparisons,
        "success": success,
    }
