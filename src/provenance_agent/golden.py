"""Offline golden-suite runner for behavioral and safety regression checks.

Executes investigation and timeout cases, verifies expected decisions and
evidence properties, and returns a machine-readable aggregate report.
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter
from typing import Any

from .contracts import InvestigationRequest
from .execution import RetryExhaustedError, RetryPolicy, run_with_retry
from .service import InvestigationService
from .store import InvestigationStore


DEFAULT_MANIFEST = Path("eval/golden/cases.json")


def run_golden_suite(manifest_path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    with TemporaryDirectory(prefix="provenance-agent-golden-") as directory:
        for case in manifest["cases"]:
            if case.get("mode") == "retry_timeout":
                result = _run_timeout_case(case)
            else:
                result = _run_investigation_case(case, Path(directory))
            results.append(result)
    passed = sum(1 for result in results if result["passed"])
    return {
        "schema": "provenance-risk-agent.golden-results.v1",
        "manifest": str(manifest_path),
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "success": passed == len(results),
        "cases": results,
    }


def _run_investigation_case(
    case: dict[str, Any],
    directory: Path,
) -> dict[str, Any]:
    service = InvestigationService(
        InvestigationStore(directory / f"{case['id']}.sqlite3")
    )
    started = perf_counter()
    result = service.run_investigation(
        InvestigationRequest(input_path=case["input_path"])
    )
    duration_ms = round((perf_counter() - started) * 1000, 3)
    evidence_codes = {item["code"] for item in result.evidence}
    contradiction_codes = {item.code for item in result.contradictions}
    evidence_ids = [
        item["evidence_id"]
        for item in result.observations + result.evidence
        if item.get("evidence_id")
    ]
    explanation = result.explanation.lower()
    checks = {
        "decision": result.decision_state == case["expected_decision"],
        "risk_score": (
            result.risk_score == case["expected_risk_score"]
            if "expected_risk_score" in case
            else True
        ),
        "evidence_codes": set(case.get("expected_evidence_codes", []))
        <= evidence_codes,
        "missing_evidence": set(case.get("expected_missing_evidence", []))
        <= set(result.missing_evidence),
        "contradictions": set(case.get("expected_contradiction_codes", []))
        <= contradiction_codes,
        "bounded_execution": duration_ms <= case["max_duration_ms"],
        "stable_evidence_ids": len(evidence_ids) == len(set(evidence_ids)),
        "source_pointers": all(
            bool(item.get("source_pointer", {}).get("record_path"))
            for item in result.observations + result.evidence
        ),
        "unsupported_claims": not any(
            term.lower() in explanation
            for term in case.get("forbidden_explanation_terms", [])
        ),
        "trace": bool(result.events)
        and result.events[0].event_type == "investigation_started",
    }
    return {
        "id": case["id"],
        "passed": all(checks.values()),
        "checks": checks,
        "duration_ms": duration_ms,
        "decision": result.decision_state,
        "risk_score": result.risk_score,
        "completeness_score": result.reliability.completeness_score,
        "confidence_score": result.reliability.confidence_score,
        "evidence_codes": sorted(evidence_codes),
        "contradiction_codes": sorted(contradiction_codes),
        "missing_evidence": result.missing_evidence,
        "event_count": len(result.events),
    }


def _run_timeout_case(case: dict[str, Any]) -> dict[str, Any]:
    attempts = 0

    def operation() -> None:
        nonlocal attempts
        attempts += 1
        raise TimeoutError("controlled golden timeout")

    started = perf_counter()
    exhausted = False
    trace_count = 0
    try:
        run_with_retry(
            operation,
            policy=RetryPolicy(
                max_attempts=case["expected_attempts"],
                base_delay_seconds=0,
            ),
            sleep=lambda _: None,
        )
    except RetryExhaustedError as exc:
        exhausted = True
        trace_count = len(exc.attempts)
    duration_ms = round((perf_counter() - started) * 1000, 3)
    checks = {
        "retry_budget": attempts == case["expected_attempts"],
        "typed_failure": exhausted,
        "attempt_trace": trace_count == case["expected_attempts"],
        "bounded_execution": duration_ms <= case["max_duration_ms"],
    }
    return {
        "id": case["id"],
        "passed": all(checks.values()),
        "checks": checks,
        "duration_ms": duration_ms,
        "attempts": attempts,
        "error": "RetryExhaustedError" if exhausted else None,
    }
