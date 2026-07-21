from __future__ import annotations

from pathlib import Path
from typing import Any

from .contracts import (
    DEFAULT_QUESTION,
    DecisionState,
    EvidenceRecord,
    InvestigationRequest,
    InvestigationResult,
    ReliabilityAssessment,
    new_investigation_id,
)
from .store import InvestigationStore
from .workflow import build_graph


class InvestigationService:
    def __init__(self, store: InvestigationStore) -> None:
        self.store = store

    def run_investigation(
        self,
        request: InvestigationRequest,
        *,
        investigation_id: str | None = None,
    ) -> InvestigationResult:
        investigation_id = investigation_id or new_investigation_id()
        self.store.create_investigation(
            investigation_id=investigation_id,
            question=request.question,
            input_path=request.input_path,
        )
        self.store.set_status(investigation_id, "running")
        self.store.add_event(
            investigation_id,
            "investigation_started",
            "Investigation started.",
            {"question": request.question, "input_path": request.input_path},
        )

        try:
            graph = build_graph(model_name=request.model)
            workflow_result = graph.invoke({"input_path": request.input_path})
            result = self._build_result(investigation_id, request, workflow_result)
            self._record_success(result)
            self.store.save_result(result)
            return result
        except Exception as exc:
            self.store.add_event(
                investigation_id,
                "investigation_failed",
                "Investigation failed before producing a result.",
                {"error": str(exc), "error_type": type(exc).__name__},
            )
            result = InvestigationResult(
                investigation_id=investigation_id,
                status="failed",
                question=request.question,
                input_path=request.input_path,
                artifact={},
                source_schema="unknown",
                decision_state="ERROR",
                risk_score=0,
                risk_level="error",
                requires_review=True,
                reliability=ReliabilityAssessment(
                    completeness_score=0,
                    confidence_score=0,
                    missing_categories=["workflow_result"],
                    notes=["Workflow failed before deterministic result creation."],
                ),
                explanation=str(exc),
                events=self.store.list_events(investigation_id),
            )
            self.store.save_result(result)
            return result

    def get_investigation(self, investigation_id: str):
        return self.store.get_investigation(investigation_id)

    def list_events(self, investigation_id: str):
        return self.store.list_events(investigation_id)

    def list_evidence(self, investigation_id: str):
        return self.store.list_evidence(investigation_id)

    def list_examples(self) -> list[dict[str, str]]:
        examples = []
        for path in sorted(Path("examples").glob("*.json")):
            examples.append(
                {
                    "id": path.stem,
                    "path": str(path),
                    "label": path.stem.replace("-", " ").title(),
                }
            )
        return examples

    def _build_result(
        self,
        investigation_id: str,
        request: InvestigationRequest,
        workflow_result: dict[str, Any],
    ) -> InvestigationResult:
        export = workflow_result["export"]
        observations = workflow_result.get("observations", [])
        evidence = workflow_result.get("evidence", [])
        reliability = assess_reliability(
            observations=observations,
            evidence=evidence,
            source_schema=export["source_schema"],
            explanation=workflow_result.get("explanation", ""),
        )
        decision_state = decision_from_workflow(workflow_result, reliability)
        return InvestigationResult(
            investigation_id=investigation_id,
            status="succeeded",
            question=request.question,
            input_path=request.input_path,
            artifact=export["artifact"],
            source_schema=export["source_schema"],
            decision_state=decision_state,
            risk_score=workflow_result["risk_score"],
            risk_level=workflow_result["risk_level"],
            requires_review=workflow_result["requires_review"],
            reliability=reliability,
            observations=observations,
            evidence=evidence,
            explanation=workflow_result.get("explanation", ""),
            report=workflow_result.get("report", ""),
        )

    def _record_success(self, result: InvestigationResult) -> None:
        self.store.add_event(
            result.investigation_id,
            "artifact_resolved",
            "Artifact identity was resolved from the source export.",
            {"artifact": result.artifact, "source_schema": result.source_schema},
        )
        self.store.add_event(
            result.investigation_id,
            "verified_facts_collected",
            "Verified coverage facts were collected.",
            {"count": len(result.observations)},
        )
        for item in result.observations:
            self.store.add_evidence(
                EvidenceRecord(
                    investigation_id=result.investigation_id,
                    kind="verified_fact",
                    code=item["code"],
                    finding=item["finding"],
                    source=item["source"],
                )
            )
        self.store.add_event(
            result.investigation_id,
            "risk_evidence_collected",
            "Risk evidence records were collected.",
            {"count": len(result.evidence)},
        )
        for item in result.evidence:
            self.store.add_evidence(
                EvidenceRecord(
                    investigation_id=result.investigation_id,
                    kind="risk_evidence",
                    code=item["code"],
                    finding=item["finding"],
                    source=item["source"],
                    weight=item["weight"],
                )
            )
        self.store.add_event(
            result.investigation_id,
            "risk_scored",
            "Deterministic risk score was calculated.",
            {"risk_score": result.risk_score, "risk_level": result.risk_level},
        )
        self.store.add_event(
            result.investigation_id,
            "reliability_assessed",
            "Evidence completeness and confidence were assessed.",
            result.reliability.model_dump(mode="json"),
        )
        self.store.add_event(
            result.investigation_id,
            "verdict_produced",
            "Decision state was produced from deterministic result fields.",
            {"decision_state": result.decision_state},
        )
        result.events = self.store.list_events(result.investigation_id)


def decision_from_workflow(
    workflow_result: dict[str, Any],
    reliability: ReliabilityAssessment,
) -> DecisionState:
    if reliability.completeness_score < 50:
        return "UNKNOWN"
    if workflow_result["requires_review"]:
        return "REVIEW"
    if workflow_result["risk_score"] == 0:
        return "ALLOW"
    return "REVIEW"


def assess_reliability(
    *,
    observations: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    source_schema: str,
    explanation: str,
) -> ReliabilityAssessment:
    present = ["artifact_identity", "risk_scoring", "explanation"]
    missing: list[str] = []
    notes = [f"Source schema: {source_schema}."]

    if observations:
        present.append("verified_facts")
    else:
        missing.append("verified_facts")

    if evidence:
        present.append("risk_evidence")
    else:
        notes.append("No risk-raising evidence was found by configured checks.")

    if source_schema == "provenance-risk-agent.simple.v1":
        notes.append(
            "Compatibility fixture input; not a full ALBS/EDGP evidence bundle."
        )

    completeness_score = round(100 * len(present) / (len(present) + len(missing)))
    confidence_score = completeness_score
    if missing:
        confidence_score = max(0, confidence_score - 15)
    if "HUMAN REVIEW REQUIRED" in explanation:
        confidence_score = min(confidence_score, 70)

    return ReliabilityAssessment(
        completeness_score=completeness_score,
        confidence_score=confidence_score,
        present_categories=present,
        missing_categories=missing,
        notes=notes,
    )


def default_service(db_path: str | Path = "provenance-agent.sqlite3") -> InvestigationService:
    return InvestigationService(InvestigationStore(db_path))


def default_request(input_path: str = "examples/suspicious-build.json") -> InvestigationRequest:
    return InvestigationRequest(input_path=input_path, question=DEFAULT_QUESTION)

