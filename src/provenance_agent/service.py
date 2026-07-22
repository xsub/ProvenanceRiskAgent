from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from .contracts import (
    DEFAULT_QUESTION,
    CompletenessAssessment,
    ConfidenceAssessment,
    Contradiction,
    EvidenceRecord,
    InvestigationRequest,
    InvestigationResult,
    PolicyEvaluation,
    ReliabilityAssessment,
    ReviewDecision,
    ReviewRequest,
    RiskAssessment,
    SourcePointer,
    new_investigation_id,
)
from .execution import RetryAttempt, run_with_retry
from .store import InvestigationStore
from .workflow import build_graph


class InvestigationService:
    def __init__(
        self,
        store: InvestigationStore,
        *,
        checkpoint_path: str | Path | None = None,
    ) -> None:
        self.store = store
        checkpoint_path = checkpoint_path or Path(f"{store.path}.checkpoints")
        self._checkpoint_connection = sqlite3.connect(
            checkpoint_path,
            check_same_thread=False,
        )
        self.checkpointer = SqliteSaver(self._checkpoint_connection)

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
            {
                "question": request.question,
                "input_path": request.input_path,
                "pause_before_review": request.pause_before_review,
            },
        )

        try:
            graph = build_graph(
                model_name=request.model,
                checkpointer=self.checkpointer if request.pause_before_review else None,
                interrupt_reviews=request.pause_before_review,
            )
            config = self._config(investigation_id)
            workflow_result = run_with_retry(
                lambda: graph.invoke(
                    {"input_path": request.input_path},
                    config=config if request.pause_before_review else None,
                ),
                on_attempt=lambda attempt: self._record_retry(
                    investigation_id,
                    attempt,
                ),
            )
            review_request = self._review_request(workflow_result)
            status = "awaiting_review" if review_request else "succeeded"
            result = self._build_result(
                investigation_id,
                request,
                workflow_result,
                status=status,
                review_request=review_request,
            )
            self._record_analysis(result)
            if review_request:
                self.store.add_event(
                    investigation_id,
                    "review_requested",
                    "Investigation paused for a human decision.",
                    review_request.model_dump(mode="json"),
                )
            else:
                self._record_verdict(result)
            result.events = self.store.list_events(investigation_id)
            self.store.save_result(result)
            return result
        except Exception as exc:
            return self._record_failure(investigation_id, request, exc)

    def resume_investigation(
        self,
        investigation_id: str,
        review: ReviewDecision,
    ) -> InvestigationResult:
        summary = self.store.get_investigation(investigation_id)
        if summary is None:
            raise KeyError(f"Investigation not found: {investigation_id}")
        if summary.status != "awaiting_review" or summary.result is None:
            raise ValueError("Investigation is not awaiting human review.")

        self.store.set_status(investigation_id, "running")
        self.store.add_event(
            investigation_id,
            "review_submitted",
            "Human review decision was submitted.",
            review.model_dump(mode="json"),
        )
        request = InvestigationRequest(
            input_path=summary.input_path,
            question=summary.question,
            pause_before_review=True,
        )
        try:
            graph = build_graph(
                checkpointer=self.checkpointer,
                interrupt_reviews=True,
            )
            workflow_result = run_with_retry(
                lambda: graph.invoke(
                    Command(resume=review.model_dump(mode="json")),
                    config=self._config(investigation_id),
                ),
                on_attempt=lambda attempt: self._record_retry(
                    investigation_id,
                    attempt,
                ),
            )
            result = self._build_result(
                investigation_id,
                request,
                workflow_result,
                status="succeeded",
                review_decision=review,
            )
            self.store.add_event(
                investigation_id,
                "review_completed",
                "Human review was applied to the proposed verdict.",
                {
                    "proposed_decision": result.proposed_decision,
                    "decision_state": result.decision_state,
                    "reviewer": review.reviewer,
                },
            )
            self._record_verdict(result)
            result.events = self.store.list_events(investigation_id)
            self.store.save_result(result)
            return result
        except Exception as exc:
            return self._record_failure(investigation_id, request, exc)

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
        *,
        status: str,
        review_request: ReviewRequest | None = None,
        review_decision: ReviewDecision | None = None,
    ) -> InvestigationResult:
        export = workflow_result["export"]
        risk = RiskAssessment.model_validate(workflow_result["risk"])
        completeness = CompletenessAssessment.model_validate(
            workflow_result["completeness"]
        )
        confidence = ConfidenceAssessment.model_validate(workflow_result["confidence"])
        policy = PolicyEvaluation.model_validate(workflow_result["policy_evaluation"])
        contradictions = [
            Contradiction.model_validate(item)
            for item in workflow_result.get("contradictions", [])
        ]
        reliability = ReliabilityAssessment(
            completeness_score=completeness.score,
            confidence_score=confidence.score,
            present_categories=completeness.present_categories,
            missing_categories=completeness.missing_categories,
            contradictory_categories=completeness.contradictory_categories,
            confidence_level=confidence.level,
            reducers=confidence.reducers,
            notes=[
                f"Source schema: {export['source_schema']}.",
                f"Policy profile: {policy.profile}.",
            ],
        )
        return InvestigationResult(
            investigation_id=investigation_id,
            status=status,
            question=request.question,
            input_path=request.input_path,
            artifact=export["artifact"],
            source_schema=export["source_schema"],
            decision_state=workflow_result["decision_state"],
            proposed_decision=workflow_result["proposed_decision"],
            risk_score=risk.score,
            risk_level=risk.level,
            requires_review=workflow_result["requires_review"],
            reliability=reliability,
            risk=risk,
            completeness=completeness,
            confidence=confidence,
            policy_evaluation=policy,
            contradictions=contradictions,
            missing_evidence=completeness.missing_categories,
            review_request=review_request,
            review_decision=review_decision,
            observations=workflow_result.get("observations", []),
            evidence=workflow_result.get("evidence", []),
            explanation=workflow_result.get("explanation", ""),
            report=workflow_result.get("report", ""),
        )

    def _record_analysis(self, result: InvestigationResult) -> None:
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
            self._persist_record(result.investigation_id, "verified_fact", item)

        self.store.add_event(
            result.investigation_id,
            "risk_evidence_collected",
            "Risk evidence records were collected.",
            {"count": len(result.evidence)},
        )
        for item in result.evidence:
            self._persist_record(result.investigation_id, "risk_evidence", item)

        for contradiction in result.contradictions:
            self.store.add_evidence(
                EvidenceRecord(
                    evidence_id=contradiction.contradiction_id,
                    investigation_id=result.investigation_id,
                    kind="contradiction",
                    code=contradiction.code,
                    finding=contradiction.message,
                    source=", ".join(
                        sorted(
                            {
                                pointer.source_system
                                for pointer in contradiction.source_pointers
                            }
                        )
                    ),
                    source_pointers=contradiction.source_pointers,
                )
            )
        self.store.add_event(
            result.investigation_id,
            "cross_source_consistency_checked",
            "Cross-source claims were compared.",
            {
                "contradiction_ids": [
                    item.contradiction_id for item in result.contradictions
                ]
            },
        )
        self.store.add_event(
            result.investigation_id,
            "risk_scored",
            "Deterministic risk score was calculated.",
            result.risk.model_dump(mode="json") if result.risk else {},
        )
        self.store.add_event(
            result.investigation_id,
            "reliability_assessed",
            "Evidence completeness and confidence were assessed.",
            result.reliability.model_dump(mode="json"),
        )
        self.store.add_event(
            result.investigation_id,
            "policy_evaluated",
            "Explicit policy rules were evaluated.",
            (
                result.policy_evaluation.model_dump(mode="json")
                if result.policy_evaluation
                else {}
            ),
        )

    def _persist_record(
        self,
        investigation_id: str,
        kind: str,
        item: dict[str, Any],
    ) -> None:
        pointer = SourcePointer.model_validate(item["source_pointer"])
        self.store.add_evidence(
            EvidenceRecord(
                evidence_id=item["evidence_id"],
                investigation_id=investigation_id,
                kind=kind,
                code=item["code"],
                finding=item["finding"],
                source=item["source"],
                weight=item.get("weight", 0),
                source_pointers=[pointer],
            )
        )

    def _record_verdict(self, result: InvestigationResult) -> None:
        self.store.add_event(
            result.investigation_id,
            "verdict_produced",
            "Decision state was produced from evidence and explicit policy rules.",
            {
                "proposed_decision": result.proposed_decision,
                "decision_state": result.decision_state,
            },
        )

    def _record_failure(
        self,
        investigation_id: str,
        request: InvestigationRequest,
        exc: Exception,
    ) -> InvestigationResult:
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

    def _record_retry(
        self,
        investigation_id: str,
        attempt: RetryAttempt,
    ) -> None:
        self.store.add_event(
            investigation_id,
            "execution_attempt_failed",
            (
                "Transient execution failure; another attempt is scheduled."
                if attempt.retrying
                else "Transient execution failure exhausted the retry budget."
            ),
            {
                "attempt": attempt.attempt,
                "error_type": attempt.error_type,
                "error": attempt.error,
                "retrying": attempt.retrying,
                "next_delay_seconds": attempt.next_delay_seconds,
            },
        )

    @staticmethod
    def _config(investigation_id: str) -> dict[str, Any]:
        return {"configurable": {"thread_id": investigation_id}}

    @staticmethod
    def _review_request(workflow_result: dict[str, Any]) -> ReviewRequest | None:
        interrupts = workflow_result.get("__interrupt__", [])
        if not interrupts:
            return None
        item = interrupts[0]
        value = item.value
        return ReviewRequest(
            interrupt_id=item.id,
            reason=value["reason"],
            proposed_decision=value["proposed_decision"],
            risk_score=value["risk_score"],
            evidence_ids=value.get("evidence_ids", []),
            contradiction_ids=value.get("contradiction_ids", []),
        )


def default_service(
    db_path: str | Path = "provenance-agent.sqlite3",
) -> InvestigationService:
    return InvestigationService(InvestigationStore(db_path))


def default_request(
    input_path: str = "examples/suspicious-build.json",
) -> InvestigationRequest:
    return InvestigationRequest(input_path=input_path, question=DEFAULT_QUESTION)
