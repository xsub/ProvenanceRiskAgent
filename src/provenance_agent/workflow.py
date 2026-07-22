from __future__ import annotations

import json
from functools import partial
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from .completeness import assess_completeness
from .confidence import assess_confidence
from .contracts import (
    CompletenessAssessment,
    ConfidenceAssessment,
    Contradiction,
    LiveArtifactRequest,
    RiskAssessment,
)
from .contradictions import detect_contradictions
from .decision import decide
from .evidence import enrich_record
from .explainer import deterministic_explanation, llm_explanation
from .models import AnalysisState
from .live import LiveAcquirer
from .normalization import SIMPLE_SCHEMA
from .policy import evaluate_policy
from .profiles import PolicyProfile, load_policy_profile
from .repository import load_export
from .risk import assess_risk
from .tools import EVIDENCE_TOOLS, OBSERVATION_TOOLS, expand_tool_exports


def load_node(state: AnalysisState) -> dict[str, Any]:
    profile = load_policy_profile(state.get("policy_profile_id", "enterprise-linux-default@1.0.0"))
    if state.get("live"):
        export = LiveAcquirer.from_environment().acquire(
            LiveArtifactRequest.model_validate(state["live"]),
            advisory_max_age_seconds=profile.advisory_max_age_seconds,
        )
    else:
        export = load_export(state["input_path"])
    return {
        "export": export,
        "policy_profile": profile.model_dump(mode="json", by_alias=True),
        "acquisition": export.get("acquisition", []),
    }


def collect_evidence_node(state: AnalysisState) -> dict[str, Any]:
    # LangChain tools are typed boundaries. The graph decides when they run.
    evidence: list[dict[str, Any]] = []
    profile = PolicyProfile.model_validate(
        state.get("policy_profile") or load_policy_profile().model_dump(by_alias=True)
    )
    for tool_export in expand_tool_exports(state["export"]):
        export_json = json.dumps(tool_export)
        for evidence_tool in EVIDENCE_TOOLS:
            result = evidence_tool.invoke({"export_json": export_json})
            for item in result:
                item["weight"] = profile.weight_for(item)
                evidence.append(
                    enrich_record(item, export=tool_export, kind="risk_evidence")
                )
    return {"evidence": evidence}


def collect_observations_node(state: AnalysisState) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    for tool_export in expand_tool_exports(state["export"]):
        export_json = json.dumps(tool_export)
        for observation_tool in OBSERVATION_TOOLS:
            result = observation_tool.invoke({"export_json": export_json})
            observations.extend(
                enrich_record(item, export=tool_export, kind="verified_fact")
                for item in result
            )
    return {"observations": observations}


def detect_contradictions_node(state: AnalysisState) -> dict[str, Any]:
    contradictions = detect_contradictions(state["export"])
    return {
        "contradictions": [item.model_dump(mode="json") for item in contradictions]
    }


def risk_node(state: AnalysisState) -> dict[str, Any]:
    risk = assess_risk(
        state.get("evidence", []),
        PolicyProfile.model_validate(state["policy_profile"]),
    )
    return {
        "risk": risk.model_dump(mode="json"),
        "risk_score": risk.score,
        "risk_level": risk.level,
    }


def completeness_node(state: AnalysisState) -> dict[str, Any]:
    completeness = assess_completeness(
        state["export"],
        _contradictions(state),
    )
    return {"completeness": completeness.model_dump(mode="json")}


def confidence_node(state: AnalysisState) -> dict[str, Any]:
    confidence = assess_confidence(
        CompletenessAssessment.model_validate(state["completeness"]),
        _contradictions(state),
        compatibility_fixture=state["export"]["source_schema"] == SIMPLE_SCHEMA,
    )
    return {"confidence": confidence.model_dump(mode="json")}


def policy_node(state: AnalysisState) -> dict[str, Any]:
    evaluation = evaluate_policy(
        risk=RiskAssessment.model_validate(state["risk"]),
        completeness=CompletenessAssessment.model_validate(state["completeness"]),
        contradictions=_contradictions(state),
        profile=PolicyProfile.model_validate(state["policy_profile"]),
    )
    return {"policy_evaluation": evaluation.model_dump(mode="json")}


def decision_node(state: AnalysisState) -> dict[str, Any]:
    proposed = decide(
        risk=RiskAssessment.model_validate(state["risk"]),
        completeness=CompletenessAssessment.model_validate(state["completeness"]),
        confidence=ConfidenceAssessment.model_validate(state["confidence"]),
        contradictions=_contradictions(state),
        profile=PolicyProfile.model_validate(state["policy_profile"]),
    )
    return {
        "proposed_decision": proposed,
        "decision_state": proposed,
        "requires_review": proposed == "REVIEW",
    }


def review_node(
    state: AnalysisState,
    *,
    interrupt_reviews: bool,
) -> dict[str, Any]:
    if not interrupt_reviews:
        return {}
    response = interrupt(
        {
            "reason": "Policy evaluation requires a human decision.",
            "proposed_decision": state["proposed_decision"],
            "risk_score": state["risk_score"],
            "evidence_ids": [
                item["evidence_id"]
                for item in state.get("evidence", [])
                if item.get("evidence_id")
            ],
            "contradiction_ids": [
                item["contradiction_id"]
                for item in state.get("contradictions", [])
            ],
        }
    )
    return {
        "human_review": response,
        "decision_state": str(response["decision"]),
    }


def explain_node(state: AnalysisState, model_name: str | None) -> dict[str, Any]:
    if model_name:
        explanation = llm_explanation(state, model_name)
    else:
        explanation = deterministic_explanation(state)
    return {"explanation": explanation}


def render_node(state: AnalysisState) -> dict[str, Any]:
    artifact = state["export"]["artifact"]
    completeness = CompletenessAssessment.model_validate(state["completeness"])
    confidence = ConfidenceAssessment.model_validate(state["confidence"])
    lines = [
        f"# Provenance risk report: {artifact['name']}",
        "",
        f"- Source schema: `{state['export']['source_schema']}`",
        f"- Policy profile: `{PolicyProfile.model_validate(state['policy_profile']).identifier}`",
        f"- Decision: **{state['decision_state']}**",
        f"- Proposed decision: **{state['proposed_decision']}**",
        f"- Risk: **{state['risk_level']}** ({state['risk_score']}/100)",
        f"- Completeness: **{completeness.score}%**",
        f"- Confidence: **{confidence.level}** ({confidence.score}%)",
        f"- Human review: {'required' if state['requires_review'] else 'not required'}",
        "",
        "## Verified Facts",
    ]
    if artifact.get("version"):
        lines.insert(3, f"- Version: {artifact['version']}")
    if artifact.get("digest"):
        lines.insert(4 if artifact.get("version") else 3, f"- Digest: `{artifact['digest']}`")
    if state.get("observations"):
        lines.extend(_record_line(item) for item in state["observations"])
    else:
        lines.append("- No verified facts recorded.")

    lines += ["", "## Risk Evidence"]
    if state.get("evidence"):
        lines.extend(_record_line(item, include_weight=True) for item in state["evidence"])
    else:
        lines.append("- No risk-raising findings.")

    lines += ["", "## Contradictions"]
    if state.get("contradictions"):
        lines.extend(
            f"- `{item['contradiction_id']}` `{item['code']}`: {item['message']}"
            for item in state["contradictions"]
        )
    else:
        lines.append("- No cross-source contradictions detected.")

    lines += ["", "## Missing Evidence"]
    if completeness.missing_categories:
        lines.extend(f"- `{category}`" for category in completeness.missing_categories)
    else:
        lines.append("- None.")
    lines += ["", "## Explanation", "", state["explanation"]]
    return {"report": "\n".join(lines)}


def route_after_decision(state: AnalysisState) -> str:
    return "review" if state["requires_review"] else "explain"


def build_graph(
    model_name: str | None = None,
    *,
    checkpointer: Any | None = None,
    interrupt_reviews: bool = False,
):
    builder = StateGraph(AnalysisState)
    builder.add_node("load", load_node)
    builder.add_node("collect_observations", collect_observations_node)
    builder.add_node("collect_evidence", collect_evidence_node)
    builder.add_node("detect_contradictions", detect_contradictions_node)
    builder.add_node("assess_risk", risk_node)
    builder.add_node("assess_completeness", completeness_node)
    builder.add_node("assess_confidence", confidence_node)
    builder.add_node("evaluate_policy", policy_node)
    builder.add_node("decide", decision_node)
    builder.add_node(
        "review",
        partial(review_node, interrupt_reviews=interrupt_reviews),
    )
    builder.add_node("explain", partial(explain_node, model_name=model_name))
    builder.add_node("render", render_node)

    builder.add_edge(START, "load")
    builder.add_edge("load", "collect_observations")
    builder.add_edge("collect_observations", "collect_evidence")
    builder.add_edge("collect_evidence", "detect_contradictions")
    builder.add_edge("detect_contradictions", "assess_risk")
    builder.add_edge("assess_risk", "assess_completeness")
    builder.add_edge("assess_completeness", "assess_confidence")
    builder.add_edge("assess_confidence", "evaluate_policy")
    builder.add_edge("evaluate_policy", "decide")
    builder.add_conditional_edges(
        "decide",
        route_after_decision,
        {"review": "review", "explain": "explain"},
    )
    builder.add_edge("review", "explain")
    builder.add_edge("explain", "render")
    builder.add_edge("render", END)
    return builder.compile(checkpointer=checkpointer)


def _contradictions(state: AnalysisState) -> list[Contradiction]:
    return [
        Contradiction.model_validate(item)
        for item in state.get("contradictions", [])
    ]


def _record_line(item: dict[str, Any], *, include_weight: bool = False) -> str:
    weight = f" (+{item['weight']})" if include_weight else ""
    record_path = item.get("source_pointer", {}).get("record_path", item["source"])
    return (
        f"- `{item['evidence_id']}` `{item['code']}`{weight}: {item['finding']} "
        f"[source: {record_path}]"
    )
