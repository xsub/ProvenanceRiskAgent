from __future__ import annotations

from functools import partial
from langgraph.graph import END, START, StateGraph

from .explainer import deterministic_explanation, llm_explanation
from .models import AnalysisState
from .repository import load_export
from .tools import EVIDENCE_TOOLS, OBSERVATION_TOOLS, expand_tool_exports


def load_node(state: AnalysisState) -> dict:
    export = load_export(state["input_path"])
    return {"export": export}


def collect_evidence_node(state: AnalysisState) -> dict:
    # LangChain tools are typed boundaries. The graph decides when they run.
    evidence: list[dict] = []
    for tool_export in expand_tool_exports(state["export"]):
        export_json = __import__("json").dumps(tool_export)
        for evidence_tool in EVIDENCE_TOOLS:
            result = evidence_tool.invoke({"export_json": export_json})
            evidence.extend(result)
    return {"evidence": evidence}


def collect_observations_node(state: AnalysisState) -> dict:
    observations: list[dict] = []
    for tool_export in expand_tool_exports(state["export"]):
        export_json = __import__("json").dumps(tool_export)
        for observation_tool in OBSERVATION_TOOLS:
            result = observation_tool.invoke({"export_json": export_json})
            observations.extend(result)
    return {"observations": observations}


def score_node(state: AnalysisState) -> dict:
    score = min(100, sum(item["weight"] for item in state["evidence"]))
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
    return {
        "risk_score": score,
        "risk_level": level,
        "requires_review": score >= 50,
    }


def review_node(state: AnalysisState) -> dict:
    # Learning-stage placeholder. Production version should call
    # langgraph.types.interrupt() and resume after a human decision.
    return {
        "explanation": (
            "HUMAN REVIEW REQUIRED. "
            + deterministic_explanation(state)
        )
    }


def explain_node(state: AnalysisState, model_name: str | None) -> dict:
    if model_name:
        explanation = llm_explanation(state, model_name)
    else:
        explanation = deterministic_explanation(state)
    return {"explanation": explanation}


def render_node(state: AnalysisState) -> dict:
    artifact = state["export"]["artifact"]
    lines = [
        f"# Provenance risk report: {artifact['name']}",
        "",
        f"- Source schema: `{state['export']['source_schema']}`",
        f"- Risk: **{state['risk_level']}** ({state['risk_score']}/100)",
        f"- Human review: {'required' if state['requires_review'] else 'not required'}",
        "",
        "## Verified Facts",
    ]
    if artifact.get("version"):
        lines.insert(3, f"- Version: {artifact['version']}")
    if artifact.get("digest"):
        lines.insert(4 if artifact.get("version") else 3, f"- Digest: `{artifact['digest']}`")
    if state.get("observations"):
        for item in state["observations"]:
            lines.append(
                f"- `{item['code']}`: {item['finding']} "
                f"[source: {item['source']}]"
            )
    else:
        lines.append("- No verified facts recorded.")
    lines += ["", "## Risk Evidence"]
    if state["evidence"]:
        for item in state["evidence"]:
            lines.append(
                f"- `{item['code']}` (+{item['weight']}): {item['finding']} "
                f"[source: {item['source']}]"
            )
    else:
        lines.append("- No findings.")
    lines += ["", "## Explanation", "", state["explanation"]]
    return {"report": "\n".join(lines)}


def route_after_score(state: AnalysisState) -> str:
    return "review" if state["requires_review"] else "explain"


def build_graph(model_name: str | None = None):
    builder = StateGraph(AnalysisState)
    builder.add_node("load", load_node)
    builder.add_node("collect_observations", collect_observations_node)
    builder.add_node("collect_evidence", collect_evidence_node)
    builder.add_node("score", score_node)
    builder.add_node("review", review_node)
    builder.add_node("explain", partial(explain_node, model_name=model_name))
    builder.add_node("render", render_node)

    builder.add_edge(START, "load")
    builder.add_edge("load", "collect_observations")
    builder.add_edge("collect_observations", "collect_evidence")
    builder.add_edge("collect_evidence", "score")
    builder.add_conditional_edges(
        "score",
        route_after_score,
        {"review": "review", "explain": "explain"},
    )
    builder.add_edge("review", "render")
    builder.add_edge("explain", "render")
    builder.add_edge("render", END)
    return builder.compile()
