from __future__ import annotations

import json
from typing import Any


SYSTEM_PROMPT = """You are a software supply-chain analyst.
Explain only the supplied evidence. Never add vulnerabilities, package facts,
policy requirements, or provenance claims that are absent from the input.
The numeric score and risk level are authoritative deterministic outputs.
Return a compact technical explanation with:
1. conclusion,
2. decisive evidence,
3. recommended next verification step.
"""


def deterministic_explanation(state: dict[str, Any]) -> str:
    evidence = state.get("evidence", [])
    if not evidence:
        return (
            "No policy violations or unresolved vulnerability findings were "
            "detected in the supplied export. Verify source completeness and "
            "signature validity before treating this as an admission decision."
        )
    findings = "; ".join(item["finding"] for item in evidence)
    return (
        f"Risk is {state['risk_level']} ({state['risk_score']}/100). "
        f"Decisive evidence: {findings} "
        "Next step: validate the original provenance and signature records "
        "against their authoritative source."
    )


def llm_explanation(state: dict[str, Any], model_name: str) -> str:
    try:
        from langchain.chat_models import init_chat_model
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import StrOutputParser
    except ImportError as exc:
        raise RuntimeError(
            "LLM mode requires a provider integration, for example: "
            "pip install -e '.[openai]'"
        ) from exc

    model = init_chat_model(model_name, temperature=0)
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", "{payload}"),
    ])
    chain = prompt | model | StrOutputParser()
    payload = json.dumps(
        {
            "artifact": state["export"]["artifact"],
            "risk_score": state["risk_score"],
            "risk_level": state["risk_level"],
            "evidence": state["evidence"],
        },
        indent=2,
    )
    return chain.invoke({"payload": payload})
