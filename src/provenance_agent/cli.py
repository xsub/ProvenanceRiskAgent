from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.markdown import Markdown

from .golden import DEFAULT_MANIFEST, run_golden_suite
from .workflow import build_graph

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.callback()
def main() -> None:
    """Provenance risk analysis commands."""


@app.command()
def analyze(
    input_path: Path = typer.Argument(..., exists=True, readable=True),
    model: str | None = typer.Option(
        None,
        help="Optional LangChain model identifier, e.g. openai:gpt-4.1-mini",
    ),
    output: Path | None = typer.Option(None, help="Write report output."),
    format: Literal["markdown", "json"] = typer.Option(
        "markdown",
        "--format",
        help="Output format.",
    ),
) -> None:
    """Analyze one provenance export."""
    graph = build_graph(model_name=model)
    result = graph.invoke({"input_path": str(input_path)})
    rendered = _render_result(result, format)
    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"Wrote {output}")
    elif format == "json":
        typer.echo(rendered)
    else:
        console.print(Markdown(rendered))


def _render_result(result: dict, format: str) -> str:
    if format == "json":
        payload = {
            "artifact": result["export"]["artifact"],
            "source_schema": result["export"]["source_schema"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "requires_review": result["requires_review"],
            "decision_state": result["decision_state"],
            "proposed_decision": result["proposed_decision"],
            "risk": result["risk"],
            "completeness": result["completeness"],
            "confidence": result["confidence"],
            "policy_evaluation": result["policy_evaluation"],
            "contradictions": result.get("contradictions", []),
            "observations": result.get("observations", []),
            "evidence": result.get("evidence", []),
            "explanation": result.get("explanation", ""),
        }
        return json.dumps(payload, indent=2, sort_keys=True)
    return result["report"]


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Bind host."),
    port: int = typer.Option(8080, help="Bind port."),
    db: Path = typer.Option(
        Path("provenance-agent.sqlite3"),
        help="SQLite investigation event log path.",
    ),
) -> None:
    """Start the local UI/API service."""
    os.environ["PROVENANCE_AGENT_DB"] = str(db)
    import uvicorn

    uvicorn.run("provenance_agent.api:app", host=host, port=port)


@app.command("evaluate-golden")
def evaluate_golden(
    manifest: Path = typer.Option(
        DEFAULT_MANIFEST,
        exists=True,
        readable=True,
        help="Golden-suite manifest.",
    ),
) -> None:
    """Run the deterministic offline golden evaluation suite."""
    result = run_golden_suite(manifest)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))
    if not result["success"]:
        raise typer.Exit(code=1)


@app.command("mcp")
def mcp_server(
    transport: Literal["stdio", "sse", "streamable-http"] = typer.Option(
        "stdio",
        help="MCP transport.",
    ),
) -> None:
    """Start the normalized MCP interface."""
    from .mcp_server import run

    run(transport)


if __name__ == "__main__":
    app()
