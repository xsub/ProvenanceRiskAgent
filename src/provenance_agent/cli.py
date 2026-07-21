from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.markdown import Markdown

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
            "observations": result.get("observations", []),
            "evidence": result.get("evidence", []),
            "explanation": result.get("explanation", ""),
        }
        return json.dumps(payload, indent=2, sort_keys=True)
    return result["report"]


if __name__ == "__main__":
    app()
