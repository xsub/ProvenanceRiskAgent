from __future__ import annotations

from pathlib import Path
import typer
from rich.console import Console
from rich.markdown import Markdown

from .workflow import build_graph

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command()
def analyze(
    input_path: Path = typer.Argument(..., exists=True, readable=True),
    model: str | None = typer.Option(
        None,
        help="Optional LangChain model identifier, e.g. openai:gpt-4.1-mini",
    ),
    output: Path | None = typer.Option(None, help="Write Markdown report."),
) -> None:
    """Analyze one provenance export."""
    graph = build_graph(model_name=model)
    result = graph.invoke({"input_path": str(input_path)})
    report = result["report"]
    if output:
        output.write_text(report, encoding="utf-8")
        console.print(f"Wrote {output}")
    else:
        console.print(Markdown(report))


if __name__ == "__main__":
    app()
