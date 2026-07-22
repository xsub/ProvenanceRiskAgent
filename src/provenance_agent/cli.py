"""Typer command-line interface for the provenance risk agent.

Provides saved and live analysis, policy inspection and calibration, golden
evaluation, API serving, MCP serving, and result rendering commands.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.markdown import Markdown

from .calibration import calibrate_policy_profiles
from .contracts import LiveArtifactRequest
from .execution import RetryExhaustedError, run_with_retry
from .golden import DEFAULT_MANIFEST, run_golden_suite
from .live import LiveAcquisitionError
from .profiles import DEFAULT_POLICY_PROFILE, list_policy_profiles
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
    policy_profile: str = typer.Option(
        DEFAULT_POLICY_PROFILE,
        "--policy-profile",
        help="Versioned policy profile identifier.",
    ),
) -> None:
    """Analyze one provenance export."""
    graph = build_graph(model_name=model)
    result = graph.invoke(
        {"input_path": str(input_path), "policy_profile_id": policy_profile}
    )
    rendered = _render_result(result, format)
    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"Wrote {output}")
    elif format == "json":
        typer.echo(rendered)
    else:
        console.print(Markdown(rendered))


@app.command("analyze-live")
def analyze_live(
    build_id: int = typer.Argument(..., min=1, help="ALBS build identifier."),
    package: str | None = typer.Option(None, help="Package name within the build."),
    arch: str | None = typer.Option(None, help="RPM architecture."),
    sbom: Path | None = typer.Option(
        None,
        exists=True,
        readable=True,
        help="CycloneDX JSON SBOM for deterministic ALBS linkage validation.",
    ),
    ecosystem: str | None = typer.Option(
        None,
        help="OSV ecosystem, e.g. AlmaLinux:9; inferred from EDGP otherwise.",
    ),
    errata_url: str | None = typer.Option(
        None,
        help="HTTPS errata.full.json URL; official AlmaLinux feed by default.",
    ),
    policy_profile: str = typer.Option(
        DEFAULT_POLICY_PROFILE,
        "--policy-profile",
        help="Versioned policy profile identifier.",
    ),
    model: str | None = typer.Option(None, help="Optional LangChain model identifier."),
    output: Path | None = typer.Option(None, help="Write report output."),
    format: Literal["markdown", "json"] = typer.Option("markdown", "--format"),
    refresh: bool = typer.Option(False, help="Refresh adapter caches."),
) -> None:
    """Investigate a live ALBS build with EDGP and OSV enrichment."""
    request = LiveArtifactRequest(
        build_id=build_id,
        package=package,
        arch=arch,
        sbom_path=str(sbom) if sbom else None,
        osv_ecosystem=ecosystem,
        errata_url=errata_url,
        refresh=refresh,
    )
    workflow_input = {
        "live": request.model_dump(mode="json"),
        "policy_profile_id": policy_profile,
    }
    try:
        result = run_with_retry(
            lambda: build_graph(model_name=model).invoke(workflow_input)
        )
    except (LiveAcquisitionError, RetryExhaustedError) as exc:
        typer.echo(f"Live acquisition failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
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
            "policy_profile": result["policy_profile"],
            "acquisition": result.get("acquisition", []),
            "contradictions": result.get("contradictions", []),
            "observations": result.get("observations", []),
            "evidence": result.get("evidence", []),
            "explanation": result.get("explanation", ""),
        }
        return json.dumps(payload, indent=2, sort_keys=True)
    return result["report"]


@app.command("policy-profiles")
def policy_profiles() -> None:
    """List immutable built-in policy profile versions."""
    payload = [
        {
            "identifier": profile.identifier,
            "title": profile.title,
            "description": profile.description,
            "calibration_dataset": profile.calibration_dataset,
        }
        for profile in list_policy_profiles()
    ]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("calibrate-policy")
def calibrate_policy(
    manifest: Path = typer.Option(
        DEFAULT_MANIFEST,
        exists=True,
        readable=True,
        help="Golden dataset used to compare built-in profile versions.",
    ),
) -> None:
    """Validate profile weights and decision monotonicity on the golden suite."""
    result = calibrate_policy_profiles(manifest)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))
    if not result["success"]:
        raise typer.Exit(code=1)


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
