import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from provenance_agent.cli import app


def test_analyze_subcommand_runs_suspicious_fixture():
    runner = CliRunner()
    result = runner.invoke(app, ["analyze", "examples/suspicious-build.json"])

    assert result.exit_code == 0
    assert "Provenance risk report: openssl" in result.output
    assert "Risk: critical" in result.output
    assert "Human review: required" in result.output


def test_analyze_subcommand_runs_real_albs_trust_export():
    path = Path(
        "/Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer/"
        "examples/demo-nginx-core/nginx-core-x86_64-trust.json"
    )
    if not path.exists():
        pytest.skip(f"Missing external ALBS fixture: {path}")

    runner = CliRunner()
    result = runner.invoke(app, ["analyze", str(path)])

    assert result.exit_code == 0
    assert "Provenance risk report: nginx-core" in result.output
    assert "Source schema:" in result.output
    assert "albs-provenance-explorer/v1" in result.output
    assert "ALBS_TRUST_COVERAGE" in result.output


def test_analyze_subcommand_can_emit_json():
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["analyze", "examples/suspicious-build.json", "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["artifact"]["name"] == "openssl"
    assert payload["source_schema"] == "provenance-risk-agent.simple.v1"
    assert payload["risk_score"] == 93
    assert payload["requires_review"] is True
    assert payload["evidence"][0]["code"] == "BUILDER_NOT_ALLOWED"
