# Project Harness

This file defines the repeatable local harness for Enterprise Linux Provenance
Risk Agent work.

## Current Commands

Create an environment and install the project:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

Run tests:

```bash
pytest -q
```

Run linting:

```bash
ruff check .
```

Run the ten-case deterministic evaluation:

```bash
provenance-agent evaluate-golden
```

## Continuous Integration

GitHub Actions repeats the deterministic quality gates on Python 3.11, 3.12,
and 3.13 for pushes to `main` and pull requests:

```bash
ruff check .
pytest -q
provenance-agent evaluate-golden
```

CI intentionally uses only repository fixtures. Tests that inspect sibling
ALBS/EDGP working copies skip when those external repositories are absent, so
the hosted workflow stays reproducible while local integration validation
remains available.

Inspect the MCP contract:

```bash
provenance-agent mcp --transport stdio
```

Run the deterministic CLI path:

```bash
provenance-agent analyze examples/clean-build.json
provenance-agent analyze examples/suspicious-build.json
provenance-agent analyze examples/suspicious-build.json --format json
```

Run against local ALBS/EDGP project contracts:

```bash
provenance-agent analyze /Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer/examples/demo-nginx-core/nginx-core-x86_64-trust.json
provenance-agent analyze /Users/pawel/_DEV/SoftwareSupplyChain/tests/fixtures/rpm-albs-provenance.json
provenance-agent analyze /Users/pawel/_DEV/SoftwareSupplyChain/tests/fixtures/albs-artifact-inventory.json
```

Run with optional LLM narration:

```bash
pip install -e '.[openai]'
export OPENAI_API_KEY=...
provenance-agent analyze examples/suspicious-build.json --model openai:gpt-4.1-mini
```

## Harness Rules

- Treat `ProjectGoals.md` as the product and architecture goal source.
- Record architectural decisions as ADRs under `docs/adr/`.
- Do not create synthetic production evidence. Use project fixtures only for
  code-level tests and request real ALBS/EDGP exports for validation claims.
- Verify claims against code, tests or source data before treating them as
  facts.
- Keep deterministic evidence extraction and scoring independent from LLM
  narration.
- Do not add AI co-author metadata to commits or documents.

## Current Verification Scope

The current local harness can verify:

- JSON export loading and validation.
- Deterministic evidence extraction.
- Deterministic risk scoring.
- Stable evidence IDs and source pointers.
- Separate risk, completeness, confidence, and policy results.
- Cross-source contradiction detection.
- Persistent LangGraph interrupt/resume behavior.
- Bounded retry exhaustion and attempt traces.
- Exponential retry timing, retry-budget validation, and no retry for invalid
  source contracts.
- Single-use human review transitions and API conflict handling.
- ALBS Provenance Explorer graph export support.
- EDGP RPM-to-ALBS provenance report support.
- EDGP ALBS artifact inventory report support.
- Operational coverage facts in reports.
- JSON output for programmatic consumption.
- REST/MCP deterministic result agreement.
- Ten offline golden scenarios, including malformed and hostile metadata.
- Container build, health/readiness, and combined ALBS/EDGP evaluation.
- Python 3.11-3.13 CI execution of lint, pytest, and golden evaluation.

The current local harness does not claim to verify:

- production ALBS feed coverage beyond local exports;
- live advisory freshness or production CVE completeness;
- multi-process checkpoint concurrency or distributed worker recovery;
- model-provider behavior when optional LLM narration is enabled.
