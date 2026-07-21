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
pytest
```

Run linting:

```bash
ruff check .
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
- LangGraph routing between explanation and review paths.
- ALBS Provenance Explorer graph export support.
- EDGP RPM-to-ALBS provenance report support.
- EDGP ALBS artifact inventory report support.
- Operational coverage facts in reports.
- JSON output for programmatic consumption.

The current local harness does not yet verify:

- Persistent LangGraph checkpointing.
- Human interrupt/resume behavior.
- Prompt-injection hardening against hostile package metadata.
- Production ALBS feed coverage beyond the local demo export.
