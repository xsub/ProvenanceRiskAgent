# Provenance Risk Agent

A compact learning project showing where **LangChain** ends and **LangGraph**
begins in a real software-supply-chain use case.

The program consumes a JSON export from ALBS Provenance Explorer or another
supply-chain graph, gathers deterministic evidence, calculates a deterministic
risk score, and uses an LLM only to explain the evidence. The LLM never invents
or modifies the score.

## Why this project

It is deliberately not a generic chatbot.

It demonstrates:

- LangChain tools as typed adapters over provenance data;
- LangChain prompt/model composition for evidence-grounded explanation;
- LangGraph state, nodes, conditional routing and checkpoints;
- separation of deterministic security logic from probabilistic narration;
- a clean future integration boundary for ALBS Provenance Explorer or EDGP.

## Workflow

```text
START
  |
load_export
  |
collect_evidence       deterministic
  |
score_risk             deterministic
  |
route_by_risk
  |              \
explain          request_review
  |              /
render_report
  |
END
```

A later iteration can replace `request_review` with a LangGraph `interrupt()`
and persist the workflow using SQLite or PostgreSQL checkpoints.

## Input contract

```json
{
  "artifact": {
    "name": "openssl",
    "version": "3.2.2-6.el10",
    "digest": "sha256:..."
  },
  "build": {
    "builder": "albs",
    "signed": true,
    "reproducible": false,
    "source_commit": "abc123"
  },
  "dependencies": [
    {"name": "glibc", "version": "2.39", "direct": true}
  ],
  "vulnerabilities": [
    {"id": "CVE-2026-0001", "severity": "high", "fixed": false}
  ],
  "policy": {
    "allowed_builders": ["albs"],
    "require_signature": true,
    "require_reproducible": false
  }
}
```

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
provenance-agent analyze examples/suspicious-build.json
```

The default mode is fully local and deterministic.

To enable LLM narration:

```bash
pip install -e '.[openai]'
export OPENAI_API_KEY=...
provenance-agent analyze examples/suspicious-build.json \
  --model openai:gpt-4.1-mini
```

The model name is intentionally supplied at runtime. The core workflow does not
depend on one provider.

## Questions this agent can answer later

- Why is this RPM considered risky?
- Which evidence caused the score?
- Did the binary come from an approved builder?
- Is its signature missing or invalid?
- Which unresolved CVEs affect the artifact?
- What changed between two builds?
- Should this artifact be admitted, quarantined, or escalated?

## Production extension points

1. Replace the JSON repository with an ALBS/EDGP HTTP or SQLite adapter.
2. Add graph queries: reverse dependencies, blast radius and provenance paths.
3. Add `interrupt()` before quarantine or policy override.
4. Add a persistent checkpointer.
5. Add LangSmith or OpenTelemetry traces.
6. Build a golden evaluation set of known artifacts and expected evidence.
7. Add prompt-injection defenses: treat package metadata as untrusted data.
