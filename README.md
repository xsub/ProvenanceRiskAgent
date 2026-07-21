# Enterprise Linux Provenance Risk Agent

Enterprise Linux Provenance Risk Agent is a container-first agentic application
for explainable Enterprise Linux artifact risk analysis.

The project is evolving from a compact LangChain/LangGraph learning harness
into a deployable application with a web UI, REST API, MCP interface, typed
evidence contracts, deterministic policy evaluation, and grounded explanations.

The agent consumes evidence from ALBS Provenance Explorer and Enterprise
Dependency Graph Pipeline (EDGP), gathers deterministic provenance and graph
evidence, calculates deterministic risk and policy outputs, and uses an LLM
only for optional explanation. The LLM never invents or modifies package facts,
evidence records, risk scores, completeness, confidence, or decisions.

## New MVP Goal

The MVP goal is a runnable demonstrator where a user can start the application
with:

```bash
docker compose up --build
```

Then open the UI, select a supplied Enterprise Linux artifact, ask why it is
risky, and receive:

- a deterministic risk assessment;
- an explicit decision state;
- evidence completeness;
- confidence assessment;
- grounded explanation with evidence identifiers;
- visible tool and workflow trace;
- evidence integrated from both ALBS Provenance Explorer and EDGP;
- no unsupported claims in the golden evaluation harness.

The first approved planning document is
[`docs/planning/initial-demonstrator-plan.md`](docs/planning/initial-demonstrator-plan.md).

## Why this project

It is deliberately not a generic chatbot.

It demonstrates:

- LangChain tools as typed adapters over provenance data;
- LangChain prompt/model composition for evidence-grounded explanation;
- LangGraph state, nodes, conditional routing and checkpoints;
- separation of deterministic security logic from probabilistic narration;
- a clean future integration boundary for ALBS Provenance Explorer or EDGP.

## Target Architecture

```mermaid
flowchart LR
  user["Browser / CLI / MCP client"]
  api["FastAPI service"]
  mcp["MCP server"]
  graph["LangGraph investigation workflow"]
  planner["Intent parsing and investigation plan"]
  adapters["Controlled adapter tools"]
  albs["ALBS Provenance Explorer<br/>build, lineage, CAS, signatures"]
  edgp["EDGP<br/>dependencies, advisories, impact"]
  evidence["Normalized evidence records"]
  policy["Deterministic policy and risk"]
  completeness["Completeness and confidence"]
  explanation["Grounded explanation<br/>LLM optional"]
  result["Decision, findings, evidence IDs, trace"]
  ui["Minimal web UI"]

  user --> ui
  user --> api
  user --> mcp
  ui --> api
  api --> graph
  mcp --> graph
  graph --> planner
  planner --> adapters
  adapters --> albs
  adapters --> edgp
  albs --> evidence
  edgp --> evidence
  evidence --> policy
  policy --> completeness
  completeness --> explanation
  explanation --> result
  result --> api
  result --> mcp
```

Deterministic code owns evidence retrieval, normalization, policy evaluation,
risk scoring, evidence completeness, confidence, contradictions, and final
decision state. The model may help interpret intent, plan bounded
investigations, and explain already-computed evidence.

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

## MVP Roadmap

1. **Contracts and fixture catalog**
   Add Pydantic contracts for artifact identity, evidence records, findings,
   policy results, decisions, completeness, confidence, and tool traces.
2. **Two-engine vertical slice**
   Answer one question for one supplied artifact using ALBS provenance evidence
   and EDGP dependency, advisory, or impact evidence in the same result.
3. **Policy, risk, completeness, confidence**
   Keep risk, evidence completeness, and confidence as separate deterministic
   outputs. Missing evidence must not be reported as proof of safety.
4. **FastAPI service**
   Add health/readiness, example listing, investigation, event, evidence,
   finding, and direct evaluation endpoints.
5. **Minimal web UI**
   Provide a restrained investigation screen for selecting an artifact, asking
   the default question, and viewing evidence, findings, trace, risk,
   completeness, confidence, and decision.
6. **Docker Compose demonstrator**
   Package the app so `docker compose up --build` starts the UI/API/MCP-ready
   service with curated fixtures.
7. **MCP and golden evaluation**
   Expose normalized investigation capabilities through MCP and add golden
   cases for missing signatures, unknown builders, vulnerabilities, incomplete
   provenance, contradictions, timeouts, malformed data, and prompt injection.

## Input contract

The preferred inputs are real exports from the local EDGP and ALBS projects:

- `albs-provenance-explorer/v1`
- `edgp.rpm.albs_provenance.v1`
- `edgp.albs.artifact_inventory.v1`
- `edgp.graph.snapshot.v1`

The small format below is kept only as a learning fixture and compatibility
input:

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

Programmatic output:

```bash
provenance-agent analyze examples/suspicious-build.json --format json
```

Reports separate verified facts from risk evidence. Verified facts describe
coverage that was present, such as ALBS signature/CAS/release coverage or EDGP
match coverage. Risk evidence is the weighted material that changes the score.

Run against the local ALBS / EDGP project contracts:

```bash
provenance-agent analyze /Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer/examples/demo-nginx-core/nginx-core-x86_64-trust.json
provenance-agent analyze /Users/pawel/_DEV/SoftwareSupplyChain/tests/fixtures/rpm-albs-provenance.json
provenance-agent analyze /Users/pawel/_DEV/SoftwareSupplyChain/tests/fixtures/albs-artifact-inventory.json
```

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
