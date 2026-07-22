# Enterprise Linux Provenance Risk Agent Goals

## Vision

Enterprise Linux supply-chain investigations should not require a human to act
as the manual orchestrator for many specialized command-line tools. ALBS
Provenance Explorer and Enterprise Dependency Graph Pipeline (EDGP) already
provide strong deterministic capabilities, but their command surfaces, source
contracts, and cross-tool combinations can become difficult to operate quickly
and consistently.

Enterprise Linux Provenance Risk Agent makes that orchestration layer explicit.
It behaves less like a chatbot and more like a specialized security officer for
software supply-chain evidence: it investigates an artifact, verifies evidence,
applies policy rules, identifies missing or contradictory facts, and produces a
traceable verdict.

The verdict is not an unsupported model opinion. Every material conclusion must
be backed by evidence records and rule results, with enough traceability for a
human or downstream system to accept the result, request review, or route it to
a policy decision.

## Primary Goal

Build a working, container-first agentic application for provenance and risk
analysis based on ALBS Provenance Explorer and EDGP evidence.

The application must answer questions such as:

- Why is this Enterprise Linux artifact risky?
- Which evidence caused the score?
- Is there enough evidence to trust the decision?
- Was the package built by an approved builder?
- Is the artifact signed and traceable to its source?
- Which vulnerabilities, dependency paths, or impact signals affect it?
- Should the artifact be `ALLOW`, `DENY`, `REVIEW`, `UNKNOWN`, or `ERROR`?

## Scope

The agent is an orchestration and presentation layer over deterministic source
engines. It supports reproducible JSON exports and live process adapters for
ALBS Provenance Explorer and EDGP, then exposes the shared workflow through
service, UI, CLI, MCP, and container delivery.

In scope:

- Investigation-question capture and grounded answers; dynamic intent parsing
  and tool selection remain a post-MVP capability.
- Explicit LangGraph workflow state, nodes, routing, retries, and review stops.
- LangChain tools as typed adapter boundaries.
- Deterministic evidence extraction and normalization.
- Deterministic policy evaluation and risk scoring.
- Evidence completeness and confidence assessment.
- Missing-evidence and contradiction detection.
- Grounded explanation generation.
- REST, CLI, MCP, and minimal web UI delivery.
- Container-first MVP demonstration.
- Golden evaluation cases for unsupported claims, failures, and prompt
  injection.

Out of scope for the initial demonstrator:

- Generic chatbot behavior.
- LLM-generated package facts, vulnerabilities, graph relationships, risk
  scores, completeness values, confidence values, or decision states.
- Replacing ALBS Provenance Explorer provenance logic.
- Replacing EDGP graph, dependency, advisory, or impact algorithms.
- Host-level runtime enforcement for downloaded files.
- Kubernetes, fleet endpoint agents, IAM, eBPF, LSM, TPM, or model fine-tuning.

## Source Engine Boundaries

ALBS Provenance Explorer is the provenance and build-evidence engine. The agent
should reuse it for build metadata, artifact lineage, source-to-build
relationships, builder identity, signatures, CAS/integrity evidence, release
provenance, and trust paths.

EDGP is the dependency, graph, repository, SBOM, advisory, and impact-analysis
engine. The agent should reuse it for package/dependency graph ingestion,
reverse dependencies, shortest paths, blast radius, repository diffs,
ALBS/RPM joins, advisory overlays, vulnerability findings, and graph-derived
supply-chain evidence.

In the target architecture, Provenance Risk Agent owns the investigation
layer: user intent, planning, controlled tool selection, workflow state,
evidence normalization, policy evaluation, risk/completeness/confidence
separation, explanation, traceability, and delivery surfaces. The current MVP
implements this boundary with the fixed evidence plan described below.

## Agentic Boundary

Agentic behavior lives in bounded workflow orchestration, not in giving the LLM
authority over the analytical core.

The target boundary allows the agent to:

- interpret a user question;
- build a bounded investigation plan;
- select deterministic tools;
- call ALBS and EDGP adapters with explicit parameters;
- normalize and join evidence;
- detect missing or contradictory facts;
- apply policy rules;
- synthesize a grounded explanation.

The current MVP runs a fixed, bounded evidence plan for every investigation.
It records the question but does not use an LLM to interpret intent or choose
tools. A future planner may add those capabilities without changing the
deterministic analytical boundary.

The LLM may eventually help with intent interpretation and currently supports
explanation, but it must not create, modify, or override:

- evidence records;
- package facts;
- graph relationships;
- vulnerability findings;
- risk weights;
- risk scores;
- evidence completeness;
- confidence;
- policy routing;
- final decision states.

## Decision Model

Risk, evidence completeness, and confidence are separate concepts.

- Risk describes the severity and weight of deterministic findings.
- Completeness describes whether required evidence categories are present.
- Confidence describes how much trust the system can place in the result given
  source quality, failures, contradictions, and missing data.

A low risk score with incomplete evidence must not be presented as proof of
safety. `ALLOW` therefore requires no missing required evidence. ALBS security
context is complete only when SBOM and checked errata coverage are present;
standalone provenance or inventory evidence may remain `REVIEW` even at zero
risk.

Decision states:

- `ALLOW`
- `DENY`
- `REVIEW`
- `UNKNOWN`
- `ERROR`

The built-in profiles currently propose `ALLOW`, `REVIEW`, or `UNKNOWN`.
Operational failures produce `ERROR`; `DENY` is available through explicit
human review and is not inferred by the optional LLM.

The policy layer is the rulebook. Evidence is checked against explicit rules,
and every material conclusion must cite the facts that support it.

## MVP Goal

The MVP is complete when a new user can run:

```bash
docker compose up --build
```

Then open the UI, select a supplied Enterprise Linux artifact, ask why it is
risky, and receive:

- deterministic risk assessment;
- decision state;
- evidence completeness;
- confidence assessment;
- grounded explanation;
- evidence identifiers;
- visible execution trace;
- ALBS provenance evidence and EDGP dependency/advisory/impact evidence in one
  result;
- no unsupported claims in the golden evaluation harness.

## Current MVP

The MVP is implemented with CLI, FastAPI, a minimal web UI, Docker Compose,
MCP, a SQLite investigation event log, and persistent LangGraph checkpoints.
It normalizes supported source contracts, creates stable evidence IDs and
source pointers, detects missing and contradictory evidence, computes separate
risk/completeness/confidence assessments, applies explicit policy rules,
supports human interrupt/resume, and renders Markdown, JSON, REST, UI, or MCP
output.

The current graph executes a fixed evidence plan. The investigation question
is persisted for traceability and presentation but does not yet change tool
selection or workflow topology.

The live extension invokes pinned ALBS/EDGP versions, validates and hashes an
official AlmaLinux errata snapshot, queries the OSV exact-package API, validates
CycloneDX structure and ALBS linkage, and records adapter timing and response
hashes. Failed or stale advisory acquisition reduces completeness instead of
becoming evidence of safety. Immutable policy profiles move risk weights and
decision thresholds out of tool code and expose their version in every result.

Automated verification is implemented in `.github/workflows/ci.yml`. Every
push to `main` and every pull request runs Ruff, pytest, and the deterministic
golden evaluation on Python 3.11, 3.12, and 3.13. This CI scope uses bundled
fixtures and does not claim availability or freshness of external ALBS/EDGP
services.

The primary bundled MVP case is `examples/albs-edgp-risk-case.json`. It uses
the combined fixture schema to evaluate ALBS provenance evidence and EDGP
installed-RPM to ALBS artifact matching evidence in one investigation result.

Supported source contracts:

- `albs-provenance-explorer/v1`
- `edgp.rpm.albs_provenance.v1`
- `edgp.albs.artifact_inventory.v1`
- `edgp.graph.snapshot.v1`
- `edgp.public.advisory_feed.v1`
- `provenance-risk-agent.simple.v1` as a compatibility fixture only.

Current verification commands:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
ruff check .
provenance-agent evaluate-golden
provenance-agent calibrate-policy
```

The 2026-07-22 local baseline is 50 passing pytest cases, Ruff passing, 10/10
golden scenarios passing, and a passing default-versus-strict calibration
report. One upstream Starlette/httpx deprecation warning remains non-fatal.

Container-first smoke path:

```bash
docker compose up --build
```

## MVP Execution Backend Decision

The MVP uses SQLite for the durable investigation event log and LangGraph
checkpoints. This is enough for traceability, restart-safe review state,
evidence persistence, and local demo reliability without introducing
unnecessary distributed infrastructure. Transient execution failures use a
bounded retry policy, and every failed attempt is recorded in the event log.

RabbitMQ, Celery, and Redis are deferred extension points:

- RabbitMQ/Celery make sense when investigations need distributed workers,
  long-running background jobs, durable queue retries, or multi-service
  execution.
- Redis can make sense for cache, live progress pub/sub, short-lived locks,
  rate limiting, or as a lightweight broker for a future worker framework.
- None of them should be the authoritative record of evidence, rules, scores,
  confidence, or verdicts. The investigation store remains the source of truth.

## Quality Principles

- Deterministic evidence first.
- Typed contracts for inputs, evidence, findings, decisions, and reports.
- Provider-independent model configuration.
- Bounded execution for tools, retries, graph steps, latency, and model usage.
- Graceful degradation on missing data, tool failures, timeouts, and
  contradictions.
- Prompt-injection resistance for untrusted package metadata, SBOM text, build
  logs, and filenames.
- Inspectable execution trace for tool calls, evidence, findings, policy
  results, and explanations.
- Testability without private infrastructure or an LLM provider.

## Verified Source Contracts

- `albs-provenance-explorer/v1` from
  `/Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer`.
- `edgp.rpm.albs_provenance.v1` from
  `/Users/pawel/_DEV/SoftwareSupplyChain`.
- `edgp.albs.artifact_inventory.v1` from
  `/Users/pawel/_DEV/SoftwareSupplyChain`.
- `edgp.graph.snapshot.v1` from
  `/Users/pawel/_DEV/SoftwareSupplyChain`.
- `edgp.public.advisory_feed.v1` from
  `/Users/pawel/_DEV/SoftwareSupplyChain`.

## Planning References

- `README.md`
- `docs/planning/initial-demonstrator-plan.md`
- `docs/adr/0001-architecture-boundaries.md`
- `docs/adr/0002-untrusted-provenance-model-input.md`
- `docs/adr/0003-real-edgp-albs-input-contracts.md`
- `docs/adr/0004-operational-coverage-reporting.md`
- `docs/adr/0005-persistent-review-retry-and-mcp.md`
- `docs/adr/0006-live-acquisition-advisory-and-policy-profiles.md`
- `learning-process.md`
- `harness.md`

## Post-MVP Decisions

- Production-governed evaluation data for real ALBS artifacts, reviewed labels,
  and explicit false-positive/false-negative costs.
- Signed advisory/errata snapshots or transparency verification where HTTPS
  and response hashes are insufficient for source authenticity.
- When SQLite checkpoints should move to PostgreSQL for concurrent users.
- Whether MCP streamable HTTP should be co-hosted with REST; the MVP defaults
  to stdio and also supports standalone SSE or streamable HTTP.
- When to introduce Redis, RabbitMQ/Celery, or another worker backend after the
  SQLite event log proves insufficient for concurrency or retry needs.
