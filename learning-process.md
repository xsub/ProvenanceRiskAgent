# Learning Process: Building the Provenance Risk Agent

## 1. Starting Point

The project starts from a practical observation: ALBS Provenance Explorer and
EDGP already contain valuable deterministic security knowledge, but a user has
to know which command to run, which parameters matter, how to join outputs, and
how to translate raw evidence into a decision. At that point the human becomes
the orchestration layer.

The first educational goal is therefore not to build a chatbot. It is to build
a specialized investigation system that can:

- receive a bounded question about a software artifact;
- collect deterministic facts from known source engines;
- separate verified facts from risk-raising evidence;
- apply explicit policy and scoring rules;
- identify missing evidence;
- produce a traceable verdict.

This distinction matters. A language model can help explain or summarize, but
the security result must come from evidence records and deterministic rules.

## 2. Agentic Behavior Without Model Authority

The agent is "agentic" because it has state, tools, routing, and a bounded
investigation goal. It is not agentic because an LLM is allowed to decide what
is true.

In this architecture, agentic behavior lives in:

- workflow state;
- typed tool boundaries;
- evidence normalization;
- risk and policy evaluation;
- completeness and confidence assessment;
- execution trace;
- review routing.

The optional LLM layer is deliberately downstream from the deterministic
analysis. It may narrate, but it must not invent package facts, override risk
scores, decide confidence, or produce unsupported conclusions.

The useful mental model is a specialized security officer. The officer checks
documents, applies rules, writes a verdict, and cites the evidence. The officer
does not become the law, and the verdict is reviewable.

## 3. First MVP Principle: Evidence Before Infrastructure

It is tempting to begin agent projects with queues, workers, distributed
execution, memory stores, and streaming status. Those tools are valuable, but
they do not by themselves make a supply-chain decision trustworthy.

For this MVP, the first reliability requirement is traceability:

- What artifact was investigated?
- Which facts were observed?
- Which findings affected risk?
- Which rule-derived values were produced?
- Which event sequence led to the verdict?

That is why the first persistence layer is a SQLite investigation event log.
It is small, inspectable, easy to run in a container, and sufficient for
restart-safe demo records. A separate SQLite LangGraph checkpointer now stores
paused workflow state.

## 4. Event Log Versus Queue

An event log records what happened. A queue coordinates work that should happen.
They solve different problems.

The MVP needs a durable record more than it needs distributed execution. The
current SQLite store records investigation metadata, ordered events, evidence
records, and final results. This supports auditability and testability without
introducing a broker.

RabbitMQ and Celery become useful when the system must execute many
long-running investigations in background workers, recover unfinished jobs
after process crashes, or distribute work across machines. That is a real
future need, but it is not necessary for the measured MVP workload.

Redis becomes useful for different reasons: cache, live progress pub/sub,
short-lived locks, rate limiting, or as a broker for lightweight worker
systems. Redis should not be the authoritative evidence store.

The trade-off is intentional: the MVP optimizes for clarity and correctness.
Execution infrastructure can be introduced later behind stable service and
store interfaces.

## 5. Implemented MVP

The implemented slice now contains:

- Pydantic contracts for requests, results, risk, completeness, confidence,
  policy, contradictions, reviews, events, evidence, and summaries.
- Stable evidence IDs and source pointers.
- Dedicated deterministic modules for policy, risk, completeness, confidence,
  contradiction detection, and decision routing.
- A service layer that runs the LangGraph workflow and persists the result.
- A SQLite store for investigations, ordered events, evidence records, and a
  separate SQLite checkpointer for review interrupts.
- FastAPI endpoints for health, readiness, examples, evaluation,
  investigations, events, evidence, findings, and review resumption.
- A minimal web UI that displays policy, missing evidence, contradictions,
  stable IDs, trace, and human-review controls.
- Eleven MCP tools over the same deterministic graph used by REST and CLI.
- A ten-case offline golden evaluation suite.
- Dockerfile and Docker Compose packaging.
- Tests for CLI, workflow, service persistence, checkpoints, API, MCP, retry
  semantics, review transitions, and the golden harness.
- A GitHub Actions quality gate across Python 3.11, 3.12, and 3.13.

The primary bundled example is `examples/albs-edgp-risk-case.json`. It is a
small combined fixture that contains ALBS provenance evidence and EDGP
installed-RPM to ALBS artifact matching evidence in one input. This keeps the
MVP self-contained and provides deterministic replay alongside the implemented
live path, which assembles the same normalized result through bounded ALBS,
EDGP, errata, OSV, and SBOM adapters.

This is a complete local MVP, not a production service. It provides the
backbone for deeper production evaluation without losing the core rule: every
material conclusion must be traceable to evidence.

## 6. Reliability Model

The first reliability model separates three concepts that are often conflated:

- Risk: how severe the deterministic findings are.
- Completeness: whether the required evidence categories were present.
- Confidence: how much trust should be placed in the result after considering
  missing evidence, source coverage, failures, and review routing.

This separation prevents a common analytical error. A package with no findings
is not necessarily safe if the investigation lacked the evidence needed to
detect problems. Missing evidence should reduce completeness or confidence, and
may route to `UNKNOWN` or `REVIEW`.

## 7. Docker as a Learning Boundary

The container is part of the learning process because it forces the application
to declare its dependencies, runtime command, exposed port, and persisted data
path.

The current Compose setup starts one app service and stores the SQLite database
under `/data`. This keeps the demonstrator simple while leaving room for later
services:

- PostgreSQL for multi-user persistence;
- Redis for progress/cache/locks;
- RabbitMQ or another broker for distributed work;
- ALBS/EDGP sidecars or service adapters.

Each addition should be justified by a concrete product need rather than added
because it is common in production architectures.

## 8. Stable Evidence Identity

The first extension gives each verified fact and risk finding a stable ID. The
ID is derived from the record kind, code, source schema, record path, and stable
artifact identity. The absolute file path is deliberately excluded, so moving
the same export does not change its evidence identity.

A source pointer records the source system, schema, file, record path, and
artifact subject. This choice increases payload size, but it makes a finding
independently reviewable and prevents reports from depending on prose alone.
The trade-off is that source adapters must expose record-level paths rather
than returning unstructured summaries.

## 9. Separating Analytical Dimensions

Risk, completeness, and confidence were moved into independent modules because
they answer different questions. Risk asks what adverse findings exist.
Completeness asks whether required categories were inspected. Confidence asks
how strongly the available and internally consistent evidence supports the
result.

This separation changes the semantics of a clean result. Zero risk with weak
coverage is no longer equivalent to safety. The decision module can return
`UNKNOWN` when completeness or confidence is too low, even if no risk finding
was emitted. The policy module remains an explicit rulebook and records each
rule result separately from the final decision.

The ALBS validation made this distinction concrete. Provenance lineage can be
complete while security context remains incomplete. The latter requires SBOM
coverage plus a checked errata state, either an advisory relation or an
explicit `confirmed_clean` result. The decision module therefore permits
`ALLOW` only when no required category is missing. Standalone EDGP provenance
or inventory can report zero findings while still routing to `REVIEW` because
it does not establish vulnerability coverage.

## 10. Cross-Source Contradictions

Combined ALBS and EDGP exports may disagree about artifact name, version,
digest, build ID, release ID, or signature state. The contradiction detector
normalizes comparable values, groups claims by category, and emits a stable
contradiction record when distinct values remain.

Contradictions reduce confidence and route the result to `REVIEW`. They do not
silently choose one source as authoritative because that hierarchy has not been
established by policy. This is conservative: it can create extra review work,
but it avoids laundering inconsistent evidence into a precise-looking verdict.

## 11. Human Review as Workflow State

A review requirement is now represented by LangGraph `interrupt()`. The graph
stores state in SQLite, returns an interrupt ID and proposed deterministic
decision, and resumes only after receiving a typed reviewer decision and
rationale. The proposed decision remains visible after resume, so human action
does not erase what the rules originally concluded.

SQLite was selected because the MVP is local and single-service. PostgreSQL
would improve concurrent write behavior and operational tooling, but it would
add deployment cost before concurrency is measured. The checkpoint interface
keeps that migration possible without changing policy semantics.

## 12. Bounded Retry Without a Broker

Transient `TimeoutError`, connection, and operating-system failures use a
bounded retry policy with exponential delay. Each failed attempt is persisted
as an investigation event. Validation errors are not retried because repeating
an invalid contract cannot repair it.

This is intentionally narrower than durable background-job recovery. If jobs
must survive process termination between attempts or run across workers,
RabbitMQ/Celery or another durable execution system becomes justified. Until
that requirement is measured, SQLite remains the source of truth and the retry
loop remains small and inspectable.

## 13. Golden Evaluation as an Executable Argument

The golden suite contains ten representative cases: clean signed input,
missing signature, unknown builder, unresolved vulnerability, incomplete
provenance, contradictory identity, large blast radius, timeout exhaustion,
malformed data, and prompt injection in metadata.

Each case checks decision correctness, expected evidence, missing categories,
contradictions, stable IDs, source pointers, bounded duration, unsupported
terms, and trace presence where applicable. This does not prove production
security. It does provide a repeatable falsification surface: a future change
that violates one of these properties fails locally without private services
or an LLM provider.

## 14. MCP Without Duplicate Semantics

The MCP server exposes normalized capabilities, but every analytical tool calls
the same workflow and source contracts as CLI and REST. This avoids a common
integration failure where each delivery surface develops its own scoring or
policy interpretation.

The default transport is stdio because it has the smallest local deployment
and authentication surface. Standalone SSE and streamable HTTP remain
available. Co-hosting network MCP with REST is deferred until deployment and
authorization requirements are explicit.

## 15. Validation and Remaining Uncertainty

The implementation is validated by unit and integration tests, the golden
suite, real local ALBS PIW fixture generation, EDGP schema validation, agent
execution over both source projects, container build and internal API smoke
tests, and responsive browser checks.

The remaining uncertainty is production-shaped: upstream feed availability and
coverage quality, concurrent users, process-level recovery, stronger source
authenticity, and governed real-world evaluation data. These are the conditions
that may justify PostgreSQL, telemetry, Redis, signed snapshots, or a
distributed queue. Infrastructure should enter only with a measurable failure
mode and an acceptance test.

The academic habit to preserve is simple: every new component should answer
which uncertainty it reduces, which failure mode it handles, and how it keeps
the final verdict reviewable.

## 16. Continuous Integration as Executable Documentation

This implementation step turns local verification commands into a hosted
quality gate. CI is not merely build automation here; it is an executable form
of the project's compatibility and determinism claims. The workflow runs Ruff,
the full pytest suite, and the golden evaluation on every supported Python
minor version from 3.11 through 3.13.

The added retry tests distinguish three failure classes. A transient adapter
failure receives a finite number of attempts with exponential delays. Retry
exhaustion preserves every attempt and the root cause. Contract or validation
errors bypass retry because repetition cannot make malformed evidence valid.
API tests also enforce that a persisted review transition is single-use: once
completed, a second resume request is a conflict rather than a second verdict.

The trade-off is that hosted CI uses bundled, deterministic fixtures and cannot
prove live ALBS/EDGP service availability or advisory freshness. Tests against
the sibling source repositories remain optional local integration checks and
skip when those repositories are absent. This separation keeps CI reproducible
without overstating what it validates.

Keeping the workflow matrix small is deliberate. Python 3.11 is the declared
minimum and 3.12-3.13 detect compatibility drift in current runtimes. Container
smoke testing remains a separate local gate because rebuilding the complete
image on every matrix leg would duplicate cost without adding independent
evidence about the deterministic core.

The local validation run on 2026-07-22 produced 50 passing pytest cases, a
clean Ruff result, and 10/10 passing golden scenarios. Pytest also exposed one
non-fatal deprecation warning at the Starlette/httpx TestClient boundary. It is
recorded rather than suppressed so a future dependency upgrade can remove it
without weakening warning visibility.

The workflow's own dependencies are part of the same supply-chain argument.
Official `checkout` and `setup-python` releases are pinned to complete commit
SHAs rather than mutable major-version tags, while comments retain their human
readable release numbers. This reduces tag-retargeting risk at the cost of
requiring an explicit reviewed update when a new action release is adopted.

The first hosted baseline, GitHub Actions run
[`29882455748`](https://github.com/xsub/ProvenanceRiskAgent/actions/runs/29882455748)
for commit `735cf27`, completed successfully on 2026-07-22. All three Python
jobs passed installation, Ruff, pytest, and the deterministic golden
evaluation. This converts the compatibility statement from a local assumption
into evidence produced by the hosted Linux runner matrix.

## 17. From Export Analysis to Live Acquisition

The post-MVP acquisition boundary starts from capabilities already owned by the
source engines. A live investigation accepts an ALBS build identifier and an
optional package, architecture, and build SBOM. The ALBS adapter invokes the
focused `albs-graph trust-path` command. EDGP runs in a separate process through
a narrow bridge over `AlbsBuildAdapter`, `build_albs_artifact_inventory`, and
`build_public_advisory_feed_report`. Their JSON output remains an internal typed
contract, but the user no longer has to prepare or join export files.

Security context uses two complementary distribution-aware checks. The ALBS
path consumes a validated snapshot of the official AlmaLinux full errata feed
and preserves its three-state result: exact NEVRA present in an advisory,
snapshot consulted without an exact match, or not checked. The agent downloads
that snapshot itself, validates its advisory/package coordinates, records its
SHA-256 digest, and gives ALBS the same temporary file. A separate OSV query
checks the exact AlmaLinux package version and EDGP normalizes the returned
advisory records. Absence of an exact NEVRA in errata is not allowed to erase
OSV findings. A network or parser failure remains incomplete coverage; only a
successful zero-result OSV query is evidence of a clean vulnerability lookup.

The SBOM is validated before it crosses the process boundary. The live ALBS
adapter accepts CycloneDX JSON with a non-empty component inventory, records
its SHA-256 digest, and then requires the ALBS graph to contain a matching SBOM
node and `described_by` relation. Syntax alone is therefore not treated as
coverage. SPDX is not advertised here because the upstream ALBS build-SBOM
adapter currently consumes CycloneDX.

Risk calibration moves out of tool implementations into immutable, versioned
policy profiles. Evidence tools identify findings and severity; a selected
profile supplies weights, score bands, completeness requirements, and decision
thresholds. The compatibility profile preserves the MVP scores, while a strict
profile can raise review sensitivity without changing evidence extraction.

This boundary also changes the correct vocabulary for agent tools. ALBS and
EDGP are not passive databases: they acquire artifacts, apply domain logic, and
produce assessments. The agent therefore does not claim to rediscover those
facts. Its tools `validate` assessment contracts and coverage, `interpret`
domain findings, `derive` bounded cross-source findings, and `evaluate` policy.
This naming records ownership in the interface and helps prevent a subtle
methodological error: treating correlated upstream opinions as independent
facts and counting the same evidence more than once.

## 18. Validation of the Live Boundary

The live boundary adds three distinct validation layers. First, command
construction is tested as an argument vector and never enters a shell. Second,
adapter outputs must match the exact ALBS and EDGP schemas before
normalization. Third, semantic checks decide whether the evidence proves the
claimed coverage: exact artifact identity and freshness for OSV, linked SBOM
evidence for ALBS, and advisory-present or confirmed-clean state for errata.

The OSV error path deserves special attention. Its retry loop may exhaust while
ALBS and EDGP remain available. The workflow preserves the successful
provenance evidence and adds a failed acquisition trace, but leaves
`vulnerability_coverage` and `advisory_freshness` missing. This is a better
degradation mode than failing the whole investigation, and much safer than
turning transport failure into an empty vulnerability set.

Endpoint validation is also part of the trust boundary. Requiring HTTPS protects
transport but does not prevent a REST or MCP caller from directing the service
to an arbitrary internal host. The live request therefore allowlists official
ALBS, AlmaLinux errata, and OSV hosts. Operators can add private mirrors only
through an explicit environment configuration, keeping deployment policy out
of untrusted request bodies.

Two immutable policy profiles are now executable configuration. The default
profile reproduces all ten golden expectations. The strict profile raises
selected finding weights and review thresholds. `calibrate-policy` checks that
strict risk never falls below default risk and that strict cannot return
`ALLOW` where default does not. These checks are not statistical calibration:
they are governance invariants. Production calibration still needs reviewed
real-world labels and an explicit cost model for false positives and false
negatives.

Local verification on 2026-07-22 produced a clean Ruff result, 50 passing
pytest cases, 10/10 passing golden cases, and a passing two-profile calibration
report. The mocked adapter tests exercise command safety, schema validation,
SBOM hashing/linkage, official errata URL selection, OSV normalization,
freshness, truncation semantics, and failure degradation.

The first containerized live run exposed three integration defects that fixture
tests did not reveal. The pinned EDGP package publishes an entry point that
imports a module absent from its wheel, so the application now uses a narrow
process bridge over the installed EDGP library API. EDGP advisory
normalization expands one advisory across affected package rows, so risk
evidence is deduplicated by advisory ID and exact package before scoring.
Finally, EDGP limits build tasks independently from artifacts; increasing only
the artifact limit omitted the selected `x86_64` task and caused an apparent
cross-architecture contradiction. Both limits are now explicit and bounded,
and the normalized inventory is scoped to the ALBS-selected name,
version-release, and architecture.

After those corrections, a real containerized investigation of ALBS build
57810 and `nginx-core-1.26.3-6.el10_2.3.x86_64` completed successfully using
the live ALBS API, the official AlmaLinux 10 errata feed, OSV, EDGP, and a
457-component CycloneDX SBOM. The artifact and SBOM agreed on SHA-256
`300eb6e84d90e76cd26041ae3e3dee83f7d735b3e30d9dd2719dc8b71ad04fef`.
The validated errata snapshot contained 315 advisories and had SHA-256
`93e2436d132896bd80138310c3e9827225db5fb5fd78ec8554d172b7e6ce28b6`.
OSV returned three unique advisory records, no cross-source contradiction
remained, and all seven acquisition stages succeeded. The deterministic result
was `REVIEW`, risk 24/100, completeness 100/100, and confidence 100/100. This
is the intended separation between evidence completeness and artifact safety:
the investigation can be complete while its collected evidence still requires
review.
