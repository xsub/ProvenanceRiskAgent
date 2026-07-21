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
restart-safe demo records.

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
future need, but it is not necessary for the first vertical slice.

Redis becomes useful for different reasons: cache, live progress pub/sub,
short-lived locks, rate limiting, or as a broker for lightweight worker
systems. Redis should not be the authoritative evidence store.

The trade-off is intentional: the MVP optimizes for clarity and correctness.
Execution infrastructure can be introduced later behind stable service and
store interfaces.

## 5. Current Vertical Slice

The implemented slice now contains:

- Pydantic contracts for requests, results, reliability, events, evidence, and
  investigation summaries.
- A service layer that runs the LangGraph workflow and persists the result.
- A SQLite store for investigations, ordered events, and evidence records.
- FastAPI endpoints for health, readiness, examples, evaluation,
  investigations, events, and evidence.
- A minimal web UI served by the app.
- Dockerfile and Docker Compose packaging.
- Tests for CLI, workflow, service persistence, and API contracts.

The primary bundled example is `examples/albs-edgp-risk-case.json`. It is a
small combined fixture that contains ALBS provenance evidence and EDGP
installed-RPM to ALBS artifact matching evidence in one input. This keeps the
MVP self-contained while preserving the future adapter boundary: later, the
same combined result can be assembled from live ALBS/EDGP CLI, HTTP, SQLite, or
library adapters.

This is not the full product. It is the first runnable backbone that lets the
project grow without losing the core rule: every material conclusion must be
traceable to evidence.

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

## 8. Next Learning Steps

The next MVP steps should deepen the evidence model before expanding
infrastructure:

1. Give evidence records stable IDs and source pointers.
2. Split policy, risk, completeness, and confidence into dedicated modules.
3. Add contradiction detection across ALBS and EDGP sources.
4. Add golden fixtures for missing signatures, unknown builders, unresolved
   vulnerabilities, incomplete provenance, malformed data, and prompt
   injection.
5. Add a LangGraph interrupt/resume path for human review.
6. Decide whether SQLite remains enough for checkpoints or whether PostgreSQL
   is needed.
7. Introduce Redis or RabbitMQ/Celery only when concurrent background
   investigations or live progress require them.

The academic habit to preserve is simple: every new component should answer
which uncertainty it reduces, which failure mode it handles, and how it keeps
the final verdict reviewable.
