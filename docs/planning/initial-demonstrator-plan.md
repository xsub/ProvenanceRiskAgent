# Initial Demonstrator Plan: Enterprise Linux Provenance Risk Agent

## Status

Reviewed planning baseline.

Date: 2026-07-21.

Integration branch: `main`.

## 1. Current-State Assessment

### ProvenanceRiskAgent

Local path: `/Users/pawel/_DEV/ProvenanceRiskAgent`.

Current shape:

- Python package `provenance-risk-agent` with Typer CLI entry point
  `provenance-agent`.
- LangGraph workflow in `src/provenance_agent/workflow.py` with explicit
  nodes for load, observation collection, evidence collection, scoring,
  conditional review routing, explanation, and report rendering.
- LangChain tools in `src/provenance_agent/tools.py` act as deterministic,
  typed boundaries over normalized exports.
- Pydantic models in `src/provenance_agent/models.py` currently cover simple
  artifact/build/dependency/vulnerability/policy records and evidence facts.
- `src/provenance_agent/normalization.py` accepts:
  - `provenance-risk-agent.simple.v1`
  - `albs-provenance-explorer/v1`
  - `edgp.rpm.albs_provenance.v1`
  - `edgp.albs.artifact_inventory.v1`
  - `edgp.graph.snapshot.v1`
- Existing ADRs record deterministic evidence first, untrusted model input,
  real ALBS/EDGP input contracts, and coverage reporting.
- Existing tests verify deterministic CLI/workflow paths and local ALBS/EDGP
  fixture compatibility.

Gaps against the project brief:

- No FastAPI service, web UI, MCP interface, Dockerfile, or Compose setup yet.
- Risk score, risk level, human-review flag, and verified facts exist, but
  decision state, evidence completeness, confidence, contradictions, policy
  profiles, and trace schema are not yet first-class contracts.
- Current workflow analyzes one export at a time. The first vertical slice
  must combine ALBS provenance evidence and EDGP dependency/vulnerability or
  impact evidence for one question.
- Current adapter boundary is file-based JSON only. It should remain for the
  demonstrator, but the plan must leave room for process, HTTP, SQLite, or
  library adapters later.

### ALBS Provenance Explorer

Local path:
`/Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer`.

Current shape:

- Python package `albs-provenance-explorer`, CLI entry point `albs-graph`.
- Read-only provenance graph explorer for ALBS, RPM lineage, SBOM, CAS,
  signatures, errata, source evidence, and trust paths.
- Key modules include:
  - `albs_graph/model/*` for graph nodes and edges.
  - `albs_graph/provenance/trust.py`, `lineage.py`, `coverage.py`,
    `inventory.py`, `reconcile.py`, `vuln.py`, `slsa.py`, and `universe.py`.
  - adapters for ALBS, CAS, DNF, RPM headers/payloads/signatures, SBOM,
    errata, and source evidence.
- Existing example exports include:
  - `examples/demo-nginx-core/nginx-core_x86_64-trust.json`
  - `examples/demo-nginx-core/nginx-core-x86_64-trust.json`
  - `examples/demo-nginx-core/build-17812-full.json`
  - artifact inventory and processing analysis JSON.
- The trust export contract is already consumed by this agent as
  `albs-provenance-explorer/v1`.

Recommended reuse:

- Treat ALBS Provenance Explorer as the authoritative provenance/build evidence
  engine.
- Reuse its exported JSON and, later, its CLI/library boundaries for provenance
  path, build metadata, signature/CAS/release coverage, build comparison, and
  integrity evidence.
- Do not duplicate graph construction, RPM parsing, CAS/signature logic, or
  trust-path derivation inside this agent.

### Enterprise Dependency Graph Pipeline

Local path: `/Users/pawel/_DEV/SoftwareSupplyChain`.

Current shape:

- Python package `unified-dependency-graph`, CLI entry point `edgp`.
- CSR-backed dependency graph prototype with ingestion, query, advisory,
  impact, report bundle, export, validation, ALBS join, and real-data coverage
  commands.
- Key modules include:
  - `src/core_graph/*` for CSR graph operations.
  - `src/adapters/*` for RPM repo, installed RPMs, ALBS, SBOM, DOT, DEB,
    JavaScript, and ecosystem inputs.
  - `src/rpm_albs_provenance.py`, `src/albs_artifact_inventory.py`,
    `src/albs_build_diff.py`, `src/albs_release_completeness.py`,
    `src/impact_report.py`, `src/advisory_overlay.py`, and
    `src/public_advisory_feed.py`.
- Public fixture contracts include:
  - `tests/fixtures/rpm-albs-provenance.json`
  - `tests/fixtures/albs-artifact-inventory.json`
  - `tests/fixtures/snapshot-right.json`
  - advisory, impact, real-data coverage, and report bundle fixtures.

Recommended reuse:

- Treat EDGP as the dependency, graph, repository snapshot, advisory,
  vulnerability overlay, SBOM, ALBS/RPM join, and impact engine.
- Use EDGP outputs for reverse dependencies, blast radius, shortest paths,
  repository diff, advisory/vulnerability overlays, and graph-derived findings.
- Do not reimplement EDGP graph traversal, advisory matching, bundle validation,
  or repository/SBOM ingestion inside this agent.

## 2. Proposed System Boundaries

The agent is the orchestration and presentation layer.

Deterministic responsibilities in this repo:

- Normalize evidence from ALBS and EDGP exports.
- Resolve a user question into an investigation plan.
- Call bounded adapter tools.
- Track workflow state, retries, limits, partial failures, and checkpoints.
- Compute policy findings, risk score, evidence completeness, confidence, and
  final decision state.
- Produce grounded answers with evidence identifiers and an execution trace.
- Serve REST, MCP, CLI, and minimal UI clients from the same typed contracts.

Responsibilities left outside this repo:

- ALBS graph construction, trust path derivation, RPM/CAS/signature/SBOM source
  collection, source-to-build lineage, and build comparison.
- EDGP dependency graph ingestion/traversal, advisory overlays, SBOM export,
  repository diffing, ALBS/RPM joins, and impact analysis.
- Host-level runtime enforcement for downloaded files or package execution.

The LLM may interpret intent, choose a bounded plan, and explain supplied
evidence. It must not create package facts, graph relationships, vulnerability
matches, policy failures, risk scores, completeness values, confidence values,
or decision states.

## 3. Repository and Deployment Topology

Recommended initial topology:

- Keep this repository as the deployable app: `ProvenanceRiskAgent`.
- Consume ALBS/EDGP via versioned JSON fixtures and adapter interfaces for the
  first demonstrator.
- Add optional process adapters that invoke `albs-graph` and `edgp` only after
  their command contracts are pinned and tested.
- Do not vendor or restructure the ALBS/EDGP repositories in the first slice.

Recommended initial packaging:

- Use `docker compose up --build` as the primary demonstrator path.
- Start with one app container exposing FastAPI, the web UI, and MCP on one
  service image.
- Include curated demo fixtures inside the image under an app-owned data path.
- Keep single-image `docker run -p 8080:8080 ...` as a later packaging target
  once fixture paths, static assets, and MCP transport are stable.

Trade-off:

- Compose is slightly heavier for the user, but it gives a clean extension
  point for future checkpointer storage, persistent run state, and optional
  sidecar engines.
- A single image is simpler to run, but premature for the first slice if the app
  still needs to validate how ALBS/EDGP engine adapters are packaged.

## 4. Proposed Domain Models

Add or evolve typed contracts around these concepts:

- `ArtifactIdentity`
  - name, version, release, epoch, arch, purl, digest, source RPM, build ID,
    release ID, ecosystem, source schema, identifiers.
- `EvidenceRecord`
  - stable evidence ID, source system, source schema, source path or URI,
    record path, observed value, subject artifact, timestamp if present,
    trust category, citation label.
- `Finding`
  - stable finding ID, code, title, severity, weight, affected subject,
    evidence IDs, confidence impact, completeness impact, remediation hint.
- `PolicyRule`
  - rule ID, description, profile, deterministic input requirements,
    severity/weight, decision impact.
- `PolicyEvaluation`
  - rule results, failed rules, skipped rules, contradictions, decision state,
    risk score, risk classification.
- `EvidenceCompleteness`
  - required categories, present categories, missing categories,
    contradictory categories, completeness score, explanation.
- `ConfidenceAssessment`
  - confidence score, confidence level, reducers, evidence age/source notes.
- `DecisionState`
  - `ALLOW`, `DENY`, `REVIEW`, `UNKNOWN`, `ERROR`.
- `ToolCallTrace`
  - tool name, adapter, inputs summary, output evidence IDs, status, duration,
    retry count, error class, bounded limit metadata.
- `InvestigationRequest`
  - question, artifact selector, selected fixtures or sources, policy profile,
    model config, execution limits.
- `InvestigationResult`
  - artifact, decision, risk, completeness, confidence, findings, evidence,
    explanation, trace, warnings, unsupported claims if any.

Risk, completeness, and confidence must remain separate fields. A low risk
score with missing provenance, missing advisory coverage, or tool failure should
route to `UNKNOWN` or `REVIEW`, not imply safety.

## 5. Proposed LangGraph State and Nodes

Proposed state keys:

- `request`
- `artifact_identity`
- `investigation_plan`
- `limits`
- `tool_calls`
- `raw_evidence`
- `normalized_evidence`
- `findings`
- `policy_evaluation`
- `risk_assessment`
- `completeness`
- `confidence`
- `decision`
- `contradictions`
- `missing_evidence`
- `explanation`
- `events`
- `errors`
- `requires_approval`
- `resume_token`

Proposed nodes:

1. `parse_request`
   - Interpret the question and artifact selector.
   - Produce a bounded investigation intent, not a final answer.
2. `resolve_artifact_identity`
   - Normalize NEVRA/PURL/digest/build ID/source RPM identifiers.
3. `plan_investigation`
   - Select required evidence categories and adapter calls.
4. `load_provenance_evidence`
   - Use ALBS adapter to retrieve trust/build/signature/CAS/release evidence.
5. `load_dependency_evidence`
   - Use EDGP adapter to retrieve dependency/advisory/impact evidence.
6. `normalize_evidence`
   - Convert source records into `EvidenceRecord` contracts.
7. `detect_missing_evidence`
   - Compare required categories with present evidence.
8. `detect_contradictions`
   - Find identity, build, release, signature, advisory, or dependency
     conflicts across sources.
9. `evaluate_policy`
   - Apply deterministic policy rules to normalized evidence.
10. `score_risk`
    - Compute risk score and risk classification from policy findings.
11. `assess_completeness`
    - Compute evidence completeness separately from risk.
12. `assess_confidence`
    - Compute confidence separately from risk and completeness.
13. `route_decision`
    - Produce `ALLOW`, `DENY`, `REVIEW`, `UNKNOWN`, or `ERROR`.
14. `maybe_interrupt_for_review`
    - Interrupt only for review/approval workflows once checkpointing exists.
15. `synthesize_explanation`
    - Deterministic explanation by default, optional provider-configured LLM.
16. `render_response`
    - Produce API/UI/MCP-safe result with evidence IDs and trace.

Routing rules:

- Tool failure or timeout routes through partial-result handling, not fabricated
  certainty.
- Missing required provenance or advisory evidence can lower completeness and
  confidence without increasing risk.
- Contradictions can route to `REVIEW` or `UNKNOWN` even when risk score is low.
- Deterministic `DENY` or `ALLOW` must come from policy evaluation, not from
  the LLM.

## 6. Proposed Adapter Interfaces

Initial adapter interfaces should be Python protocols or abstract base classes:

```python
class ProvenanceEvidenceAdapter(Protocol):
    def resolve_artifact(self, selector: ArtifactSelector) -> ArtifactIdentity: ...
    def inspect_build_provenance(self, artifact: ArtifactIdentity) -> EvidenceBundle: ...
    def verify_integrity(self, artifact: ArtifactIdentity) -> EvidenceBundle: ...
    def compare_builds(self, left: ArtifactIdentity, right: ArtifactIdentity) -> EvidenceBundle: ...
```

```python
class DependencyIntelligenceAdapter(Protocol):
    def query_dependencies(self, artifact: ArtifactIdentity) -> EvidenceBundle: ...
    def query_reverse_dependencies(self, artifact: ArtifactIdentity) -> EvidenceBundle: ...
    def calculate_blast_radius(self, artifact: ArtifactIdentity) -> EvidenceBundle: ...
    def retrieve_vulnerabilities(self, artifact: ArtifactIdentity) -> EvidenceBundle: ...
    def compare_snapshots(self, left: SnapshotRef, right: SnapshotRef) -> EvidenceBundle: ...
```

```python
class PolicyEngine(Protocol):
    def evaluate(self, evidence: list[EvidenceRecord], profile: str) -> PolicyEvaluation: ...
```

First implementations:

- `FixtureProvenanceAdapter`
  - Reads curated ALBS JSON fixtures.
- `FixtureDependencyAdapter`
  - Reads curated EDGP JSON fixtures.
- `LocalJsonEvidenceRepository`
  - Provides artifact lookup across bundled example cases.

Later implementations:

- `AlbsGraphCliAdapter`
  - Invokes pinned `albs-graph` commands and parses JSON.
- `EdgpCliAdapter`
  - Invokes pinned `edgp` commands and parses JSON.
- `HttpEvidenceAdapter`
  - For future service-backed ALBS/EDGP deployments.

## 7. MCP and REST Boundaries

### MCP

Recommended initial choice: one MCP server exposed by this agent.

Rationale:

- The user-facing product is a synthesis layer, so MCP clients should see
  normalized capabilities and stable evidence IDs instead of raw ALBS/EDGP
  internals.
- A single MCP server keeps policy, trace, completeness, confidence, and
  decision semantics consistent with REST and UI results.
- Separate provenance/dependency MCP servers may be useful later if ALBS or EDGP
  become independently deployable tools, but that should not be required for
  the first demonstrator.

Initial MCP tools:

- `resolve_artifact_identity`
- `inspect_build_provenance`
- `verify_signature_or_integrity`
- `query_dependencies`
- `query_reverse_dependencies`
- `calculate_blast_radius`
- `retrieve_vulnerabilities`
- `evaluate_policy`
- `evaluate_artifact_risk`
- `explain_decision`

MCP is an agent/tool boundary. It should not replace the stable REST API for
web, CLI, local security tooling, or future policy clients.

### REST

Use FastAPI with versioned paths.

Initial endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /api/v1/examples`
- `POST /api/v1/investigations`
- `GET /api/v1/investigations/{id}`
- `GET /api/v1/investigations/{id}/events`
- `GET /api/v1/investigations/{id}/evidence`
- `GET /api/v1/investigations/{id}/findings`
- `POST /api/v1/evaluate`
- `POST /api/v1/investigations/{id}/resume`
- `POST /api/v1/investigations/{id}/approve`

For the first demonstrator, in-memory investigation state is acceptable if the
README clearly says it is non-persistent. Persistent checkpointers should be a
later stage with an ADR choosing SQLite or PostgreSQL.

## 8. Minimal Vertical Slice

Question:

> Why is this Enterprise Linux artifact risky, and is there enough evidence to
> trust the decision?

Recommended demonstration artifact:

- Use `nginx-core` because both local ALBS and EDGP fixtures already contain
  related ALBS/RPM evidence.
- Add a curated negative case in this repo that pairs:
  - ALBS provenance evidence with a missing or failed category; and
  - EDGP vulnerability or reverse-dependency evidence indicating impact.

The slice must:

1. Resolve the artifact from a fixture selector.
2. Load ALBS provenance evidence.
3. Load EDGP dependency/advisory or impact evidence.
4. Normalize both evidence sets into evidence records with stable IDs.
5. Apply deterministic policy rules.
6. Compute risk score and risk classification.
7. Compute evidence completeness separately.
8. Compute confidence separately.
9. Produce a decision state.
10. Generate a grounded explanation with evidence IDs.
11. Return a trace of tools and engines used.
12. Run from `docker compose up --build`.
13. Be covered by an integration test.

First UI behavior:

- Start on the actual investigation screen.
- Let the user select a bundled example artifact.
- Let the user ask the default question.
- Show workflow state, tool calls, evidence, findings, risk, completeness,
  confidence, decision, missing/contradictory evidence, final explanation, and
  compact timeline.

## 9. Test and Evaluation Strategy

Unit tests:

- Domain model validation.
- Evidence normalization from ALBS and EDGP fixtures.
- Policy rule evaluation.
- Risk scoring thresholds.
- Completeness calculation.
- Confidence reducers.
- Contradiction detection.
- Decision routing.
- Prompt-injection handling for untrusted metadata.

Integration tests:

- `POST /api/v1/evaluate` returns the complete vertical-slice result.
- `POST /api/v1/investigations` creates a run and exposes status/events.
- CLI and REST results agree for the same fixture.
- MCP tool `evaluate_artifact_risk` returns the same deterministic result as
  REST.
- Docker Compose smoke test starts the service and passes health/readiness.

Golden evaluation harness:

- Valid signed package from an approved builder.
- Missing signature.
- Unknown builder.
- Unresolved high-severity vulnerability.
- Incomplete provenance.
- Contradictory ALBS/EDGP identity.
- Large reverse-dependency impact.
- Tool timeout.
- Malformed source data.
- Prompt injection inside package metadata.

Metrics to record per golden case:

- Correct tool selection.
- Evidence retrieval completeness.
- Deterministic policy correctness.
- Decision correctness.
- Unsupported-claim detection.
- Contradiction detection.
- Recovery after tool failure.
- Bounded execution.
- Cache behavior when enabled.
- Latency and tool-call count.
- Final-answer grounding.

## 10. Risks and Unresolved Decisions

Risks:

- ALBS and EDGP are currently CLI/library prototypes, so their external
  contracts may change.
- Existing local fixtures may not cover enough negative Enterprise Linux cases
  for credible policy evaluation.
- A low-risk result may be misread as safe unless completeness/confidence and
  decision state are prominent.
- Running upstream CLIs inside the container may complicate packaging because
  ALBS/EDGP have different dependencies and optional system tools.
- Model-generated explanations can still overstate evidence unless the prompt,
  output schema, and tests are strict.

Unresolved decisions:

- Exact default policy profile and risk weights for ALLOW/DENY/REVIEW.
- Whether first persistent checkpoints use SQLite or PostgreSQL.
- Whether MCP uses streamable HTTP, stdio, or both in the demonstrator image.
- Whether process adapters should invoke upstream CLIs in stage 2 or wait until
  the JSON fixture path is complete.
- Which EDGP fixture should be the first authoritative vulnerability/impact
  evidence source for the negative vertical slice.
- How to version and publish bundled fixture provenance.

Assumptions:

- The first demonstrator can use curated local fixtures and still satisfy the
  "integration of both existing engines" requirement if each fixture is traced
  to ALBS/EDGP source contracts.
- Broad implementation should wait for review of this plan, but narrow doc,
  contract, and test scaffolding changes are acceptable.

## 11. Ordered Implementation Stages

### Stage 1: Planning and Contract Baseline

Create or update:

- `docs/planning/initial-demonstrator-plan.md`
- follow-up ADR for MCP topology and deployment topology if accepted.

Acceptance criteria:

- Plan assesses all three repositories.
- Plan defines system boundaries, vertical slice, stages, and acceptance
  criteria.
- No broad implementation is introduced before review.

### Stage 2: Domain Contracts and Fixture Catalog

Create or update:

- `src/provenance_agent/contracts.py`
- `src/provenance_agent/fixtures.py`
- `examples/golden/*.json`
- `tests/test_contracts.py`
- `tests/test_fixture_catalog.py`

Acceptance criteria:

- Artifact, evidence, findings, completeness, confidence, decision, and trace
  contracts are Pydantic models.
- Bundled examples declare source schemas and provenance of fixture data.
- Existing CLI tests still pass.

### Stage 3: Adapter Layer

Create or update:

- `src/provenance_agent/adapters/base.py`
- `src/provenance_agent/adapters/fixture_albs.py`
- `src/provenance_agent/adapters/fixture_edgp.py`
- `tests/test_adapters.py`

Acceptance criteria:

- ALBS and EDGP fixture adapters return normalized evidence bundles.
- Adapter failures return typed partial errors.
- No LLM is needed for adapter tests.

### Stage 4: Policy, Risk, Completeness, Confidence

Create or update:

- `src/provenance_agent/policy.py`
- `src/provenance_agent/risk.py`
- `src/provenance_agent/completeness.py`
- `src/provenance_agent/confidence.py`
- `src/provenance_agent/contradictions.py`
- `tests/test_policy.py`
- `tests/test_completeness.py`
- `tests/test_confidence.py`

Acceptance criteria:

- Risk, completeness, and confidence are separate deterministic outputs.
- Decision states are `ALLOW`, `DENY`, `REVIEW`, `UNKNOWN`, `ERROR`.
- Missing evidence does not silently become low risk.
- Contradictory evidence routes to `REVIEW` or `UNKNOWN`.

### Stage 5: LangGraph Vertical Slice

Create or update:

- `src/provenance_agent/workflow.py`
- `src/provenance_agent/explainer.py`
- `tests/test_vertical_slice.py`

Acceptance criteria:

- One question flows through artifact identity, ALBS evidence, EDGP evidence,
  policy, risk, completeness, confidence, decision, explanation, and trace.
- Result includes evidence IDs for material conclusions.
- Deterministic mode works without an LLM provider.

### Stage 6: FastAPI Service

Create or update:

- `src/provenance_agent/api.py`
- `src/provenance_agent/service.py`
- `tests/test_api.py`

Acceptance criteria:

- Health/readiness endpoints work.
- `POST /api/v1/evaluate` returns a complete deterministic result.
- Investigation create/status/events/evidence endpoints work with in-memory
  state.
- API schemas match Pydantic contracts.

### Stage 7: Minimal Web UI

Create or update:

- `src/provenance_agent/web.py` or static assets under `src/provenance_agent/static/`
- `tests/test_web_smoke.py`

Acceptance criteria:

- Browser UI can select a supplied example artifact and ask the default
  question.
- UI shows risk, completeness, confidence, decision, evidence, findings, missing
  evidence, contradictions, explanation, and trace.
- No complex frontend framework is introduced unless plain server-rendered HTML
  proves insufficient.

### Stage 8: MCP Interface

Create or update:

- `src/provenance_agent/mcp_server.py`
- `tests/test_mcp_contract.py`

Acceptance criteria:

- MCP exposes normalized capabilities for artifact resolution, provenance,
  dependency intelligence, policy evaluation, risk evaluation, and explanation.
- MCP result for the vertical slice matches REST deterministic output.
- MCP transport choice is documented.

### Stage 9: Container Delivery

Create or update:

- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `README.md`
- `tests/test_container_smoke.py` or documented manual smoke command.

Acceptance criteria:

- `docker compose up --build` starts the app.
- UI opens on the investigation screen.
- Vertical-slice example works from inside the container.
- README documents Compose as primary mode and the single-image trade-off.

### Stage 10: Golden Evaluation Harness

Create or update:

- `eval/golden/*.json`
- `eval/run_golden.py`
- `tests/test_golden_eval.py`
- `harness.md`

Acceptance criteria:

- Golden cases cover the required representative scenarios.
- Harness verifies unsupported-claim detection, tool selection, policy,
  decision, completeness, contradictions, bounded execution, and trace.
- Evaluation runs without private infrastructure or an LLM provider.

## 12. Stage-Level Completion Criteria

The initial demonstrator is complete when a new user can run:

```bash
git clone <repository>
cd <repository>
docker compose up --build
```

Then open the UI, select the supplied example artifact, ask why it is risky,
and receive:

- deterministic risk assessment;
- decision state;
- evidence completeness;
- confidence assessment;
- grounded explanation;
- evidence identifiers;
- visible execution trace;
- ALBS provenance evidence and EDGP dependency/advisory/impact evidence in one
  result;
- no unsupported claims in the golden evaluation.
