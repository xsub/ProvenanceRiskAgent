# Project Goals

## Primary Goal

Build a working agent for provenance and risk analysis based on ALBS / Software
Supply Chain data.

The project must demonstrate the architectural difference between:

- LangChain as the layer for models, prompts and tools.
- LangGraph as an explicit process automaton with stages, state, branches and
  the ability to stop before a decision.

The project is an external adapter over JSON exported from ALBS Provenance
Explorer. The LLM must not be pushed into the analytical core.

## Product Boundary

- Input: JSON export from ALBS Provenance Explorer, or a documented compatible
  software-supply-chain export.
- Core analysis: deterministic evidence extraction and deterministic risk
  scoring.
- LLM usage: evidence-grounded explanation only, without changing evidence,
  score or policy decision.
- Workflow: explicit LangGraph state machine with auditable nodes and routing.
- Integration shape: external adapter over exported provenance data, not a
  modification of ALBS analytical internals.
- Reports: distinguish verified coverage facts from risk-raising evidence.

## Verified Source Contracts

- `albs-provenance-explorer/v1` from
  `/Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer`.
- `edgp.rpm.albs_provenance.v1` from
  `/Users/pawel/_DEV/SoftwareSupplyChain`.
- `edgp.albs.artifact_inventory.v1` from
  `/Users/pawel/_DEV/SoftwareSupplyChain`.
- `edgp.graph.snapshot.v1` from
  `/Users/pawel/_DEV/SoftwareSupplyChain`.

## Non-Goals

- Generic chatbot behavior.
- LLM-generated risk scores.
- LLM-driven policy decisions.
- Hidden provenance fetches or undocumented data sources.
- Fake production evidence. If real provenance data is needed, request the
  source export from the user.

## Open Architectural Questions

- Exact ALBS Provenance Explorer JSON export schema and version.
- Whether persisted LangGraph checkpoints should use SQLite or PostgreSQL.
- The interrupt/resume contract for human review.
- Admission decision vocabulary: admit, quarantine, escalate, reject, or another
  project-specific set.
- Evaluation data source for real ALBS artifacts and expected evidence.
- Whether missing SBOM or errata coverage should affect admission risk, and with
  what weight.
