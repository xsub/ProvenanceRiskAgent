# Enterprise Linux Provenance Risk Agent Goals

## Primary Goal

Build a working agent for provenance and risk analysis based on ALBS Provenance
Explorer and Enterprise Dependency Graph Pipeline (EDGP) evidence.

The project must demonstrate the architectural difference between:

- LangChain as the layer for models, prompts and tools.
- LangGraph as an explicit process automaton with stages, state, branches and
  the ability to stop before a decision.

The project is an orchestration and presentation layer over deterministic
source engines. It starts with external adapters over JSON exported from ALBS
Provenance Explorer and EDGP. The LLM must not be pushed into the analytical
core.

## Product Boundary

- Input: JSON exports from ALBS Provenance Explorer, EDGP, or a documented
  compatible software-supply-chain export.
- Core analysis: deterministic evidence extraction and deterministic risk
  scoring.
- LLM usage: evidence-grounded explanation only, without changing evidence,
  score, evidence completeness, confidence, or policy decision state.
- Workflow: explicit LangGraph state machine with auditable nodes and routing.
- Integration shape: external adapters over exported evidence data, not a
  modification of ALBS or EDGP analytical internals.
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

- Exact ALBS Provenance Explorer and EDGP JSON export schemas and versions.
- Whether persisted LangGraph checkpoints should use SQLite or PostgreSQL.
- The interrupt/resume contract for human review.
- Exact policy profiles and risk weights for `ALLOW`, `DENY`, `REVIEW`,
  `UNKNOWN`, and `ERROR`.
- Evaluation data source for real ALBS artifacts and expected evidence.
- Whether missing SBOM or errata coverage should affect evidence completeness,
  confidence, risk, or only decision routing, and with what weight.
