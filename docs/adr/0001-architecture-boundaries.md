# ADR 0001: Architecture Boundaries for Enterprise Linux Provenance Risk Agent

## Status

Accepted.

## Context

The project goal is to build a working provenance and risk analysis agent based
on ALBS Provenance Explorer and Enterprise Dependency Graph Pipeline (EDGP)
evidence. The project must make the architectural boundary between LangChain
and LangGraph explicit while keeping the analytical core deterministic.

The user-stated direction is:

- Use LangChain as the layer for models, prompts and tools.
- Use LangGraph as the explicit process automaton with stages, state, branches
  and a persistent stop-before-decision capability.
- Build external adapters over JSON exported from ALBS Provenance Explorer and
  EDGP.
- Do not push the LLM into the analytical core.

## Decision

The project will use:

- Documented JSON input contracts as the integration boundary for ALBS
  Provenance Explorer and EDGP exports.
- Deterministic code for evidence extraction, risk scoring and review routing.
- LangChain tools as typed callable boundaries over provenance data.
- LangChain prompt/model composition only for evidence-grounded narration.
- LangGraph to model the workflow state machine, including load, evidence
  collection, contradiction detection, scoring, policy, conditional review
  routing, explanation and report rendering.
- SQLite for the investigation event log and LangGraph checkpoints.
- MCP as a normalized agent-facing interface over the same deterministic graph
  used by CLI and REST.

The LLM must not create, modify or override:

- evidence records,
- risk weights,
- risk scores,
- risk levels,
- policy routing,
- final decision states.

## Consequences

- Risk decisions remain auditable and testable without model access.
- The project can run fully locally in deterministic mode.
- LLM failures affect explanation quality, not scoring correctness.
- Real ALBS compatibility depends on obtaining and validating the real export
  schema.
- Human review is an explicit LangGraph interrupt and resumes from a persistent
  checkpoint rather than being hidden in prompt logic.

## Follow-Up ADR Candidates

- ALBS Provenance Explorer and EDGP export schemas and adapter contracts.
- Conditions for moving checkpoints from SQLite to PostgreSQL.
- Risk scoring model and policy vocabulary.
- Evaluation data governance for real artifacts.
