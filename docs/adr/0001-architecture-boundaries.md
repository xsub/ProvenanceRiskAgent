# ADR 0001: Architecture Boundaries for Provenance Risk Agent

## Status

Accepted.

## Context

The project goal is to build a working provenance and risk analysis agent based
on ALBS / Software Supply Chain data. The project must make the architectural
boundary between LangChain and LangGraph explicit while keeping the analytical
core deterministic.

The user-stated direction is:

- Use LangChain as the layer for models, prompts and tools.
- Use LangGraph as the explicit process automaton with stages, state, branches
  and an eventual stop-before-decision capability.
- Build an external adapter over JSON exported from ALBS Provenance Explorer.
- Do not push the LLM into the analytical core.

## Decision

The project will use:

- A documented JSON input contract as the integration boundary for ALBS
  Provenance Explorer exports.
- Deterministic code for evidence extraction, risk scoring and review routing.
- LangChain tools as typed callable boundaries over provenance data.
- LangChain prompt/model composition only for evidence-grounded narration.
- LangGraph to model the workflow state machine, including load, evidence
  collection, scoring, conditional review routing, explanation and report
  rendering.

The LLM must not create, modify or override:

- evidence records,
- risk weights,
- risk scores,
- risk levels,
- policy routing,
- final admission decisions.

## Consequences

- Risk decisions remain auditable and testable without model access.
- The project can run fully locally in deterministic mode.
- LLM failures affect explanation quality, not scoring correctness.
- Real ALBS compatibility depends on obtaining and validating the real export
  schema.
- A future human-review interrupt should be implemented in LangGraph rather than
  hidden in prompt logic.

## Follow-Up ADR Candidates

- ALBS Provenance Explorer export schema and adapter contract.
- Human review interrupt/resume persistence.
- Checkpointer backend selection.
- Risk scoring model and policy vocabulary.
- Evaluation data governance for real artifacts.
