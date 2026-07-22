# ADR 0005: Persistent Review, Bounded Retry, and MCP Delivery

## Status

Accepted.

## Context

The MVP needs restart-safe human review, traceable handling of transient
failures, and an agent-facing interface. It does not yet need distributed
workers or a network broker.

## Decision

- Use SQLite through `langgraph-checkpoint-sqlite` for persistent LangGraph
  interrupt/resume state.
- Preserve the deterministic proposed decision separately from the submitted
  human decision.
- Retry only transient timeout, connection, and operating-system failures with
  a bounded exponential policy, recording every failed attempt in the event
  log.
- Do not retry contract and validation failures.
- Use one FastMCP server over the same deterministic workflow as REST and CLI.
- Default MCP to stdio; allow standalone SSE and streamable HTTP transports.
- Do not add Redis, RabbitMQ, or Celery to the MVP.

## Consequences

- Human review can survive service object or process restart while SQLite state
  remains available.
- Retry behavior is finite, visible, and testable, but does not provide a
  distributed durable work queue.
- REST, CLI, UI, and MCP share decision semantics.
- PostgreSQL or a broker can be introduced later behind existing boundaries
  when concurrency or process-level recovery becomes a measured requirement.
