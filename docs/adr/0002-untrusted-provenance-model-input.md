# ADR 0002: Treat Provenance Metadata as Untrusted Model Input

## Status

Accepted.

## Context

The agent consumes package names, build metadata, SBOM-derived text,
vulnerability records and provenance evidence from external supply-chain
systems. Those fields may contain text controlled by package authors, build
systems, mirrors or compromised upstream sources.

The project goal keeps deterministic evidence extraction and scoring outside of
the LLM. The LLM is used only to explain already-computed evidence.

## Decision

All provenance and package metadata passed to an LLM must be treated as
untrusted data, not as instructions.

The explanation prompt must explicitly state that:

- supplied artifact metadata and evidence strings are data;
- model output must not add missing package facts, vulnerabilities, policy
  requirements or provenance claims;
- deterministic score and risk level are authoritative.

Actions such as quarantine, admission, policy override or rejection must remain
outside model-only control and require explicit workflow routing and human
approval where applicable.

## Consequences

- Prompt-injection attempts embedded in package metadata should have a clear
  policy boundary.
- Evidence and score remain the authority for reports.
- Future tools that read build logs, SBOM descriptions or package metadata must
  preserve this boundary.
- This ADR does not by itself prove prompt-injection resistance; adversarial
  tests are still required before making security claims.
