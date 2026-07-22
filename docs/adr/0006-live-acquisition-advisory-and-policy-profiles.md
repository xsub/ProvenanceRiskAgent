# ADR 0006: Live Acquisition, Advisory Coverage, and Policy Profiles

- Status: accepted
- Date: 2026-07-22

## Context

The MVP required users to export ALBS/EDGP JSON before an investigation. That
made reproducible tests easy but left the operator responsible for selecting
commands, joining identities, choosing feeds, and deciding whether an empty
vulnerability result meant clean coverage or a failed lookup. Risk weights
were also embedded in code, so changing review sensitivity had no governed,
versioned boundary.

## Decision

The agent invokes ALBS Provenance Explorer and EDGP through subprocess adapters
with argument arrays, bounded time/output, JSON schema checks, and no shell.
ALBS uses its CLI. EDGP uses a narrow bridge over its published adapter and
normalizer modules because the pinned upstream wheel's monolithic `edgp` entry
point imports an unpackaged `scripts` module. The container installs both
projects from immutable Git revisions. Live endpoint hosts are restricted to
the official services unless an operator explicitly allowlists a private
mirror, limiting server-side request-forgery exposure through REST or MCP.

EDGP inventory runs first so the AlmaLinux major version can be inferred. The
agent then downloads the matching official `errata.full.json`, validates its
advisory and package-coordinate structure, records its response hash, and gives
ALBS the same temporary snapshot. ALBS remains the authority for provenance,
CAS, signature, release, SBOM linkage, and exact-NEVRA errata association. OSV
is queried for the exact package/version and EDGP normalizes complete OSV
records into `edgp.public.advisory_feed.v1`.

A successful zero-result OSV query establishes vulnerability lookup coverage.
A timeout, parser error, truncation, stale response, or artifact mismatch leaves
coverage incomplete. It is never converted into a clean result.

CycloneDX SBOMs receive a bounded structural preflight and a SHA-256 digest.
Coverage is recognized only if the returned ALBS graph contains a matching SBOM
node and `described_by` edge. Errata coverage similarly requires an advisory
edge or ALBS `confirmed_clean` state after consulting the validated snapshot.
That state proves the exact-NEVRA lookup was performed; it does not override
vulnerability findings from the separate exact-version OSV query.

Risk weights, bands, advisory freshness, and decision thresholds live in
immutable profile documents identified by `profile_id@semver`. The default
profile preserves the MVP golden baseline; the strict profile is calibrated by
executable monotonicity checks.

## Consequences

- Users can investigate a build ID through UI, REST, CLI, or MCP without
  preparing JSON exports.
- Saved exports remain supported for deterministic replay and CI.
- ALBS/EDGP/OSV failures are distinguishable from successful clean checks.
- A profile change is explicit in every result and can be reviewed as data.
- Live operation now depends on external service availability and container
  build access to the pinned source repositories.
- HTTPS and response hashes provide transport integrity and traceability, but
  do not replace signed feed snapshots or transparency proofs.
