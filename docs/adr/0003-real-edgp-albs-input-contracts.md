# ADR 0003: Real EDGP and ALBS Input Contracts

## Status

Accepted.

## Context

The agent must be based on the existing provenance and software-supply-chain
analysis projects, primarily:

- `/Users/pawel/_DEV/SoftwareSupplyChain`
- `/Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer`

Those repositories already define meaningful export contracts. This agent
should consume those contracts as an external adapter instead of inventing a new
provenance core.

## Decision

The agent accepts these source formats:

- `albs-provenance-explorer/v1`
  - Source: ALBS Provenance Explorer graph export.
  - Verified with:
    `/Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer/examples/demo-nginx-core/nginx-core-x86_64-trust.json`.
  - Risk checks use graph relations such as `produces`, `signed_as`,
    `released_to`, `authenticated_by` and `built_by`.

- `edgp.rpm.albs_provenance.v1`
  - Source: EDGP installed-RPM to ALBS artifact provenance report.
  - Verified with the contract fixture:
    `/Users/pawel/_DEV/SoftwareSupplyChain/tests/fixtures/rpm-albs-provenance.json`.
  - Risk checks cover unmatched installed packages, missing CAS hash, unknown
    ALBS build id and missing release id.

- `edgp.albs.artifact_inventory.v1`
  - Source: EDGP ALBS artifact inventory report.
  - Verified with the contract fixture:
    `/Users/pawel/_DEV/SoftwareSupplyChain/tests/fixtures/albs-artifact-inventory.json`.
  - Risk checks cover empty inventory, missing CAS hash and missing build task
    id.

- `edgp.graph.snapshot.v1`
  - Source: EDGP deterministic dependency graph snapshot.
  - Risk checks are currently limited to structural integrity: stats mismatch,
    missing root and dangling edges.

The previous small `artifact/build/policy` JSON remains as a learning fixture
format only. It is not the target ALBS/EDGP contract.

## Consequences

- The agent now runs against real local project contracts from EDGP and ALBS
  Provenance Explorer.
- The ALBS graph path is the strongest provenance-risk input because it carries
  explicit trust-path relations.
- EDGP fixtures validate adapter shape, but they must not be described as
  production ALBS data unless the source export is confirmed.
- Future policy decisions should be negotiated before adding heavier weights for
  missing SBOM, errata coverage, reverse-dependency blast radius or quarantine.
