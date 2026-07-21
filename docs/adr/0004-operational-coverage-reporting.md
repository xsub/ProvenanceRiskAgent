# ADR 0004: Operational Coverage Reporting

## Status

Accepted.

## Context

The first useful real-data runs against ALBS and EDGP exports often produce
`risk_score = 0` because the configured deterministic checks find no
risk-raising evidence. That is correct, but operationally weak: a user still
needs to know what was actually checked.

For provenance analysis, "no findings" must not look like an empty analysis.

## Decision

Reports will separate:

- verified facts: deterministic coverage observations that do not affect risk;
- risk evidence: deterministic findings with weights that affect risk score.

Examples of verified facts:

- ALBS binary RPM count, build task count and source package count;
- ALBS release/signature/artifact-CAS/source-CAS coverage;
- EDGP installed-RPM to ALBS match coverage;
- EDGP artifact inventory coverage;
- EDGP graph snapshot node/edge/root summary.

The CLI also supports `--format json` for programmatic use. JSON output exposes
artifact, source schema, score, level, review flag, verified facts, risk
evidence and explanation, but not the full raw input export.

## Consequences

- A clean ALBS/EDGP run becomes useful: it shows what evidence was present.
- Positive facts remain distinct from risk evidence and do not change scoring.
- The result can be consumed by scripts, CI or future UI code without scraping
  Rich-rendered Markdown.
- This still does not mean "safe to admit"; admission remains a policy decision.
