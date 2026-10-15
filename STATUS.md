# Project status

Snapshot: 2026-10-15. Release line: 1.0.

The project remains a report-processing CLI: normalization, classification,
combined findings, expiring waivers, build decisions, evidence output and
provider response checklists.

Version 1.0.0 defines the [stable 1.x contract](docs/compatibility.md), schema
evolution and deprecation rules, supported environments and migration from
0.5.0. Existing runtime behavior and document schema identifiers are retained.
Generated CI starters reference the 1.0.0 release. The optional Hub Python
bridge remains experimental; its remediation file exchange remains stable.

The 0.5.0 increment introduced canonical input, Betterleaks 1.x, output collision
preflight, explicit waiver-file requirements and file exports for OPA and
DefectDojo. Earlier PR publication and Remediation Hub features remain available.
The [changelog](CHANGELOG.md) records compatibility changes. Detector corpus
captures and the recorded CLI demonstration describe their historical versions;
they are not fresh execution evidence for a different release candidate.

Distribution uses versioned GitHub Release wheels and source archives. PR posting
requires explicit trusted-repository configuration. Hub writes require an explicit
database and --apply; tracker payloads are a preview. Provider mutation, PyPI,
Jira, ServiceNow, hosted services and a vault remain outside the product scope.

Release validation is recorded by the repository's required release check.
See [CHANGELOG.md](CHANGELOG.md), the [release list](https://github.com/lucashgrifoni/secrets-hygiene-kit/releases)
and the [CI runs](https://github.com/lucashgrifoni/secrets-hygiene-kit/actions/workflows/ci.yml)
for the current published state and execution evidence.

Product validation uses the maintainer's internal pilot with synthetic reports
and owned local consumers. No external participants or production adoption are
claimed. Promotion to a stable contract does not establish complete detector
coverage, absence of secrets or credential remediation.

Known limits: selected metadata may contain sensitive information supplied by
a caller; scanner completion must be enforced by its own step; waiver
approvers are recorded rather than authenticated; combined findings require
matching type, path and line; filesystem guards do not prevent concurrent
destination changes. Betterleaks 2.x envelopes are outside the tested adapter.
DefectDojo reimport requires stable-ID matching; the tested consumer preserves
existing severities, so changed severity needs review. See [integration details](docs/integrations.md).
