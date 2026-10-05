# Project status

Snapshot: 2026-10-05. Release target: 0.3.0.

The project remains a report-processing CLI: normalization, classification,
combined findings, expiring waivers, build decisions, evidence output and
provider response checklists.

The previous published version was 0.2.0. The 0.3.0 increment includes
malformed-input handling, metadata hygiene, safer output destinations,
predictable waiver matching, stable SARIF severity IDs and reviewed playbooks.

Distribution uses versioned GitHub Release wheels and source archives. PyPI
publication, automatic PR posting, provider mutation and service integrations
are outside this release.

Release validation is recorded by the repository's required release check.
See [CHANGELOG.md](CHANGELOG.md), the [release list](https://github.com/lucashgrifoni/secrets-hygiene-kit/releases)
and the [CI runs](https://github.com/lucashgrifoni/secrets-hygiene-kit/actions/workflows/ci.yml)
for the current published state and execution evidence.

Known limits: selected metadata may contain sensitive information supplied by
a caller; scanner completion must be enforced by its own step; waiver
approvers are recorded rather than authenticated; combined findings require
matching type, path and line; filesystem guards do not prevent concurrent
destination changes.
