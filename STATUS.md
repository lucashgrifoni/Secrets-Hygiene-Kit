# Project status

Snapshot: 2026-10-05. Release target: 0.4.0 Beta.

The project remains a report-processing CLI: normalization, classification,
combined findings, expiring waivers, build decisions, evidence output and
provider response checklists.

The 0.4.0 increment adds optional PR summary publication, a versioned remediation
exchange, an opt-in AppSec Remediation Hub bridge and reports produced by fixed
versions of three detectors. It also permits pytest 9 for development validation.
The 0.3.0 input, waiver, filesystem and SARIF corrections remain covered by tests.

Distribution uses versioned GitHub Release wheels and source archives. PR posting
requires explicit trusted-repository configuration. Hub writes require an explicit
database and --apply; tracker payloads are a preview. Provider mutation, PyPI,
Jira, ServiceNow, hosted services and a vault remain outside the product scope.

Release validation is recorded by the repository's required release check.
See [CHANGELOG.md](CHANGELOG.md), the [release list](https://github.com/lucashgrifoni/secrets-hygiene-kit/releases)
and the [CI runs](https://github.com/lucashgrifoni/secrets-hygiene-kit/actions/workflows/ci.yml)
for the current published state and execution evidence.

Known limits: selected metadata may contain sensitive information supplied by
a caller; scanner completion must be enforced by its own step; waiver
approvers are recorded rather than authenticated; combined findings require
matching type, path and line; filesystem guards do not prevent concurrent
destination changes.
