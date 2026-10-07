# Secrets Hygiene Kit

[![CI](https://github.com/lucashgrifoni/secrets-hygiene-kit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/lucashgrifoni/secrets-hygiene-kit/actions/workflows/ci.yml)

[0.5.0 beta](https://github.com/lucashgrifoni/secrets-hygiene-kit/releases/tag/v0.5.0)
· Python 3.12 / 3.13 / 3.14 · [Apache-2.0](LICENSE)

**Turn secret-scanner reports into consistent CI decisions and response guidance.**

Secrets Hygiene Kit is a Python CLI, `secguard`, for development and AppSec teams
working with Gitleaks, Betterleaks, TruffleHog and detect-secrets. It combines their findings,
applies expiring exceptions and produces reports that reviewers can act on.

Detection runs in your scanner. Credential changes remain with the authorized
responder. secguard processes reports locally and never contacts a credential provider.

[Install](#install-050) · [Quickstart](#quickstart) · [CLI](#cli-reference) ·
[CI integration](#ci-integration) · [Documentation](#documentation)

## See it work

![secguard evaluates constructed reports: BLOCK, then PASS](docs/images/secguard-demo.png)

This capture shows the installed 0.4.0 CLI processing constructed scanner reports.
Five observations become three findings; the gate blocks on two active findings.
A second scenario contains only the fixture covered by a valid exception and passes.
The demonstration also checks that an expired waiver blocks.

[Run the example](docs/demo.md) to inspect the JSON, SARIF, Markdown and remediation
exports. No credential provider is contacted; the example does not revoke or rotate credentials.

## What it does

| Capability | Result |
| --- | --- |
| Normalize scanner reports | Canonical findings from Gitleaks, Betterleaks 1.x, TruffleHog and detect-secrets |
| Reprocess canonical JSON | Reapply the selected catalog and waiver policy to `secguard.findings/v1` input |
| Combine detector evidence | Findings at the same type, path and line retain the strongest severity and every contributing rule |
| Enforce exception policy | Expiring waivers, partial-scope notices and a blocking decision for expired waivers |
| Evaluate a CI threshold | Predictable exit codes for passing, blocking and processing errors |
| Export review artifacts | JSON, SARIF 2.1.0, Markdown and a PR comment draft |
| Publish a PR summary | Optional counts-only comment with trusted repository checks and idempotent updates |
| Hand off remediation | An active-only exchange and an opt-in bridge to AppSec Remediation Hub |
| Evaluate an external policy | Reconciled OPA input and a packaged Rego v1 example |
| Import into DefectDojo | Generic Findings Import JSON with stable identifiers and explicit triage semantics |
| Support incident response | 13 provider and secret-type playbooks, incident checklists and review-date checks |
| Set up a repository | Pre-commit and GitHub/GitLab CI starters that preserve existing files |

The adapters also accept synthetic reports for testing. Files are written locally.
Automatic PR publication requires explicit configuration in the composite action.

## Install 0.5.0

The release is **0.5.0 beta**, tested on Linux, Windows and macOS with
Python **3.12, 3.13 and 3.14**. Install the versioned wheel from
[GitHub Releases](https://github.com/lucashgrifoni/secrets-hygiene-kit/releases/tag/v0.5.0).

Create a virtual environment:

```console
python -m venv .venv
```

### Linux and macOS

```console
.venv/bin/python -m pip install https://github.com/lucashgrifoni/secrets-hygiene-kit/releases/download/v0.5.0/secrets_hygiene_kit-0.5.0-py3-none-any.whl
.venv/bin/secguard version
```

### Windows

```console
.\.venv\Scripts\python.exe -m pip install https://github.com/lucashgrifoni/secrets-hygiene-kit/releases/download/v0.5.0/secrets_hygiene_kit-0.5.0-py3-none-any.whl
.\.venv\Scripts\secguard.exe version
```

The version command prints `0.5.0`. In the examples below, replace `secguard`
with `.venv/bin/secguard` on Linux/macOS or `.\.venv\Scripts\secguard.exe` on Windows,
or activate that virtual environment first.

The release also includes a source archive, SHA-256 checksums, a dependency
inventory and build provenance. Distribution is through GitHub Releases;
the package has no PyPI release.

## Quickstart

### 1. Create the local policy

```console
secguard init . --ci none
```

This creates the waiver policy and pre-commit starter. Existing files are
preserved. Choose `--ci github`, `gitlab` or `both` to include CI starters;
configure their scanner steps before use.

### 2. Collect a scanner report

Install and pin a scanner version your team has reviewed. For
[Gitleaks](https://github.com/gitleaks/gitleaks#usage):

```console
gitleaks git --redact --exit-code 0 --report-format json --report-path gitleaks.json
```

`--exit-code 0` leaves the finding threshold to secguard. Gitleaks operational
errors must still stop the scanner step. Run the scanner successfully before
evaluating its report.

### 3. Evaluate findings and export the results

```console
secguard scan check --input gitleaks.json --fail-on high --json findings.json --sarif secguard.sarif --markdown report.md
```

The gate blocks on active findings at or above `high`, or on any expired waiver.
Reports retain waived findings for review.

To combine reports, repeat `--input`:

```console
secguard scan check --input gitleaks.json --input trufflehog.jsonl --input .secrets.baseline --fail-on high
```

| Exit code | Meaning | CI handling |
| --- | --- | --- |
| `0` | No active finding reached the threshold and no waiver expired | Continue |
| `1` | Findings or expired waivers blocked the gate | Review findings and policy |
| `2` | Input, policy or output could not be processed | Correct the error before accepting a scan result |

A clean report describes that scanner run and its scope. It does not establish
that a repository contains no secrets. Empty TruffleHog output is accepted with
a notice; its preceding scanner step must succeed.

See the [full quickstart](docs/quickstart.md) for report collection, exports,
exceptions and troubleshooting.

## CLI reference

| Command | Purpose |
| --- | --- |
| `secguard init [dir] --ci github\|gitlab\|both\|none` | Create policy, pre-commit and optional CI starters |
| `secguard scan check --input FILE [--input FILE]` | Combine reports, apply waivers and enforce the threshold |
| `secguard scan check --input FILE --remediation FILE --repository owner/repo` | Export active findings for remediation, preserving the gate decision |
| `secguard scan normalize --input FILE [--input FILE]` | Combine reports and export canonical JSON without evaluating waivers |
| `secguard report --input FILE [--input FILE]` | Render Markdown without a finding threshold |
| `secguard scan check --input FILE --opa-input FILE --defectdojo FILE` | Export files for external OPA evaluation and DefectDojo import |
| `secguard policy show [--output FILE]` | Print or save the packaged Rego v1 policy |
| `secguard waivers check\|list\|add` | Validate, inspect or add expiring exceptions |
| `secguard playbooks list\|show\|check` | Inspect response guidance and review dates |
| `secguard incident start --secret-type TYPE` | Generate an incident checklist |
| `secguard version` | Print the installed version |

Run `secguard --help` or add `--help` to a command for its options.

Version 0.5.0 includes multi-input normalization, output preflight and explicit
detector-provenance labels. See [Changelog](CHANGELOG.md) for migration details.

To combine reports without applying the waiver policy or severity gate:

```console
secguard scan normalize --input gitleaks.json --input trufflehog.jsonl --output findings.json
```

This uses the same classification and coalescing as `check` and `report`.
With `--format auto`, inputs may come from different supported detectors.
An explicit format applies to every input. A malformed input exits with `2`
and does not create the requested output. Canonical `secguard.findings/v1` JSON
can be read by `normalize`, `check` and `report`. Reimport recomputes classification
and IDs and keeps the stronger of the imported and selected catalog severities.
The document is report data; it does not authenticate the detector's claims.

Betterleaks 1.x reports resemble Gitleaks reports. Select `--format betterleaks`
explicitly. To combine them with other producers, normalize that report first
and combine its canonical output using `--format auto`.

## Waiver policy

Store reviewed exceptions in `.secguard/waivers.yaml`:

If this default file is absent and `--waivers` is omitted, the CLI uses no waivers
and emits a notice. An explicitly selected file must exist, including
`--waivers .secguard/waivers.yaml`; absence exits with `2` even in report-only mode.

```yaml
schema: "secguard.waiver/v1"
waivers:
  - id: WV-2026-001
    rule: secret-type:aws-access-key
    path: tests/fixtures/**
    reason: "Synthetic detector fixture, not a credential."
    owner: appsec@example.invalid
    expires_at: 2026-11-01
    approver: security-lead
```

The date is an example. Choose a future expiry when creating a waiver.

- `*` matches within a path segment; `**` can cross directories.
- Expired waivers suppress nothing and block the gate, even without a matching finding.
- New waivers added through the CLI must expire within 365 days. Expiries beyond
  90 days produce a warning.
- Detector-scoped waivers must collectively cover every rule in a combined
  finding. Partial coverage leaves the finding active and produces a notice.
- A canonical `secret-type:` scope covers that type across detectors and requires
  review of the contributing evidence.

Owner and approver fields record your review process; secguard does not
authenticate those identities. Protect waiver changes through repository review.
Use the [waiver request template](docs/waiver-request-template.md) to document a decision.

## CI integration

### GitHub Actions

The composite action installs secguard from the selected revision and evaluates
existing reports. Add these steps after checking out your repository and installing
a reviewed Gitleaks version. Use a reviewed commit to pin the action:

```yaml
- name: Collect Gitleaks report
  run: gitleaks git --redact --exit-code 0 --report-format json --report-path gitleaks.json

- name: Evaluate secret findings
  uses: lucashgrifoni/secrets-hygiene-kit@v0.5.0 # pin the reviewed release commit in production
  with:
    reports: gitleaks.json
    fail-on: high
```

The action's default outputs are `secguard.sarif`, `secguard-report.md` and
`secguard-comment.md`.
Provide multiple reports as one path per line; paths may contain spaces.

The action skips individual missing paths and fails if no listed report exists.
`allow-missing-reports: true` explicitly permits that case and reports
`NO-REPORTS`. Keep the default when CI requires scanner coverage.

See [action.yml](action.yml) for inputs, output paths and the playbook freshness check.
The `waivers` input follows the CLI contract: empty selects the optional default;
a nonempty path is required. Normalize Betterleaks reports explicitly before
passing their canonical output to the action.

To publish summaries, explicitly enable `publish-pr-comment` and configure a
fixed `comment-repository` in a trusted same-repository PR job. The publisher
posts counts, the gate decision and a run link; it updates its own marker comment.
Publication preserves a blocking gate. See [PR comments](docs/pr-comments.md)
for permissions, fork restrictions and failure handling.

### GitLab CI

```console
secguard init . --ci gitlab
```

This generates `.gitlab/secguard.gitlab-ci.yml`, an includable GitLab snippet.
Configure and install the scanner steps before using it; the generated detector
examples are comments.

## Remediation handoff

```console
secguard scan check --input gitleaks.json --remediation remediation.json --repository acme/example
```

The `secguard.remediation/v1` exchange contains active findings, their resolved
severity, occurrence fingerprints, locations and response playbooks. Waived
findings are omitted, and the gate decision is retained. Free-text messages,
waiver reasons and native detector digests are excluded.

The packaged bridge validates AppSec Remediation Hub models, optionally imports
into an explicitly selected local database, and generates GitHub issue payloads
for review. See [Remediation Hub](docs/remediation-hub.md) for the validated
consumer version, preview mode and reimport behavior.

For OPA and DefectDojo, export files from the same reconciled decision:

```console
secguard scan check --input findings.json --opa-input opa-input.json --defectdojo defectdojo.json
secguard policy show --output secguard.rego
opa eval --fail --data secguard.rego --input opa-input.json 'true = data.secguard.allow'
```

The example policy requires a passing secguard gate and blocks active Medium or
higher findings. DefectDojo receives active findings with `verified: false`;
detector credential verification does not establish human triage. Configure
deduplication by stable ID and preserve `close_old_findings=false` on reimport.
See [OPA and DefectDojo](docs/integrations.md) for tested versions, consumer
configuration and the treatment of severity changes.

## Classification and response

The packaged catalog maps reviewed detector rule identifiers to canonical
secret types. Unmapped rules use a generic playbook and carry `mapping: fallback`.
TruffleHog's `Verified: true` and Betterleaks' `ValidationStatus: valid` raise
severity to Critical; they are claims imported
from the detector report, without fresh verification by secguard.

The console labels it `verified=detector:true`; Markdown identifies the value
as reported by the detector. `false` and missing values do not prove that a
credential is invalid. JSON retains `verified: true`, `false` or `null`.

Catalog overrides require an explicit `--rules` argument:

```console
secguard scan check --input gitleaks.json --rules .secguard/rules.yaml
```

A file at `.secguard/rules.yaml` is not loaded automatically. Overrides that
lower severity emit a warning and need review alongside the waiver policy.

The 13 response playbooks cover:

| Provider or category | Secret types |
| --- | --- |
| AWS | Access keys and secret access keys |
| GitHub | Personal access tokens and App private keys |
| Slack | Bot tokens and webhooks |
| Stripe | Secret keys |
| Google Cloud | Service-account JSON |
| Azure | Storage keys |
| Database and application | PostgreSQL URIs and JWT signing keys |
| Generic | Private keys and API keys |

Each playbook records a review date and covers identification, invalidation,
rotation, usage audit, communication and closure. Provider containment and
replacement order depend on the incident. Follow the
[incident guide](docs/incident-flow.md) and confirm current provider guidance.

## Data handling and operating limits

Adapters discard known credential fields, including `Secret`, `Match`, `Raw`,
`RawV2` and `hashed_secret`, while retaining selected review metadata. Keep
credentials out of paths, identifiers, descriptions, waiver reasons and other
metadata. Review exported reports before sharing them.

| Limit | Effect |
| --- | --- |
| 64 MiB per input report | Larger reports exit with a processing error before JSON parsing; use smaller repository scopes |
| 16 MiB / 10,000 findings per remediation exchange | Oversized handoffs fail before any scan output is written; use smaller repository scopes |
| In-memory parsing | The input limit does not impose an aggregate memory limit on parsing or combined findings |
| Type, path and line matching | Different reported lines can produce separate findings; location-derived detect-secrets fingerprints change when code moves |
| Filesystem write guards | Output preflight rejects collisions with selected inputs/policies, conflicting exports, symlinks and Windows junctions; concurrent changes and later I/O failures remain outside the guarantee |

For `check`, `report` and `normalize`, use destinations distinct from every
scanner input, the selected waiver policy and the explicitly selected rule
catalog. Each export also needs a separate destination. Conflicts, file aliases
and invalid file/directory layouts exit with `2` before any export is written.
Outputs are written sequentially after preflight; a later I/O failure can still
leave earlier exports, so the operation is not an atomic transaction.

Tests cover credential canaries, malformed payloads, terminal control characters,
Markdown escaping, directory-aware waiver scope and linked output destinations.
secguard is not a universal secret scrubber. SARIF severity overrides use stable
severity suffixes; see the [migration notes](CHANGELOG.md#migration-notes).

## Documentation

| Guide | Use it for |
| --- | --- |
| [Quickstart](docs/quickstart.md) | End-to-end setup, scanner reports and troubleshooting |
| [Incident response](docs/incident-flow.md) | Containment, rotation and closure guidance |
| [Adding a playbook](docs/adding-playbook.md) | Extending response guidance and rule mappings |
| [Waiver request](docs/waiver-request-template.md) | Recording an exception for review |
| [PR comments](docs/pr-comments.md) | Trusted publication, permissions and idempotent summaries |
| [Remediation Hub](docs/remediation-hub.md) | Active-only exchange, local import and issue preview |
| [Detector compatibility](docs/detector-compatibility.md) | Fixed producer versions, fixture provenance and reproduction |
| [OPA and DefectDojo](docs/integrations.md) | Offline file exports, policy evaluation and stable reimport |
| [Changelog](CHANGELOG.md) | Release changes and migration notes |
| [Project status](STATUS.md) | Current scope and known limitations |

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, tests and extension
requirements. Use synthetic fixtures when reporting problems or adding examples.

For vulnerabilities, use the private reporting channel described in
[SECURITY.md](SECURITY.md). Never include live credentials or sensitive scanner
reports in public issues.

## License

Licensed under [Apache-2.0](LICENSE).
