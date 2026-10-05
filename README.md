# Secrets Hygiene Kit

`secguard` turns secret-scanner reports into a build decision and a response checklist.
It combines findings from Gitleaks, TruffleHog and detect-secrets, applies expiring
waivers, and exports JSON, SARIF or Markdown for review.

Detection runs in your scanner. Credential changes remain with the authorized
responder. secguard reads reports and never contacts a credential provider.

## Install 0.3.0

Use Python 3.12, 3.13 or 3.14 on Linux or Windows.

Create a virtual environment and install the versioned wheel from the
[0.3.0 release](https://github.com/lucashgrifoni/secrets-hygiene-kit/releases/tag/v0.3.0):

```console
python -m venv .venv
```

On Linux:

```console
.venv/bin/python -m pip install https://github.com/lucashgrifoni/secrets-hygiene-kit/releases/download/v0.3.0/secrets_hygiene_kit-0.3.0-py3-none-any.whl
.venv/bin/secguard version
```

On Windows:

```console
.venv\Scripts\python.exe -m pip install https://github.com/lucashgrifoni/secrets-hygiene-kit/releases/download/v0.3.0/secrets_hygiene_kit-0.3.0-py3-none-any.whl
.venv\Scripts\secguard.exe version
```

The release includes a source archive, SHA-256 checksums, a dependency inventory
and build provenance. The package is distributed through GitHub Releases;
there is no PyPI release. Use the environment's `secguard` executable for the
commands below.

## First use

Run your chosen scanner and keep its failure status visible. For example,
Gitleaks can write findings without using them as its process exit status:

```console
gitleaks git --redact --exit-code 0 --report-format json --report-path gitleaks.json
secguard scan check --input gitleaks.json --fail-on high
```

Gitleaks operational errors still stop the scanner step. Pin and install the
scanner version your team reviewed separately.

| Exit | Meaning |
| --- | --- |
| `0` | no active finding reached the threshold and no waiver expired |
| `1` | findings or expired waivers blocked the gate |
| `2` | input, policy or output could not be processed |

A clean report is evidence about that scanner run and its scope. It does not
prove the repository contains no secrets. Empty TruffleHog output is accepted
with a notice; the preceding scanner step must succeed.

See the [quickstart](docs/quickstart.md) for setup, report formats and CI.

## Capabilities

- Read Gitleaks JSON, TruffleHog JSON/JSON Lines, detect-secrets baselines and
  synthetic test reports.
- Map detector rules to 13 canonical secret types and response playbooks.
- Combine findings at the same type, path and line, preserving the strongest
  severity and each contributing detector rule.
- Require every contributing rule to be covered before a waiver suppresses
  a combined finding.
- Block on expired waivers and warn about unused or partial scopes.
- Export JSON, SARIF 2.1.0, a Markdown report or a PR comment draft.
- Create pre-commit and CI starters without overwriting existing files.
- Print response checklists and check playbook review dates.

| Command | Purpose |
| --- | --- |
| `secguard init [dir] --ci github\|gitlab\|both\|none` | create starter files |
| `secguard scan check --input FILE...` | combine reports and enforce the gate |
| `secguard scan normalize --input FILE` | export canonical findings |
| `secguard report --input FILE...` | write a report without a finding threshold |
| `secguard waivers check\|list\|add` | manage expiring exceptions |
| `secguard playbooks list\|show\|check` | inspect response guidance |
| `secguard incident start --secret-type TYPE` | generate an incident checklist |

## Exception policy

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

A waiver records an owner and approver; secguard does not authenticate them or
replace your review process. Protect the waiver file in your repository.

`*` stays within a path segment; `**` crosses directories. Expired waivers
suppress nothing and block the gate even if they match no current finding.
New waivers created through the CLI must expire in the future within 365 days;
expiries beyond 90 days produce a warning.

Detector-scoped waivers must collectively cover every rule in a combined
finding. A canonical `secret-type:` scope covers the type across detectors
and requires review of the added evidence.

## Classification and severity

The packaged catalog maps reviewed detector rule identifiers. Unmapped rules
use a generic playbook and carry `mapping: fallback`.

A TruffleHog `Verified: true` field raises severity to Critical. This imports
the detector's claim at scan time; secguard performs no fresh verification.

Catalog overrides can lower severity, so they require an explicit `--rules`
argument and emit a warning for reductions. A file merely present at
`.secguard/rules.yaml` is not automatically loaded.

```console
secguard scan check --input gitleaks.json --rules .secguard/rules.yaml
```

## GitHub Action

The composite action installs this package from its own versioned checkout.
Reports take one path per line, including paths containing spaces.

```yaml
- name: Collect Gitleaks report
  run: gitleaks git --redact --exit-code 0 --report-format json --report-path gitleaks.json

- uses: lucashgrifoni/secrets-hygiene-kit@v0.3.0
  with:
    reports: gitleaks.json
    fail-on: high
```

Install a reviewed scanner before the first step. Pin the secguard action to the
release commit SHA when your dependency policy requires immutable references.
Missing reports fail by default. `allow-missing-reports: true` explicitly
permits a run without coverage and reports `NO-REPORTS`, rather than `PASS`.

`secguard init --ci gitlab` produces an includable GitLab snippet. The starter
scanner steps are comments for your team to configure.

## Response playbooks

The package contains guidance for AWS access keys, AWS secret access keys,
GitHub PATs and App keys, Slack bot tokens and webhooks, Stripe secret keys,
GCP service-account JSON, Azure Storage keys, PostgreSQL URIs, JWT signing keys,
generic private keys and generic API keys.

Each playbook has a review date and the same sections: identify, invalidate,
rotate, audit usage, communicate and close. The containment mechanism and
replacement order depend on the provider and the incident. Follow the
[incident guide](docs/incident-flow.md) and confirm current provider guidance.

## Data handling and limits

Adapters discard known credential fields such as `Secret`, `Match`,
`Raw`, `RawV2` and `hashed_secret`. They retain selected metadata needed
for review. Do not place credentials in paths, identifiers, descriptions,
waiver reasons or other metadata: secguard is not a universal secret scrubber.

Tests cover credential canaries, malformed payloads, terminal control
characters, Markdown escaping, directory-aware waiver scope, and writes
through symlinks or Windows junctions. These checks do not establish safety
under concurrent filesystem mutation by another process.

Each input report is limited to 64 MiB. Larger inputs exit with a processing
error before JSON parsing. Collect reports in smaller repository scopes when
that budget is exceeded; parsing and canonical findings still use memory.

Findings combine by type, normalized path and line. Different reported lines
can produce separate findings. Location-derived detect-secrets fingerprints
change when code moves. For severity overrides, SARIF IDs include a stable
severity suffix; see the [migration notes](CHANGELOG.md).

Report vulnerabilities through [SECURITY.md](SECURITY.md). Contribution and
extension guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE).
