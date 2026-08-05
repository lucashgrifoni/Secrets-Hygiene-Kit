# Secrets Hygiene Kit

**gitleaks tells you a secret leaked. `secguard` tells you what to do about it.**

Secret scanners are good at detection and silent about response. Each provider
has a different revocation path, every team improvises the first thirty minutes,
and accepted exceptions quietly become permanent. `secguard` closes that gap: it
normalizes detector reports into one canonical finding set, applies a waiver
lifecycle that actually expires, and hands the responder a provider-specific
checklist.

```console
$ secguard scan check --input gitleaks.json --input trufflehog.jsonl --fail-on high
5 finding(s): 5 active, 0 waived, threshold=high, date=2026-08-04
- critical  aws-access-key  src/example_config.py:12  rule=gitleaks:aws-access-token  playbook=aws-access-key verified=live
- high      postgres-uri    infra/db.tf:5             rule=trufflehog:Postgres        playbook=postgres-uri
- medium    slack-webhook   docs/example.env:4        rule=gitleaks:slack-webhook-url playbook=slack-webhook
BLOCK: 2 finding(s) at or above high

$ secguard incident start --secret-type aws-access-key --leaked-via public-github-issue
# Incident checklist: AWS Access Key Leak Playbook
...
## Invalidate
- [ ] Deactivate the exposed access key through IAM before relying on source cleanup.
```

## Scope

| secguard does | secguard does not |
| --- | --- |
| read gitleaks, trufflehog, and detect-secrets reports | run any scanner |
| normalize them into one canonical, dedup'd finding set | detect secrets itself |
| enforce a waiver lifecycle that fails closed on expiry | permanently silence a rule |
| decide block or pass, and emit SARIF, JSON, and Markdown | upload results for you |
| print provider-specific response checklists | revoke, rotate, or mutate provider state |

Detection stays with the tool your team already trusts. secguard never pins,
ships, or executes a scanner binary, which keeps it out of your supply chain and
makes every adapter deterministically testable.

Response stays with a human. A tool that revokes credentials automatically is a
tool that takes production down at 3am on a false positive.

## Install

```bash
python -m pip install secrets-hygiene-kit
secguard init .
```

Start at [docs/quickstart.md](docs/quickstart.md).

## How it works

```text
gitleaks.json  ─┐
trufflehog.jsonl├─> normalize ─> classify ─> merge ─> reconcile ─> gate ─> SARIF / JSON / Markdown
.secrets.baseline┘   (redact)   (catalog)  (dedup)   (waivers)              incident checklist
```

**Normalize.** Each adapter reads an explicit allowlist of metadata keys and
ignores everything else, so gitleaks `Secret` and `Match`, trufflehog `Raw` and
`RawV2`, detect-secrets `hashed_secret`, commit messages, and author emails
never enter the pipeline. The canonical model has no field that could hold them.

**Classify.** A rule catalog maps `gitleaks:aws-access-token` to the canonical
secret type `aws-access-key`, a default severity, and the playbook that
describes the response. An unmapped rule falls back to the generic playbook and
is flagged `mapping: fallback` rather than silently presented as a confident
match.

**Merge.** The same leak found by three scanners becomes one finding at the
highest severity any of them assigned, listing the others as corroborating
evidence. In SARIF that means one alert, not three.

**Reconcile.** Findings meet the waiver file. An expired waiver suppresses
nothing and fails the gate on its own.

**Gate.** Exit `0` clean, `1` blocked on purpose, `2` bad input.

## Commands

| Command | What it does |
| --- | --- |
| `secguard init [dir] --ci github\|gitlab\|both\|none` | scaffold waivers, pre-commit, and CI, never overwriting by default |
| `secguard scan check --input FILE...` | merge reports, apply waivers, decide block or pass |
| `secguard scan normalize --input FILE` | one report to canonical JSON, no gate |
| `secguard report --input FILE...` | Markdown report without failing the build |
| `secguard waivers check \| list \| add` | the exception lifecycle |
| `secguard playbooks list \| show \| check` | response guidance and its freshness |
| `secguard incident start --secret-type TYPE` | tickable response checklist |

## Waivers that expire for real

```yaml
schema: "secguard.waiver/v1"
waivers:
  - id: WV-2026-001
    rule: secret-type:aws-access-key      # or gitleaks:aws-access-token, or gitleaks:*
    path: tests/fixtures/**               # git-style globs: * stays in one segment
    reason: "Synthetic value in a detector fixture, not a credential."
    owner: appsec@example.com
    expires_at: 2026-11-01
    approver: security-lead
```

Three properties keep this from becoming a parking lot:

- **Expiry is enforced, not decorative.** Past `expires_at`, the waiver stops
  suppressing findings *and* fails the gate on its own, so a stale exception
  cannot hide behind code that moved.
- **Scope is narrow by construction.** `*` matches inside one path segment;
  crossing directories takes an explicit `**`. `fnmatch` would have let `src/*`
  silently mean "everything under src, recursively".
- **New waivers are bounded.** `waivers add` rejects an expiry in the past or
  more than 365 days out, and warns past 90 days.

Targeting `secret-type:` instead of a detector rule means the waiver survives a
scanner renaming its rules.

## Playbooks

Thirteen packaged playbooks, each following the same response shape: identify,
invalidate, rotate, audit usage, communicate, close.

`aws-access-key` · `aws-secret-access-key` · `github-pat` ·
`github-app-private-key` · `slack-bot-token` · `slack-webhook` ·
`stripe-secret-key` · `gcp-service-account-json` · `azure-storage-key` ·
`postgres-uri` · `jwt-signing-key` · `generic-private-key` · `generic-api-key`

Every playbook carries a `Vetted:` date, and `secguard playbooks check` exits
`1` once one passes its review window. Vendor consoles change; guidance nobody
has reviewed in a year gets followed with misplaced confidence mid-incident.

Adding your own: [docs/adding-playbook.md](docs/adding-playbook.md).

## CI

A composite GitHub Action ships in [action.yml](action.yml):

```yaml
- name: Run gitleaks
  run: gitleaks detect --report-format json --report-path gitleaks.json || true

- uses: lucashgrifoni/secrets-hygiene-kit@v0.2.0
  with:
    reports: gitleaks.json
    fail-on: high
```

`secguard init --ci gitlab` writes an includable GitLab snippet instead of
overwriting `.gitlab-ci.yml`.

Both starter workflows request `contents: read` only and leave the detector step
commented out, so you pin the scanner your team reviewed rather than inheriting
one from this project.

## Extending the rule catalog

Detector rule ids drift between releases, and every team has custom rules. Merge
a local catalog over the packaged one:

```yaml
# .secguard/rules.yaml
detectors:
  gitleaks:
    acme-internal-token: generic-api-key
    acme-signing-key: jwt-signing-key
```

```bash
secguard scan check --input gitleaks.json --rules .secguard/rules.yaml
```

The packaged catalog maps only what is defensible. Where a mapping would be a
guess, secguard falls back and says so.

## Security posture

- **Redaction is a tested invariant, not a convention.** The suite feeds
  canary-laced fixtures through every output path (canonical JSON, SARIF,
  Markdown report, PR comment, console) and asserts nothing leaks. A separate
  test asserts the fixtures actually contain the canary, because a redaction
  test against clean input proves nothing.
- **Free text is sanitized.** ANSI escape sequences, control characters, and
  newlines are stripped from anything a scanner supplies, and Markdown cells are
  escaped, so a hostile report cannot forge log lines or break out of a table.
- **Paths are validated.** Absolute and parent-traversal paths are rejected in
  reports, waiver scope, and playbook slugs.
- **File writes refuse symlinks** and never write through a symlinked directory.
- **Error messages never echo input values**, so a validation failure cannot
  print the credential it rejected.

Report issues per [SECURITY.md](SECURITY.md). Never include a secret value.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check . && python -m ruff format --check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
