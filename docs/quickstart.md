# Quickstart

secguard turns detector output into a decision and a response. It does not
detect secrets, and it never rotates or revokes a credential.

## Install

```bash
python -m pip install secrets-hygiene-kit
secguard version
```

## 1. Scaffold the local controls

```bash
secguard init .
```

This creates, without overwriting anything that already exists:

| File | Purpose |
| --- | --- |
| `.secguard/waivers.yaml` | the versioned exception log |
| `.pre-commit-config.yaml` | waiver and playbook checks, plus commented detector hooks |
| `.github/workflows/secguard.yml` | the CI gate |

Use `--dry-run` to preview, `--force` to overwrite, and `--ci gitlab`, `--ci both`,
or `--ci none` to choose the CI starter.

## 2. Produce a scanner report

secguard reads reports, so run whichever detector your team already trusts.
Let it exit non-zero without failing the job; the secguard gate makes the
block-or-pass decision.

```bash
gitleaks detect --no-banner --redact --report-format json --report-path gitleaks.json || true
trufflehog git file://. --json > trufflehog.jsonl || true
detect-secrets scan > .secrets.baseline || true
```

## 3. Run the gate

```bash
secguard scan check \
  --input gitleaks.json \
  --input trufflehog.jsonl \
  --input .secrets.baseline \
  --fail-on high
```

Every `--input` is merged into one canonical finding set. The format is inferred
from the file structure, not the file name; pass `--format` to override.

The same leak reported by three scanners becomes one finding, at the highest
severity any of them assigned, listing the others as corroborating evidence:

```text
5 finding(s): 5 active, 0 waived, threshold=high, date=2026-08-04
- critical  aws-access-key  src/example_config.py:12  rule=gitleaks:aws-access-token  playbook=aws-access-key verified=live
BLOCK: 2 finding(s) at or above high
```

`verified=live` means trufflehog authenticated the credential against the
provider. That is not a heuristic, so secguard escalates it to critical.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | no unwaived finding reached the threshold and no waiver has expired |
| `1` | the gate blocked on purpose |
| `2` | input missing, malformed, or rejected by policy |

### Output artifacts

```bash
secguard scan check --input gitleaks.json \
  --json findings.json \
  --sarif secguard.sarif \
  --markdown report.md \
  --pr-comment comment.md
```

- `--sarif` uploads to GitHub code scanning or Azure DevOps Advanced Security.
  Rules are keyed by canonical secret type, so one leak is one alert regardless
  of how many detectors found it, and a waived finding appears as a SARIF
  suppression rather than disappearing.
- `--pr-comment` is sized for a bot comment on the pull request.

## 4. Respond to a real leak

```bash
secguard incident start --secret-type aws-access-key --leaked-via public-github-issue
```

Prints a tickable checklist: identify, invalidate, rotate, audit usage,
communicate, close. See [incident-flow.md](incident-flow.md).

## 5. Accept a match on purpose

A detector fixture that matches a rule forever needs an exception with an owner
and an expiry date, not a permanently silenced rule:

```bash
secguard waivers add \
  --rule "secret-type:aws-access-key" \
  --path "tests/fixtures/**" \
  --reason "Intentional detector fixture with a synthetic value." \
  --owner appsec@example.com \
  --approver security-lead \
  --expires 2026-11-01
```

Rules for waiver scope:

- `--rule` accepts a detector rule (`gitleaks:aws-access-token`), a glob
  (`gitleaks:*`), or the canonical type (`secret-type:aws-access-key`), which
  survives a detector renaming its rules.
- `--path` uses git-style globs: `*` stays inside one path segment, `**`
  crosses segments.
- Expiry must be in the future and at most 365 days out. Past 90 days secguard
  warns.
- An expired waiver stops suppressing findings **and** fails the gate on its
  own, so a stale exception cannot sit unnoticed.

## 6. Keep the response guidance fresh

```bash
secguard playbooks list
secguard playbooks check --max-age-days 180
```

Vendor consoles and revocation flows change. `playbooks check` exits `1` once a
playbook passes its review window, because advice nobody has reviewed in a year
gets followed with misplaced confidence during an incident.

## Teaching secguard about your own rules

An unmapped detector rule resolves to the generic playbook and is flagged as
`mapping: fallback`, so you can see where the routing is guessing. Fix it with a
local catalog merged over the packaged one:

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

See [adding-playbook.md](adding-playbook.md) to add a provider playbook of your
own.
