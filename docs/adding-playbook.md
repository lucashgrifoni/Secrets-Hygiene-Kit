# Adding a playbook

A playbook is the response half of the kit. Detection tells you a credential
leaked; the playbook tells the responder what to do in the next thirty minutes.

Two rules govern every playbook:

1. **Instructions for humans, never automation.** A playbook must not ship a
   command that revokes, deletes, or rotates anything. secguard prints steps; a
   person with the authority executes them.
2. **No secret values, ever.** Not in examples, not in placeholders that look
   real. Use obviously synthetic material or describe the shape in prose.

## 1. Create the file

```text
src/secguard/playbooks/<slug>/PLAYBOOK.md
```

The slug is lowercase kebab-case and must match the `playbook` field of a secret
type in `src/secguard/data/rules.yaml`.

## 2. Follow the required shape

```markdown
# <Provider> <Credential> Leak Playbook

Vetted: 2026-08-04

## Scope

When to use this playbook, and what makes this credential type different.

## Identify
## Invalidate
## Rotate
## Audit Usage
## Communicate
## Close
```

The section names are load-bearing: `tests/test_playbooks.py` asserts all seven
are present, and `secguard incident start` renders bullets under them as a
tickable checklist.

### What the `Vetted` date means

**A human reviewed these steps against current vendor documentation on that
date.** It is not the file's creation date and not the last time a typo was
fixed. `secguard playbooks check` fails once a playbook passes its review window
(180 days by default) because stale response guidance is followed with
misplaced confidence during an incident.

Do not bump the date without doing the review.

## 3. Write steps that survive a UI redesign

Vendor consoles get reorganized constantly. Write at the level of the operation,
not the click path:

- Good: "Deactivate the access key in IAM before relying on source cleanup."
- Bad: "Click Security Credentials, then Access keys, then Deactivate."

Prefer documented API operations and CLI commands when you name specifics, and
prefer the reversible containment step where the provider offers one.

## 4. Say what the response cannot know

The strongest playbooks name their own blind spots. If a log source is often
disabled by default, say so and tell the responder to record the gap rather than
report a clean window. "We could not tell" is a finding; "it looked clean" when
logging was off is a false assurance.

## 5. Register it in the catalog

```yaml
# src/secguard/data/rules.yaml
secret_types:
  acme-deploy-token:
    title: "Acme deploy token"
    severity: high
    playbook: acme-deploy-token

detectors:
  gitleaks:
    acme-deploy-token: acme-deploy-token
  trufflehog:
    AcmeDeploy: acme-deploy-token
```

Map only what you can defend. An unmapped rule falls back to
`generic-api-key` and is flagged `mapping: fallback`, which is honest. A wrong
mapping is worse: it sends a responder down a provider-specific path that does
not apply.

Two tests keep the catalog and the playbook set coherent, and they run in both
directions:

- every `playbook:` reference resolves to a packaged playbook, and
- every packaged playbook is reachable from some secret type, so nothing becomes
  dead weight nobody is ever routed to.

## 6. Choosing a severity

| Severity | Use when |
| --- | --- |
| `critical` | mints other credentials, moves money, or signs artifacts (GitHub App private key, Stripe live key, GCP service account key) |
| `high` | direct access to an account or data plane (AWS access key, GitHub PAT, Azure Storage key, database URI, JWT signing key) |
| `medium` | scoped or single-purpose access (Slack webhook, unclassified API key) |
| `low` | heuristic matches with a high false-positive rate (entropy detectors) |

A detector report with a true verification result overrides these defaults
and escalates to `critical`. secguard prioritizes that imported claim; it does
not establish current validity, permissions or exploitability at the provider.

## 7. Verify

```console
python -m pytest tests/test_playbooks.py
secguard playbooks show <slug>
secguard incident start --secret-type <secret-type>
python -m ruff check . && python -m ruff format --check .
```

Then confirm the playbook survives packaging, since playbooks ship as package
data and a missing entry only shows up after install:

```console
python -m build
python -m venv /tmp/verify && /tmp/verify/bin/python -m pip install dist/*.whl
/tmp/verify/bin/secguard playbooks list
```

On Windows the virtualenv puts its executables in `Scripts`, not `bin`:

```console
python -m build
python -m venv $env:TEMP\verify
& "$env:TEMP\verify\Scripts\python.exe" -m pip install (Get-Item dist\*.whl)
& "$env:TEMP\verify\Scripts\secguard.exe" playbooks list
```
