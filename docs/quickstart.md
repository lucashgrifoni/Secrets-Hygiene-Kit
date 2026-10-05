# Quickstart

Install the versioned wheel using the [README](../README.md#install-030).
Use the virtual environment's executable for every command below.

## 1. Create the starter files

```console
secguard init . --ci github
```

This creates `.secguard/waivers.yaml`, a pre-commit configuration and a
GitHub workflow without overwriting existing files. Choose `--ci gitlab`,
`both` or `none` as needed. Use `--dry-run` to preview changes and
`--force` only when overwriting the selected files is intended.

## 2. Produce reports

Install and pin the detector version separately. Run its step successfully
before calling secguard. Examples:

```console
gitleaks git --no-banner --redact --exit-code 0 --report-format json --report-path gitleaks.json
trufflehog git file://. --json --fail-on-scan-errors > trufflehog.jsonl
detect-secrets scan > .secrets.baseline
```

Gitleaks uses secguard for the finding threshold while preserving operational
errors. TruffleHog's scan-error option preserves incomplete-scan failures.
An empty TruffleHog report is valid only when its preceding scanner run
succeeded. secguard cannot infer scanner success from an empty file.

These commands collect reports; secguard does not execute any detector.

## 3. Evaluate the gate

```console
secguard scan check --input gitleaks.json --input trufflehog.jsonl --input .secrets.baseline --fail-on high
```

Formats are inferred from content. `--format` selects an explicit format;
all inputs in that invocation must follow it. Exit codes are `0` for PASS,
`1` for BLOCK and `2` for processing errors.

Each report has a 64 MiB input limit. A larger report exits with code `2`;
collect a smaller repository scope rather than treating that error as a scan result.

At a shared type, path and line, findings combine at the highest reported
severity. `Verified: true` in a TruffleHog report raises severity to Critical;
the CLI's `verified=live` label refers to that imported report claim.

## 4. Export evidence

```console
secguard scan check --input gitleaks.json --json findings.json --sarif secguard.sarif --markdown report.md --pr-comment comment.md
```

These options write files. Upload SARIF and post comment drafts through your
own authorized workflow; secguard does neither automatically.

SARIF rules identify the canonical type, with a severity suffix for overrides.
Waived findings remain visible as suppressions. Review sensitive metadata
before sharing any output.

## 5. Respond or document an exception

For a real exposure:

```console
secguard incident start --secret-type aws-access-key --leaked-via public-github-issue
```

Use the [incident guide](incident-flow.md) to establish authority, containment
and evidence. Source cleanup alone does not invalidate a credential.

For a confirmed synthetic fixture, record a reviewed exception:

```console
secguard waivers add --rule "secret-type:aws-access-key" --path "tests/fixtures/**" --reason "Synthetic detector fixture." --owner appsec@example.invalid --approver security-lead --expires 2026-11-01
```

Select a future expiry within 365 days. The date above is an example, not
approval of a waiver. The owner and approver fields record your process;
secguard does not verify their identities.

Scopes use directory-aware globs. A detector rule scope must cover all rules
contributing to a combined finding. Partial coverage remains active and is
reported for review.

## 6. Check the guidance

```console
secguard playbooks list
secguard playbooks check --max-age-days 180
```

A stale playbook makes the freshness check fail. A review date records a
documentation review, not a test of revocation in your account.

## Custom rules

Catalog overrides are loaded only when explicitly passed:

```yaml
detectors:
  gitleaks:
    acme-token: generic-api-key
    acme-signing-key: jwt-signing-key
```

```console
secguard scan check --input gitleaks.json --rules .secguard/rules.yaml
```

Severity reductions produce warnings. Protect custom catalogs alongside the
waiver policy. See [adding-playbook.md](adding-playbook.md) for extension work.

## Troubleshooting

| Symptom | Next check |
| --- | --- |
| exit 2 with an unreadable report | confirm UTF-8, format and scanner completion |
| no report in the CI starter | configure and install the detector step |
| a partial waiver leaves a finding active | review every contributing rule |
| output refuses a linked directory | choose a regular destination in the checkout |
| an unmapped rule uses a generic playbook | identify the provider and add a reviewed mapping |
