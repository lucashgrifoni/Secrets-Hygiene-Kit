# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-04

The release that connects detection to response. 0.1.0 could validate a waiver
file and print a playbook; 0.2.0 reads real scanner output and decides.

### Added

- **Scanner ingestion.** Adapters for gitleaks JSON reports, trufflehog JSON
  Lines and JSON array output, and detect-secrets baselines, alongside the
  existing synthetic fixture format. The format is inferred from payload
  structure rather than the file name.
- **Cross-scanner merge.** `--input` is repeatable; the same leak reported by
  several scanners collapses into one finding at the highest severity assigned,
  recording the others in `corroborated_by`.
- **Rule catalog** (`secguard.rules/v1`) mapping detector rules to a canonical
  secret type, a default severity, and a response playbook. Unmapped rules
  resolve to the generic playbook and are flagged `mapping: fallback`. Extend or
  override with a local `.secguard/rules.yaml` via `--rules`.
- **Verification escalation.** A trufflehog `Verified: true` result escalates the
  finding to critical, because the credential was proven live at scan time.
- **`secguard scan check`** — the gate: merges reports, applies waivers, and
  exits `1` on unwaived findings at or above `--fail-on`, or on any expired
  waiver.
- **Outputs**: canonical JSON (`--json`), SARIF 2.1.0 (`--sarif`), a full
  Markdown report (`--markdown`), and a compact PR comment (`--pr-comment`).
  SARIF rules are keyed by canonical secret type so one leak is one alert, and
  waived findings are emitted as SARIF suppressions rather than dropped.
- **`secguard report`** renders the Markdown report without gating the build.
- **`secguard waivers add`** writes a validated waiver, generating sequential
  ids, rejecting expiry in the past or beyond 365 days, and warning past 90.
- **`secguard playbooks list | show | check`**. `check` fails once a playbook
  passes its review window (180 days by default).
- **`secguard incident start`** renders a tickable response checklist for a
  secret type, warning when the playbook is stale.
- **`secguard version`**.
- **Nine playbooks** (13 total): `aws-secret-access-key`,
  `github-app-private-key`, `slack-bot-token`, `stripe-secret-key`,
  `gcp-service-account-json`, `azure-storage-key`, `postgres-uri`,
  `jwt-signing-key`, `generic-private-key`.
- **Composite GitHub Action** in `action.yml`, and a GitLab CI starter selected
  with `secguard init --ci gitlab|both|none`.
- **Documentation**: `docs/quickstart.md`, `docs/incident-flow.md`,
  `docs/adding-playbook.md`.
- **Repository CI** running tests and lint on Python 3.12 and 3.13, checking its
  own playbook freshness, and verifying packaged resources survive the wheel.

### Changed

- Waiver `rule` now accepts glob patterns (`gitleaks:*`) and canonical types
  (`secret-type:aws-access-key`), which survive a detector renaming its rules.
- Waiver `path` accepts git-style globs where `*` stays inside one path segment
  and `**` crosses segments, instead of `fnmatch` semantics that would let
  `src/*` silently mean "everything under src, recursively".
- Waiver `path` is validated as repository-relative; absolute and
  parent-traversal scopes are rejected.
- `scan normalize` accepts every supported scanner format and gained `--output`.
- The canonical `Finding` model carries `secret_type`, `secret_title`,
  `playbook`, `mapping`, `commit`, `verified`, and `corroborated_by`.
- A synthetic finding without an explicit `severity` now takes the catalog
  default instead of a hardcoded `medium`.
- The pre-commit starter also runs `secguard playbooks check` and documents how
  to pin detector hooks.
- The GitHub Actions starter runs the full gate and uploads evidence, with the
  detector step and SARIF upload left commented so the team pins them itself.
- `templates/` at the repository root was removed; the packaged templates under
  `src/secguard/templates/` are the single source, and the waiver request form
  moved to `docs/waiver-request-template.md`.

### Security

- Every adapter reads scanner reports by **allowlist**, so gitleaks `Secret`,
  `Match`, and commit `Message`, trufflehog `Raw`, `RawV2`, `Redacted`, and
  `ExtraData`, detect-secrets `hashed_secret`, and author email addresses never
  reach canonical findings. The canonical model has no field able to hold them.
- `hashed_secret` is deliberately not propagated: a SHA-1 digest of a
  low-entropy credential is recoverable, so fingerprints derive from location
  metadata instead.
- Scanner-supplied free text is stripped of ANSI escape sequences and control
  characters and escaped for Markdown, so a hostile report cannot forge log
  lines or break out of a report table.
- Output paths refuse to write through symlinks.
- Validation errors never echo the rejected input value.

## [0.1.0] - 2026-05-18

### Added

- Initial `secguard` skeleton with the waiver model, waiver CLI, templates,
  provider playbooks, and unit tests.
- Safe local `secguard init` scaffolding with dry-run, no-clobber, and force
  modes.
- `secguard scan normalize --input` for local synthetic scanner fixtures.
- Baseline contribution guidance.
