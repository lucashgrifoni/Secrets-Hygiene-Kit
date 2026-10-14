---
type: "architecture"
title: "Report normalization and identity"
description: "Follow allowlisted scanner metadata, location identity and corroboration through merged findings."
tags: ["normalization","identity","redaction"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:27:23.043Z
sources:
  - id: openwiki-source-81ca5fe2248cb8558f09d05c
    resource: repo://src/secguard/core/detectors/gitleaks.py
  - id: openwiki-source-ac3a64a30672f0db301a9e3f
    resource: repo://src/secguard/core/findings.py
generated: { by: "codex", at: "2026-10-14T19:25:43.426Z" }
---

# Report normalization and identity

## Adapters select metadata

The Gitleaks adapter accepts a JSON array and maps explicit rule, repository-relative path, location and fingerprint metadata into canonical findings. It does not read the credential-bearing Secret, Match or commit Message fields. The adapter validates its input shape and keeps scanner format handling outside the canonical model ([adapter](../../src/secguard/core/detectors/gitleaks.py)). Metadata itself must still be treated as untrusted input.

Repository-relative path validation rejects absolute paths, parent traversal and control characters. Text helpers sanitize display values and validation details rather than echoing arbitrary input-controlled field names ([path contract](../../src/secguard/core/findings.py#L66-L93), [validation diagnostics](../../src/secguard/core/redaction.py#L65-L84)). This boundary does not mean every possible upstream metadata value is harmless.

## A merged finding keeps corroboration

The merge groups findings by canonical secret type and occurrence location. It selects a stable primary record, keeps the highest severity, aggregates verification signals and records corroborating scanners/rules. Final sorting uses severity, path, line and id for stable ordering ([merge](../../src/secguard/core/findings.py#L300-L347)). Adding another scanner should enrich the occurrence rather than manufacture an unrelated incident solely because the detector name differs.

When no scanner fingerprint is supplied, the fallback digest uses scanner, rule, path, line, column and normalized message metadata, rather than raw secret material ([fallback identity](../../src/secguard/core/findings.py#L448-L460)). Continue with [waiver scope](../concepts/waivers-and-gate.md) before treating a merged finding as excepted.
