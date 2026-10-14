---
type: "quickstart"
title: "Secrets hygiene workflow"
description: "Navigate scanner-report normalization, waiver decisions and human response artifacts."
tags: ["secrets","reports","cli"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:27:23.043Z
sources:
  - id: openwiki-source-05ccef8d4cf1698187f20464
    resource: repo://pyproject.toml
  - id: openwiki-source-552c17f9bcd7852ebcdd11bd
    resource: repo://src/secguard/cli/app.py
generated: { by: "codex", at: "2026-10-14T19:25:43.426Z" }
---

# Secrets hygiene workflow

The package installs `secguard` and requires Python3.12 or newer. It normalizes scanner reports, evaluates reviewed waivers and prepares response artifacts ([package metadata](../pyproject.toml), [CLI workflow](../src/secguard/cli/app.py#L558-L619)). Reading a scanner report is separate from running that scanner, and a waiver is separate from credential remediation.

## Choose a task

| Task | Page |
|---|---|
| Trace scanner metadata into canonical merged findings | [Report normalization](architecture/report-normalization.md) |
| Interpret scope, expiry and blocking findings | [Waivers and gate](concepts/waivers-and-gate.md) |
| Prepare incident and remediation records | [Response artifacts](workflows/response-artifacts.md) |
| Maintain the source-linked guide | [OpenWiki setup](../docs/openwiki.md) |

Use the [README](../README.md) and existing guides for installation and command examples. Keep raw scanner reports in a controlled location: they may carry actual credential material, even though canonical adapters select metadata for reporting.
