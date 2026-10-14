---
type: "workflow"
title: "Incident and remediation artifacts"
description: "Prepare human playbook records and bounded active-finding exchanges without treating them as provider-side remediation."
tags: ["incident","remediation","playbooks"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:27:23.043Z
sources:
  - id: openwiki-source-b443de470d7caed0d8a56fec
    resource: repo://src/secguard/core/playbooks.py
  - id: openwiki-source-275f5a1599e6c76065cfc723
    resource: repo://src/secguard/core/remediation.py
generated: { by: "codex", at: "2026-10-14T19:25:43.426Z" }
---

# Incident and remediation artifacts

## Playbooks are human instructions

Packaged playbooks carry a vetted date, and their freshness checks use the configured maximum age. The playbook subsystem prints instructions; it does not revoke a provider credential or mutate provider state ([playbook contract](../../src/secguard/core/playbooks.py#L1-L27)). Incident rendering produces a Markdown response record with containment and close-out tasks ([incident renderer](../../src/secguard/core/incident.py)). A checked-off task needs separate action evidence before it supports closure.

## Export only the active occurrence set

The remediation builder requires a checked date and exports active findings, omitting scanner free text and native digests. It derives an occurrence fingerprint from repository, secret type, path, line and the finding fingerprint, then sorts the exchange by that fingerprint. The exchange records the gate decision, threshold, expired-waiver count and omitted-waived count ([builder](../../src/secguard/core/remediation.py#L102-L152)). This maintains the distinction between waived records and active remediation work.

The serialized exchange is bounded by its byte limit before output; the reader applies the same limit and avoids echoing invalid values in diagnostics. Use the existing integration guide for a receiving product's import contract, and inspect both producer and consumer semantics before relying on the exchange.

Return to [quickstart](../quickstart.md) for routing or [waivers and gate](../concepts/waivers-and-gate.md) for the recorded decision.
