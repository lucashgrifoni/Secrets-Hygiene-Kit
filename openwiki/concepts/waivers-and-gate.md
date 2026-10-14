---
type: "concept"
title: "Waivers, expiry and gate semantics"
description: "Separate reviewed exception scope from expiration and the core blocking decision."
tags: ["waivers","gate","exceptions"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:27:23.043Z
sources:
  - id: openwiki-source-566f432c8bc3028d6db9931b
    resource: repo://src/secguard/core/reconcile.py
  - id: openwiki-source-97ae8a49ef583b3a37ea08b6
    resource: repo://src/secguard/core/waivers.py
generated: { by: "codex", at: "2026-10-14T19:27:23.043Z" }
---

# Waivers, expiry and gate semantics

## Scope is explicit

A waiver requires id, rule, repository path/glob, reason, owner, expiry date and approver. Validation constrains text, patterns and repository-relative path shape. Calendar expiry is inclusive: the waiver becomes expired when its expires_at date is earlier than the checked date ([waiver model](../../src/secguard/core/waivers.py#L66-L168)).

The path must match. A secret-type scope matches the canonical type; a detector-rule scope must cover every contributing rule in the merged finding. Matching one contributing detector alone does not suppress the other detector's observation ([scope matching](../../src/secguard/core/waivers.py#L170-L188)).

## Reconciliation owns dispositions

`reconcile` separates active and waived findings and records expired, unused and narrowed waivers. The core outcome blocks when active findings reach the selected severity threshold or when expired waivers exist. Selecting no severity threshold removes the active-finding threshold but does not remove the core expiry condition ([outcome](../../src/secguard/core/reconcile.py#L49-L88), [reconciliation](../../src/secguard/core/reconcile.py#L114-L172)).

The standalone waiver-check and playbook-freshness commands have explicit audited override paths. The scan-check command still exits from its core outcome; an override receipt is not remediation evidence. A waiver records acceptance of an exception, not revocation, rotation or confirmation that the secret is invalid.

See [normalization](../architecture/report-normalization.md) for the occurrence/rule identity and [response artifacts](../workflows/response-artifacts.md) for subsequent work.
