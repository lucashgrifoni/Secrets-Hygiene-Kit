# Optional metadata minimization

This option is unreleased; published 1.0.0 defaults are unchanged.

```console
secguard scan check --input gitleaks.json --minimize-metadata --json findings.json --sarif findings.sarif
secguard scan normalize --input gitleaks.json --minimize-metadata --output findings.json
secguard report --input findings.json --minimize-metadata --output report.md
```

`--minimize-metadata` removes caller prose rather than trying to recognize
every possible credential. It operates locally without provider calls or
external services. The default remains the existing metadata-preserving mode.

| Field or channel | Source | Behavior with the option |
| --- | --- | --- |
| `message`, `remediation` | Selected detector description, synthetic/canonical input | Replace message with fixed text; set remediation to null |
| `secret_title`, catalog title | Packaged or explicitly selected catalog | Use the neutral title `Secret finding`; preserve classification, rule mappings and severity |
| Waiver reason, owner, approver | Selected waiver policy | Replace in-memory display prose; preserve ID, rule, path and expiry; never rewrite the policy file |
| Canonical JSON and normalize stdout | Projected findings | Same strict `/v1` shape and original identities, minimized prose |
| SARIF | Findings, catalog and waiver summaries | Minimized messages, titles and suppression prose; same locations, severities and fingerprints |
| OPA | Reconciled findings | Minimized prose; same resolved gate, waiver IDs, statuses and classification |
| DefectDojo | Active findings | Minimized titles/descriptions; same severity and stable unique IDs; use the documented ID matching settings |
| Remediation exchange | Active findings | Existing allowlist already excludes these prose fields; exchange identity and content remain unchanged |
| Markdown, PR draft and scan console | Reconciled allowlist | Existing minimal fields remain; any waiver prose used for diagnostics is minimized |
| Processing errors, warnings and write notices | These three commands | Generic diagnostics and output notices; inspect originals locally to diagnose details |

There is no separate logging backend. The diagnostic policy covers the console
stdout/stderr produced inside these commands after argument parsing. Parser
errors, other command families, composite-Action publication messages, scanner
logs and external consumer logs are outside this option.

## Identity and reimport

Original messages are normalized and combined before projection, so fallback
fingerprints and primary selection keep their existing algorithm. IDs, paths,
rules, line/column, commits, verification claims, corroboration and waiver
matching remain unchanged. Reimport minimized output as canonical
`secguard.findings/v1`, using auto format or the canonical format. No fields are
added to an existing schema. Recreating a synthetic report from the shortened
message is a different input and does not preserve this identity guarantee.

With DefectDojo, retain matching by `unique_id_from_tool` as described in the
[integration guide](integrations.md). An independently configured consumer
that correlates on mutable titles can behave differently when titles change.

## Limits and review

This policy intentionally removes useful, harmless prose too. Keep the original
report and waiver policy in an appropriately protected location for triage,
ownership and approval review. The tool does not authenticate an approver.

Paths, repository names, scanner/rule names, playbook/type identifiers,
fingerprints and waiver IDs remain caller-controlled metadata. They may
themselves contain sensitive information. They are retained because changing
them could alter correlation, waiver scope or the record's meaning. Review
these fields and completion-marker paths before sharing any artifact.

There is no universal secret-removal guarantee or measured detector
false-positive/false-negative rate: this is an explicit field policy, not a
credential detector. Tests use synthetic canaries to verify the covered
surfaces, including processing failures, Unicode, long messages and canonical
reimport. Raw secret-bearing detector fields continue to be excluded by the
existing adapter allowlists in either mode.
