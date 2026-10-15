# Compatibility and support

This document defines the public contract for secguard 1.x. Version 1.0.0
promotes the 0.5.0 report-processing behavior to a stable contract; it does not
add scanner execution, credential-provider access or automatic remediation.

## Stable and experimental surfaces

| Surface | 1.x commitment | Reference |
| --- | --- | --- |
| CLI | Existing command names, documented options, defaults and exit meanings remain compatible within 1.x | [Quickstart](quickstart.md) and each command's `--help` |
| Canonical input and output | The `secguard.findings/v1` shape and reclassification rules remain compatible | [Documents and schema evolution](#documents-and-schema-evolution) |
| Waivers and catalog | Versioned policy documents, scope matching, expiry and explicit catalog selection remain compatible | [Policy and waiver decisions](#policy-and-waiver-decisions) |
| SARIF | SARIF 2.1.0, resolved severity, finding fingerprints and waived-result suppressions remain supported | [Identity and correlation](#identity-and-correlation) |
| Remediation exchange | `secguard.remediation/v1` remains a stable, active-only file exchange | [Remediation Hub](remediation-hub.md) |
| OPA and DefectDojo exports | The documented file formats and decision semantics remain supported for the tested consumers | [OPA and DefectDojo](integrations.md) |
| Composite Action | Documented inputs, defaults and output meanings remain compatible | [PR comments](pr-comments.md) and `action.yml` in the selected revision |
| Hub Python bridge | Experimental; tied to the reviewed Hub source, outside the 1.x compatibility guarantee | [Experimental Hub bridge](#experimental-hub-bridge) |

Python module paths, classes, private helpers and validator error wording are
implementation details, not a supported library API. Console tables, help
layout, Markdown prose and playbook text may change. Use JSON, SARIF, Action
outputs and process exit codes for automation rather than parsing display text.

## Version and deprecation policy

- Patch releases preserve the stable interfaces and correct defects. Security
  fixes can reject previously accepted malformed or unsafe input; the changelog
  must identify the rejection and its effect on callers.
- Minor releases can add opt-in commands, options, adapters and exports without
  changing existing invocations or existing versioned document shapes.
- Removing or renaming a stable interface, changing an existing default or exit
  meaning, or changing an identity algorithm requires a major release and
  migration notes. A deprecated interface remains available throughout 1.x;
  removal is announced in a minor release before a later major release.
- Catalog mappings, default classification data and response guidance can be
  reviewed and updated in a minor release. A documented security correction may
  also update them in a patch. These updates can change resolved severity and
  gate results without changing the document schema. The changelog must name
  changes that affect classification, waiver applicability or consumer identity.

Pin the secguard release or reviewed commit, detector versions and policy files
when reproducing a decision. Review classification changes before upgrading.
This policy does not promise identical findings across different detector
reports, catalogs, waiver files, check dates or software versions.

## CLI and CI decisions

The stable command families are `init`, `scan check`, `scan normalize`, `report`,
`waivers check|list|add`, `playbooks list|show|check`, `incident start`, `policy
show` and `version`. Run a command with `--help` for its complete option list.

| Result | Exit | Meaning |
| --- | --- | --- |
| Successful operation | `0` | The requested operation succeeded; a gating command passed |
| Policy block | `1` | `scan check`, `waivers check` or `playbooks check` found its blocking condition |
| Processing or usage error | `2` | Input, arguments, policy, destination or processing prevented a valid result |

`scan check` defaults to `--format auto` and `--fail-on high`. Repeated `--input`
combines reports. An explicit format applies to every input. `--fail-on none`
disables the finding threshold but still blocks on expired waivers.

`scan normalize` classifies and combines findings without applying waivers or
evaluating a gate. `report` applies waivers for display but returns `0` after
successful rendering, including when it displays expired waivers. Use `scan
check` or `waivers check` to enforce policy. A generated file alone does not
establish a passing decision: a blocked check can write valid review artifacts.

The Action returns `verdict` as `PASS`, `BLOCK`, `ERROR` or `NO-REPORTS`, plus
`reports-found`, `comment-status` and `comment-id`. Missing individual report
paths are skipped; no present reports fails unless `allow-missing-reports` is
explicitly enabled. A present report does not prove that its scanner completed.
Playbook freshness checking is enabled by default and can fail the Action
independently of the finding threshold. PR publication is opt-in and preserves
a blocking gate; see [PR comments](pr-comments.md) for the trusted-repository
and bot-identity requirements.

The `--allow-override` option on waiver and playbook checks is for the generated
local pre-commit hooks. It requires `SECGUARD_OVERRIDE=1` and a sufficiently long
`SECGUARD_OVERRIDE_REASON`. `scan check` does not accept this bypass; do not pass
the hook option in CI.

## Documents and schema evolution

| Document | Direction and contents |
| --- | --- |
| `secguard.findings/v1` | Canonical input/output: `schema` and `findings`. Each finding includes classification, location, scanner/rule, ID, fingerprint and detector-reported verification. Optional metadata includes source coordinates, commit, remediation hint and corroborating scanners/rules. |
| `secguard.synthetic-findings/v1` | Synthetic input for fixtures and examples; it is not evidence that a scanner ran. |
| `secguard.waiver/v1` | YAML policy: `schema`, `waivers` and each waiver's ID, rule, path, reason, owner, approver and expiry. |
| `secguard.rules/v1` | YAML catalog: `schema`, fallback type, secret types and detector rule mappings. Local overrides are merged only when selected explicitly. |
| `secguard.policy-input/v1` | OPA snapshot: producer, check date, gate, expired waiver IDs and every finding with reconciled status and matching waiver IDs. |
| `secguard.remediation/v1` | Active-only exchange: producer, repository, check date, gate, omitted waived count and bounded occurrence records. |
| DefectDojo Generic Findings Import | `type: secguard`, producer version, description and active findings. This uses the consumer's format, not a secguard schema identifier. |
| SARIF 2.1.0 | Review output retaining active and waived findings; waived results carry external suppressions. |

Canonical JSON from `scan check --json` contains both active and waived findings;
it does not contain the gate decision or waiver status. Reimport reapplies the
selected catalog and waiver policy, recomputes derived classification and IDs,
and retains the stronger of imported and catalog severity. It does not replay
an authenticated historical decision. Use the OPA snapshot for reconciled
statuses or the remediation exchange for an active-only handoff with its gate.

The canonical, waiver, catalog and remediation models reject unknown fields.
Canonical reimport and the remediation exchange also reject scalar type
coercions at their input boundaries. Waiver dates accept YAML dates or
`YYYY-MM-DD` strings. A version label is not permission to add arbitrary fields.

Existing `/v1` documents keep their field names, types, required/optional status
and meaning throughout 1.x. Adding a field, including an optional output field,
requires a new document schema identifier because older strict readers may
reject it. A new schema must be opt-in while `/v1` remains supported in 1.x;
the release notes must describe the producer/reader transition. Unknown schema
versions are rejected rather than silently interpreted as `/v1`. JSON whitespace
and object-key order are not part of the contract.

## Identity and correlation

Canonical findings merge by resolved secret type, repository-relative path and
line. The result retains the strongest severity and every contributing rule.
Primary selection ranks native fingerprints, presence of column and commit,
then scanner and fingerprint. The selected scanner/fingerprint and canonical ID
within a merge group do not depend on input order. Complete ranking ties can
retain the first observation's other metadata, so reversing tied reports can
change fields such as column, message or commit. Final sorting uses descending
severity, path, line and canonical ID; complete sorting ties can retain input
group order.

These identifiers have different purposes:

| Identifier | Identity basis and limits |
| --- | --- |
| Canonical `id` | Scanner and selected primary fingerprint; a richer observation or a different native fingerprint can change the selected primary and ID. It is not a credential identifier. |
| Canonical `fingerprint` | Selected detector fingerprint or a fallback derived from scanner, rule, path, line, column and message. Changes to those inputs can change identity. |
| SARIF `partialFingerprints["secguard/v1"]` | The canonical fingerprint. The rule ID is the canonical type at its catalog default severity, otherwise `<type>/<severity>`. |
| Remediation occurrence fingerprint | SHA-256 of repository, secret type, path, line and selected canonical fingerprint. Distinct locations remain distinct occurrences. |
| DefectDojo `unique_id_from_tool` | SHA-256 identity from secret type, path and line, prefixed with `secguard:`. Additional detector corroboration preserves it when these inputs remain unchanged. |

Preserving an identifier does not establish remediation. Moving source lines or
paths can create a new consumer record. Catalog changes that remap a secret
type can also affect correlation. Configure DefectDojo's stable-ID matching and
keep `close_old_findings=false`; its tested reimport behavior does not update
an existing finding's severity automatically. Review changed severities as
described in the [integration guide](integrations.md).

## Policy and waiver decisions

The severity order is `info`, `low`, `medium`, `high`, `critical`. A detector's
positive credential-verification claim raises severity to Critical. `true`,
`false` and `null` remain imported report values; secguard does not contact the
issuer to verify them. Unmapped rules use the catalog fallback and carry
`mapping: fallback`.

A local `.secguard/rules.yaml` is never discovered automatically. `--rules`
selects an override explicitly, and severity reductions produce a notice.

When `--waivers` is omitted, an absent `.secguard/waivers.yaml` means no waivers
and produces a notice. An explicitly selected file must exist, including the
default path when passed as an argument. Waiver-management commands require
their selected file to exist, except `waivers add`, which can create it.

Waiver matching is repository-relative: `*` stays within one path segment;
`**` can cross directories. Detector-scoped waivers must collectively cover
every contributing rule. Partial coverage leaves the finding active. A
`secret-type:` scope covers the canonical type across detectors.

An expiry date remains valid on that date and expires the following day. Any
expired waiver blocks `scan check`, even without a matching finding; expired
waivers suppress nothing. `waivers add` caps new expiries at 365 days and warns
above 90 days. Those creation limits do not make older files unreadable.
Owner and approver fields record a decision without authenticating identities;
repository review and access controls must protect policy changes.

## Supported environments and tested integrations

The supported runtime matrix is Python 3.12, 3.13 and 3.14 on Linux, Windows and
macOS. The package's Python floor is 3.12; a permissive package constraint does
not establish support for future Python versions. Distribution is by versioned
GitHub Release wheel and source archive. PyPI is outside the supported
distribution channels.

| Producer or consumer | Tested version and scope |
| --- | --- |
| Gitleaks | 8.30.1, JSON array from `dir` |
| TruffleHog | 3.97.9, JSON Lines from `filesystem` |
| detect-secrets | 1.5.0, scan baseline JSON |
| Betterleaks | 1.9.0, 1.x JSON array selected explicitly with `--format betterleaks`; 2.x envelopes are excluded |
| OPA | 1.21.1 with the packaged Rego v1 example and reconciled input |
| DefectDojo | 3.4.0 Generic Findings Import, with the documented matching and reimport settings |

These are bounded compatibility observations, not a claim that every release,
plugin, source mode or platform-produced report is supported. See the
[detector corpus](detector-compatibility.md) for capture provenance and limits.
Consumer evidence uses owned local environments and synthetic data; it does
not establish external adoption or production acceptance. GitHub Enterprise
Server PR publication needs its own deployment acceptance run.

Security maintenance and private reporting are defined in
[SECURITY.md](https://github.com/lucashgrifoni/secrets-hygiene-kit/blob/main/SECURITY.md).

## Experimental Hub bridge

The stable remediation file exchange is separate from the optional Python
bridge. The bridge targets Hub 0.1.0 at the source revision documented in the
[Hub guide](remediation-hub.md). Hub is a separate PreAlpha project; its reviewed
local source is not evidence of a compatible published package.

The bridge and `secguard.hub-preview/v1` remain experimental and may change in
a minor secguard release with migration notes. Preview mode does not open a
database. Applying an import requires an explicit isolated SQLite file and
`--apply`; imports and preview files do not share an atomic transaction.
Concurrent importers and production deployment require separate validation.
The bridge does not post tracker issues or close remediation tasks.

## Migrating from 0.5.0 to 1.0.0

No functional migration is planned for this transition. Existing CLI arguments,
waiver/catalog files, schema identifiers, exit meanings and export identity
algorithms are retained. Version strings and versioned playbook links change
to 1.0.0. The compatibility policy above becomes the maintenance commitment;
the experimental Hub bridge is excluded from that commitment.

1. Preserve the 0.5.0 wheel, detector versions, policies and representative
   sanitized reports so the previous environment can be reproduced.
2. Install the versioned 1.0.0 wheel in a separate virtual environment using the
   [README instructions](https://github.com/lucashgrifoni/secrets-hygiene-kit#install-100).
   Update a composite Action reference to the reviewed 1.0.0 release commit.
3. Replay passing, blocking, malformed-input and expired-waiver cases with the
   same reports, catalog, waivers and explicit `--today` date. Compare exit
   status, classification, IDs, waiver applicability and exported decisions.
   Account for the expected producer version and playbook-link changes.
4. For optional consumers, validate their documented settings before reimport.
   Preserve DefectDojo triage and review stored severity; use a dedicated Hub
   database and review an interrupted import before retrying.

For rollback, restore the prior virtual environment or install the preserved
0.5.0 wheel in a clean one, then restore the reviewed Action reference and
policy snapshot. The core has no database migration. Consumer changes and Hub
imports need their own recovery procedure; downgrading secguard does not undo
them. An expired waiver remains expired after rollback.

The operational limits remain: 64 MiB per report, in-memory aggregation without
an aggregate memory cap, 16 MiB/10,000 findings per remediation exchange,
selected metadata that may contain caller-supplied sensitive text, and output
preflight without filesystem isolation or an atomic multi-file transaction.
Successful processing is not proof of complete scanner coverage, credential
revocation or a repository free of secrets.
