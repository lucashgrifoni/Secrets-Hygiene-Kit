# Local Remediation Hub handoff

Secguard exports active findings as `secguard.remediation/v1`. Its optional
Python bridge converts that exchange into AppSec Remediation Hub findings,
groups and tasks, and writes a local preview of GitHub issue payloads.

The supported consumer contract is Hub `0.1.0` at source commit
`fbd3b004b5eb7a3b5ffd29a83070292d4cadbf99`. Compatibility is checked against
that local source and its current worktree. Hub is a separate PreAlpha project;
this does not establish compatibility with a published package or release.
Use an environment containing the reviewed Hub source and the secguard wheel.
Hub remains optional for other secguard commands.

## Export and preview

Create the exchange with the existing check command:

```sh
secguard scan check --input gitleaks.json --remediation remediation.json --repository acme/example
```

The scanner check still returns its gate exit code. A blocked check can produce
a valid exchange for remediation. The export includes resolved severities,
repository-relative paths, optional line numbers, occurrence fingerprints and
playbook identifiers. It omits waived findings, scanner messages, detector
digests, reasons and arbitrary metadata. `omitted_waived` records the count;
expired waivers remain part of the gate decision.

In the environment containing both packages, preview the handoff:

```sh
python -m secguard.integrations.remediation_hub --input remediation.json --issues-output issues-preview.json
```

This validates the exchange and consumer contract, then writes the issue
preview. It never constructs a Hub Store or creates, opens or compares a
database. An optional `--database FILE` is checked for path safety in this mode;
the preview still describes proposed records rather than existing state.

## Apply to an isolated database

Use a dedicated SQLite file exclusively for this bridge:

```sh
python -m secguard.integrations.remediation_hub --input remediation.json --database secguard-hub.sqlite --issues-output issues-preview.json --apply
```

`--apply` requires an explicit database path. Database URLs and in-memory
databases are rejected. The file must be new or already marked by this bridge.
Existing foreign SQLite databases and zero-byte files are rejected before Hub
migration. New files receive SQLite `application_id` `0x53475248` (`SGRH`);
the marker identifies operational ownership and does not authenticate a file.
A marked file left by an interrupted migration can be retried.
New database paths must also have no existing SQLite sidecar files.
Input, output, database and SQLite journal/WAL/SHM
paths must be distinct. Linked destinations, linked ancestors and existing
hard-linked destination files are rejected. The output is replaced through a
temporary file in its own directory. These checks do not provide protection
against another process changing paths during execution.

The bridge creates the Hub schema and writes only records belonging to the
received occurrences. It uses the existing Hub models, secret correlation,
scoring, SLA calculation and GitHub payload renderer. It does not run the Hub's
global correlation, ownership routing or tracker synchronization commands.
Do not share this database with concurrent importers or use it as a production
integration without separate operational validation.

## Mapping and replay

| Exchange field | Hub record |
|---|---|
| Finding | `RawFinding` and `NormalizedFinding`, category `secret` |
| `severity` | Same normalized severity, including low and info |
| `repository`, `path`, `line` | Repository/asset, file path, optional single-line range |
| `fingerprint` | Normalized and secret fingerprint; deterministic record IDs |
| `secret_type` | Secret type and a fixed-format group/task title |
| `playbook` | Provider guide ID and versioned URL in normalized payload |
| Native Hub task playbook | `secret_exposed` |

An occurrence fingerprint includes repository, type, path, line and native
detector fingerprint. Two locations remain distinct even if a detector gives
them the same native digest. Each occurrence has its own group and task.
IDs use the `RAW-SG-`, `NF-SG-`, `FG-SG-` and `TASK-SG-` prefixes followed by the
64-character exchange fingerprint. Ingestion run IDs hash the exchange.

New groups start open with owner `appsec`. The Hub calculates priority using
its default asset and scoring values, without external enrichment or a claim
that the repository's exposure or business criticality has been assessed.
Tasks use the Hub's `flat-severity` SLA policy. Priority and severity remain
separate fields.

Repeating a complete occurrence preserves its persisted records, status,
assignment and timestamps. Importing another occurrence also preserves older
closed groups and tasks. Identity conflicts are rejected before any finding,
group or task write; the bridge does not overwrite a changed classification.

The Hub commits each write separately. An interrupted import can therefore
leave partial records. Retrying resumes missing raw findings, normalized
findings, groups and tasks while preserving existing records. A missing task
can be recreated only for an open group. A task without its group, or a missing
task for a closed or otherwise managed group, requires operator review and
returns an error. There is no transaction spanning the database and preview
file; review a failure before retrying against the same isolated database.

## Review the issue preview

The output is a `secguard.hub-preview/v1` receipt with `dry_run: true`, the
repository, original gate, waived count, import counts and issue payloads.
Payloads contain the Hub's `title`, `body` and `labels`, plus a versioned
provider response guide and the local task status. They cover only occurrences
in the current exchange. Free-text titles and owners edited in the database
are projected to the fixed-format title and `appsec` preview owner; review the
actual assignment in the Hub before using a payload.

The bridge does not post issues, contact GitHub, rotate credentials, attach
remediation evidence or close tasks. A playbook is guidance, and a completed
checklist does not establish revocation or a clean rescan. Jira and ServiceNow
are outside this integration's supported contract.

Review paths, repository names and issue contents before sharing them. An
allowlist excludes raw scanner text but cannot determine whether a repository
name or filename itself contains sensitive information. Versioned playbook
links are constructed locally; availability of the corresponding public tag
is a separate release check.

Exit `0` means the local handoff and output succeeded, including when the
preserved gate is `BLOCK` or the exchange is empty. It does not mean the scan
passed or the secrets were remediated. Exit `2` means arguments, input,
consumer compatibility, destination safety or local processing failed.
Diagnostics omit input values and tracebacks.
