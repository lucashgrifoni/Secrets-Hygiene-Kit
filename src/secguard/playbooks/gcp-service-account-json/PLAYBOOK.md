# Google Cloud Service Account Key Leak Playbook

Vetted: 2026-08-04

## Scope

Use this playbook when a Google Cloud service account key file (the JSON containing
`private_key`) or an API key is exposed. A service account key does not expire, so an exposed
key stays usable until someone deletes it.

Do not paste the JSON or the private key block into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the service account
  email and key id from the JSON. The key id and client email are safe to record; the
  `private_key` block is not.
- Identify the project, the roles bound to the service account, and whether those bindings are
  at project, folder, or organization level.
- Check whether the service account can impersonate other identities, which turns a narrow
  leak into a broad one.
- Establish the exposure window.

## Invalidate

- Disable the key first, then delete it. Deletion is immediate and irreversible; disabling
  gives you a reversible containment step while you confirm which workloads depend on it.
- If the service account holds broad roles and abuse is suspected, remove its role bindings or
  disable the service account entirely while you investigate.
- Escalate to the project or organization owner when you lack IAM permissions.

## Rotate

- Prefer workload identity federation or attached service accounts over a downloadable key.
  A key that does not exist cannot leak, and most workloads that use one do not need it.
- If a key is genuinely required, create the replacement and distribute it through the
  approved secret manager, never through the repository.
- Reduce role bindings to the permissions the workload actually exercised.
- Consider enforcing the organization policy constraint that disables service account key
  creation so the pattern does not return.

## Audit Usage

- Review Cloud Audit Logs (Admin Activity and Data Access) for the service account across the
  exposure window.
- Data Access logs are not enabled by default for every service. If they were off, record that
  gap rather than reporting the window as clean.
- Look for IAM policy changes, new service accounts or keys, role grants, compute creation,
  and Cloud Storage or BigQuery reads.
- Check for activity from unfamiliar regions and outside normal automation hours.

## Communicate

- Notify the service owner, AppSec, and the project or organization owner with redacted
  evidence.
- State the exposure window, what the audit covered, and explicitly which log types were not
  enabled.
- If billing anomalies or unfamiliar resources appear, escalate to an incident.

## Close

- Remove the key file from source, artifacts, container images, and CI logs.
- Add detection for service account JSON and private key blocks in pre-commit and CI.
- Record residual risk with an owner and a review date, including any audit-log coverage gap.
