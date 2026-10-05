# Google Cloud Service Account Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when a Google Cloud service account key file (the JSON containing
`private_key`) is exposed. User-managed service account keys normally have no expiry, but
expiry policies and key status must be checked. A Google API key is a different credential;
identify its issuer and use the generic API key response rather than these IAM key steps.

Do not paste the JSON or the private key block into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the service account
  email and key id from the JSON in the restricted incident record. Never include the
  `private_key` block.
- Identify the project, the roles bound to the service account, and whether those bindings are
  at project, folder, or organization level.
- Check whether the service account can impersonate other identities, which turns a narrow
  leak into a broad one.
- Establish the exposure window.

## Invalidate

- Disable the key first, then delete it. Deletion is irreversible; disabling
  gives you a reversible containment step while you confirm which workloads depend on it.
- Confirm the exact key's disabled state. Disabling or deleting a key does not revoke
  short-lived credentials already issued with it; do not re-enable the exposed key as
  routine rollback.
- If abuse or a compromised derived token requires broader containment, have the incident
  owner assess disabling the service account or changing permissions. Disabling the account
  affects every workload that uses it and needs explicit scope and service recovery planning.
- Escalate to the project or organization owner when you lack IAM permissions.

## Rotate

- Prefer workload identity federation or attached service accounts over a downloadable key.
- If a key is required, securely create and deliver the replacement through the approved
  credential-handling channel, never through the repository. If a workload can already
  authenticate to a cloud secret store, review whether it can use that identity directly;
  Google advises against storing service account keys in cloud secret stores for that case.
- Prove each consumer adopted the replacement and can authenticate an actual dependency
  operation, including background and scheduled consumers.
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
- Correlate the service account identity and key identifier where logs provide it. Some
  services omit key attribution. Record permissions, projects, log categories, retention,
  pagination, and interval coverage before drawing conclusions about absence of abuse.

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

## References

- [Disable and enable service account keys](https://docs.cloud.google.com/iam/docs/keys-disable-enable)
- [Service account key management, expiry, and storage](https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [Cloud Audit Logs coverage](https://docs.cloud.google.com/logging/docs/audit)
- [Service account key attribution in logs](https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts)
- [Google API key management](https://docs.cloud.google.com/docs/authentication/api-keys-best-practices)
