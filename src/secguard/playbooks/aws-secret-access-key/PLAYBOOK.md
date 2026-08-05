# AWS Secret Access Key Leak Playbook

Vetted: 2026-08-04

## Scope

Use this playbook when the secret half of an AWS long-lived credential pair is exposed. The
access key ID alone identifies a key; the secret access key is what signs requests, so treat
this as an active credential compromise until proven otherwise.

Do not paste the secret value into tickets, chat, waiver reasons, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the redacted access
  key ID prefix.
- Resolve the key to an account and principal with `aws sts get-access-key-info` if you only
  have the key ID, then confirm the IAM user with `aws iam get-access-key-last-used`.
- Note the attached policies and whether the principal can escalate, assume roles, or reach
  data stores.
- Establish the exposure window: first commit that introduced the value, and whether the
  repository, artifact, or log was ever public.

## Invalidate

- Deactivate the access key in IAM first. Deactivation is reversible and stops signing
  immediately, so it is the safe first move even when ownership is unclear.
- Delete the key once the dependent workloads are confirmed migrated.
- If the principal has broad permissions and abuse is suspected, attach an explicit deny
  policy to the principal while you investigate.
- Escalate to the account or platform owner when you lack IAM permissions. Containment
  authority belongs to them, not to the person who found the leak.

## Rotate

- Create a replacement key only if the workload genuinely needs long-lived credentials.
- Prefer IAM roles, instance or task roles, or OIDC federation from the CI provider. Most
  leaked keys exist because a workload could have used a role and did not.
- Distribute the replacement through the approved secret manager or CI/CD variable store,
  never by editing a file in the repository.
- Scope the replacement down to the permissions the workload actually used.

## Audit Usage

- Review CloudTrail for the principal across the entire exposure window, not just recent
  activity.
- Look for `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`,
  `CreateRole`, and `AssumeRole` events: persistence is established before data is taken.
- Check for unfamiliar regions, unusual source IPs, and resource creation, especially compute
  in regions the account does not normally use.
- Check data-plane access for S3, DynamoDB, RDS, and Secrets Manager reads.

## Communicate

- Notify the service owner, AppSec, and the cloud account owner with redacted evidence.
- State actions taken, exposure window, audit status, and residual risk.
- If billing anomalies or unfamiliar resources appear, escalate to an incident and involve
  the account owner for AWS support engagement.

## Close

- Remove the secret from source and rewrite history only after the credential is invalid;
  history rewriting is not containment.
- Purge the value from build artifacts, container images, and CI logs where feasible.
- Add a regression control: pre-commit detection, CI scanning, and a waiver only if the match
  is an intentional fixture.
- Record residual risk with an owner and a review date if the audit could not fully rule out
  abuse.
