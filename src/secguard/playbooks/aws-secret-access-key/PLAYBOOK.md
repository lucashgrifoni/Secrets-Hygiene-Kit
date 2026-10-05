# AWS Secret Access Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when the secret half of an AWS long-lived credential pair is exposed. The
access key ID alone identifies a key; the secret access key is what signs requests, so treat
this as a credential exposure requiring containment. Exposure alone does not prove
unauthorized use.

Do not paste the secret value into tickets, chat, waiver reasons, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the redacted access
  key ID prefix.
- Resolve the key's account with `aws sts get-access-key-info` if you only have the key ID;
  that operation does not identify the principal or establish key validity. For an IAM user
  key, confirm its owner with `aws iam get-access-key-last-used` in the authorized account.
- Note the attached policies and whether the principal can escalate, assume roles, or reach
  data stores.
- Establish the exposure window: first commit that introduced the value, and whether the
  repository, artifact, or log was ever public.

## Invalidate

- Have the authorized account owner deactivate the exact exposed access key through the
  applicable IAM-user or root-credential management controls and confirm its inactive status.
  Do not reactivate an exposed key as routine rollback.
- Delete the key once the dependent workloads are confirmed migrated.
- Identify temporary sessions and other credentials issued with the key. Disabling it does
  not prove those are revoked. When abuse is suspected, the incident owner must choose
  session revocation or scoped permission denial with the affected role and workload impact
  identified.
- Escalate to the account or platform owner when you lack IAM permissions. Containment
  authority belongs to them, not to the person who found the leak.

## Rotate

- Create a replacement key only if the workload genuinely needs long-lived credentials.
- Do not replace root user keys; migrate those consumers to scoped roles or IAM credentials
  under the account owner's recovery plan.
- Prefer IAM roles, instance or task roles, or OIDC federation from the CI provider.
- Distribute the replacement through the approved secret manager or CI/CD variable store,
  never by editing a file in the repository.
- Scope the replacement down to the permissions the workload actually used.
- Confirm adoption and a successful authenticated dependency operation for every consumer,
  including workers and scheduled jobs, before closing recovery.

## Audit Usage

- Review CloudTrail for the principal across the entire exposure window, not just recent
  activity.
- Look for `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`,
  `CreateRole`, and `AssumeRole` events that may indicate persistence or role assumption.
- Check for unfamiliar regions, unusual source IPs, and resource creation, especially compute
  in regions the account does not normally use.
- Check data-plane access for S3, DynamoDB, RDS, and Secrets Manager reads.
- Verify the relevant service logs and CloudTrail event categories were enabled and retained
  for the reviewed accounts, regions, and interval. Regional event history covers 90 days of
  management events and does not include data events; unavailable coverage remains a gap.

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

## References

- [Access key account lookup](https://docs.aws.amazon.com/cli/latest/reference/sts/get-access-key-info.html)
- [IAM access key owner and last-use metadata](https://docs.aws.amazon.com/cli/latest/reference/iam/get-access-key-last-used.html)
- [IAM access key management](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [Root user access key containment](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html)
- [Temporary credential containment](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html)
- [CloudTrail event history limits](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
