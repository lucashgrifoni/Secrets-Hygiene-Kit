# AWS Access Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when a detector reports an AWS access key ID or related credential material.
Do not paste the key value into tickets, chat, waiver reasons, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and redacted key prefix.
- Identify the AWS account, IAM principal, environment, and owner if available.
- An access key ID alone is an identifier, not the secret used to authenticate. Confirm
  whether the secret half or a temporary session credential was also exposed.
- Distinguish a long-lived IAM or root key from an STS session. Temporary credentials need
  session-specific containment; they cannot be disabled as an IAM access key.

## Invalidate

- For a long-lived key, have the authorized owner deactivate it through the applicable
  IAM-user or root-credential management controls before relying on source cleanup.
- If ownership is unclear, escalate to the cloud or platform owner for containment.
- Record issuer confirmation that the identified key is inactive or deleted. Investigate
  sessions and credentials created with it; disabling the source key does not prove those
  are invalid. An exposed key must not be reactivated as routine rollback.

## Rotate

- Create a replacement key only if the workload still needs long-lived credentials.
- Do not replace root user keys; migrate those consumers to scoped roles or IAM credentials
  under the account owner's recovery plan.
- Prefer workload identity, federation, or short-lived credentials when feasible.
- Update the dependent workload through the approved secret manager or CI/CD variable store.
- Confirm each consumer uses the replacement through an authenticated dependency operation
  before closing recovery, including workers and scheduled jobs.

## Audit Usage

- Review CloudTrail activity for the affected principal during the exposure window.
- Check unusual regions, source IPs, requests, privilege changes, and data access events.
- Record the accounts, regions, interval, retention, and event categories reviewed. Event
  history covers regional management events for 90 days; data events require separate
  configured coverage. Missing logs do not prove that no abuse occurred.

## Communicate

- Notify the service owner, AppSec, and cloud owner with redacted evidence.
- Include actions taken, exposure window, audit status, and residual risk.

## Close

- Remove the secret from source, invalidate caches or artifacts when possible, and add a
  regression control such as pre-commit or CI scanning.

## References

- [AWS credential classification and response](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)
- [IAM access key management](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [Root user access key containment](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html)
- [Temporary credential containment](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html)
- [CloudTrail event history limits](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
