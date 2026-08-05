# AWS Access Key Leak Playbook

Vetted: 2026-05-18

## Scope

Use this playbook when a detector reports an AWS access key ID or related credential material.
Do not paste the key value into tickets, chat, waiver reasons, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and redacted key prefix.
- Identify the AWS account, IAM principal, environment, and owner if available.

## Invalidate

- Disable the exposed access key through IAM before relying on source cleanup.
- If ownership is unclear, escalate to the cloud or platform owner for containment.

## Rotate

- Create a replacement key only if the workload still needs long-lived credentials.
- Prefer workload identity, federation, or short-lived credentials when feasible.
- Update the dependent workload through the approved secret manager or CI/CD variable store.

## Audit Usage

- Review CloudTrail activity for the affected principal during the exposure window.
- Check unusual regions, source IPs, API calls, privilege changes, and data access events.

## Communicate

- Notify the service owner, AppSec, and cloud owner with redacted evidence.
- Include actions taken, exposure window, audit status, and residual risk.

## Close

- Remove the secret from source, invalidate caches or artifacts when possible, and add a
  regression control such as pre-commit or CI scanning.

