# Slack Webhook Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when an incoming Slack webhook URL is exposed. Treat the full URL as a
secret because it can post into the configured channel.

## Identify

- Record repository path, commit hash, detector rule, timestamp, channel, and app owner.
- Do not paste the webhook URL into tickets or chat.

## Invalidate

- Revoke or regenerate the webhook in the Slack app configuration.
- Confirm the exposed URL was revoked. Creating a new webhook alone does not prove the old
  one stopped working, and automatic leak detection is not a containment receipt.
- Remove the old webhook from CI/CD variables, application configs, and deployment systems.

## Rotate

- Create a replacement webhook only for channels that still need automated posting.
- Store the replacement in the approved secret manager or CI/CD variable store.
- Update each consumer and verify posting through the replacement under the channel owner's
  approved validation plan.

## Audit Usage

- Review channel history and app audit events for unexpected messages during the exposure
  window.
- Audit Logs access depends on the Enterprise plan and does not include message content.
  Record channel-history retention and any unavailable audit coverage. Webhooks cannot
  delete messages they already posted; have the channel owner handle harmful content.

## Communicate

- Notify the app owner and channel owner with redacted evidence and containment status.

## Close

- Remove source references, purge exposed artifacts when possible, and add scanner coverage
  for webhook URL patterns.

## References

- [Incoming webhook secrets and message behavior](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks)
- [Slack Audit Logs coverage](https://docs.slack.dev/admins/audit-logs-api/)
