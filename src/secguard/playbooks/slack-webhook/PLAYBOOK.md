# Slack Webhook Leak Playbook

Vetted: 2026-05-18

## Scope

Use this playbook when an incoming Slack webhook URL is exposed. Treat the full URL as a
secret because it can post into the configured channel.

## Identify

- Record repository path, commit hash, detector rule, timestamp, channel, and app owner.
- Do not paste the webhook URL into tickets or chat.

## Invalidate

- Revoke or regenerate the webhook in the Slack app configuration.
- Remove the old webhook from CI/CD variables, application configs, and deployment systems.

## Rotate

- Create a replacement webhook only for channels that still need automated posting.
- Store the replacement in the approved secret manager or CI/CD variable store.

## Audit Usage

- Review channel history and app audit events for unexpected messages during the exposure
  window.

## Communicate

- Notify the app owner and channel owner with redacted evidence and containment status.

## Close

- Remove source references, purge exposed artifacts when possible, and add scanner coverage
  for webhook URL patterns.

