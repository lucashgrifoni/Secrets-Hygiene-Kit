# Slack Bot or User Token Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when a Slack bot token (`xoxb-`), user token (`xoxp-`), app-level token
(`xapp-`), or configuration access token is exposed. Bot and user tokens act within their
granted scopes; app-level and configuration tokens serve different app or management
functions. Classify the token before choosing containment.

Do not paste the token into tickets or channels.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and redacted token
  prefix. Confirm its class, scopes, installation, and any associated refresh credentials;
  the prefix alone does not establish permissions.
- Identify the workspace, the app, the app owner, and the granted OAuth scopes.
- A user token's granted scopes and the user's access can include private channels and DMs.
  Scope the exposure from the actual permissions; token exposure alone does not prove the
  person's interactive account was compromised.
- List channels and files the scopes reach.

## Invalidate

- Use Slack's revocation mechanism for the exact token class. OAuth access and refresh
  tokens have a single-token revocation path; app-level and configuration tokens require
  their own management controls. Have the app owner confirm the result and escalate if the
  class-specific revocation path is unclear.
- For a user token, also review the person's active sessions and consider forcing a re-auth.
- If the app has broad scopes and abuse is suspected, uninstall the app from the workspace
  while you investigate. Uninstalling invalidates the tokens issued to that installation.
- With token rotation, revoking one token does not necessarily remove the underlying
  installation or its other credentials. Revoke exposed refresh credentials and any related
  active tokens as required by the incident scope.

## Rotate

- Reauthorize or reinstall only when the token class and revocation path require it. Issue a
  replacement only for integrations that still need it and verify consumer adoption.
- Reduce scopes to the minimum the integration uses.
- Enable token rotation for the app if the integration supports refresh tokens.
- Store the replacement in the approved secret manager or CI/CD variable store.

## Audit Usage

- Review the workspace audit logs for the app and the token across the exposure window. Audit
  log access depends on the Slack plan; if it is unavailable, say so in the record rather than
  assuming the activity was clean.
- Look for messages posted, files downloaded, channels joined, users invited, and app
  configuration changes.
- Check whether the token could read private channels or DMs, and scope the notification
  accordingly.
- Slack's Audit Logs API is an Enterprise feature and does not provide message content or
  every token operation. Review available channel history or approved content evidence
  separately; record retention, permissions, pagination, and attribution gaps.

## Communicate

- Notify the app owner, workspace admins, and the owners of any channel whose content was
  reachable.
- If private conversations were in scope, treat the notification as a data-exposure
  notification, not just a credential rotation notice.
- State the exposure window, the audit coverage, and the residual risk.

## Close

- Remove the token from source, artifacts, and CI logs.
- Add detection for Slack token prefixes in pre-commit and CI.
- Record residual risk with an owner and a review date, especially when audit logs were not
  available for the full window.

## References

- [Slack token classes](https://docs.slack.dev/authentication/tokens/)
- [OAuth token revocation](https://docs.slack.dev/reference/methods/auth.revoke/)
- [Token rotation and uninstall behavior](https://docs.slack.dev/authentication/using-token-rotation/)
- [Audit Logs availability and coverage](https://docs.slack.dev/admins/audit-logs-api/)
