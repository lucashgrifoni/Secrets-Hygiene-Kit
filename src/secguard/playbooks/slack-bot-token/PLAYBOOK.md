# Slack Bot or User Token Leak Playbook

Vetted: 2026-08-04

## Scope

Use this playbook when a Slack bot token (`xoxb-`), user token (`xoxp-`), app-level token
(`xapp-`), or configuration access token is exposed. These tokens read and post as the app or
the user, so the exposure is both a data-access and an impersonation problem.

Do not paste the token into tickets or channels.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and redacted token
  prefix. The prefix tells you the token class and therefore the blast radius.
- Identify the workspace, the app, the app owner, and the granted OAuth scopes.
- A user token inherits that person's access to private channels and DMs; treat it as an
  account compromise, not only an app issue.
- List channels and files the scopes reach.

## Invalidate

- Revoke the token through the Slack app configuration or the token revocation API.
- For a user token, also review the person's active sessions and consider forcing a re-auth.
- If the app has broad scopes and abuse is suspected, uninstall the app from the workspace
  while you investigate. Uninstalling invalidates the tokens issued to that installation.

## Rotate

- Reinstall the app and issue a replacement token only for the integrations that still need
  it.
- Reduce scopes to the minimum the integration uses; most integrations request more than they
  exercise.
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
