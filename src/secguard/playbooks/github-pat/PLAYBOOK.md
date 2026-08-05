# GitHub Personal Access Token Leak Playbook

Vetted: 2026-05-18

## Scope

Use this playbook when a GitHub personal access token may have been exposed. Do not copy the
token into evidence notes.

## Identify

- Record repository path, commit hash, detector rule, timestamp, and redacted token prefix.
- Identify token owner, scopes, organization access, and whether SSO was enabled.

## Invalidate

- Revoke the exposed token from GitHub before relying on deleting source material.
- If the owner is unavailable, ask an organization admin to revoke or suspend access.

## Rotate

- Replace only the required automation path.
- Prefer GitHub Apps, fine-grained tokens, or OIDC where practical.
- Limit scopes and expiration for any replacement credential.

## Audit Usage

- Review GitHub audit logs for token use, repository access, workflow changes, branch
  protection changes, and package publication events.

## Communicate

- Notify repository owners and organization security contacts with redacted evidence.

## Close

- Remove leaked material from code and artifacts, then add a detector rule or waiver review
  if the match was a controlled fixture.

