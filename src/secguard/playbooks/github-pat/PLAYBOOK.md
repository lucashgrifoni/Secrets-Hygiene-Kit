# GitHub Personal Access Token Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when a GitHub personal access token may have been exposed. Do not copy the
token into evidence notes.

## Identify

- Record repository path, commit hash, detector rule, timestamp, and redacted token prefix.
- Identify token owner, scopes, organization access, and whether SSO was enabled.
- Distinguish a classic token from a fine-grained token and record each affected account or
  organization in the restricted incident record.

## Invalidate

- Revoke the exposed token from GitHub before relying on deleting source material.
- If the owner is unavailable, ask an organization owner to contain access to their
  resources. They can revoke a fine-grained token's organization access, but that is not
  global token deletion and does not revoke other access or SSH keys the token created.
  Classic tokens require their own policy or authorization response.
- Confirm deletion or revocation at the issuer and separately review persistence such as
  deploy keys, SSH keys, new tokens, and integrations created during exposure.

## Rotate

- Replace only the required automation path.
- Prefer GitHub Apps, fine-grained tokens, or OIDC where practical.
- Limit scopes and expiration for any replacement credential.
- Deliver it through the approved credential store and verify each affected automation uses
  the replacement successfully.

## Audit Usage

- Review GitHub audit logs for token use, repository access, workflow changes, branch
  protection changes, and package publication events.
- Include the owner's security log where available. Record plan, permissions, retention,
  event coverage, and the reviewed interval; logs may not include every read or request.

## Communicate

- Notify repository owners and organization security contacts with redacted evidence.

## Close

- Remove leaked material from code and artifacts, then add a detector rule or waiver review
  if the match was a controlled fixture.

## References

- [Personal access token management](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [Limits of organization token revocation](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization)
- [GitHub incident investigation coverage](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-areas)
