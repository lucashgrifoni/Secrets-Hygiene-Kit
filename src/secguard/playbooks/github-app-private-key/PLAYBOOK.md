# GitHub App Private Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when a GitHub App private key (a PEM file) is exposed. The key is not a
token: it mints installation tokens on demand for every organization and repository where the
App is installed. Revoking a single token does not contain this.

Do not paste key material into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, and timestamp.
- Identify the App, its owner, and every installation: organizations, repositories, and the
  permissions granted at each.
- Treat the blast radius as the union of all installation permissions, not the permissions of
  the workload that leaked the key.
- Determine whether the App can write code, change workflows, publish packages, or alter
  branch protection.

## Invalidate

- For an owner-approved staged replacement, generate a new private key, securely update all
  consumers, and prove they can obtain tokens with the replacement before deleting the
  exposed key. Multiple active keys permit migration; the exposed key remains a risk until
  deletion. Record a short deadline and the expected service impact.
- Delete the exposed key even if no abuse is visible. Key material does not expire on its own.
- If abuse is suspected, have the authorized owner contain affected installations promptly,
  including suspension where appropriate. If the exposed key is the App's only key, GitHub
  requires another key to exist before it can be deleted; do not wait for normal migration
  to finish before selecting an incident containment path.
- Account for installation tokens already issued during exposure. They expire after one
  hour, and known compromised tokens need separate revocation. Key deletion alone is not
  evidence that every previously issued token was invalidated.

## Rotate

- Distribute the new key through the approved secret manager or CI/CD variable store.
- Apply each consumer's credential reload contract, restarting or redeploying when needed,
  and verify authenticated operations with the replacement.
- Reduce App permissions to what the workload actually uses, and remove installations that
  are no longer needed.
- Prefer fine-grained permissions and repository-scoped installations over organization-wide
  access.

## Audit Usage

- Review the organization audit log for the App across the exposure window.
- Look for installation changes, permission grants, new repositories added to the
  installation, workflow file changes, branch protection changes, and package publication.
- Check for commits, releases, or deploy keys attributed to the App that no owner recognizes.
- Installation tokens are short-lived, so focus on what was done with them rather than on
  which tokens existed.
- Record audit permissions, plan availability, installations, event categories, retention,
  and interval coverage. Organization audit logs do not capture every repository view or
  request; unavailable telemetry remains an evidence gap.

## Communicate

- Notify the App owner, organization security contacts, and the owners of every installed
  repository.
- State which installations were in scope, the exposure window, and what the audit covered.
- If the App could publish artifacts, notify downstream consumers so they can check
  provenance.

## Close

- Remove the key material from source and from any artifact, image, or CI log that captured
  it.
- Add detection for PEM material in pre-commit and CI.
- Store the replacement key so no human copy exists outside the secret manager.
- Record residual risk with an owner and a review date if audit coverage was incomplete.

## References

- [GitHub App key generation and deletion](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)
- [GitHub App compromise response](https://docs.github.com/en/enterprise-cloud%40latest/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app)
- [Installation token lifetime](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [GitHub incident investigation coverage](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-areas)
