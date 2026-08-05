# GitHub App Private Key Leak Playbook

Vetted: 2026-08-04

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

- Generate a new private key for the App first, then delete the exposed key. Apps support
  multiple active keys, so this order avoids an outage while still containing the leak.
- Delete the exposed key even if no abuse is visible. Key material does not expire on its own.
- If the App holds write or admin permissions and abuse is suspected, suspend the installation
  while you investigate.

## Rotate

- Distribute the new key through the approved secret manager or CI/CD variable store.
- Restart or redeploy every consumer so no process keeps the old key in memory.
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
