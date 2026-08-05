# Azure Storage Account Key Leak Playbook

Vetted: 2026-08-04

## Scope

Use this playbook when an Azure Storage account access key or a connection string containing
one is exposed. An account key grants full control of every blob, file, queue, and table in
the storage account, and it bypasses Azure RBAC entirely.

Do not paste the key or the full connection string into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the storage account
  name. The account name is safe to record; the key is not.
- Identify the subscription, resource group, owner, and what the account stores. Whether it
  holds customer data changes the notification path.
- Check whether the account is reachable from the public internet or restricted to a private
  endpoint or a network rule set.
- List shared access signatures issued from this account key, because they will be
  invalidated when it rotates.

## Invalidate

- Storage accounts have two keys so you can rotate without downtime. Move consumers to the
  key that did not leak, then regenerate the exposed one.
- Regenerating the exposed key invalidates every SAS token signed with it. Inventory those
  first, then regenerate; that ordering avoids a surprise outage during an incident.
- If abuse is suspected, regenerate immediately and accept the outage. Containment outranks
  availability when the key grants full data-plane access.

## Rotate

- Prefer Microsoft Entra ID authentication with Azure RBAC over account keys. Consider
  disabling shared key authorization on the account once consumers are migrated.
- If SAS is required, issue user-delegation SAS with a short expiry rather than account-key
  SAS.
- Store any remaining key material in Azure Key Vault, referenced by managed identity, not in
  application configuration.
- Regenerate the second key as well once migration is complete, so no key predates the
  incident.

## Audit Usage

- Review storage diagnostic and resource logs for the exposure window.
- Storage logging is not always enabled. If it was off, record that gap explicitly rather than
  concluding the window was clean.
- Look for large or unusual read volume, container listing, deletions, changes to public
  access level, and access from unfamiliar IP ranges.
- Check Azure Activity Log for changes to the account's network rules or access configuration.

## Communicate

- Notify the service owner, AppSec, and the subscription owner with redacted evidence.
- If the account stores personal or customer data and access cannot be ruled out, involve
  privacy or legal for LGPD and GDPR assessment.
- State the exposure window, what the audit covered, and which logs were unavailable.

## Close

- Remove the key and connection string from source, artifacts, images, and CI logs.
- Add detection for storage connection strings in pre-commit and CI.
- Record residual risk with an owner and a review date, including any logging coverage gap.
