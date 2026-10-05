# Azure Storage Account Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when an Azure Storage account access key or a connection string containing
one is exposed. Shared Key authorization can grant broad access to storage data without
Microsoft Entra role authorization. Network restrictions and the account's Shared Key
configuration still affect whether an attacker can use it.

Do not paste the key or the full connection string into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the storage account
  name in the restricted incident record; never record the key.
- Identify the subscription, resource group, owner, and what the account stores. Whether it
  holds customer data changes the notification path.
- Check whether the account is reachable from the public internet or restricted to a private
  endpoint or a network rule set.
- Identify which key slot leaked and which slot each consumer uses, including known account
  and service shared access signatures (SAS). Azure does not track generated SAS tokens, so
  a complete provider-side SAS inventory is unavailable.

## Invalidate

- The account owner must choose immediate regeneration or approve a short migration window
  with a deadline and service impact recorded. Do not delay urgent containment for a
  complete consumer or SAS inventory.
- For staged rotation, establish a verified unused alternative slot, regenerate it, and
  securely move consumers to that fresh key. Prove adoption before regenerating the exposed
  slot. If both slots are in use or usage is unknown, coordinate migration or downtime
  before choosing a slot; a second key alone does not guarantee uninterrupted service.
- Regenerating a key revokes account and service SAS signed with that key. User-delegation
  SAS are unaffected and need a separate response if they were exposed.
- Confirm the exposed slot was regenerated; changing a stored connection string alone does
  not invalidate the original key.

## Rotate

- Prefer Microsoft Entra ID authentication with Azure RBAC over account keys. Consider
  disabling shared key authorization on the account once consumers are migrated.
- Where the service supports it, prefer user-delegation SAS with a short expiry over
  account-key SAS.
- Store any remaining key material in Azure Key Vault, referenced by managed identity, not in
  application configuration.
- If both keys need replacement, complete both transitions with consumer adoption verified
  before regenerating a slot that is still in use.

## Audit Usage

- Review storage diagnostic and resource logs for the exposure window.
- Storage logging is not always enabled. If it was off, record that gap explicitly rather than
  concluding the window was clean.
- Look for large or unusual read volume, container listing, deletions, changes to public
  access level, and access from unfamiliar IP ranges.
- Check Azure Activity Log for changes to the account's network rules or access configuration.
- Record service-specific logging coverage, retention, and the reviewed interval. Activity
  Log records control-plane changes; it does not establish data access or attribute every
  request to a particular account key.

## Communicate

- Notify the service owner, AppSec, and the subscription owner with redacted evidence.
- If the account stores personal or customer data and access cannot be ruled out, involve
  privacy or legal for LGPD and GDPR assessment.
- State the exposure window, what the audit covered, and which logs were unavailable.

## Close

- Remove the key and connection string from source, artifacts, images, and CI logs.
- Add detection for storage connection strings in pre-commit and CI.
- Record residual risk with an owner and a review date, including any logging coverage gap.

## References

- [Storage key management and rotation](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)
- [SAS types and inventory limits](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [Azure control-plane Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log)
- [Storage resource logging](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage)
