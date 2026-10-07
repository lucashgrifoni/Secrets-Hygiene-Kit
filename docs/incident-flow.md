# Responding to an exposed credential

Contain exposed access promptly. secguard prints guidance; an authorized
responder performs every provider action.

## Preserve references without spreading the secret

Record the provider, resource or account, rule ID, redacted fingerprint, path,
commit and exposure timestamp. Never copy the credential into an issue, chat,
screenshot, waiver reason or incident checklist.

Capture enough metadata to identify the affected credential and notify its
owner. Continue scoping in parallel with urgent containment; a complete
inventory must not delay an emergency response.

## Get the provider checklist

```console
secguard incident start --secret-type aws-access-key --leaked-via public-github-issue --reference INC-2026-42 --output incident-aws.md
```

Use the canonical type shown by the scan. If the mapping is a fallback,
identify the actual provider before applying provider-specific instructions.

## Scope the exposure

Establish permissions, consumers, exposure window and distribution through
repositories, logs, packages or images. Treat public exposure as requiring
containment even when use cannot yet be confirmed.

Version 0.5.0 labels imported verification as `verified=detector:true`
(0.4.0 used `verified=live`). This is a claim from the detector
report at its scan time. secguard does not test the credential. A false or
missing verification value does not prove that access is invalid.

## Contain and replace at the issuer

Choose the mechanism supported by the affected provider. Deactivate, revoke,
regenerate or remove trust as appropriate. Source deletion and history
rewriting do not invalidate access already copied elsewhere.

If an approved replacement must be adopted before invalidation to preserve a
service, require an authorized owner, a short deadline and evidence that every
consumer adopted it. Record the exposure risk during that interval.

- For AWS IAM user keys, follow the IAM playbook. Root credentials require the
  root-account procedure; do not replace them with another root access key.
- For GitHub App keys, account for the final active key, consumer adoption and
  installation tokens already issued.
- For Azure Storage keys, identify the exposed slot and current use of both
  slots before regenerating one. Review SAS types and their revocation paths.
- For database and signing credentials, replacement may leave existing
  sessions, issued tokens or cached trust valid. Follow the specific playbook.

Escalate immediately when you lack containment authority. Coordinate the
impact with the service owner and verify invalidation at the issuer.

Distribute replacement material through the approved secret manager or CI
variable store. Refresh or reconnect consumers according to their contract,
then prove the required authenticated operation works with the replacement.

## Investigate use and derived access

Review the exposure window using the available provider and service logs.
Check suspicious use, privilege changes, new credentials and derived access
appropriate to the provider.

Record the log sources, categories, retention, pagination, permissions and
coverage gaps. Absence of recorded activity does not establish absence of
misuse when relevant logging or retention is incomplete.

## Communicate and close

Notify the service owner and security team with redacted evidence, containment
status, impact and remaining gaps. Involve privacy or legal when regulated
data may be affected; they determine the applicable obligations and deadlines.

After containment, remove the credential from source and distributed
artifacts. Review cached copies, images and CI logs as needed. Cleanup must not
reactivate old access.

Record consumer adoption, issuer invalidation, derived-access review and
residual risk with an owner and review date. A detected synthetic fixture may
use an expiring waiver after its provenance has been established. A waiver
does not contain a real credential.
