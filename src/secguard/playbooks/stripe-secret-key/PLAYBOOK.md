# Stripe Secret Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when a Stripe secret key (`sk_live_`, `sk_test_`) or restricted key
(`rk_live_`, `rk_test_`) is exposed. A live secret key can enable financial operations and
customer-data access; restricted keys depend on their permissions and access policies.
Treat exposure as a potential compromise and assess the financial and privacy impact.

Check the prefix before escalating: a `_test_` key touches test-mode data only, which changes
the severity but not the need to rotate.

Do not paste the key into tickets or chat.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the redacted key
  prefix.
- Confirm live versus test mode, and confirm whether the key is a full secret key or a
  restricted key with a narrower permission set.
- Identify the Stripe account, the integration that uses the key, and the account owner.
- Establish the exposure window and whether the repository or artifact was ever public.

## Invalidate

- Rotate the exposed key promptly in the Stripe dashboard. Select immediate expiry for
  urgent containment; a grace period leaves the old key usable until expiry.
- Any staged migration needs account-owner approval, a short deadline, and consumer
  adoption evidence before the exposed key expires. Internal exposure also warrants
  immediate response; do not treat repository visibility as proof that no one obtained it.
- Confirm the old key is expired or revoked in Stripe. A replacement in the credential
  store alone does not establish containment.
- Escalate to the account owner if you lack permission to roll keys. Do not delay containment
  waiting for the original developer.

## Rotate

- Store the replacement in the approved secret manager or CI/CD variable store.
- Prefer restricted keys scoped to the specific resources the integration uses instead of a
  full secret key.
- Apply each consumer's reload contract, restarting or redeploying when needed, and verify
  authenticated operations with the replacement.
- Verify webhooks and background jobs, which are the usual places an old key survives a
  rotation.

## Audit Usage

- Review the Stripe events and logs for the exposure window, filtered to requests made with
  the exposed key.
- Look for refunds, payouts, transfers, new API keys, webhook endpoint changes, team member
  invitations, and bank account changes.
- Check for customer or payment-method reads that suggest data harvesting rather than fraud.
- Reconcile balance and payout activity with finance for the full window.
- Use the key's request-log view for attribution and review account changes separately where
  evidence is available. Record mode, account, permissions, retention, and interval gaps;
  events and request logs do not prove every administrative action was captured.

## Communicate

- Notify the service owner, AppSec, the Stripe account owner, and finance.
- If customer data was reachable, involve privacy or legal early: payment and customer records
  carry notification obligations under LGPD and GDPR.
- Contact Stripe support if fraudulent activity is confirmed.

## Close

- Remove the key from source, artifacts, and CI logs.
- Add detection for Stripe key prefixes in pre-commit and CI.
- Move the integration to restricted keys if it was using a full secret key.
- Record residual risk with an owner and a review date, including the outcome of the financial
  reconciliation.

## References

- [Stripe key types, rotation, expiry, and key request logs](https://docs.stripe.com/keys)
- [Response to exposed Stripe keys](https://docs.stripe.com/keys-best-practices)
- [Workbench request and event coverage](https://docs.stripe.com/workbench/overview)
