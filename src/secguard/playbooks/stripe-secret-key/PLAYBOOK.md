# Stripe Secret Key Leak Playbook

Vetted: 2026-08-04

## Scope

Use this playbook when a Stripe secret key (`sk_live_`, `sk_test_`) or restricted key
(`rk_live_`, `rk_test_`) is exposed. A live secret key can move money, read customer data,
and change account configuration, so this is a financial and a privacy incident at once.

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

- Roll the key in the Stripe dashboard. Rolling issues a replacement and lets you set an
  expiry for the old key, so you can contain without an immediate outage.
- Choose an immediate expiry when the repository was public or abuse is suspected; accept a
  short grace window only when exposure was clearly internal.
- Escalate to the account owner if you lack permission to roll keys. Do not delay containment
  waiting for the original developer.

## Rotate

- Store the replacement in the approved secret manager or CI/CD variable store.
- Prefer restricted keys scoped to the specific resources the integration uses instead of a
  full secret key.
- Redeploy or restart every consumer so no process keeps the old key.
- Verify webhooks and background jobs, which are the usual places an old key survives a
  rotation.

## Audit Usage

- Review the Stripe events and logs for the exposure window, filtered to requests made with
  the exposed key.
- Look for refunds, payouts, transfers, new API keys, webhook endpoint changes, team member
  invitations, and bank account changes.
- Check for customer or payment-method reads that suggest data harvesting rather than fraud.
- Reconcile balance and payout activity with finance for the full window.

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
