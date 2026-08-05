# I leaked a secret. What now?

The first thirty minutes decide how bad this gets. Work in this order.

## The one rule

**Do not copy the credential anywhere new.** Not into a ticket, a chat message,
a screenshot, a waiver reason, or a log line. Reference it by provider, rule id,
redacted fingerprint, file path, commit hash, and timestamp.

Every step below is executed by a human with the authority to do it. secguard
prints instructions; it never contacts a provider.

## Order of operations

**Invalidate first. Rotate second. Audit third. Clean up last.**

The most common mistake is starting with `git filter-repo`. Rewriting history is
not containment: the credential was already cloned, cached, mirrored, and
possibly indexed. Deleting it from source while it still works changes nothing
for the attacker and costs you the minutes that mattered.

## 1. Get the checklist

```bash
secguard incident start \
  --secret-type aws-access-key \
  --leaked-via public-github-issue \
  --reference INC-2026-42 \
  --output incident-aws.md
```

Find the secret type from a scan:

```bash
secguard scan check --input gitleaks.json --fail-on none
# - critical  aws-access-key  src/example_config.py:12  ... playbook=aws-access-key
```

If the finding shows `mapping: fallback`, secguard could not classify the rule
and gave you the generic playbook. Identify the provider yourself before acting,
then add a catalog mapping so the next occurrence routes correctly.

## 2. Scope the exposure

Answer these before touching the provider, because they set the response:

- **What can the credential do?** Permissions, not credential type, set the
  blast radius. A read-only key and an admin key are different incidents.
- **How long was it exposed?** From the commit that introduced it to now.
- **Who could see it?** A public repository, a public issue, a published package
  or container image, and a CI log all mean "assume harvested". Bots scrape
  public git in minutes.
- **Is it live?** `verified=live` in a secguard scan means trufflehog
  authenticated it successfully. Absence of that flag is not evidence it is
  dead.

## 3. Invalidate

Prefer the reversible step where the provider has one: deactivate an AWS key
before deleting it, publish a new GitHub App key before removing the old, move
Azure Storage consumers to the second key before regenerating the first.

If you lack the permission, escalate immediately. Containment authority belongs
to the account owner, not to whoever found the leak. Do not wait for the
original developer to come online.

## 4. Rotate

Distribute the replacement through the approved secret manager or CI/CD variable
store, never by editing a file in the repository. Take the opportunity to reduce
scope: most leaked credentials had more permissions than the workload used, and
many did not need a long-lived credential at all.

Restart or redeploy every consumer, including cron jobs, migrations, and
webhooks, which are where an old credential usually survives a rotation.

## 5. Audit usage

Review provider logs across the **entire** exposure window, not just recent
activity. Look for persistence before you look for data theft: new credentials,
new users or roles, changed permissions, and new integrations.

When a log source was disabled, say so in the record. "We could not tell" is a
finding. "It looked clean" when the logs were off is a false assurance that will
be quoted back at you later.

## 6. Communicate

Notify the service owner, AppSec, and the provider or account owner with
redacted evidence: actions taken, exposure window, audit coverage, and residual
risk. If personal or customer data was reachable and access cannot be ruled out,
involve privacy or legal early. LGPD and GDPR notification clocks do not wait
for the technical investigation to finish.

## 7. Close out

- Remove the credential from source, artifacts, container images, and CI logs.
  Now that it is invalid, history rewriting is cleanup rather than containment.
- Add detection so the same pattern is caught next time.
- If the match was an intentional fixture, replace the realistic value with an
  obviously fake one, then open a waiver with an owner and an expiry.
- Write down residual risk with an owner and a review date, especially when
  audit coverage was incomplete.

## When it was only a fixture

Not every detector hit is an incident. If the value is genuinely synthetic:

```bash
secguard waivers add \
  --rule "secret-type:aws-access-key" \
  --path "tests/fixtures/**" \
  --reason "Synthetic value in a detector fixture, not a credential." \
  --owner appsec@example.com \
  --approver security-lead \
  --expires 2026-11-01
```

Confirm it is synthetic before waiving. A waiver on a real credential is worse
than no scanning at all, because it converts a visible finding into a documented
decision not to look.
