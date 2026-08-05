# Generic API Key Leak Playbook

Vetted: 2026-05-18

## Scope

Use this playbook when the detector identifies an API key but the provider-specific playbook
does not exist yet.

## Identify

- Record repository path, commit hash, detector rule, timestamp, suspected provider, owner,
  and redacted fingerprint.
- Confirm whether the value is active without copying it into new systems.

## Invalidate

- Revoke, disable, or scope down the exposed key in the authoritative provider.
- If the provider is unknown, search configuration ownership and billing records without
  redistributing the key value.

## Rotate

- Replace the key through the approved secret manager or deployment variable store.
- Reduce permissions, add expiration, and prefer short-lived credentials when supported.

## Audit Usage

- Review provider logs for usage during the exposure window, focusing on unusual source
  networks, high-volume calls, data access, and privilege changes.

## Communicate

- Notify the service owner, security reviewer, and provider owner with redacted evidence.

## Close

- Remove source material, purge artifacts when feasible, add scanner coverage, and create a
  provider-specific playbook if this secret type is expected to recur.

