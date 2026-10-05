# Generic API Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when the detector identifies an API key but the provider-specific playbook
does not exist yet.

## Identify

- Record repository path, commit hash, detector rule, timestamp, suspected provider, owner,
  and redacted fingerprint.
- Confirm whether the value is active without copying it into new systems.
- Identify the exact issuer, credential class, permissions, and consumers. Use approved
  provider metadata or an explicitly authorized validity check; avoid sending the value to
  third-party checking services.

## Invalidate

- Revoke or disable the exposed key in the authoritative provider and record issuer
  confirmation. Reducing permissions can limit impact but does not invalidate a credential.
- If the provider is unknown, search configuration ownership and billing records without
  redistributing the key value.
- Follow the issuer's compromise procedure. Any staged replacement must have an authorized
  owner, a short exposure deadline, and verified consumer adoption before retiring the old
  key. Account for derived sessions or refresh credentials separately.

## Rotate

- Replace the key through the approved secret manager or deployment variable store.
- Reduce permissions, add expiration, and prefer short-lived credentials when supported.
- Verify each consumer adopted the replacement and can authenticate its required operation.

## Audit Usage

- Review provider logs for usage during the exposure window, focusing on unusual source
  networks, high-volume calls, data access, and privilege changes.
- Record log availability, permissions, retention, reviewed interval, and attribution limits.
  An empty or unavailable log source does not establish absence of abuse.

## Communicate

- Notify the service owner, security reviewer, and provider owner with redacted evidence.

## Close

- Remove source material, purge artifacts when feasible, add scanner coverage, and create a
  provider-specific playbook if this secret type is expected to recur.

## References

- [OWASP secret lifecycle, revocation, and incident response](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

This is a fallback procedure. The identified provider's current compromise instructions
must determine its revocation mechanism and session behavior.
