# JWT Signing Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when a JWT signing key is exposed: an HMAC secret for `HS256`, or a private
key for `RS256` and `ES256`. Anyone holding it can forge signed claims; the impact depends on
which claims and issuers each verifier trusts. Session revocation alone does not remove
that signing capability.

A leaked signed token is a narrower problem: use the issuer's session or token revocation
mechanism where available and check its claims. A leaked signing key can bypass authentication
where its signed claims are trusted.

Do not paste the key or a full token into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the algorithm.
- Distinguish a signing key from a signed token. If the detector matched a token, extract only
  the `kid`, `iss`, `aud`, and `exp` claims for the record.
- Identify every service that validates tokens signed with this key, including internal
  services that trust the issuer transitively.
- Determine token lifetime limits, verifier key caches, and session behavior. An attacker can
  choose a forged token's expiry; the issuer's normal lifetime does not bound that token
  unless each verifier enforces the limit independently.

## Invalidate

- Replace the signing key and remove the exposed key from every verifier's accepted trust
  set. Confirm issuer revocation and verifier adoption separately, including cached keys.
- If the issuer supports key ids, publish the new key alongside the old one, move signing to
  the new key, then stop accepting the old `kid` at every verifier. While the exposed key
  remains accepted, forged tokens can still pass. Any overlap needs an authorized owner,
  a short deadline, and explicit residual risk; it cannot guarantee an uninterrupted service.
- If abuse requires urgent containment, use the issuer's emergency rotation and revocation
  path with the identity owner. Without `kid` support, coordinate direct replacement and
  the expected session invalidation.
- Invalidate refresh tokens and active sessions issued during the exposure window.
- Under the authorized validation plan, prove old-key tokens are rejected and legitimate
  replacement tokens still work at each verifier. Rejecting one old `kid` is insufficient
  if the same exposed key remains trusted through another lookup path.

## Rotate

- Generate the replacement with the same or stronger algorithm; prefer asymmetric signing so
  verifiers never hold signing material.
- Store the key in the approved secret manager or a KMS or HSM that signs without exporting
  the key.
- Shorten access token lifetime so a future leak has a smaller window.
- Confirm every verifier rejects `alg: none` and does not accept algorithm substitution.

## Audit Usage

- Review authentication and authorization logs for the exposure window.
- Look for tokens with unexpected subjects, roles, scopes, or unusually long expiry, and for
  privileged actions without a matching login event.
- Check for successful requests that have no corresponding session creation: a forged token
  produces authorized activity with no login.
- If logs do not record token claims, record that gap rather than reporting a clean window.
- Record the inspected services, retention, and interval without copying full tokens. Claims
  from an unverified token are investigative leads, not proof of identity or issuer.

## Communicate

- Notify the service owner, AppSec, and the identity or platform owner.
- State that the exposure allowed token forgery, not only session theft. That distinction
  drives the response from everyone downstream.
- If privileged actions cannot be ruled out, escalate to an incident.

## Close

- Remove the key from source, artifacts, images, and CI logs.
- Add detection for signing keys and private key blocks in pre-commit and CI.
- Move signing into a KMS or HSM if the key was stored in application configuration.
- Record residual risk with an owner and a review date.

## References

- [JWT validation best practices, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html)
- [Signing key rotation and verifier impact](https://auth0.com/docs/get-started/tenant-settings/signing-keys/rotate-signing-keys)
- [Signing key revocation](https://auth0.com/docs/get-started/tenant-settings/signing-keys/revoke-signing-keys)

Auth0 is an issuer-specific example. Other issuers and verifier libraries need their own
revocation and cache-refresh procedure.
