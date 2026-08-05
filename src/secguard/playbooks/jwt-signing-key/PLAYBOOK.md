# JWT Signing Key Leak Playbook

Vetted: 2026-08-04

## Scope

Use this playbook when a JWT signing key is exposed: an HMAC secret for `HS256`, or a private
key for `RS256` and `ES256`. Anyone holding it can mint valid tokens for any user, any role,
and any expiry. Revoking sessions does not help until the key is replaced.

A leaked signed token is a narrower problem: revoke the session and check its claims. A leaked
signing key is an authentication bypass.

Do not paste the key or a full token into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the algorithm.
- Distinguish a signing key from a signed token. If the detector matched a token, extract only
  the `kid`, `iss`, `aud`, and `exp` claims for the record.
- Identify every service that validates tokens signed with this key, including internal
  services that trust the issuer transitively.
- Determine the maximum token lifetime, because that sets how long a forged token stays valid
  after rotation.

## Invalidate

- Rotate the signing key. Until it is replaced, every access control that depends on token
  validation is bypassable.
- If the issuer supports key ids, publish the new key alongside the old one, move signing to
  the new key, then stop accepting the old `kid`. That contains the leak without a hard
  outage.
- If the issuer has no `kid` support, accept the session invalidation and rotate directly.
  Availability is the cheaper loss here.
- Invalidate refresh tokens and active sessions issued during the exposure window.

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
