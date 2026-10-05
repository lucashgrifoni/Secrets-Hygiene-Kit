# Private Key Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when private key material is exposed and the provider-specific playbook does
not apply: an RSA or EC key, an OpenSSH key, or a PGP secret key.

The response depends entirely on what the key authenticates. Classify it first, because a TLS
key, an SSH key, and a code-signing key have different containment paths and different blast
radii.

Do not paste key material into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the key type and
  size. Derive the public key fingerprint for correlation in the restricted incident record.
- Classify the purpose:
  - **TLS**: matched by a certificate; the certificate is public, the key is not.
  - **SSH**: identify a client, host, or CA key and the corresponding trust stores, including
    `authorized_keys` or a deploy key list for client authentication.
  - **Code signing or artifact signing**: the key attests to build provenance.
  - **PGP**: signs commits, releases, or encrypts data at rest.
- Determine whether the key is passphrase-protected. A passphrase buys time; it is not
  containment, because it can be brute forced offline.
- Identify every system that trusts the corresponding public key.

## Invalidate

- **TLS**: request revocation for key compromise from the issuing CA, reissue with a fresh
  key pair, and deploy the replacement. Confirm the CA's revocation status and the affected
  clients' trust behavior; replacement alone does not make the stolen key unusable elsewhere.
- **SSH**: remove the public key from every `authorized_keys` file, deploy key list, and
  configuration management source. For host or CA keys, update the relevant client or
  certificate trust stores as well. Removing trust does not terminate already established
  sessions; the incident owner must handle those separately.
- **Code signing**: revoke the affected certificate or remove trust according to the signing
  authority's procedure and identify every artifact signed during the exposure window.
  Record approval and timestamp rules; a submitted revocation request is not completed
  revocation, and historical signature trust depends on the verifier.
- **PGP**: publish the key or subkey revocation through the channels where it was distributed
  and notify recipients. Revocation does not prevent decryption of previously captured data
  with the stolen private key.

## Rotate

- Generate the replacement on an approved system, or in a KMS or HSM with non-exportable
  keys where supported. Generating a key locally does not by itself prevent copies.
- Distribute only the public half. If the private key must be stored, store it in the approved
  secret manager.
- Reduce trust scope: one key per host or per service instead of one shared key.
- Update configuration management, deployment automation, and documentation so the old key is
  not restored by a later run.
- Verify the replacement works at each consumer and the exposed key is no longer trusted.

## Audit Usage

- **SSH**: review authentication logs for the key fingerprint across the exposure window, and
  look for `authorized_keys` modifications, new sudo grants, and cron or systemd persistence.
- **TLS**: check for certificate issuance you did not request and for unexpected hosts
  presenting the certificate.
- **Code signing**: inventory every artifact signed during the window and verify each against
  an independent build record. Anything you cannot account for should be treated as suspect.
- **PGP**: check for signatures created during the window on commits, releases, or messages.
- Record log availability, retention, fingerprint attribution, and the reviewed interval.
  Missing authentication or signing telemetry does not establish absence of misuse.

## Communicate

- Notify the service owner, AppSec, and the owner of every system that trusted the key.
- For code signing, notify downstream consumers: they need to know which artifacts to
  distrust, and only you can tell them.
- State the key purpose, exposure window, audit coverage, and residual risk.

## Close

- Remove the key material from source, artifacts, images, and CI logs.
- Add detection for private key blocks in pre-commit and CI.
- Move key generation and storage into a KMS or HSM where the workflow supports it.
- Record residual risk with an owner and a review date, especially for signing keys where
  artifact provenance could not be fully reconstructed.

## References

- [TLS certificate revocation](https://letsencrypt.org/docs/revoking/)
- [OpenSSH key trust and revoked host keys](https://man.openbsd.org/sshd.8)
- [OpenPGP revocation and historical decryption](https://gnupg.org/gph/en/manual.html)
- [Code signing revocation and timestamp handling](https://docs.digicert.com/en/certcentral/order-and-manage-certificates/manage-certificate-orders/revoke-a-code-signing-certificate/submit-a-request-to-revoke-a-code-signing-or-ev-code-signing-certificate.html)

These sources illustrate distinct trust systems. Confirm the actual issuer's procedure and
each verifier's behavior before closing an incident.
