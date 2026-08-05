# Private Key Leak Playbook

Vetted: 2026-08-04

## Scope

Use this playbook when private key material is exposed and the provider-specific playbook does
not apply: an RSA or EC key, an OpenSSH key, or a PGP secret key.

The response depends entirely on what the key authenticates. Classify it first, because a TLS
key, an SSH key, and a code-signing key have different containment paths and different blast
radii.

Do not paste key material into tickets, chat, or logs.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the key type and
  size. Derive the public key fingerprint for correlation; it is safe to share.
- Classify the purpose:
  - **TLS** — matched by a certificate; the certificate is public, the key is not.
  - **SSH** — the public half appears in `authorized_keys` or as a deploy key.
  - **Code signing or artifact signing** — the key attests to build provenance.
  - **PGP** — signs commits, releases, or encrypts data at rest.
- Determine whether the key is passphrase-protected. A passphrase buys time; it is not
  containment, because it can be brute forced offline.
- Identify every system that trusts the corresponding public key.

## Invalidate

- **TLS**: revoke the certificate through the issuing CA and reissue with a fresh key pair.
  Revocation checking is unreliable in practice, so treat reissue and deployment as the real
  containment step.
- **SSH**: remove the public key from every `authorized_keys` file, deploy key list, and
  configuration management source. Removing it from one host is not enough.
- **Code signing**: revoke the key with the trust authority and identify every artifact signed
  during the exposure window.
- **PGP**: publish a revocation certificate to the keyservers where the key was distributed.

## Rotate

- Generate the replacement on the system that will use it, or in a KMS or HSM, so the private
  half never exists as a file a human can copy.
- Distribute only the public half. If the private key must be stored, store it in the approved
  secret manager.
- Reduce trust scope: one key per host or per service instead of one shared key.
- Update configuration management, deployment automation, and documentation so the old key is
  not restored by a later run.

## Audit Usage

- **SSH**: review authentication logs for the key fingerprint across the exposure window, and
  look for `authorized_keys` modifications, new sudo grants, and cron or systemd persistence.
- **TLS**: check for certificate issuance you did not request and for unexpected hosts
  presenting the certificate.
- **Code signing**: inventory every artifact signed during the window and verify each against
  an independent build record. Anything you cannot account for should be treated as suspect.
- **PGP**: check for signatures created during the window on commits, releases, or messages.

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
