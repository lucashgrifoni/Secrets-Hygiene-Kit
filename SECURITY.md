# Security policy

## Supported version

Security fixes for the 1.0 release line target the latest 1.0.x release and the
current main development line. Once 1.0.0 is published, earlier beta releases,
including 0.5.0, are superseded and do not receive separate backports.
The supported Python versions are 3.12, 3.13 and 3.14 on Linux, Windows and macOS.
See [compatibility and support](docs/compatibility.md) for the stable 1.x
interfaces, tested integration versions and migration policy. The optional
Remediation Hub Python bridge remains experimental.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/lucashgrifoni/secrets-hygiene-kit/security/advisories/new)
for a suspected vulnerability. If that form is unavailable, open a public issue
asking for a private reporting channel without including exploit details or
credential material.

Include the affected version, command or report format, impact and a minimal
synthetic reproducer. Never submit live credentials, private keys, raw scanner
reports, customer data or sensitive account details.

## Data handling

secguard discards known credential fields in supported detector reports and
retains selected metadata. Do not put secrets in paths, identifiers,
descriptions, waiver reasons or other metadata. Review exported reports before
sharing them.

A waiver records a review decision and expiry. It does not authenticate the
owner or approver. Repository access controls must protect policy changes.

## Response limits

The tool never runs scanners, contacts credential providers or rotates keys.
Use the relevant playbook and your incident process for real exposures.
Report validation is not proof that a detector completed its scan, or that a
credential is currently invalid.

Write guards reject symlinks and Windows junctions in the selected destination.
They do not provide isolation against concurrent filesystem changes.
