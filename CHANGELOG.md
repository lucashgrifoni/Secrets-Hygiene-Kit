# Changelog

## [0.3.0] - 2026-10-05

### Gate and input handling

- Reject malformed detect-secrets documents instead of accepting missing results.
- Distinguish clean empty TruffleHog output from formats requiring JSON.
- Reject unsafe identifiers and prevent validation errors from echoing unknown keys.
- Return processing-error status for unreadable policies, write failures and oversized JSON numbers.
- Limit each report to 64 MiB with a bounded read before parsing.
- Preserve each detector's evidence through repeated finding merges.
- Show severity reductions from explicit catalog overrides, including fallback changes.
- Replace backtracking waiver matching with predictable directory-aware matching.
- Show partial waiver scopes even when they cover a different finding completely.

### Output and response

- Guard output and scaffold destinations against symlinks, Windows junctions,
  parent-component redirects and literal-tilde path confusion.
- Escape waiver IDs and other metadata in Markdown output.
- Ignore structured scanner descriptions and preserve distinct long fingerprints.
- Encode SARIF paths as URIs and export resolved severity.
- Review all 13 playbooks against provider documentation on 2026-10-05.
- Clarify issuer containment, consumer adoption, derived access and audit limits.

### Distribution

- Publish versioned wheel and source assets through GitHub Releases.
- Test Python 3.12, 3.13 and 3.14 on Linux and Windows.
- Exercise the composite Action in GitHub and install both distributions outside
  the checkout.
- Pin workflow dependencies and preserve scanner operational failures in starters.
- Include dependency review, a CycloneDX inventory, checksums and build provenance.
- Restore the canonical Apache-2.0 license and SPDX package metadata.

### Migration notes

SARIF default severities retain the canonical type ID. Overrides now always use
`<type>/<severity>`, such as `aws-access-key/critical`, and security severity
reflects the resolved finding. Existing imported alerts may transition once
when this rule identity changes.

Native Gitleaks fingerprints longer than 160 characters are hashed in full.
Their identity changes from the previously truncated representation; normal
short fingerprints retain their identity.

A catalog override is used only with explicit `--rules`. Empty Gitleaks,
detect-secrets and synthetic files are input errors. Empty TruffleHog reports
remain valid, with a notice; enforce scanner success in the preceding step.

## [0.2.0] - 2026-08-05

Added Gitleaks, TruffleHog and detect-secrets ingestion, a canonical catalog,
combined findings, SARIF and Markdown reports, 13 response playbooks, the
composite Action and CI starters.

## [0.1.0] - 2026-05-18

Initial local CLI, waiver model, scaffold templates and response guidance.
