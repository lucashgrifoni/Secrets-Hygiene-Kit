# Repository CI and required checks

The repository uses five supplied workflow templates as its baseline. Their
jobs are adapted to this Python CLI; the CLI does not run scanners for its users.
Every pull request runs quality, security, documentation and repository posture
checks without path filters.

## Template mapping

| Supplied template | Repository configuration | Adaptation |
| --- | --- | --- |
| `github-ci-cd.yml` | `.github/workflows/ci.yml` | Explicit Ruff, pytest, distribution, Action and installation checks replace npm commands. Linux/Windows and Python 3.12/3.13/3.14 remain covered. |
| `security-ci-cd.yml` | `.github/workflows/security-ci-cd.yml` | Semgrep and Python CodeQL cover SAST; pip-audit and Trivy cover resolved dependencies; Gitleaks and Trivy cover secrets; zizmor and actionlint cover Actions. |
| `scorecard.yml` | `.github/workflows/scorecard.yml` | Posture analysis and policy checks run on PRs with repository contents access. Authenticated publication runs only from the default branch or repository events. |
| `deploy-github-pages.yml` | `.github/workflows/deploy-github-pages.yml` | MkDocs builds the existing CLI documentation. Deployment uses the protected `github-pages` environment on main. |
| `dependabot.yml` | `.github/dependabot.yml` | Weekly updates cover Actions, Python project dependencies and documentation requirements. No automatic merge. |

Snyk Code and Open Source jobs require a Snyk account and token. This repository
does not have that credential, so the adapted pipeline uses Semgrep/CodeQL and
pip-audit/Trivy for those categories. It does not claim that Snyk ran.

There are no Terraform, Kubernetes, Docker or other infrastructure manifests in
the project. KICS and Trivy IaC jobs would therefore provide no applicable
infrastructure coverage. The adapted pipeline audits the actual GitHub Actions
configuration with zizmor. Adding infrastructure requires adding its scanner
targets and required gates in the same PR.

## Blocking policy

- Semgrep blocks WARNING and ERROR findings and scan/configuration errors.
- CodeQL uses Python's security-extended suite. A separate SARIF gate blocks
  security scores of 4.0 or higher, and warnings/errors without a security score.
  Uploading SARIF alone does not satisfy this gate.
- pip-audit blocks reported advisories and collection failures. Trivy blocks
  MEDIUM, HIGH, CRITICAL and UNKNOWN severities, including advisories with no
  available fix. Its inventory must contain resolved packages.
- Gitleaks examines all branches and tags with complete Git history. Trivy examines the source tree.
  Reports with actual secret matches stay out of uploaded artifacts; Gitleaks
  redacts values and Trivy publishes only counts and rule identifiers.
- zizmor blocks medium and higher findings; actionlint blocks invalid workflows.
- Scorecard requires 10/10 for Dangerous-Workflow, Token-Permissions,
  Binary-Artifacts, Security-Policy and License. The full report also records
  other checks; passing this policy does not mean every Scorecard check is 10/10.
  Classic branch protection is verified through the repository API because
  Scorecard's limited token may not observe that configuration.
- Documentation builds fail on warnings.

`Security checks`, `Scorecard checks` and the existing `Release checks` reject
failed, cancelled and unexpectedly skipped dependencies. Expected skips are
limited to operations that do not apply to an event: PR dependency review on
push, trusted publication on fork/contributor PRs, and main-only provenance or
deployment on PRs. Scanners and documentation builds run on every PR.

Required check names are bound to the GitHub Actions app. Main requires an
up-to-date branch and passing checks; administrators are subject to protection.
Individual security gates, the aggregate gates and `Documentation build` are
required. Publishing artifacts, an absent job or a green workflow with skipped
scanning is insufficient.

## Reproducibility and credentials

Actions are pinned to full commit SHAs. Gitleaks 8.30.1, Trivy 0.75.0 and
actionlint 1.7.12 archives are checked against their recorded SHA-256 before
execution. Semgrep 1.179.0, zizmor 1.30.1, pip-audit 2.10.1 and MkDocs 1.6.1 are
pinned Python tools. Semgrep's registry rules and vulnerability databases are
fetched at run time and can change; each run preserves its reports.

Scan jobs receive permission to read repository contents. SARIF publication has a separate write
permission and consumes artifacts from the same run. PR publication is restricted
to the repository owner's same-repository PRs. Scorecard publication uses OIDC;
Pages deployment receives Pages/OIDC permissions only on main. No
`pull_request_target` workflow executes contributor code.

Runner hardening currently audits egress. This setting records connections; it
does not enforce a network allowlist. Findings and scanner failures still block
the required security gates.

## Two historical false positives

`.gitleaksignore` contains two exact fingerprints from commit
`9a9e368d967cb1a8fdce55045b22dc736600bdf7`, file
`tests/fixtures/detect-secrets-baseline.json`, lines 16 and 26. Both are 40-character
SHA-1 `hashed_secret` fields from a constructed detect-secrets baseline, not
provider credentials. The exception binds the original commit, path, rule and
line; it does not ignore the fixture directory or new secrets in that file.

No vulnerability baseline, unfixed-CVE exclusion or broad secrets-directory
exclusion is used. A scanner failure is a failed check.

## Contributor validation and maintenance

See the [contributor guide](https://github.com/lucashgrifoni/secrets-hygiene-kit/blob/main/CONTRIBUTING.md) for the environment setup and validation procedure.

The CI uploads security JSON/SARIF, CycloneDX inventory and complete Scorecard
reports. Artifact retention is 14 days for these runs. The distribution workflow
keeps its existing clean-installation checks and trusted-main provenance.

Changes to scanners, exceptions, thresholds or required-check names need
verification in a protected PR. Reverts also use a protected PR. Update branch
protection when a required job is deliberately renamed so that a missing check
cannot be mistaken for a successful check.

References:
[GitHub required checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
[Scorecard action](https://github.com/ossf/scorecard-action),
[Semgrep CLI](https://docs.semgrep.dev/cli-reference),
[Trivy](https://trivy.dev/docs/latest/),
[zizmor](https://docs.zizmor.sh/),
[Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
