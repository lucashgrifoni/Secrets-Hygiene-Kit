# Secrets Hygiene Kit

Secrets Hygiene Kit is a Python CLI, `secguard`, for teams that already run
Gitleaks, Betterleaks, TruffleHog or detect-secrets. It combines their reports, enforces expiring
waivers and produces JSON, SARIF and Markdown reports with response guidance.

The release is **0.5.0 beta**, tested on Linux, Windows and macOS with Python
3.12, 3.13 and 3.14.

[Install the versioned release](https://github.com/lucashgrifoni/secrets-hygiene-kit#install-050),
then follow the [quickstart](quickstart.md) or reproduce the [demonstration](demo.md).

![Recorded CLI demonstration](images/secguard-demo.png)

The CLI processes reports locally. Your scanner performs detection; an authorized
responder handles credential revocation and rotation. Remediation Hub exchange is
local and tracker output is a preview. [OPA and DefectDojo](integrations.md)
consume optional file exports. Canonical JSON can be reimported with the current
catalog and waiver policy; detector claims remain imported report data.

For changes to this repository, see [repository CI and required checks](repository-ci.md).
