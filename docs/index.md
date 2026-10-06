# Secrets Hygiene Kit

Secrets Hygiene Kit is a Python CLI, `secguard`, for teams that already run
Gitleaks, TruffleHog or detect-secrets. It combines their reports, enforces expiring
waivers and produces JSON, SARIF and Markdown reports with response guidance.

The current release is **0.4.0 beta**, tested on Linux and Windows with Python
3.12, 3.13 and 3.14.

[Install the versioned release](https://github.com/lucashgrifoni/secrets-hygiene-kit#install-040),
then follow the [quickstart](quickstart.md) or reproduce the [demonstration](demo.md).

![Recorded CLI demonstration](images/secguard-demo.png)

The CLI processes reports locally. Your scanner performs detection; an authorized
responder handles credential revocation and rotation. Remediation Hub exchange is
local and tracker output is a preview.

For changes to this repository, see [repository CI and required checks](repository-ci.md).
