# Contributing

Use Python 3.12, 3.13 or 3.14 in a virtual environment.

```console
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m build
```

## Development boundaries

Keep detection with external scanners and credential changes with authorized
responders. Do not add scanner execution or provider mutation to the CLI.

Use synthetic fixtures. Never commit credentials, production account details
or customer data. Adapters read selected metadata and discard documented
credential fields. Redaction tests must contain a canary before asserting its
absence from output.

Changes to gate decisions need passing, blocking and malformed-input cases.
Security fixes need a regression that demonstrates the vulnerable behavior
before the change and correct behavior afterward. Use explicit dates for
expiry and freshness tests.

## Adapters and playbooks

A detector adapter implements parsing and a structural format probe under
`src/secguard/core/detectors/`. Add synthetic fixtures and tests covering
JSON, SARIF, Markdown and console output. Update the rule catalog only when
the mapping is supported by the detector's documented rule.

See [adding-playbook.md](docs/adding-playbook.md) for response guidance. A
`Vetted:` date requires a review against current provider documentation; it
does not establish that actions were exercised in an account.

## Exceptions and review

A waiver needs a reason without credential values, an owner, approver and
expiry. Protect waiver and catalog changes through repository review.
The CLI records these fields without authenticating their authors.

Open a focused pull request that describes the observable change and its
validation. The release check covers Linux and Windows, installed packages,
the composite Action and dependency review. See [SECURITY.md](SECURITY.md)
for private vulnerability reporting.
