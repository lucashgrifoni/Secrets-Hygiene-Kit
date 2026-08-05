# Contributing

## Development Setup

Use Python 3.12 or newer.

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

## Non-negotiables

These are the properties the project exists to guarantee. A change that breaks
one is a defect, not a trade-off to discuss.

- **Never commit real secrets**, access tokens, private keys, production URLs,
  or customer data. Fixtures use obviously synthetic canary strings.
- **secguard never runs a scanner.** Detection stays with the tool the team
  already trusts, which keeps scanner binaries out of this project's supply
  chain and keeps every adapter deterministically testable.
- **secguard never rotates, revokes, or mutates provider state.** Playbooks
  instruct humans who hold the authority to act.
- **No secret material reaches output.** Adapters read scanner reports by
  allowlist, never denylist: name the metadata keys you need and ignore
  everything else, so a new detector field that happens to carry a credential
  cannot leak in by default.

## Adding a scanner adapter

1. Add `src/secguard/core/detectors/<scanner>.py` with `parse_report` and a
   `looks_like_<scanner>` structural probe. Infer the format from payload
   structure, never from the file name.
2. Read only the keys you need. Document in the module docstring which
   secret-bearing fields you are deliberately ignoring.
3. Add a **redacted** fixture under `tests/fixtures/` whose secret-bearing
   fields contain a `SECGUARD-CANARY-DO-NOT-EMIT-*` value, and register it in
   `tests/conftest.py`. The redaction suite then covers your adapter across
   every output path automatically.
4. Map the detector's rule identifiers in `src/secguard/data/rules.yaml`. Map
   only what you can defend: a wrong mapping sends a responder down a
   provider-specific path that does not apply, which is worse than the honest
   `mapping: fallback`.

## Adding a playbook

See [docs/adding-playbook.md](docs/adding-playbook.md). In short: seven required
sections, human instructions only, no secret values, and a `Vetted:` date that
means a human checked the steps against current vendor documentation on that
date. Do not bump the date without doing the review.

## Waivers

Every waiver needs an owner, a reason without secret values, an approver, and an
expiry date tied to a real revisit plan. The gate enforces the expiry, so treat
it as a commitment rather than a formality.

## Tests

Test the behaviour, not the implementation. In particular:

- new parsing paths need a malformed-input test,
- new output surfaces need redaction coverage,
- new gate behaviour needs both the passing and the blocking case, and
- anything date-dependent takes an explicit date so the suite stays
  deterministic.
