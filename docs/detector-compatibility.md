# Detector compatibility corpus

## Betterleaks 1.9.0

The [Betterleaks corpus](../tests/fixtures/betterleaks-1.9.0) was captured on
Windows amd64 with the official 1.9.0 executable and checksum-verified archive.
The actual `dir` scan returned two findings for constructed input and none for
clean input. The malformed path case is derived test data, not producer output.
The [provenance record](../tests/fixtures/betterleaks-1.9.0/provenance.json) records
binary, input, raw-report and sanitized-fixture hashes and command arguments.
Credential validation was not enabled for the capture.

Select the adapter explicitly:

```console
secguard scan normalize --input betterleaks.json --format betterleaks --output betterleaks-canonical.json
secguard scan check --input betterleaks-canonical.json --input trufflehog.jsonl
```

Betterleaks 1.x uses an array resembling Gitleaks JSON. Auto-detection keeps
Gitleaks identity for that ambiguous shape; the explicit adapter keeps
`betterleaks:` rule identity and independent waiver scopes. Reported
`ValidationStatus: valid` maps to true/Critical; invalid and revoked map to false.
Missing, unknown, error and needs-validation map to null. Unrecognized values
fail rather than silently weakening results. These are imported report claims,
with no provider request by secguard.

Betterleaks 2.x envelopes are outside this adapter. The capture script requires
the pinned Windows binary hash; its help describes reproduction:

```console
python scripts/capture_betterleaks_fixtures.py --help
```

Regression tests check corpus hashes, identity, classification, clean/malformed
inputs, verification semantics and credential-canary redaction.

## Original producer corpus

secguard parses detector reports. The corpus in
[`tests/fixtures/producer_versions`](../tests/fixtures/producer_versions) records
formats observed by running pinned producers against synthetic inputs on
2026-10-05. It provides regression evidence for the cases below.

| Producer | Version | Captured format | Positive findings | Clean findings |
| --- | --- | --- | ---: | ---: |
| [Gitleaks](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) | 8.30.1 | JSON array, `dir` source | 3 | 0 |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog/releases/tag/v3.97.9) | 3.97.9 | JSON Lines, `filesystem` source | 2 | 0 |
| [detect-secrets](https://pypi.org/project/detect-secrets/1.5.0/) | 1.5.0 | Scan baseline JSON | 2 | 0 |

The capture environment was Windows 11, amd64, Python 3.12.10. Gitleaks used its
built-in rules. TruffleHog selected `AWS,Github`; detect-secrets used its default
plugins. The source directory contained only a generated `config.env`. The
positive input held constructed AWS and GitHub patterns; the clean input held
`APP_MODE=demo`. Both controls exited successfully in all three producers.

## Observed classification

| Producer rule | Source line | Canonical type | Default result |
| --- | ---: | --- | --- |
| `gitleaks:aws-access-token` | 2 | `aws-access-key` | high |
| `gitleaks:generic-api-key` | 3 | `generic-api-key` | low |
| `gitleaks:github-pat` | 4 | `github-pat` | high |
| `trufflehog:AWS` | 2 | `aws-access-key` | high, unverified |
| `trufflehog:Github` | 4 | `github-pat` | high, unverified |
| `detect-secrets:AWS Access Key` | 2 | `aws-access-key` | high, unverified |
| `detect-secrets:GitHub Token` | 4 | `github-pat` | high, unverified |

All captured locations were relative `config.env` paths. The AWS and GitHub
findings merge across the three producers while retaining their detector rules.
The Gitleaks generic finding remains a separate low-severity finding.

## Provenance and redaction

[`producer-lock.json`](../tests/fixtures/producer_versions/producer-lock.json)
records the official download URLs, archive hashes, executable hashes and seven
wheel versions/hashes used for capture. Archive hashes matched both release
asset digests and the vendors' checksum files. Wheel hashes matched PyPI's
published digests. Signature verification was not performed.

[`provenance.json`](../tests/fixtures/producer_versions/provenance.json) records
producer versions, commands, regeneration-script hash, input hashes, original report hashes, curated
fixture hashes and observed rule/location metadata. Original reports and
execution receipts remain in the ignored evidence area. The committed files
retain native field names, containers, types, coordinates and detector names.
The following transformations make them suitable for publication:

- Gitleaks credential, match, commit-message and author/email fields contain
  canaries wherever the producer supplied a nonempty value.
- TruffleHog raw, redacted, extra-data, secret-parts and structured-data fields
  contain canaries wherever the producer supplied a string value. Containers,
  empty strings, booleans and nulls retain their native shape.
- detect-secrets hashes become obvious 40-digit synthetic canaries. Its
  `generated_at` field is fixed at `2026-10-05T00:00:00Z`.
- Entries are sorted and serialized with UTF-8 and LF endings so fixture hashes
  survive checkout across operating systems.

Each `malformed` file is derived from its positive fixture by replacing the
first required rule name with an object containing a canary. These are negative
test inputs; the producers did not emit them.

## Reproduction

Download the versions above from their official sources and check them against
the lock. Install detect-secrets and the wheel versions listed in the lock in an
isolated environment. Keep binaries, inputs, caches and receipts under the
ignored `melhorias/09_evidencias/mel_002_detector_producers` directory.

The capture uses these producer arguments from the synthetic directory:

```text
gitleaks dir . --exit-code 0 --report-format json --report-path <REPORT> --no-banner --no-color --log-level error
trufflehog filesystem . --json --no-verification --no-update --fail-on-scan-errors --concurrency 1 --log-level=-1 --include-detectors=AWS,Github
detect-secrets scan --all-files --no-verify
```

The [`regeneration script`](../scripts/regenerate_detector_fixtures.py) creates
the inputs, checks versions and pinned native executable hashes, captures the
reports and applies the transformations above. It accepts explicit CLI paths:

```text
python scripts/regenerate_detector_fixtures.py --gitleaks <GITLEAKS_CLI> --trufflehog <TRUFFLEHOG_CLI> --detect-secrets <DETECT_SECRETS_CLI>
```

For the recorded Windows capture, Python's legacy path limit prevented normal
imports from the long checkout path. A temporary drive mapping to the same
evidence directory and a `.py` loader supplied the isolated package directory
on `sys.path`, then called the unmodified `detect_secrets.main.main` entrypoint
under `python -S`. The loader's digest and kind are recorded in the manifest;
the package itself came from the verified wheel. The loader changed no detector
logic. A short checkout path can use the ordinary detect-secrets executable.

The native binary lock covers the recorded Windows distributions. To capture a
different distribution, verify its official asset and update the executable
hashes in the lock before regeneration.

Verification-capable producers ran with `--no-verification` or `--no-verify`,
and TruffleHog ran with `--no-update`. Provider credentials were excluded from
the child environment. These controls do not constitute an operating-system
network sandbox or a measurement of all network activity. Flag semantics are
documented in the pinned [TruffleHog source](https://github.com/trufflesecurity/trufflehog/blob/v3.97.9/main.go)
and [detect-secrets documentation](https://github.com/Yelp/detect-secrets/blob/v1.5.0/README.md).

## Regression checks and limits

[`test_producer_versions.py`](../tests/test_producer_versions.py) contains 26
cases covering the recorded corpus. The tests need no producer installation.

| Contract | Cases | Oracle |
| --- | ---: | --- |
| Version/report provenance | 1 | Versions, hashes, successful capture and fixture identity |
| Positive parsing/classification | 3 | Auto and explicit parsing agree with the observed rules, types and severities |
| Clean parsing | 3 | Auto and explicit parsing produce zero findings |
| Malformed parsing | 3 | Input error without echoing canaries |
| Positive/clean CLI outputs | 6 | Gate exits 1/0; counts agree; console, JSON, SARIF, Markdown, PR comment and remediation exchange omit canaries |
| Canonical JSON stdout | 3 | Finding counts and absence of canaries |
| Markdown stdout | 3 | Report rendering and absence of canaries |
| Malformed CLI outputs | 3 | Exit 2, no traceback, no partial outputs and no canaries |
| Cross-producer merge | 1 | Three findings, all correlated rules retained, input order independent |

```text
python -m pytest tests/test_producer_versions.py
```

The corpus covers the listed versions, source modes and synthetic patterns.
Other detector versions, plugins, source modes and platform-produced formats
remain outside this matrix. Credential verification is disabled, so these
fixtures provide no evidence about live credentials or provider access.
