import json
from pathlib import Path

import pytest

from secguard.core.findings import (
    CANONICAL_FINDINGS_SCHEMA_VERSION,
    FindingParseError,
    load_synthetic_scan_file,
)

FIXTURE_FILE = Path(__file__).parent / "fixtures" / "synthetic-findings.json"


def test_load_synthetic_scan_file_normalizes_findings():
    document = load_synthetic_scan_file(FIXTURE_FILE)

    assert document.schema_version == CANONICAL_FINDINGS_SCHEMA_VERSION
    assert len(document.findings) == 2

    finding = document.findings[0]
    assert finding.id.startswith("FND-")
    assert finding.scanner == "gitleaks"
    assert finding.rule == "gitleaks:aws-access-key"
    assert finding.path == "src/example_config.py"
    assert finding.line == 12
    assert finding.column == 7
    assert finding.fingerprint == "synthetic-gitleaks-src-example-config-12"


def test_load_synthetic_scan_file_generates_fingerprint_when_missing(tmp_path):
    finding_file = tmp_path / "findings.json"
    finding_file.write_text(
        json.dumps(
            {
                "schema": "secguard.synthetic-findings/v1",
                "scanner": "detect-secrets",
                "findings": [
                    {
                        "rule_id": "keyword",
                        "path": "src/settings.py",
                        "message": "Synthetic scanner hit for a keyword pattern.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    document = load_synthetic_scan_file(finding_file)

    assert document.findings[0].fingerprint.startswith("secguard:")
    assert document.findings[0].id.startswith("FND-")


def test_load_synthetic_scan_file_rejects_secret_material_fields(tmp_path):
    finding_file = tmp_path / "findings.json"
    finding_file.write_text(
        json.dumps(
            {
                "schema": "secguard.synthetic-findings/v1",
                "scanner": "trufflehog",
                "findings": [
                    {
                        "rule_id": "private-key",
                        "path": "src/fixture.txt",
                        "message": "Synthetic scanner hit for a private key pattern.",
                        "match": "synthetic-placeholder-value",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(FindingParseError) as exc_info:
        load_synthetic_scan_file(finding_file)

    message = str(exc_info.value)
    assert "Extra inputs are not permitted" in message
    assert "synthetic-placeholder-value" not in message


def test_load_synthetic_scan_file_rejects_unsafe_paths(tmp_path):
    finding_file = tmp_path / "findings.json"
    finding_file.write_text(
        json.dumps(
            {
                "schema": "secguard.synthetic-findings/v1",
                "scanner": "gitleaks",
                "findings": [
                    {
                        "rule_id": "generic-api-key",
                        "path": "../outside.txt",
                        "message": "Synthetic scanner hit for a generic API key pattern.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(FindingParseError, match="path cannot contain parent traversal"):
        load_synthetic_scan_file(finding_file)
