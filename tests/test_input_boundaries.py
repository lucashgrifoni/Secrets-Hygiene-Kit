"""Input budget boundaries and nested validation keys from the release review."""

from __future__ import annotations

import json

import pytest
import yaml
from typer.testing import CliRunner

from secguard.cli.app import app
from secguard.core.catalog import CatalogError, load_catalog
from secguard.core.detectors import load_reports
from secguard.core.findings import FindingParseError, load_synthetic_scan_file

runner = CliRunner()
NUMERIC_KEY_CANARY = 9876543210123456789


@pytest.mark.parametrize(
    "report_format", ["auto", "gitleaks", "trufflehog", "detect-secrets", "synthetic"]
)
def test_report_exactly_at_the_byte_budget_preserves_a_legitimate_finding(
    tmp_path, monkeypatch, report_format
):
    import secguard.core.findings as findings

    path = "src/café.py"
    if report_format in {"auto", "gitleaks"}:
        payload = [{"RuleID": "generic-api-key", "File": path, "StartLine": 1}]
    elif report_format == "trufflehog":
        payload = [
            {
                "DetectorName": "GitHub",
                "SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": 1}}},
            }
        ]
    elif report_format == "detect-secrets":
        payload = {
            "results": {
                path: [
                    {
                        "type": "Secret Keyword",
                        "line_number": 1,
                        "hashed_secret": "synthetic-digest",
                    }
                ]
            }
        }
    else:
        payload = {
            "schema": "secguard.synthetic-findings/v1",
            "scanner": "fixture",
            "findings": [
                {
                    "rule_id": "generic-api-key",
                    "path": path,
                    "message": "Synthetic boundary fixture",
                }
            ],
        }
    encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b" " * 8
    monkeypatch.setattr(findings, "MAX_REPORT_BYTES", len(encoded))
    report = tmp_path / "at-limit.json"
    report.write_bytes(encoded)

    document = load_reports([report], report_format=report_format)

    assert len(document.findings) == 1
    assert document.findings[0].path == path
    assert report.read_bytes() == encoded


def test_direct_synthetic_loader_rejects_over_budget_before_json_parsing(tmp_path, monkeypatch):
    import secguard.core.findings as findings

    monkeypatch.setattr(findings, "MAX_REPORT_BYTES", 1024)
    report = tmp_path / "too-large.json"
    payload = b"{" + b" " * 1024
    report.write_bytes(payload)

    with pytest.raises(FindingParseError, match="input limit"):
        load_synthetic_scan_file(report)

    assert report.read_bytes() == payload


def _catalog(detector, rule):
    return {
        "schema": "secguard.rules/v1",
        "fallback_secret_type": "generic-api-key",
        "secret_types": {
            "generic-api-key": {
                "title": "Generic API key",
                "severity": "medium",
                "playbook": "generic-api-key",
            }
        },
        "detectors": {detector: {rule: {"secret_type": "generic-api-key"}}},
    }


@pytest.mark.parametrize("detector", ["findings", "waivers"])
def test_nested_numeric_rule_keys_cannot_escape_through_validation_errors(tmp_path, detector):
    policy = tmp_path / "rules.yaml"
    policy.write_text(yaml.safe_dump(_catalog(detector, NUMERIC_KEY_CANARY)), encoding="utf-8")
    clean = tmp_path / "clean.json"
    clean.write_text("[]", encoding="utf-8")

    with pytest.raises(CatalogError) as error:
        load_catalog(policy)
    assert str(NUMERIC_KEY_CANARY) not in str(error.value)

    result = runner.invoke(
        app, ["scan", "check", "--input", str(clean), "--rules", str(policy), "--fail-on", "none"]
    )

    assert result.exit_code == 2, result.output
    assert str(NUMERIC_KEY_CANARY) not in result.output
    assert "PASS:" not in result.output


@pytest.mark.parametrize("detector", ["findings", "waivers"])
def test_valid_rules_under_the_same_detector_names_still_classify(tmp_path, detector):
    policy = tmp_path / "rules.yaml"
    policy.write_text(yaml.safe_dump(_catalog(detector, "example-rule")), encoding="utf-8")

    result = load_catalog(policy).classify(detector, "example-rule")

    assert result.secret_type == "generic-api-key"
    assert result.mapping == "catalog"
    assert result.severity == "medium"
