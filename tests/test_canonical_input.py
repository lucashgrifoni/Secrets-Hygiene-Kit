"""Canonical reimport is a new untrusted input boundary, not an attestation."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from secguard.cli.app import app
from secguard.core.catalog import load_catalog
from secguard.core.detectors import load_reports
from secguard.core.findings import FindingParseError, build_finding

runner = CliRunner()


def canonical_payload(tmp_path):
    raw = tmp_path / "native.json"
    raw.write_text(
        json.dumps([{"RuleID": "github-pat", "File": "src/auth.py", "StartLine": 3}]),
        encoding="utf-8",
    )
    return load_reports([raw]).model_dump(mode="json", by_alias=True)


def write_payload(tmp_path, payload):
    path = tmp_path / "canonical.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.parametrize("report_format", ["auto", "canonical"])
def test_round_trip_and_gate_for_an_unmodified_export(tmp_path, report_format):
    payload = canonical_payload(tmp_path)
    path = write_payload(tmp_path, payload)
    loaded = load_reports([path], report_format=report_format)
    assert loaded.model_dump(mode="json", by_alias=True) == payload
    result = runner.invoke(app, ["scan", "check", "--input", str(path)])
    assert result.exit_code == 1, result.output
    assert "gitleaks:github-pat" in result.output


def test_merged_round_trip_preserves_each_independent_waiver_scope(tmp_path):
    native = tmp_path / "native.json"
    native.write_text('[{"RuleID":"github-pat","File":"src/auth.py","StartLine":3}]')
    truffle = tmp_path / "truffle.json"
    truffle.write_text(
        json.dumps(
            [
                {
                    "DetectorName": "Github",
                    "Verified": True,
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "src/auth.py", "line": 3}}},
                }
            ]
        )
    )
    original = load_reports([native, truffle])
    path = write_payload(tmp_path, original.model_dump(mode="json", by_alias=True))
    repeated = load_reports([path, native, truffle])
    assert repeated == original
    assert set(repeated.findings[0].rules) == {"gitleaks:github-pat", "trufflehog:Github"}
    assert repeated.findings[0].verified is True


def test_forged_classification_id_or_lower_severity_cannot_weaken_the_gate(tmp_path):
    payload = canonical_payload(tmp_path)
    finding = payload["findings"][0]
    original_id = finding["id"]
    finding.update(
        id="forged",
        secret_type="generic-api-key",
        secret_title="Forged",
        playbook="generic-api-key",
        mapping="fallback",
        severity="info",
    )
    path = write_payload(tmp_path, payload)
    result = runner.invoke(app, ["scan", "check", "--input", str(path)])
    assert result.exit_code == 1, result.output
    imported = load_reports([path]).findings[0]
    assert imported.secret_type == "github-pat"
    assert imported.severity == "high"
    assert imported.id == original_id


def test_canonical_import_preserves_a_stricter_source_rating(tmp_path):
    payload = canonical_payload(tmp_path)
    payload["findings"][0]["severity"] = "critical"
    imported = load_reports([write_payload(tmp_path, payload)]).findings[0]
    assert imported.severity == "critical"


@pytest.mark.parametrize(
    "update",
    [
        {"verified": "false"},
        {"verified": 1},
        {"line": True},
        {"line": "3"},
        {"path": "../outside.py"},
        {"path": "C:\\outside.py"},
        {"path": "src/auth.py\nPASS"},
        {"scanner": "gitleaks\nPASS"},
        {"rule": "trufflehog:Github"},
        {"fingerprint": "forged\x1b[31m"},
        {"corroborated_rules": ["gitleaks:private-key"]},
        {"SECGUARD-CANARY-UNKNOWN-FIELD": "hidden-value"},
    ],
)
def test_invalid_canonical_metadata_is_rejected_without_writing_or_echoing_values(tmp_path, update):
    payload = canonical_payload(tmp_path)
    payload["findings"][0].update(update)
    path = write_payload(tmp_path, payload)
    output = tmp_path / "out.json"
    result = runner.invoke(app, ["scan", "check", "--input", str(path), "--json", str(output)])
    assert result.exit_code == 2, result.output
    assert not output.exists()
    assert "SECGUARD-CANARY" not in result.output
    assert "PASS:" not in result.output


@pytest.mark.parametrize(
    "payload",
    [
        {"findings": []},
        {"schema": "secguard.findings/v2", "findings": []},
        {"schema": "secguard.findings/v1", "findings": None},
        {"schema": "secguard.findings/v1", "findings": [], "Secret": "SECGUARD-CANARY"},
    ],
)
def test_explicit_canonical_schema_and_structure_are_required(tmp_path, payload):
    with pytest.raises(FindingParseError):
        load_reports([write_payload(tmp_path, payload)], report_format="canonical")


def test_empty_canonical_is_a_valid_clean_report(tmp_path):
    path = write_payload(tmp_path, {"schema": "secguard.findings/v1", "findings": []})
    result = runner.invoke(app, ["scan", "check", "--input", str(path)])
    assert result.exit_code == 0, result.output


def test_custom_scanner_and_rule_colon_round_trip(tmp_path):
    finding = build_finding(
        scanner="internal",
        rule_id="custom:rule",
        path="src/a.py",
        message="Synthetic integration finding",
        catalog=load_catalog(),
    )
    payload = {"schema": "secguard.findings/v1", "findings": [finding.model_dump(mode="json")]}
    imported = load_reports([write_payload(tmp_path, payload)])
    assert imported.findings == [finding]
