"""Betterleaks 1.x shares JSON metadata with Gitleaks but has a distinct identity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secguard.cli.app import app
from secguard.core.catalog import load_catalog
from secguard.core.detectors import load_reports
from secguard.core.findings import FindingParseError

runner = CliRunner()
CANARY = "SECGUARD-BETTERLEAKS-CANARY"


def write_report(tmp_path, status="absent"):
    entry = {
        "RuleID": "github-pat",
        "File": "src/auth.py",
        "StartLine": 3,
        "Secret": CANARY,
        "Match": CANARY,
        "Message": CANARY,
        "Email": CANARY,
        "MatchContext": CANARY,
        "CaptureGroups": {"secret": CANARY},
        "ComponentSets": [{"components": [{"Secret": CANARY}]}],
        "ValidationMeta": {"token": CANARY},
        "ValidationReason": CANARY,
    }
    if status != "absent":
        entry["ValidationStatus"] = status
    path = tmp_path / "betterleaks.json"
    path.write_text(json.dumps([entry]), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "status,verified,severity",
    [
        ("absent", None, "high"),
        ("", None, "high"),
        ("valid", True, "critical"),
        ("invalid", False, "high"),
        ("revoked", False, "high"),
        ("unknown", None, "high"),
        ("error", None, "high"),
        ("needs_validation", None, "high"),
    ],
)
def test_validation_is_an_imported_claim_and_never_a_network_call(
    tmp_path, monkeypatch, status, verified, severity
):
    def forbidden(*args, **kwargs):
        pytest.fail("normalization must not contact providers or invoke a producer")

    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    path = write_report(tmp_path, status)
    imported = load_reports([path], report_format="betterleaks").findings[0]
    assert imported.scanner == "betterleaks"
    assert imported.rule == "betterleaks:github-pat"
    assert imported.secret_type == "github-pat"
    assert imported.mapping == "catalog"
    assert imported.verified is verified
    assert imported.severity == severity
    assert CANARY not in imported.model_dump_json()
    output = tmp_path / "out.json"
    result = runner.invoke(
        app,
        ["scan", "check", "--input", str(path), "--format", "betterleaks", "--json", str(output)],
    )
    assert result.exit_code == 1, result.output
    assert CANARY not in result.output + output.read_text(encoding="utf-8")


@pytest.mark.parametrize("status", [True, 1, None, [], "unsupported-" + CANARY])
def test_invalid_validation_status_fails_without_echoing_values(tmp_path, status):
    path = write_report(tmp_path, status)
    with pytest.raises(FindingParseError) as error:
        load_reports([path], report_format="betterleaks")
    assert CANARY not in str(error.value)


def test_clean_report_and_unknown_rule(tmp_path):
    clean = tmp_path / "clean.json"
    clean.write_text("[]", encoding="utf-8")
    assert load_reports([clean], report_format="betterleaks").findings == []
    catalog = load_catalog()
    assert catalog.classify("betterleaks", "unknown-rule").mapping == "fallback"


def test_unverified_1x_report_needs_explicit_format_for_identity(tmp_path):
    path = write_report(tmp_path)
    assert load_reports([path]).findings[0].scanner == "gitleaks"
    assert load_reports([path], report_format="betterleaks").findings[0].scanner == "betterleaks"


def test_v2_envelope_is_rejected_instead_of_claiming_compatibility(tmp_path):
    path = tmp_path / "v2.json"
    path.write_text('{"schema_version":"1","findings":[],"scan":{}}', encoding="utf-8")
    result = runner.invoke(
        app, ["scan", "normalize", "--input", str(path), "--format", "betterleaks"]
    )
    assert result.exit_code == 2, result.output


def test_real_producer_fixture_provenance_and_redaction():
    corpus = Path(__file__).parent / "fixtures/betterleaks-1.9.0"
    manifest = json.loads((corpus / "provenance.json").read_text(encoding="utf-8"))
    assert manifest["version"] == "1.9.0"
    assert (
        manifest["script_sha256"]
        == hashlib.sha256(
            (corpus.parents[2] / "scripts/capture_betterleaks_fixtures.py").read_bytes()
        ).hexdigest()
    )
    for case, observation in manifest["cases"].items():
        path = corpus / f"{case}.json"
        assert observation["fixture_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert b"\r" not in path.read_bytes()
        if case != "malformed":
            assert observation["exit_code"] == 0
            assert observation["validation_enabled"] is False
    positive = load_reports([corpus / "positive.json"], report_format="betterleaks")
    assert sorted(
        (item.rule, item.secret_type, item.line, item.verified) for item in positive.findings
    ) == [
        ("betterleaks:aws-access-token", "aws-access-key", 2, None),
        ("betterleaks:github-pat", "github-pat", 4, None),
    ]
    assert "SECGUARD-BETTERLEAKS-CANARY" not in positive.model_dump_json()
    assert load_reports([corpus / "clean.json"], report_format="betterleaks").findings == []
    with pytest.raises(FindingParseError):
        load_reports([corpus / "malformed.json"], report_format="betterleaks")
