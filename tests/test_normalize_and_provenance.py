"""Composition and detector provenance through the public CLI."""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path

import pytest
from conftest import ALL_REPORTS, GITLEAKS_REPORT, assert_no_secret_material
from typer.testing import CliRunner

from secguard.cli.app import app

runner = CliRunner()


def _normalize(reports: list[Path], *extra: str):
    arguments = ["scan", "normalize"]
    for report in reports:
        arguments.extend(["--input", str(report)])
    return runner.invoke(app, [*arguments, *extra])


def test_normalize_combines_three_detectors_and_keeps_the_strongest_evidence():
    result = _normalize(ALL_REPORTS)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["schema"] == "secguard.findings/v1"
    assert len(payload["findings"]) == 5
    assert [item["severity"] for item in payload["findings"]] == [
        "critical",
        "high",
        "medium",
        "medium",
        "low",
    ]
    aws = next(item for item in payload["findings"] if item["secret_type"] == "aws-access-key")
    assert aws["verified"] is True
    assert sorted([aws["scanner"], *aws["corroborated_by"]]) == [
        "detect-secrets",
        "gitleaks",
        "trufflehog",
    ]
    assert aws["fingerprint"].startswith("gitleaks:")
    assert len(aws["corroborated_rules"]) == 2
    assert_no_secret_material(result.output)


def test_normalize_order_and_repeated_reports_do_not_change_the_document():
    first = _normalize(ALL_REPORTS)
    reversed_inputs = _normalize(list(reversed(ALL_REPORTS)))
    repeated = _normalize([*ALL_REPORTS, GITLEAKS_REPORT])

    assert first.exit_code == reversed_inputs.exit_code == repeated.exit_code == 0
    assert first.stdout == reversed_inputs.stdout == repeated.stdout
    assert len(json.loads(first.stdout)["findings"]) == 5


@pytest.mark.parametrize("policy_present", [False, True])
def test_normalize_does_not_apply_waivers(tmp_path, monkeypatch, policy_present):
    monkeypatch.chdir(tmp_path)
    if policy_present:
        policy = tmp_path / ".secguard" / "waivers.yaml"
        policy.parent.mkdir()
        policy.write_text(
            'schema: "secguard.waiver/v1"\nwaivers:\n'
            "  - id: WV-2026-001\n    rule: gitleaks:aws-access-token\n"
            "    path: src/example_config.py\n    reason: Expired fixture exception\n"
            "    owner: appsec@example.invalid\n    approver: security-lead\n"
            "    expires_at: 2026-01-01\n",
            encoding="utf-8",
        )

    result = _normalize(ALL_REPORTS)

    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)["findings"]) == 5
    assert "waiver" not in result.stderr.lower()


@pytest.mark.parametrize("bad_first", [False, True])
def test_one_bad_input_prevents_normalize_output(tmp_path, bad_first):
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"unexpected": true}', encoding="utf-8")
    inputs = [malformed, GITLEAKS_REPORT] if bad_first else [GITLEAKS_REPORT, malformed]
    output = tmp_path / "canonical.json"

    result = _normalize(inputs, "--output", str(output))

    assert result.exit_code == 2
    assert not output.exists()


def test_explicit_format_applies_to_every_normalize_input(tmp_path):
    output = tmp_path / "canonical.json"
    result = _normalize(ALL_REPORTS, "--format", "gitleaks", "--output", str(output))

    assert result.exit_code == 2
    assert not output.exists()


def test_missing_normalize_input_uses_the_shared_input_error():
    result = runner.invoke(app, ["scan", "normalize"])

    assert result.exit_code == 2
    assert "at least one --input scanner report is required" in result.output


@pytest.mark.parametrize(
    ("verified", "console_label", "markdown_label", "severity", "exit_code"),
    [
        (True, "verified=detector:true", "**reported true**", "critical", 1),
        (False, "verified=detector:false", "reported false", "high", 0),
        (None, "verified=not-reported", "not reported", "high", 0),
    ],
)
def test_verification_is_imported_without_provider_calls(
    tmp_path, monkeypatch, verified, console_label, markdown_label, severity, exit_code
):
    def forbidden_call(*args, **kwargs):
        pytest.fail("normalization must not contact a provider or run a detector")

    monkeypatch.setattr(socket, "create_connection", forbidden_call)
    monkeypatch.setattr(subprocess, "Popen", forbidden_call)
    report = tmp_path / "detector.json"
    entry = {
        "DetectorName": "AWS",
        "Raw": "SECGUARD-CANARY-DO-NOT-EMIT-0001",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "src/settings.py", "line": 12}}},
    }
    if verified is not None:
        entry["Verified"] = verified
    report.write_text(json.dumps([entry]), encoding="utf-8")
    output = tmp_path / "findings.json"
    markdown = tmp_path / "report.md"
    sarif = tmp_path / "out.sarif"
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text('schema: "secguard.waiver/v1"\nwaivers: []\n', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "check",
            "--input",
            str(report),
            "--fail-on",
            "critical",
            "--today",
            "2026-10-06",
            "--waivers",
            str(waiver_file),
            "--json",
            str(output),
            "--markdown",
            str(markdown),
            "--sarif",
            str(sarif),
        ],
    )

    assert result.exit_code == exit_code, result.output
    assert console_label in result.stdout
    assert "verified=live" not in result.stdout
    text = markdown.read_text(encoding="utf-8")
    assert "Verified (detector report)" in text
    assert markdown_label in text
    assert "**live**" not in text
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema"] == "secguard.findings/v1"
    finding = document["findings"][0]
    assert finding["verified"] is verified
    assert finding["severity"] == severity
    sarif_result = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"][0]
    if verified is None:
        assert "verified" not in sarif_result["properties"]
    else:
        assert sarif_result["properties"]["verified"] is verified
    for artifact in (
        result.output,
        text,
        output.read_text(encoding="utf-8"),
        sarif.read_text(encoding="utf-8"),
    ):
        assert_no_secret_material(artifact)
