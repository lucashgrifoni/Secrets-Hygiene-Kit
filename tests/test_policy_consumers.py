"""OPA and DefectDojo receive reconciled, redacted files; secguard stays offline."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from secguard.cli.app import app

runner = CliRunner()


def fixture(tmp_path):
    raw = tmp_path / "report.json"
    raw.write_text(
        json.dumps(
            [
                {
                    "RuleID": "github-pat",
                    "File": "src/auth.py",
                    "StartLine": 3,
                    "Secret": "SECGUARD-CONSUMER-CANARY",
                    "Match": "SECGUARD-CONSUMER-CANARY",
                },
                {"RuleID": "aws-access-token", "File": "fixtures/sample.env", "StartLine": 2},
            ]
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "waivers.yaml"
    policy.write_text(
        """schema: secguard.waiver/v1
waivers:
- id: WV-2026-006
  rule: gitleaks:aws-access-token
  path: fixtures/**
  owner: pilot
  approver: pilot-review
  reason: Synthetic local pilot exception only
  expires_at: 2026-10-20
""",
        encoding="utf-8",
    )
    return ["scan", "check", "--input", str(raw), "--waivers", str(policy), "--today", "2026-10-07"]


def test_both_consumers_keep_waiver_and_verification_semantics(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("exports must not invoke subprocesses or contact a server")

    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    opa, dojo = tmp_path / "opa.json", tmp_path / "dojo.json"
    result = runner.invoke(
        app, [*fixture(tmp_path), "--opa-input", str(opa), "--defectdojo", str(dojo)]
    )
    assert result.exit_code == 1, result.output
    policy = json.loads(opa.read_text(encoding="utf-8"))
    assert policy["schema"] == "secguard.policy-input/v1"
    assert policy["checked_on"] == "2026-10-07"
    assert policy["gate"]["passed"] is False
    assert policy["gate"]["fail_on"] == "high"
    assert sorted(item["status"] for item in policy["findings"]) == ["active", "waived"]
    imported = json.loads(dojo.read_text(encoding="utf-8"))
    assert imported["type"] == "secguard"
    assert len(imported["findings"]) == 1
    finding = imported["findings"][0]
    assert finding["severity"] == "High"
    assert finding["verified"] is False
    assert finding["active"] is True
    assert finding["file_path"] == "src/auth.py"
    assert finding["line"] == 3
    assert finding["vuln_id_from_tool"] == "gitleaks:github-pat"
    assert finding["date"] == "2026-10-07"
    assert "not-reported" in finding["description"]
    assert "SECGUARD-CONSUMER-CANARY" not in opa.read_text() + dojo.read_text() + result.output


def test_defectdojo_identity_stays_stable_when_a_second_detector_corroborates(tmp_path):
    args = fixture(tmp_path)
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    assert runner.invoke(app, [*args, "--defectdojo", str(first)]).exit_code == 1
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
    result = runner.invoke(app, [*args, "--input", str(truffle), "--defectdojo", str(second)])
    assert result.exit_code == 1, result.output
    original = json.loads(first.read_text())["findings"][0]
    corroborated = json.loads(second.read_text())["findings"][0]
    assert original["unique_id_from_tool"] == corroborated["unique_id_from_tool"]
    assert corroborated["verified"] is False
    assert "detector:true" in corroborated["description"]
    assert corroborated["severity"] == "Critical"


@pytest.mark.parametrize("flag", ["--opa-input", "--defectdojo"])
def test_new_outputs_cannot_overwrite_any_input_or_policy(tmp_path, flag):
    args = fixture(tmp_path)
    raw = tmp_path / "report.json"
    before = raw.read_bytes()
    safe = tmp_path / "normal.json"
    result = runner.invoke(app, [*args, "--json", str(safe), flag, str(raw)])
    assert result.exit_code == 2, result.output
    assert raw.read_bytes() == before
    assert not safe.exists()


def test_colliding_new_outputs_are_rejected_before_writing(tmp_path):
    destination = tmp_path / "output.json"
    result = runner.invoke(
        app, [*fixture(tmp_path), "--opa-input", str(destination), "--defectdojo", str(destination)]
    )
    assert result.exit_code == 2, result.output
    assert not destination.exists()


def test_clean_exports_and_expired_policy_still_block(tmp_path):
    args = fixture(tmp_path)
    (tmp_path / "report.json").write_text("[]", encoding="utf-8")
    opa, dojo = tmp_path / "opa.json", tmp_path / "dojo.json"
    result = runner.invoke(
        app, [*args, "--today", "2026-10-21", "--opa-input", str(opa), "--defectdojo", str(dojo)]
    )
    assert result.exit_code == 1, result.output
    assert json.loads(dojo.read_text())["findings"] == []
    exported = json.loads(opa.read_text())
    assert exported["findings"] == []
    assert exported["gate"]["passed"] is False
    assert exported["gate"]["expired_waivers"] == ["WV-2026-006"]
