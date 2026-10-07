"""An explicit policy path is required; only the unselected default is optional."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from secguard.cli.app import app

runner = CliRunner()


@pytest.mark.parametrize("command", [["scan", "check"], ["report"]])
@pytest.mark.parametrize("selected", ["missing.yaml", ".secguard/waivers.yaml"])
def test_explicit_missing_policy_fails_before_any_output(tmp_path, monkeypatch, command, selected):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "clean.json").write_text("[]", encoding="utf-8")
    output_flag = "--json" if command[0] == "scan" else "--output"
    result = runner.invoke(
        app, [*command, "--input", "clean.json", "--waivers", selected, output_flag, "output.txt"]
    )
    assert result.exit_code == 2, result.output
    assert "waiver file not found" in result.output
    assert not (tmp_path / "output.txt").exists()


@pytest.mark.parametrize("command", [["scan", "check"], ["report"]])
def test_unselected_absent_default_is_optional(tmp_path, monkeypatch, command):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "clean.json").write_text("[]", encoding="utf-8")
    result = runner.invoke(app, [*command, "--input", "clean.json"])
    assert result.exit_code == 0, result.output
    assert "continuing with zero waivers" in result.output


@pytest.mark.parametrize("command", [["scan", "check"], ["report"]])
def test_existing_explicit_empty_policy_remains_valid(tmp_path, command):
    clean = tmp_path / "clean.json"
    clean.write_text("[]", encoding="utf-8")
    policy = tmp_path / "waivers.yaml"
    policy.write_text('schema: "secguard.waiver/v1"\nwaivers: []\n', encoding="utf-8")
    result = runner.invoke(app, [*command, "--input", str(clean), "--waivers", str(policy)])
    assert result.exit_code == 0, result.output
