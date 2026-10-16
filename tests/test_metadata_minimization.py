"""Opt-in prose minimization across output consumers, with identity and gate oracles."""

from __future__ import annotations

import json

import pytest
import yaml
from typer.testing import CliRunner

from secguard.cli.app import app
from secguard.core.catalog import load_catalog
from secguard.core.metadata import OMITTED

CANARY = "CANARY-confidential-prose-42"
runner = CliRunner()


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            {
                "schema": "secguard.synthetic-findings/v1",
                "scanner": "synthetic",
                "findings": [
                    {
                        "rule_id": "aws-access-token",
                        "path": path,
                        "line": 2,
                        "message": CANARY,
                        "remediation": CANARY,
                        "severity": "high",
                    }
                    for path in ("src/active.py", "src/waived.py")
                ],
            }
        ),
        encoding="utf-8",
    )
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(
        yaml.safe_dump(
            {
                "schema": "secguard.waiver/v1",
                "waivers": [
                    {
                        "id": "WV-2026-001",
                        "rule": "synthetic:*",
                        "path": "src/waived.py",
                        "reason": CANARY,
                        "owner": CANARY,
                        "approver": CANARY,
                        "expires_at": "2027-01-01",
                    }
                ],
            },
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    catalog = load_catalog().model_dump(mode="json", by_alias=True)
    for spec in catalog["secret_types"].values():
        spec["title"] = CANARY
    rules = tmp_path / "rules.yaml"
    rules.write_text(yaml.safe_dump(catalog, allow_unicode=True), encoding="utf-8")
    return raw, waivers, rules


def _check(inputs, tmp_path, *, minimal, today="2026-10-16"):
    raw, waivers, rules = inputs
    folder = tmp_path / ("minimal" if minimal else "default")
    options = ("json", "sarif", "markdown", "pr-comment", "remediation", "opa-input", "defectdojo")
    args = [
        "scan",
        "check",
        "-i",
        str(raw),
        "--waivers",
        str(waivers),
        "--rules",
        str(rules),
        "--today",
        today,
        "--repository",
        "example/internal",
    ]
    for option in options:
        args += ["--" + option, str(folder / option)]
    if minimal:
        args += ["--minimize-metadata"]
    result = runner.invoke(app, args)
    return result, {name: (folder / name).read_text(encoding="utf-8") for name in options}


@pytest.mark.parametrize("today", ["2026-10-16", "2027-01-02"])
def test_all_export_channels_minimize_prose_without_altering_ids_or_gate(inputs, tmp_path, today):
    normal, original = _check(inputs, tmp_path, minimal=False, today=today)
    minimal, protected = _check(inputs, tmp_path, minimal=True, today=today)
    assert normal.exit_code == minimal.exit_code == 1, minimal.output
    assert CANARY in original["json"]
    assert CANARY not in minimal.output
    for content in protected.values():
        assert CANARY not in content
    original_findings = json.loads(original["json"])["findings"]
    protected_findings = json.loads(protected["json"])["findings"]
    for left, right in zip(original_findings, protected_findings, strict=True):
        assert right == {
            **left,
            "message": OMITTED,
            "secret_title": "Secret finding",
            "remediation": None,
        }
    # The remediation exchange excludes caller prose already. OPA carries
    # findings but its resolved decision must survive the projection unchanged.
    assert original["remediation"] == protected["remediation"]
    original_dojo = json.loads(original["defectdojo"])["findings"]
    protected_dojo = json.loads(protected["defectdojo"])["findings"]
    for left, right in zip(original_dojo, protected_dojo, strict=True):
        for key in ("unique_id_from_tool", "vuln_id_from_tool", "severity", "active", "verified"):
            assert left[key] == right[key]
    original_opa, protected_opa = (
        json.loads(original["opa-input"]),
        json.loads(protected["opa-input"]),
    )
    assert {key: value for key, value in original_opa.items() if key != "findings"} == {
        key: value for key, value in protected_opa.items() if key != "findings"
    }
    original_sarif = json.loads(original["sarif"])["runs"][0]["results"]
    protected_sarif = json.loads(protected["sarif"])["runs"][0]["results"]
    for left, right in zip(original_sarif, protected_sarif, strict=True):
        for key in ("ruleId", "level", "locations", "partialFingerprints"):
            assert left.get(key) == right.get(key)
        assert bool(left.get("suppressions")) == bool(right.get("suppressions"))


@pytest.mark.parametrize("command", [["scan", "normalize"], ["report"]])
def test_stdout_is_minimized_and_the_policy_does_not_leak_between_invocations(inputs, command):
    raw, waivers, rules = inputs
    args = [*command, "-i", str(raw), "--rules", str(rules)]
    if command == ["report"]:
        args += ["--waivers", str(waivers), "--today", "2026-10-16"]
    assert CANARY not in runner.invoke(app, [*args, "--minimize-metadata"]).output
    normal = runner.invoke(app, args)
    assert normal.exit_code == 0
    if command == ["scan", "normalize"]:
        assert CANARY in normal.output
    else:
        # The full Markdown renderer already excludes these prose fields.
        assert CANARY not in normal.output


def test_canonical_reimport_preserves_minimized_fingerprint_and_waiver_scope(inputs, tmp_path):
    raw, waivers, rules = inputs
    destination = tmp_path / "minimal.json"
    normal = runner.invoke(app, ["scan", "normalize", "-i", str(raw), "--rules", str(rules)])
    minimal = runner.invoke(
        app,
        [
            "scan",
            "normalize",
            "-i",
            str(raw),
            "--rules",
            str(rules),
            "--minimize-metadata",
            "-o",
            str(destination),
        ],
    )
    assert normal.exit_code == minimal.exit_code == 0
    before = json.loads(normal.stdout)["findings"]
    result = runner.invoke(
        app,
        [
            "scan",
            "check",
            "-i",
            str(destination),
            "--waivers",
            str(waivers),
            "--rules",
            str(rules),
            "--today",
            "2026-10-16",
            "--minimize-metadata",
        ],
    )
    assert result.exit_code == 1
    assert "1 active, 1 waived" in result.stdout
    assert CANARY not in result.output
    after = json.loads(destination.read_text(encoding="utf-8"))["findings"]
    assert [(item["id"], item["fingerprint"]) for item in before] == [
        (item["id"], item["fingerprint"]) for item in after
    ]


def test_processing_diagnostics_and_write_notices_omit_input_text(tmp_path):
    raw = tmp_path / (CANARY + ".json")
    raw.write_text("{malformed")
    result = runner.invoke(app, ["scan", "normalize", "-i", str(raw), "--minimize-metadata"])
    assert result.exit_code == 2
    assert CANARY not in result.output
    assert "inspect arguments and inputs locally" in result.output
    raw.write_text("[]")
    result = runner.invoke(
        app,
        [
            "scan",
            "normalize",
            "-i",
            str(raw),
            "-o",
            str(tmp_path / (CANARY + ".out")),
            "--minimize-metadata",
        ],
    )
    assert result.exit_code == 0
    assert CANARY not in result.output


@pytest.mark.parametrize("message", ["legitimate summary", "日本語 ação", "A" * 3000])
def test_minimization_does_not_corrupt_location_or_identity_without_supplied_fingerprint(
    tmp_path, message
):
    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            [{"RuleID": "aws-access-token", "File": "código/日本語.py", "Description": message}]
        ),
        encoding="utf-8",
    )
    args = ["scan", "normalize", "-i", str(raw)]
    normal = json.loads(runner.invoke(app, args).stdout)["findings"][0]
    minimal = json.loads(runner.invoke(app, [*args, "--minimize-metadata"]).stdout)["findings"][0]
    assert minimal["path"] == normal["path"] == "código/日本語.py"
    assert minimal["id"] == normal["id"]
    assert minimal["fingerprint"] == normal["fingerprint"]
