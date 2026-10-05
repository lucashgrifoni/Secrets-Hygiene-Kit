"""Release regressions for gate integrity, output safety and package contracts."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
import yaml
from typer.testing import CliRunner

import secguard
from secguard.cli.app import app
from secguard.core.catalog import load_catalog
from secguard.core.detectors import load_reports
from secguard.core.findings import merge_findings
from secguard.core.matching import path_matches, rule_matches
from secguard.core.reconcile import reconcile
from secguard.core.report import render_pr_comment, render_report
from secguard.core.sarif import build_sarif
from secguard.core.waivers import WaiverDocument, new_waiver_document

TODAY = date(2026, 10, 5)
runner = CliRunner()


def _report(tmp_path, payload, name="report.json"):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _scan(path, *args):
    return runner.invoke(app, ["scan", "check", "-i", str(path), "--today", str(TODAY), *args])


@pytest.mark.parametrize("payload", [{}, {"results": None}, {"DetectorName": "AWS"}])
def test_detect_secrets_requires_results_mapping(tmp_path, payload):
    result = _scan(_report(tmp_path, payload), "--format", "detect-secrets")
    assert result.exit_code == 2
    assert "PASS" not in result.output


@pytest.mark.parametrize("report_format", ["gitleaks", "detect-secrets", "synthetic", "unknown"])
def test_empty_json_format_or_unknown_format_is_an_input_error(tmp_path, report_format):
    path = tmp_path / "empty.json"
    path.touch()
    result = _scan(path, "--format", report_format)
    assert result.exit_code == 2


@pytest.mark.parametrize("report_format", ["auto", "trufflehog"])
def test_clean_trufflehog_empty_output_survives(tmp_path, report_format):
    path = tmp_path / "clean.jsonl"
    path.touch()
    assert _scan(path, "--format", report_format).exit_code == 0


@pytest.mark.parametrize("field", ["scanner", "rule_id", "fingerprint"])
@pytest.mark.parametrize("unsafe", ["x\nPASS: forged", "x\x1b[31m", "x\udcff"])
def test_synthetic_identifiers_cannot_forge_output(tmp_path, field, unsafe):
    payload = {
        "schema": "secguard.synthetic-findings/v1",
        "scanner": "synthetic",
        "findings": [{"rule_id": "generic-api-key", "path": "src/key.py", "message": "Signal"}],
    }
    if field == "scanner":
        payload[field] = unsafe
    else:
        payload["findings"][0][field] = unsafe
    result = _scan(_report(tmp_path, payload))
    assert result.exit_code == 2
    assert "PASS: forged" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("kind", ["synthetic", "waiver", "catalog"])
@pytest.mark.parametrize(
    "canary", ["SECGUARD-CANARY-EXTRA-FIELD\nPASS: forged", 9876543210123456789]
)
def test_unknown_model_keys_are_never_echoed(tmp_path, kind, canary):
    if kind == "synthetic":
        payload = {"schema": "secguard.synthetic-findings/v1", "scanner": "x", str(canary): "value"}
        path = _report(tmp_path, payload)
        result = _scan(path)
    else:
        path = tmp_path / "policy.yaml"
        path.write_text(yaml.safe_dump({canary: "value"}), encoding="utf-8")
        if kind == "waiver":
            result = runner.invoke(app, ["waivers", "check", "--file", str(path)])
        else:
            report = _report(tmp_path, [])
            result = _scan(report, "--rules", str(path))
    assert result.exit_code == 2
    assert "SECGUARD-CANARY" not in result.output
    assert "PASS: forged" not in result.output
    assert "9876543210123456789" not in result.output


@pytest.mark.parametrize(
    "description", [{"Secret": "SECGUARD-CANARY-NESTED"}, ["SECGUARD-CANARY-NESTED"]]
)
def test_structured_description_cannot_smuggle_secret_values(tmp_path, description):
    path = _report(tmp_path, [{"RuleID": "x", "File": "a.py", "Description": description}])
    document = load_reports([path])
    outcome = reconcile(document, new_waiver_document(), today=TODAY, fail_on="none")
    assert "SECGUARD-CANARY" not in document.model_dump_json()
    assert "SECGUARD-CANARY" not in json.dumps(
        build_sarif(outcome, catalog=load_catalog(), version="test")
    )
    assert "SECGUARD-CANARY" not in _scan(path).output


def test_long_native_fingerprints_preserve_distinct_identity(tmp_path):
    prefix = "a" * 250
    report = _report(
        tmp_path,
        [
            {"RuleID": "x", "File": "a.py", "Fingerprint": prefix + "A"},
            {"RuleID": "x", "File": "b.py", "Fingerprint": prefix + "B"},
        ],
    )
    findings = load_reports([report]).findings
    assert len({finding.id for finding in findings}) == 2
    assert len({finding.fingerprint for finding in findings}) == 2


@pytest.mark.parametrize("kind", ["waiver", "catalog"])
def test_policy_read_errors_are_input_errors(tmp_path, monkeypatch, kind):
    path = tmp_path / "policy.yaml"
    path.write_text("{}", encoding="utf-8")
    original = Path.read_text

    def denied(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError(13, "Permission denied")
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    if kind == "waiver":
        result = runner.invoke(app, ["waivers", "check", "--file", str(path)])
    else:
        result = _scan(_report(tmp_path, []), "--rules", str(path))
    assert result.exit_code == 2
    assert "cannot read" in result.output
    assert "Traceback" not in result.output


def test_scaffold_write_error_is_an_input_error(tmp_path, monkeypatch):
    original = Path.open

    def denied(candidate, *args, **kwargs):
        if candidate.name == "waivers.yaml" and args and args[0] == "x":
            raise PermissionError(13, "Permission denied")
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    result = runner.invoke(app, ["init", str(tmp_path / "project"), "--ci", "none"])
    assert result.exit_code == 2
    assert "cannot write" in result.output


def test_fallback_downgrade_is_disclosed(tmp_path):
    report = _report(tmp_path, [{"RuleID": "acme-unknown", "File": "a.py"}])
    assert _scan(report, "--fail-on", "medium").exit_code == 1
    override = tmp_path / "rules.yaml"
    override.write_text(
        "fallback_secret_type: custom\nsecret_types:\n  custom:\n"
        "    title: Custom\n    severity: low\n    playbook: generic-api-key\n",
        encoding="utf-8",
    )
    result = _scan(report, "--fail-on", "medium", "--rules", str(override))
    assert result.exit_code == 0
    assert "fallback medium->low" in result.output


def test_remerge_preserves_all_detector_authority(tmp_path):
    gitleaks = _report(tmp_path, [{"RuleID": "aws-access-token", "File": "a.py", "StartLine": 1}])
    trufflehog = _report(
        tmp_path,
        [
            {
                "DetectorName": "AWS",
                "Verified": True,
                "SourceMetadata": {"Data": {"Git": {"file": "a.py", "line": 1}}},
            }
        ],
        "trufflehog.json",
    )
    first = load_reports([gitleaks, trufflehog])
    second = merge_findings([first, load_reports([gitleaks])])
    assert set(second.findings[0].rules) == set(first.findings[0].rules)
    assert "trufflehog" in second.findings[0].corroborated_by


def test_remerge_preserves_original_scanner_evidence(tmp_path):
    gitleaks = _report(tmp_path, [{"RuleID": "aws-access-token", "File": "a.py", "StartLine": 1}])
    trufflehog = _report(
        tmp_path,
        [
            {
                "DetectorName": "AWS",
                "Verified": True,
                "SourceMetadata": {"Data": {"Git": {"file": "a.py", "line": 1}}},
            }
        ],
        "trufflehog.json",
    )
    first = load_reports([gitleaks, trufflehog])
    second = merge_findings([first, load_reports([gitleaks])])
    assert {second.findings[0].scanner, *second.findings[0].corroborated_by} == {
        "gitleaks",
        "trufflehog",
    }


@pytest.mark.parametrize("report_format", ["auto", "gitleaks", "synthetic"])
def test_oversized_json_integer_is_an_input_error(tmp_path, report_format):
    path = tmp_path / "huge.json"
    if report_format == "synthetic":
        text = '{"schema":"secguard.synthetic-findings/v1","scanner":"x","findings":['
        text += '{"rule_id":"generic-api-key","path":"a.py","message":"x","line":'
        text += "9" * 5000 + "}]}"
    else:
        text = '[{"RuleID":"x","File":"a.py","StartLine":' + "9" * 5000 + "}]"
    path.write_text(text, encoding="utf-8")
    result = _scan(path, "--format", report_format)
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def _waiver_document(identifier="WV-2026-001", expires="2026-12-01"):
    return WaiverDocument.model_validate(
        {
            "schema": "secguard.waiver/v1",
            "waivers": [
                {
                    "id": identifier,
                    "rule": "gitleaks:*",
                    "path": "src/**",
                    "reason": "Synthetic fixture",
                    "owner": "appsec@example.invalid",
                    "approver": "security-lead",
                    "expires_at": expires,
                }
            ],
        }
    )


@pytest.mark.parametrize("expires", ["2026-12-01", "2026-01-01"])
def test_waiver_identifier_cannot_inject_markdown(tmp_path, expires):
    identifier = "WV-2026-001` | [click](https://example.invalid)"
    report = _report(tmp_path, [{"RuleID": "x", "File": "src/a.py"}])
    outcome = reconcile(
        load_reports([report]), _waiver_document(identifier, expires), today=TODAY, fail_on="high"
    )
    for text in [
        render_report(outcome, generated_on=TODAY, version="test"),
        render_pr_comment(outcome, generated_on=TODAY),
    ]:
        assert f"`{identifier}`" not in text
        if identifier.split("`")[0] in text:
            assert "``WV-2026-001`" in text
            assert "\\|" in text


def test_partial_waiver_remains_visible_when_it_waives_another_finding(tmp_path):
    gitleaks = _report(
        tmp_path,
        [
            {"RuleID": "aws-access-token", "File": "src/a.py", "StartLine": 1},
            {"RuleID": "aws-access-token", "File": "src/b.py", "StartLine": 1},
        ],
    )
    trufflehog = _report(
        tmp_path,
        [
            {
                "DetectorName": "AWS",
                "SourceMetadata": {"Data": {"Git": {"file": "src/b.py", "line": 1}}},
            }
        ],
        "second.json",
    )
    waivers = _waiver_document()
    outcome = reconcile(load_reports([gitleaks, trufflehog]), waivers, today=TODAY, fail_on="high")
    assert len(outcome.waived) == 1
    assert len(outcome.narrowed_waivers) == 1
    assert not outcome.unused_waivers
    text = render_report(outcome, generated_on=TODAY, version="test")
    assert "covers only part" in text
    path = tmp_path / "waivers.yaml"
    path.write_text(
        yaml.safe_dump(waivers.model_dump(mode="json", by_alias=True)), encoding="utf-8"
    )
    result = _scan(gitleaks, "--input", str(trufflehog), "--waivers", str(path))
    assert result.exit_code == 1
    assert "partial-waiver" in result.output


def test_sarif_rule_id_is_stable_when_another_severity_is_added(tmp_path):
    verified = _report(
        tmp_path,
        [
            {
                "DetectorName": "AWS",
                "Verified": True,
                "SourceMetadata": {"Data": {"Git": {"file": "src/a.py", "line": 1}}},
            }
        ],
    )
    unverified = _report(
        tmp_path, [{"RuleID": "aws-access-token", "File": "src/b.py"}], "other.json"
    )
    outcomes = [
        reconcile(load_reports(paths), new_waiver_document(), today=TODAY, fail_on="high")
        for paths in [[verified], [verified, unverified]]
    ]
    ids = []
    for outcome in outcomes:
        run = build_sarif(outcome, catalog=load_catalog(), version="test")["runs"][0]
        result = next(
            r for r in run["results"] if r["properties"]["resolvedSeverity"] == "critical"
        )
        ids.append(result["ruleId"])
        assert (
            run["tool"]["driver"]["rules"][result["ruleIndex"]]["properties"]["security-severity"]
            == "9.5"
        )
    assert ids == ["aws-access-key/critical"] * 2


def test_sarif_preserves_resolved_severity_and_portable_uri(tmp_path):
    path = "src/ação #key?%.py"
    report = _report(
        tmp_path,
        [
            {
                "DetectorName": "AWS",
                "Verified": True,
                "SourceMetadata": {"Data": {"Git": {"file": path, "line": 1}}},
            }
        ],
    )
    outcome = reconcile(load_reports([report]), new_waiver_document(), today=TODAY, fail_on="high")
    sarif = build_sarif(outcome, catalog=load_catalog(), version="test")["runs"][0]
    result = sarif["results"][0]
    rule = sarif["tool"]["driver"]["rules"][result["ruleIndex"]]
    assert rule["properties"]["security-severity"] == "9.5"
    assert result["properties"]["resolvedSeverity"] == "critical"
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert unquote(uri) == path
    assert urlsplit(uri).fragment == urlsplit(uri).query == ""


def test_actions_are_pinned_and_runtime_has_no_input_interpolation():
    root = Path(secguard.__file__).resolve().parents[2]
    documents = [root / "action.yml", *sorted((root / ".github" / "workflows").glob("*.yml"))]
    for path in documents:
        text = path.read_text(encoding="utf-8")
        for action in re.findall(r"uses:\s*(\S+)", text):
            if action.startswith("./"):
                continue
            assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), (path.name, action)
    action = yaml.safe_load((root / "action.yml").read_text(encoding="utf-8"))
    assert all("${{ inputs." not in step.get("run", "") for step in action["runs"]["steps"])


@pytest.mark.skipif(sys.platform != "win32", reason="Windows directory junction")
def test_windows_junction_cannot_redirect_scaffold(tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    result = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(project / ".secguard"), str(outside)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, "junction creation failed in the Windows test environment"
    initialized = runner.invoke(app, ["init", str(project), "--ci", "none"])
    assert initialized.exit_code == 2
    assert not (outside / "waivers.yaml").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink/parent traversal")
def test_symlink_before_parent_component_cannot_redirect_output(tmp_path, monkeypatch):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    (outside / "nested").mkdir(parents=True)
    (project / "redirect").symlink_to(outside / "nested", target_is_directory=True)
    report = _report(project, [])
    monkeypatch.chdir(project)
    result = _scan(report, "--sarif", "redirect/../victim.sarif")
    assert result.exit_code == 2
    assert not (outside / "victim.sarif").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows literal tilde junction")
def test_literal_tilde_cannot_bypass_output_guard(tmp_path, monkeypatch):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    (project / "~").mkdir(parents=True)
    outside.mkdir()
    created = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(project / "~" / "redirect"), str(outside)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert created.returncode == 0
    report = _report(project, [])
    monkeypatch.chdir(project)
    result = _scan(report, "--sarif", "~/redirect/out.sarif")
    assert result.exit_code == 2
    assert not (outside / "out.sarif").exists()


@pytest.mark.parametrize("kind", ["report", "waiver", "catalog", "output"])
def test_filesystem_probe_errors_are_input_errors(tmp_path, monkeypatch, kind):
    report = _report(tmp_path, [])
    target = tmp_path / "policy.yaml" if kind in {"waiver", "catalog"} else report
    if kind == "output":
        target = tmp_path / "output.sarif"
    method = "is_symlink" if kind == "output" else "exists"
    original = getattr(Path, method)

    def denied(candidate, *args, **kwargs):
        if candidate == target:
            raise PermissionError(13, "Permission denied")
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, method, denied)
    if kind == "waiver":
        result = runner.invoke(app, ["waivers", "check", "--file", str(target)])
    elif kind == "catalog":
        result = _scan(report, "--rules", str(target))
    elif kind == "output":
        result = _scan(report, "--sarif", str(target))
    else:
        result = _scan(report)
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_sarif_path_is_a_portable_uri(tmp_path):
    path = "src/ação #key?%.py"
    report = _report(tmp_path, [{"RuleID": "x", "File": path}])
    outcome = reconcile(load_reports([report]), new_waiver_document(), today=TODAY, fail_on="high")
    result = build_sarif(outcome, catalog=load_catalog(), version="test")["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert unquote(uri) == path
    assert not urlsplit(uri).query and not urlsplit(uri).fragment


def test_four_wildcard_scope_finishes_without_backtracking():
    value = "a" * 400 + "!"
    started = time.perf_counter()
    assert not path_matches("*a*a*a*aZ", value)
    assert not rule_matches("*a*a*a*aZ", value)
    assert time.perf_counter() - started < 5.0


def test_long_literal_scopes_preserve_fast_matching():
    value = "a" * 8192
    started = time.perf_counter()
    assert path_matches(value, value)
    assert rule_matches(value + "*", value + "suffix")
    assert not path_matches(value, value + "x")
    assert time.perf_counter() - started < 1.0


@pytest.mark.parametrize(
    "report_format", ["auto", "gitleaks", "synthetic", "trufflehog", "detect-secrets"]
)
def test_oversized_reports_fail_before_parsing(tmp_path, monkeypatch, report_format):
    import secguard.core.findings as findings

    # A small test budget exercises the same bounded read without allocating 64 MiB.
    monkeypatch.setattr(findings, "MAX_REPORT_BYTES", 1024)
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * 1025)
    result = _scan(path, "--format", report_format)
    assert result.exit_code == 2
    assert "input limit" in result.output
    assert "PASS" not in result.output


def test_large_legitimate_report_preserves_every_finding(tmp_path):
    path = _report(
        tmp_path,
        [
            {"RuleID": "aws-access-token", "File": f"src/{i}.py", "StartLine": 1}
            for i in range(10000)
        ],
    )
    result = _scan(path, "--fail-on", "none")
    assert result.exit_code == 0
    assert "10000 finding(s)" in result.output
