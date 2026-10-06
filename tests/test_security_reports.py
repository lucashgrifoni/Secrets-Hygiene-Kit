"""A green upload must not conceal findings, collection failures or missing coverage."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_security_reports import (
    SCORECARD_MINIMUMS,
    check_sarif,
    check_scorecard,
    check_trivy_dependencies,
    sanitize_trivy_secrets,
)

ROOT = Path(__file__).resolve().parents[1]


def sarif(score="8.8", level="warning"):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {"id": "py/security-test", "properties": {"security-severity": score}}
                        ],
                    }
                },
                "results": [{"ruleId": "py/security-test", "level": level}],
            }
        ],
    }


@pytest.mark.parametrize("score", ["4.0", "6.9", "7.0", "9.0", "10.0"])
def test_sarif_blocks_medium_and_above_even_when_the_upload_succeeded(score):
    assert check_sarif(sarif(score), "CodeQL") == 1


def test_sarif_does_not_allow_baselining_or_suppression_to_hide_a_finding():
    report = sarif()
    report["runs"][0]["results"][0].update(
        baselineState="unchanged", suppressions=[{"status": "accepted", "kind": "external"}]
    )
    assert check_sarif(report, "CodeQL") == 1


def test_sarif_low_remains_reported_below_the_documented_threshold():
    assert check_sarif(sarif("3.9"), "CodeQL") == 0


@pytest.mark.parametrize("score", ["NaN", "inf", "-1", "11", "not-a-score"])
def test_sarif_rejects_invalid_scores(score):
    with pytest.raises(ValueError):
        check_sarif(sarif(score), "CodeQL")


@pytest.mark.parametrize("change", ["no-runs", "no-rules", "no-results", "wrong-tool", "failed"])
def test_sarif_cannot_pass_without_a_successful_analysis(change):
    report = sarif()
    if change == "no-runs":
        report["runs"] = []
    elif change == "no-rules":
        report["runs"][0]["tool"]["driver"]["rules"] = []
    elif change == "no-results":
        del report["runs"][0]["results"]
    elif change == "wrong-tool":
        report["runs"][0]["tool"]["driver"]["name"] = "another-tool"
    else:
        report["runs"][0]["invocations"] = [{"executionSuccessful": False}]
    with pytest.raises(ValueError):
        check_sarif(report, "CodeQL")


def test_unknown_unscored_warning_is_blocking():
    report = sarif()
    del report["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    assert check_sarif(report, "CodeQL") == 1


def test_zizmor_omits_rule_descriptors_in_its_successful_clean_report():
    report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "zizmor"}},
                "invocations": [{"executionSuccessful": True}],
                "results": [],
            }
        ],
    }
    assert check_sarif(report, "zizmor") == 0
    report["runs"][0]["results"] = [{"ruleId": "dangerous-workflow", "level": "error"}]
    assert check_sarif(report, "zizmor") == 1
    report["runs"][0]["invocations"] = []
    with pytest.raises(ValueError):
        check_sarif(report, "zizmor")


@pytest.mark.parametrize("report", [{"Results": []}, {"Results": [{"Packages": []}]}, {}])
def test_dependency_scan_cannot_pass_with_an_empty_inventory(report):
    with pytest.raises(ValueError):
        check_trivy_dependencies(report)


@pytest.mark.parametrize("severity", ["MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"])
def test_dependency_gate_blocks_unfixed_findings_too(severity):
    report = {
        "Results": [
            {
                "Packages": [{"Name": "example", "Version": "1.0"}],
                "Vulnerabilities": [{"Severity": severity, "FixedVersion": ""}],
            }
        ]
    }
    assert check_trivy_dependencies(report) == 1


def test_secret_artifact_carries_counts_and_rules_without_credentials_or_snippets():
    sensitive = "synthetic-value-not-a-provider-credential"
    report = {
        "Results": [
            {
                "Target": sensitive,
                "Secrets": [
                    {
                        "RuleID": "generic",
                        "Severity": "HIGH",
                        "Match": sensitive,
                        "Code": {"Lines": [{"Content": sensitive}]},
                    }
                ],
            }
        ]
    }
    report.update(SchemaVersion=2, ArtifactType="filesystem", ArtifactName=".")
    summary = sanitize_trivy_secrets(report, 1)
    assert summary["verdict"] == "BLOCK"
    assert summary["blocking_count"] == 1
    assert sensitive not in json.dumps(summary)


def test_secret_scan_error_with_zero_findings_cannot_pass():
    assert (
        sanitize_trivy_secrets(
            {"SchemaVersion": 2, "ArtifactType": "filesystem", "ArtifactName": ".", "Results": []},
            2,
        )["verdict"]
        == "BLOCK"
    )


def test_clean_valid_secret_scan_passes():
    assert (
        sanitize_trivy_secrets(
            {"SchemaVersion": 2, "ArtifactType": "filesystem", "ArtifactName": ".", "Results": []},
            0,
        )["verdict"]
        == "PASS"
    )


def test_scorecard_requires_every_selected_check_to_be_present_and_pass():
    report = {"checks": [{"name": name, "score": 10} for name in SCORECARD_MINIMUMS]}
    assert check_scorecard(report) == 0
    failed = copy.deepcopy(report)
    failed["checks"][0]["score"] = 9
    assert check_scorecard(failed) == 1
    missing = copy.deepcopy(report)
    missing["checks"].pop()
    with pytest.raises(ValueError):
        check_scorecard(missing)


@pytest.mark.parametrize("score", [-1, None, 11])
def test_scorecard_unknown_or_error_score_is_not_a_pass(score):
    report = {"checks": [{"name": name, "score": score} for name in SCORECARD_MINIMUMS]}
    with pytest.raises(ValueError):
        check_scorecard(report)


@pytest.mark.parametrize("content", ["not-json", "[]", "{}", '{"version":"2.1.0","runs":[]}'])
def test_report_command_fails_closed_without_printing_raw_data(content, tmp_path):
    report = tmp_path / "report.json"
    report.write_text(content, encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check_security_reports.py"),
            "sarif",
            str(report),
            "--tool",
            "CodeQL",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "ERROR" in result.stdout
    assert content not in result.stdout


@pytest.mark.parametrize(
    "file,gate",
    [("security-ci-cd.yml", "security-checks"), ("scorecard.yml", "scorecard-checks")],
)
@pytest.mark.parametrize("status", ["failure", "cancelled", "skipped", "unknown"])
def test_actual_aggregate_script_rejects_each_failed_scanner(file, gate, status, tmp_path):
    import os

    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows" / file).read_text(encoding="utf-8"))
    job = workflow["jobs"][gate]
    body = job["steps"][0]["run"]
    script = body.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    results = {name: {"result": "success"} for name in job["needs"]}
    if file == "security-ci-cd.yml":
        results["dependency-review"]["result"] = "skipped"
        scanners = ("semgrep", "codeql", "dependencies", "workflows", "secrets")
    else:
        scanners = ("analyze", "policy")
    environment = {
        **os.environ,
        "RESULTS": json.dumps(results),
        "EVENT_NAME": "push",
        "REF": "refs/heads/main",
        "REPOSITORY": "lucashgrifoni/secrets-hygiene-kit",
        "PR_HEAD_REPOSITORY": "",
        "PR_AUTHOR": "",
        "ACTOR": "lucashgrifoni",
    }
    clean = subprocess.run(
        [sys.executable, "-c", script],
        env=environment,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert clean.returncode == 0, clean.stderr
    for scanner in scanners:
        broken = copy.deepcopy(results)
        broken[scanner]["result"] = status
        failed = subprocess.run(
            [sys.executable, "-c", script],
            env={**environment, "RESULTS": json.dumps(broken)},
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert failed.returncode != 0, f"{scanner} {status} was incorrectly accepted"


@pytest.mark.parametrize(
    "file,gate",
    [("security-ci-cd.yml", "security-checks"), ("scorecard.yml", "scorecard-checks")],
)
def test_fork_pr_runs_all_scanners_without_requiring_a_write_token(file, gate, tmp_path):
    import os

    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows" / file).read_text(encoding="utf-8"))
    job = workflow["jobs"][gate]
    script = job["steps"][0]["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    results = {name: {"result": "success"} for name in job["needs"]}
    results["publish"]["result"] = "skipped"
    result = subprocess.run(
        [sys.executable, "-c", script],
        env={
            **os.environ,
            "RESULTS": json.dumps(results),
            "EVENT_NAME": "pull_request",
            "REF": "refs/pull/1/merge",
            "REPOSITORY": "lucashgrifoni/secrets-hygiene-kit",
            "PR_HEAD_REPOSITORY": "contributor/secrets-hygiene-kit",
            "PR_AUTHOR": "contributor",
            "ACTOR": "contributor",
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_license_policy_checks_the_approved_apache_text_even_when_scorecard_is_offline():
    import hashlib
    import tomllib

    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert (
        hashlib.sha256(text.encode()).hexdigest()
        == "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
    )
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["license"] == "Apache-2.0"


def test_codeql_rule_descriptors_in_extensions_still_block_medium_findings():
    report = sarif("4.0")
    driver = report["runs"][0]["tool"]["driver"]
    rules = driver.pop("rules")
    report["runs"][0]["tool"]["extensions"] = [{"name": "codeql/python-queries", "rules": rules}]
    report["runs"][0]["results"] = [
        {
            "ruleId": "py/security-test",
            "rule": {"id": "py/security-test", "index": 0, "toolComponent": {"index": 0}},
        }
    ]
    assert check_sarif(report, "CodeQL") == 1


def test_secret_gate_console_has_only_a_fixed_verdict_and_artifact_retains_counts(tmp_path):
    report = tmp_path / "secret-report.json"
    output = tmp_path / "counts.json"
    report.write_text(
        json.dumps({"SchemaVersion": 2, "ArtifactType": "filesystem", "ArtifactName": "."}),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check_security_reports.py"),
            "trivy-secrets",
            str(report),
            "--scanner-status",
            "0",
            "--sanitized-output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "trivy-secrets: PASS"
    assert json.loads(output.read_text())["finding_count"] == 0


@pytest.mark.parametrize("results", [None, []])
def test_trivy_clean_report_may_omit_results_but_must_keep_producer_metadata(results):
    report = {"SchemaVersion": 2, "ArtifactType": "filesystem", "ArtifactName": "."}
    if results is not None:
        report["Results"] = results
    assert sanitize_trivy_secrets(report, 0)["verdict"] == "PASS"
    assert sanitize_trivy_secrets(report, 2)["verdict"] == "BLOCK"


@pytest.mark.parametrize("report", [{}, {"Results": []}, {"SchemaVersion": 2}])
def test_incomplete_trivy_document_is_not_a_clean_scan(report):
    with pytest.raises(ValueError):
        sanitize_trivy_secrets(report, 0)
