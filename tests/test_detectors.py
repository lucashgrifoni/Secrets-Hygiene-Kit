"""Scanner adapter parsing, format inference, and cross-scanner merge."""

from __future__ import annotations

import json

import pytest
from conftest import (
    ALL_REPORTS,
    DETECT_SECRETS_BASELINE,
    GITLEAKS_REPORT,
    SYNTHETIC_REPORT,
    TRUFFLEHOG_REPORT,
)

from secguard.core.detectors import detect_format, load_report, load_reports
from secguard.core.findings import FindingFileNotFound, FindingParseError


def _by_path(document, path: str):
    return next(finding for finding in document.findings if finding.path == path)


# ------------------------------------------------------------------- inference


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (GITLEAKS_REPORT, "gitleaks"),
        (TRUFFLEHOG_REPORT, "trufflehog"),
        (DETECT_SECRETS_BASELINE, "detect-secrets"),
        (SYNTHETIC_REPORT, "synthetic"),
    ],
)
def test_format_is_inferred_from_structure(path, expected):
    assert detect_format(path.read_text(encoding="utf-8"), source=path) == expected


def test_format_inference_ignores_the_file_name(tmp_path):
    """A report named gitleaks.json that holds a baseline must still parse correctly."""
    misleading = tmp_path / "gitleaks.json"
    misleading.write_text(DETECT_SECRETS_BASELINE.read_text(encoding="utf-8"), encoding="utf-8")

    assert detect_format(misleading.read_text(encoding="utf-8"), source=misleading) == (
        "detect-secrets"
    )


def test_unrecognized_payload_names_the_supported_formats(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"unrelated": true}', encoding="utf-8")

    with pytest.raises(FindingParseError, match="could not infer the scanner format"):
        load_report(report)


def test_empty_report_file_is_rejected(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("   \n", encoding="utf-8")

    with pytest.raises(FindingParseError, match="report file is empty"):
        load_report(report)


def test_missing_report_file_is_reported(tmp_path):
    with pytest.raises(FindingFileNotFound):
        load_report(tmp_path / "absent.json")


# -------------------------------------------------------------------- gitleaks


def test_gitleaks_report_is_normalized(catalog):
    document = load_report(GITLEAKS_REPORT, catalog=catalog)
    finding = _by_path(document, "src/example_config.py")

    assert len(document.findings) == 3
    assert finding.scanner == "gitleaks"
    assert finding.rule == "gitleaks:aws-access-token"
    assert finding.secret_type == "aws-access-key"
    assert finding.playbook == "aws-access-key"
    assert finding.mapping == "catalog"
    assert finding.severity == "high"
    assert finding.line == 12
    assert finding.column == 7
    assert finding.commit == "9f2c1ab7d3e45f6789012345678901234567abcd"
    assert finding.message == "AWS Access Token"


def test_unmapped_gitleaks_rule_falls_back_instead_of_guessing(catalog):
    document = load_report(GITLEAKS_REPORT, catalog=catalog)
    finding = _by_path(document, "services/api/settings.py")

    assert finding.rule == "gitleaks:acme-internal-token"
    assert finding.mapping == "fallback"
    assert finding.secret_type == "generic-api-key"
    assert finding.playbook == "generic-api-key"


def test_gitleaks_report_must_be_an_array(tmp_path):
    report = tmp_path / "gitleaks.json"
    report.write_text('{"RuleID": "aws-access-token"}', encoding="utf-8")

    with pytest.raises(FindingParseError):
        load_report(report, report_format="gitleaks")


def test_absolute_paths_are_rejected_with_actionable_guidance(tmp_path):
    report = tmp_path / "gitleaks.json"
    report.write_text(
        json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "File": "/home/runner/work/repo/src/config.py",
                    "StartLine": 3,
                    "Description": "AWS Access Token",
                }
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(FindingParseError) as exc_info:
        load_report(report, report_format="gitleaks")

    message = str(exc_info.value)
    assert "run the scanner from the repository root" in message
    assert "config.py" in message
    # The error names the file, never the absolute path that exposes the host layout.
    assert "/home/runner" not in message


# ------------------------------------------------------------------ trufflehog


def test_trufflehog_jsonl_is_normalized(catalog):
    document = load_report(TRUFFLEHOG_REPORT, catalog=catalog)
    finding = _by_path(document, "src/example_config.py")

    assert len(document.findings) == 2
    assert finding.scanner == "trufflehog"
    assert finding.rule == "trufflehog:AWS"
    assert finding.secret_type == "aws-access-key"
    assert finding.line == 12
    assert finding.commit == "9f2c1ab7d3e45f6789012345678901234567abcd"


def test_a_verified_credential_is_escalated_to_critical(catalog):
    """A detector that proved the credential is live outranks the catalog default."""
    document = load_report(TRUFFLEHOG_REPORT, catalog=catalog)
    finding = _by_path(document, "src/example_config.py")

    assert finding.verified is True
    assert finding.severity == "critical"


def test_unverified_trufflehog_finding_keeps_the_catalog_severity(catalog):
    document = load_report(TRUFFLEHOG_REPORT, catalog=catalog)
    finding = _by_path(document, "infra/db.tf")

    assert finding.verified is False
    assert finding.secret_type == "postgres-uri"
    assert finding.severity == "high"


def test_trufflehog_json_array_form_is_accepted(tmp_path, catalog):
    lines = TRUFFLEHOG_REPORT.read_text(encoding="utf-8").strip().splitlines()
    report = tmp_path / "trufflehog.json"
    report.write_text(json.dumps([json.loads(line) for line in lines]), encoding="utf-8")

    document = load_report(report, report_format="trufflehog", catalog=catalog)

    assert len(document.findings) == 2


# --------------------------------------------------------------- detect-secrets


def test_detect_secrets_baseline_is_normalized(catalog):
    document = load_report(DETECT_SECRETS_BASELINE, catalog=catalog)
    finding = _by_path(document, "src/example_config.py")

    assert len(document.findings) == 2
    assert finding.scanner == "detect-secrets"
    assert finding.rule == "detect-secrets:AWS Access Key"
    assert finding.secret_type == "aws-access-key"
    assert finding.line == 12


def test_high_entropy_plugin_is_downgraded_to_low(catalog):
    """Entropy heuristics are noisy, so the catalog gives them a lower default."""
    document = load_report(DETECT_SECRETS_BASELINE, catalog=catalog)
    finding = _by_path(document, "tests/fixtures/dummy_token.txt")

    assert finding.rule == "detect-secrets:Base64 High Entropy String"
    assert finding.severity == "low"


def test_baseline_without_results_yields_no_findings(tmp_path, catalog):
    report = tmp_path / ".secrets.baseline"
    report.write_text(
        json.dumps({"version": "1.5.0", "plugins_used": [], "results": {}}), encoding="utf-8"
    )

    document = load_report(report, catalog=catalog)

    assert document.findings == []


# ----------------------------------------------------------------------- merge


def test_the_same_leak_from_three_scanners_collapses_into_one_finding(catalog):
    document = load_reports(ALL_REPORTS, catalog=catalog)
    aws = [finding for finding in document.findings if finding.secret_type == "aws-access-key"]

    assert len(aws) == 1
    assert sorted([aws[0].scanner, *aws[0].corroborated_by]) == [
        "detect-secrets",
        "gitleaks",
        "trufflehog",
    ]


def test_merge_keeps_the_most_informative_finding_as_primary(catalog):
    """gitleaks carries a native fingerprint, a column, and a commit, so it wins."""
    document = load_reports(ALL_REPORTS, catalog=catalog)
    aws = next(f for f in document.findings if f.secret_type == "aws-access-key")

    assert aws.scanner == "gitleaks"
    assert aws.column == 7
    assert aws.fingerprint.startswith("gitleaks:")


def test_merge_takes_the_highest_severity_and_any_verification(catalog):
    document = load_reports(ALL_REPORTS, catalog=catalog)
    aws = next(f for f in document.findings if f.secret_type == "aws-access-key")

    assert aws.verified is True
    assert aws.severity == "critical"


def test_merged_document_is_sorted_by_descending_severity(catalog):
    document = load_reports(ALL_REPORTS, catalog=catalog)
    severities = [finding.severity for finding in document.findings]

    assert severities == ["critical", "high", "medium", "medium", "low"]


def test_merge_is_deterministic(catalog):
    first = load_reports(ALL_REPORTS, catalog=catalog)
    second = load_reports(list(reversed(ALL_REPORTS)), catalog=catalog)

    assert [f.id for f in first.findings] == [f.id for f in second.findings]


def test_load_reports_requires_at_least_one_input():
    with pytest.raises(FindingParseError, match="at least one scanner report"):
        load_reports([])
