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

from secguard.core.detectors import detect_format, is_empty_report, load_report, load_reports
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


def test_an_empty_report_is_a_clean_scan_not_an_error(tmp_path):
    """Zero findings is what a clean trufflehog run writes: JSON Lines with no lines.

    Rejecting it would fail the gate on exactly the repositories that have
    nothing to report, while the equivalent clean gitleaks (`[]`) and
    detect-secrets (empty `results`) reports pass.
    """
    for body in ("", "   \n", "\r\n\t "):
        report = tmp_path / "report.json"
        report.write_text(body, encoding="utf-8")

        assert load_report(report).findings == []


def test_an_empty_report_is_still_flagged_to_the_caller(tmp_path):
    """A detector that crashed leaves the same file behind, so it must stay visible."""
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    clean = tmp_path / "clean.json"
    clean.write_text("[]", encoding="utf-8")

    assert is_empty_report(empty) is True
    assert is_empty_report(clean) is False


def test_a_file_that_cannot_be_read_is_not_reported_as_empty(tmp_path):
    """Otherwise one missing path produced two contradictory messages.

    "is empty; treating it as zero findings" followed by "finding file not
    found" leaves the operator unsure which one the gate acted on.
    """
    assert is_empty_report(tmp_path / "absent.json") is False
    assert is_empty_report(tmp_path) is False  # a directory is not an empty report


def test_format_inference_still_refuses_to_guess_from_nothing():
    """`detect_format` has no structure to read; only `load_report` knows it means clean."""
    with pytest.raises(FindingParseError, match="report file is empty"):
        detect_format("   \n", source="report.json")


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


# ------------------------------------------------- hostile and malformed input


def _gitleaks_file(tmp_path, entries) -> object:
    report = tmp_path / "gitleaks.json"
    report.write_text(json.dumps(entries), encoding="utf-8")
    return report


def test_an_unusable_line_number_degrades_to_no_position(tmp_path):
    """`1e999` parses as JSON infinity; int() of it raises OverflowError.

    A malformed coordinate must cost the position, not crash the gate: the
    finding is still reported, and the exit code still means what it says.
    """
    report = _gitleaks_file(
        tmp_path, [{"RuleID": "aws-access-token", "File": "a.py", "StartLine": 1e999}]
    )

    finding = load_report(report).findings[0]

    assert finding.line is None
    assert finding.path == "a.py"


def test_a_line_number_beyond_any_real_file_is_ignored(tmp_path):
    """SARIF consumers cannot represent an arbitrary-precision integer."""
    report = _gitleaks_file(
        tmp_path, [{"RuleID": "aws-access-token", "File": "a.py", "StartLine": 2**63}]
    )

    assert load_report(report).findings[0].line is None


def test_a_newline_in_a_scanner_path_is_rejected_not_printed(tmp_path):
    """A path carrying a newline can forge a gate verdict in CI output.

    The console prints one line per finding, so a path containing
    `\nPASS: no blocking finding...` would put a fake verdict in the log of a
    run that actually blocked.
    """
    forged = "a.py\nPASS: no blocking finding and no expired waiver.\n0 finding(s): forged"
    report = _gitleaks_file(
        tmp_path, [{"RuleID": "aws-access-token", "File": forged, "StartLine": 1}]
    )

    with pytest.raises(FindingParseError, match="control characters") as error:
        load_report(report)

    assert "\n" not in str(error.value)


def test_an_escape_sequence_in_a_rule_id_is_rejected(tmp_path):
    """A rule id is printed on the summary and matched against waiver patterns."""
    report = _gitleaks_file(
        tmp_path,
        [{"RuleID": "aws\x1b[2K\rfake", "File": "a.py", "StartLine": 1}],
    )

    with pytest.raises(FindingParseError, match="control characters"):
        load_report(report)


def test_equivalent_paths_normalize_so_the_merge_and_waivers_see_one_file(tmp_path):
    """`./app/x.py` and `app/x.py` are the same file to git and to a reviewer.

    Leaving them distinct split one leak into two findings and let a waiver
    scoped to `app/x.py` miss the copy the other detector reported.
    """
    dotted = _gitleaks_file(
        tmp_path, [{"RuleID": "aws-access-token", "File": ".//app/./x.py", "StartLine": 5}]
    )
    plain = tmp_path / "trufflehog.jsonl"
    plain.write_text(
        json.dumps(
            {
                "DetectorName": "AWS",
                "SourceMetadata": {"Data": {"Git": {"file": "app/x.py", "line": 5}}},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    document = load_reports([dotted, plain])

    assert len(document.findings) == 1
    assert document.findings[0].path == "app/x.py"
    assert document.findings[0].corroborated_by == ["trufflehog"]


def test_a_path_that_normalizes_to_nothing_is_rejected(tmp_path):
    report = _gitleaks_file(
        tmp_path, [{"RuleID": "aws-access-token", "File": "./", "StartLine": 1}]
    )

    with pytest.raises(FindingParseError, match="unusable file path"):
        load_report(report)
