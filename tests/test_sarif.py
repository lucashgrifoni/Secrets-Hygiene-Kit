"""SARIF 2.1.0 export shape and waiver suppression semantics."""

from __future__ import annotations

import pytest
from conftest import ALL_REPORTS, TODAY

from secguard import __version__
from secguard.core.detectors import load_reports
from secguard.core.reconcile import reconcile
from secguard.core.sarif import build_sarif
from secguard.core.waivers import WaiverDocument, new_waiver_document

WAIVER = {
    "id": "WV-2026-001",
    "rule": "secret-type:aws-access-key",
    "path": "src/example_config.py",
    "reason": "Intentional fixture, not a real credential.",
    "owner": "appsec@example.invalid",
    "expires_at": "2026-12-01",
    "approver": "security-lead",
}


@pytest.fixture
def outcome(catalog):
    return reconcile(
        load_reports(ALL_REPORTS, catalog=catalog),
        new_waiver_document(),
        today=TODAY,
        fail_on="high",
    )


@pytest.fixture
def sarif(outcome, catalog):
    return build_sarif(outcome, catalog=catalog, version=__version__)


def test_sarif_envelope(sarif):
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "secguard"
    assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__


def test_rules_are_keyed_by_canonical_secret_type_not_detector_rule(sarif):
    """One leak reported by three scanners must become one code-scanning alert."""
    rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]

    assert "aws-access-key" in rule_ids
    assert "gitleaks:aws-access-token" not in rule_ids
    assert len(rule_ids) == len(set(rule_ids))


def test_rule_index_points_at_the_matching_rule(sarif):
    driver = sarif["runs"][0]["tool"]["driver"]

    for result in sarif["runs"][0]["results"]:
        assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"]


def test_severity_maps_to_sarif_level_and_github_security_severity(sarif):
    rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    results = {result["ruleId"]: result for result in sarif["runs"][0]["results"]}

    assert results["aws-access-key"]["level"] == "error"
    assert rules["postgres-uri"]["properties"]["security-severity"] == "8.0"
    assert results["generic-api-key"]["level"] in {"warning", "note"}


def test_locations_and_fingerprints_are_present(sarif):
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "aws-access-key")
    location = result["locations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uri"] == "src/example_config.py"
    assert location["region"] == {"startLine": 12, "startColumn": 7}
    assert result["partialFingerprints"]["secguard/v1"].startswith("gitleaks:")


def test_result_properties_carry_triage_context(sarif):
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "aws-access-key")

    assert result["properties"]["playbook"] == "aws-access-key"
    assert result["properties"]["detectorRule"] == "gitleaks:aws-access-token"
    assert result["properties"]["verified"] is True
    assert sorted(result["properties"]["corroboratedBy"]) == ["detect-secrets", "trufflehog"]
    assert "verified this credential as live" in result["message"]["text"]


def test_a_fallback_mapping_says_so_in_the_message(sarif):
    result = next(
        r
        for r in sarif["runs"][0]["results"]
        if r["properties"]["detectorRule"] == "gitleaks:acme-internal-token"
    )

    assert result["properties"]["mapping"] == "fallback"
    assert "not in the secguard catalog" in result["message"]["text"]


def test_a_waived_finding_is_suppressed_not_dropped(catalog):
    """Dropping a waived finding hides the exception; suppressing shows it."""
    waivers = WaiverDocument.model_validate({"schema": "secguard.waiver/v1", "waivers": [WAIVER]})
    outcome = reconcile(
        load_reports(ALL_REPORTS, catalog=catalog),
        waivers,
        today=TODAY,
        fail_on="high",
    )
    sarif = build_sarif(outcome, catalog=catalog, version=__version__)

    aws = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "aws-access-key")
    assert aws["suppressions"] == [
        {"kind": "external", "justification": "secguard waiver WV-2026-001"}
    ]

    others = [r for r in sarif["runs"][0]["results"] if r["ruleId"] != "aws-access-key"]
    assert all("suppressions" not in result for result in others)


def test_an_empty_scan_produces_a_valid_empty_run(catalog):
    from secguard.core.findings import FindingDocument

    outcome = reconcile(FindingDocument(), new_waiver_document(), today=TODAY, fail_on="high")
    sarif = build_sarif(outcome, catalog=catalog, version=__version__)

    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
