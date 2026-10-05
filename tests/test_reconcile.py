"""Waiver reconciliation and the gate decision."""

from __future__ import annotations

from datetime import date

import pytest
from conftest import ALL_REPORTS, TODAY

from secguard.core.detectors import load_reports
from secguard.core.reconcile import reconcile
from secguard.core.waivers import WaiverDocument

SCHEMA = "secguard.waiver/v1"


def _waivers(*entries: dict) -> WaiverDocument:
    return WaiverDocument.model_validate({"schema": SCHEMA, "waivers": list(entries)})


def _waiver(**overrides) -> dict:
    base = {
        "id": "WV-2026-001",
        "rule": "gitleaks:aws-access-token",
        "path": "src/example_config.py",
        "reason": "Intentional fixture, not a real credential.",
        "owner": "appsec@example.invalid",
        "expires_at": "2026-12-01",
        "approver": "security-lead",
    }
    return {**base, **overrides}


@pytest.fixture
def findings(catalog):
    return load_reports(ALL_REPORTS, catalog=catalog)


def test_clean_scan_passes(findings):
    outcome = reconcile(findings, _waivers(), today=TODAY, fail_on="none")

    assert outcome.failed is False
    assert outcome.exit_code == 0
    assert len(outcome.active) == 5


def test_findings_at_or_above_the_threshold_block(findings):
    outcome = reconcile(findings, _waivers(), today=TODAY, fail_on="high")

    assert outcome.failed is True
    assert outcome.exit_code == 1
    assert {result.finding.severity for result in outcome.blocking} == {"critical", "high"}


def test_threshold_is_inclusive_and_ordered(findings):
    assert len(reconcile(findings, _waivers(), today=TODAY, fail_on="critical").blocking) == 1
    assert len(reconcile(findings, _waivers(), today=TODAY, fail_on="high").blocking) == 2
    assert len(reconcile(findings, _waivers(), today=TODAY, fail_on="medium").blocking) == 4
    assert len(reconcile(findings, _waivers(), today=TODAY, fail_on="info").blocking) == 5
    assert reconcile(findings, _waivers(), today=TODAY, fail_on="none").blocking == []


def test_an_active_waiver_suppresses_a_finding(findings):
    outcome = reconcile(
        findings,
        _waivers(_waiver(rule="secret-type:aws-access-key")),
        today=TODAY,
        fail_on="high",
    )

    waived = outcome.waived
    assert len(waived) == 1
    assert waived[0].finding.secret_type == "aws-access-key"
    assert waived[0].waiver_id == "WV-2026-001"
    assert len(outcome.blocking) == 1


def test_a_detector_scoped_waiver_cannot_suppress_another_detectors_detection(findings):
    """Adding a detector must never weaken the gate.

    The AWS finding in the fixtures is one leak that gitleaks, trufflehog, and
    detect-secrets all reported, merged into a single record whose `rule` is
    whichever detection won the primary rank. A waiver written for the gitleaks
    match alone was never reviewed against trufflehog's evidence — and that
    evidence is `Verified: true`, a credential proven live. Letting the gitleaks
    waiver carry the merged record through the gate would mean a second scanner
    confirming the leak is what silenced the alarm.
    """
    aws = next(f for f in findings.findings if f.secret_type == "aws-access-key")
    assert aws.rule == "gitleaks:aws-access-token"
    assert "trufflehog:AWS" in aws.corroborated_rules
    assert aws.verified is True

    outcome = reconcile(
        findings,
        _waivers(_waiver(rule="gitleaks:aws-access-token")),
        today=TODAY,
        fail_on="high",
    )

    assert outcome.waived == []
    assert outcome.failed is True
    assert outcome.exit_code == 1
    assert [w.id for w in outcome.unused_waivers] == ["WV-2026-001"]


def test_an_expired_waiver_does_not_suppress_and_fails_the_gate(findings):
    """The lifecycle fails closed: a stale exception stops protecting anything."""
    outcome = reconcile(
        findings,
        _waivers(_waiver(expires_at="2026-08-03")),
        today=TODAY,
        fail_on="none",
    )

    assert outcome.waived == []
    assert outcome.failed is True
    assert [waiver.id for waiver in outcome.expired_waivers] == ["WV-2026-001"]


def test_an_expired_waiver_is_named_on_the_finding_it_used_to_cover(findings):
    outcome = reconcile(
        findings,
        _waivers(_waiver(rule="secret-type:aws-access-key", expires_at="2026-08-03")),
        today=TODAY,
        fail_on="high",
    )
    aws = next(r for r in outcome.active if r.finding.secret_type == "aws-access-key")

    assert aws.expired_waiver_id == "WV-2026-001"


def test_a_waiver_expiring_today_is_still_active(findings):
    outcome = reconcile(
        findings,
        _waivers(_waiver(rule="secret-type:aws-access-key", expires_at=TODAY.isoformat())),
        today=TODAY,
        fail_on="high",
    )

    assert outcome.expired_waivers == []
    assert len(outcome.waived) == 1


def test_a_waiver_can_target_the_canonical_secret_type(findings):
    """Waiving by secret type survives a detector rule id rename."""
    outcome = reconcile(
        findings,
        _waivers(_waiver(rule="secret-type:aws-access-key")),
        today=TODAY,
        fail_on="high",
    )

    assert len(outcome.waived) == 1


def test_a_waiver_path_glob_scopes_to_a_directory(findings):
    outcome = reconcile(
        findings,
        _waivers(_waiver(rule="*", path="tests/**")),
        today=TODAY,
        fail_on="none",
    )

    assert [result.finding.path for result in outcome.waived] == ["tests/fixtures/dummy_token.txt"]


def test_a_waiver_for_the_wrong_scanner_does_not_apply(findings):
    """A trufflehog-only waiver covers none of the AWS finding's other detections."""
    outcome = reconcile(
        findings,
        _waivers(_waiver(rule="trufflehog:AWS")),
        today=TODAY,
        fail_on="high",
    )

    assert outcome.waived == []


def test_waivers_that_match_nothing_are_reported_as_unused(findings):
    outcome = reconcile(
        findings,
        _waivers(_waiver(id="WV-2026-009", path="src/gone.py")),
        today=TODAY,
        fail_on="none",
    )

    assert [waiver.id for waiver in outcome.unused_waivers] == ["WV-2026-009"]
    assert outcome.failed is False


def test_summaries_group_by_severity_and_secret_type(findings):
    outcome = reconcile(findings, _waivers(), today=TODAY, fail_on="high")

    assert outcome.severity_counts("active") == {
        "critical": 1,
        "high": 1,
        "medium": 2,
        "low": 1,
    }
    assert outcome.secret_type_counts()["generic-api-key"] == 2
    assert "aws-access-key" in outcome.playbooks()


def test_an_unknown_threshold_is_rejected(findings):
    with pytest.raises(ValueError, match="fail_on must be one of"):
        reconcile(findings, _waivers(), today=date(2026, 8, 4), fail_on="urgent")
