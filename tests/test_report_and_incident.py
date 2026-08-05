"""Markdown report rendering and incident checklist generation."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from conftest import ALL_REPORTS, TODAY

from secguard import __version__
from secguard.core.detectors import load_reports
from secguard.core.findings import FindingDocument
from secguard.core.incident import render_incident
from secguard.core.playbooks import load_playbook
from secguard.core.reconcile import reconcile
from secguard.core.redaction import escape_markdown_cell
from secguard.core.report import render_pr_comment, render_report
from secguard.core.waivers import WaiverDocument, new_waiver_document

EXPIRED_WAIVER = {
    "id": "WV-2026-004",
    "rule": "secret-type:slack-webhook",
    "path": "docs/example.env",
    "reason": "Documented example webhook.",
    "owner": "appsec@example.invalid",
    "expires_at": "2026-07-01",
    "approver": "security-lead",
}

ACTIVE_WAIVER = {**EXPIRED_WAIVER, "id": "WV-2026-005", "expires_at": "2026-12-31"}


def _outcome(catalog, waivers=None, fail_on="high"):
    return reconcile(
        load_reports(ALL_REPORTS, catalog=catalog),
        waivers or new_waiver_document(),
        today=TODAY,
        fail_on=fail_on,
    )


def _waivers(*entries):
    return WaiverDocument.model_validate({"schema": "secguard.waiver/v1", "waivers": list(entries)})


# ------------------------------------------------------------------- reporting


def test_report_states_the_verdict_and_counts(catalog):
    markdown = render_report(_outcome(catalog), generated_on=TODAY, version=__version__)

    assert "# secguard scan report" in markdown
    assert "**BLOCK**" in markdown
    assert "5 total (5 active, 0 waived)" in markdown
    assert f"secguard version: {__version__}" in markdown


def test_report_says_plainly_what_the_tool_does_not_do(catalog):
    markdown = render_report(_outcome(catalog), generated_on=TODAY, version=__version__)

    assert "does not run detectors" in markdown
    assert "does not rotate or revoke" in markdown


def test_report_lists_playbooks_and_the_response_order(catalog):
    markdown = render_report(_outcome(catalog), generated_on=TODAY, version=__version__)

    assert "Invalidate first, rotate second, audit third." in markdown
    assert "secguard playbooks show aws-access-key" in markdown


def test_report_shows_corroborating_scanners_and_live_verification(catalog):
    markdown = render_report(_outcome(catalog), generated_on=TODAY, version=__version__)

    assert "gitleaks+detect-secrets+trufflehog" in markdown
    assert "**live**" in markdown


def test_report_separates_waived_findings_and_names_the_waiver(catalog):
    markdown = render_report(
        _outcome(catalog, _waivers(ACTIVE_WAIVER)), generated_on=TODAY, version=__version__
    )

    assert "## Waived findings (1)" in markdown
    assert "`WV-2026-005`" in markdown


def test_report_flags_expired_waivers_as_hygiene_debt(catalog):
    markdown = render_report(
        _outcome(catalog, _waivers(EXPIRED_WAIVER)), generated_on=TODAY, version=__version__
    )

    assert "## Waiver hygiene" in markdown
    assert "**1 expired waiver(s).**" in markdown
    assert "`WV-2026-004`" in markdown


def test_report_flags_waivers_that_match_nothing(catalog):
    unused = {**ACTIVE_WAIVER, "id": "WV-2026-006", "path": "src/deleted.py"}
    markdown = render_report(
        _outcome(catalog, _waivers(unused)), generated_on=TODAY, version=__version__
    )

    assert "matched no finding in this scan" in markdown


def test_report_handles_an_empty_scan():
    outcome = reconcile(FindingDocument(), new_waiver_document(), today=TODAY, fail_on="high")
    markdown = render_report(outcome, generated_on=TODAY, version=__version__)

    assert "No findings were reported by any input report." in markdown
    assert "**PASS**" in markdown


def test_a_hostile_scanner_message_cannot_break_out_of_a_table_cell():
    hostile = "value | injected | row\nnew line\x1b[31m"
    escaped = escape_markdown_cell(hostile)

    assert "\\|" in escaped
    assert "\n" not in escaped
    assert "\x1b" not in escaped


# ----------------------------------------------------------------- pr comments


def test_pr_comment_is_compact_and_actionable(catalog):
    comment = render_pr_comment(_outcome(catalog), generated_on=TODAY)

    assert comment.startswith("### secguard: BLOCK")
    assert "secguard incident start --secret-type aws-access-key" in comment
    assert "Never paste the credential into this thread." in comment
    assert len(comment.splitlines()) < 30


def test_pr_comment_reports_a_clean_scan(catalog):
    comment = render_pr_comment(_outcome(catalog, fail_on="none"), generated_on=TODAY)

    assert comment.startswith("### secguard: PASS")
    assert "No unwaived finding reached the threshold" in comment


def test_pr_comment_surfaces_expired_waivers(catalog):
    comment = render_pr_comment(
        _outcome(catalog, _waivers(EXPIRED_WAIVER), fail_on="none"), generated_on=TODAY
    )

    assert "**1 expired waiver(s)**" in comment
    assert "WV-2026-004" in comment


# -------------------------------------------------------------------- incident


def test_incident_checklist_carries_the_exposure_record():
    checklist = render_incident(
        load_playbook("aws-access-key"),
        secret_type="aws-access-key",
        opened_on=TODAY,
        leaked_via="github-issue",
        reference="INC-2026-42",
    )

    assert "# Incident checklist: AWS Access Key Leak Playbook" in checklist
    assert "- Secret type: `aws-access-key`" in checklist
    assert "- Leaked via: github-issue" in checklist
    assert "- Reference: INC-2026-42" in checklist
    assert f"- Opened: {TODAY.isoformat()}" in checklist


def test_incident_checklist_is_tickable_and_ends_with_close_out():
    checklist = render_incident(
        load_playbook("stripe-secret-key"), secret_type="stripe-secret-key", opened_on=TODAY
    )

    assert "- [ ] " in checklist
    assert "## Close-out record" in checklist
    assert "- [ ] Residual risk written down with an owner and a review date." in checklist


def test_incident_checklist_repeats_the_evidence_rule():
    checklist = render_incident(
        load_playbook("github-pat"), secret_type="github-pat", opened_on=TODAY
    )

    assert "Never copy the credential itself into tickets" in checklist


def test_a_stale_playbook_warns_the_responder():
    playbook = load_playbook("aws-access-key")
    stale_day = playbook.vetted + timedelta(days=400)

    checklist = render_incident(
        playbook, secret_type="aws-access-key", opened_on=stale_day, max_age_days=180
    )

    assert "Warning: this playbook was last vetted" in checklist
    assert "Confirm each provider step" in checklist


def test_a_fresh_playbook_does_not_warn():
    checklist = render_incident(
        load_playbook("aws-access-key"), secret_type="aws-access-key", opened_on=TODAY
    )

    assert "Warning: this playbook was last vetted" not in checklist


@pytest.mark.parametrize("hostile", ["a\nb", "x\x1b[31m", "p" * 500])
def test_incident_metadata_is_sanitized(hostile):
    checklist = render_incident(
        load_playbook("generic-api-key"),
        secret_type="generic-api-key",
        opened_on=date(2026, 8, 4),
        leaked_via=hostile,
    )
    leaked_line = next(line for line in checklist.splitlines() if line.startswith("- Leaked via:"))

    assert "\x1b" not in leaked_line
    assert len(leaked_line) <= len("- Leaked via: ") + 120
