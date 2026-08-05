"""The redaction invariant: no secret material reaches any secguard output.

These tests are the reason the project exists. secguard reads reports that
contain live credentials; if a canonical document, a SARIF log, a Markdown
report, or a console line ever carried that material, the tool would spread the
leak it was built to contain.
"""

from __future__ import annotations

import json

import pytest
from conftest import ALL_REPORTS, FORBIDDEN_IN_OUTPUT, TODAY, assert_no_secret_material
from typer.testing import CliRunner

from secguard import __version__
from secguard.cli.app import app
from secguard.core.detectors import load_reports
from secguard.core.findings import Finding
from secguard.core.incident import render_incident
from secguard.core.playbooks import load_playbook
from secguard.core.reconcile import reconcile
from secguard.core.redaction import sanitize_text
from secguard.core.report import render_pr_comment, render_report
from secguard.core.sarif import build_sarif
from secguard.core.waivers import new_waiver_document

runner = CliRunner()


def test_fixtures_actually_contain_the_canary():
    """Guard the guard: a redaction test against clean input proves nothing."""
    raw = "\n".join(path.read_text(encoding="utf-8") for path in ALL_REPORTS)
    for forbidden in FORBIDDEN_IN_OUTPUT:
        assert forbidden in raw


def test_canonical_json_carries_no_secret_material(catalog):
    document = load_reports(ALL_REPORTS, catalog=catalog)
    assert document.findings
    assert_no_secret_material(json.dumps(document.model_dump(mode="json", by_alias=True)))


def test_sarif_carries_no_secret_material(catalog):
    outcome = reconcile(
        load_reports(ALL_REPORTS, catalog=catalog),
        new_waiver_document(),
        today=TODAY,
        fail_on="high",
    )
    sarif = build_sarif(outcome, catalog=catalog, version=__version__)
    assert_no_secret_material(json.dumps(sarif))


def test_markdown_outputs_carry_no_secret_material(catalog):
    outcome = reconcile(
        load_reports(ALL_REPORTS, catalog=catalog),
        new_waiver_document(),
        today=TODAY,
        fail_on="high",
    )
    assert_no_secret_material(render_report(outcome, generated_on=TODAY, version=__version__))
    assert_no_secret_material(render_pr_comment(outcome, generated_on=TODAY))


def test_cli_stdout_carries_no_secret_material():
    arguments = ["scan", "check", "--today", TODAY.isoformat(), "--fail-on", "none"]
    for path in ALL_REPORTS:
        arguments.extend(["--input", str(path)])

    result = runner.invoke(app, arguments)

    assert result.exit_code == 0
    assert_no_secret_material(result.output)


def test_incident_checklist_carries_no_secret_material():
    checklist = render_incident(
        load_playbook("aws-access-key"),
        secret_type="aws-access-key",
        opened_on=TODAY,
        leaked_via="github-issue",
    )
    assert_no_secret_material(checklist)


@pytest.mark.parametrize(
    "field",
    ["Secret", "Match", "Raw", "RawV2", "Redacted", "hashed_secret", "line_content"],
)
def test_canonical_model_has_no_field_that_could_hold_secret_material(field):
    """The model itself is the control: there is nowhere for a secret to land."""
    assert field not in Finding.model_fields


def test_sanitize_text_strips_control_characters_and_escapes():
    hostile = "line one\r\nline two\x1b[31mred\x00null"
    cleaned = sanitize_text(hostile)

    assert "\n" not in cleaned
    assert "\r" not in cleaned
    assert "\x1b" not in cleaned
    assert "\x00" not in cleaned
    assert cleaned == "line one line two red null"


def test_sanitize_text_truncates_long_values():
    cleaned = sanitize_text("a" * 500, max_length=32)

    assert len(cleaned) == 32
    assert cleaned.endswith("...")
