"""CLI behaviour and the exit-code contract CI depends on."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from conftest import (
    ALL_REPORTS,
    DETECT_SECRETS_BASELINE,
    GITLEAKS_REPORT,
    SYNTHETIC_REPORT,
    TODAY,
)
from typer.testing import CliRunner

from secguard import __version__
from secguard.cli.app import app

runner = CliRunner()
FIXTURE_FILE = SYNTHETIC_REPORT

WAIVER_HEADER = 'schema: "secguard.waiver/v1"\n'

ACTIVE_WAIVER_FILE = """
schema: "secguard.waiver/v1"
waivers:
  - id: WV-2026-001
    rule: gitleaks:aws-access-key
    path: tests/fixtures/aws_key_dummy.py
    reason: "Intentional fixture, not a real credential."
    owner: appsec@example.invalid
    expires_at: 2026-08-12
    approver: security-lead
"""


def _scan_arguments(*extra: str, reports=ALL_REPORTS) -> list[str]:
    arguments = ["scan", "check", "--today", TODAY.isoformat()]
    for path in reports:
        arguments.extend(["--input", str(path)])
    arguments.extend(extra)
    return arguments


# ------------------------------------------------------------------- version


def test_version_matches_the_package():
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


# ------------------------------------------------------------------- waivers


def test_waivers_check_succeeds_when_all_waivers_are_active(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(ACTIVE_WAIVER_FILE, encoding="utf-8")

    result = runner.invoke(
        app,
        ["waivers", "check", "--file", str(waiver_file), "--today", "2026-05-18"],
    )

    assert result.exit_code == 0
    assert "All 1 waiver(s) are active" in result.stdout


def test_waivers_check_fails_when_a_waiver_is_expired(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(ACTIVE_WAIVER_FILE.replace("2026-08-12", "2026-05-17"), encoding="utf-8")

    result = runner.invoke(
        app,
        ["waivers", "check", "--file", str(waiver_file), "--today", "2026-05-18"],
    )

    assert result.exit_code == 1
    assert "expired waiver(s)" in result.stdout
    assert "WV-2026-001" in result.stdout


def test_waivers_check_on_a_missing_file_is_an_input_error(tmp_path):
    result = runner.invoke(app, ["waivers", "check", "--file", str(tmp_path / "absent.yaml")])

    assert result.exit_code == 2


def test_waivers_list_prints_metadata_without_reason(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        ACTIVE_WAIVER_FILE.replace(
            "Intentional fixture, not a real credential.",
            "Sensitive explanation that should not be listed by default.",
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["waivers", "list", "--file", str(waiver_file), "--today", "2026-05-18"],
    )

    assert result.exit_code == 0
    assert "WV-2026-001" in result.stdout
    assert "Sensitive explanation" not in result.stdout


def test_waivers_add_creates_the_file_and_generates_an_id(tmp_path):
    waiver_file = tmp_path / ".secguard" / "waivers.yaml"

    result = runner.invoke(
        app,
        [
            "waivers",
            "add",
            "--file",
            str(waiver_file),
            "--rule",
            "gitleaks:aws-access-token",
            "--path",
            "tests/fixtures/dummy.py",
            "--reason",
            "Intentional detector fixture.",
            "--owner",
            "appsec@example.invalid",
            "--approver",
            "security-lead",
            "--expires",
            "2026-09-01",
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 0
    assert "added\tWV-2026-001" in result.stdout

    document = yaml.safe_load(waiver_file.read_text(encoding="utf-8"))
    assert document["schema"] == "secguard.waiver/v1"
    assert document["waivers"][0]["id"] == "WV-2026-001"
    assert "Do not store secret values" in waiver_file.read_text(encoding="utf-8")


def test_waivers_add_assigns_sequential_ids(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    common = [
        "--file",
        str(waiver_file),
        "--rule",
        "gitleaks:aws-access-token",
        "--reason",
        "Intentional detector fixture.",
        "--owner",
        "appsec@example.invalid",
        "--approver",
        "security-lead",
        "--expires",
        "2026-09-01",
        "--today",
        TODAY.isoformat(),
    ]

    runner.invoke(app, ["waivers", "add", *common, "--path", "a.py"])
    result = runner.invoke(app, ["waivers", "add", *common, "--path", "b.py"])

    assert result.exit_code == 0
    assert "added\tWV-2026-002" in result.stdout


def test_waivers_add_rejects_an_expiry_in_the_past(tmp_path):
    result = runner.invoke(
        app,
        [
            "waivers",
            "add",
            "--file",
            str(tmp_path / "waivers.yaml"),
            "--rule",
            "gitleaks:aws-access-token",
            "--path",
            "a.py",
            "--reason",
            "Intentional detector fixture.",
            "--owner",
            "appsec@example.invalid",
            "--approver",
            "security-lead",
            "--expires",
            "2026-08-03",
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 2
    assert "already in the past" in result.output
    assert not (tmp_path / "waivers.yaml").exists()


def test_waivers_add_caps_the_expiry_horizon(tmp_path):
    """An exception that outlives its approval is a silent permanent acceptance."""
    result = runner.invoke(
        app,
        [
            "waivers",
            "add",
            "--file",
            str(tmp_path / "waivers.yaml"),
            "--rule",
            "gitleaks:aws-access-token",
            "--path",
            "a.py",
            "--reason",
            "Intentional detector fixture.",
            "--owner",
            "appsec@example.invalid",
            "--approver",
            "security-lead",
            "--expires",
            "2030-01-01",
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 2
    assert "caps new waivers at 365 days" in result.output


def test_waivers_add_dry_run_validates_without_writing(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"

    result = runner.invoke(
        app,
        [
            "waivers",
            "add",
            "--file",
            str(waiver_file),
            "--rule",
            "gitleaks:aws-access-token",
            "--path",
            "a.py",
            "--reason",
            "Intentional detector fixture.",
            "--owner",
            "appsec@example.invalid",
            "--approver",
            "security-lead",
            "--expires",
            "2026-11-01",
            "--today",
            TODAY.isoformat(),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "would-add\tWV-2026-001" in result.stdout
    assert "warning: expiry is 89 days away" not in result.output
    assert not waiver_file.exists()


def test_waivers_add_warns_on_a_long_but_allowed_horizon(tmp_path):
    result = runner.invoke(
        app,
        [
            "waivers",
            "add",
            "--file",
            str(tmp_path / "waivers.yaml"),
            "--rule",
            "gitleaks:aws-access-token",
            "--path",
            "a.py",
            "--reason",
            "Intentional detector fixture.",
            "--owner",
            "appsec@example.invalid",
            "--approver",
            "security-lead",
            "--expires",
            "2027-01-01",
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 0
    assert "recommended horizon is 90 days" in result.output


def test_a_waiver_written_by_add_is_readable_by_check(tmp_path):
    """Round trip: the writer and the reader must agree on the schema."""
    waiver_file = tmp_path / "waivers.yaml"
    runner.invoke(
        app,
        [
            "waivers",
            "add",
            "--file",
            str(waiver_file),
            "--rule",
            "gitleaks:aws-access-token",
            "--path",
            "a.py",
            "--reason",
            "Intentional detector fixture.",
            "--owner",
            "appsec@example.invalid",
            "--approver",
            "security-lead",
            "--expires",
            "2026-09-01",
            "--today",
            TODAY.isoformat(),
        ],
    )

    result = runner.invoke(
        app, ["waivers", "check", "--file", str(waiver_file), "--today", TODAY.isoformat()]
    )

    assert result.exit_code == 0


# ---------------------------------------------------------------------- init


def test_init_creates_starter_files_in_destination(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path)])

    assert result.exit_code == 0
    assert "created\t.secguard/waivers.yaml" in result.stdout
    assert (tmp_path / ".secguard" / "waivers.yaml").exists()
    assert (tmp_path / ".pre-commit-config.yaml").exists()
    assert (tmp_path / ".github" / "workflows" / "secguard.yml").exists()


def test_init_dry_run_does_not_create_files(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path), "--dry-run"])

    assert result.exit_code == 0
    assert "would-create\t.secguard/waivers.yaml" in result.stdout
    assert not (tmp_path / ".secguard").exists()


def test_init_skips_existing_files_without_force(tmp_path):
    pre_commit_file = tmp_path / ".pre-commit-config.yaml"
    pre_commit_file.write_text("existing config\n", encoding="utf-8")

    result = runner.invoke(app, ["init", str(tmp_path)])

    assert result.exit_code == 0
    assert "skipped\t.pre-commit-config.yaml" in result.stdout
    assert pre_commit_file.read_text(encoding="utf-8") == "existing config\n"


def test_init_force_overwrites_existing_files(tmp_path):
    pre_commit_file = tmp_path / ".pre-commit-config.yaml"
    pre_commit_file.write_text("existing config\n", encoding="utf-8")

    result = runner.invoke(app, ["init", str(tmp_path), "--force"])

    assert result.exit_code == 0
    assert "overwritten\t.pre-commit-config.yaml" in result.stdout
    assert "secguard waivers check" in pre_commit_file.read_text(encoding="utf-8")


def test_init_can_target_gitlab_instead_of_github(tmp_path):
    """secguard writes an includable snippet rather than clobbering .gitlab-ci.yml."""
    result = runner.invoke(app, ["init", str(tmp_path), "--ci", "gitlab"])

    assert result.exit_code == 0
    assert (tmp_path / ".gitlab" / "secguard.gitlab-ci.yml").exists()
    assert not (tmp_path / ".github").exists()
    assert not (tmp_path / ".gitlab-ci.yml").exists()


def test_init_can_skip_ci_entirely(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path), "--ci", "none"])

    assert result.exit_code == 0
    assert (tmp_path / ".secguard" / "waivers.yaml").exists()
    assert not (tmp_path / ".github").exists()
    assert not (tmp_path / ".gitlab").exists()


def test_generated_waiver_file_passes_its_own_check(tmp_path):
    """The starter files must not fail the gate they install."""
    runner.invoke(app, ["init", str(tmp_path)])

    result = runner.invoke(
        app,
        ["waivers", "check", "--file", str(tmp_path / ".secguard" / "waivers.yaml")],
    )

    assert result.exit_code == 0


# ---------------------------------------------------------------------- scan


def test_scan_normalize_outputs_canonical_findings_without_secret_values():
    result = runner.invoke(app, ["scan", "normalize", "--input", str(FIXTURE_FILE)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema"] == "secguard.findings/v1"
    assert payload["findings"][0]["rule"] == "gitleaks:aws-access-key"
    assert payload["findings"][0]["path"] == "src/example_config.py"
    assert "synthetic-placeholder-value" not in result.stdout


def test_scan_normalize_can_write_to_a_file(tmp_path):
    output = tmp_path / "nested" / "findings.json"

    result = runner.invoke(
        app,
        ["scan", "normalize", "--input", str(GITLEAKS_REPORT), "--output", str(output)],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert len(payload["findings"]) == 3


def test_scan_normalize_honors_an_explicit_format():
    result = runner.invoke(
        app,
        ["scan", "normalize", "--input", str(DETECT_SECRETS_BASELINE), "--format", "gitleaks"],
    )

    assert result.exit_code == 2
    assert "must be a JSON array" in result.output


def test_scan_check_blocks_on_findings_at_the_threshold():
    result = runner.invoke(app, _scan_arguments("--fail-on", "high"))

    assert result.exit_code == 1
    assert "BLOCK: 2 finding(s) at or above high" in result.output
    assert "critical\taws-access-key\tsrc/example_config.py:12" in result.output


def test_scan_check_passes_below_the_threshold():
    result = runner.invoke(app, _scan_arguments("--fail-on", "none"))

    assert result.exit_code == 0
    assert "PASS: no blocking finding and no expired waiver." in result.output


def test_scan_check_reports_the_playbook_for_each_finding():
    result = runner.invoke(app, _scan_arguments("--fail-on", "none"))

    assert "playbook=aws-access-key" in result.output
    assert "playbook=postgres-uri" in result.output


def test_scan_check_marks_a_live_credential():
    result = runner.invoke(app, _scan_arguments("--fail-on", "none"))

    assert "verified=live" in result.output


def test_scan_check_writes_every_requested_artifact(tmp_path):
    result = runner.invoke(
        app,
        _scan_arguments(
            "--fail-on",
            "none",
            "--json",
            str(tmp_path / "findings.json"),
            "--sarif",
            str(tmp_path / "out.sarif"),
            "--markdown",
            str(tmp_path / "report.md"),
            "--pr-comment",
            str(tmp_path / "comment.md"),
        ),
    )

    assert result.exit_code == 0
    assert json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert (tmp_path / "report.md").read_text(encoding="utf-8").startswith("# secguard scan")
    assert (tmp_path / "comment.md").read_text(encoding="utf-8").startswith("### secguard:")

    findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert len(findings["findings"]) == 5


def test_scan_check_fails_on_an_expired_waiver_even_with_no_blocking_finding(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        WAIVER_HEADER + "waivers:\n"
        "  - id: WV-2026-001\n"
        "    rule: gitleaks:aws-access-token\n"
        "    path: src/gone.py\n"
        '    reason: "Removed long ago."\n'
        "    owner: appsec@example.invalid\n"
        "    expires_at: 2026-01-01\n"
        "    approver: security-lead\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, _scan_arguments("--fail-on", "none", "--waivers", str(waiver_file)))

    assert result.exit_code == 1
    assert "BLOCK: 1 expired waiver(s)" in result.output


def test_scan_check_suppresses_a_waived_finding(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        WAIVER_HEADER + "waivers:\n"
        "  - id: WV-2026-001\n"
        "    rule: secret-type:aws-access-key\n"
        "    path: src/example_config.py\n"
        '    reason: "Reviewed placeholder in an example file."\n'
        "    owner: appsec@example.invalid\n"
        "    expires_at: 2026-12-01\n"
        "    approver: security-lead\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app, _scan_arguments("--fail-on", "critical", "--waivers", str(waiver_file))
    )

    assert result.exit_code == 0
    assert "4 active, 1 waived" in result.output


def test_scan_check_without_input_is_an_input_error():
    result = runner.invoke(app, ["scan", "check"])

    assert result.exit_code == 2
    assert "at least one --input scanner report is required" in result.output


def test_scan_check_rejects_an_unknown_threshold():
    result = runner.invoke(app, _scan_arguments("--fail-on", "urgent"))

    assert result.exit_code == 2


def test_scan_check_notes_a_missing_waiver_file_without_failing(tmp_path):
    result = runner.invoke(
        app, _scan_arguments("--fail-on", "none", "--waivers", str(tmp_path / "absent.yaml"))
    )

    assert result.exit_code == 0
    assert "continuing with zero waivers" in result.output


def test_scan_check_applies_a_local_rule_override(tmp_path):
    override = tmp_path / "rules.yaml"
    override.write_text(
        "detectors:\n  gitleaks:\n    acme-internal-token: stripe-secret-key\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        _scan_arguments("--fail-on", "none", "--rules", str(override), reports=[GITLEAKS_REPORT]),
    )

    assert result.exit_code == 0
    assert "critical\tstripe-secret-key\tservices/api/settings.py:88" in result.output


# -------------------------------------------------------------------- report


def test_report_renders_markdown_to_stdout_without_gating():
    arguments = ["report", "--today", TODAY.isoformat()]
    for path in ALL_REPORTS:
        arguments.extend(["--input", str(path)])

    result = runner.invoke(app, arguments)

    assert result.exit_code == 0
    assert result.stdout.startswith("# secguard scan report")


def test_report_can_write_to_a_file(tmp_path):
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "report",
            "--input",
            str(GITLEAKS_REPORT),
            "--output",
            str(output),
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 0
    assert "# secguard scan report" in output.read_text(encoding="utf-8")


# ----------------------------------------------------------------- playbooks


def test_playbooks_list_shows_freshness():
    result = runner.invoke(app, ["playbooks", "list", "--today", TODAY.isoformat()])

    assert result.exit_code == 0
    assert "aws-access-key\tfresh\tvetted=" in result.stdout
    assert len(result.stdout.strip().splitlines()) == 13


def test_playbooks_show_prints_the_playbook():
    result = runner.invoke(app, ["playbooks", "show", "stripe-secret-key"])

    assert result.exit_code == 0
    assert "# Stripe Secret Key Leak Playbook" in result.stdout
    assert "## Invalidate" in result.stdout


def test_playbooks_show_rejects_an_unknown_slug():
    result = runner.invoke(app, ["playbooks", "show", "not-a-playbook"])

    assert result.exit_code == 2
    assert "available playbooks:" in result.output


def test_playbooks_check_passes_inside_the_review_window():
    result = runner.invoke(app, ["playbooks", "check", "--today", TODAY.isoformat()])

    assert result.exit_code == 0
    assert "were vetted within 180 days" in result.stdout


def test_playbooks_check_fails_once_guidance_goes_stale():
    result = runner.invoke(app, ["playbooks", "check", "--today", "2030-01-01"])

    assert result.exit_code == 1
    assert "exceeded the 180-day review window" in result.stdout


# ------------------------------------------------------------------ incident


def test_incident_start_prints_a_checklist_for_a_secret_type():
    result = runner.invoke(
        app,
        [
            "incident",
            "start",
            "--secret-type",
            "aws-access-key",
            "--leaked-via",
            "public-github-issue",
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 0
    assert "# Incident checklist: AWS Access Key Leak Playbook" in result.stdout
    assert "- Leaked via: public-github-issue" in result.stdout
    assert "- [ ] " in result.stdout


def test_incident_start_can_write_to_a_file(tmp_path):
    output = tmp_path / "incident.md"
    result = runner.invoke(
        app,
        ["incident", "start", "--secret-type", "stripe-secret-key", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert "## Close-out record" in output.read_text(encoding="utf-8")


def test_incident_start_rejects_an_unknown_secret_type():
    result = runner.invoke(app, ["incident", "start", "--secret-type", "not-a-type"])

    assert result.exit_code == 2
    assert "known secret types:" in result.output


def test_incident_start_requires_a_target():
    result = runner.invoke(app, ["incident", "start"])

    assert result.exit_code == 2
    assert "provide --secret-type or --playbook" in result.output


def test_every_secret_type_in_the_catalog_can_start_an_incident(catalog):
    """No routing dead ends: every classification leads to a usable checklist."""
    for secret_type in catalog.secret_types:
        result = runner.invoke(app, ["incident", "start", "--secret-type", secret_type])

        assert result.exit_code == 0, f"{secret_type} could not start an incident"
        assert "## Close-out record" in result.stdout


# ------------------------------------------------------------------- safety


def test_output_writing_refuses_to_follow_a_symlink(tmp_path):
    target = tmp_path / "real.md"
    target.write_text("original\n", encoding="utf-8")
    link = tmp_path / "link.md"

    try:
        link.symlink_to(target)
    except OSError:
        return  # Windows without developer mode cannot create symlinks.

    result = runner.invoke(app, ["report", "--input", str(GITLEAKS_REPORT), "--output", str(link)])

    assert result.exit_code == 2
    assert "refusing to write through a symlink" in result.output
    assert target.read_text(encoding="utf-8") == "original\n"


def test_paths_in_help_do_not_depend_on_the_working_directory():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert str(Path.home()) not in result.stdout
