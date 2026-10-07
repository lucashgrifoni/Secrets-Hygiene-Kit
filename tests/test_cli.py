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
from secguard.cli import app as cli_app
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


def test_scan_check_marks_detector_reported_verification():
    result = runner.invoke(app, _scan_arguments("--fail-on", "none"))

    assert "verified=detector:true" in result.output


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


def test_scan_check_will_not_let_one_detectors_waiver_pass_another_detectors_finding(tmp_path):
    """The gate must not weaken when a second scanner confirms the same leak.

    The fixture AWS key is reported by gitleaks, trufflehog, and detect-secrets,
    and trufflehog marks it `Verified: true`. A waiver reviewed against the
    gitleaks match alone has no authority over the other two.
    """
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        WAIVER_HEADER + "waivers:\n"
        "  - id: WV-2026-001\n"
        "    rule: gitleaks:aws-access-token\n"
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

    assert result.exit_code == 1
    assert "5 active, 0 waived" in result.output
    assert "BLOCK" in result.output
    # The near miss has to be legible, or an operator reads the unused waiver as
    # a bug: its rule and path both look like they match the blocking finding.
    assert "also=detect-secrets:AWS Access Key,trufflehog:AWS" in result.output
    assert "unused-waiver\tWV-2026-001" in result.output
    assert "covers only one detector of a finding several reported" in result.output


def test_scan_check_treats_an_empty_report_as_a_clean_scan(tmp_path):
    """A clean trufflehog run writes zero JSON Lines, which is a zero-byte file."""
    empty = tmp_path / "trufflehog.jsonl"
    empty.write_text("", encoding="utf-8")
    clean_gitleaks = tmp_path / "gitleaks.json"
    clean_gitleaks.write_text("[]", encoding="utf-8")
    (tmp_path / "empty-waivers.yaml").write_text(
        'schema: "secguard.waiver/v1"\nwaivers: []\n', encoding="utf-8"
    )

    result = runner.invoke(
        app,
        _scan_arguments(
            "--fail-on",
            "high",
            "--waivers",
            str(tmp_path / "empty-waivers.yaml"),
            reports=[clean_gitleaks, empty],
        ),
    )

    assert result.exit_code == 0
    assert "0 finding(s)" in result.output
    assert "PASS" in result.output
    # Silence would hide a detector that crashed, which leaves the same file.
    assert "trufflehog.jsonl is empty; treating it as zero findings" in result.output


def test_scan_check_without_input_is_an_input_error():
    result = runner.invoke(app, ["scan", "check"])

    assert result.exit_code == 2
    assert "at least one --input scanner report is required" in result.output


def test_malformed_input_exits_two_and_never_shows_a_traceback(tmp_path):
    """`1` means "the gate blocked on purpose"; a crash must never claim that.

    Each of these used to reach the user as a Python traceback with exit `1`,
    so a CI log said "blocked" when the truth was "your file is unreadable".
    """
    impossible_date = tmp_path / "waivers.yaml"
    impossible_date.write_text(
        WAIVER_HEADER + "waivers:\n"
        "  - id: WV-2026-001\n"
        "    rule: gitleaks:aws-access-token\n"
        "    path: app/config.py\n"
        '    reason: "r"\n'
        "    owner: o\n"
        "    expires_at: 2026-02-30\n"
        "    approver: a\n",
        encoding="utf-8",
    )
    forged_path = tmp_path / "forged.json"
    forged_path.write_text(
        json.dumps([{"RuleID": "aws-access-token", "File": "a.py\nPASS: forged", "StartLine": 1}]),
        encoding="utf-8",
    )

    cases = [
        (["waivers", "check", "--file", str(impossible_date), "--today", TODAY.isoformat()]),
        (_scan_arguments("--fail-on", "high", reports=[forged_path])),
    ]

    for arguments in cases:
        result = runner.invoke(app, arguments)

        assert result.exit_code == 2, arguments
        assert "Traceback" not in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)


def test_scan_check_rejects_an_unknown_threshold():
    result = runner.invoke(app, _scan_arguments("--fail-on", "urgent"))

    assert result.exit_code == 2


def test_scan_check_rejects_explicit_missing_waivers_even_in_report_only_mode(tmp_path):
    result = runner.invoke(
        app, _scan_arguments("--fail-on", "none", "--waivers", str(tmp_path / "absent.yaml"))
    )

    assert result.exit_code == 2
    assert "waiver file not found" in result.output


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


# ------------------------------------------------------------- entry point


def test_the_entry_point_disables_windows_glob_expansion(monkeypatch):
    """Click expands argv globs against the cwd on Windows before Typer parses.

    `--path 'tests/fixtures/**'` — the command the docs give — then became
    whatever happened to match: one hit silently recorded a literal directory as
    the waiver scope, several produced "unexpected extra arguments". A waiver
    scope is a pattern, not a file list.
    """
    recorded: dict[str, object] = {}

    def fake_app(**kwargs):
        recorded.update(kwargs)

    monkeypatch.setattr(cli_app, "app", fake_app)
    monkeypatch.setattr(cli_app, "use_utf8_output", lambda: None)

    cli_app.main()

    assert recorded == {"windows_expand_args": False}


def test_the_entry_point_forces_utf8_output(monkeypatch):
    """A redirected stream on Windows defaults to the ANSI code page.

    `secguard playbooks show generic-private-key > playbook.md` wrote a file
    that was not valid UTF-8, for a document a responder attaches to an incident
    record.
    """
    calls: list[dict] = []

    class Stream:
        def reconfigure(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(cli_app.sys, "stdout", Stream())
    monkeypatch.setattr(cli_app.sys, "stderr", Stream())

    cli_app.use_utf8_output()

    assert calls == [{"encoding": "utf-8", "newline": "\n"}] * 2


def test_forcing_utf8_output_tolerates_a_stream_that_cannot_be_reconfigured(monkeypatch):
    monkeypatch.setattr(cli_app.sys, "stdout", object())
    monkeypatch.setattr(cli_app.sys, "stderr", object())

    cli_app.use_utf8_output()  # must not raise


# ------------------------------------------------- audited pre-commit override


def _expired_waiver_file(tmp_path) -> Path:
    path = tmp_path / "waivers.yaml"
    path.write_text(ACTIVE_WAIVER_FILE.replace("2026-08-12", "2026-05-17"), encoding="utf-8")
    return path


def test_the_override_is_refused_without_a_reason(tmp_path, monkeypatch):
    """An unexplained bypass is indistinguishable from a broken check."""
    monkeypatch.setenv("SECGUARD_OVERRIDE", "1")
    monkeypatch.delenv("SECGUARD_OVERRIDE_REASON", raising=False)

    result = runner.invoke(
        app,
        [
            "waivers",
            "check",
            "--file",
            str(_expired_waiver_file(tmp_path)),
            "--today",
            "2026-05-18",
            "--allow-override",
        ],
    )

    assert result.exit_code == 2
    assert "SECGUARD_OVERRIDE_REASON" in result.output


def test_the_override_is_refused_when_the_reason_is_a_shrug(tmp_path, monkeypatch):
    monkeypatch.setenv("SECGUARD_OVERRIDE", "1")
    monkeypatch.setenv("SECGUARD_OVERRIDE_REASON", "wip")

    result = runner.invoke(
        app,
        [
            "waivers",
            "check",
            "--file",
            str(_expired_waiver_file(tmp_path)),
            "--today",
            "2026-05-18",
            "--allow-override",
        ],
    )

    assert result.exit_code == 2


def test_an_audited_override_passes_and_still_shows_what_it_bypassed(tmp_path, monkeypatch):
    monkeypatch.setenv("SECGUARD_OVERRIDE", "1")
    monkeypatch.setenv("SECGUARD_OVERRIDE_REASON", "hotfix INC-42, waiver renewed Monday")

    result = runner.invoke(
        app,
        [
            "waivers",
            "check",
            "--file",
            str(_expired_waiver_file(tmp_path)),
            "--today",
            "2026-05-18",
            "--allow-override",
        ],
    )

    assert result.exit_code == 0
    assert "WV-2026-001" in result.output  # the finding is still printed
    assert "OVERRIDE:" in result.output
    assert "hotfix INC-42" in result.output
    assert "still fails in CI" in result.output


def test_the_override_does_nothing_without_the_opt_in_flag(tmp_path, monkeypatch):
    """A gate an environment variable can switch off is not a gate.

    `scan check` and the CI templates never pass `--allow-override`, so the
    escape hatch cannot reach the pipeline.
    """
    monkeypatch.setenv("SECGUARD_OVERRIDE", "1")
    monkeypatch.setenv("SECGUARD_OVERRIDE_REASON", "hotfix INC-42, waiver renewed Monday")

    result = runner.invoke(
        app,
        [
            "waivers",
            "check",
            "--file",
            str(_expired_waiver_file(tmp_path)),
            "--today",
            "2026-05-18",
        ],
    )

    assert result.exit_code == 1
    assert "OVERRIDE:" not in result.output


def test_the_ci_gate_never_offers_an_override(monkeypatch):
    monkeypatch.setenv("SECGUARD_OVERRIDE", "1")
    monkeypatch.setenv("SECGUARD_OVERRIDE_REASON", "hotfix INC-42, waiver renewed Monday")

    result = runner.invoke(app, _scan_arguments("--fail-on", "high"))

    assert result.exit_code == 1
    assert "--allow-override" not in runner.invoke(app, ["scan", "check", "--help"]).output


# --------------------------------------------------- fallback classification


def test_a_guessed_classification_is_visible_in_the_console(tmp_path):
    """Four documents told the responder to look for `mapping: fallback` here."""
    result = runner.invoke(app, _scan_arguments("--fail-on", "none", reports=[GITLEAKS_REPORT]))

    assert result.exit_code == 0
    fallback_lines = [line for line in result.output.splitlines() if "mapping=fallback" in line]
    assert fallback_lines, result.output
    assert "acme-internal-token" in fallback_lines[0]


# --------------------------------------------------------- local rule catalog


def test_a_local_rule_catalog_is_never_loaded_without_being_named(tmp_path, monkeypatch):
    """`.secguard/rules.yaml` sits inside the checkout the workflow is scanning.

    The packaged workflow runs on `pull_request`, so its content comes from
    whoever opened the pull request. A catalog can lower a severity, and a
    severity under the threshold does not block, so loading one implicitly would
    let a single added file turn BLOCK into PASS with no owner, approver, or
    expiry — everything the waiver lifecycle demands for exactly that decision.
    """
    catalog = tmp_path / ".secguard" / "rules.yaml"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        """
schema: "secguard.rules/v1"
secret_types:
  aws-access-key:
    title: AWS access key ID
    severity: info
    playbook: aws-access-key
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    blocked = runner.invoke(app, _scan_arguments("--fail-on", "high", reports=[GITLEAKS_REPORT]))

    assert blocked.exit_code == 1
    assert "using the local rule catalog" not in blocked.output
    assert "BLOCK" in blocked.output

    # Naming it explicitly works, and says what it changed.
    named = runner.invoke(
        app,
        _scan_arguments("--fail-on", "high", "--rules", str(catalog), reports=[GITLEAKS_REPORT]),
    )

    assert named.exit_code == 0
    # Every rule that now resolves lower is named, not just the secret type:
    # a per-rule override or a remap lowers what a finding actually gets while
    # leaving the secret-type default untouched.
    assert "lowers" in named.output
    assert "aws-access-key high->info" in named.output
    assert "gitleaks:aws-access-token high->info" in named.output
