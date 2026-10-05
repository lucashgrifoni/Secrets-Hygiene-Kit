"""End-to-end tests: the real console script, as a real process, on real files.

Every other test in this suite drives Typer in-process through `CliRunner`,
which is fast and precise but shares the interpreter with the test. That leaves
a class of failure invisible: the packaged entry point, argv handling, the
stream encoding a redirect actually gets, the process exit code CI reads, and
whether package data survived the wheel at all.

These tests spend a subprocess each to cover the flows a user performs, from a
clean working directory, through the public interface only.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"

CLEAN_GITLEAKS = "[]"
CLEAN_DETECT_SECRETS = '{"version": "1.5.0", "results": {}}'

# One leak, reported by two detectors at the same location. trufflehog proves it
# is live, which is what makes the waiver-scope rules matter.
LEAKED_GITLEAKS = json.dumps(
    [
        {
            "RuleID": "aws-access-token",
            "File": "src/settings.py",
            "StartLine": 12,
            "StartColumn": 5,
            "Description": "AWS Access Key",
            "Match": "key = AKIAIOSFODNN7EXAMPLE",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Commit": "9f1c2b3d4e5f60718293a4b5c6d7e8f901234567",
            "Message": "add deployment config",
            "Author": "A Developer",
            "Email": "dev@example.invalid",
            "Fingerprint": "9f1c:src/settings.py:aws-access-token:12",
        }
    ]
)
LEAKED_TRUFFLEHOG = (
    json.dumps(
        {
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "RawV2": "AKIAIOSFODNN7EXAMPLEsecret",
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "file": "src/settings.py",
                        "line": 12,
                        "commit": "9f1c2b3d4e5f60718293a4b5c6d7e8f901234567",
                        "email": "dev@example.invalid",
                    }
                }
            },
        }
    )
    + "\n"
)

# Values that must never appear in anything secguard writes.
SECRET_MATERIAL = (
    "AKIAIOSFODNN7EXAMPLE",
    "dev@example.invalid",
    "add deployment config",
    "A Developer",
)


@pytest.fixture(scope="session")
def secguard_environment() -> dict[str, str]:
    """An environment where `python -m secguard` resolves to this working tree."""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(SOURCE_ROOT)
    environment.pop("SECGUARD_OVERRIDE", None)
    environment.pop("SECGUARD_OVERRIDE_REASON", None)
    return environment


def run(
    arguments: list[str],
    cwd: Path,
    environment: dict[str, str],
    *,
    capture_output: bool = True,
    **kwargs,
) -> subprocess.CompletedProcess[str]:
    """Invoke secguard as a separate process and return the completed result.

    `encoding` is explicit because secguard emits UTF-8 on every platform, while
    a parent process on Windows would otherwise decode with the ANSI code page
    and choke on the first non-ASCII byte. Any caller reading secguard's output
    programmatically needs the same setting.
    """
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "secguard", *arguments],
        cwd=cwd,
        env=environment,
        capture_output=capture_output,
        text=True,
        encoding="utf-8",
        timeout=120,
        **kwargs,
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A clean directory standing in for a freshly cloned repository."""
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    return workspace


# --------------------------------------------------------------- first contact


def test_a_new_user_can_scaffold_and_the_result_validates_itself(project, secguard_environment):
    """`init` then `waivers check` — the first two commands the quickstart gives."""
    created = run(["init", ".", "--ci", "both"], project, secguard_environment)

    assert created.returncode == 0, created.stderr
    for expected in (
        ".secguard/waivers.yaml",
        ".pre-commit-config.yaml",
        ".github/workflows/secguard.yml",
        ".gitlab/secguard.gitlab-ci.yml",
    ):
        assert (project / expected).is_file(), expected

    checked = run(
        ["waivers", "check", "--file", ".secguard/waivers.yaml", "--today", "2026-08-05"],
        project,
        secguard_environment,
    )

    assert checked.returncode == 0, checked.stderr


def test_init_is_idempotent_and_never_silently_replaces_local_work(project, secguard_environment):
    run(["init", "."], project, secguard_environment)
    edited = project / ".secguard" / "waivers.yaml"
    edited.write_text("# a team's own waiver file\n", encoding="utf-8")

    again = run(["init", "."], project, secguard_environment)

    assert again.returncode == 0
    assert "skipped" in again.stdout
    assert edited.read_text(encoding="utf-8") == "# a team's own waiver file\n"


# ------------------------------------------------------------- the daily path


def test_a_clean_repository_passes_the_gate(project, secguard_environment):
    """Zero findings from three detectors, including trufflehog's empty file.

    A clean trufflehog run writes JSON Lines with no lines. Rejecting that as
    malformed failed the gate on exactly the repositories with nothing wrong.
    """
    (project / "gitleaks.json").write_text(CLEAN_GITLEAKS, encoding="utf-8")
    (project / "trufflehog.jsonl").write_text("", encoding="utf-8")
    (project / ".secrets.baseline").write_text(CLEAN_DETECT_SECRETS, encoding="utf-8")

    result = run(
        [
            "scan",
            "check",
            "-i",
            "gitleaks.json",
            "-i",
            "trufflehog.jsonl",
            "-i",
            ".secrets.baseline",
            "--fail-on",
            "high",
            "--today",
            "2026-08-05",
        ],
        project,
        secguard_environment,
    )

    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout
    assert "0 finding(s)" in result.stdout
    # An empty report is also what a detector that crashed leaves behind.
    assert "trufflehog.jsonl is empty" in result.stderr


def test_a_live_credential_blocks_the_build_and_no_output_carries_it(project, secguard_environment):
    """The whole pipeline in one run: merge, classify, gate, and every artifact."""
    (project / "gitleaks.json").write_text(LEAKED_GITLEAKS, encoding="utf-8")
    (project / "trufflehog.jsonl").write_text(LEAKED_TRUFFLEHOG, encoding="utf-8")

    result = run(
        [
            "scan",
            "check",
            "-i",
            "gitleaks.json",
            "-i",
            "trufflehog.jsonl",
            "--fail-on",
            "high",
            "--today",
            "2026-08-05",
            "--json",
            "out.json",
            "--sarif",
            "out.sarif",
            "--markdown",
            "out.md",
            "--pr-comment",
            "pr.md",
        ],
        project,
        secguard_environment,
    )

    assert result.returncode == 1, result.stderr
    assert "BLOCK" in result.stdout
    assert "critical" in result.stdout
    assert "verified=live" in result.stdout
    assert "also=trufflehog:AWS" in result.stdout

    artifacts = ["out.json", "out.sarif", "out.md", "pr.md"]
    for name in artifacts:
        assert (project / name).is_file(), name

    written = "\n".join((project / name).read_text(encoding="utf-8") for name in artifacts)
    console = result.stdout + result.stderr
    for forbidden in SECRET_MATERIAL:
        assert forbidden not in written, f"{forbidden} reached a written artifact"
        assert forbidden not in console, f"{forbidden} reached the console"

    document = json.loads((project / "out.json").read_text(encoding="utf-8"))
    finding = document["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["verified"] is True
    assert finding["corroborated_rules"] == ["trufflehog:AWS"]

    sarif = json.loads((project / "out.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1


def test_the_full_waiver_lifecycle_through_the_public_interface(project, secguard_environment):
    """Block, waive, pass, expire, block again — with a real file on disk between each.

    This is the flow the waiver design exists for, and no test covered it end to
    end: each step here reads the file the previous step wrote.
    """
    (project / "gitleaks.json").write_text(LEAKED_GITLEAKS, encoding="utf-8")
    (project / "trufflehog.jsonl").write_text(LEAKED_TRUFFLEHOG, encoding="utf-8")
    gate = [
        "scan",
        "check",
        "-i",
        "gitleaks.json",
        "-i",
        "trufflehog.jsonl",
        "--fail-on",
        "high",
        "--waivers",
        "w.yaml",
    ]

    blocked = run([*gate, "--today", "2026-08-05"], project, secguard_environment)
    assert blocked.returncode == 1

    # A waiver written against one detector's match must not carry the merged
    # finding — the other detector proved the credential is live.
    narrow = run(
        [
            "waivers",
            "add",
            "--file",
            "w.yaml",
            "--rule",
            "gitleaks:aws-access-token",
            "--path",
            "src/settings.py",
            "--reason",
            "Believed to be a placeholder in an example config.",
            "--owner",
            "appsec@example.invalid",
            "--approver",
            "security-lead",
            "--expires",
            "2026-10-01",
            "--today",
            "2026-08-05",
        ],
        project,
        secguard_environment,
    )
    assert narrow.returncode == 0, narrow.stderr

    still_blocked = run([*gate, "--today", "2026-08-05"], project, secguard_environment)
    assert still_blocked.returncode == 1
    assert "covers only one detector" in still_blocked.stdout

    # Re-scoped the way the tool just advised.
    waiver_file = project / "w.yaml"
    waiver_file.write_text(
        waiver_file.read_text(encoding="utf-8").replace(
            "gitleaks:aws-access-token", "secret-type:aws-access-key"
        ),
        encoding="utf-8",
    )

    waived = run([*gate, "--today", "2026-08-05"], project, secguard_environment)
    assert waived.returncode == 0
    assert "1 waived" in waived.stdout

    # The exception expires and the gate fails closed on its own.
    expired = run([*gate, "--today", "2026-10-02"], project, secguard_environment)
    assert expired.returncode == 1
    assert "expired-waiver" in expired.stdout

    lifecycle = run(
        ["waivers", "check", "--file", "w.yaml", "--today", "2026-10-02"],
        project,
        secguard_environment,
    )
    assert lifecycle.returncode == 1
    assert "expired waiver(s)" in lifecycle.stdout


def test_a_responder_can_reach_the_playbook_the_gate_named(project, secguard_environment):
    """The handoff from "the build failed" to "here is what to do about it"."""
    (project / "gitleaks.json").write_text(LEAKED_GITLEAKS, encoding="utf-8")
    gate = run(
        ["scan", "check", "-i", "gitleaks.json", "--fail-on", "high", "--today", "2026-08-05"],
        project,
        secguard_environment,
    )
    assert gate.returncode == 1
    assert "playbook=aws-access-key" in gate.stdout

    checklist = run(
        [
            "incident",
            "start",
            "--secret-type",
            "aws-access-key",
            "--leaked-via",
            "public-repository",
            "--reference",
            "INC-42",
            "--today",
            "2026-08-05",
            "--output",
            "incident.md",
        ],
        project,
        secguard_environment,
    )

    assert checklist.returncode == 0, checklist.stderr
    body = (project / "incident.md").read_text(encoding="utf-8")
    assert "# Incident checklist" in body
    assert "INC-42" in body
    assert "- [ ]" in body
    for forbidden in SECRET_MATERIAL:
        assert forbidden not in body


# ------------------------------------------------------- the process contract


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (["scan", "check"], 2),
        (["scan", "check", "-i", "absent.json"], 2),
        (["scan", "check", "-i", "gitleaks.json", "--fail-on", "urgent"], 2),
        (["waivers", "check", "--file", "absent.yaml"], 2),
        (["playbooks", "show", "no-such-playbook"], 2),
        (["incident", "start"], 2),
        (["version"], 0),
        (["playbooks", "check", "--today", "2026-08-05"], 0),
    ],
)
def test_the_exit_code_contract_holds_for_a_real_process(
    project, secguard_environment, arguments, expected
):
    """CI branches on these numbers, and `1` must only ever mean a deliberate block."""
    (project / "gitleaks.json").write_text(CLEAN_GITLEAKS, encoding="utf-8")

    result = run(arguments, project, secguard_environment)

    assert result.returncode == expected, f"{arguments}: {result.stdout}{result.stderr}"
    assert "Traceback (most recent call last)" not in result.stderr


def test_redirected_output_is_utf8_with_unix_endings(project, secguard_environment):
    """A responder attaches this file to an incident record.

    On Windows a redirected stream defaults to the ANSI code page, so this
    produced a file that was not valid UTF-8 — and `CliRunner` cannot see it,
    because there is no real stream involved.
    """
    destination = project / "playbook.md"
    with destination.open("wb") as handle:
        result = run(
            ["playbooks", "show", "generic-private-key"],
            project,
            secguard_environment,
            stdout=handle,
            capture_output=False,
            stderr=subprocess.PIPE,
        )

    assert result.returncode == 0
    raw = destination.read_bytes()
    assert raw.decode("utf-8")  # must not raise
    assert b"\r\n" not in raw


def test_a_hostile_report_cannot_forge_the_gate_verdict(project, secguard_environment):
    """A newline in a scanner path would print a fake PASS line in a run that blocked."""
    (project / "hostile.json").write_text(
        json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "File": "a.py\nPASS: no blocking finding and no expired waiver.",
                    "StartLine": 1,
                }
            ]
        ),
        encoding="utf-8",
    )

    result = run(
        ["scan", "check", "-i", "hostile.json", "--fail-on", "high", "--today", "2026-08-05"],
        project,
        secguard_environment,
    )

    assert result.returncode == 2
    assert "PASS" not in result.stdout
    assert "control characters" in result.stderr


def test_the_audited_override_reaches_pre_commit_but_not_the_gate(project, secguard_environment):
    """The spec's Definition of Public asks for a bypass; a bypassable gate is not one."""
    (project / "w.yaml").write_text(
        'schema: "secguard.waiver/v1"\n'
        "waivers:\n"
        "  - id: WV-2026-001\n"
        "    rule: secret-type:aws-access-key\n"
        "    path: src/settings.py\n"
        '    reason: "Placeholder in an example config."\n'
        "    owner: appsec@example.invalid\n"
        "    expires_at: 2026-08-01\n"
        "    approver: security-lead\n",
        encoding="utf-8",
    )
    (project / "gitleaks.json").write_text(LEAKED_GITLEAKS, encoding="utf-8")

    overridden = dict(secguard_environment)
    overridden["SECGUARD_OVERRIDE"] = "1"
    overridden["SECGUARD_OVERRIDE_REASON"] = "hotfix INC-42, waiver renewed Monday"

    hook = run(
        ["waivers", "check", "--file", "w.yaml", "--today", "2026-08-05", "--allow-override"],
        project,
        overridden,
    )
    assert hook.returncode == 0
    assert "OVERRIDE:" in hook.stderr
    assert "WV-2026-001" in hook.stdout  # still shown before being carried past

    gate = run(
        [
            "scan",
            "check",
            "-i",
            "gitleaks.json",
            "--waivers",
            "w.yaml",
            "--fail-on",
            "high",
            "--today",
            "2026-08-05",
        ],
        project,
        overridden,
    )
    assert gate.returncode == 1
    assert "OVERRIDE:" not in gate.stderr


def test_the_same_reports_in_any_order_produce_identical_bytes(project, secguard_environment):
    """Evidence bundles get diffed and committed; churn from argument order is noise.

    The two reports must hold findings that stay *separate* and tie on the sort
    key, or the merge collapses them into one record and any ordering bug is
    invisible. These are two different secret types at the same path and line:
    same severity, same path, same line, and nothing else to order them by.
    """
    # One tied finding per file. Two in the same file would keep their relative
    # order under a stable sort no matter what, so swapping the inputs could
    # never move them and the test would pass against the bug.
    (project / "first.json").write_text(
        json.dumps([{"RuleID": "slack-webhook-url", "File": "app/a.py", "StartLine": 7}]),
        encoding="utf-8",
    )
    (project / "second.json").write_text(
        json.dumps([{"RuleID": "acme-internal-token", "File": "app/a.py", "StartLine": 7}]),
        encoding="utf-8",
    )

    for index, inputs in enumerate((["first.json", "second.json"], ["second.json", "first.json"])):
        arguments = ["scan", "check"]
        for name in inputs:
            arguments += ["-i", name]
        run(
            [
                *arguments,
                "--fail-on",
                "none",
                "--today",
                "2026-08-05",
                "--json",
                f"{index}.json",
                "--sarif",
                f"{index}.sarif",
            ],
            project,
            secguard_environment,
        )

    # Guard the guard: if these ever merge into one finding, the test stops
    # being able to detect an ordering bug and would pass for the wrong reason.
    document = json.loads((project / "0.json").read_text(encoding="utf-8"))
    tied = [f for f in document["findings"] if f["path"] == "app/a.py" and f["line"] == 7]
    assert len(tied) == 2, "the two findings must stay separate, not merge"
    assert len({f["severity"] for f in tied}) == 1, "and must tie on the sort key"

    assert (project / "0.json").read_bytes() == (project / "1.json").read_bytes()
    assert (project / "0.sarif").read_bytes() == (project / "1.sarif").read_bytes()
