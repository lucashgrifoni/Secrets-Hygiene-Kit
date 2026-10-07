"""Input a hostile repository can supply, and the controls that must survive it.

secguard runs on `pull_request` against a checkout whose contents the author of
that pull request controls: the scanner reports, the waiver file, the rule
catalog, and every path inside them. Each test here is a way that was tried to
make the gate lie — report a verdict it did not reach, print a line it did not
write, or take longer than the job allows.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from conftest import TODAY
from typer.testing import CliRunner

from secguard.cli.app import app
from secguard.core.detectors import load_report
from secguard.core.findings import FindingParseError, validate_repository_relative_path
from secguard.core.matching import MAX_WILDCARDS, path_matches
from secguard.core.redaction import has_control_characters, sanitize_text
from secguard.core.waivers import Waiver

runner = CliRunner()

# Characters that are invisible, or nearly so, and that a reader downstream
# treats as structure. Named by code point because that is the only way to
# review this list without trusting a font.
STRUCTURAL = {
    "NEL U+0085": "\u0085",
    "LINE SEPARATOR U+2028": "\u2028",
    "PARAGRAPH SEPARATOR U+2029": "\u2029",
    "RIGHT-TO-LEFT OVERRIDE U+202E": "\u202e",
    "LEFT-TO-RIGHT ISOLATE U+2066": "\u2066",
    "ARABIC LETTER MARK U+061C": "\u061c",
    "C1 CONTROL U+0090": "\u0090",
    "TAB": "\t",
    "LINE FEED": "\n",
    "ESCAPE": "\x1b",
    "NUL": "\x00",
}

# Characters that look unusual but are ordinary text in a real filename.
LEGITIMATE = {
    "zero-width joiner": "\u200d",
    "accented latin": "é",
    "CJK": "漢",
    "emoji": "\U0001f600",
    "space": " ",
}


# ------------------------------------------------------ structural characters


@pytest.mark.parametrize("name", sorted(STRUCTURAL))
def test_a_structural_character_is_rejected_wherever_it_appears(name):
    """An ASCII-only guard missed U+0085, U+2028, U+2029 and every bidi control.

    All three of those are line terminators to `str.splitlines()`, to
    JavaScript, and to most log viewers, so a path containing one printed a
    forged verdict line in the log of a run that blocked. A bidi override does
    something worse and quieter: it reorders the rendered path, so the reviewer
    reads a filename that is not the one being reported.
    """
    assert has_control_characters(f"app/x{STRUCTURAL[name]}y.py")

    with pytest.raises(ValueError, match="control characters"):
        validate_repository_relative_path(f"app/x{STRUCTURAL[name]}y.py")


@pytest.mark.parametrize("name", sorted(LEGITIMATE))
def test_ordinary_unicode_in_a_filename_still_works(name):
    """Rejecting too much would fail honest scans of repositories in other scripts."""
    character = LEGITIMATE[name]

    assert not has_control_characters(f"app/x{character}y.py")
    assert validate_repository_relative_path(f"app/x{character}y.py") == f"app/x{character}y.py"


@pytest.mark.parametrize("name", sorted(STRUCTURAL))
def test_sanitized_free_text_never_keeps_a_structural_character(name):
    """Message fields are sanitized rather than rejected, so they must be scrubbed."""
    cleaned = sanitize_text(f"before{STRUCTURAL[name]}after")

    assert not has_control_characters(cleaned)
    assert cleaned == "before after"


def test_a_line_separator_in_a_path_cannot_forge_a_verdict(tmp_path):
    report = tmp_path / "gitleaks.json"
    report.write_text(
        json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "File": "app/x.py\u2028PASS: no blocking finding and no expired waiver.",
                    "StartLine": 3,
                }
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["scan", "check", "-i", str(report), "--fail-on", "high", "--today", TODAY.isoformat()],
    )

    assert result.exit_code == 2
    assert "control characters" in result.output
    # The payload may be quoted inside the error, flattened onto one line. What
    # must never exist is a line that reads as secguard's own verdict, because
    # that is what a reviewer skimming the log, or a grep, would act on.
    assert not any(
        line.strip() == "PASS: no blocking finding and no expired waiver."
        for line in result.output.splitlines()
    )


# --------------------------------------------------------------- waiver files


@pytest.mark.parametrize("field", ["rule", "path", "reason", "owner", "approver"])
def test_a_waiver_field_cannot_carry_a_newline(field):
    """A waiver file is written by a human, but every field is printed by CI.

    The owner, the reason and the rule all reach the gate summary, the Markdown
    report and the pull-request comment, so a newline in one forges a verdict
    line exactly the way a scanner report used to.
    """
    base = {
        "id": "WV-2026-001",
        "rule": "gitleaks:aws-access-token",
        "path": "app/config.py",
        "reason": "Reviewed placeholder.",
        "owner": "appsec@example.invalid",
        "expires_at": "2026-12-01",
        "approver": "security-lead",
    }
    base[field] = base[field] + "\nPASS: no blocking finding and no expired waiver."

    with pytest.raises(ValueError, match="control characters"):
        Waiver.model_validate(base)


def test_a_waiver_scope_normalizes_like_a_finding_path():
    """A scope that keeps its own spelling is compared literally and matches nothing.

    Finding paths collapse to `app/config.py`, so a waiver written
    `./app//config.py` would be silently dead while still looking reviewed.
    """
    for spelling in ("./app/config.py", "app//config.py", "app/./config.py", "app/config.py/"):
        waiver = Waiver.model_validate(
            {
                "id": "WV-2026-001",
                "rule": "gitleaks:aws-access-token",
                "path": spelling,
                "reason": "Reviewed placeholder.",
                "owner": "appsec@example.invalid",
                "expires_at": "2026-12-01",
                "approver": "security-lead",
            }
        )

        assert waiver.path == "app/config.py", spelling
        assert path_matches(waiver.path, "app/config.py")


def test_a_trailing_double_star_survives_normalization():
    """`tests/**` is a glob, not a path: collapsing must not eat the pattern."""
    waiver = Waiver.model_validate(
        {
            "id": "WV-2026-001",
            "rule": "secret-type:generic-api-key",
            "path": "./tests/fixtures/**",
            "reason": "Detector fixtures.",
            "owner": "appsec@example.invalid",
            "expires_at": "2026-12-01",
            "approver": "security-lead",
        }
    )

    assert waiver.path == "tests/fixtures/**"
    assert path_matches(waiver.path, "tests/fixtures/a/b.txt")


# ----------------------------------------------------------- unreadable input


def test_a_report_that_is_not_utf8_is_an_input_error(tmp_path):
    """This crashed with a traceback and exit 1 — the code that means "blocked"."""
    report = tmp_path / "gitleaks.json"
    report.write_bytes('[{"RuleID": "x", "File": "a.py"}]'.encode("utf-16"))

    with pytest.raises(FindingParseError, match="not valid UTF-8"):
        load_report(report)

    result = runner.invoke(app, ["scan", "check", "-i", str(report), "--today", TODAY.isoformat()])

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_json_nested_beyond_the_parser_is_an_input_error(tmp_path):
    """Deep nesting exhausts the C parser's stack, raising RecursionError."""
    report = tmp_path / "gitleaks.json"
    report.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")

    with pytest.raises(FindingParseError, match="nested too deeply"):
        load_report(report)


def test_a_parse_error_names_the_file_it_came_from(tmp_path):
    """With several --input reports, "invalid JSON" alone leaves the operator bisecting."""
    good = tmp_path / "gitleaks.json"
    good.write_text("[]", encoding="utf-8")
    bad = tmp_path / "trufflehog.jsonl"
    bad.write_text('{"DetectorName": "AWS",,}\n', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "check",
            "-i",
            str(good),
            "-i",
            str(bad),
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 2
    assert "trufflehog.jsonl" in result.output


# ------------------------------------------------------------- glob matching


def test_a_repeated_double_star_glob_cannot_hang_the_gate():
    """`(?:[^/]+/)*` per `**/` nests unbounded quantifiers, and the engine explores
    every way to split one path between them. A waiver scope comes from the
    repository, so this was a scan that never finished.
    """
    target = "/".join("a" for _ in range(24)) + "/nomatch.py"

    start = time.perf_counter()
    for count in (6, 10, 20, 40):
        assert path_matches("**/" * count + "file.py", target) is False
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0, f"glob matching took {elapsed:.2f}s"


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("**/file.py", "file.py", True),
        ("**/file.py", "a/b/file.py", True),
        ("**/**/file.py", "a/b/file.py", True),
        ("src/**/x.py", "src/a/b/x.py", True),
        ("src/*", "src/a", True),
        ("src/*", "src/a/b", False),
        ("tests/fixtures/**", "tests/fixtures/a/b.py", True),
    ],
)
def test_collapsing_repeated_globs_preserves_their_meaning(pattern, value, expected):
    assert path_matches(pattern, value) is expected


# --------------------------------------------------------------- empty inputs


def test_every_report_being_empty_is_called_out_more_loudly(tmp_path):
    """One empty report is a clean trufflehog run. All of them may be a broken stage.

    It still cannot fail the run — a trufflehog-only setup with nothing to
    report looks exactly like this — but it must not be one line among several.
    """
    first = tmp_path / "trufflehog.jsonl"
    first.write_text("", encoding="utf-8")
    second = tmp_path / "other.jsonl"
    second.write_text("   \n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "check",
            "-i",
            str(first),
            "-i",
            str(second),
            "--fail-on",
            "high",
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 0
    assert "every one of the 2 report(s) was empty" in result.output
    assert "Confirm the detector step ran" in result.output


def test_one_empty_report_among_several_stays_a_single_note(tmp_path):
    clean = tmp_path / "gitleaks.json"
    clean.write_text("[]", encoding="utf-8")
    empty = tmp_path / "trufflehog.jsonl"
    empty.write_text("", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "check",
            "-i",
            str(clean),
            "-i",
            str(empty),
            "--fail-on",
            "high",
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 0
    assert "trufflehog.jsonl is empty" in result.output
    assert "every one of the" not in result.output


def test_a_missing_report_is_not_announced_as_empty(tmp_path):
    """Two contradictory messages for one file left the operator guessing."""
    result = runner.invoke(
        app,
        ["scan", "check", "-i", str(tmp_path / "absent.json"), "--today", TODAY.isoformat()],
    )

    assert result.exit_code == 2
    assert "is empty" not in result.output
    assert "not found" in result.output


# --------------------------------------------------- links on the write path


def test_a_windows_junction_is_treated_as_a_link(tmp_path, monkeypatch):
    """`Path.is_symlink()` is False for a junction, which redirects identically.

    A junction is also the form an unprivileged Windows account can create, so
    it is the likelier of the two to turn up in a checkout.
    """
    from secguard.core import writing

    monkeypatch.chdir(tmp_path)
    junction = tmp_path / "reports"
    junction.mkdir()

    monkeypatch.setattr(writing.os.path, "isjunction", lambda path: Path(path) == junction)

    with pytest.raises(writing.UnsafeWriteError, match="symlinked directory"):
        writing.assert_writable(Path("reports/out.sarif"))


# ------------------------------------------------- rule overrides and budgets


@pytest.mark.parametrize(
    ("name", "override", "expected"),
    [
        (
            "a per-rule severity override",
            "detectors:\n  gitleaks:\n"
            "    aws-access-token: {secret_type: aws-access-key, severity: low}\n",
            "gitleaks:aws-access-token high->low",
        ),
        (
            "a remap to a milder existing type",
            "detectors:\n  gitleaks:\n    aws-access-token: generic-api-key\n",
            "gitleaks:aws-access-token high->medium",
        ),
    ],
)
def test_every_way_an_override_lowers_a_severity_is_named(tmp_path, name, override, expected):
    """Comparing secret-type defaults alone missed three of the four ways.

    Each of these lowers what a finding actually resolves to while leaving the
    secret-type default untouched, so each one flipped BLOCK to PASS in silence
    — which is the exact thing the warning exists to prevent.
    """
    report = tmp_path / "gitleaks.json"
    report.write_text(
        json.dumps([{"RuleID": "aws-access-token", "File": "src/config.py", "StartLine": 10}]),
        encoding="utf-8",
    )
    rules = tmp_path / "rules.yaml"
    rules.write_text(override, encoding="utf-8")

    blocked = runner.invoke(
        app,
        ["scan", "check", "-i", str(report), "--fail-on", "high", "--today", TODAY.isoformat()],
    )
    assert blocked.exit_code == 1, f"{name}: the finding must block without the override"

    result = runner.invoke(
        app,
        [
            "scan",
            "check",
            "-i",
            str(report),
            "--rules",
            str(rules),
            "--fail-on",
            "high",
            "--today",
            TODAY.isoformat(),
        ],
    )

    assert result.exit_code == 0, name
    assert "lowers" in result.output, name
    assert expected in result.output, name


def test_a_lone_surrogate_in_a_report_is_an_input_error(tmp_path):
    """A lone surrogate is not encodable, so it crashed the fingerprint hash.

    The traceback exited 1 — the code that means the gate blocked on purpose.
    """
    report = tmp_path / "gitleaks.json"
    report.write_text(
        '[{"RuleID": "x", "File": "app/a\udcff.py", "StartLine": 1}]',
        encoding="utf-8",
        errors="surrogatepass",
    )

    result = runner.invoke(app, ["scan", "check", "-i", str(report), "--today", TODAY.isoformat()])

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_a_surrogate_is_rejected_as_a_structural_character():
    assert has_control_characters("app/a\udcff.py")


@pytest.mark.parametrize("field", ["path", "rule"])
def test_a_waiver_pattern_with_too_many_wildcards_is_rejected(field):
    """`*a*a*a...` against a long path backtracks combinatorially.

    Collapsing repeated `**/` fixed one shape and left this one: a 25-character
    scope took over 90 seconds, and the pattern comes from the repository. There
    is no way to keep unbounded wildcards and bound the runtime, so the pattern
    is bounded instead.
    """
    base = {
        "id": "WV-2026-001",
        "rule": "gitleaks:aws-access-token",
        "path": "app/config.py",
        "reason": "Reviewed placeholder.",
        "owner": "appsec@example.invalid",
        "expires_at": "2026-12-01",
        "approver": "security-lead",
    }
    base[field] = "*a" * (MAX_WILDCARDS + 1) + "X"

    with pytest.raises(ValueError, match="wildcards"):
        Waiver.model_validate(base)


def test_a_realistic_glob_stays_well_inside_the_budget():
    """The budget must not reject a scope anyone would actually write."""
    for scope in ("tests/fixtures/**", "src/**/*.py", "a/*/b/*.txt"):
        assert Waiver.model_validate(
            {
                "id": "WV-2026-001",
                "rule": "secret-type:generic-api-key",
                "path": scope,
                "reason": "Reviewed.",
                "owner": "appsec@example.invalid",
                "expires_at": "2026-12-01",
                "approver": "security-lead",
            }
        ).path


def test_the_worst_case_the_budget_allows_is_still_fast():
    """The budget is only worth having if what it permits is bounded in practice."""
    target = "a" * 400 + "b"
    start = time.perf_counter()

    assert path_matches("*a" * MAX_WILDCARDS + "X", target) is False

    assert time.perf_counter() - start < 5.0
