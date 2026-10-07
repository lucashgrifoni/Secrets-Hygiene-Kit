"""CLI export preflight: reject conflicting paths before changing any file."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secguard.cli.app import app

runner = CliRunner()
CHECK_DATE = "2026-10-06"
CANARY = "SECGUARD-OUTPUT-PATH-CANARY"
COMMANDS = ("check", "report", "normalize")


@pytest.fixture
def scan_files(tmp_path, monkeypatch) -> dict[str, Path]:
    """Keep all writes in the caller-configured pytest temporary directory."""
    monkeypatch.chdir(tmp_path)
    report = tmp_path / "raw.json"
    report.write_text(
        json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "File": "src/config.py",
                    "StartLine": 3,
                    "Secret": CANARY,
                    "Description": "Synthetic AWS fixture",
                }
            ]
        ),
        encoding="utf-8",
    )
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text('schema: "secguard.waiver/v1"\nwaivers: []\n', encoding="utf-8")
    catalog = tmp_path / "rules.yaml"
    catalog.write_text(
        'schema: "secguard.rules/v1"\n'
        "fallback_secret_type: generic-api-key\n"
        "secret_types:\n"
        "  aws-access-key:\n"
        '    title: "AWS access key ID"\n'
        "    severity: high\n"
        "    playbook: aws-access-key\n"
        "  generic-api-key:\n"
        '    title: "Generic API key"\n'
        "    severity: medium\n"
        "    playbook: generic-api-key\n"
        "detectors:\n"
        "  gitleaks:\n"
        "    aws-access-token: aws-access-key\n",
        encoding="utf-8",
    )
    return {"input": report, "waivers": waivers, "rules": catalog}


def _arguments(command: str, files: dict[str, Path]) -> list[str]:
    arguments = ["report"] if command == "report" else ["scan", command]
    arguments.extend(["--input", str(files["input"])])
    if command != "normalize":
        arguments.extend(["--waivers", str(files["waivers"]), "--today", CHECK_DATE])
    if command == "check":
        arguments.extend(["--fail-on", "none"])
    return arguments


def _output_option(command: str) -> str:
    return "--json" if command == "check" else "--output"


def _snapshot(files: dict[str, Path]) -> dict[Path, bytes]:
    return {path: path.read_bytes() for path in files.values()}


def _assert_preserved(before: dict[Path, bytes]) -> None:
    for path, contents in before.items():
        assert path.read_bytes() == contents, f"preflight changed {path.name}"


@pytest.mark.parametrize("command", COMMANDS)
def test_input_cannot_be_an_output(scan_files, command):
    before = _snapshot(scan_files)
    result = runner.invoke(
        app,
        [*_arguments(command, scan_files), _output_option(command), str(scan_files["input"])],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


@pytest.mark.parametrize("command", COMMANDS)
def test_relative_alias_of_an_input_cannot_be_an_output(scan_files, command):
    before = _snapshot(scan_files)
    result = runner.invoke(
        app,
        [*_arguments(command, scan_files), _output_option(command), scan_files["input"].name],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


@pytest.mark.parametrize("command", ("check", "report"))
def test_selected_waiver_file_cannot_be_an_output(scan_files, command):
    before = _snapshot(scan_files)
    result = runner.invoke(
        app,
        [*_arguments(command, scan_files), _output_option(command), str(scan_files["waivers"])],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


@pytest.mark.parametrize("command", ("check", "report"))
def test_default_waiver_file_cannot_be_an_output(scan_files, command):
    default_waivers = Path(".secguard/waivers.yaml")
    default_waivers.parent.mkdir()
    default_waivers.write_bytes(scan_files["waivers"].read_bytes())
    before = {**_snapshot(scan_files), default_waivers: default_waivers.read_bytes()}
    arguments = ["report"] if command == "report" else ["scan", "check", "--fail-on", "none"]
    result = runner.invoke(
        app,
        [
            *arguments,
            "--input",
            str(scan_files["input"]),
            "--today",
            CHECK_DATE,
            _output_option(command),
            str(default_waivers),
        ],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


@pytest.mark.parametrize("command", COMMANDS)
def test_selected_rule_catalog_cannot_be_an_output(scan_files, command):
    before = _snapshot(scan_files)
    result = runner.invoke(
        app,
        [
            *_arguments(command, scan_files),
            "--rules",
            str(scan_files["rules"]),
            _output_option(command),
            str(scan_files["rules"]),
        ],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


@pytest.mark.parametrize("command", COMMANDS)
def test_every_input_is_protected_when_reports_are_combined(scan_files, command):
    second = Path("second.json")
    second.write_bytes(scan_files["input"].read_bytes())
    before = {**_snapshot(scan_files), second: second.read_bytes()}
    result = runner.invoke(
        app,
        [
            *_arguments(command, scan_files),
            "--input",
            str(second),
            _output_option(command),
            str(second),
        ],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


def test_duplicate_export_destinations_are_rejected(scan_files, tmp_path):
    output = tmp_path / "combined.json"
    output.write_bytes(b"existing review artifact\n")
    before = {**_snapshot(scan_files), output: output.read_bytes()}
    result = runner.invoke(
        app,
        [*_arguments("check", scan_files), "--json", str(output), "--sarif", str(output)],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


def test_relative_parent_alias_of_an_export_is_rejected(scan_files, tmp_path):
    output = tmp_path / "combined.json"
    output.write_bytes(b"existing review artifact\n")
    Path("alias-dir").mkdir()
    before = {**_snapshot(scan_files), output: output.read_bytes()}
    result = runner.invoke(
        app,
        [
            *_arguments("check", scan_files),
            "--json",
            str(output),
            "--sarif",
            "alias-dir/../combined.json",
        ],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


def test_hardlinked_export_destinations_are_rejected(scan_files, tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.sarif"
    first.write_bytes(b"existing review artifact\n")
    try:
        second.hardlink_to(first)
    except OSError:
        pytest.skip("filesystem does not support creating hardlinks")
    before = {**_snapshot(scan_files), first: first.read_bytes(), second: second.read_bytes()}
    result = runner.invoke(
        app,
        [*_arguments("check", scan_files), "--json", str(first), "--sarif", str(second)],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


def test_hardlink_to_an_input_cannot_be_an_output(scan_files, tmp_path):
    output = tmp_path / "input-alias.json"
    try:
        output.hardlink_to(scan_files["input"])
    except OSError:
        pytest.skip("filesystem does not support creating hardlinks")
    before = {**_snapshot(scan_files), output: output.read_bytes()}
    result = runner.invoke(
        app,
        [*_arguments("normalize", scan_files), "--output", str(output)],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path case aliases")
def test_case_alias_of_an_export_is_rejected_on_windows(scan_files, tmp_path):
    output = tmp_path / "combined.json"
    alias = tmp_path / "COMBINED.JSON"
    output.write_bytes(b"existing review artifact\n")
    if not alias.exists():
        pytest.skip("directory uses case-sensitive filenames")
    before = {**_snapshot(scan_files), output: output.read_bytes()}
    result = runner.invoke(
        app,
        [*_arguments("check", scan_files), "--json", str(output), "--sarif", str(alias)],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


def test_a_later_linked_destination_does_not_change_the_first_export(
    scan_files, tmp_path, monkeypatch
):
    first = tmp_path / "first.json"
    unsafe = tmp_path / "linked.sarif"
    first.write_bytes(b"existing first artifact\n")
    before = {**_snapshot(scan_files), first: first.read_bytes()}
    original_is_symlink = Path.is_symlink

    def linked_path(path: Path) -> bool:
        return path == unsafe or original_is_symlink(path)

    # A filesystem double avoids requiring Windows symlink privileges. The CLI
    # and its actual write guard still run; no output writer is replaced.
    monkeypatch.setattr(Path, "is_symlink", linked_path)
    result = runner.invoke(
        app,
        [*_arguments("check", scan_files), "--json", str(first), "--sarif", str(unsafe)],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)
    assert not unsafe.exists()


@pytest.mark.parametrize("parent_first", (True, False), ids=("parent-first", "child-first"))
def test_export_destinations_cannot_be_a_file_and_its_descendant(
    scan_files, tmp_path, parent_first
):
    parent = tmp_path / "artifacts"
    child = parent / "scan.sarif"
    first, second = (parent, child) if parent_first else (child, parent)
    before = _snapshot(scan_files)
    result = runner.invoke(
        app,
        [*_arguments("check", scan_files), "--json", str(first), "--sarif", str(second)],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)
    assert not parent.exists()
    assert not child.exists()


def test_a_regular_file_ancestor_is_detected_before_any_export(scan_files, tmp_path):
    first = tmp_path / "first.json"
    ancestor = tmp_path / "not-a-directory"
    first.write_bytes(b"existing first artifact\n")
    ancestor.write_bytes(b"existing ancestor file\n")
    before = {
        **_snapshot(scan_files),
        first: first.read_bytes(),
        ancestor: ancestor.read_bytes(),
    }
    result = runner.invoke(
        app,
        [
            *_arguments("check", scan_files),
            "--json",
            str(first),
            "--sarif",
            str(ancestor / "scan.sarif"),
        ],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)


def test_a_directory_destination_is_detected_before_any_export(scan_files, tmp_path):
    first = tmp_path / "first.json"
    directory = tmp_path / "existing-directory"
    first.write_bytes(b"existing first artifact\n")
    directory.mkdir()
    before = {**_snapshot(scan_files), first: first.read_bytes()}
    result = runner.invoke(
        app,
        [*_arguments("check", scan_files), "--json", str(first), "--sarif", str(directory)],
    )

    assert result.exit_code == 2, result.output
    _assert_preserved(before)
    assert directory.is_dir()
    assert not list(directory.iterdir())


@pytest.mark.parametrize(
    ("threshold", "exit_code", "decision"),
    [("none", 0, "PASS"), ("high", 1, "BLOCK")],
)
def test_distinct_exports_preserve_the_gate_and_inputs(
    scan_files, tmp_path, threshold, exit_code, decision
):
    before = _snapshot(scan_files)
    outputs = {
        "--json": tmp_path / "out" / "findings.json",
        "--sarif": tmp_path / "out" / "scan.sarif",
        "--markdown": tmp_path / "out" / "report.md",
        "--pr-comment": tmp_path / "out" / "comment.md",
        "--remediation": tmp_path / "out" / "remediation.json",
    }
    arguments = [
        "scan",
        "check",
        "--input",
        str(scan_files["input"]),
        "--waivers",
        str(scan_files["waivers"]),
        "--rules",
        str(scan_files["rules"]),
        "--today",
        CHECK_DATE,
        "--fail-on",
        threshold,
        "--repository",
        "acme/example",
    ]
    for option, output in outputs.items():
        arguments.extend([option, str(output)])
    result = runner.invoke(app, arguments)

    assert result.exit_code == exit_code, result.output
    assert f"{decision}:" in result.stdout
    _assert_preserved(before)
    content = {option: output.read_text(encoding="utf-8") for option, output in outputs.items()}
    assert json.loads(content["--json"])["schema"] == "secguard.findings/v1"
    assert len(json.loads(content["--json"])["findings"]) == 1
    assert json.loads(content["--sarif"])["version"] == "2.1.0"
    assert "# secguard scan report" in content["--markdown"]
    assert f"### secguard: {decision}" in content["--pr-comment"]
    exchange = json.loads(content["--remediation"])
    assert exchange["schema"] == "secguard.remediation/v1"
    assert exchange["gate"]["decision"] == decision
    assert all(CANARY not in value for value in content.values())
