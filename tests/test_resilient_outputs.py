"""Publication failure boundaries and an independently checked completion marker."""

from __future__ import annotations

import io
import json
import os

import pytest
from typer.testing import CliRunner

from secguard.cli.app import app
from secguard.core import writing


@pytest.mark.parametrize(
    "error", [OSError("disk full"), PermissionError("denied"), KeyboardInterrupt()]
)
def test_failed_flush_preserves_previous_destination_and_cleans_temporary(
    tmp_path, monkeypatch, error
):
    destination = tmp_path / "report.json"
    destination.write_bytes(b"previous complete report")
    monkeypatch.setattr(writing.os, "fsync", lambda *_: (_ for _ in ()).throw(error))
    with pytest.raises(type(error)):
        writing.write_outputs([(destination, "new report")])
    assert destination.read_bytes() == b"previous complete report"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["report.json"]


def test_failed_staging_does_not_change_any_previous_artifact_or_marker(tmp_path, monkeypatch):
    first, second, marker = [tmp_path / name for name in ("first", "second", "manifest")]
    writing.write_outputs([(first, "old one"), (second, "old two")], manifest=marker)
    before = {path: path.read_bytes() for path in (first, second, marker)}
    original = writing._stage_output

    def fail_second(path, content):
        if path == second:
            raise OSError("full disk while staging")
        return original(path, content)

    monkeypatch.setattr(writing, "_stage_output", fail_second)
    with pytest.raises(OSError):
        writing.write_outputs([(first, "new one"), (second, "new two")], manifest=marker)
    assert {path: path.read_bytes() for path in before} == before
    assert not list(tmp_path.glob(".secguard-*.tmp"))


@pytest.mark.parametrize("error", [PermissionError("destination busy"), KeyboardInterrupt()])
def test_interrupted_publication_invalidates_old_marker_and_keeps_files_whole(
    tmp_path, monkeypatch, error
):
    first, second, marker = [tmp_path / name for name in ("first", "second", "manifest")]
    writing.write_outputs([(first, "old one"), (second, "old two")], manifest=marker)
    replace = os.replace

    def fail_second(source, destination):
        if destination == second:
            raise error
        replace(source, destination)

    monkeypatch.setattr(writing.os, "replace", fail_second)
    with pytest.raises(type(error)):
        writing.write_outputs([(first, "new one"), (second, "new two")], manifest=marker)
    assert first.read_text() == "new one"
    assert second.read_text() == "old two"
    assert not marker.exists()
    assert not list(tmp_path.glob(".secguard-*.tmp"))
    monkeypatch.setattr(writing.os, "replace", replace)
    writing.write_outputs([(first, "new one"), (second, "new two")], manifest=marker)
    assert writing.verify_output_manifest(marker)["complete"] is True


@pytest.mark.parametrize("gate", ["PASS", "BLOCK"])
def test_marker_checks_exact_utf8_bytes_and_detects_a_stale_or_modified_set(tmp_path, gate):
    artifact, marker = tmp_path / "report", tmp_path / "manifest"
    writing.write_outputs([(artifact, "ação\nअभ्यास\n")], manifest=marker, gate=gate)
    result = writing.verify_output_manifest(marker)
    assert result["gate"] == gate
    assert result["artifacts"][0]["bytes"] == len(artifact.read_bytes())
    artifact.write_bytes(b"modified by a later run")
    with pytest.raises(writing.UnsafeWriteError, match="incomplete"):
        writing.verify_output_manifest(marker)


@pytest.mark.parametrize("payload", ["{}", "[]", "null", '{"gate": []}', "\xff", "{" * 2000])
def test_untrusted_marker_fails_closed(tmp_path, payload):
    marker = tmp_path / "manifest"
    marker.write_text(payload, encoding="utf-8")
    with pytest.raises(writing.UnsafeWriteError):
        writing.verify_output_manifest(marker)


def test_cli_marker_distinguishes_complete_blocked_artifacts_from_passing_policy(tmp_path):
    raw, output, marker = [tmp_path / name for name in ("raw.json", "output.json", "manifest.json")]
    raw.write_text(
        json.dumps([{"RuleID": "aws-access-token", "File": "src/app.py", "StartLine": 2}])
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", "check", "-i", str(raw), "--json", str(output), "--output-manifest", str(marker)],
    )
    assert result.exit_code == 1, result.output
    assert writing.verify_output_manifest(marker)["gate"] == "BLOCK"
    verified = runner.invoke(app, ["scan", "verify-outputs", "--manifest", str(marker)])
    assert verified.exit_code == 0
    assert "gate=BLOCK" in verified.output
    output.write_text("truncated")
    assert runner.invoke(app, ["scan", "verify-outputs", "--manifest", str(marker)]).exit_code == 2


def test_marker_cannot_overwrite_an_input_and_requires_an_export(tmp_path):
    raw = tmp_path / "input.json"
    raw.write_text("[]")
    runner = CliRunner()
    for args in (
        ["--output-manifest", str(raw), "--json", str(tmp_path / "out.json")],
        ["--output-manifest", str(tmp_path / "marker")],
    ):
        assert runner.invoke(app, ["scan", "check", "-i", str(raw), *args]).exit_code == 2
    assert raw.read_text() == "[]"
    assert not (tmp_path / "out.json").exists()


def test_cli_processing_failure_is_exit_two_without_success_summary(tmp_path, monkeypatch):
    raw, output = tmp_path / "raw.json", tmp_path / "output.json"
    raw.write_text("[]")
    output.write_text("old")
    monkeypatch.setattr(writing.os, "replace", lambda *_: (_ for _ in ()).throw(PermissionError()))
    result = CliRunner().invoke(app, ["scan", "check", "-i", str(raw), "--json", str(output)])
    assert result.exit_code == 2
    assert "PASS:" not in result.output
    assert "wrote\t" not in result.output
    assert output.read_text() == "old"


def test_real_partial_write_failure_never_truncates_the_previous_report(tmp_path, monkeypatch):
    """The same public CLI regression fails on the 1.0 implementation."""
    raw, destination = tmp_path / "raw.json", tmp_path / "report.json"
    raw.write_text("[]")
    destination.write_bytes(b"previous complete report")
    original = io.open

    class FailingWriter:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, value):
            self.stream.write(value[:5])
            self.stream.flush()
            raise OSError("simulated disk exhaustion after partial write")

    def failing_open(file, mode="r", *args, **kwargs):
        stream = original(file, mode, *args, **kwargs)
        return FailingWriter(stream) if "w" in mode else stream

    monkeypatch.setattr(io, "open", failing_open)
    result = CliRunner().invoke(app, ["scan", "normalize", "-i", str(raw), "-o", str(destination)])
    assert result.exit_code == 2
    assert destination.read_bytes() == b"previous complete report"
    assert not list(tmp_path.glob(".secguard-*.tmp"))
