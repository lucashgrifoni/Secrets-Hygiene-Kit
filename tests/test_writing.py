"""Symlink safety for every file secguard writes.

The README promises secguard "never writes through a symlinked directory", and
until now only the final path component was checked, so a symlinked *directory*
on the way to the target sent the write wherever it pointed. secguard runs in
CI against a checkout a pull request controls, which is exactly where that link
would come from.

Creating a symlink on Windows needs a privilege most accounts do not have, so
the traversal logic is covered without touching the filesystem and the
real-filesystem behaviour is covered wherever symlinks can actually be made.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from secguard.core.writing import UnsafeWriteError, assert_writable


def _symlinks_available() -> bool:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "real").mkdir()
        try:
            os.symlink(root / "real", root / "link", target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError):
            return False
        return True


SYMLINKS = pytest.mark.skipif(
    not _symlinks_available(), reason="this account cannot create symlinks"
)


def _pretend_symlink(monkeypatch, *targets: Path) -> None:
    """Make specific paths report as symlinks without needing the privilege."""
    marked = {Path(os.path.normpath(target)) for target in targets}
    real = Path.is_symlink
    monkeypatch.setattr(
        Path, "is_symlink", lambda self: Path(os.path.normpath(self)) in marked or real(self)
    )


def test_an_ordinary_path_is_writable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert_writable(tmp_path / "reports" / "out.sarif")  # must not raise
    assert_writable(Path("reports/out.sarif"))


def test_a_symlinked_target_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "out.sarif"
    _pretend_symlink(monkeypatch, target)

    with pytest.raises(UnsafeWriteError, match="write through a symlink"):
        assert_writable(target)


def test_a_symlinked_directory_on_the_way_is_refused(tmp_path, monkeypatch):
    """The final component can be an ordinary file inside a linked directory."""
    monkeypatch.chdir(tmp_path)
    _pretend_symlink(monkeypatch, tmp_path / "reports")

    with pytest.raises(UnsafeWriteError, match="symlinked directory"):
        assert_writable(tmp_path / "reports" / "nested" / "out.sarif")


def test_a_relative_path_is_checked_the_same_way(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _pretend_symlink(monkeypatch, tmp_path / "reports")

    with pytest.raises(UnsafeWriteError, match="symlinked directory"):
        assert_writable(Path("reports/out.sarif"))


def test_directories_above_the_working_directory_are_not_the_tools_business(tmp_path, monkeypatch):
    """A symlinked temp or home directory is the operator's layout, not an attack.

    Walking to the filesystem root would refuse to write anywhere on a machine
    where `/tmp` is a link, which is the default on macOS.
    """
    working = tmp_path / "checkout"
    working.mkdir()
    monkeypatch.chdir(working)
    _pretend_symlink(monkeypatch, tmp_path)

    assert_writable(working / "reports" / "out.sarif")  # must not raise


@SYMLINKS
def test_a_real_symlinked_directory_cannot_be_written_through(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    working = tmp_path / "checkout"
    working.mkdir()
    os.symlink(outside, working / "reports", target_is_directory=True)
    monkeypatch.chdir(working)

    with pytest.raises(UnsafeWriteError):
        assert_writable(Path("reports/out.sarif"))

    assert list(outside.iterdir()) == []


@SYMLINKS
def test_a_real_symlinked_file_cannot_be_overwritten(tmp_path, monkeypatch):
    outside = tmp_path / "outside.sarif"
    outside.write_text("original", encoding="utf-8")
    working = tmp_path / "checkout"
    working.mkdir()
    os.symlink(outside, working / "out.sarif")
    monkeypatch.chdir(working)

    with pytest.raises(UnsafeWriteError):
        assert_writable(Path("out.sarif"))

    assert outside.read_text(encoding="utf-8") == "original"
