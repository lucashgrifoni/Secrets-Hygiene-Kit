"""Symlink safety for every file secguard writes.

secguard runs inside a checkout it did not create, in CI, against content a
pull request controls. A symlinked output path — or a symlinked directory on
the way to it — turns `--sarif reports/secguard.sarif` into a write somewhere
the caller never named. Checking only the final component is not enough: the
last hop can be an ordinary file inside a directory that is itself a link.

The check stops at the working directory. Above it the layout belongs to the
operator who launched the run, and on some systems the temp directory is a
symlink by design; below it, the tree is whatever the checkout contains.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


class UnsafeWriteError(Exception):
    """Raised for a linked, unusable, or conflicting output destination."""


def assert_output_paths(outputs: list[Path], protected: list[Path]) -> None:
    """Check every export destination before the caller starts writing.

    Protected paths are read inputs and may legitimately be links. Only output
    paths receive the write guard. This detects present path conflicts, not
    concurrent changes, write permissions, or failures after writing begins.
    """
    for output in outputs:
        # Keep the original spelling: resolving first can hide `link/..`.
        assert_writable(output)
        _assert_file_destination(output)

    for index, output in enumerate(outputs):
        for previous in outputs[:index]:
            if _same_destination(output, previous):
                raise UnsafeWriteError(
                    "conflicting output destinations: "
                    f"{previous.as_posix()} and {output.as_posix()}"
                )
            resolved = _resolved_path(output)
            previous_resolved = _resolved_path(previous)
            if resolved.is_relative_to(previous_resolved) or previous_resolved.is_relative_to(
                resolved
            ):
                raise UnsafeWriteError(
                    "output destinations cannot be a file and its descendant: "
                    f"{previous.as_posix()} and {output.as_posix()}"
                )
        for source in protected:
            if _same_destination(output, source):
                raise UnsafeWriteError(
                    f"output conflicts with an input or policy file: {output.as_posix()}"
                )


def _assert_file_destination(path: Path) -> None:
    """Reject existing non-file destinations and non-directory ancestors."""
    # Walk from the root so `file/child` is rejected at the regular-file
    # ancestor before probing a descendant raises platform-specific errors.
    for parent in reversed(path.absolute().parents):
        information = _stat_if_present(parent)
        if information is not None and not stat.S_ISDIR(information.st_mode):
            raise UnsafeWriteError(f"output ancestor is not a directory: {parent.as_posix()}")
    information = _stat_if_present(path)
    if information is not None and not stat.S_ISREG(information.st_mode):
        raise UnsafeWriteError(f"output destination is not a regular file: {path.as_posix()}")


def _same_destination(first: Path, second: Path) -> bool:
    """Compare lexical/resolved aliases, then existing-file identity."""
    if Path(os.path.abspath(first)) == Path(os.path.abspath(second)):
        return True
    if _resolved_path(first) == _resolved_path(second):
        return True
    first_information = _stat_if_present(first)
    second_information = _stat_if_present(second)
    return (
        first_information is not None and second_information is not None and first.samefile(second)
    )


def _stat_if_present(path: Path) -> os.stat_result | None:
    """Allow absent paths while propagating access and other filesystem errors."""
    try:
        return path.stat()
    except FileNotFoundError:
        return None


def _resolved_path(path: Path) -> Path:
    try:
        return path.resolve()
    except RuntimeError as exc:
        # Python 3.12 reports resolution loops as RuntimeError rather than OSError.
        raise UnsafeWriteError(f"cannot resolve output or input path: {path.as_posix()}") from exc


def assert_writable(path: Path) -> None:
    """Raise when a path, or a directory leading to it, is a link."""
    # Check exactly the path the writer will open. A quoted '~' is a literal
    # directory for Path.write_text, so expanding it here would guard another file.
    target = path

    if is_link(target):
        raise UnsafeWriteError(f"refusing to write through a symlink: {target.as_posix()}")

    for parent in _parents_within_working_directory(target):
        if is_link(parent):
            raise UnsafeWriteError(
                f"refusing to write through a symlinked directory: {parent.as_posix()}"
            )


def is_link(path: Path) -> bool:
    """Return whether a path redirects elsewhere, by symlink or by junction.

    `Path.is_symlink()` is False for a Windows directory junction, which
    redirects exactly the same way and is the form `mklink /J` produces — and
    the one an unprivileged account can create, so it is the likelier of the
    two to appear in a checkout.
    """
    return path.is_symlink() or os.path.isjunction(path)


def _parents_within_working_directory(target: Path) -> list[Path]:
    """Return the target's ancestors that sit under the current working directory.

    Every comparison here is lexical. Resolving a path would follow the symlink
    this module exists to detect, so a link pointing outside the tree would be
    judged "not inside the tree" and skipped — exactly backwards.
    """
    try:
        root = Path.cwd()
    except OSError:  # pragma: no cover - unreadable working directory
        return []

    absolute = target if target.is_absolute() else root / target
    # The OS traverses `link/..` through the link first. Preserve those
    # components while checking; normpath would hide that redirect.
    return [parent for parent in absolute.parents if parent.is_relative_to(root) and parent != root]
