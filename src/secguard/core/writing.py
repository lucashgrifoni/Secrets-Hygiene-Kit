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
from pathlib import Path


class UnsafeWriteError(Exception):
    """Raised when a write would follow a symlink out of the intended tree."""


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
