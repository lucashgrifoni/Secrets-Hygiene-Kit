"""Glob matching with directory-aware semantics for waiver scope.

A waiver is a security exception, so its scope must be predictable. Python's
``fnmatch`` lets ``*`` cross directory separators, which silently turns
``src/*`` into "everything under src, recursively". These helpers use git-style
semantics instead:

- ``*`` matches within one path segment
- ``**`` matches across segments
- ``**/`` also matches zero segments, so ``**/fixture.py`` matches a top-level
  ``fixture.py``
- ``?`` matches one character within a segment
"""

from __future__ import annotations

import re
from functools import lru_cache

__all__ = ["path_matches", "rule_matches"]


def path_matches(pattern: str, value: str) -> bool:
    """Return whether a repository-relative path matches a waiver path pattern."""
    return _path_regex(pattern).match(value.replace("\\", "/")) is not None


def rule_matches(pattern: str, value: str) -> bool:
    """Return whether a rule identifier matches a waiver rule pattern.

    Rule identifiers use ``:`` rather than ``/`` as a separator, so ``*`` is
    free to match anything: ``gitleaks:*`` waives every gitleaks rule.
    """
    return _rule_regex(pattern).match(value) is not None


@lru_cache(maxsize=512)
def _path_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(_translate_path(pattern), re.DOTALL)


@lru_cache(maxsize=512)
def _rule_regex(pattern: str) -> re.Pattern[str]:
    translated = "".join(
        ".*" if character == "*" else "." if character == "?" else re.escape(character)
        for character in pattern
    )
    return re.compile(f"^{translated}$", re.DOTALL)


def _translate_path(pattern: str) -> str:
    parts: list[str] = ["^"]
    index = 0
    length = len(pattern)

    while index < length:
        character = pattern[index]

        if character == "*":
            if pattern.startswith("**/", index):
                parts.append("(?:[^/]+/)*")
                index += 3
                continue
            if pattern.startswith("**", index):
                parts.append(".*")
                index += 2
                continue
            parts.append("[^/]*")
            index += 1
            continue

        if character == "?":
            parts.append("[^/]")
            index += 1
            continue

        parts.append(re.escape(character))
        index += 1

    parts.append("$")
    return "".join(parts)
