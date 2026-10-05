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

from functools import lru_cache

__all__ = [
    "MAX_WILDCARDS",
    "PatternTooComplex",
    "assert_pattern_is_simple",
    "path_matches",
    "rule_matches",
]

# Preserve the existing scope-review policy. Runtime safety no longer depends
# on this limit: even an allowed four-star pattern backtracked for seconds.
MAX_WILDCARDS = 4


class PatternTooComplex(ValueError):
    """Raised when a waiver pattern has more wildcards than are defensible."""


def assert_pattern_is_simple(pattern: str, *, field: str) -> None:
    """Keep waiver patterns within the existing scope-review budget."""
    wildcards = pattern.count("*") + pattern.count("?")
    if wildcards > MAX_WILDCARDS:
        raise PatternTooComplex(
            f"{field} has {wildcards} wildcards; secguard allows at most {MAX_WILDCARDS}, "
            "to keep exception scopes reviewable"
        )


def path_matches(pattern: str, value: str) -> bool:
    """Return whether a repository-relative path matches a waiver path pattern."""
    return _match(_tokens(pattern, path=True), value.replace("\\", "/"))


def rule_matches(pattern: str, value: str) -> bool:
    """Return whether a rule identifier matches a waiver rule pattern.

    Rule identifiers use ``:`` rather than ``/`` as a separator, so ``*`` is
    free to match anything: ``gitleaks:*`` waives every gitleaks rule.
    """
    return _match(_tokens(pattern, path=False), value)


@lru_cache(maxsize=512)
def _tokens(pattern: str, *, path: bool) -> tuple[tuple[str, str], ...]:
    tokens: list[tuple[str, str]] = []
    index = 0
    while index < len(pattern):
        if path and pattern.startswith("**/", index):
            tokens.append(("directories", ""))
            while pattern.startswith("**/", index):
                index += 3
        elif path and pattern.startswith("**", index):
            tokens.append(("star", ""))
            index += 2
        elif pattern[index] == "*":
            tokens.append(("segment-star" if path else "star", ""))
            index += 1
        elif pattern[index] == "?":
            tokens.append(("segment-one" if path else "one", ""))
            index += 1
        else:
            end = index + 1
            while end < len(pattern) and pattern[end] not in "*?":
                end += 1
            tokens.append(("literal", pattern[index:end]))
            index = end
    return tuple(tokens)


def _match(tokens: tuple[tuple[str, str], ...], value: str) -> bool:
    """Match reachable prefixes in O(tokens * value) time and O(value) space."""
    if not tokens:
        return not value
    if len(tokens) == 1 and tokens[0][0] == "literal":
        return tokens[0][1] == value
    previous = [True] + [False] * len(value)
    for kind, literal in tokens:
        current = [False] * (len(value) + 1)
        if kind in {"star", "segment-star"}:
            current[0] = previous[0]
            for index, character in enumerate(value):
                current[index + 1] = previous[index + 1] or (
                    current[index] and (kind == "star" or character != "/")
                )
        elif kind == "directories":
            current = previous.copy()  # Zero directories is a valid match.
            in_segment = False
            for index, character in enumerate(value):
                if character == "/":
                    current[index + 1] = current[index + 1] or in_segment
                    in_segment = False
                else:
                    in_segment = in_segment or previous[index] or current[index]
        elif kind == "literal":
            size = len(literal)
            for index, reachable in enumerate(previous):
                if reachable and value.startswith(literal, index):
                    current[index + size] = True
        else:
            for index, character in enumerate(value):
                matches = kind == "one" or character != "/"
                current[index + 1] = previous[index] and matches
        previous = current
    return previous[-1]
