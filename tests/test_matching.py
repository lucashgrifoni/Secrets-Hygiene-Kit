"""Waiver scope matching semantics.

A waiver is a security exception, so an over-broad glob is a security bug.
These tests pin the directory-aware behaviour that `fnmatch` would not give.
"""

from __future__ import annotations

import pytest

from secguard.core.matching import path_matches, rule_matches


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("tests/fixtures/key.py", "tests/fixtures/key.py", True),
        ("tests/fixtures/key.py", "tests/fixtures/other.py", False),
        # `*` stays inside one path segment, so it cannot silently widen scope.
        ("tests/*", "tests/key.py", True),
        ("tests/*", "tests/nested/key.py", False),
        ("tests/**", "tests/nested/deep/key.py", True),
        ("**/fixtures/*.py", "tests/fixtures/key.py", True),
        ("**/fixtures/*.py", "a/b/c/fixtures/key.py", True),
        # `**/` also matches zero segments.
        ("**/key.py", "key.py", True),
        ("tests/fixtures/?ey.py", "tests/fixtures/key.py", True),
        ("tests/fixtures/?ey.py", "tests/fixtures/kkey.py", False),
        ("*", "key.py", True),
        ("*", "tests/key.py", False),
        ("**", "tests/nested/key.py", True),
        ("a/*/b", "a/b", False),
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/y/b", True),
        ("**/b", "a//b", False),
        ("?", "/", False),
        ("*", "", True),
        ("", "", True),
        ("[x]+(y)", "[x]+(y)", True),
        ("*.py", "ação.py", True),
        ("A.py", "a.py", False),
    ],
)
def test_path_matching_is_directory_aware(pattern, value, expected):
    assert path_matches(pattern, value) is expected


def test_windows_separators_are_normalized():
    assert path_matches("tests/fixtures/key.py", "tests\\fixtures\\key.py")


def test_glob_metacharacters_in_a_literal_path_do_not_widen_scope():
    assert path_matches("tests/a+b.py", "tests/a+b.py")
    assert not path_matches("tests/a+b.py", "tests/aab.py")


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("gitleaks:aws-access-token", "gitleaks:aws-access-token", True),
        ("gitleaks:aws-access-token", "gitleaks:github-pat", False),
        # Rule ids use `:`, not `/`, so `*` is free to span the separator.
        ("gitleaks:*", "gitleaks:aws-access-token", True),
        ("gitleaks:*", "trufflehog:AWS", False),
        ("*", "trufflehog:AWS", True),
        ("detect-secrets:AWS*", "detect-secrets:AWS Access Key", True),
    ],
)
def test_rule_matching(pattern, value, expected):
    assert rule_matches(pattern, value) is expected
