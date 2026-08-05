"""Shared fixtures and the redaction canary used across the test suite."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from secguard.core.catalog import load_catalog

FIXTURES = Path(__file__).parent / "fixtures"

GITLEAKS_REPORT = FIXTURES / "gitleaks-report.json"
TRUFFLEHOG_REPORT = FIXTURES / "trufflehog-report.jsonl"
DETECT_SECRETS_BASELINE = FIXTURES / "detect-secrets-baseline.json"
SYNTHETIC_REPORT = FIXTURES / "synthetic-findings.json"

ALL_REPORTS = [GITLEAKS_REPORT, TRUFFLEHOG_REPORT, DETECT_SECRETS_BASELINE]

# Every value the fixtures carry that must never reach secguard output. The
# canary strings stand in for credentials; the rest are real detector fields
# that carry secret or personal data (commit message text, author email, and
# the detect-secrets SHA-1 digest of the credential).
FORBIDDEN_IN_OUTPUT = (
    "SECGUARD-CANARY-DO-NOT-EMIT-0001",
    "SECGUARD-CANARY-DO-NOT-EMIT-0002",
    "SECGUARD-CANARY-DO-NOT-EMIT-0003",
    "SECGUARD-CANARY-DO-NOT-EMIT-0004",
    "dev@example.invalid",
    "1f2d3c4b5a69788796a5b4c3d2e1f00918273645",
    "abcdef0123456789abcdef0123456789abcdef01",
)

TODAY = date(2026, 8, 4)


@pytest.fixture(scope="session")
def catalog():
    """The packaged rule catalog."""
    return load_catalog()


@pytest.fixture
def today() -> date:
    """A fixed date so every lifecycle assertion is deterministic."""
    return TODAY


def assert_no_secret_material(text: str) -> None:
    """Fail when any forbidden fixture value appears in rendered output."""
    for forbidden in FORBIDDEN_IN_OUTPUT:
        assert forbidden not in text, f"secret-bearing value leaked into output: {forbidden[:24]}"


def write_waiver_file(path: Path, body: str) -> Path:
    """Write a waiver YAML file and return its path."""
    path.write_text(body, encoding="utf-8")
    return path
