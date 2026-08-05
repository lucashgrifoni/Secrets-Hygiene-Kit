"""Scanner adapters that normalize detector reports into canonical findings.

secguard reads reports; it never executes a scanner. Keeping detection outside
the tool means secguard does not pin, ship, or trust a scanner binary, and it
makes every adapter deterministically testable against a redacted fixture.

Typical use in CI:

```bash
gitleaks detect --report-format json --report-path gitleaks.json || true
trufflehog git file://. --json > trufflehog.jsonl || true
secguard scan --input gitleaks.json --input trufflehog.jsonl --fail-on high
```
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, get_args

from secguard.core.catalog import RuleCatalog, load_catalog
from secguard.core.detectors import detect_secrets, gitleaks, trufflehog
from secguard.core.findings import (
    FindingDocument,
    FindingFileNotFound,
    FindingParseError,
    load_synthetic_scan_file,
    merge_findings,
)

ReportFormat = Literal["auto", "gitleaks", "trufflehog", "detect-secrets", "synthetic"]

SUPPORTED_FORMATS: tuple[str, ...] = tuple(
    name for name in get_args(ReportFormat) if name != "auto"
)

SYNTHETIC_SCHEMA_KEY = "secguard.synthetic-findings/v1"

__all__ = [
    "SUPPORTED_FORMATS",
    "ReportFormat",
    "detect_format",
    "load_report",
    "load_reports",
]


def load_reports(
    paths: list[Path],
    *,
    report_format: ReportFormat = "auto",
    catalog: RuleCatalog | None = None,
) -> FindingDocument:
    """Load one or more scanner reports and merge them into one canonical document."""
    if not paths:
        raise FindingParseError("at least one scanner report is required")

    resolved_catalog = catalog or load_catalog()
    documents = [
        load_report(path, report_format=report_format, catalog=resolved_catalog) for path in paths
    ]
    return merge_findings(documents)


def load_report(
    path: Path,
    *,
    report_format: ReportFormat = "auto",
    catalog: RuleCatalog | None = None,
) -> FindingDocument:
    """Load a single scanner report into canonical findings."""
    if not path.exists():
        raise FindingFileNotFound(f"finding file not found: {path}")
    if not path.is_file():
        raise FindingFileNotFound(f"finding path is not a file: {path}")

    resolved_catalog = catalog or load_catalog()
    text = path.read_text(encoding="utf-8")
    resolved_format = report_format if report_format != "auto" else detect_format(text, source=path)

    if resolved_format == "synthetic":
        return load_synthetic_scan_file(path, resolved_catalog)
    if resolved_format == "gitleaks":
        return gitleaks.parse_report(text, source=str(path), catalog=resolved_catalog)
    if resolved_format == "trufflehog":
        return trufflehog.parse_report(text, source=str(path), catalog=resolved_catalog)
    if resolved_format == "detect-secrets":
        return detect_secrets.parse_report(text, source=str(path), catalog=resolved_catalog)

    raise FindingParseError(f"unsupported report format: {resolved_format}")


def detect_format(text: str, *, source: Path | str) -> str:
    """Infer the report format from its structure, never from the file name."""
    stripped = text.strip()
    if not stripped:
        raise FindingParseError(f"{source}: report file is empty")

    content = _probe(stripped)

    if isinstance(content, dict) and content.get("schema") == SYNTHETIC_SCHEMA_KEY:
        return "synthetic"
    if detect_secrets.looks_like_detect_secrets(content):
        return "detect-secrets"
    if gitleaks.looks_like_gitleaks(content):
        return "gitleaks"
    if trufflehog.looks_like_trufflehog(content):
        return "trufflehog"

    raise FindingParseError(
        f"{source}: could not infer the scanner format; "
        f"pass --format with one of: {', '.join(SUPPORTED_FORMATS)}"
    )


def _probe(stripped: str) -> object:
    """Parse enough of the payload to identify the format, tolerating JSON Lines."""
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    first_line = next(iter(trufflehog.split_json_lines(stripped)), None)
    if first_line is None:
        raise FindingParseError("report file contains no JSON payload")

    try:
        return [json.loads(first_line)]
    except json.JSONDecodeError as exc:
        raise FindingParseError(f"invalid JSON in report file: line {exc.lineno}") from exc
