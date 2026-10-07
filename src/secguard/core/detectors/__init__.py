"""Scanner adapters that normalize detector reports into canonical findings.

secguard reads reports; it never executes a scanner. Keeping detection outside
the tool means secguard does not pin, ship, or trust a scanner binary, and it
makes every adapter deterministically testable against a redacted fixture.

Typical use in CI:

```bash
gitleaks git --exit-code 0 --report-format json --report-path gitleaks.json
trufflehog git file://. --json --fail-on-scan-errors > trufflehog.jsonl
secguard scan check --input gitleaks.json --input trufflehog.jsonl --fail-on high
```
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, get_args

from secguard.core.catalog import RuleCatalog, load_catalog
from secguard.core.detectors import betterleaks, canonical, detect_secrets, gitleaks, trufflehog
from secguard.core.findings import (
    FindingDocument,
    FindingFileNotFound,
    FindingParseError,
    load_synthetic_scan_file,
    merge_findings,
    read_bounded_report,
)

ReportFormat = Literal[
    "auto", "gitleaks", "trufflehog", "detect-secrets", "synthetic", "canonical", "betterleaks"
]

SUPPORTED_FORMATS: tuple[str, ...] = tuple(
    name for name in get_args(ReportFormat) if name != "auto"
)

SYNTHETIC_SCHEMA_KEY = "secguard.synthetic-findings/v1"

__all__ = [
    "SUPPORTED_FORMATS",
    "ReportFormat",
    "detect_format",
    "is_empty_report",
    "load_report",
    "load_reports",
    "read_report_text",
]


def is_empty_report(path: Path) -> bool:
    """Return whether a readable report file carries no payload at all.

    A detector that finds nothing still writes a file. gitleaks writes ``[]``
    and detect-secrets writes an empty ``results`` map, but trufflehog writes
    JSON Lines, and zero findings means zero lines — an empty file. Callers use
    this to tell the operator which inputs were blank, because an empty report
    is also what a detector that crashed leaves behind.
    """
    # A file that cannot be read at all is not "empty" — saying so would print
    # a note contradicting the error the loader is about to raise.
    try:
        return path.is_file() and not read_report_text(path).strip()
    except (FindingParseError, OSError, UnicodeDecodeError):
        return False


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

    if report_format not in ("auto", *SUPPORTED_FORMATS):
        raise FindingParseError("unsupported report format")

    resolved_catalog = catalog or load_catalog()
    text = read_report_text(path)

    # A clean trufflehog run writes JSON Lines with no lines, which is a
    # zero-byte file. Rejecting it as bad input would fail the gate on exactly
    # the repositories that have nothing to report, while the equivalent clean
    # gitleaks (`[]`) and detect-secrets (empty `results`) reports pass. The CLI
    # names every empty input so a detector that crashed is still visible.
    if not text.strip():
        if report_format in {"auto", "trufflehog"}:
            return FindingDocument()
        raise FindingParseError(f"{path}: {report_format} requires a JSON payload")

    resolved_format = report_format if report_format != "auto" else detect_format(text, source=path)

    if resolved_format == "synthetic":
        return load_synthetic_scan_file(path, resolved_catalog)
    if resolved_format == "canonical":
        return canonical.parse_report(text, source=str(path), catalog=resolved_catalog)
    if resolved_format == "betterleaks":
        return betterleaks.parse_report(text, source=str(path), catalog=resolved_catalog)
    if resolved_format == "gitleaks":
        return gitleaks.parse_report(text, source=str(path), catalog=resolved_catalog)
    if resolved_format == "trufflehog":
        return trufflehog.parse_report(text, source=str(path), catalog=resolved_catalog)
    if resolved_format == "detect-secrets":
        return detect_secrets.parse_report(text, source=str(path), catalog=resolved_catalog)

    raise FindingParseError(f"unsupported report format: {resolved_format}")


def read_report_text(path: Path) -> str:
    """Read a report as UTF-8, turning every read failure into an input error.

    Detector reports are UTF-8 by convention, but a scanner run under a
    different locale, a truncated upload, or a file the runner cannot open all
    reach here. Each of those used to escape as a traceback with exit `1` — the
    code that means "the gate blocked on purpose" — so a CI log reported a
    security decision that was never made.
    """
    try:
        return read_bounded_report(path)
    except UnicodeDecodeError as exc:
        raise FindingParseError(
            f"{path}: report is not valid UTF-8 (byte {exc.start}); "
            "have the detector write UTF-8, which is what every supported format uses"
        ) from exc
    except OSError as exc:
        raise FindingParseError(f"cannot read report {path}: {exc.strerror or exc}") from exc


def detect_format(text: str, *, source: Path | str) -> str:
    """Infer the report format from its structure, never from the file name."""
    stripped = text.strip()
    if not stripped:
        raise FindingParseError(f"{source}: report file is empty")

    content = _probe(stripped, source=source)

    if isinstance(content, dict) and content.get("schema") == SYNTHETIC_SCHEMA_KEY:
        return "synthetic"
    if isinstance(content, dict) and content.get("schema") == "secguard.findings/v1":
        return "canonical"
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


def _probe(stripped: str, *, source: Path | str) -> object:
    """Parse enough of the payload to identify the format, tolerating JSON Lines.

    Every error names the file. With several `--input` reports in one run, an
    error that says only "invalid JSON" leaves the operator to bisect by hand.
    """
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    except RecursionError as exc:
        raise FindingParseError(f"{source}: JSON is nested too deeply to parse") from exc
    except ValueError as exc:
        raise FindingParseError(f"{source}: JSON contains an unsupported numeric value") from exc

    first_line = next(iter(trufflehog.split_json_lines(stripped)), None)
    if first_line is None:
        raise FindingParseError(f"{source}: report contains no JSON payload")

    try:
        return [json.loads(first_line)]
    except json.JSONDecodeError as exc:
        raise FindingParseError(
            f"{source}: invalid JSON on the first payload line (column {exc.colno}: {exc.msg})"
        ) from exc
    except RecursionError as exc:
        raise FindingParseError(f"{source}: JSON is nested too deeply to parse") from exc
    except ValueError as exc:
        raise FindingParseError(f"{source}: JSON contains an unsupported numeric value") from exc
