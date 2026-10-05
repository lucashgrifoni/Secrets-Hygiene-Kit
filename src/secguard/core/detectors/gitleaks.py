"""Adapter for gitleaks JSON reports.

Produced by ``gitleaks detect --report-format json --report-path gitleaks.json``.

The report contains the credential itself in ``Secret`` and ``Match``, and may
contain it again inside the commit ``Message``. This adapter reads an explicit
allowlist of metadata keys and never touches those fields.
"""

from __future__ import annotations

import hashlib
from typing import Any

from secguard.core.catalog import RuleCatalog
from secguard.core.detectors.base import (
    load_json,
    pick,
    positive_int,
    require_mapping,
    require_relative_path,
    require_text,
)
from secguard.core.findings import Finding, FindingDocument, FindingParseError, build_finding
from secguard.core.redaction import sanitize_commit, sanitize_text

SCANNER_NAME = "gitleaks"


def looks_like_gitleaks(content: Any) -> bool:
    """Return whether parsed JSON looks like a gitleaks report."""
    if not isinstance(content, list):
        return False
    if not content:
        # An empty array is a clean gitleaks report; treat it as a match so a
        # passing scan does not fail format detection.
        return True
    first = content[0]
    return isinstance(first, dict) and any(
        key in first for key in ("RuleID", "ruleID", "Fingerprint", "StartLine")
    )


def parse_report(text: str, *, source: str, catalog: RuleCatalog) -> FindingDocument:
    """Parse a gitleaks JSON report into canonical findings."""
    content = load_json(text, source=source)

    if not isinstance(content, list):
        raise FindingParseError(f"{source}: gitleaks reports must be a JSON array")

    findings: list[Finding] = [
        _build(require_mapping(entry, source=source, index=index), source, index, catalog)
        for index, entry in enumerate(content)
    ]
    return FindingDocument(findings=findings)


def _build(entry: dict[str, Any], source: str, index: int, catalog: RuleCatalog) -> Finding:
    rule_id = require_text(
        pick(entry, "RuleID", "ruleID", "rule_id"),
        source=source,
        index=index,
        field="RuleID",
    )
    path = require_relative_path(
        pick(entry, "File", "file"),
        source=source,
        index=index,
    )
    description = pick(entry, "Description", "description")

    return build_finding(
        scanner=SCANNER_NAME,
        rule_id=rule_id,
        path=path,
        message=(
            sanitize_text(description)
            if isinstance(description, str) and description.strip()
            else f"gitleaks rule {rule_id} matched"
        ),
        catalog=catalog,
        line=positive_int(pick(entry, "StartLine", "startLine")),
        column=positive_int(pick(entry, "StartColumn", "startColumn")),
        fingerprint=_fingerprint(entry),
        commit=sanitize_commit(pick(entry, "Commit", "commit")),
    )


def _fingerprint(entry: dict[str, Any]) -> str | None:
    """Use the gitleaks fingerprint, which encodes path, rule, and line only."""
    value = pick(entry, "Fingerprint", "fingerprint")
    if not isinstance(value, str) or not value.strip():
        return None
    safe = sanitize_text(value, max_length=max(160, len(value)))
    if len(safe) > 160:
        return f"gitleaks:sha256:{hashlib.sha256(safe.encode('utf-8')).hexdigest()}"
    return f"gitleaks:{safe}"
