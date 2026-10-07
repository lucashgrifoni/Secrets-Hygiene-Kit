"""Betterleaks 1.x JSON array adapter; producer execution stays outside secguard.

Only Gitleaks-compatible metadata and ValidationStatus are read. Secret,
MatchContext, CaptureGroups, ComponentSets and validation metadata are ignored.
The v2 envelope is intentionally rejected until it has its own tested contract.
"""

from __future__ import annotations

from secguard.core.catalog import RuleCatalog
from secguard.core.detectors.base import load_json, require_mapping
from secguard.core.detectors.gitleaks import _build
from secguard.core.findings import FindingDocument, FindingParseError

SCANNER_NAME = "betterleaks"
_STATUS_FLAGS = {
    "": None,
    "valid": True,
    "invalid": False,
    "revoked": False,
    "unknown": None,
    "error": None,
    "needs_validation": None,
}


def parse_report(text: str, *, source: str, catalog: RuleCatalog) -> FindingDocument:
    content = load_json(text, source=source)
    if not isinstance(content, list):
        raise FindingParseError(f"{source}: Betterleaks 1.x reports must be a JSON array")
    findings = []
    for index, item in enumerate(content):
        entry = require_mapping(item, source=source, index=index)
        status = entry.get("ValidationStatus", "")
        if not isinstance(status, str) or status not in _STATUS_FLAGS:
            raise FindingParseError(f"{source}: entry {index}: unsupported ValidationStatus")
        findings.append(
            _build(
                entry, source, index, catalog, scanner=SCANNER_NAME, verified=_STATUS_FLAGS[status]
            )
        )
    return FindingDocument(findings=findings)
