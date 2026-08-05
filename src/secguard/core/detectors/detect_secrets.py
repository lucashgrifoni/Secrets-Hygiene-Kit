"""Adapter for detect-secrets baseline and scan output.

Produced by ``detect-secrets scan > .secrets.baseline``.

Each result carries ``hashed_secret``, a SHA-1 digest of the credential. A
digest is not the credential, but SHA-1 of a low-entropy secret is recoverable
by brute force, so secguard does not propagate it. Fingerprints are derived
from location metadata instead, which costs some stability when code moves and
buys a canonical document that is safe to attach to a ticket.
"""

from __future__ import annotations

from typing import Any

from secguard.core.catalog import RuleCatalog
from secguard.core.detectors.base import (
    load_json,
    optional_bool,
    pick,
    positive_int,
    require_mapping,
    require_relative_path,
    require_text,
)
from secguard.core.findings import Finding, FindingDocument, FindingParseError, build_finding

SCANNER_NAME = "detect-secrets"


def looks_like_detect_secrets(content: Any) -> bool:
    """Return whether parsed JSON looks like a detect-secrets baseline."""
    return (
        isinstance(content, dict)
        and isinstance(content.get("results"), dict)
        and any(key in content for key in ("plugins_used", "version", "generated_at"))
    )


def parse_report(text: str, *, source: str, catalog: RuleCatalog) -> FindingDocument:
    """Parse a detect-secrets baseline into canonical findings."""
    content = load_json(text, source=source)

    if not isinstance(content, dict):
        raise FindingParseError(f"{source}: detect-secrets baselines must be a JSON object")

    results = content.get("results")
    if results is None:
        return FindingDocument()
    if not isinstance(results, dict):
        raise FindingParseError(f"{source}: detect-secrets `results` must be a JSON object")

    findings: list[Finding] = []
    index = 0

    for filename, entries in sorted(results.items()):
        if not isinstance(entries, list):
            raise FindingParseError(f"{source}: results for one file must be a JSON array")

        for entry in entries:
            findings.append(
                _build(
                    require_mapping(entry, source=source, index=index),
                    filename,
                    source,
                    index,
                    catalog,
                )
            )
            index += 1

    return FindingDocument(findings=findings)


def _build(
    entry: dict[str, Any],
    filename: str,
    source: str,
    index: int,
    catalog: RuleCatalog,
) -> Finding:
    secret_type = require_text(
        pick(entry, "type"),
        source=source,
        index=index,
        field="type",
    )
    path = require_relative_path(
        pick(entry, "filename") or filename,
        source=source,
        index=index,
    )

    return build_finding(
        scanner=SCANNER_NAME,
        rule_id=secret_type,
        path=path,
        message=f"detect-secrets plugin reported {secret_type}",
        catalog=catalog,
        line=positive_int(pick(entry, "line_number")),
        verified=optional_bool(pick(entry, "is_verified")),
    )
