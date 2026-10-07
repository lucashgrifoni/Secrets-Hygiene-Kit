"""Adapter for trufflehog JSON output.

Produced by ``trufflehog git file://. --json`` (JSON Lines) or by tooling that
collects those lines into a JSON array. Both shapes are accepted.

trufflehog carries the credential in ``Raw``, ``RawV2``, ``Redacted``, and
sometimes inside ``ExtraData``; the git source metadata also carries the commit
author's email address. None of those keys are read here.

trufflehog can verify credentials against the provider. An imported
``Verified: true`` result reports verification at the detector's scan time,
so secguard escalates it to critical severity without contacting the provider.
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
from secguard.core.redaction import sanitize_commit

SCANNER_NAME = "trufflehog"

# Source containers trufflehog nests location metadata under.
_SOURCE_KEYS = ("Git", "Filesystem", "Github", "GitHub", "Gitlab", "S3", "Docker")


def looks_like_trufflehog(content: Any) -> bool:
    """Return whether parsed JSON looks like trufflehog output."""
    entries = content if isinstance(content, list) else [content]
    if not entries:
        return False
    first = entries[0]
    return isinstance(first, dict) and (
        "DetectorName" in first or "SourceMetadata" in first or "DetectorType" in first
    )


def split_json_lines(text: str) -> list[str]:
    """Return non-empty lines from a JSON Lines payload."""
    return [line for line in (raw.strip() for raw in text.splitlines()) if line]


def parse_report(text: str, *, source: str, catalog: RuleCatalog) -> FindingDocument:
    """Parse trufflehog JSON Lines or JSON array output into canonical findings."""
    entries = _load_entries(text, source=source)

    findings: list[Finding] = [
        _build(require_mapping(entry, source=source, index=index), source, index, catalog)
        for index, entry in enumerate(entries)
    ]
    return FindingDocument(findings=findings)


def _load_entries(text: str, *, source: str) -> list[Any]:
    stripped = text.strip()
    if not stripped:
        return []

    if stripped.startswith("["):
        content = load_json(stripped, source=source)
        if not isinstance(content, list):
            raise FindingParseError(f"{source}: trufflehog array reports must be a JSON array")
        return content

    return [load_json(line, source=f"{source} line {number}") for number, line in _numbered(text)]


def _numbered(text: str) -> list[tuple[int, str]]:
    return [
        (number, line)
        for number, raw in enumerate(text.splitlines(), start=1)
        if (line := raw.strip())
    ]


def _build(entry: dict[str, Any], source: str, index: int, catalog: RuleCatalog) -> Finding:
    detector = require_text(
        pick(entry, "DetectorName", "detector_name"),
        source=source,
        index=index,
        field="DetectorName",
    )
    location = _location(entry)
    path = require_relative_path(pick(location, "file", "File"), source=source, index=index)
    verified = optional_bool(pick(entry, "Verified", "verified"))

    return build_finding(
        scanner=SCANNER_NAME,
        rule_id=detector,
        path=path,
        message=f"trufflehog detector {detector} matched",
        catalog=catalog,
        line=positive_int(pick(location, "line", "Line")),
        commit=sanitize_commit(pick(location, "commit", "Commit")),
        verified=verified,
    )


def _location(entry: dict[str, Any]) -> dict[str, Any]:
    """Extract the source-metadata container without reading credential fields."""
    metadata = pick(entry, "SourceMetadata", "source_metadata")
    if not isinstance(metadata, dict):
        return {}

    data = pick(metadata, "Data", "data")
    if not isinstance(data, dict):
        return {}

    for key in _SOURCE_KEYS:
        container = data.get(key)
        if isinstance(container, dict):
            return container

    # Unknown source type: accept the first object-shaped container so new
    # trufflehog sources still yield a path instead of failing the scan.
    for container in data.values():
        if isinstance(container, dict):
            return container

    return {}
