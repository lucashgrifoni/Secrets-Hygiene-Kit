"""Canonical finding schema and synthetic scanner normalization for secguard.

The canonical model deliberately has no field able to carry secret material.
Adapters drop detector fields such as gitleaks `Secret`/`Match`, trufflehog
`Raw`/`RawV2`, and detect-secrets `hashed_secret` before constructing a
:class:`Finding`, so a canonical document can be attached to a ticket, a PR
comment, or a release evidence bundle without redistributing the credential.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secguard.core.catalog import (
    Classification,
    RuleCatalog,
    Severity,
    load_catalog,
    max_severity,
    severity_rank,
)
from secguard.core.redaction import has_control_characters, sanitize_text, validation_error_details

SYNTHETIC_SCAN_SCHEMA_VERSION = "secguard.synthetic-findings/v1"
CANONICAL_FINDINGS_SCHEMA_VERSION = "secguard.findings/v1"

EMPTY_FIELD_MESSAGE = "field cannot be empty"
MAX_REPORT_BYTES = 64 * 1024 * 1024

__all__ = [
    "CANONICAL_FINDINGS_SCHEMA_VERSION",
    "SYNTHETIC_SCAN_SCHEMA_VERSION",
    "Finding",
    "FindingDocument",
    "FindingError",
    "FindingFileNotFound",
    "FindingParseError",
    "Severity",
    "SyntheticFinding",
    "SyntheticScanDocument",
    "build_finding",
    "load_synthetic_scan_file",
    "merge_findings",
    "normalize_synthetic_scan",
    "validate_repository_relative_path",
]


class FindingError(Exception):
    """Base class for finding loading and normalization errors."""


class FindingFileNotFound(FindingError):
    """Raised when a scanner findings file does not exist."""


class FindingParseError(FindingError):
    """Raised when a scanner findings file cannot be parsed or validated."""


def validate_repository_relative_path(value: str) -> str:
    """Normalize to POSIX separators and reject absolute or parent-traversal paths.

    Two properties matter beyond traversal. A path carrying a newline or a
    terminal escape can forge a line of gate output, so it is rejected rather
    than quietly rewritten into a different path that a waiver might match. And
    `./app/x.py` and `app/x.py` name the same file, so they must normalize to
    one value: the merge key and every waiver scope compare paths literally.
    """
    if has_control_characters(value):
        raise ValueError("path cannot contain control characters, newlines, or escape sequences")

    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)

    if path.is_absolute() or PureWindowsPath(value).is_absolute():
        raise ValueError("path must be repository-relative")
    if ".." in path.parts:
        raise ValueError("path cannot contain parent traversal")

    # PurePosixPath collapses `//`, drops `.` segments, and strips a trailing
    # slash. `str()` of a path with no parts is `.`, which is not a file.
    collapsed = str(path)
    if collapsed in {".", ""}:
        raise ValueError("path cannot be empty")

    return collapsed


class SyntheticFinding(BaseModel):
    """One finding from the local synthetic scanner JSON format."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    rule_id: str = Field(..., description="Scanner-native rule identifier.")
    path: str = Field(..., description="Repository-relative path where the finding was reported.")
    message: str = Field(..., description="Human-readable finding summary without secret values.")
    severity: Severity | None = Field(
        default=None,
        description="Explicit severity; when omitted the rule catalog decides.",
    )
    line: int | None = Field(default=None, ge=1, description="One-based source line.")
    column: int | None = Field(default=None, ge=1, description="One-based source column.")
    fingerprint: str | None = Field(
        default=None,
        description="Stable synthetic scanner fingerprint.",
    )
    remediation: str | None = Field(default=None, description="Optional human remediation hint.")

    @field_validator("rule_id", "path", "message")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        """Reject empty required text fields after whitespace trimming."""
        if not value:
            raise ValueError(EMPTY_FIELD_MESSAGE)
        return value

    @field_validator("fingerprint", "remediation")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        """Reject empty optional text fields when they are present."""
        if value is not None and not value:
            raise ValueError(EMPTY_FIELD_MESSAGE)
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        """Reject absolute or parent-traversal paths."""
        return validate_repository_relative_path(value)

    @field_validator("rule_id", "fingerprint")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is not None and has_control_characters(value):
            raise ValueError("identifier cannot contain control characters or escape sequences")
        return value

    @field_validator("message", "remediation")
    @classmethod
    def sanitize_summary(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = sanitize_text(value)
        if not text:
            raise ValueError(EMPTY_FIELD_MESSAGE)
        return text


class SyntheticScanDocument(BaseModel):
    """Top-level local synthetic scanner JSON document."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)

    schema_version: Literal["secguard.synthetic-findings/v1"] = Field(alias="schema")
    scanner: str = Field(..., description="Scanner name represented by the synthetic file.")
    findings: list[SyntheticFinding] = Field(default_factory=list)

    @field_validator("scanner")
    @classmethod
    def validate_scanner(cls, value: str) -> str:
        """Reject empty or structurally unsafe scanner names."""
        if not value:
            raise ValueError(EMPTY_FIELD_MESSAGE)
        if has_control_characters(value):
            raise ValueError("scanner cannot contain control characters or escape sequences")
        return value


class Finding(BaseModel):
    """Canonical secguard finding without raw secret material."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(..., description="Stable secguard finding identifier.")
    scanner: str = Field(..., description="Scanner that produced the original finding.")
    rule: str = Field(..., description="Scanner-qualified rule identifier.")
    secret_type: str = Field(..., description="Canonical secret type resolved from the catalog.")
    secret_title: str = Field(..., description="Human-readable secret type name.")
    playbook: str = Field(..., description="Playbook slug describing the response.")
    mapping: Literal["catalog", "fallback"] = Field(
        ...,
        description="Whether the rule was mapped explicitly or resolved by fallback.",
    )
    severity: Severity = Field(..., description="Resolved severity label.")
    path: str = Field(..., description="Repository-relative path for triage.")
    message: str = Field(..., description="Finding summary without secret values.")
    fingerprint: str = Field(..., description="Stable scanner or secguard fingerprint.")
    line: int | None = Field(default=None, ge=1, description="One-based source line.")
    column: int | None = Field(default=None, ge=1, description="One-based source column.")
    commit: str | None = Field(default=None, description="Commit that introduced the match.")
    verified: bool | None = Field(
        default=None,
        description="Detector-reported live-credential verification result, when available.",
    )
    remediation: str | None = Field(default=None, description="Optional human remediation hint.")
    corroborated_by: list[str] = Field(
        default_factory=list,
        description="Other scanners that reported the same location and secret type.",
    )
    corroborated_rules: list[str] = Field(
        default_factory=list,
        description="Scanner-qualified rules of the other detections merged into this finding.",
    )

    @property
    def dedup_key(self) -> tuple[str, str, int | None]:
        """Return the identity used to merge the same leak across scanners."""
        return (self.secret_type, self.path, self.line)

    @property
    def rules(self) -> tuple[str, ...]:
        """Every scanner-qualified rule that contributed to this finding.

        Merging collapses the same leak reported by several detectors into one
        record, and only the primary detection's rule survives in ``rule``. The
        waiver lifecycle needs all of them: an exception written for one
        scanner's match must not inherit authority over another scanner's
        independent detection at the same location.
        """
        return (self.rule, *self.corroborated_rules)


class FindingDocument(BaseModel):
    """Canonical secguard finding document."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal["secguard.findings/v1"] = Field(
        default=CANONICAL_FINDINGS_SCHEMA_VERSION,
        alias="schema",
    )
    findings: list[Finding] = Field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        """Return finding counts per severity label, highest severity first."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: severity_rank(item[0]), reverse=True))


def build_finding(
    *,
    scanner: str,
    rule_id: str,
    path: str,
    message: str,
    catalog: RuleCatalog,
    severity: Severity | None = None,
    line: int | None = None,
    column: int | None = None,
    fingerprint: str | None = None,
    commit: str | None = None,
    verified: bool | None = None,
    remediation: str | None = None,
) -> Finding:
    """Build a canonical finding from non-secret detector metadata."""
    classification: Classification = catalog.classify(scanner, rule_id)
    resolved_fingerprint = fingerprint or _fallback_fingerprint(
        scanner=scanner,
        rule_id=rule_id,
        path=path,
        line=line,
        column=column,
        message=message,
    )
    resolved_severity = severity or classification.severity

    # A detector that proved the credential is live removes all doubt about
    # exploitability, so it outranks any catalog default.
    if verified:
        resolved_severity = max_severity(resolved_severity, "critical")

    return Finding(
        id=_finding_id(scanner, resolved_fingerprint),
        scanner=scanner,
        rule=f"{scanner}:{rule_id}",
        secret_type=classification.secret_type,
        secret_title=classification.title,
        playbook=classification.playbook,
        mapping=classification.mapping,
        severity=resolved_severity,
        path=path,
        line=line,
        column=column,
        message=message,
        fingerprint=resolved_fingerprint,
        commit=commit,
        verified=verified,
        remediation=remediation,
    )


def merge_findings(documents: list[FindingDocument]) -> FindingDocument:
    """Merge canonical documents, collapsing the same leak reported by many scanners."""
    groups: dict[tuple[str, str, int | None], list[Finding]] = {}
    order: list[tuple[str, str, int | None]] = []

    for document in documents:
        for finding in document.findings:
            key = finding.dedup_key
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(finding)

    merged: list[Finding] = []
    for key in order:
        group = sorted(groups[key], key=_primary_rank)
        primary = group[0]

        if len(group) == 1:
            merged.append(primary)
            continue

        scanners = sorted(
            {name for item in group for name in (item.scanner, *item.corroborated_by)}
        )
        rules = sorted({rule for item in group for rule in item.rules})
        verified_flags = [item.verified for item in group if item.verified is not None]
        merged.append(
            primary.model_copy(
                update={
                    "severity": max_severity(*[item.severity for item in group]),
                    "verified": any(verified_flags) if verified_flags else None,
                    "remediation": next(
                        (item.remediation for item in group if item.remediation), None
                    ),
                    "commit": next((item.commit for item in group if item.commit), None),
                    "corroborated_by": [name for name in scanners if name != primary.scanner],
                    "corroborated_rules": [rule for rule in rules if rule != primary.rule],
                }
            )
        )

    # `id` breaks the final tie so a merged document is byte-identical whatever
    # order the reports were passed in. Severity, path, and line alone leave
    # unrelated findings that share a location free to swap places.
    merged.sort(
        key=lambda item: (-severity_rank(item.severity), item.path, item.line or 0, item.id)
    )
    return FindingDocument(findings=merged)


def load_synthetic_scan_file(path: Path, catalog: RuleCatalog | None = None) -> FindingDocument:
    """Load a local synthetic scanner JSON file and return canonical findings."""
    if not path.exists():
        raise FindingFileNotFound(f"finding file not found: {path}")
    if not path.is_file():
        raise FindingFileNotFound(f"finding path is not a file: {path}")

    try:
        content: Any = json.loads(read_bounded_report(path))
    except json.JSONDecodeError as exc:
        raise FindingParseError(
            f"invalid JSON in finding file {path}: line {exc.lineno} column {exc.colno}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise FindingParseError(
            f"{path}: finding file is not valid UTF-8 (byte {exc.start})"
        ) from exc
    except RecursionError as exc:
        raise FindingParseError(f"{path}: JSON is nested too deeply to parse") from exc
    except ValueError as exc:
        raise FindingParseError(f"{path}: JSON contains an unsupported numeric value") from exc
    except OSError as exc:
        raise FindingParseError(f"cannot read finding file {path}: {exc.strerror or exc}") from exc

    if not isinstance(content, dict):
        raise FindingParseError(f"finding file must contain a JSON object: {path}")

    try:
        document = SyntheticScanDocument.model_validate(content)
    except ValidationError as exc:
        raise FindingParseError(format_validation_error(path, exc)) from exc

    return normalize_synthetic_scan(document, catalog=catalog)


def read_bounded_report(path: Path) -> str:
    """Read at most the documented per-report budget, even if a file grows."""
    with path.open("rb") as stream:
        payload = stream.read(MAX_REPORT_BYTES + 1)
    if len(payload) > MAX_REPORT_BYTES:
        raise FindingParseError(f"{path}: report exceeds the 64 MiB input limit")
    return payload.decode("utf-8")


def normalize_synthetic_scan(
    document: SyntheticScanDocument,
    catalog: RuleCatalog | None = None,
) -> FindingDocument:
    """Normalize a synthetic scanner document into secguard canonical findings."""
    resolved_catalog = catalog or load_catalog()
    findings = [
        build_finding(
            scanner=document.scanner,
            rule_id=source.rule_id,
            path=source.path,
            message=source.message,
            catalog=resolved_catalog,
            severity=source.severity,
            line=source.line,
            column=source.column,
            fingerprint=source.fingerprint,
            remediation=source.remediation,
        )
        for source in document.findings
    ]
    return FindingDocument(findings=findings)


def format_validation_error(path: Path, exc: ValidationError) -> str:
    """Format Pydantic errors without echoing raw field input values."""
    return (
        f"invalid finding file {path}: {validation_error_details(exc.errors(include_input=False))}"
    )


def _primary_rank(finding: Finding) -> tuple[int, int, int, str, str]:
    """Rank findings in a merge group so the most informative one becomes the primary.

    A scanner-native fingerprint, a column, and a commit each carry triage value
    that a derived fingerprint does not. Scanner name and fingerprint break ties
    so the chosen primary, and therefore the finding id, stays deterministic.
    """
    return (
        1 if finding.fingerprint.startswith("secguard:") else 0,
        0 if finding.column is not None else 1,
        0 if finding.commit else 1,
        finding.scanner,
        finding.fingerprint,
    )


def _finding_id(scanner: str, fingerprint: str) -> str:
    """Generate a stable secguard identifier from non-secret metadata."""
    digest = hashlib.sha256(f"{scanner}|{fingerprint}".encode()).hexdigest()
    return f"FND-{digest[:12].upper()}"


def _fallback_fingerprint(
    *,
    scanner: str,
    rule_id: str,
    path: str,
    line: int | None,
    column: int | None,
    message: str,
) -> str:
    """Generate a stable fingerprint from location metadata, never from secret material."""
    identity = "|".join([scanner, rule_id, path, str(line or ""), str(column or ""), message])
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return f"secguard:{digest[:16]}"
