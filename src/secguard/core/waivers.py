"""Waiver schema, scope matching, and lifecycle checks for secguard.

A waiver is an accepted, time-bound exception. Two properties keep it from
becoming a parking lot: it expires on a date the CI enforces, and its scope is
narrow and predictable. An expired waiver never suppresses a finding — the
lifecycle fails closed.
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from secguard.core.matching import path_matches, rule_matches

SCHEMA_VERSION = "secguard.waiver/v1"
WAIVER_ID_PREFIX = "WV-"
SECRET_TYPE_PREFIX = "secret-type:"

EMPTY_FIELD_MESSAGE = "field cannot be empty"

# A waiver that outlives the people who approved it is not an exception, it is
# a permanent silent acceptance. These bounds are enforced on write only, so
# existing files stay readable.
MAX_EXPIRY_HORIZON_DAYS = 365
RECOMMENDED_EXPIRY_HORIZON_DAYS = 90

WAIVER_FILE_HEADER = """\
# secguard waivers
#
# Every entry is a reviewed, time-bound exception. An expired waiver stops
# suppressing findings, so keep `expires_at` tied to a real revisit plan.
#
# Do not store secret values or detector match text in this file.
"""


class WaiverError(Exception):
    """Base class for waiver loading and validation errors."""


class WaiverFileNotFound(WaiverError):
    """Raised when a waiver file does not exist."""


class WaiverParseError(WaiverError):
    """Raised when a waiver file cannot be parsed or validated."""


class WaiverPolicyError(WaiverError):
    """Raised when a new waiver would violate lifecycle policy."""


class Waiver(BaseModel):
    """A time-bound accepted exception for one detector rule and path."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(..., description="Stable waiver identifier, for example WV-2026-001.")
    rule: str = Field(
        ...,
        description=(
            "Detector rule pattern such as gitleaks:aws-access-token, gitleaks:*, "
            "or secret-type:aws-access-key."
        ),
    )
    path: str = Field(..., description="Repository path or glob covered by this waiver.")
    reason: str = Field(..., description="Human-readable justification without secret values.")
    owner: str = Field(..., description="Person or team accountable for revisiting the waiver.")
    expires_at: date = Field(..., description="Date after which this waiver is no longer valid.")
    approver: str = Field(..., description="Person or group that approved the waiver.")

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        """Validate the public waiver identifier shape."""
        if not value.startswith(WAIVER_ID_PREFIX):
            raise ValueError(f"waiver id must start with {WAIVER_ID_PREFIX}")
        if len(value) < len("WV-2026-001"):
            raise ValueError("waiver id must include a year and sequence")
        return value

    @field_validator("rule", "path", "reason", "owner", "approver")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        """Reject empty required text fields after whitespace trimming."""
        if not value:
            raise ValueError(EMPTY_FIELD_MESSAGE)
        return value

    @field_validator("path")
    @classmethod
    def validate_scope_path(cls, value: str) -> str:
        """Keep waiver scope inside the repository so it cannot silently match nothing."""
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or ":" in normalized.split("/")[0]:
            raise ValueError("path must be repository-relative")
        if ".." in normalized.split("/"):
            raise ValueError("path cannot contain parent traversal")
        return normalized

    @field_validator("expires_at", mode="before")
    @classmethod
    def parse_expiry_date(cls, value: Any) -> date:
        """Accept YAML date objects or ISO date strings, rejecting datetime timestamps."""
        if isinstance(value, date) and not isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return date.fromisoformat(value)
            except ValueError as exc:
                raise ValueError("expires_at must use YYYY-MM-DD") from exc
        raise ValueError("expires_at must use YYYY-MM-DD")

    def is_expired(self, today: date) -> bool:
        """Return whether the waiver is expired for a given date."""
        return self.expires_at < today

    def covers(self, *, rule: str, secret_type: str, path: str) -> bool:
        """Return whether this waiver's scope covers a finding, ignoring expiry."""
        if not path_matches(self.path, path):
            return False

        if self.rule.startswith(SECRET_TYPE_PREFIX):
            return rule_matches(self.rule[len(SECRET_TYPE_PREFIX) :].strip(), secret_type)

        return rule_matches(self.rule, rule)


class WaiverDocument(BaseModel):
    """Top-level YAML document for secguard waiver files."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal["secguard.waiver/v1"] = Field(alias="schema")
    waivers: list[Waiver] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> WaiverDocument:
        """Ensure waiver IDs are unique inside a document."""
        seen: set[str] = set()
        duplicates: set[str] = set()

        for waiver in self.waivers:
            if waiver.id in seen:
                duplicates.add(waiver.id)
            seen.add(waiver.id)

        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"duplicate waiver id(s): {duplicate_list}")

        return self

    def expired(self, today: date) -> list[Waiver]:
        """Return waivers that are expired for a given date."""
        return [waiver for waiver in self.waivers if waiver.is_expired(today)]

    def match(self, *, rule: str, secret_type: str, path: str, today: date) -> Waiver | None:
        """Return the first active waiver covering a finding, or None."""
        for waiver in self.waivers:
            if waiver.is_expired(today):
                continue
            if waiver.covers(rule=rule, secret_type=secret_type, path=path):
                return waiver
        return None

    def next_id(self, today: date) -> str:
        """Return the next sequential waiver id for the current year."""
        prefix = f"{WAIVER_ID_PREFIX}{today.year}-"
        sequences = [
            int(suffix)
            for waiver in self.waivers
            if waiver.id.startswith(prefix) and (suffix := waiver.id[len(prefix) :]).isdigit()
        ]
        return f"{prefix}{max(sequences, default=0) + 1:03d}"


def load_waiver_file(path: Path) -> WaiverDocument:
    """Load and validate a secguard waiver YAML file."""
    if not path.exists():
        raise WaiverFileNotFound(f"waiver file not found: {path}")
    if not path.is_file():
        raise WaiverFileNotFound(f"waiver path is not a file: {path}")

    try:
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise WaiverParseError(f"invalid YAML in waiver file: {path}") from exc

    if content is None:
        content = {}
    if not isinstance(content, dict):
        raise WaiverParseError(f"waiver file must contain a YAML mapping: {path}")

    try:
        return WaiverDocument.model_validate(content)
    except ValidationError as exc:
        raise WaiverParseError(_format_validation_error(path, exc)) from exc


def new_waiver_document(waivers: list[Waiver] | None = None) -> WaiverDocument:
    """Build an in-memory waiver document at the current schema version."""
    return WaiverDocument.model_validate({"schema": SCHEMA_VERSION, "waivers": waivers or []})


def load_waiver_file_or_empty(path: Path | None) -> WaiverDocument:
    """Load a waiver file, returning an empty document when the path is absent."""
    if path is None or not path.exists():
        return new_waiver_document()
    return load_waiver_file(path)


def add_waiver(
    path: Path,
    *,
    rule: str,
    scope_path: str,
    reason: str,
    owner: str,
    approver: str,
    expires_at: date,
    today: date,
    waiver_id: str | None = None,
    dry_run: bool = False,
) -> tuple[Waiver, list[str]]:
    """Append a validated waiver to a waiver file and return it with any warnings."""
    document = load_waiver_file(path) if path.exists() else new_waiver_document()
    warnings = _validate_expiry_policy(expires_at, today)
    resolved_id = waiver_id or document.next_id(today)

    if any(waiver.id == resolved_id for waiver in document.waivers):
        raise WaiverPolicyError(f"waiver id already exists: {resolved_id}")

    try:
        waiver = Waiver(
            id=resolved_id,
            rule=rule,
            path=scope_path,
            reason=reason,
            owner=owner,
            expires_at=expires_at,
            approver=approver,
        )
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_input=False)
        )
        raise WaiverPolicyError(f"invalid waiver: {details}") from exc

    updated = new_waiver_document([*document.waivers, waiver])

    if not dry_run:
        write_waiver_file(path, updated)

    return waiver, warnings


def write_waiver_file(path: Path, document: WaiverDocument) -> None:
    """Write a waiver document with the standard header, creating parent directories."""
    payload = {
        "schema": document.schema_version,
        "waivers": [waiver.model_dump(mode="python") for waiver in document.waivers],
    }
    body = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, default_flow_style=False)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{WAIVER_FILE_HEADER}\n{body}", encoding="utf-8", newline="\n")


def _validate_expiry_policy(expires_at: date, today: date) -> list[str]:
    if expires_at < today:
        raise WaiverPolicyError(
            f"expires_at {expires_at.isoformat()} is already in the past as of {today.isoformat()}"
        )

    horizon = (expires_at - today).days
    if horizon > MAX_EXPIRY_HORIZON_DAYS:
        raise WaiverPolicyError(
            f"expires_at is {horizon} days away; secguard caps new waivers at "
            f"{MAX_EXPIRY_HORIZON_DAYS} days so an exception cannot outlive its approval"
        )

    if horizon > RECOMMENDED_EXPIRY_HORIZON_DAYS:
        return [
            f"expiry is {horizon} days away; the recommended horizon is "
            f"{RECOMMENDED_EXPIRY_HORIZON_DAYS} days or less"
        ]

    return []


def _format_validation_error(path: Path, exc: ValidationError) -> str:
    """Format Pydantic errors without echoing raw field input values."""
    details: list[str] = []
    for error in exc.errors(include_input=False):
        location = ".".join(str(part) for part in error["loc"])
        details.append(f"{location}: {error['msg']}")

    return f"invalid waiver file {path}: {'; '.join(details)}"
