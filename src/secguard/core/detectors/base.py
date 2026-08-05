"""Shared parsing helpers for secguard scanner adapters."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

from secguard.core.findings import FindingParseError, validate_repository_relative_path


def load_json(text: str, *, source: str) -> Any:
    """Parse JSON text, raising a secguard error that never echoes file content."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise FindingParseError(f"invalid JSON in {source}: line {exc.lineno}") from exc


def pick(item: dict[str, Any], *keys: str) -> Any:
    """Return the first present, non-null value among the given keys."""
    for key in keys:
        if key in item and item[key] is not None:
            return item[key]
    return None


def positive_int(value: Any) -> int | None:
    """Coerce a scanner-supplied line or column into a one-based integer."""
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None

    try:
        number = int(value)
    except (TypeError, ValueError):
        return None

    return number if number >= 1 else None


def optional_bool(value: Any) -> bool | None:
    """Return a boolean only when the scanner actually reported one."""
    return value if isinstance(value, bool) else None


def require_relative_path(value: Any, *, source: str, index: int) -> str:
    """Validate a scanner path, reporting problems without echoing the full path."""
    if not isinstance(value, str) or not value.strip():
        raise FindingParseError(f"{source}: entry {index} is missing a file path")

    try:
        return validate_repository_relative_path(value.strip())
    except ValueError as exc:
        name = PurePosixPath(value.replace("\\", "/")).name or "<unnamed>"
        raise FindingParseError(
            f"{source}: entry {index} ({name}) has a path that is not repository-relative "
            f"({exc}); run the scanner from the repository root so paths stay portable"
        ) from exc


def require_mapping(value: Any, *, source: str, index: int) -> dict[str, Any]:
    """Ensure one report entry is a JSON object."""
    if not isinstance(value, dict):
        raise FindingParseError(f"{source}: entry {index} must be a JSON object")
    return value


def require_text(value: Any, *, source: str, index: int, field: str) -> str:
    """Ensure a required identifier field is a non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise FindingParseError(f"{source}: entry {index} is missing {field}")
    return value.strip()
