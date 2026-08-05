"""Packaged remediation playbooks and their freshness lifecycle.

A playbook is human instruction, never automation: secguard prints the steps a
responder should take and never revokes, rotates, or mutates provider state.

Vendor consoles and revocation flows change, so every playbook carries a
``Vetted:`` date and ``secguard playbooks check`` fails once one goes stale.
Advice nobody has reviewed in a year is worse than no advice, because it is
followed with misplaced confidence during an incident.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from importlib.resources import files
from typing import Literal

PLAYBOOK_DIRECTORY = "playbooks"
PLAYBOOK_FILENAME = "PLAYBOOK.md"
DEFAULT_MAX_AGE_DAYS = 180

_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_TITLE_PATTERN = re.compile(r"^#\s+(?P<title>.+?)\s*$")
_VETTED_PATTERN = re.compile(r"^Vetted:\s*(?P<date>\d{4}-\d{2}-\d{2})\s*$")
_BULLET_PATTERN = re.compile(r"^(?P<indent>\s*)-\s+(?!\[[ xX]\])(?P<text>\S.*)$")

PlaybookFreshness = Literal["fresh", "stale"]


class PlaybookError(Exception):
    """Base class for playbook loading errors."""


class PlaybookNotFound(PlaybookError):
    """Raised when a playbook slug does not exist."""


class PlaybookFormatError(PlaybookError):
    """Raised when a playbook is missing required metadata."""


@dataclass(frozen=True)
class Playbook:
    """One packaged remediation playbook."""

    slug: str
    title: str
    vetted: date
    body: str

    def age_days(self, today: date) -> int:
        """Return how many days ago this playbook was last vetted."""
        return (today - self.vetted).days

    def freshness(self, today: date, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> PlaybookFreshness:
        """Return whether the playbook is still inside its review window."""
        return "stale" if self.age_days(today) > max_age_days else "fresh"

    def checklist(self) -> str:
        """Render the playbook body as a tickable Markdown checklist."""
        lines: list[str] = []

        for line in self.body.splitlines():
            if _TITLE_PATTERN.match(line) or _VETTED_PATTERN.match(line):
                continue
            match = _BULLET_PATTERN.match(line)
            lines.append(f"{match.group('indent')}- [ ] {match.group('text')}" if match else line)

        return "\n".join(lines).strip()


def available_slugs() -> list[str]:
    """Return every packaged playbook slug, sorted."""
    root = files("secguard").joinpath(PLAYBOOK_DIRECTORY)
    return sorted(
        entry.name for entry in root.iterdir() if entry.is_dir() and _SLUG_PATTERN.match(entry.name)
    )


def load_playbook(slug: str) -> Playbook:
    """Load one packaged playbook by slug."""
    if not _SLUG_PATTERN.match(slug):
        raise PlaybookNotFound(f"playbook slug must be lowercase kebab-case: {slug}")

    resource = files("secguard").joinpath(PLAYBOOK_DIRECTORY, slug, PLAYBOOK_FILENAME)
    if not resource.is_file():
        available = ", ".join(available_slugs())
        raise PlaybookNotFound(f"playbook not found: {slug}; available playbooks: {available}")

    return _parse(slug, resource.read_text(encoding="utf-8"))


def load_all() -> list[Playbook]:
    """Load every packaged playbook, sorted by slug."""
    return [load_playbook(slug) for slug in available_slugs()]


def stale_playbooks(
    playbooks: list[Playbook],
    *,
    today: date,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> list[Playbook]:
    """Return playbooks whose vetted date is older than the review window."""
    return [book for book in playbooks if book.freshness(today, max_age_days) == "stale"]


def _parse(slug: str, text: str) -> Playbook:
    title: str | None = None
    vetted: date | None = None

    for line in text.splitlines():
        if title is None and (match := _TITLE_PATTERN.match(line)):
            title = match.group("title")
            continue
        if vetted is None and (match := _VETTED_PATTERN.match(line)):
            vetted = date.fromisoformat(match.group("date"))

        if title is not None and vetted is not None:
            break

    if title is None:
        raise PlaybookFormatError(f"playbook {slug} is missing a level-one title")
    if vetted is None:
        raise PlaybookFormatError(
            f"playbook {slug} is missing a `Vetted: YYYY-MM-DD` line; "
            "secguard needs it to detect stale response guidance"
        )

    return Playbook(slug=slug, title=title, vetted=vetted, body=text.strip())
