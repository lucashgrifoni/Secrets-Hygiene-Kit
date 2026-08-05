"""Playbook packaging, freshness lifecycle, and catalog coherence."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from secguard.core.catalog import load_catalog
from secguard.core.playbooks import (
    DEFAULT_MAX_AGE_DAYS,
    PlaybookFormatError,
    PlaybookNotFound,
    _parse,
    available_slugs,
    load_all,
    load_playbook,
    stale_playbooks,
)

REQUIRED_SECTIONS = (
    "## Scope",
    "## Identify",
    "## Invalidate",
    "## Rotate",
    "## Audit Usage",
    "## Communicate",
    "## Close",
)

SPEC_PLAYBOOKS = {
    "aws-access-key",
    "aws-secret-access-key",
    "github-pat",
    "github-app-private-key",
    "slack-bot-token",
    "slack-webhook",
    "stripe-secret-key",
    "gcp-service-account-json",
    "azure-storage-key",
    "postgres-uri",
    "jwt-signing-key",
    "generic-api-key",
}


def test_every_playbook_named_in_the_specification_is_packaged():
    assert SPEC_PLAYBOOKS.issubset(set(available_slugs()))


@pytest.mark.parametrize("slug", available_slugs())
def test_every_playbook_parses_and_covers_the_full_response_shape(slug):
    playbook = load_playbook(slug)

    assert playbook.title
    assert isinstance(playbook.vetted, date)
    for section in REQUIRED_SECTIONS:
        assert section in playbook.body, f"{slug} is missing {section}"


@pytest.mark.parametrize("slug", available_slugs())
def test_no_playbook_tells_a_responder_to_automate_revocation(slug):
    """secguard instructs humans. A playbook that ships a destructive command
    would turn an incident checklist into an unreviewed automation path."""
    body = load_playbook(slug).body.lower()

    for forbidden in ("aws iam delete-access-key ", "curl -x delete", "rm -rf"):
        assert forbidden not in body


def test_every_catalog_playbook_reference_resolves():
    """A catalog entry pointing at a missing playbook would break incident start."""
    catalog = load_catalog()
    packaged = set(available_slugs())

    for key, definition in catalog.secret_types.items():
        assert definition.playbook in packaged, f"secret type {key} references a missing playbook"


def test_every_packaged_playbook_is_reachable_from_the_catalog():
    """An unreferenced playbook is dead weight nobody will ever be routed to."""
    catalog = load_catalog()
    referenced = {definition.playbook for definition in catalog.secret_types.values()}

    assert set(available_slugs()) == referenced


def test_freshness_uses_the_review_window():
    playbook = load_playbook("aws-access-key")
    fresh_day = playbook.vetted + timedelta(days=DEFAULT_MAX_AGE_DAYS)
    stale_day = fresh_day + timedelta(days=1)

    assert playbook.freshness(fresh_day) == "fresh"
    assert playbook.freshness(stale_day) == "stale"
    assert playbook.age_days(stale_day) == DEFAULT_MAX_AGE_DAYS + 1


def test_stale_playbooks_are_reported():
    playbooks = load_all()
    far_future = date(2030, 1, 1)

    assert stale_playbooks(playbooks, today=far_future) == playbooks
    assert stale_playbooks(playbooks, today=date(2026, 8, 4)) == []


def test_checklist_converts_bullets_into_tickable_items():
    checklist = load_playbook("aws-access-key").checklist()

    assert "- [ ] " in checklist
    assert "## Identify" in checklist
    # The rendered header replaces the title and vetted line.
    assert not checklist.startswith("# ")
    assert "Vetted:" not in checklist


def test_unknown_slug_lists_the_available_playbooks():
    with pytest.raises(PlaybookNotFound) as exc_info:
        load_playbook("not-a-playbook")

    assert "available playbooks:" in str(exc_info.value)


@pytest.mark.parametrize("slug", ["../etc", "aws/../..", "AWS-Access-Key", "a b"])
def test_slug_traversal_is_rejected(slug):
    with pytest.raises(PlaybookNotFound, match="lowercase kebab-case"):
        load_playbook(slug)


def test_a_playbook_without_a_vetted_date_is_rejected():
    with pytest.raises(PlaybookFormatError, match="Vetted"):
        _parse("example", "# Example\n\n## Scope\n\nNo vetted line.\n")


def test_a_playbook_without_a_title_is_rejected():
    with pytest.raises(PlaybookFormatError, match="level-one title"):
        _parse("example", "Vetted: 2026-08-04\n\n## Scope\n")
