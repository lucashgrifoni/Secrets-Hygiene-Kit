"""Render an incident response checklist from a packaged playbook.

The first minutes after a leak are where improvisation costs the most. This
module turns the relevant playbook into a tickable checklist with the exposure
facts already filled in, so the responder reads steps instead of inventing them.

secguard never contacts a provider. Every step is executed by a human with the
authority to do it.
"""

from __future__ import annotations

from datetime import date

from secguard.core.playbooks import Playbook
from secguard.core.redaction import sanitize_text

EVIDENCE_RULE = (
    "Record the provider, rule id, redacted fingerprint, file path, commit hash, and "
    "timestamp. Never copy the credential itself into tickets, chat, or this checklist."
)


def render_incident(
    playbook: Playbook,
    *,
    secret_type: str,
    opened_on: date,
    leaked_via: str | None = None,
    reference: str | None = None,
    max_age_days: int = 180,
) -> str:
    """Render a Markdown incident checklist for one secret type."""
    sections: list[str] = [
        f"# Incident checklist: {playbook.title}",
        "",
        "## Exposure record",
        "",
        f"- Secret type: `{secret_type}`",
        f"- Playbook: `{playbook.slug}` (vetted {playbook.vetted.isoformat()})",
        f"- Opened: {opened_on.isoformat()}",
    ]

    if leaked_via:
        sections.append(f"- Leaked via: {sanitize_text(leaked_via, max_length=120)}")
    if reference:
        sections.append(f"- Reference: {sanitize_text(reference, max_length=200)}")

    sections.extend(
        [
            "",
            f"> {EVIDENCE_RULE}",
            "",
        ]
    )

    if playbook.freshness(opened_on, max_age_days) == "stale":
        sections.extend(
            [
                f"> Warning: this playbook was last vetted {playbook.age_days(opened_on)} days "
                f"ago, beyond the {max_age_days}-day review window. Confirm each provider step "
                "against current vendor documentation before relying on it.",
                "",
            ]
        )

    sections.extend(
        [
            playbook.checklist(),
            "",
            "## Close-out record",
            "",
            "- [ ] Credential confirmed invalid at the provider.",
            "- [ ] Replacement credential stored in the approved secret manager.",
            "- [ ] Provider logs reviewed for the full exposure window.",
            "- [ ] Owner, AppSec, and affected service teams notified.",
            "- [ ] Detection or waiver added so the same match does not recur silently.",
            "- [ ] Residual risk written down with an owner and a review date.",
        ]
    )

    return "\n".join(sections).rstrip() + "\n"
