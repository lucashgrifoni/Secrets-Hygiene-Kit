"""Markdown reporting for reconciled scan outcomes.

Two renderers share one outcome: a full report for evidence bundles and review,
and a compact summary sized for a pull-request comment. Neither prints secret
material, and every free-text value passes through the Markdown-cell escape so
a hostile scanner report cannot break out of a table or forge a section.
"""

from __future__ import annotations

from datetime import date

from secguard.core.reconcile import ReconciledFinding, ScanOutcome
from secguard.core.redaction import escape_markdown_cell
from secguard.core.waivers import Waiver

MAX_TABLE_ROWS = 100
MAX_LIST_ROWS = 10


def render_report(outcome: ScanOutcome, *, generated_on: date, version: str) -> str:
    """Render the full Markdown scan report."""
    lines: list[str] = [
        "# secguard scan report",
        "",
        f"- Generated on: {generated_on.isoformat()}",
        f"- secguard version: {version}",
        f"- Gate: `--fail-on {outcome.fail_on}` -> **{_verdict(outcome)}**",
        f"- Findings: {len(outcome.results)} total "
        f"({len(outcome.active)} active, {len(outcome.waived)} waived)",
        "",
        "secguard does not run detectors and does not rotate or revoke credentials. "
        "It normalizes detector reports, applies the waiver lifecycle, and points at the "
        "response playbook a human should follow.",
        "",
    ]

    lines.extend(_severity_table(outcome))
    lines.extend(_next_actions(outcome))
    lines.extend(_findings_table("Active findings", outcome.active))
    lines.extend(_waived_table(outcome))
    lines.extend(_waiver_hygiene(outcome))

    return "\n".join(lines).rstrip() + "\n"


def render_pr_comment(outcome: ScanOutcome, *, generated_on: date) -> str:
    """Render a compact summary sized for a pull-request comment."""
    verdict = _verdict(outcome)
    lines: list[str] = [
        f"### secguard: {verdict}",
        "",
        f"{len(outcome.active)} active finding(s), {len(outcome.waived)} waived, "
        f"threshold `{outcome.fail_on}` (checked {generated_on.isoformat()}).",
        "",
    ]

    if outcome.expired_waivers:
        lines.extend(
            [
                f"**{len(outcome.expired_waivers)} expired waiver(s)** no longer suppress "
                "anything. Renew with a new expiry or delete them:",
                "",
                *[
                    f"- `{waiver.id}` expired {waiver.expires_at.isoformat()}"
                    for waiver in outcome.expired_waivers[:MAX_LIST_ROWS]
                ],
                "",
            ]
        )

    blocking = outcome.blocking
    if blocking:
        lines.extend(["Blocking findings:", ""])
        lines.extend(
            f"- **{result.finding.severity}** `{escape_markdown_cell(result.finding.secret_type)}` "
            f"in `{escape_markdown_cell(_location(result.finding))}` "
            f"-> `secguard incident start --secret-type {result.finding.secret_type}`"
            for result in blocking[:MAX_LIST_ROWS]
        )
        if len(blocking) > MAX_LIST_ROWS:
            lines.append(f"- ...and {len(blocking) - MAX_LIST_ROWS} more")
        lines.append("")

    if not outcome.failed:
        lines.append("No unwaived finding reached the threshold and no waiver has expired.")
        lines.append("")

    lines.append(
        "Never paste the credential into this thread. Reference the rule id, path, and "
        "commit hash instead."
    )
    return "\n".join(lines).rstrip() + "\n"


def _verdict(outcome: ScanOutcome) -> str:
    return "BLOCK" if outcome.failed else "PASS"


def _severity_table(outcome: ScanOutcome) -> list[str]:
    active = outcome.severity_counts("active")
    waived = outcome.severity_counts("waived")

    if not active and not waived:
        return ["## Summary", "", "No findings were reported by any input report.", ""]

    rows = [
        f"| {severity} | {active.get(severity, 0)} | {waived.get(severity, 0)} |"
        for severity in dict.fromkeys([*active, *waived])
    ]
    return [
        "## Summary by severity",
        "",
        "| Severity | Active | Waived |",
        "| --- | ---: | ---: |",
        *rows,
        "",
    ]


def _next_actions(outcome: ScanOutcome) -> list[str]:
    if not outcome.active:
        return []

    lines = ["## What to do next", "", "1. Invalidate first, rotate second, audit third."]
    lines.extend(
        f"{index}. Open the `{playbook}` playbook: `secguard playbooks show {playbook}`"
        for index, playbook in enumerate(outcome.playbooks(), start=2)
    )
    lines.extend(
        [
            f"{len(outcome.playbooks()) + 2}. Record evidence with paths, commits, and "
            "timestamps, never the credential value.",
            "",
        ]
    )
    return lines


def _findings_table(title: str, results: list[ReconciledFinding]) -> list[str]:
    if not results:
        return []

    rows = [
        f"| {result.finding.severity} "
        f"| `{escape_markdown_cell(result.finding.secret_type)}` "
        f"| `{escape_markdown_cell(_location(result.finding))}` "
        f"| {escape_markdown_cell(_scanners(result))} "
        f"| {_verified_label(result)} "
        f"| `{escape_markdown_cell(result.finding.playbook)}` |"
        for result in results[:MAX_TABLE_ROWS]
    ]

    lines = [
        f"## {title} ({len(results)})",
        "",
        "| Severity | Secret type | Location | Scanner | Verified | Playbook |",
        "| --- | --- | --- | --- | --- | --- |",
        *rows,
    ]

    if len(results) > MAX_TABLE_ROWS:
        lines.append("")
        lines.append(
            f"Showing the first {MAX_TABLE_ROWS} of {len(results)}. "
            "Use the JSON or SARIF output for the complete set."
        )

    lines.append("")
    return lines


def _waived_table(outcome: ScanOutcome) -> list[str]:
    if not outcome.waived:
        return []

    rows = [
        f"| `{result.waiver_id}` | {result.finding.severity} | "
        f"`{escape_markdown_cell(result.finding.secret_type)}` | "
        f"`{escape_markdown_cell(_location(result.finding))}` |"
        for result in outcome.waived[:MAX_TABLE_ROWS]
    ]
    return [
        f"## Waived findings ({len(outcome.waived)})",
        "",
        "Suppressed by an active waiver. Each one still has an owner and an expiry date.",
        "",
        "| Waiver | Severity | Secret type | Location |",
        "| --- | --- | --- | --- |",
        *rows,
        "",
    ]


def _waiver_hygiene(outcome: ScanOutcome) -> list[str]:
    if not outcome.expired_waivers and not outcome.unused_waivers:
        return []

    lines = ["## Waiver hygiene", ""]

    if outcome.expired_waivers:
        lines.append(
            f"**{len(outcome.expired_waivers)} expired waiver(s).** These no longer suppress "
            "findings and they fail this gate on their own. Renew with a new expiry date and "
            "approver, or delete them."
        )
        lines.append("")
        lines.extend(_waiver_lines(outcome.expired_waivers))
        lines.append("")

    if outcome.unused_waivers:
        lines.append(
            f"{len(outcome.unused_waivers)} active waiver(s) matched no finding in this scan. "
            "That usually means the underlying match is gone and the waiver can be removed."
        )
        lines.append("")
        lines.extend(_waiver_lines(outcome.unused_waivers))
        lines.append("")

    return lines


def _waiver_lines(waivers: list[Waiver]) -> list[str]:
    return [
        f"- `{waiver.id}` rule `{escape_markdown_cell(waiver.rule)}` "
        f"path `{escape_markdown_cell(waiver.path)}` "
        f"owner {escape_markdown_cell(waiver.owner)} "
        f"expires {waiver.expires_at.isoformat()}"
        for waiver in waivers
    ]


def _location(finding) -> str:  # noqa: ANN001 - narrow internal helper
    return f"{finding.path}:{finding.line}" if finding.line else finding.path


def _scanners(result: ReconciledFinding) -> str:
    scanners = [result.finding.scanner, *result.finding.corroborated_by]
    return "+".join(scanners)


def _verified_label(result: ReconciledFinding) -> str:
    if result.finding.verified is True:
        return "**live**"
    if result.finding.verified is False:
        return "no"
    return "unknown"
