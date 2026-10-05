"""Reconcile canonical findings against the waiver lifecycle and decide the gate.

The gate fails when either of two things is true:

1. an unwaived finding reaches the configured severity threshold, or
2. any waiver in the file has expired.

The second rule is what stops waivers becoming a parking lot. An expired waiver
never suppresses a finding, and it also fails the build on its own, so a stale
exception cannot sit unnoticed just because the code around it changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Literal

from secguard.core.catalog import SEVERITY_ORDER, severity_rank
from secguard.core.findings import Finding, FindingDocument
from secguard.core.waivers import Waiver, WaiverDocument

FindingStatus = Literal["active", "waived"]

NO_THRESHOLD = "none"
FAIL_ON_CHOICES: tuple[str, ...] = (NO_THRESHOLD, *SEVERITY_ORDER)

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_INPUT_ERROR = 2


@dataclass(frozen=True)
class ReconciledFinding:
    """One canonical finding with its waiver decision."""

    finding: Finding
    status: FindingStatus
    waiver_ids: tuple[str, ...] = ()
    expired_waiver_id: str | None = None

    @property
    def waiver_id(self) -> str | None:
        """The waivers that suppressed this finding, joined for display."""
        return "+".join(self.waiver_ids) if self.waiver_ids else None


@dataclass(frozen=True)
class ScanOutcome:
    """The result of reconciling a scan against the waiver file."""

    results: list[ReconciledFinding]
    expired_waivers: list[Waiver] = field(default_factory=list)
    unused_waivers: list[Waiver] = field(default_factory=list)
    narrowed_waivers: list[Waiver] = field(default_factory=list)
    fail_on: str = NO_THRESHOLD
    checked_on: date | None = None

    @property
    def active(self) -> list[ReconciledFinding]:
        """Findings that no active waiver covers."""
        return [result for result in self.results if result.status == "active"]

    @property
    def waived(self) -> list[ReconciledFinding]:
        """Findings suppressed by an active waiver."""
        return [result for result in self.results if result.status == "waived"]

    @property
    def blocking(self) -> list[ReconciledFinding]:
        """Active findings at or above the configured severity threshold."""
        if self.fail_on == NO_THRESHOLD:
            return []
        threshold = severity_rank(self.fail_on)
        return [
            result for result in self.active if severity_rank(result.finding.severity) >= threshold
        ]

    @property
    def failed(self) -> bool:
        """Whether the gate should block."""
        return bool(self.blocking) or bool(self.expired_waivers)

    @property
    def exit_code(self) -> int:
        """Process exit code for the gate."""
        return EXIT_GATE_FAILED if self.failed else EXIT_OK

    def document(self, status: FindingStatus | None = None) -> FindingDocument:
        """Return a canonical document for all findings or one status subset."""
        selected = (
            self.results
            if status is None
            else [result for result in self.results if result.status == status]
        )
        return FindingDocument(findings=[result.finding for result in selected])

    def severity_counts(self, status: FindingStatus | None = None) -> dict[str, int]:
        """Return finding counts per severity, highest first."""
        return self.document(status).severity_counts()

    def secret_type_counts(self) -> dict[str, int]:
        """Return active-finding counts per canonical secret type, highest count first."""
        counts: dict[str, int] = {}
        for result in self.active:
            counts[result.finding.secret_type] = counts.get(result.finding.secret_type, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def playbooks(self) -> list[str]:
        """Return the distinct playbook slugs a responder needs for active findings."""
        return sorted({result.finding.playbook for result in self.active})


def reconcile(
    document: FindingDocument,
    waivers: WaiverDocument,
    *,
    today: date,
    fail_on: str = "high",
) -> ScanOutcome:
    """Apply the waiver lifecycle to canonical findings and compute the gate outcome."""
    if fail_on not in FAIL_ON_CHOICES:
        raise ValueError(f"fail_on must be one of: {', '.join(FAIL_ON_CHOICES)}")

    used_waiver_ids: set[str] = set()
    results: list[ReconciledFinding] = []

    for finding in document.findings:
        covering = waivers.match(
            rules=finding.rules,
            secret_type=finding.secret_type,
            path=finding.path,
            today=today,
        )

        if covering:
            used_waiver_ids.update(waiver.id for waiver in covering)
            results.append(
                ReconciledFinding(
                    finding=finding,
                    status="waived",
                    waiver_ids=tuple(waiver.id for waiver in covering),
                )
            )
            continue

        results.append(
            ReconciledFinding(
                finding=finding,
                status="active",
                expired_waiver_id=_expired_cover(waivers, finding, today),
            )
        )

    expired = waivers.expired(today)
    expired_ids = {waiver.id for waiver in expired}
    unused = [
        waiver
        for waiver in waivers.waivers
        if waiver.id not in used_waiver_ids and waiver.id not in expired_ids
    ]

    active_waivers = [waiver for waiver in waivers.waivers if waiver.id not in expired_ids]

    return ScanOutcome(
        results=results,
        expired_waivers=expired,
        unused_waivers=unused,
        narrowed_waivers=_narrowed_waivers(active_waivers, results),
        fail_on=fail_on,
        checked_on=today,
    )


def _narrowed_waivers(active: list[Waiver], results: list[ReconciledFinding]) -> list[Waiver]:
    """Return active waivers that cover part of a still-active merged finding.

    Without this, the near miss is invisible and reads like a bug: the waiver's
    rule and path both look like they match the blocking finding, because the
    console shows only the primary detection's rule. Naming it turns a confusing
    "why is my waiver unused?" into a one-line answer.

    Every active waiver is considered, not only the unused ones. A waiver that
    suppresses one finding while falling short on another is exactly the case
    where the operator has the least reason to suspect a scope problem.
    """
    # Only findings that are still blocking matter here. A near miss on a
    # finding some other waiver already suppressed is not a problem to report.
    merged = [
        result.finding
        for result in results
        if result.status == "active" and len(result.finding.rules) > 1
    ]
    narrowed: list[Waiver] = []

    for waiver in active:
        for finding in merged:
            scope = {"secret_type": finding.secret_type, "path": finding.path}
            if waiver.covers(rules=finding.rules, **scope):
                continue
            if any(waiver.covers(rules=(rule,), **scope) for rule in finding.rules):
                narrowed.append(waiver)
                break

    return narrowed


def _expired_cover(waivers: WaiverDocument, finding: Finding, today: date) -> str | None:
    """Return the id of an expired waiver that would have covered this finding."""
    for waiver in waivers.waivers:
        if not waiver.is_expired(today):
            continue
        if waiver.covers(
            rules=finding.rules,
            secret_type=finding.secret_type,
            path=finding.path,
        ):
            return waiver.id
    return None
