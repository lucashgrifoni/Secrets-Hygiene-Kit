"""Deterministic file handoffs for OPA and DefectDojo; no transport or execution."""

from __future__ import annotations

import hashlib
import json

from secguard.core.findings import FindingError
from secguard.core.reconcile import ScanOutcome
from secguard.core.redaction import sanitize_text


def build_opa_input(outcome: ScanOutcome, *, version: str) -> dict:
    if outcome.checked_on is None:
        raise FindingError("OPA export requires a checked date")
    return {
        "schema": "secguard.policy-input/v1",
        "producer": {"name": "secguard", "version": version},
        "checked_on": outcome.checked_on.isoformat(),
        "gate": {
            "passed": not outcome.failed,
            "fail_on": outcome.fail_on,
            "expired_waivers": sorted(waiver.id for waiver in outcome.expired_waivers),
        },
        "findings": [
            {
                **item.finding.model_dump(mode="json"),
                "status": item.status,
                "waiver_ids": list(item.waiver_ids),
            }
            for item in outcome.results
        ],
    }


def build_defectdojo_report(outcome: ScanOutcome, *, version: str) -> dict:
    """Generic Findings Import, active only; waived does not mean remediated."""
    if outcome.checked_on is None:
        raise FindingError("DefectDojo export requires a checked date")
    findings = []
    for item in outcome.active:
        finding = item.finding
        if len(finding.path) > 4000 or any(len(rule) > 500 for rule in finding.rules):
            raise FindingError("DefectDojo export exceeds the consumer's path or rule length limit")
        identity = json.dumps(
            [finding.secret_type, finding.path, finding.line],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        identifier = "secguard:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        verification = (
            f"detector:{str(finding.verified).lower()}"
            if finding.verified is not None
            else "not-reported"
        )
        row = {
            "title": sanitize_text(
                f"{finding.secret_title}: {finding.path}:{finding.line or '?'}", max_length=511
            ),
            "description": (
                f"{finding.message}\n\nRules: {', '.join(finding.rules)}\n"
                f"Credential verification: {verification} (imported claim).\n"
                "DefectDojo verified=false; human triage has not been established."
            ),
            "severity": finding.severity.capitalize(),
            "date": outcome.checked_on.isoformat(),
            "file_path": finding.path,
            "unique_id_from_tool": identifier,
            "vuln_id_from_tool": finding.rule,
            "mitigation": f"secguard incident start --secret-type {finding.secret_type}",
            "active": True,
            "verified": False,
            "static_finding": True,
            "dynamic_finding": False,
        }
        if finding.line is not None:
            row["line"] = finding.line
        findings.append(row)
    return {
        "type": "secguard",
        "version": version,
        "description": (
            f"Active secret findings checked on {outcome.checked_on.isoformat()}. "
            f"{len(outcome.waived)} waived finding(s) omitted. "
            "An omitted or waived finding is not evidence of remediation."
        ),
        "findings": sorted(findings, key=lambda item: item["unique_id_from_tool"]),
    }
