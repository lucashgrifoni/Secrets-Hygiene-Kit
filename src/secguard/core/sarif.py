"""SARIF 2.1.0 export for canonical secguard findings.

SARIF is how a scan result reaches GitHub code scanning, Azure DevOps Advanced
Security, and most aggregation tooling. Two design choices matter here:

- The SARIF ``ruleId`` identifies the canonical secret type and severity.
  Default severities keep the type ID; overrides use a stable severity suffix.
  This groups corroborating detectors without changing IDs between reports.
- A waived finding is emitted as a ``suppression`` rather than dropped. The
  reviewer sees that the exception exists, who owns it, and when it expires,
  instead of seeing a silent gap.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from secguard.core.catalog import RuleCatalog
from secguard.core.findings import Finding
from secguard.core.reconcile import ReconciledFinding, ScanOutcome
from secguard.core.redaction import sanitize_text
from secguard.core.waivers import Waiver

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "secguard"
TOOL_INFORMATION_URI = "https://github.com/lucashgrifoni/secrets-hygiene-kit"

_SARIF_LEVELS: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub reads `security-severity` to place an alert in its own severity bands.
_SECURITY_SEVERITY: dict[str, str] = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def build_sarif(outcome: ScanOutcome, *, catalog: RuleCatalog, version: str) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log for a reconciled scan outcome."""
    severities: dict[str, set[str]] = {}
    for result in outcome.results:
        finding = result.finding
        severities.setdefault(finding.secret_type, set()).add(finding.severity)

    rule_keys = sorted(
        (secret_type, severity)
        for secret_type, observed in severities.items()
        for severity in observed
    )
    rule_ids: dict[tuple[str, str], str] = {}
    for secret_type, observed in severities.items():
        default = catalog.secret_types[secret_type].severity
        for severity in observed:
            rule_ids[secret_type, severity] = (
                secret_type if severity == default else f"{secret_type}/{severity}"
            )
    rule_index = {key: index for index, key in enumerate(rule_keys)}

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": version,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": [
                            _rule(secret_type, catalog, severity, rule_ids[secret_type, severity])
                            for secret_type, severity in rule_keys
                        ],
                    }
                },
                "automationDetails": {"id": "secguard/scan"},
                "columnKind": "utf16CodeUnits",
                "results": [_result(result, rule_index, rule_ids) for result in outcome.results],
            }
        ],
    }


def _rule(secret_type: str, catalog: RuleCatalog, severity: str, rule_id: str) -> dict[str, Any]:
    definition = catalog.secret_types.get(secret_type)
    title = definition.title if definition else secret_type
    playbook = definition.playbook if definition else secret_type

    return {
        "id": rule_id,
        "name": _pascal_case(rule_id),
        "shortDescription": {"text": f"Exposed {title}"},
        "fullDescription": {
            "text": (
                f"A detector reported {title} in the repository. "
                f"Follow the secguard `{playbook}` playbook to contain access at the issuer, "
                "replace credentials and review activity during the exposure window."
            )
        },
        "help": {
            "text": f"Run `secguard incident start --secret-type {secret_type}` for the checklist.",
            "markdown": (
                f"Run `secguard incident start --secret-type {secret_type}` to print the "
                f"`{playbook}` response checklist."
            ),
        },
        "defaultConfiguration": {"level": _SARIF_LEVELS.get(severity, "warning")},
        "properties": {
            "tags": ["security", "secrets", rule_id],
            "security-severity": _SECURITY_SEVERITY.get(severity, "5.5"),
        },
    }


def _result(
    result: ReconciledFinding,
    rule_index: dict[tuple[str, str], int],
    rule_ids: dict[tuple[str, str], str],
) -> dict[str, Any]:
    finding = result.finding
    key = (finding.secret_type, finding.severity)
    payload: dict[str, Any] = {
        "ruleId": rule_ids[key],
        "ruleIndex": rule_index[key],
        "level": _SARIF_LEVELS.get(finding.severity, "warning"),
        "message": {"text": _message(finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.path, safe="/")},
                    **({"region": _region(finding)} if finding.line else {}),
                }
            }
        ],
        "partialFingerprints": {"secguard/v1": finding.fingerprint},
        "properties": {
            "secguardId": finding.id,
            "scanner": finding.scanner,
            "detectorRule": finding.rule,
            "playbook": finding.playbook,
            "mapping": finding.mapping,
            "secretType": finding.secret_type,
            "resolvedSeverity": finding.severity,
            **({"verified": finding.verified} if finding.verified is not None else {}),
            **({"corroboratedBy": finding.corroborated_by} if finding.corroborated_by else {}),
            **(
                {"corroboratedRules": finding.corroborated_rules}
                if finding.corroborated_rules
                else {}
            ),
        },
    }

    if result.status == "waived" and result.waiver_id:
        payload["suppressions"] = [
            {
                "kind": "external",
                "justification": f"secguard waiver {result.waiver_id}",
            }
        ]

    return payload


def _message(finding: Finding) -> str:
    parts = [sanitize_text(finding.message)]

    if finding.verified:
        parts.append(
            "The input detector report says it verified this credential as live at scan time."
        )
    if finding.mapping == "fallback":
        parts.append(
            f"Rule `{finding.rule}` is not in the secguard catalog, so the generic "
            f"`{finding.playbook}` playbook applies; add a mapping for provider-specific steps."
        )
    if finding.corroborated_by:
        parts.append(f"Also reported by: {', '.join(finding.corroborated_by)}.")

    parts.append(f"Response playbook: {finding.playbook}.")
    return " ".join(parts)


def _region(finding: Finding) -> dict[str, int]:
    region: dict[str, int] = {"startLine": finding.line or 1}
    if finding.column:
        region["startColumn"] = finding.column
    return region


def _pascal_case(slug: str) -> str:
    return "".join(part.capitalize() for part in slug.replace("/", "-").split("-"))


def waiver_summary(waiver: Waiver) -> str:
    """Return a one-line, non-sensitive summary of a waiver."""
    return (
        f"{waiver.id} rule={waiver.rule} path={waiver.path} "
        f"owner={waiver.owner} expires_at={waiver.expires_at.isoformat()}"
    )
