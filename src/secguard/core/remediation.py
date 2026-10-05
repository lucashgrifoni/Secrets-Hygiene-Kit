"""A bounded, versioned handoff of active findings to remediation consumers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from secguard.core.catalog import Severity, severity_rank
from secguard.core.findings import FindingError, validate_repository_relative_path
from secguard.core.reconcile import ScanOutcome

MAX_EXCHANGE_BYTES = 16 * 1024 * 1024
REPOSITORY_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}"
SLUG_PATTERN = r"[a-z0-9]+(?:-[a-z0-9]+)*"
VERSION_PATTERN = r"[0-9]+\.[0-9]+\.[0-9]+"


class RemediationModel(BaseModel):
    """Unknown fields and scalar coercions are rejected at the handoff boundary."""

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


class Producer(RemediationModel):
    name: Literal["secguard"]
    version: str = Field(max_length=32)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        if re.fullmatch(VERSION_PATTERN, value) is None:
            raise ValueError("unsupported producer version")
        return value


class RemediationGate(RemediationModel):
    decision: Literal["PASS", "BLOCK"]
    fail_on: Literal["none", "critical", "high", "medium", "low", "info"]
    expired_waivers: int = Field(ge=0)


class RemediationFinding(RemediationModel):
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$", max_length=64)
    secret_type: str = Field(max_length=100)
    severity: Severity
    path: str = Field(max_length=4096)
    line: int | None = Field(default=None, ge=1)
    playbook: str = Field(max_length=100)

    @field_validator("secret_type", "playbook")
    @classmethod
    def valid_slug(cls, value: str) -> str:
        if re.fullmatch(SLUG_PATTERN, value) is None:
            raise ValueError("invalid response identifier")
        return value

    @field_validator("path")
    @classmethod
    def relative_path(cls, value: str) -> str:
        return validate_repository_relative_path(value)


class RemediationDocument(RemediationModel):
    schema_version: Literal["secguard.remediation/v1"] = Field(alias="schema")
    producer: Producer
    repository: str = Field(max_length=201)
    checked_on: date
    gate: RemediationGate
    omitted_waived: int = Field(ge=0)
    findings: list[RemediationFinding] = Field(max_length=10000)

    @field_validator("repository")
    @classmethod
    def valid_repository(cls, value: str) -> str:
        if re.fullmatch(REPOSITORY_PATTERN, value) is None:
            raise ValueError("repository must be owner/name")
        return value

    @model_validator(mode="after")
    def distinct_occurrences(self) -> RemediationDocument:
        fingerprints = [item.fingerprint for item in self.findings]
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("duplicate occurrence fingerprint")
        blocking = self.gate.expired_waivers > 0 or (
            self.gate.fail_on != "none"
            and any(
                severity_rank(item.severity) >= severity_rank(self.gate.fail_on)
                for item in self.findings
            )
        )
        if self.gate.decision != ("BLOCK" if blocking else "PASS"):
            raise ValueError("gate decision contradicts the active findings")
        return self


def build_remediation_document(
    outcome: ScanOutcome, *, repository: str, version: str
) -> RemediationDocument:
    """Export only active findings, without scanner free text or native digests.

    The consumer correlates secrets by fingerprint, rather than location. The
    digest therefore includes the occurrence's path and line: two exposures
    must remain two findings even if their native detector digest is identical.
    """
    if outcome.checked_on is None:
        raise FindingError("remediation export requires a checked date")
    try:
        findings = []
        for result in outcome.active:
            finding = result.finding
            identity = json.dumps(
                [repository, finding.secret_type, finding.path, finding.line, finding.fingerprint],
                ensure_ascii=True,
                separators=(",", ":"),
            )
            fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
            findings.append(
                RemediationFinding(
                    fingerprint=fingerprint,
                    secret_type=finding.secret_type,
                    severity=finding.severity,
                    path=finding.path,
                    line=finding.line,
                    playbook=finding.playbook,
                )
            )
        return RemediationDocument(
            schema_version="secguard.remediation/v1",
            producer=Producer(name="secguard", version=version),
            repository=repository,
            checked_on=outcome.checked_on,
            gate=RemediationGate(
                decision="BLOCK" if outcome.failed else "PASS",
                fail_on=outcome.fail_on,
                expired_waivers=len(outcome.expired_waivers),
            ),
            omitted_waived=len(outcome.waived),
            findings=sorted(findings, key=lambda item: item.fingerprint),
        )
    except ValidationError as exc:
        raise FindingError("remediation export rejected an invalid field or repository") from exc


def serialize_remediation_document(document: RemediationDocument) -> str:
    """Use the reader's byte limit before emitting the exchange."""
    content = (
        json.dumps(document.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n"
    )
    if len(content.encode("utf-8")) > MAX_EXCHANGE_BYTES:
        raise FindingError("remediation exchange exceeds the size limit")
    return content


def load_remediation_file(path: Path) -> RemediationDocument:
    """Read a bounded exchange; never echo its values in validation diagnostics."""
    try:
        with path.open("rb") as stream:
            content = stream.read(MAX_EXCHANGE_BYTES + 1)
        if len(content) > MAX_EXCHANGE_BYTES:
            raise FindingError("remediation exchange exceeds the size limit")
        return RemediationDocument.model_validate_json(content)
    except (ValidationError, ValueError) as exc:
        raise FindingError("invalid secguard remediation exchange") from exc
    except OSError as exc:
        raise FindingError("cannot read remediation exchange") from exc


def playbook_url(document: RemediationDocument, finding: RemediationFinding) -> str:
    """Build an immutable-version guidance link from validated identifiers."""
    return (
        "https://github.com/lucashgrifoni/secrets-hygiene-kit/blob/"
        f"v{document.producer.version}/src/secguard/playbooks/{finding.playbook}/PLAYBOOK.md"
    )
