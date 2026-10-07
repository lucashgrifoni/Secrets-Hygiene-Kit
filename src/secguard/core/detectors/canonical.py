"""Reimport secguard exports without trusting their derived policy fields."""

from __future__ import annotations

from pydantic import ValidationError

from secguard.core.catalog import RuleCatalog, max_severity
from secguard.core.detectors.base import load_json
from secguard.core.findings import (
    CANONICAL_FINDINGS_SCHEMA_VERSION,
    Finding,
    FindingDocument,
    FindingParseError,
    build_finding,
    validate_repository_relative_path,
)
from secguard.core.redaction import (
    has_control_characters,
    sanitize_commit,
    sanitize_text,
    validation_error_details,
)


def parse_report(text: str, *, source: str, catalog: RuleCatalog) -> FindingDocument:
    content = load_json(text, source=source)
    if not isinstance(content, dict) or content.get("schema") != CANONICAL_FINDINGS_SCHEMA_VERSION:
        raise FindingParseError(f"{source}: canonical input requires secguard.findings/v1")
    # Strict validation prevents strings/integers from becoming verification
    # booleans and boolean/string line numbers from becoming source locations.
    try:
        document = FindingDocument.model_validate(content, strict=True)
    except ValidationError as exc:
        raise FindingParseError(
            f"{source}: invalid canonical input: "
            + validation_error_details(exc.errors(include_input=False))
        ) from exc
    findings = []
    for index, finding in enumerate(document.findings):
        try:
            findings.append(_rebuild(finding, catalog))
        except ValueError as exc:
            # Do not echo untrusted field names, fingerprints or metadata.
            raise FindingParseError(f"{source}: invalid canonical finding {index}: {exc}") from exc
    return FindingDocument(findings=findings)


def _identifier(value: str) -> str:
    if not value or has_control_characters(value):
        raise ValueError("identifiers must be nonempty text without control characters")
    return value


def _native_rule(rule: str, scanner: str) -> str:
    _identifier(scanner)
    _identifier(rule)
    prefix = f"{scanner}:"
    if not rule.startswith(prefix) or not rule[len(prefix) :]:
        raise ValueError("rule must be qualified by its declared scanner")
    return rule[len(prefix) :]


def _rebuild(item: Finding, catalog: RuleCatalog) -> Finding:
    rule_id = _native_rule(item.rule, item.scanner)
    path = validate_repository_relative_path(item.path)
    fingerprint = _identifier(item.fingerprint)
    classification = catalog.classify(item.scanner, rule_id)
    severities = [item.severity, classification.severity]
    scanners = {_identifier(scanner) for scanner in item.corroborated_by}
    rules = sorted(set(item.corroborated_rules) - {item.rule})
    known_scanners = sorted({item.scanner, *scanners}, key=len, reverse=True)
    for rule in rules:
        _identifier(rule)
        scanner = next((name for name in known_scanners if rule.startswith(f"{name}:")), None)
        if scanner is None:
            raise ValueError("corroborated rule must name a declared scanner")
        mapped = catalog.classify(scanner, _native_rule(rule, scanner))
        if mapped.secret_type != classification.secret_type:
            raise ValueError("corroborated rules must resolve to the same secret type")
        severities.append(mapped.severity)
    if scanners - {item.scanner} != {
        name
        for name in scanners
        if name != item.scanner and any(rule.startswith(f"{name}:") for rule in rules)
    }:
        raise ValueError("corroborated scanners must have a corroborated rule")
    message = sanitize_text(item.message)
    if not message:
        raise ValueError("message cannot be empty")
    rebuilt = build_finding(
        scanner=item.scanner,
        rule_id=rule_id,
        path=path,
        message=message,
        catalog=catalog,
        severity=max_severity(*severities),
        line=item.line,
        column=item.column,
        fingerprint=fingerprint,
        commit=sanitize_commit(item.commit),
        verified=item.verified,
        remediation=sanitize_text(item.remediation) if item.remediation is not None else None,
    )
    return rebuilt.model_copy(
        update={
            "corroborated_by": sorted(scanners - {item.scanner}),
            "corroborated_rules": rules,
        }
    )
