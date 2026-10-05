"""Rule catalog mapping detector rules to secret types, severity, and playbooks.

The catalog is the bridge between detection and response: a detector reports
``gitleaks:aws-access-token`` and secguard turns that into the canonical secret
type ``aws-access-key``, a default severity, and the playbook a responder should
open. Mappings are best effort because detector rule identifiers change between
releases, so an unmapped rule resolves to the fallback secret type and is
flagged as ``fallback`` rather than silently presented as a confident match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from secguard.core.redaction import has_control_characters, sanitize_text, validation_error_details

CATALOG_SCHEMA_VERSION = "secguard.rules/v1"
DATA_DIRECTORY = "data"
PACKAGED_CATALOG_NAME = "rules.yaml"
LOCAL_CATALOG_PATH = Path(".secguard/rules.yaml")

Severity = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_ORDER: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK: dict[str, int] = {name: index for index, name in enumerate(SEVERITY_ORDER)}

_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_NORMALIZE_PATTERN = re.compile(r"[^a-z0-9]+")

MappingConfidence = Literal["catalog", "fallback"]


class CatalogError(Exception):
    """Base class for rule catalog loading and validation errors."""


def severity_rank(severity: str) -> int:
    """Return the ordinal rank of a severity label, lowest first."""
    try:
        return _SEVERITY_RANK[severity]
    except KeyError as exc:
        raise CatalogError(f"unknown severity: {severity}") from exc


def max_severity(*severities: str) -> Severity:
    """Return the highest severity from the given labels."""
    if not severities:
        raise CatalogError("at least one severity is required")
    return max(severities, key=severity_rank)  # type: ignore[return-value]


def normalize_rule_key(value: str) -> str:
    """Normalize a detector rule identifier for tolerant lookups."""
    return _NORMALIZE_PATTERN.sub("-", value.strip().lower()).strip("-")


class SecretTypeSpec(BaseModel):
    """Canonical secret type with its default severity and playbook."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(..., description="Human-readable secret type name.")
    severity: Severity = Field(..., description="Default severity for this secret type.")
    playbook: str = Field(..., description="Playbook slug that describes the response.")

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        """Reject empty titles."""
        if not value:
            raise ValueError("field cannot be empty")
        if has_control_characters(value):
            raise ValueError("title cannot contain control characters or escape sequences")
        return sanitize_text(value)

    @field_validator("playbook")
    @classmethod
    def validate_playbook_slug(cls, value: str) -> str:
        """Reject playbook slugs that could escape the packaged playbook tree."""
        if not _SLUG_PATTERN.match(value):
            raise ValueError("playbook must be a lowercase kebab-case slug")
        return value


class DetectorRuleSpec(BaseModel):
    """One detector rule mapped onto a canonical secret type."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    secret_type: str = Field(..., description="Canonical secret type key.")
    severity: Severity | None = Field(
        default=None,
        description="Severity override for this specific detector rule.",
    )

    @model_validator(mode="before")
    @classmethod
    def allow_shorthand(cls, value: Any) -> Any:
        """Accept the `rule: secret-type` shorthand alongside the mapping form."""
        if isinstance(value, str):
            return {"secret_type": value}
        return value


@dataclass(frozen=True)
class Classification:
    """The catalog decision for one detector rule."""

    secret_type: str
    title: str
    severity: Severity
    playbook: str
    mapping: MappingConfidence


class RuleCatalog(BaseModel):
    """Detector rule catalog document."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)

    schema_version: Literal["secguard.rules/v1"] = Field(
        default=CATALOG_SCHEMA_VERSION,
        alias="schema",
    )
    fallback_secret_type: str = Field(
        default="generic-api-key",
        description="Secret type used when a detector rule is not mapped.",
    )
    secret_types: dict[str, SecretTypeSpec] = Field(default_factory=dict)
    detectors: dict[str, dict[str, DetectorRuleSpec]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_references(self) -> RuleCatalog:
        """Ensure every referenced secret type exists in the catalog."""
        if not self.secret_types:
            raise ValueError("catalog must define at least one secret type")

        for key in self.secret_types:
            if not _SLUG_PATTERN.match(key):
                raise ValueError("secret type keys must be lowercase kebab-case")

        if self.fallback_secret_type not in self.secret_types:
            raise ValueError("fallback secret type must refer to a defined secret type")

        for detector, rules in self.detectors.items():
            if not detector or has_control_characters(detector):
                raise ValueError("detector names cannot be empty or contain control characters")
            for rule_id, spec in rules.items():
                if not rule_id or has_control_characters(rule_id):
                    raise ValueError(
                        "rule identifiers cannot be empty or contain control characters"
                    )
                if spec.secret_type not in self.secret_types:
                    raise ValueError("detector rule refers to an unknown secret type")

        return self

    def classify(self, scanner: str, rule_id: str) -> Classification:
        """Resolve a detector rule to a secret type, severity, and playbook."""
        spec = self._lookup(scanner, rule_id)

        if spec is None:
            secret_type = self.fallback_secret_type
            definition = self.secret_types[secret_type]
            return Classification(
                secret_type=secret_type,
                title=definition.title,
                severity=definition.severity,
                playbook=definition.playbook,
                mapping="fallback",
            )

        definition = self.secret_types[spec.secret_type]
        return Classification(
            secret_type=spec.secret_type,
            title=definition.title,
            severity=spec.severity or definition.severity,
            playbook=definition.playbook,
            mapping="catalog",
        )

    def playbook_for(self, secret_type: str) -> str | None:
        """Return the playbook slug for a canonical secret type."""
        definition = self.secret_types.get(secret_type)
        return definition.playbook if definition else None

    def _lookup(self, scanner: str, rule_id: str) -> DetectorRuleSpec | None:
        rules = self.detectors.get(scanner) or self.detectors.get(normalize_rule_key(scanner)) or {}

        exact = rules.get(rule_id)
        if exact is not None:
            return exact

        normalized_rule = normalize_rule_key(rule_id)
        for candidate_id, spec in rules.items():
            if normalize_rule_key(candidate_id) == normalized_rule:
                return spec

        # A custom detector rule named exactly like a canonical secret type is a
        # deliberate signal from the team, so honor it before falling back.
        if normalized_rule in self.secret_types:
            return DetectorRuleSpec(secret_type=normalized_rule)

        return None


def load_catalog(override: Path | None = None) -> RuleCatalog:
    """Load the packaged catalog and merge an optional local override file."""
    catalog = _parse_catalog(_read_packaged_catalog(), source="packaged rule catalog")

    if override is None:
        return catalog

    if not override.exists():
        raise CatalogError(f"rule catalog override not found: {override}")
    if not override.is_file():
        raise CatalogError(f"rule catalog override is not a file: {override}")

    # PyYAML raises a bare ValueError for a resolvable-but-impossible scalar
    # such as `2026-02-30`, which would escape as a traceback and exit 1.
    try:
        raw = yaml.safe_load(override.read_text(encoding="utf-8"))
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        raise CatalogError(
            f"cannot parse rule catalog override {override}: the YAML is malformed or "
            "holds a value no date can represent, such as 2026-02-30"
        ) from exc
    except OSError as exc:
        raise CatalogError(f"cannot read rule catalog override {override}: {exc.strerror}") from exc

    if raw is None:
        return catalog
    if not isinstance(raw, dict):
        raise CatalogError(f"rule catalog override must contain a YAML mapping: {override}")

    merged = _merge_catalog_documents(catalog.model_dump(mode="json", by_alias=True), raw)
    return _parse_catalog(merged, source=f"rule catalog override {override}")


#
# There is deliberately no helper that discovers a local catalog and loads it.
# `LOCAL_CATALOG_PATH` is the conventional place to keep one, and `--rules`
# names it explicitly. A catalog can lower a severity, and a severity below the
# threshold does not block, so a catalog picked up implicitly from inside the
# scanned checkout would let anyone who can open a pull request turn a blocking
# finding into a passing one — with none of the owner, approver, or expiry the
# waiver lifecycle requires for exactly that decision.


def _read_packaged_catalog() -> dict[str, Any]:
    text = (
        files("secguard")
        .joinpath(DATA_DIRECTORY, PACKAGED_CATALOG_NAME)
        .read_text(encoding="utf-8")
    )
    content = yaml.safe_load(text)
    if not isinstance(content, dict):
        raise CatalogError("packaged rule catalog must contain a YAML mapping")
    return content


def _merge_catalog_documents(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge an override document over the packaged catalog, one level deep."""
    merged: dict[str, Any] = dict(base)

    for key, value in override.items():
        if key == "secret_types" and isinstance(value, dict):
            secret_types = dict(base.get("secret_types") or {})
            secret_types.update(value)
            merged["secret_types"] = secret_types
        elif key == "detectors" and isinstance(value, dict):
            detectors = {name: dict(rules) for name, rules in (base.get("detectors") or {}).items()}
            for detector, rules in value.items():
                if not isinstance(rules, dict):
                    raise CatalogError("each detector must map rule ids to secret types")
                detectors.setdefault(detector, {}).update(rules)
            merged["detectors"] = detectors
        else:
            merged[key] = value

    return merged


def _parse_catalog(content: dict[str, Any], *, source: str) -> RuleCatalog:
    try:
        return RuleCatalog.model_validate(content)
    except ValidationError as exc:
        details = validation_error_details(exc.errors(include_input=False))
        raise CatalogError(f"invalid {source}: {details}") from exc
