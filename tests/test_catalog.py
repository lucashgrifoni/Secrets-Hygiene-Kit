"""Rule catalog resolution, severity ordering, and local overrides."""

from __future__ import annotations

import pytest

from secguard.core.catalog import (
    SEVERITY_ORDER,
    CatalogError,
    default_catalog_override,
    load_catalog,
    max_severity,
    normalize_rule_key,
    severity_rank,
)


def test_severity_order_is_lowest_to_highest():
    assert SEVERITY_ORDER == ("info", "low", "medium", "high", "critical")
    assert severity_rank("critical") > severity_rank("high") > severity_rank("info")
    assert max_severity("low", "critical", "medium") == "critical"


def test_unknown_severity_is_rejected():
    with pytest.raises(CatalogError, match="unknown severity"):
        severity_rank("urgent")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AWS Access Key", "aws-access-key"),
        ("  Base64 High Entropy String ", "base64-high-entropy-string"),
        ("aws_access_token", "aws-access-token"),
        ("GitHubOauth2", "githuboauth2"),
    ],
)
def test_rule_keys_normalize_for_tolerant_lookup(value, expected):
    assert normalize_rule_key(value) == expected


def test_exact_mapping_wins(catalog):
    classification = catalog.classify("gitleaks", "aws-access-token")

    assert classification.secret_type == "aws-access-key"
    assert classification.playbook == "aws-access-key"
    assert classification.severity == "high"
    assert classification.mapping == "catalog"


def test_lookup_tolerates_separator_and_case_drift(catalog):
    """Detectors rename `AWS Access Key` to `aws_access_key` between releases."""
    assert catalog.classify("detect-secrets", "aws access key").secret_type == "aws-access-key"
    assert catalog.classify("detect-secrets", "AWS_Access_Key").secret_type == "aws-access-key"


def test_a_rule_named_after_a_canonical_secret_type_is_honored(catalog):
    """A team that names its custom rule `postgres-uri` means it."""
    classification = catalog.classify("gitleaks", "postgres-uri")

    assert classification.secret_type == "postgres-uri"
    assert classification.mapping == "catalog"


def test_an_unmapped_rule_falls_back_and_is_flagged(catalog):
    classification = catalog.classify("gitleaks", "acme-internal-token")

    assert classification.secret_type == "generic-api-key"
    assert classification.mapping == "fallback"


def test_a_per_rule_severity_override_beats_the_secret_type_default(catalog):
    """Entropy heuristics share the generic playbook but deserve a lower severity."""
    assert catalog.classify("detect-secrets", "Base64 High Entropy String").severity == "low"
    assert catalog.classify("detect-secrets", "AWS Access Key").severity == "high"


def test_unknown_scanner_falls_back(catalog):
    assert catalog.classify("some-new-scanner", "whatever").mapping == "fallback"


def test_playbook_lookup(catalog):
    assert catalog.playbook_for("stripe-secret-key") == "stripe-secret-key"
    assert catalog.playbook_for("not-a-secret-type") is None


# ------------------------------------------------------------------- overrides


def test_a_local_override_adds_a_detector_mapping(tmp_path):
    override = tmp_path / "rules.yaml"
    override.write_text(
        "detectors:\n  gitleaks:\n    acme-internal-token: stripe-secret-key\n",
        encoding="utf-8",
    )

    catalog = load_catalog(override)
    classification = catalog.classify("gitleaks", "acme-internal-token")

    assert classification.secret_type == "stripe-secret-key"
    assert classification.mapping == "catalog"
    # Packaged mappings survive the merge.
    assert catalog.classify("gitleaks", "aws-access-token").secret_type == "aws-access-key"


def test_a_local_override_can_change_a_secret_type_severity(tmp_path):
    override = tmp_path / "rules.yaml"
    override.write_text(
        "secret_types:\n"
        "  slack-webhook:\n"
        "    title: Slack incoming webhook URL\n"
        "    severity: critical\n"
        "    playbook: slack-webhook\n",
        encoding="utf-8",
    )

    catalog = load_catalog(override)

    assert catalog.classify("gitleaks", "slack-webhook-url").severity == "critical"


def test_an_override_referencing_a_missing_secret_type_is_rejected(tmp_path):
    override = tmp_path / "rules.yaml"
    override.write_text(
        "detectors:\n  gitleaks:\n    acme-internal-token: not-a-secret-type\n",
        encoding="utf-8",
    )

    with pytest.raises(CatalogError, match="unknown secret type"):
        load_catalog(override)


def test_an_override_with_an_unsafe_playbook_slug_is_rejected(tmp_path):
    override = tmp_path / "rules.yaml"
    override.write_text(
        "secret_types:\n"
        "  evil:\n"
        "    title: Traversal attempt\n"
        "    severity: high\n"
        "    playbook: ../../etc/passwd\n",
        encoding="utf-8",
    )

    with pytest.raises(CatalogError, match="kebab-case"):
        load_catalog(override)


def test_a_missing_override_file_is_reported(tmp_path):
    with pytest.raises(CatalogError, match="override not found"):
        load_catalog(tmp_path / "absent.yaml")


def test_an_empty_override_leaves_the_packaged_catalog_intact(tmp_path):
    override = tmp_path / "rules.yaml"
    override.write_text("# nothing here\n", encoding="utf-8")

    assert load_catalog(override).classify("gitleaks", "aws-access-token").mapping == "catalog"


def test_default_override_is_discovered_only_when_present(tmp_path):
    assert default_catalog_override(tmp_path) is None

    secguard_dir = tmp_path / ".secguard"
    secguard_dir.mkdir()
    (secguard_dir / "rules.yaml").write_text("{}", encoding="utf-8")

    assert default_catalog_override(tmp_path) == secguard_dir / "rules.yaml"
