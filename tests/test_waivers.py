from datetime import date

import pytest

from secguard.core.waivers import (
    Waiver,
    WaiverDocument,
    WaiverParseError,
    load_waiver_file,
    new_waiver_document,
    write_waiver_file,
)


def _waiver(**overrides) -> Waiver:
    base = {
        "id": "WV-2026-001",
        "rule": "gitleaks:aws-access-token",
        "path": "tests/fixtures/dummy.py",
        "reason": "Intentional fixture, not a real credential.",
        "owner": "appsec@example.invalid",
        "expires_at": date(2026, 12, 1),
        "approver": "security-lead",
    }
    return Waiver.model_validate({**base, **overrides})


def test_load_waiver_file_parses_valid_document(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        """
schema: "secguard.waiver/v1"
waivers:
  - id: WV-2026-001
    rule: gitleaks:aws-access-key
    path: tests/fixtures/aws_key_dummy.py
    reason: "Intentional fixture, not a real credential."
    owner: appsec@example.com
    expires_at: 2026-08-12
    approver: security-lead
""",
        encoding="utf-8",
    )

    document = load_waiver_file(waiver_file)

    assert isinstance(document, WaiverDocument)
    assert document.waivers[0].id == "WV-2026-001"
    assert not document.waivers[0].is_expired(date(2026, 5, 18))


def test_document_reports_expired_waivers():
    document = WaiverDocument.model_validate(
        {
            "schema": "secguard.waiver/v1",
            "waivers": [
                {
                    "id": "WV-2026-001",
                    "rule": "gitleaks:github-pat",
                    "path": "tests/fixtures/token.txt",
                    "reason": "Intentional detector fixture.",
                    "owner": "appsec@example.com",
                    "expires_at": "2026-05-17",
                    "approver": "security-lead",
                }
            ],
        }
    )

    assert [waiver.id for waiver in document.expired(date(2026, 5, 18))] == ["WV-2026-001"]


def test_duplicate_waiver_ids_are_rejected(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        """
schema: "secguard.waiver/v1"
waivers:
  - id: WV-2026-001
    rule: gitleaks:aws-access-key
    path: tests/fixtures/one.py
    reason: "First fixture."
    owner: appsec@example.com
    expires_at: 2026-08-12
    approver: security-lead
  - id: WV-2026-001
    rule: gitleaks:github-pat
    path: tests/fixtures/two.py
    reason: "Second fixture."
    owner: appsec@example.com
    expires_at: 2026-08-13
    approver: security-lead
""",
        encoding="utf-8",
    )

    with pytest.raises(WaiverParseError, match="duplicate waiver id"):
        load_waiver_file(waiver_file)


def test_unknown_fields_are_rejected(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        """
schema: "secguard.waiver/v1"
waivers:
  - id: WV-2026-001
    rule: gitleaks:aws-access-key
    path: tests/fixtures/aws_key_dummy.py
    reason: "Intentional fixture."
    owner: appsec@example.com
    expires_at: 2026-08-12
    approver: security-lead
    unexpected_field: "not allowed"
""",
        encoding="utf-8",
    )

    with pytest.raises(WaiverParseError, match="Extra inputs are not permitted"):
        load_waiver_file(waiver_file)


def test_waiver_scope_rejects_absolute_paths():
    """A waiver whose scope can never match is a silent hole in the exception log."""
    with pytest.raises(ValueError, match="repository-relative"):
        _waiver(path="/etc/passwd")

    with pytest.raises(ValueError, match="repository-relative"):
        _waiver(path="C:/secrets/key.txt")


def test_waiver_scope_rejects_parent_traversal():
    with pytest.raises(ValueError, match="parent traversal"):
        _waiver(path="../outside/key.txt")


def test_waiver_scope_normalizes_windows_separators():
    assert _waiver(path=r"tests\fixtures\dummy.py").path == "tests/fixtures/dummy.py"


def test_a_datetime_expiry_is_rejected():
    """`expires_at: 2026-12-01T00:00:00Z` in YAML would parse as a datetime."""
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        _waiver(expires_at="2026-12-01T00:00:00Z")


def test_waiver_covers_matches_rule_and_path():
    waiver = _waiver()

    assert waiver.covers(
        rules=("gitleaks:aws-access-token",),
        secret_type="aws-access-key",
        path="tests/fixtures/dummy.py",
    )
    assert not waiver.covers(
        rules=("gitleaks:github-pat",),
        secret_type="github-pat",
        path="tests/fixtures/dummy.py",
    )


def test_a_detector_scoped_waiver_must_cover_every_contributing_rule():
    """Partial coverage of a merged finding is no coverage at all.

    Merging collapses the same leak reported by several detectors into one
    record. If a waiver written for one detector could suppress the merged
    record, adding a second scanner would silence the first scanner's alert
    instead of corroborating it.
    """
    waiver = _waiver()
    merged = ("gitleaks:aws-access-token", "trufflehog:AWS")

    assert not waiver.covers(
        rules=merged, secret_type="aws-access-key", path="tests/fixtures/dummy.py"
    )
    assert _waiver(rule="*").covers(
        rules=merged, secret_type="aws-access-key", path="tests/fixtures/dummy.py"
    )
    # The canonical secret type is the merge key, so it is shared by every
    # contributing detection and a `secret-type:` waiver still applies.
    assert _waiver(rule="secret-type:aws-access-key").covers(
        rules=merged, secret_type="aws-access-key", path="tests/fixtures/dummy.py"
    )


def test_a_waiver_covers_nothing_when_no_rule_contributed():
    assert not _waiver().covers(
        rules=(), secret_type="aws-access-key", path="tests/fixtures/dummy.py"
    )


def test_waiver_covers_ignores_expiry_so_reconcile_can_report_the_reason():
    expired = _waiver(expires_at=date(2020, 1, 1))

    assert expired.is_expired(date(2026, 8, 4))
    assert expired.covers(
        rules=("gitleaks:aws-access-token",),
        secret_type="aws-access-key",
        path="tests/fixtures/dummy.py",
    )


def test_next_id_continues_the_sequence_for_the_current_year():
    document = new_waiver_document([_waiver(id="WV-2026-001"), _waiver(id="WV-2026-007")])

    assert document.next_id(date(2026, 8, 4)) == "WV-2026-008"
    assert document.next_id(date(2027, 1, 1)) == "WV-2027-001"


def test_next_id_ignores_ids_that_do_not_follow_the_sequence():
    document = new_waiver_document([_waiver(id="WV-2026-legacy")])

    assert document.next_id(date(2026, 8, 4)) == "WV-2026-001"


def test_written_waiver_files_round_trip(tmp_path):
    path = tmp_path / "nested" / "waivers.yaml"
    write_waiver_file(path, new_waiver_document([_waiver()]))

    reloaded = load_waiver_file(path)

    assert [waiver.id for waiver in reloaded.waivers] == ["WV-2026-001"]
    assert reloaded.waivers[0].expires_at == date(2026, 12, 1)


def test_written_waiver_files_carry_the_hygiene_header(tmp_path):
    path = tmp_path / "waivers.yaml"
    write_waiver_file(path, new_waiver_document([_waiver()]))
    body = path.read_text(encoding="utf-8")

    assert body.startswith("# secguard waivers")
    assert "Do not store secret values" in body


def test_a_waiver_file_missing_its_schema_is_rejected(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text("waivers: []\n", encoding="utf-8")

    with pytest.raises(WaiverParseError, match="schema"):
        load_waiver_file(waiver_file)


def test_an_empty_waiver_file_is_rejected(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text("", encoding="utf-8")

    with pytest.raises(WaiverParseError):
        load_waiver_file(waiver_file)


def test_a_non_mapping_waiver_file_is_rejected(tmp_path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text("- just\n- a\n- list\n", encoding="utf-8")

    with pytest.raises(WaiverParseError, match="YAML mapping"):
        load_waiver_file(waiver_file)


def test_document_helper_types():
    document = new_waiver_document()

    assert isinstance(document, WaiverDocument)
    assert document.waivers == []


def test_an_impossible_date_is_an_input_error_not_a_crash(tmp_path):
    """PyYAML resolves `2026-02-30` before secguard sees it and raises ValueError.

    Letting that escape turned a typo into a traceback and exit 1, which a CI
    log reads as "the gate blocked" rather than "fix your waiver file".
    """
    path = tmp_path / "waivers.yaml"
    path.write_text(
        "schema: secguard.waiver/v1\n"
        "waivers:\n"
        "  - id: WV-2026-001\n"
        "    rule: gitleaks:aws-access-token\n"
        "    path: app/config.py\n"
        "    reason: r\n"
        "    owner: o\n"
        "    approver: a\n"
        "    expires_at: 2026-02-30\n",
        encoding="utf-8",
    )

    with pytest.raises(WaiverParseError, match="no date can represent"):
        load_waiver_file(path)
