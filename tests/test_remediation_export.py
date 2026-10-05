"""Active-only, privacy and identity contracts for the remediation handoff."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from conftest import ALL_REPORTS, TODAY, assert_no_secret_material
from typer.testing import CliRunner

from secguard import __version__
from secguard.cli.app import app
from secguard.core.detectors import load_reports
from secguard.core.findings import FindingDocument, FindingError
from secguard.core.reconcile import reconcile
from secguard.core.remediation import (
    MAX_EXCHANGE_BYTES,
    build_remediation_document,
    load_remediation_file,
    playbook_url,
    serialize_remediation_document,
)
from secguard.core.waivers import WaiverDocument, new_waiver_document

REPOSITORY = "acme/example"
CANARY = "SECGUARD-CANARY-DO-NOT-EMIT-0001"


@pytest.fixture
def findings(catalog):
    return load_reports(ALL_REPORTS, catalog=catalog)


def export(findings, *, waivers=None, fail_on="high", repository=REPOSITORY):
    outcome = reconcile(findings, waivers or new_waiver_document(), today=TODAY, fail_on=fail_on)
    return build_remediation_document(outcome, repository=repository, version=__version__)


def test_handoff_retains_category_inputs_severity_location_and_response(findings):
    document = export(findings)
    items = {item.path: item for item in document.findings}
    assert document.repository == REPOSITORY
    assert document.gate.decision == "BLOCK"
    assert document.gate.expired_waivers == 0
    for finding in findings.findings:
        item = items[finding.path]
        assert (item.secret_type, item.severity, item.line, item.playbook) == (
            finding.secret_type,
            finding.severity,
            finding.line,
            finding.playbook,
        )
        assert finding.fingerprint != item.fingerprint
        assert len(item.fingerprint) == 64
        assert playbook_url(document, item).endswith(f"/{item.playbook}/PLAYBOOK.md")


def test_allowlist_drops_all_free_text_and_native_digests(findings):
    poisoned = findings.model_copy(
        update={
            "findings": [
                item.model_copy(
                    update={
                        "message": CANARY,
                        "remediation": CANARY,
                        "commit": CANARY,
                        "rule": CANARY,
                        "scanner": CANARY,
                        "fingerprint": CANARY,
                        "secret_title": CANARY,
                        "corroborated_rules": [CANARY],
                    }
                )
                for item in findings.findings
            ]
        }
    )
    content = export(poisoned).model_dump_json(by_alias=True)
    assert_no_secret_material(content)
    assert "message" not in content
    assert 'remediation"' not in content


def test_waived_finding_is_omitted_and_expired_waiver_still_blocks(findings):
    waivers = WaiverDocument.model_validate(
        {
            "schema": "secguard.waiver/v1",
            "waivers": [
                {
                    "id": "WV-2026-001",
                    "rule": "*",
                    "path": "**",
                    "reason": "Synthetic fixtures are deliberately present.",
                    "owner": "owner@example.invalid",
                    "approver": "reviewer",
                    "expires_at": "2026-12-01",
                }
            ],
        }
    )
    document = export(findings, waivers=waivers)
    assert document.findings == []
    assert document.omitted_waived == len(findings.findings)
    assert document.gate.decision == "PASS"
    expired = waivers.model_copy(
        update={
            "waivers": [
                waivers.waivers[0].model_copy(update={"expires_at": TODAY - timedelta(days=1)})
            ]
        }
    )
    document = export(FindingDocument(), waivers=expired, fail_on="none")
    assert document.findings == []
    assert document.gate.decision == "BLOCK"
    assert document.gate.expired_waivers == 1


def test_identity_is_stable_order_independent_and_occurrence_specific(findings):
    original = export(findings)
    reordered = export(findings.model_copy(update={"findings": list(reversed(findings.findings))}))
    assert original == reordered
    other_repository = export(findings, repository="acme/another")
    assert {item.fingerprint for item in original.findings}.isdisjoint(
        item.fingerprint for item in other_repository.findings
    )
    first = findings.findings[0]
    repeated_secret = first.model_copy(update={"path": "another/file.py"})
    document = export(FindingDocument(findings=[first, repeated_secret]))
    assert len({item.fingerprint for item in document.findings}) == 2


@pytest.mark.parametrize("repository", ["", "acme", "../repo", "acme/repo\n", "acme/<script>"])
def test_repository_validation_does_not_echo_values(findings, repository):
    with pytest.raises(FindingError) as caught:
        export(findings, repository=repository)
    assert str(caught.value) == "remediation export rejected an invalid field or repository"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update({"Raw": CANARY}),
        lambda data: data.pop("schema"),
        lambda data: data.pop("findings"),
        lambda data: data["producer"].pop("name"),
        lambda data: data.update({"schema": "secguard.remediation/v2"}),
        lambda data: data["producer"].update({"version": "../main"}),
        lambda data: data["findings"][0].update({"path": "../../escape"}),
        lambda data: data["findings"][0].update({"line": True}),
        lambda data: data["findings"][0].update({"playbook": "<img>"}),
        lambda data: data["findings"][0].update({"severity": "unknown"}),
        lambda data: data["findings"][0].update({"fingerprint": CANARY}),
        lambda data: data["findings"].append(data["findings"][0]),
        lambda data: data["gate"].update({"decision": "PASS"}),
        lambda data: data.update({"checked_on": "invalid"}),
        lambda data: data.update({"omitted_waived": -1}),
    ],
)
def test_exchange_rejects_unknown_unsafe_or_contradictory_fields(findings, tmp_path, mutation):
    data = export(findings).model_dump(mode="json", by_alias=True)
    mutation(data)
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(FindingError) as caught:
        load_remediation_file(path)
    assert str(caught.value) == "invalid secguard remediation exchange"
    assert CANARY not in str(caught.value)


def test_exchange_roundtrip_and_empty_input(findings, tmp_path):
    path = tmp_path / "handoff.json"
    expected = export(findings)
    path.write_text(expected.model_dump_json(by_alias=True), encoding="utf-8")
    assert load_remediation_file(path) == expected
    empty = export(FindingDocument())
    assert empty.gate.decision == "PASS" and empty.findings == []
    path.write_text("", encoding="utf-8")
    with pytest.raises(FindingError):
        load_remediation_file(path)
    path.write_bytes(b" " * (MAX_EXCHANGE_BYTES + 1))
    with pytest.raises(FindingError, match="size limit"):
        load_remediation_file(path)


def test_cli_writes_handoff_when_gate_blocks(tmp_path):
    output = tmp_path / "handoff.json"
    args = ["scan", "check", "--today", TODAY.isoformat()]
    for report in ALL_REPORTS:
        args += ["--input", str(report)]
    result = CliRunner().invoke(
        app, [*args, "--remediation", str(output), "--repository", REPOSITORY]
    )
    assert result.exit_code == 1
    assert load_remediation_file(output).gate.decision == "BLOCK"
    assert_no_secret_material(output.read_text(encoding="utf-8"))


def test_serialized_exchange_exact_byte_boundary_roundtrip(findings, tmp_path, monkeypatch):
    document = export(findings)
    content = serialize_remediation_document(document)
    boundary = len(content.encode("utf-8"))
    monkeypatch.setattr("secguard.core.remediation.MAX_EXCHANGE_BYTES", boundary)
    output = tmp_path / "exchange.json"
    output.write_text(serialize_remediation_document(document), encoding="utf-8", newline="\n")
    assert load_remediation_file(output) == document
    monkeypatch.setattr("secguard.core.remediation.MAX_EXCHANGE_BYTES", boundary - 1)
    with pytest.raises(FindingError, match="^remediation exchange exceeds the size limit$"):
        serialize_remediation_document(document)


def test_oversized_export_leaves_no_partial_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr("secguard.core.remediation.MAX_EXCHANGE_BYTES", 1)
    output = tmp_path / "handoff.json"
    canonical = tmp_path / "canonical.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "check",
            "--input",
            str(ALL_REPORTS[0]),
            "--json",
            str(canonical),
            "--remediation",
            str(output),
            "--repository",
            REPOSITORY,
        ],
    )
    assert result.exit_code == 2
    assert "remediation exchange exceeds the size limit" in result.output
    assert not output.exists() and not canonical.exists()


@pytest.mark.parametrize("extra", [["--repository", REPOSITORY], ["--remediation", "out.json"]])
def test_cli_requires_paired_output_and_repository(extra):
    result = CliRunner().invoke(app, ["scan", "check", *extra])
    assert result.exit_code == 2
    assert "provided together" in result.output


def test_invalid_handoff_does_not_leave_partial_other_outputs(tmp_path):
    output = tmp_path / "handoff.json"
    canonical = tmp_path / "canonical.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "check",
            "--input",
            str(ALL_REPORTS[0]),
            "--json",
            str(canonical),
            "--remediation",
            str(output),
            "--repository",
            CANARY,
        ],
    )
    assert result.exit_code == 2
    assert CANARY not in result.output
    assert not output.exists() and not canonical.exists()
