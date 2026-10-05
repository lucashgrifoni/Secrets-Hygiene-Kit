"""Bridge isolation, replay and failure recovery, without a live Hub or tracker."""

from __future__ import annotations

import copy
import json
import sqlite3
from enum import StrEnum
from pathlib import Path
from types import SimpleNamespace

import pytest

from secguard.integrations import remediation_hub as bridge


class _Category(StrEnum):
    SECRET = "secret"


class _Subcategory(StrEnum):
    EXPOSED_SECRET = "exposed_secret"


class _Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class _Status(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class _Priority(StrEnum):
    LOW = "low"


class _Entity(SimpleNamespace):
    def model_copy(self, *, update):
        clone = copy.deepcopy(self)
        clone.__dict__.update(update)
        return clone


class _Group(_Entity):
    def with_score(self, result):
        return self.model_copy(
            update={"score": result.value, "priority_class": result.priority_class}
        )


@pytest.fixture
def contract(monkeypatch):
    """A controlled persistence double; consumer compatibility is tested separately."""
    tables = {name: {} for name in ("raw", "normalized", "groups", "tasks", "ingestion_runs")}
    state = SimpleNamespace(tables=tables, constructors=0, writes=[], fail_task=False, disposed=0)

    class Store:
        def __init__(self, url):
            state.constructors += 1
            self.database = Path(url.removeprefix("sqlite:///"))
            self.engine = SimpleNamespace(dispose=self.dispose)

        def dispose(self):
            state.disposed += 1

        def create_schema(self):
            self.database.parent.mkdir(parents=True, exist_ok=True)
            self.database.touch(exist_ok=True)

    for table, singular in (
        ("raw", "raw"),
        ("normalized", "normalized"),
        ("groups", "group"),
        ("tasks", "task"),
        ("ingestion_runs", "ingestion_run"),
    ):

        def read(self, *, table=table):
            return copy.deepcopy(list(tables[table].values()))

        def write(self, entry, *, table=table):
            if table == "tasks" and state.fail_task:
                state.fail_task = False
                raise RuntimeError("CANARY-PRIVATE-TASK-FAILURE")
            state.writes.append((table, entry.id))
            tables[table][entry.id] = copy.deepcopy(entry)

        setattr(Store, "list_" + table, read)
        setattr(Store, "add_" + singular, write)

    def issue_payloads(service):
        groups = {group.id: group for group in service.store.list_groups()}
        return [
            {
                "title": task.title,
                "body": f"Severity: {groups[task.group_id].severity.value}\nOwner: {task.owner}\n",
                "labels": ["appsec-remediation"],
            }
            for task in service.store.list_tasks()
        ]

    hub = SimpleNamespace(
        RawFinding=_Entity,
        NormalizedFinding=_Entity,
        FindingGroup=_Group,
        RemediationTask=_Entity,
        IngestionRun=_Entity,
        Asset=_Entity,
        ScoringSignals=_Entity,
        LineRange=_Entity,
        Category=_Category,
        Subcategory=_Subcategory,
        Severity=_Severity,
        GroupStatus=_Status,
        TaskStatus=_Status,
        fingerprint_for=lambda finding: finding.secret_fingerprint[:16],
        compute_score=lambda *args: SimpleNamespace(value=25, priority_class=_Priority.LOW),
        compute_due=lambda policy, priority, now: (now, "flat-severity"),
        resolve_policy=lambda name: name,
        Store=Store,
        issue_payloads=issue_payloads,
    )
    monkeypatch.setattr(bridge, "_load_hub", lambda: hub)
    return state


def _exchange(tmp_path, *, fingerprints=("a" * 64,), severity="low", line=7, expired=0):
    blocked = severity in {"critical", "high"} and bool(fingerprints) or expired > 0
    value = {
        "schema": "secguard.remediation/v1",
        "producer": {"name": "secguard", "version": "0.4.0"},
        "repository": "example/project",
        "checked_on": "2026-10-05",
        "gate": {
            "decision": "BLOCK" if blocked else "PASS",
            "fail_on": "high",
            "expired_waivers": expired,
        },
        "omitted_waived": 2,
        "findings": [
            {
                "fingerprint": fingerprint,
                "secret_type": "github-pat",
                "severity": severity,
                "path": "src/settings.py",
                "line": line,
                "playbook": "github-pat",
            }
            for fingerprint in fingerprints
        ],
    }
    path = tmp_path / "exchange.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _args(tmp_path, exchange, *, apply=False):
    args = [
        "--input",
        str(exchange),
        "--database",
        str(tmp_path / "isolated.sqlite"),
        "--issues-output",
        str(tmp_path / "issues.json"),
    ]
    return args + ["--apply"] if apply else args


def _receipt(tmp_path):
    return json.loads((tmp_path / "issues.json").read_text(encoding="utf-8"))


def test_preview_never_constructs_store_or_creates_database(tmp_path, contract, monkeypatch):
    monkeypatch.setattr(
        bridge.sqlite3, "connect", lambda *a, **kw: pytest.fail("preview opened SQLite")
    )
    assert bridge.main(_args(tmp_path, _exchange(tmp_path))) == 0
    assert contract.constructors == 0
    assert not (tmp_path / "isolated.sqlite").exists()
    receipt = _receipt(tmp_path)
    assert receipt["applied"] is False
    assert receipt["dry_run"] is True
    assert receipt["omitted_waived"] == 2
    assert receipt["issues"][0]["body"].endswith("no remediation evidence is attached.\n")
    assert (
        "/blob/v0.4.0/src/secguard/playbooks/github-pat/PLAYBOOK.md" in receipt["issues"][0]["body"]
    )


def test_apply_requires_explicit_database_before_loading_hub(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(bridge, "_load_hub", lambda: pytest.fail("Hub must not load"))
    assert (
        bridge.main(["--input", "CANARY", "--issues-output", str(tmp_path / "out"), "--apply"]) == 2
    )
    assert "requires an explicit --database" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
@pytest.mark.parametrize("line", [None, 7])
def test_fields_are_preserved_without_gitleaks_severity_promotion(
    tmp_path, contract, severity, line
):
    assert (
        bridge.main(_args(tmp_path, _exchange(tmp_path, severity=severity, line=line), apply=True))
        == 0
    )
    finding = next(iter(contract.tables["normalized"].values()))
    assert finding.category.value == "secret"
    assert finding.severity.value == severity
    assert finding.secret_type == "github-pat"
    assert finding.repository == finding.asset_ref == "example/project"
    assert finding.file_path == "src/settings.py"
    assert finding.secret_fingerprint == finding.fingerprint == "a" * 64
    assert finding.line_range == (_Entity(start=7, end=7) if line else None)
    assert finding.payload["playbook"] == "github-pat"
    task = next(iter(contract.tables["tasks"].values()))
    assert task.playbook_id == "secret_exposed"
    assert _receipt(tmp_path)["created"] == 1
    assert contract.disposed == 1


def test_replay_preserves_closed_states_and_existing_records(tmp_path, contract):
    args = _args(tmp_path, _exchange(tmp_path), apply=True)
    assert bridge.main(args) == 0
    for table in ("groups", "tasks"):
        for entry in contract.tables[table].values():
            entry.status = _Status.CLOSED
            entry.owner = "CANARY-PRIVATE-OWNER"
            entry.title = "CANARY-PRIVATE-TITLE"
    before = copy.deepcopy(contract.tables)
    writes = len(contract.writes)
    assert bridge.main(args) == 0
    assert contract.tables == before
    assert len(contract.writes) == writes
    assert _receipt(tmp_path)["replayed"] == 1
    assert "`closed`" in _receipt(tmp_path)["issues"][0]["body"]
    assert "CANARY" not in json.dumps(_receipt(tmp_path))


def test_new_occurrence_does_not_reopen_closed_groups_or_tasks(tmp_path, contract):
    exchange = _exchange(tmp_path)
    args = _args(tmp_path, exchange, apply=True)
    assert bridge.main(args) == 0
    group_id = "FG-SG-" + "a" * 64
    task_id = "TASK-SG-" + "a" * 64
    contract.tables["groups"][group_id].status = _Status.CLOSED
    contract.tables["tasks"][task_id].status = _Status.CLOSED
    closed_group = copy.deepcopy(contract.tables["groups"][group_id])
    closed_task = copy.deepcopy(contract.tables["tasks"][task_id])
    _exchange(tmp_path, fingerprints=("b" * 64,))
    assert bridge.main(args) == 0
    assert contract.tables["groups"][group_id] == closed_group
    assert contract.tables["tasks"][task_id] == closed_task
    assert len(contract.tables["normalized"]) == len(contract.tables["tasks"]) == 2
    assert len(_receipt(tmp_path)["issues"]) == 1
    assert _receipt(tmp_path)["created"] == 1


def test_partial_commit_recovers_task_only_on_retry(tmp_path, contract, capsys):
    args = _args(tmp_path, _exchange(tmp_path), apply=True)
    contract.fail_task = True
    assert bridge.main(args) == 2
    assert "CANARY" not in capsys.readouterr().err
    assert len(contract.tables["normalized"]) == len(contract.tables["groups"]) == 1
    assert not contract.tables["tasks"]
    run = next(iter(contract.tables["ingestion_runs"].values()))
    assert run.completed_at is None and run.raw_count == 0
    before = copy.deepcopy(contract.tables)
    writes = len(contract.writes)
    assert bridge.main(args) == 0
    assert contract.tables["raw"] == before["raw"]
    assert contract.tables["normalized"] == before["normalized"]
    assert contract.tables["groups"] == before["groups"]
    assert [table for table, _ in contract.writes[writes:]] == ["tasks", "ingestion_runs"]
    completed_run = next(iter(contract.tables["ingestion_runs"].values()))
    assert completed_run.completed_at is not None and completed_run.raw_count == 1
    assert _receipt(tmp_path)["recovered"] == 1


def test_missing_task_in_closed_group_fails_without_reopening(tmp_path, contract, capsys):
    args = _args(tmp_path, _exchange(tmp_path), apply=True)
    assert bridge.main(args) == 0
    contract.tables["tasks"].clear()
    next(iter(contract.tables["groups"].values())).status = _Status.CLOSED
    before = copy.deepcopy(contract.tables)
    assert bridge.main(args) == 2
    assert "incomplete terminal or managed group" in capsys.readouterr().err
    assert contract.tables == before


def test_conflict_is_detected_before_any_new_occurrence_write(tmp_path, contract, capsys):
    args = _args(tmp_path, _exchange(tmp_path), apply=True)
    assert bridge.main(args) == 0
    next(iter(contract.tables["normalized"].values())).file_path = "CANARY-CONFLICT"
    before = copy.deepcopy(contract.tables)
    _exchange(tmp_path, fingerprints=("a" * 64, "b" * 64))
    assert bridge.main(args) == 2
    assert "identity conflict" in capsys.readouterr().err
    assert contract.tables == before
    assert "CANARY" not in capsys.readouterr().err


@pytest.mark.parametrize("apply", [False, True])
def test_empty_blocked_exchange_retains_gate_and_has_no_tasks(tmp_path, contract, apply):
    assert (
        bridge.main(_args(tmp_path, _exchange(tmp_path, fingerprints=(), expired=1), apply=apply))
        == 0
    )
    receipt = _receipt(tmp_path)
    assert receipt["gate"] == {"decision": "BLOCK", "fail_on": "high", "expired_waivers": 1}
    assert receipt["issues"] == []
    assert not contract.tables["normalized"] and not contract.tables["tasks"]


def test_unknown_exchange_field_is_redacted_and_never_loads_hub(tmp_path, monkeypatch, capsys):
    exchange = _exchange(tmp_path)
    payload = json.loads(exchange.read_text())
    payload["token"] = "CANARY-RAW-SECRET"
    exchange.write_text(json.dumps(payload))
    monkeypatch.setattr(bridge, "_load_hub", lambda: pytest.fail("Hub must not load"))
    assert bridge.main(_args(tmp_path, exchange, apply=True)) == 2
    diagnostic = capsys.readouterr()
    assert "CANARY" not in diagnostic.out + diagnostic.err
    assert not (tmp_path / "isolated.sqlite").exists()


def test_missing_consumer_failure_is_redacted(monkeypatch):
    def absent(name):
        raise ImportError("CANARY-ENVIRONMENT")

    monkeypatch.setattr(bridge.importlib, "import_module", absent)
    with pytest.raises(bridge.BridgeError, match="unavailable or incompatible") as error:
        bridge._load_hub()
    assert "CANARY" not in str(error.value)


def test_unsupported_consumer_version_fails(monkeypatch):
    monkeypatch.setattr(
        bridge.importlib, "import_module", lambda name: SimpleNamespace(__version__="0.2.0")
    )
    with pytest.raises(bridge.BridgeError, match="unsupported"):
        bridge._load_hub()


def test_unknown_arguments_do_not_echo_values(capsys):
    assert (
        bridge.main(["--input", "input", "--issues-output", "out", "--unknown", "CANARY-ARG"]) == 2
    )
    assert "CANARY" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "database", ["sqlite:///data.sqlite", ":memory:", "data?token=CANARY", "data#fragment"]
)
def test_database_requires_file_not_url(tmp_path, contract, database, capsys):
    args = [
        "--input",
        str(_exchange(tmp_path)),
        "--database",
        database,
        "--issues-output",
        str(tmp_path / "issues.json"),
        "--apply",
    ]
    assert bridge.main(args) == 2
    assert contract.constructors == 0
    assert "CANARY" not in capsys.readouterr().err


def test_input_cannot_be_overwritten_by_output(tmp_path, contract):
    exchange = _exchange(tmp_path)
    before = exchange.read_bytes()
    assert bridge.main(["--input", str(exchange), "--issues-output", str(exchange)]) == 2
    assert exchange.read_bytes() == before
    assert contract.constructors == 0


def test_nonexistent_parent_alias_cannot_overwrite_input(tmp_path, contract):
    exchange = _exchange(tmp_path)
    before = exchange.read_bytes()
    alias = tmp_path / "uncreated-directory" / ".." / exchange.name
    assert bridge.main(["--input", str(exchange), "--issues-output", str(alias)]) == 2
    assert exchange.read_bytes() == before
    assert not (tmp_path / "uncreated-directory").exists()
    assert contract.constructors == 0


def test_linked_sqlite_sidecar_is_rejected_before_store(tmp_path, contract, monkeypatch):
    sidecar = tmp_path / "isolated.sqlite-journal"
    native = bridge.is_link
    monkeypatch.setattr(bridge, "is_link", lambda path: path == sidecar or native(path))
    assert bridge.main(_args(tmp_path, _exchange(tmp_path), apply=True)) == 2
    assert contract.constructors == 0


def test_external_linked_ancestor_is_rejected(tmp_path, contract, monkeypatch):
    exchange = _exchange(tmp_path)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(checkout)
    native = bridge.is_link
    monkeypatch.setattr(bridge, "is_link", lambda path: path == outside or native(path))
    assert (
        bridge.main(["--input", str(exchange), "--issues-output", str(outside / "issues.json")])
        == 2
    )
    assert contract.constructors == 0
    assert not list(outside.iterdir())


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
@pytest.mark.parametrize("collision", ["input", "output"])
def test_sqlite_sidecars_cannot_collide_with_exchange_or_preview(
    tmp_path, contract, suffix, collision
):
    exchange = _exchange(tmp_path)
    sidecar = tmp_path / ("isolated.sqlite" + suffix)
    output = tmp_path / "issues.json"
    if collision == "input":
        sidecar.write_bytes(exchange.read_bytes())
        exchange = sidecar
    else:
        output = sidecar
    assert (
        bridge.main(
            [
                "--input",
                str(exchange),
                "--database",
                str(tmp_path / "isolated.sqlite"),
                "--issues-output",
                str(output),
                "--apply",
            ]
        )
        == 2
    )
    assert contract.constructors == 0


def test_hardlinked_output_is_rejected(tmp_path, contract):
    original = tmp_path / "original.json"
    original.write_text("do not replace")
    output = tmp_path / "issues.json"
    output.hardlink_to(original)
    assert bridge.main(_args(tmp_path, _exchange(tmp_path))) == 2
    assert original.read_text() == output.read_text() == "do not replace"


@pytest.mark.parametrize("empty", [False, True])
def test_foreign_database_is_unchanged_before_hub_migration(tmp_path, contract, empty, capsys):
    database = tmp_path / "isolated.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE user_data (value TEXT)")
        connection.execute("INSERT INTO user_data VALUES ('CANARY-PRIVATE-ROW')")
    connection.close()
    before = database.read_bytes()
    exchange = _exchange(tmp_path, fingerprints=() if empty else ("a" * 64,))
    assert bridge.main(_args(tmp_path, exchange, apply=True)) == 2
    assert database.read_bytes() == before
    assert contract.constructors == 0
    assert not (tmp_path / "issues.json").exists()
    with sqlite3.connect(database) as connection:
        tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        assert tables == [("user_data",)]
        assert connection.execute("SELECT value FROM user_data").fetchall() == [
            ("CANARY-PRIVATE-ROW",)
        ]
    connection.close()
    assert "CANARY" not in capsys.readouterr().err


def test_zero_byte_database_is_not_adopted(tmp_path, contract):
    database = tmp_path / "isolated.sqlite"
    database.touch()
    assert bridge.main(_args(tmp_path, _exchange(tmp_path), apply=True)) == 2
    assert database.read_bytes() == b""
    assert contract.constructors == 0


def test_marker_only_database_can_resume_before_migration(tmp_path, contract):
    database = tmp_path / "isolated.sqlite"
    bridge._claim_database(database)
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("PRAGMA application_id").fetchone()[0]
            == bridge.DATABASE_APPLICATION_ID
        )
        assert (
            connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
        )
    connection.close()
    assert bridge.main(_args(tmp_path, _exchange(tmp_path), apply=True)) == 0
    assert _receipt(tmp_path)["created"] == 1


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_new_database_does_not_adopt_existing_sidecars(tmp_path, contract, suffix):
    sidecar = tmp_path / ("isolated.sqlite" + suffix)
    sidecar.write_bytes(b"CANARY-FOREIGN-SIDECAR")
    assert bridge.main(_args(tmp_path, _exchange(tmp_path), apply=True)) == 2
    assert sidecar.read_bytes() == b"CANARY-FOREIGN-SIDECAR"
    assert not (tmp_path / "isolated.sqlite").exists()
    assert contract.constructors == 0
