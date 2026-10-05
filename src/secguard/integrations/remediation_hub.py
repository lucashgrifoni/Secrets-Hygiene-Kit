"""Explicit, local handoff to the AppSec Remediation Hub 0.1.0 contract."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from secguard.core.findings import FindingError
from secguard.core.remediation import (
    RemediationDocument,
    load_remediation_file,
    playbook_url,
)
from secguard.core.writing import UnsafeWriteError, assert_writable, is_link

HUB_VERSION = "0.1.0"
EXCHANGE_SCHEMA = "secguard.remediation/v1"
DATABASE_APPLICATION_ID = 0x53475248  # SGRH: an operational marker, not authentication.


class BridgeError(Exception):
    """A diagnostic that contains no input, database or credential values."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise BridgeError("invalid bridge arguments; use --help")


@dataclass
class _Occurrence:
    raw: Any
    finding: Any
    group: Any
    task: Any
    url: str


def _load_hub() -> SimpleNamespace:
    """Load only the verified consumer contract, without instantiating its service."""
    try:
        package = importlib.import_module("appsec_remediation_hub")
        if package.__version__ != HUB_VERSION:
            raise BridgeError("unsupported AppSec Remediation Hub version; expected 0.1.0")
        entities = importlib.import_module("appsec_remediation_hub.domain.entities")
        values = importlib.import_module("appsec_remediation_hub.domain.value_objects")
        enums = importlib.import_module("appsec_remediation_hub.domain.enums")
        correlation = importlib.import_module("appsec_remediation_hub.domain.correlation")
        scoring = importlib.import_module("appsec_remediation_hub.domain.scoring")
        sla = importlib.import_module("appsec_remediation_hub.domain.sla")
        repository = importlib.import_module(
            "appsec_remediation_hub.infrastructure.repositories.store"
        )
        service = importlib.import_module("appsec_remediation_hub.application.service")
        return SimpleNamespace(
            RawFinding=entities.RawFinding,
            NormalizedFinding=entities.NormalizedFinding,
            FindingGroup=entities.FindingGroup,
            RemediationTask=entities.RemediationTask,
            IngestionRun=entities.IngestionRun,
            Asset=entities.Asset,
            ScoringSignals=entities.ScoringSignals,
            LineRange=values.LineRange,
            Category=enums.Category,
            Subcategory=enums.Subcategory,
            Severity=enums.NormalizedSeverity,
            GroupStatus=enums.GroupStatus,
            TaskStatus=enums.TaskStatus,
            fingerprint_for=correlation.fingerprint_for,
            compute_score=scoring.compute_score,
            compute_due=sla.compute_due,
            resolve_policy=sla.resolve_policy,
            Store=repository.Store,
            issue_payloads=service.AppService.github_issue_payloads,
        )
    except BridgeError:
        raise
    except Exception as exc:
        raise BridgeError(
            "AppSec Remediation Hub 0.1.0 is unavailable or incompatible in this environment"
        ) from exc


def _digest(value: Any) -> str:
    content = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _plan(document: RemediationDocument, hub: SimpleNamespace) -> tuple[Any, list[_Occurrence]]:
    now = datetime.now(UTC)
    run = hub.IngestionRun(
        id="RUN-SG-" + _digest(document.model_dump(mode="json", by_alias=True)),
        source="secguard",
        source_format=EXCHANGE_SCHEMA,
        path="secguard-remediation-exchange",
        started_at=now,
        completed_at=None,
        raw_count=0,
    )
    occurrences = []
    for item in sorted(document.findings, key=lambda entry: entry.fingerprint):
        raw_payload = {"repository": document.repository, **item.model_dump(mode="json")}
        raw = hub.RawFinding(
            id="RAW-SG-" + item.fingerprint,
            source="secguard",
            source_format=EXCHANGE_SCHEMA,
            category=hub.Category.SECRET,
            raw_payload_hash=_digest(raw_payload),
            raw_payload=raw_payload,
            ingestion_run_id=run.id,
        )
        url = playbook_url(document, item)
        group_id = "FG-SG-" + item.fingerprint
        finding = hub.NormalizedFinding(
            id="NF-SG-" + item.fingerprint,
            raw_finding_id=raw.id,
            category=hub.Category.SECRET,
            subcategory=hub.Subcategory.EXPOSED_SECRET,
            severity=hub.Severity(item.severity),
            asset_ref=document.repository,
            repository=document.repository,
            file_path=item.path,
            line_range=hub.LineRange(start=item.line, end=item.line) if item.line else None,
            secret_fingerprint=item.fingerprint,
            secret_type=item.secret_type,
            fingerprint=item.fingerprint,
            group_id=group_id,
            payload={"schema": EXCHANGE_SCHEMA, "playbook": item.playbook, "playbook_url": url},
        )
        group = hub.FindingGroup(
            id=group_id,
            title=f"Exposed {item.secret_type} secret",
            category=hub.Category.SECRET,
            subcategory=hub.Subcategory.EXPOSED_SECRET,
            status=hub.GroupStatus.OPEN,
            asset_ref=document.repository,
            owner="appsec",
            fingerprint=hub.fingerprint_for(finding),
            finding_ids=[finding.id],
            severity=finding.severity,
        )
        score = hub.compute_score(
            group, hub.Asset(asset_ref=document.repository), hub.ScoringSignals()
        )
        group = group.with_score(score)
        due, basis = hub.compute_due(hub.resolve_policy("flat-severity"), group.priority_class, now)
        task = hub.RemediationTask(
            id="TASK-SG-" + item.fingerprint,
            group_id=group.id,
            title=group.title,
            owner=group.owner,
            status=hub.TaskStatus.OPEN,
            priority_class=group.priority_class,
            playbook_id="secret_exposed",
            due_at=due,
            sla_basis=basis,
        )
        occurrences.append(_Occurrence(raw, finding, group, task, url))
    return run, occurrences


def _guard_file(path: Path) -> None:
    """Guard lexical ancestors, including paths outside the current checkout."""
    assert_writable(path)
    absolute = path if path.is_absolute() else Path.cwd() / path
    if any(is_link(component) for component in (absolute, *absolute.parents)):
        raise BridgeError("refusing a linked bridge destination")
    if path.exists() and (not path.is_file() or path.stat().st_nlink > 1):
        raise BridgeError("bridge destinations must be ordinary files without hard links")


def _check_paths(input_path: Path, output: Path, database: Path | None) -> None:
    _guard_file(output)
    destinations = [input_path, output]
    if database is not None:
        spelling = str(database)
        if (
            re.match(r"^[A-Za-z][A-Za-z0-9+.-]+:/", spelling)
            or spelling.startswith(("sqlite:", "file:"))
            or "?" in spelling
            or "#" in spelling
            or spelling == ":memory:"
        ):
            raise BridgeError("--database requires a SQLite file path")
        _guard_file(database)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(database) + suffix)
            _guard_file(sidecar)
            destinations.append(sidecar)
        destinations.append(database)
    for index, left in enumerate(destinations):
        for right in destinations[index + 1 :]:
            if left.resolve(strict=False) == right.resolve(strict=False) or (
                left.exists() and right.exists() and left.samefile(right)
            ):
                raise BridgeError("input, database and issue output must be distinct files")


def _same_fields(actual: Any, expected: Any, fields: tuple[str, ...]) -> bool:
    return all(getattr(actual, name) == getattr(expected, name) for name in fields)


def _claim_database(database: Path) -> None:
    """Reject unrelated SQLite files before the Hub can migrate or stamp them."""
    _guard_file(database)
    sidecars = [Path(str(database) + suffix) for suffix in ("-journal", "-wal", "-shm")]
    for sidecar in sidecars:
        _guard_file(sidecar)
    if database.exists():
        with database.open("rb") as stream:
            header = stream.read(100)
        if (
            len(header) != 100
            or header[:16] != b"SQLite format 3\x00"
            or int.from_bytes(header[68:72], "big") != DATABASE_APPLICATION_ID
        ):
            raise BridgeError("existing database is not a recognized bridge database")
        try:
            with closing(
                sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
            ) as connection:
                marker = connection.execute("PRAGMA application_id").fetchone()[0]
        except sqlite3.Error as exc:
            raise BridgeError("existing database is not a recognized bridge database") from exc
        if marker != DATABASE_APPLICATION_ID:
            raise BridgeError("existing database is not a recognized bridge database")
        return
    if any(sidecar.exists() for sidecar in sidecars):
        raise BridgeError("new bridge database requires absent SQLite sidecar files")
    database.parent.mkdir(parents=True, exist_ok=True)
    _guard_file(database)
    # Exclusive creation avoids adopting a file that appeared after validation.
    descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(f"PRAGMA application_id = {DATABASE_APPLICATION_ID}")
        connection.commit()


def _validate_existing(occurrences: list[_Occurrence], store: Any, hub: SimpleNamespace) -> list:
    """Validate every identity before the first entity write; retain existing lifecycle state."""
    raw = {entry.id: entry for entry in store.list_raw()}
    findings = {entry.id: entry for entry in store.list_normalized()}
    groups = {entry.id: entry for entry in store.list_groups()}
    tasks = {entry.id: entry for entry in store.list_tasks()}
    group_keys = {entry.fingerprint: entry.id for entry in groups.values()}
    task_groups = {entry.group_id: entry.id for entry in tasks.values()}
    changes = []
    for occurrence in occurrences:
        old_raw = raw.get(occurrence.raw.id)
        old_finding = findings.get(occurrence.finding.id)
        old_group = groups.get(occurrence.group.id)
        old_task = tasks.get(occurrence.task.id)
        conflict = bool(
            old_raw
            and not _same_fields(
                old_raw,
                occurrence.raw,
                ("source", "source_format", "category", "raw_payload_hash", "raw_payload"),
            )
        )
        conflict |= bool(
            old_finding
            and (
                not _same_fields(
                    old_finding,
                    occurrence.finding,
                    (
                        "raw_finding_id",
                        "category",
                        "subcategory",
                        "severity",
                        "asset_ref",
                        "repository",
                        "file_path",
                        "line_range",
                        "secret_fingerprint",
                        "secret_type",
                        "fingerprint",
                        "group_id",
                    ),
                )
                or old_finding.payload.get("schema") != EXCHANGE_SCHEMA
                or old_finding.payload.get("playbook") != occurrence.finding.payload["playbook"]
            )
        )
        conflict |= bool(
            old_group
            and not _same_fields(
                old_group,
                occurrence.group,
                ("category", "subcategory", "asset_ref", "fingerprint", "finding_ids", "severity"),
            )
        )
        conflict |= bool(
            old_task and not _same_fields(old_task, occurrence.task, ("group_id", "playbook_id"))
        )
        conflict |= (
            group_keys.get(occurrence.group.fingerprint, occurrence.group.id) != occurrence.group.id
        )
        conflict |= task_groups.get(occurrence.group.id, occurrence.task.id) != occurrence.task.id
        if conflict:
            raise BridgeError(
                "bridge identity conflict; review the isolated database before retrying"
            )
        if old_task is not None and old_group is None:
            raise BridgeError(
                "incomplete bridge state; a task lacks its group; review the isolated database"
            )
        if old_group is not None and old_task is None and old_group.status != hub.GroupStatus.OPEN:
            raise BridgeError(
                "incomplete terminal or managed group; review the isolated database before retrying"
            )
        changes.append((occurrence, old_raw, old_finding, old_group, old_task))
    return changes


def _apply(
    run: Any, occurrences: list[_Occurrence], database: Path, hub: SimpleNamespace
) -> tuple[int, int]:
    _claim_database(database)
    # The Hub migration helper accepts a string URL; query/fragment characters
    # are rejected before construction so they cannot change the named file.
    store = hub.Store("sqlite:///" + database.absolute().as_posix())
    try:
        store.create_schema()
        changes = _validate_existing(occurrences, store, hub)
        known_run = next(
            (entry for entry in store.list_ingestion_runs() if entry.id == run.id), None
        )
        if known_run is None:
            store.add_ingestion_run(run)
            known_run = run
        created = recovered = 0
        for occurrence, old_raw, old_finding, old_group, old_task in changes:
            missing = (old_raw is None, old_finding is None, old_group is None, old_task is None)
            if not any(missing):
                occurrence.group = old_group
                occurrence.task = old_task
                continue
            if all(missing):
                created += 1
            else:
                recovered += 1
            if old_raw is None:
                store.add_raw(occurrence.raw)
            if old_finding is None:
                store.add_normalized(occurrence.finding)
            if old_group is None:
                store.add_group(occurrence.group)
            else:
                occurrence.group = old_group
            if old_task is None:
                # Retain the existing group's priority and assignment when
                # resuming an interrupted OPEN-group import.
                due, basis = hub.compute_due(
                    hub.resolve_policy("flat-severity"),
                    occurrence.group.priority_class,
                    datetime.now(UTC),
                )
                occurrence.task = occurrence.task.model_copy(
                    update={
                        "owner": occurrence.group.owner,
                        "priority_class": occurrence.group.priority_class,
                        "due_at": due,
                        "sla_basis": basis,
                    }
                )
                store.add_task(occurrence.task)
            else:
                occurrence.task = old_task
        if known_run.completed_at is None:
            store.add_ingestion_run(
                known_run.model_copy(
                    update={
                        "completed_at": datetime.now(UTC),
                        "raw_count": len(occurrences),
                    }
                )
            )
        return created, recovered
    finally:
        store.engine.dispose()


def _preview(
    document: RemediationDocument, occurrences: list[_Occurrence], hub: SimpleNamespace
) -> list:
    # The real Hub renderer reads only these two lists. Project free-text fields
    # from the validated exchange instead of echoing manually edited DB text.
    groups = [
        entry.group.model_copy(
            update={
                "title": f"Exposed {entry.finding.secret_type} secret",
                "asset_ref": document.repository,
                "owner": "appsec",
            }
        )
        for entry in occurrences
    ]
    tasks = [
        entry.task.model_copy(
            update={
                "title": f"Exposed {entry.finding.secret_type} secret",
                "owner": "appsec",
            }
        )
        for entry in occurrences
    ]
    view = SimpleNamespace(
        store=SimpleNamespace(
            list_groups=lambda: groups,
            list_tasks=lambda: tasks,
        )
    )
    rendered = hub.issue_payloads(view)
    if len(rendered) != len(occurrences):
        raise BridgeError("incompatible Hub issue preview contract")
    for issue, occurrence in zip(rendered, occurrences, strict=True):
        if (
            set(issue) != {"title", "body", "labels"}
            or not isinstance(issue["title"], str)
            or not isinstance(issue["body"], str)
            or not isinstance(issue["labels"], list)
            or not all(isinstance(label, str) for label in issue["labels"])
        ):
            raise BridgeError("incompatible Hub issue preview contract")
        issue["body"] += (
            f"\nProvider response guide: {occurrence.url}\n"
            f"Local task status: `{occurrence.task.status.value}`\n"
            "Guidance requires operator review; no remediation evidence is attached.\n"
        )
    return rendered


def _write_output(output: Path, receipt: dict) -> None:
    _guard_file(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    _guard_file(output)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=".secguard-hub-",
            suffix=".json",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(receipt, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
        _guard_file(output)
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        description="Validate or import a local secguard exchange; issues remain dry-run."
    )
    parser.add_argument("--input", required=True, type=Path, metavar="EXCHANGE")
    parser.add_argument(
        "--database", type=Path, metavar="FILE", help="isolated SQLite file; required with --apply"
    )
    parser.add_argument("--issues-output", required=True, type=Path, metavar="FILE")
    parser.add_argument(
        "--apply", action="store_true", help="write the explicitly named isolated database"
    )
    try:
        args = parser.parse_args(argv)
        if args.apply and args.database is None:
            raise BridgeError("--apply requires an explicit --database file")
        _check_paths(args.input, args.issues_output, args.database)
        document = load_remediation_file(args.input)
        hub = _load_hub()
        run, occurrences = _plan(document, hub)
        created = recovered = 0
        if args.apply:
            created, recovered = _apply(run, occurrences, args.database, hub)
        receipt = {
            "schema": "secguard.hub-preview/v1",
            "hub_version": HUB_VERSION,
            "repo": document.repository,
            "dry_run": True,
            "applied": args.apply,
            "gate": document.gate.model_dump(mode="json"),
            "omitted_waived": document.omitted_waived,
            "findings": len(occurrences),
            "created": created,
            "recovered": recovered,
            "replayed": len(occurrences) - created - recovered if args.apply else 0,
            "issues": _preview(document, occurrences, hub),
        }
        _write_output(args.issues_output, receipt)
        print(f"Hub dry-run written: {len(occurrences)} findings; gate={document.gate.decision}")
        return 0
    except (FindingError, BridgeError) as exc:
        print(f"secguard hub: {exc}", file=sys.stderr)
    except (UnsafeWriteError, OSError):
        print("secguard hub: cannot use a bridge file destination", file=sys.stderr)
    except Exception:
        print(
            "secguard hub: local handoff failed; review the isolated database and retry",
            file=sys.stderr,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
