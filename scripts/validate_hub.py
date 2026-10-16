"""Internal synthetic pilot against the installed, source-pinned Hub and real SQLite.

Run in a fresh environment containing both wheels. No trackers or providers are
contacted. All databases live in a temporary directory created by this script.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import sqlite3
import subprocess
import sys
import tempfile
from importlib import metadata
from pathlib import Path

CANARY = "SECGUARD-INTERNAL-PROSE-CANARY-0182"


def pilot(work: Path, checks: list[str], commands: list[dict]) -> None:
    from secguard.integrations import remediation_hub as bridge

    bridge._load_hub()
    checks.append("H01-clean-installed-source-pin")

    def cli(arguments: list[str], expected: int = 0, *, integration: bool = True) -> None:
        module = "secguard.integrations.remediation_hub" if integration else "secguard"
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        environment.update(PYTHONUTF8="1", NO_COLOR="1")
        result = subprocess.run(
            [sys.executable, "-m", module, *arguments],
            cwd=work,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=90,
        )
        commands.append(
            {"module": module, "expected_exit": expected, "actual_exit": result.returncode}
        )
        if result.returncode != expected or CANARY in result.stdout + result.stderr:
            raise RuntimeError(f"command {len(commands)} failed its exit/disclosure oracle")

    def require(condition: bool, case: str) -> None:
        if not condition:
            raise RuntimeError(case)
        checks.append(case)

    def fault(arguments: list[str], kind: str) -> str:
        # Faults run in a child process just like the supported bridge CLI.
        # Hub migration engines have process lifetime; no in-process library
        # compatibility is inferred from this command-line pilot.
        injection = (
            "hub = bridge._load_hub(); "
            "hub.Store.add_task = lambda *_: (_ for _ in ()).throw(RuntimeError('"
            + CANARY
            + "')); "
            if kind == "task"
            else "bridge._write_output = lambda *_: (_ for _ in ()).throw(PermissionError()); "
        )
        code = (
            "import sys; from secguard.integrations import remediation_hub as bridge; "
            + injection
            + "raise SystemExit(bridge.main(sys.argv[1:]))"
        )
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        environment["PYTHONUTF8"] = "1"
        result = subprocess.run(
            [sys.executable, "-c", code, *arguments],
            cwd=work,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=90,
        )
        commands.append(
            {"module": "bridge-fault-" + kind, "expected_exit": 2, "actual_exit": result.returncode}
        )
        if result.returncode != 2 or CANARY in result.stdout + result.stderr:
            raise RuntimeError("fault injection failed its exit/disclosure oracle")
        return result.stderr

    def receipt() -> dict:
        return json.loads((work / "preview.json").read_text(encoding="utf-8"))

    def rows(database: Path) -> dict:
        queries = {
            "raw_finding": "SELECT id, payload FROM raw_finding ORDER BY id",
            "normalized_finding": "SELECT id, payload FROM normalized_finding ORDER BY id",
            "finding_group": "SELECT id, payload FROM finding_group ORDER BY id",
            "remediation_task": "SELECT id, payload FROM remediation_task ORDER BY id",
            "ingestion_run": "SELECT id, payload FROM ingestion_run ORDER BY id",
        }
        with contextlib.closing(sqlite3.connect(database)) as connection:
            return {table: connection.execute(query).fetchall() for table, query in queries.items()}

    raw = work / "scanner.json"
    raw.write_text(
        json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "File": "src/settings.py",
                    "StartLine": 7,
                    "Description": CANARY,
                    "Secret": "SECGUARD-RAW-SYNTHETIC-CANARY",
                }
            ]
        ),
        encoding="utf-8",
    )
    cli(
        [
            "scan",
            "check",
            "-i",
            "scanner.json",
            "--today",
            "2026-10-16",
            "--minimize-metadata",
            "--json",
            "findings.json",
            "--remediation",
            "exchange.json",
            "--repository",
            "example/internal",
            "--output-manifest",
            "manifest.json",
        ],
        1,
        integration=False,
    )
    cli(["scan", "verify-outputs", "--manifest", "manifest.json"], integration=False)
    require(
        CANARY not in (work / "findings.json").read_text(),
        "H02-installed-minimized-blocked-exports",
    )

    args = [
        "--input",
        "exchange.json",
        "--database",
        "bridge.sqlite",
        "--issues-output",
        "preview.json",
    ]
    database = work / "bridge.sqlite"
    cli(args)
    require(
        not database.exists() and receipt()["database_committed"] is False,
        "H03-preview-no-database",
    )
    cli([*args, "--apply"])
    require(receipt()["created"] == 1 and receipt()["database_committed"], "H04-explicit-apply")
    before = rows(database)
    cli([*args, "--apply"])
    require(
        receipt()["replayed"] == 1 and rows(database) == before, "H05-idempotent-real-sqlite-replay"
    )

    state_setup = (
        "import sys; from secguard.integrations import remediation_hub as bridge; "
        "hub = bridge._load_hub(); store = hub.Store('sqlite:///' + sys.argv[1]); "
        "group, task = store.list_groups()[0], store.list_tasks()[0]; "
        "store.add_group(group.model_copy(update={'status': hub.GroupStatus.CLOSED, "
        "'owner': 'internal-owner'})); "
        "store.add_task(task.model_copy(update={'status': hub.TaskStatus.CLOSED, "
        "'owner': 'internal-owner'})); store.engine.dispose()"
    )
    setup = subprocess.run(
        [sys.executable, "-c", state_setup, database.as_posix()],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=90,
    )
    commands.append(
        {"module": "hub-managed-state-setup", "expected_exit": 0, "actual_exit": setup.returncode}
    )
    if setup.returncode != 0:
        raise RuntimeError("managed-state fixture failed")
    before = rows(database)
    cli([*args, "--apply"])
    require(
        rows(database) == before and "`closed`" in receipt()["issues"][0]["body"],
        "H06-managed-state-and-assignment-preserved",
    )

    exchange = json.loads((work / "exchange.json").read_text())
    conflict = json.loads(json.dumps(exchange))
    conflict["findings"][0]["severity"] = (
        "critical" if exchange["findings"][0]["severity"] != "critical" else "high"
    )
    (work / "conflict.json").write_text(json.dumps(conflict))
    cli(["--input", "conflict.json", *args[2:], "--apply"], 2)
    require(rows(database) == before, "H07-conflict-before-entity-write")

    foreign = work / "foreign.sqlite"
    with contextlib.closing(sqlite3.connect(foreign)) as connection:
        connection.execute("CREATE TABLE unrelated (id INTEGER)")
        connection.commit()
    before_foreign = foreign.read_bytes()
    cli(
        [
            "--input",
            "exchange.json",
            "--database",
            "foreign.sqlite",
            "--issues-output",
            "foreign-preview.json",
            "--apply",
        ],
        2,
    )
    require(foreign.read_bytes() == before_foreign, "H08-foreign-database-unchanged")

    # Fault injection uses the actual installed Store and SQLite commits.
    # It is distinct from the subprocess user journeys above.
    partial = work / "partial.sqlite"
    partial_output = work / "partial-preview.json"
    partial_output.write_text("previous preview")
    partial_args = [
        "--input",
        str(work / "exchange.json"),
        "--database",
        str(partial),
        "--issues-output",
        str(partial_output),
        "--apply",
    ]
    errors = fault(partial_args, "task")
    require(
        "partial import" in errors and not partial_output.exists(),
        "H09-partial-import-without-stale-preview",
    )
    require(
        len(rows(partial)["finding_group"]) == 1 and not rows(partial)["remediation_task"],
        "H10-real-partial-commit-observed",
    )
    cli(partial_args)
    require(
        len(rows(partial)["remediation_task"]) == 1
        and json.loads(partial_output.read_text())["recovered"] == 1,
        "H11-real-partial-recovery",
    )

    errors = fault(partial_args, "output")
    require(
        "database import completed; preview missing" in errors and not partial_output.exists(),
        "H12-post-commit-output-failure-disambiguated",
    )
    before = rows(partial)
    cli(partial_args)
    require(
        rows(partial) == before and json.loads(partial_output.read_text())["replayed"] == 1,
        "H13-preview-regeneration-preserves-state",
    )

    old_preview = partial_output.read_bytes()
    with bridge._database_lock(partial):
        cli(partial_args, 2)
        require(
            rows(partial) == before and partial_output.read_bytes() == old_preview,
            "H14-overlapping-process-refused",
        )

    empty = {
        **exchange,
        "findings": [],
        "gate": {"decision": "BLOCK", "fail_on": "high", "expired_waivers": 1},
    }
    (work / "empty.json").write_text(json.dumps(empty))
    cli(["--input", "empty.json", "--issues-output", "empty-preview.json"])
    empty_receipt = json.loads((work / "empty-preview.json").read_text())
    require(
        empty_receipt["findings"] == 0 and empty_receipt["gate"]["decision"] == "BLOCK",
        "H15-empty-blocked-gate-preserved",
    )
    (work / "findings.json").write_text("modified later")
    cli(["scan", "verify-outputs", "--manifest", "manifest.json"], 2, integration=False)
    checks.append("H16-installed-marker-rejects-changed-artifact")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    report = {
        "scope": "internal synthetic pilot; installed wheels and isolated SQLite",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "checks": [],
        "commands": [],
        "status": "FAIL",
    }
    try:
        report["versions"] = {
            name: metadata.version(name)
            for name in (
                "secrets-hygiene-kit",
                "appsec-remediation-hub",
                "sqlalchemy",
                "alembic",
                "pydantic",
            )
        }
        with tempfile.TemporaryDirectory(prefix="sg-hub-pilot-") as temporary:
            pilot(Path(temporary), report["checks"], report["commands"])
        report["status"] = "PASS"
    except Exception as exc:
        report["failure"] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"Hub pilot: {report['status']}; {len(report['checks'])} checks; "
        f"{len(report['commands'])} commands"
    )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
