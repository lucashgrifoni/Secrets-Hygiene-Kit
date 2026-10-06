"""Run the published CLI against constructed scanner reports.

This example never runs a scanner or contacts a credential provider.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

CANARY = "demo-placeholder"
TODAY = "2026-10-05"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def gitleaks(rule: str, path: str, line: int) -> dict:
    return {
        "RuleID": rule,
        "File": path,
        "StartLine": line,
        "Description": "Synthetic demonstration finding",
        "Fingerprint": f"{path}:{rule}:{line}",
        "Secret": CANARY,
        "Match": CANARY,
    }


def trufflehog(detector: str, path: str, line: int) -> dict:
    return {
        "DetectorName": detector,
        "Verified": False,
        "Raw": CANARY,
        "SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": line}}},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secguard", default=shutil.which("secguard"))
    parser.add_argument("--output-dir", type=Path, help="A new or empty directory for the demo.")
    args = parser.parse_args()
    require(bool(args.secguard), "Install secguard 0.4.0 and activate its environment first.")
    cli = str(Path(args.secguard).resolve())
    work = args.output_dir or Path(tempfile.mkdtemp(prefix="secguard-demo-"))
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    require(
        not any(work.iterdir()), "The output directory must be empty; existing files are preserved."
    )
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "SECGUARD_OVERRIDE", "SECGUARD_OVERRIDE_REASON"):
        environment.pop(name, None)
    environment.update(PYTHONUTF8="1", NO_COLOR="1", TERM="dumb")
    runs: list[dict] = []

    def execute(name: str, argv: list[str], expected: int) -> str:
        result = subprocess.run(
            [cli, *argv],
            cwd=work,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
        require(CANARY not in result.stdout + result.stderr, f"{name} exposed the raw canary.")
        require(
            result.returncode == expected, f"{name}: exit {result.returncode}, expected {expected}."
        )
        runs.append({"name": name, "arguments": argv, "exit": result.returncode})
        print(f"\n$ secguard {' '.join(argv)}")
        print(result.stdout, end="")
        print(f"Observed exit: {result.returncode}")
        return result.stdout

    require(
        execute("version", ["version"], 0).strip() == "0.4.0", "Use the published 0.4.0 release."
    )
    fixture = gitleaks("aws-access-token", "tests/fixtures/fake_aws.txt", 4)
    before = [
        gitleaks("aws-access-token", "app/config.py", 12),
        gitleaks("github-pat", "app/github_client.py", 28),
        fixture,
    ]
    extra = [
        trufflehog("AWS", "app/config.py", 12),
        trufflehog("Github", "app/github_client.py", 28),
    ]
    for phase, findings, contributing in (
        ("antes", before, extra),
        ("depois", [fixture], [trufflehog("AWS", "tests/fixtures/fake_aws.txt", 4)]),
    ):
        (work / phase).mkdir()
        (work / phase / "gitleaks.json").write_text(json.dumps(findings), encoding="utf-8")
        (work / phase / "trufflehog.jsonl").write_text(
            "\n".join(json.dumps(item) for item in contributing) + "\n", encoding="utf-8"
        )
    (work / "waivers.yaml").write_text(
        'schema: "secguard.waiver/v1"\nwaivers:\n'
        "  - id: WV-DEMO-001\n"
        "    rule: secret-type:aws-access-key\n"
        "    path: tests/fixtures/**\n"
        '    reason: "Fictitious demonstration fixture, not a credential."\n'
        "    owner: appsec@example.invalid\n"
        "    approver: demo-reviewer\n"
        "    expires_at: 2026-10-12\n",
        encoding="utf-8",
    )
    for phase, name, expected in (("antes", "block", 1), ("depois", "pass", 0)):
        output = work / "output" / name
        output.mkdir(parents=True)
        argv = [
            "scan",
            "check",
            "--input",
            f"{phase}/gitleaks.json",
            "--input",
            f"{phase}/trufflehog.jsonl",
            "--waivers",
            "waivers.yaml",
            "--fail-on",
            "high",
            "--today",
            TODAY,
        ]
        for flag, filename in (
            ("--json", "findings.json"),
            ("--sarif", "secguard.sarif"),
            ("--markdown", "report.md"),
            ("--pr-comment", "pr-comment.md"),
            ("--remediation", "remediation.json"),
        ):
            argv.extend([flag, f"output/{name}/{filename}"])
        argv.extend(["--repository", "example/secguard-demo"])
        stdout = execute(name, argv, expected)
        expected_counts = (
            "3 finding(s): 2 active, 1 waived"
            if name == "block"
            else "1 finding(s): 0 active, 1 waived"
        )
        require(expected_counts in stdout, f"{name}: unexpected reconciliation counts.")
        exchange = json.loads((output / "remediation.json").read_text(encoding="utf-8"))
        require(
            len(exchange["findings"]) == (2 if name == "block" else 0), "Unexpected active handoff."
        )

    execute(
        "expired-waiver",
        [
            "scan",
            "check",
            "--input",
            "depois/gitleaks.json",
            "--input",
            "depois/trufflehog.jsonl",
            "--waivers",
            "waivers.yaml",
            "--fail-on",
            "high",
            "--today",
            "2026-10-13",
        ],
        1,
    )
    execute(
        "incident",
        [
            "incident",
            "start",
            "--secret-type",
            "github-pat",
            "--today",
            TODAY,
            "--reference",
            "DEMO-001",
            "--output",
            "output/github-incident.md",
        ],
        0,
    )
    exports = sorted(path for path in (work / "output").rglob("*") if path.is_file())
    for path in exports:
        require(
            CANARY not in path.read_text(encoding="utf-8"), f"{path.name} exposed the raw canary."
        )
    receipt = {
        "status": "PASS",
        "secguard_version": "0.4.0",
        "fixed_date": TODAY,
        "runs": runs,
        "scope": "Constructed reports; actual CLI; no scanner or provider operation.",
        "exports": [
            {
                "path": path.relative_to(work).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in exports
        ],
    }
    (work / "demo-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"\nDemo PASS: BLOCK=1, PASS=0, expired waiver=1. Outputs: {work}")


if __name__ == "__main__":
    main()
