"""Run the packaged policy against actual secguard exports using an external OPA.

Run from an environment with secguard installed. The lab creates only synthetic
files in a fresh temporary directory and records a compact result if requested.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, cwd=cwd, text=True, encoding="utf-8", capture_output=True, timeout=30, check=False
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opa", type=Path, required=True)
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    opa = str(args.opa.resolve())
    observations = []
    with tempfile.TemporaryDirectory(prefix="sg-opa-") as temporary:
        working = Path(temporary)
        version = run([opa, "version"], cwd=working)
        if version.returncode or "Rego Version: v1" not in version.stdout:
            raise SystemExit("A working OPA with Rego v1 is required")
        shown = run([sys.executable, "-m", "secguard", "policy", "show"], cwd=working)
        if shown.returncode:
            raise SystemExit("Packaged secguard policy could not be read")
        policy = working / "secguard.rego"
        policy.write_text(shown.stdout, encoding="utf-8", newline="\n")
        checked = run([opa, "check", "--strict", str(policy)], cwd=working)
        if checked.returncode:
            raise SystemExit("The packaged policy did not compile")
        for case, report, threshold, expected_gate, expected_opa in [
            ("clean", [], "high", 0, 0),
            ("high-block", [{"RuleID": "github-pat", "File": "src/auth.py"}], "high", 1, 1),
            ("high-report-only", [{"RuleID": "github-pat", "File": "src/auth.py"}], "none", 0, 1),
            ("low", [{"RuleID": "generic-api-key", "File": "src/auth.py"}], "high", 0, 0),
            ("unknown-medium", [{"RuleID": "unknown-rule", "File": "src/auth.py"}], "high", 0, 1),
        ]:
            raw = working / "raw.json"
            raw.write_text(json.dumps(report), encoding="utf-8")
            exported = working / "opa.json"
            gate = run(
                [
                    sys.executable,
                    "-m",
                    "secguard",
                    "scan",
                    "check",
                    "--input",
                    str(raw),
                    "--fail-on",
                    threshold,
                    "--today",
                    "2026-10-07",
                    "--opa-input",
                    str(exported),
                ],
                cwd=working,
            )
            evaluated = run(
                [
                    opa,
                    "eval",
                    "--strict",
                    "--fail",
                    "--format=json",
                    "--data",
                    str(policy),
                    "--input",
                    str(exported),
                    "true = data.secguard.allow",
                ],
                cwd=working,
            )
            if gate.returncode != expected_gate or evaluated.returncode != expected_opa:
                raise SystemExit(
                    f"OPA lab failed: {case}, gate={gate.returncode}, OPA={evaluated.returncode}"
                )
            observations.append(
                {"case": case, "secguard_exit": gate.returncode, "opa_exit": evaluated.returncode}
            )
        clean = {
            "schema": "secguard.policy-input/v1",
            "gate": {"passed": True, "expired_waivers": []},
            "findings": [],
        }
        invalid = [
            ("schema-invalid", {**clean, "schema": "unknown"}),
            ("gate-blocked", {**clean, "gate": {"passed": False, "expired_waivers": []}}),
            (
                "waiver-expired",
                {**clean, "gate": {"passed": True, "expired_waivers": ["WV-2026-006"]}},
            ),
            ("findings-missing", {"schema": clean["schema"], "gate": clean["gate"]}),
            (
                "verification-not-triage",
                {
                    **clean,
                    "findings": [{"status": "active", "severity": "high", "verified": False}],
                },
            ),
            ("unknown-status", {**clean, "findings": [{"status": "ignored", "severity": "low"}]}),
            (
                "unknown-severity",
                {**clean, "findings": [{"status": "active", "severity": "unknown"}]},
            ),
            (
                "waiver-without-authority",
                {**clean, "findings": [{"status": "waived", "severity": "high", "waiver_ids": []}]},
            ),
        ]
        raw.write_text(json.dumps([{"RuleID": "github-pat", "File": "fixtures/token.txt"}]))
        waivers = working / "waivers.yaml"
        waivers.write_text(
            "schema: secguard.waiver/v1\nwaivers:\n- id: WV-2026-006\n"
            "  rule: gitleaks:github-pat\n  path: fixtures/**\n"
            "  owner: pilot\n  approver: pilot-review\n"
            "  reason: Synthetic internal pilot only\n  expires_at: 2026-10-20\n",
            encoding="utf-8",
        )
        gate = run(
            [
                sys.executable,
                "-m",
                "secguard",
                "scan",
                "check",
                "--input",
                str(raw),
                "--waivers",
                str(waivers),
                "--today",
                "2026-10-07",
                "--opa-input",
                str(exported),
            ],
            cwd=working,
        )
        evaluated = run(
            [
                opa,
                "eval",
                "--fail",
                "--data",
                str(policy),
                "--input",
                str(exported),
                "true = data.secguard.allow",
            ],
            cwd=working,
        )
        if gate.returncode != 0 or evaluated.returncode != 0:
            raise SystemExit("OPA rejected a valid, fully scoped waiver")
        observations.append({"case": "valid-waiver", "secguard_exit": 0, "opa_exit": 0})
        for case, payload in invalid:
            exported.write_text(json.dumps(payload), encoding="utf-8")
            evaluated = run(
                [
                    opa,
                    "eval",
                    "--fail",
                    "--format=json",
                    "--data",
                    str(policy),
                    "--input",
                    str(exported),
                    "true = data.secguard.allow",
                ],
                cwd=working,
            )
            if evaluated.returncode != 1:
                raise SystemExit(f"OPA accepted invalid or blocking input: {case}")
            observations.append({"case": case, "opa_exit": evaluated.returncode})
        evaluated = run(
            [
                opa,
                "eval",
                "--fail",
                "--data",
                str(policy),
                "true = data.secguard.undefined_decision",
            ],
            cwd=working,
        )
        if evaluated.returncode != 1:
            raise SystemExit("Undefined policy query did not fail closed")
        observations.append({"case": "undefined-decision", "opa_exit": evaluated.returncode})
        broken = working / "broken.rego"
        broken.write_text("package secguard\nallow if {", encoding="utf-8")
        evaluated = run(
            [
                opa,
                "eval",
                "--fail",
                "--data",
                str(broken),
                "true = data.secguard.allow",
            ],
            cwd=working,
        )
        if evaluated.returncode == 0:
            raise SystemExit("A policy compilation failure was accepted")
        observations.append({"case": "policy-compilation-error", "opa_exit": evaluated.returncode})
        report = {
            "schema": "secguard.opa-validation/v1",
            "status": "PASS",
            "checked_at": datetime.now(UTC).isoformat(),
            "opa_version": version.stdout,
            "opa_sha256": hashlib.sha256(Path(opa).read_bytes()).hexdigest(),
            "scope": "Local synthetic pilot; actual OPA and secguard subprocesses",
            "cases": observations,
        }
    if args.result:
        args.result.parent.mkdir(parents=True, exist_ok=True)
        args.result.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"OPA policy contract PASS: {len(observations)} cases")


if __name__ == "__main__":
    main()
