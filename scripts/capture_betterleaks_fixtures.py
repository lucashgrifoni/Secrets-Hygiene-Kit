"""Capture Betterleaks 1.9.0 locally; no download or credential verification.

The binary is independently installed from the official release. Raw output
and logs stay under ignored melhorias; only transformed fixtures enter Git.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from regenerate_detector_fixtures import synthetic_input

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/betterleaks-1.9.0"
EVIDENCE = ROOT / "melhorias/02_ativos/melhoria_006_integracoes_piloto/evidencias/betterleaks"
WINDOWS_BINARY_SHA256 = "41a3dc5e75712d52d25aa7203b0b6bc2fa9c796fe5109d3835c60226a9a69352"
RAW_FIELDS = (
    "Secret",
    "Match",
    "MatchContext",
    "CaptureGroups",
    "ComponentSets",
    "ValidationMeta",
    "ValidationReason",
    "Author",
    "Email",
    "Message",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if digest(binary.read_bytes()) != WINDOWS_BINARY_SHA256:
        raise SystemExit("This capture locks the official Windows x64 1.9.0 binary")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC"}
    }
    version = subprocess.run(
        [str(binary), "version"], capture_output=True, env=environment, timeout=30, check=True
    )
    if version.stdout.decode().strip() != "1.9.0":
        raise SystemExit("Unexpected producer version")
    CORPUS.mkdir(exist_ok=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    observations = {}
    for case in ("positive", "clean"):
        with tempfile.TemporaryDirectory(prefix="sg-bl-") as temporary:
            working = Path(temporary)
            data = synthetic_input(case == "positive").encode()
            (working / "sample.env").write_bytes(data)
            command = [
                str(binary),
                "dir",
                "sample.env",
                "--report-format",
                "json",
                "--report-path",
                "raw.json",
                "--exit-code",
                "0",
                "--no-banner",
                "--no-color",
                "--redact=100",
                "--timeout",
                "30",
            ]
            result = subprocess.run(
                command, cwd=working, env=environment, capture_output=True, timeout=60, check=False
            )
            (EVIDENCE / f"{case}.stdout").write_bytes(result.stdout)
            (EVIDENCE / f"{case}.stderr").write_bytes(result.stderr)
            if result.returncode != 0:
                raise SystemExit(f"Producer {case} failed with exit {result.returncode}")
            raw = (working / "raw.json").read_bytes()
            (EVIDENCE / f"{case}.raw.json").write_bytes(raw)
            entries = json.loads(raw)
            if not isinstance(entries, list) or bool(entries) != (case == "positive"):
                raise SystemExit("Producer case did not produce the expected finding presence")
            transformed = copy.deepcopy(entries)
            for index, entry in enumerate(transformed):
                for field in RAW_FIELDS:
                    if field in entry:
                        entry[field] = f"SECGUARD-BETTERLEAKS-CANARY-{index}-{field}"
                # Attributes can carry commit messages/email or source data.
                if "Attributes" in entry:
                    entry["Attributes"] = {"canary": "SECGUARD-BETTERLEAKS-CANARY-Attributes"}
            fixture = CORPUS / f"{case}.json"
            write(fixture, transformed)
            observations[case] = {
                "kind": "captured-producer-output-with-redaction-canaries",
                "argv": ["betterleaks", *command[1:]],
                "exit_code": result.returncode,
                "input_sha256": digest(data),
                "raw_sha256": digest(raw),
                "fixture_sha256": digest(fixture.read_bytes()),
                "finding_count": len(entries),
                "observed_rules": sorted(entry["RuleID"] for entry in entries),
                "validation_enabled": False,
            }
    malformed = [
        {
            "RuleID": "github-pat",
            "File": "../outside.py",
            "Secret": "SECGUARD-BETTERLEAKS-CANARY-malformed",
        }
    ]
    write(CORPUS / "malformed.json", malformed)
    observations["malformed"] = {
        "kind": "derived-invalid-input-not-emitted-by-producer",
        "fixture_sha256": digest((CORPUS / "malformed.json").read_bytes()),
    }
    write(
        CORPUS / "provenance.json",
        {
            "schema": "secguard.betterleaks-fixtures/v1",
            "version": "1.9.0",
            "source": "https://github.com/betterleaks/betterleaks/releases/tag/v1.9.0",
            "binary_sha256": WINDOWS_BINARY_SHA256,
            "archive_sha256": "b765daec9fda475b031b5a5159798cbe4294a3f2a50683cbc0471226e376d3da",
            "platform": "windows/amd64",
            "captured_at": datetime.now(UTC).isoformat(),
            "script_sha256": digest(Path(__file__).read_bytes()),
            "cases": observations,
            "scope": "Local synthetic file only; default rule pack; no provider verification",
        },
    )
    print("Betterleaks 1.9.0 corpus captured: positive, clean, malformed; validation disabled")


if __name__ == "__main__":
    main()
