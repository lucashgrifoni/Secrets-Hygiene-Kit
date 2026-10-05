"""Regenerate the pinned producer corpus from controlled local synthetic inputs.

Install the producers separately from their official releases. This script does
not download tools, scan this checkout, or verify credentials with a provider.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests/fixtures/producer_versions"
EVIDENCE = REPO_ROOT / "melhorias/09_evidencias/mel_002_detector_producers"
VERSIONS = {"gitleaks": "8.30.1", "trufflehog": "3.97.9", "detect-secrets": "1.5.0"}
FIXTURE_CLOCK = "2026-10-05T00:00:00Z"
SOURCE_LOCK = FIXTURES / "producer-lock.json"
SOURCES = {
    "gitleaks": "https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1",
    "trufflehog": "https://github.com/trufflesecurity/trufflehog/releases/tag/v3.97.9",
    "detect-secrets": "https://pypi.org/project/detect-secrets/1.5.0/",
}
RAW_FIELDS = {
    "gitleaks": ("Secret", "Match", "Message", "Author", "Email"),
    "trufflehog": ("Raw", "RawV2", "Redacted", "ExtraData", "SecretParts", "StructuredData"),
}


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def synthetic_input(positive: bool) -> str:
    """Construct values locally; the repository contains no usable credential."""
    header = "# Synthetic detector compatibility lab. Never authenticate these values.\n"
    if not positive:
        return header + "APP_MODE=demo\n"
    first = "AKIA" + "ZQ7N6F5B" + "3J4V2R6M"
    second = "zQ7n6F5b3J" + "4v2R6m8T9k" + "1P5d7H3s2W" + "4y6A8c9E0g"
    third = "ghp_" + "4b8e1C7f2" + "A9d6E3g5H" + "0j8K2m4N7" + "p1Q6r9S3t"
    return (
        header
        + f"AWS_ACCESS_KEY_ID={first}\n"
        + f"AWS_SECRET_ACCESS_KEY={second}\n"
        + f"GITHUB_TOKEN={third}\n"
    )


def producer_command(path: Path) -> list[str]:
    # A .py entrypoint loader can keep isolated site-packages reachable on
    # Windows hosts whose checkout path exceeds Python's legacy MAX_PATH limit.
    # The loader must call the unmodified producer CLI entrypoint.
    if path.suffix.lower() == ".py":
        return [sys.executable, "-S", str(path)]
    return [str(path)]


def run(command: list[str], *, cwd: Path, label: str) -> subprocess.CompletedProcess[bytes]:
    logs = EVIDENCE / "runs"
    logs.mkdir(parents=True, exist_ok=True)
    state = EVIDENCE / "state"
    state.mkdir(exist_ok=True)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC", "LANG", "LC_ALL"}
    }
    environment.update(
        HOME=str(state),
        USERPROFILE=str(state),
        TEMP=str(state),
        TMP=str(state),
        PYTHONNOUSERSITE="1",
    )
    result = subprocess.run(
        command, cwd=cwd, env=environment, capture_output=True, timeout=120, check=False
    )
    (logs / f"{label}.stdout").write_bytes(result.stdout)
    (logs / f"{label}.stderr").write_bytes(result.stderr)
    write_json(
        logs / f"{label}.execution.json",
        {"argv": command, "cwd": str(cwd), "exit_code": result.returncode},
    )
    if result.returncode:
        raise RuntimeError(f"{label} failed with exit {result.returncode}; inspect ignored logs")
    return result


def redacted_value(value: Any, prefix: str) -> Any:
    if isinstance(value, str):
        return prefix if value else value
    if isinstance(value, dict):
        return {key: redacted_value(item, f"{prefix}-{key}") for key, item in value.items()}
    if isinstance(value, list):
        return [redacted_value(item, f"{prefix}-{index}") for index, item in enumerate(value)]
    return value


def curate(name: str, raw: bytes) -> Any:
    if name == "trufflehog":
        data = [json.loads(line) for line in raw.splitlines() if line.strip()]
        data.sort(
            key=lambda item: (
                item["DetectorName"],
                item["SourceMetadata"]["Data"]["Filesystem"]["line"],
            )
        )
    else:
        data = json.loads(raw)
    if name in RAW_FIELDS:
        if name == "gitleaks":
            data.sort(key=lambda item: (item["File"], item["StartLine"], item["RuleID"]))
        for index, entry in enumerate(data, start=1):
            for field in RAW_FIELDS[name]:
                if field in entry:
                    entry[field] = redacted_value(
                        entry[field], f"SECGUARD-PRODUCER-CANARY-{name}-{index}-{field}"
                    )
    else:
        data["generated_at"] = FIXTURE_CLOCK
        for entries in data["results"].values():
            entries.sort(key=lambda item: (item["line_number"], item["type"]))
            for index, entry in enumerate(entries, start=1):
                # Obvious synthetic SHA-1-shaped values preserve the native
                # field's format while making any propagation observable.
                entry["hashed_secret"] = str(index) * 40
    return data


def write_report(path: Path, name: str, data: Any) -> None:
    if name == "trufflehog":
        path.write_text(
            "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in data),
            encoding="utf-8",
            newline="\n",
        )
    else:
        write_json(path, data)


def malformed_variant(name: str, positive: Any) -> Any:
    data = copy.deepcopy(positive)
    invalid = {"untrusted_canary": "SECGUARD-PRODUCER-CANARY-MALFORMED"}
    if name == "gitleaks":
        data[0]["RuleID"] = invalid
    elif name == "trufflehog":
        data[0]["DetectorName"] = invalid
    else:
        next(iter(data["results"].values()))[0]["type"] = invalid
    return data


def observed(name: str, data: Any) -> list[dict[str, Any]]:
    if name == "gitleaks":
        return [
            {"rule": item["RuleID"], "path": item["File"], "line": item["StartLine"]}
            for item in data
        ]
    if name == "trufflehog":
        return [
            {
                "rule": item["DetectorName"],
                "path": item["SourceMetadata"]["Data"]["Filesystem"]["file"],
                "line": item["SourceMetadata"]["Data"]["Filesystem"]["line"],
                "verified": item["Verified"],
            }
            for item in data
        ]
    return [
        {
            "rule": item["type"],
            "path": filename,
            "line": item["line_number"],
            "verified": item["is_verified"],
        }
        for filename, entries in data["results"].items()
        for item in entries
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in VERSIONS:
        parser.add_argument(f"--{name}", type=Path, required=True, help="Pinned producer CLI path")
    args = parser.parse_args()
    commands = {name: producer_command(getattr(args, name.replace("-", "_"))) for name in VERSIONS}
    source_lock = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    FIXTURES.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "schema": "secguard.producer-fixtures/v1",
        "captured_on": datetime.now(UTC).date().isoformat(),
        "script_sha256": sha256(Path(__file__).read_bytes()),
        "curation_clock": FIXTURE_CLOCK,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "input_scope": "Fresh directories containing only script-generated synthetic config.env",
        "verification": "Disabled by --no-verification / --no-verify; no provider validation",
        "isolation": "Controlled paths, environment and flags; no network sandbox claimed",
        "source_lock_sha256": sha256(SOURCE_LOCK.read_bytes()),
        "producers": {},
    }
    for name, prefix in commands.items():
        entrypoint_digest = sha256(Path(prefix[-1]).read_bytes())
        if name in source_lock["binaries"]:
            pinned_binary = source_lock["binaries"][name]
            if entrypoint_digest != pinned_binary["binary_sha256"]:
                raise RuntimeError(
                    f"{name} binary differs from producer-lock.json; "
                    "verify its official release asset before updating the lock"
                )
        version_args = ["version"] if name == "gitleaks" else ["--version"]
        version_result = run(prefix + version_args, cwd=EVIDENCE, label=f"{name}-version")
        version_text = (version_result.stdout + version_result.stderr).decode("utf-8").strip()
        expected = VERSIONS[name] if name != "trufflehog" else f"trufflehog {VERSIONS[name]}"
        if version_text != expected:
            raise RuntimeError(f"{name} version mismatch; expected {expected}")
        destination = FIXTURES / f"{name}-{VERSIONS[name]}"
        destination.mkdir(exist_ok=True)
        producer: dict[str, Any] = {
            "version": VERSIONS[name],
            "version_output": version_text,
            "source": SOURCES[name],
            "entrypoint_sha256": entrypoint_digest,
            "entrypoint_kind": "python-cli-loader" if len(prefix) > 1 else "native-cli",
            "cases": {},
        }
        for case in ("positive", "clean"):
            cwd = EVIDENCE / "inputs" / case
            cwd.mkdir(parents=True, exist_ok=True)
            input_path = cwd / "config.env"
            input_path.write_text(
                synthetic_input(case == "positive"), encoding="utf-8", newline="\n"
            )
            if {item.name for item in cwd.iterdir()} != {"config.env"}:
                raise RuntimeError("Synthetic scan directory contains an unexpected file")
            suffix = "jsonl" if name == "trufflehog" else "json"
            raw_path = EVIDENCE / "runs" / f"{name}-{case}.raw.{suffix}"
            if name == "gitleaks":
                tail = [
                    "dir",
                    ".",
                    "--exit-code",
                    "0",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(raw_path),
                    "--no-banner",
                    "--no-color",
                    "--log-level",
                    "error",
                ]
            elif name == "trufflehog":
                tail = [
                    "filesystem",
                    ".",
                    "--json",
                    "--no-verification",
                    "--no-update",
                    "--fail-on-scan-errors",
                    "--concurrency",
                    "1",
                    "--log-level=-1",
                    "--include-detectors=AWS,Github",
                ]
            else:
                tail = ["scan", "--all-files", "--no-verify"]
            execution = run(prefix + tail, cwd=cwd, label=f"{name}-{case}")
            raw = raw_path.read_bytes() if name == "gitleaks" else execution.stdout
            raw_path.write_bytes(raw)
            curated = curate(name, raw)
            case_path = destination / f"{case}.{suffix}"
            write_report(case_path, name, curated)
            safe_args = ["<REPORT>" if item == str(raw_path) else item for item in tail]
            producer["cases"][case] = {
                "kind": "real-producer-report-with-documented-redaction",
                "command": [f"<{name.upper()}>", *safe_args],
                "cwd": "<SYNTHETIC_CASE_DIR>",
                "exit_code": execution.returncode,
                "input_sha256": sha256(input_path.read_bytes()),
                "raw_sha256": sha256(raw),
                "fixture": str(case_path.relative_to(FIXTURES)).replace("\\", "/"),
                "fixture_sha256": sha256(case_path.read_bytes()),
                "observed": observed(name, curated),
            }
            if case == "positive":
                if not producer["cases"][case]["observed"]:
                    raise RuntimeError(f"{name} did not detect the synthetic positive control")
                malformed_path = destination / f"malformed.{suffix}"
                write_report(malformed_path, name, malformed_variant(name, curated))
                producer["cases"]["malformed"] = {
                    "kind": "derived-invalid-input-not-emitted-by-producer",
                    "fixture": str(malformed_path.relative_to(FIXTURES)).replace("\\", "/"),
                    "fixture_sha256": sha256(malformed_path.read_bytes()),
                    "mutation": "Replace the first rule name with an object containing a canary",
                }
            elif producer["cases"][case]["observed"]:
                raise RuntimeError(f"{name} detected a finding in the clean control")
        manifest["producers"][name] = producer
        print(f"{name} {VERSIONS[name]}: positive and clean captured; malformed derived")
    write_json(FIXTURES / "provenance.json", manifest)


if __name__ == "__main__":
    main()
