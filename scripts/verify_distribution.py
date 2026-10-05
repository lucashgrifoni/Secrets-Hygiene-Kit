"""Verify wheel and sdist installations in fresh environments outside the checkout."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANARY = "SECGUARD-CANARY-DISTRIBUTION-0001"


def run(argv: list[str], cwd: Path, *, expected: int = 0) -> str:
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "SECGUARD_OVERRIDE", "SECGUARD_OVERRIDE_REASON"):
        environment.pop(name, None)
    environment.update(PYTHONUTF8="1", NO_COLOR="1", TERM="dumb")
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    output = result.stdout + result.stderr
    if CANARY in output:
        raise RuntimeError("distribution smoke emitted the secret canary")
    if result.returncode != expected:
        raise RuntimeError(
            f"{Path(argv[0]).name} {argv[1]} returned {result.returncode}, expected {expected}: "
            f"{output[-3000:]}"
        )
    return result.stdout


def required_resources() -> set[str]:
    package = ROOT / "src" / "secguard"
    resources = {"secguard/py.typed", "secguard/data/rules.yaml"}
    for pattern in ("templates/*.yaml", "templates/*.yml", "playbooks/*/PLAYBOOK.md"):
        resources.update(
            f"secguard/{path.relative_to(package).as_posix()}" for path in package.glob(pattern)
        )
    return resources


def inspect_archives(wheel: Path, sdist: Path) -> str:
    expected = required_resources()
    license_text = (ROOT / "LICENSE").read_bytes()
    with zipfile.ZipFile(wheel) as archive:
        members = set(archive.namelist())
        if missing := expected - members:
            raise RuntimeError(f"wheel is missing resources: {sorted(missing)}")
        metadata_files = [name for name in members if name.endswith(".dist-info/METADATA")]
        if len(metadata_files) != 1:
            raise RuntimeError("wheel must have exactly one package metadata file")
        metadata = Parser().parsestr(archive.read(metadata_files[0]).decode("utf-8"))
        if metadata["Name"] != "secrets-hygiene-kit":
            raise RuntimeError("unexpected distribution name")
        if metadata["License-Expression"] != "Apache-2.0":
            raise RuntimeError("wheel must declare the Apache-2.0 license expression")
        license_member = metadata_files[0].removesuffix("METADATA") + "licenses/LICENSE"
        if license_member not in members or archive.read(license_member) != license_text:
            raise RuntimeError("wheel does not contain the canonical license text")
        version = metadata["Version"]
        if not version:
            raise RuntimeError("wheel version is missing")
    with tarfile.open(sdist, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        prefixes = {name.split("/", 1)[0] for name in members}
        if len(prefixes) != 1:
            raise RuntimeError("sdist must have one root directory")
        prefix = prefixes.pop()
        if missing := {f"{prefix}/src/{name}" for name in expected} - members.keys():
            raise RuntimeError(f"sdist is missing resources: {sorted(missing)}")
        member = members.get(f"{prefix}/LICENSE")
        stream = archive.extractfile(member) if member is not None and member.isfile() else None
        if stream is None or stream.read() != license_text:
            raise RuntimeError("sdist does not contain the canonical license text")
    return version


def smoke(cli: Path, project: Path, version: str) -> None:
    def invoke(*arguments: str, expected: int = 0) -> str:
        return run([str(cli), *arguments], project, expected=expected)

    invoke("--help")
    if invoke("version").strip() != version:
        raise RuntimeError("console script version disagrees with wheel metadata")
    listing = invoke("playbooks", "list")
    for playbook in (ROOT / "src/secguard/playbooks").glob("*/PLAYBOOK.md"):
        if playbook.parent.name not in listing:
            raise RuntimeError(f"installed playbook is missing: {playbook.parent.name}")
    invoke("playbooks", "check")
    invoke("init", ".", "--ci", "both")
    for name in (
        ".secguard/waivers.yaml",
        ".pre-commit-config.yaml",
        ".github/workflows/secguard.yml",
        ".gitlab/secguard.gitlab-ci.yml",
    ):
        if not (project / name).is_file():
            raise RuntimeError(f"init did not create {name}")
    invoke("waivers", "check", "--file", ".secguard/waivers.yaml")
    invoke(
        "incident", "start", "--secret-type", "gcp-service-account-json", "--output", "incident.md"
    )
    if (
        not (project / "incident.md")
        .read_text(encoding="utf-8")
        .startswith("# Incident checklist:")
    ):
        raise RuntimeError("installed incident command produced no checklist")

    (project / "clean.json").write_text("[]", encoding="utf-8")
    (project / "invalid.json").write_text("{", encoding="utf-8")
    (project / "leaked.json").write_text(
        json.dumps(
            [{"RuleID": "aws-access-token", "File": "example.py", "StartLine": 1, "Secret": CANARY}]
        ),
        encoding="utf-8",
    )
    invoke("scan", "check", "--input", "clean.json", "--fail-on", "high")
    blocked = invoke(
        "scan",
        "check",
        "--input",
        "leaked.json",
        "--fail-on",
        "high",
        "--sarif",
        "blocked.sarif",
        "--markdown",
        "blocked.md",
        "--pr-comment",
        "comment.md",
        "--remediation",
        "remediation.json",
        "--repository",
        "acme/distribution-smoke",
        expected=1,
    )
    if "BLOCK" not in blocked:
        raise RuntimeError("blocking exit code did not contain a BLOCK verdict")
    invoke("scan", "check", "--input", "invalid.json", "--fail-on", "high", expected=2)
    for name in ("blocked.sarif", "blocked.md", "comment.md", "remediation.json"):
        if CANARY in (project / name).read_text(encoding="utf-8"):
            raise RuntimeError(f"secret canary leaked into {name}")
    sarif = json.loads((project / "blocked.sarif").read_text(encoding="utf-8"))
    if not sarif["runs"][0]["results"]:
        raise RuntimeError("blocking fixture produced no SARIF finding")
    exchange = json.loads((project / "remediation.json").read_text(encoding="utf-8"))
    if (
        exchange["schema"] != "secguard.remediation/v1"
        or exchange["gate"]["decision"] != "BLOCK"
        or len(exchange["findings"]) != 1
    ):
        raise RuntimeError("installed remediation export did not preserve the blocking finding")
    python = cli.with_name("python.exe" if os.name == "nt" else "python")
    run([str(python), "-m", "secguard.integrations.remediation_hub", "--help"], project)
    run(
        [
            str(python),
            "-m",
            "secguard.integrations.remediation_hub",
            "--input",
            "remediation.json",
            "--database",
            "unused.sqlite",
            "--issues-output",
            "unused-issues.json",
        ],
        project,
        expected=2,
    )
    if (project / "unused.sqlite").exists() or (project / "unused-issues.json").exists():
        raise RuntimeError("missing Hub dependency did not fail without side effects")


def verify(dist: Path, requirements_output: Path | None) -> None:
    wheels, sdists = list(dist.glob("*.whl")), list(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError("expected exactly one wheel and one sdist")
    wheel, sdist = wheels[0].resolve(), sdists[0].resolve()
    version = inspect_archives(wheel, sdist)
    with tempfile.TemporaryDirectory(prefix="secguard-distribution-") as temporary:
        work = Path(temporary)
        if work.is_relative_to(ROOT):
            raise RuntimeError("distribution smoke must run outside the checkout")
        requirements = work / "runtime-requirements.txt"
        for kind, artifact in (("wheel", wheel), ("sdist", sdist)):
            environment = work / f"{kind}-env"
            project = work / f"{kind}-project"
            project.mkdir()
            run([sys.executable, "-m", "venv", str(environment)], work)
            binaries = environment / ("Scripts" if os.name == "nt" else "bin")
            python = binaries / ("python.exe" if os.name == "nt" else "python")
            cli = binaries / ("secguard.exe" if os.name == "nt" else "secguard")
            install = [str(python), "-m", "pip", "install", "--disable-pip-version-check"]
            if kind == "sdist":
                install += ["--constraint", str(requirements)]
            run([*install, str(artifact)], project)
            smoke(cli, project, version)
            frozen = run(
                [str(python), "-m", "pip", "freeze", "--exclude", "secrets-hygiene-kit"], project
            )
            lines = sorted(line.strip() for line in frozen.splitlines() if line.strip())
            if not lines or any(
                not re.fullmatch(r"[A-Za-z0-9_.-]+==[^\s]+", line) for line in lines
            ):
                raise RuntimeError("runtime dependencies are not fully resolved index requirements")
            if kind == "wheel":
                requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")
            elif lines != requirements.read_text(encoding="utf-8").splitlines():
                raise RuntimeError("wheel and sdist runtime dependencies disagree")
            print(
                f"{kind}: PASS (clean install, resources, console script, exit codes 0/1/2, canary)"
            )
        if requirements_output is not None:
            requirements_output.write_bytes(requirements.read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--requirements-output", type=Path)
    arguments = parser.parse_args()
    try:
        verify(arguments.dist.resolve(), arguments.requirements_output)
    except (
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        parser.exit(1, f"distribution verification failed: {exc}\n")


if __name__ == "__main__":
    main()
