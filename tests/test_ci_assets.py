"""The composite action and the packaged CI templates.

These files are shell and YAML that no unit test exercised, and they are the
only part of secguard that runs inside someone else's pipeline. Two properties
have to hold for a security gate: it must fail when it cannot scan, and it must
never let a workflow input reach the runner as code.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ACTION_FILE = REPOSITORY_ROOT / "action.yml"

TEMPLATE_NAMES = (
    "github-actions-secguard.yml",
    "gitlab-ci-secguard.yml",
    "pre-commit-config.yaml",
    "waivers.yaml",
)

# `${{ inputs.x }}` inside a `run:` body is spliced into the script before bash
# parses it, so the value becomes code. `env:` passes it as data.
INPUT_INTERPOLATION = re.compile(r"\$\{\{\s*inputs\.")
INPUT_REFERENCE = re.compile(r"\$\{\{\s*inputs\.([a-zA-Z0-9_-]+)")


def _template_text(name: str) -> str:
    return files("secguard").joinpath("templates", name).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def action() -> dict:
    return yaml.safe_load(ACTION_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def action_steps(action) -> list[dict]:
    return action["runs"]["steps"]


# ------------------------------------------------------------- the action file


def test_the_action_is_valid_yaml_with_the_expected_shape(action):
    assert action["runs"]["using"] == "composite"
    assert action["inputs"]
    assert action["outputs"]


def test_no_workflow_input_is_interpolated_into_a_shell_body(action_steps):
    """An input must reach the shell as an environment variable, never as code."""
    offenders = [
        step["name"]
        for step in action_steps
        if "run" in step and INPUT_INTERPOLATION.search(step["run"])
    ]

    assert offenders == [], f"steps splicing an input into their script: {offenders}"


def test_every_referenced_input_is_declared(action, action_steps):
    declared = set(action["inputs"])
    referenced = set()
    for step in action_steps:
        for value in list(step.get("env", {}).values()) + [step.get("if", "")]:
            referenced.update(INPUT_REFERENCE.findall(str(value)))

    assert referenced <= declared, f"undeclared inputs: {sorted(referenced - declared)}"


def test_the_action_fails_when_no_scanner_report_was_found(action_steps):
    """A gate that scanned nothing must not report success.

    Skipping quietly makes a pipeline whose detector never ran look exactly like
    a repository with no secrets, which is the failure this tool exists to stop.
    """
    step = next(step for step in action_steps if step["name"].startswith("Fail when no scanner"))

    assert step["if"] == "steps.collect.outputs.count == '0'"
    assert "exit 1" in step["run"]
    # The escape hatch exists, but the caller has to ask for it in writing.
    assert 'SECGUARD_ALLOW_MISSING" = "true"' in step["run"]
    assert "exit 0" in step["run"]


def test_report_collection_never_splits_a_path_on_spaces(action_steps):
    """`tr ' ' '\\n'` shredded any path with a space into two missing paths."""
    collect = next(step for step in action_steps if step.get("id") == "collect")

    assert "tr ' '" not in collect["run"]
    assert "while IFS= read -r report" in collect["run"]


def test_the_gate_passes_report_paths_as_an_array(action_steps):
    """A string of arguments re-splits on whitespace one layer down."""
    gate = next(step for step in action_steps if step.get("id") == "gate")

    assert 'args+=(--input "$report")' in gate["run"]
    assert '"${args[@]}"' in gate["run"]


def test_the_action_reports_a_verdict_even_when_nothing_was_gated(action):
    assert "NO-REPORTS" in action["outputs"]["verdict"]["value"]


# ------------------------------------------------------- the packaged templates


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_every_packaged_template_is_valid_yaml(name):
    assert yaml.safe_load(_template_text(name)) is not None


def test_the_github_template_gate_has_no_skip_guard():
    """`if: hashFiles(...)` skipped the gate whenever the detector step was off.

    The detector step ships commented out, so the template as generated produced
    a green secret-hygiene job that never ran the gate.
    """
    workflow = yaml.safe_load(_template_text("github-actions-secguard.yml"))
    steps = workflow["jobs"]["secguard"]["steps"]
    gate = next(step for step in steps if step["name"] == "Secret hygiene gate")

    assert "if" not in gate
    assert "exit 1" in gate["run"]


def test_the_gitlab_template_fails_when_no_report_reached_it():
    pipeline = yaml.safe_load(_template_text("gitlab-ci-secguard.yml"))
    script = "\n".join(pipeline["secguard:gate"]["script"])

    assert "exit 1" in script
    assert "exit 0" not in script


def test_precommit_lifecycle_checks_run_even_without_matching_files():
    configuration = yaml.safe_load(_template_text("pre-commit-config.yaml"))
    hooks = configuration["repos"][0]["hooks"]
    assert len(hooks) == 2
    assert all(hook["always_run"] is True for hook in hooks)


def _command_tree() -> dict[str, set[str]]:
    """Return the real CLI command tree: top-level name -> subcommand names."""
    from secguard.cli.app import app, incident_app, playbooks_app, scan_app, waivers_app

    tree: dict[str, set[str]] = {
        command.name: set() for command in app.registered_commands if command.name
    }
    for name, group in (
        ("waivers", waivers_app),
        ("scan", scan_app),
        ("playbooks", playbooks_app),
        ("incident", incident_app),
    ):
        tree[name] = {command.name for command in group.registered_commands if command.name}
    return tree


def _shell_bodies(document: object) -> list[str]:
    """Collect every executable body in a CI document, ignoring prose and comments."""
    bodies: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"run", "entry"} and isinstance(value, str):
                    bodies.append(value)
                elif key == "script":
                    bodies.append("\n".join(value) if isinstance(value, list) else str(value))
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    return bodies


def _invocations(bodies: list[str]) -> list[tuple[str, str]]:
    """Return (command, subcommand) for every line that actually runs secguard."""
    found: list[tuple[str, str]] = []
    for body in bodies:
        for line in body.splitlines():
            match = re.match(r"secguard\s+([a-z-]+)(?:\s+([a-z-]+))?", line.strip())
            if match:
                found.append((match.group(1), match.group(2) or ""))
    return found


@pytest.mark.parametrize(
    "name",
    ("github-actions-secguard.yml", "gitlab-ci-secguard.yml", "pre-commit-config.yaml"),
)
def test_ci_templates_only_call_commands_the_cli_provides(name):
    """A template naming a command that does not exist fails in someone else's pipeline.

    Nothing else in the suite reads these files, so a renamed subcommand would
    ship silently and only surface as a broken build for whoever adopted it.
    """
    tree = _command_tree()
    invocations = _invocations(_shell_bodies(yaml.safe_load(_template_text(name))))
    assert invocations, f"{name} runs secguard nowhere"

    for command, subcommand in invocations:
        assert command in tree, f"{name} calls unknown command: {command}"
        if tree[command]:
            assert subcommand in tree[command], f"{name} calls unknown: {command} {subcommand}"


def test_the_action_only_calls_commands_the_cli_provides(action):
    tree = _command_tree()
    invocations = _invocations(_shell_bodies(action))
    assert invocations

    for command, subcommand in invocations:
        assert command in tree, f"action.yml calls unknown command: {command}"
        if tree[command]:
            assert subcommand in tree[command], f"action.yml calls unknown: {command} {subcommand}"


# ------------------------------------------------- the action, actually running


def _find_bash() -> str | None:
    # Windows bash.exe may be a WSL launcher without an installed Linux shell.
    # Prefer Git's Bash, which is also the shell GitHub uses on Windows runners.
    candidates: list[str] = []
    if os.name == "nt" and (git := shutil.which("git")):
        for parent in Path(git).parents:
            candidate = parent / "bin" / "bash.exe"
            if candidate.is_file():
                candidates.append(str(candidate))
    if found := shutil.which("bash"):
        candidates.append(found)
    for candidate in candidates:
        try:
            probe = subprocess.run(
                [candidate, "--noprofile", "--norc", "-c", "exit 0"],
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


BASH = _find_bash()
NEEDS_BASH = pytest.mark.skipif(BASH is None, reason="the composite action is bash")


def _step(action: dict, *, name: str = "", step_id: str = "") -> dict:
    for step in action["runs"]["steps"]:
        if (step_id and step.get("id") == step_id) or (name and step["name"].startswith(name)):
            return step
    raise AssertionError(f"no step matching name={name!r} id={step_id!r}")


def _run_step(step: dict, workspace: Path, environment: dict[str, str]):
    """Execute one composite step's script under the shell GitHub gives it.

    Asserting on substrings proved too weak: a rewrite that reintroduced
    fail-open could keep every phrase these tests grep for. The only honest
    check of shell is to run it.
    """
    script = workspace / "step.sh"
    script.write_text(step["run"], encoding="utf-8", newline="\n")
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [BASH, "--noprofile", "--norc", "-eo", "pipefail", script.as_posix()],
        cwd=workspace,
        env={**os.environ, **environment},
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "runner-temp").mkdir()
    (tmp_path / "github-output").write_text("", encoding="utf-8")
    return tmp_path


def _runner_environment(workspace: Path) -> dict[str, str]:
    return {
        "RUNNER_TEMP": (workspace / "runner-temp").as_posix(),
        "GITHUB_OUTPUT": (workspace / "github-output").as_posix(),
    }


def _outputs(workspace: Path) -> dict[str, str]:
    lines = (workspace / "github-output").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)


@NEEDS_BASH
def test_collection_finds_a_report_whose_path_contains_a_space(action, workspace):
    """`tr ' ' '\n'` shredded such a path into two that did not exist.

    The count then reached zero, the gate step was skipped by its `if:`, and the
    job went green having scanned nothing.
    """
    (workspace / "scan results").mkdir()
    (workspace / "scan results" / "gitleaks.json").write_text("[]", encoding="utf-8")

    result = _run_step(
        _step(action, step_id="collect"),
        workspace,
        {**_runner_environment(workspace), "SECGUARD_REPORTS": "scan results/gitleaks.json\n"},
    )

    assert result.returncode == 0, result.stderr
    assert _outputs(workspace)["count"] == "1"


@NEEDS_BASH
def test_collection_reports_zero_when_nothing_is_there(action, workspace):
    result = _run_step(
        _step(action, step_id="collect"),
        workspace,
        {**_runner_environment(workspace), "SECGUARD_REPORTS": "gitleaks.json\nabsent.jsonl\n"},
    )

    assert result.returncode == 0
    assert _outputs(workspace)["count"] == "0"
    assert "no report at: gitleaks.json" in result.stdout


@NEEDS_BASH
def test_the_no_report_step_fails_by_default_and_passes_only_when_told(action, workspace):
    step = _step(action, name="Fail when no scanner")
    base = {**_runner_environment(workspace), "SECGUARD_REPORTS": "gitleaks.json\n"}

    blocked = _run_step(step, workspace, {**base, "SECGUARD_ALLOW_MISSING": "false"})
    assert blocked.returncode == 1
    assert "::error" in blocked.stdout

    allowed = _run_step(step, workspace, {**base, "SECGUARD_ALLOW_MISSING": "true"})
    assert allowed.returncode == 0
    assert "::warning" in allowed.stdout


@NEEDS_BASH
def test_an_input_value_reaches_the_shell_as_data_not_as_a_command(action, workspace):
    """Interpolating an input into a `run:` body hands the runner a command."""
    payload = '.secguard/waivers.yaml"; touch PWNED; echo "'

    result = _run_step(
        _step(action, name="Check waiver lifecycle"),
        workspace,
        {**_runner_environment(workspace), "SECGUARD_WAIVERS": payload},
    )

    assert result.returncode == 0
    assert not (workspace / "PWNED").exists()
    assert payload in result.stdout  # echoed as text, executed as nothing


@NEEDS_BASH
@pytest.mark.parametrize("status,verdict", [(0, "PASS"), (1, "BLOCK"), (2, "ERROR"), (99, "ERROR")])
def test_gate_preserves_cli_exit_code_and_distinguishes_invalid_input(
    action, workspace, status, verdict
):
    step = _step(action, step_id="gate")
    mocked = {**step, "run": 'secguard() { return "$FAKE_EXIT"; }\n' + step["run"]}
    (workspace / "runner-temp/secguard-reports.txt").write_text(
        "scan results/gitleaks.json\n", encoding="utf-8"
    )
    result = _run_step(
        mocked,
        workspace,
        {
            **_runner_environment(workspace),
            "FAKE_EXIT": str(status),
            "SECGUARD_WAIVERS": ".secguard/waivers.yaml",
            "SECGUARD_FAIL_ON": "high",
            "SECGUARD_RULES": "",
            "SECGUARD_SARIF": "",
            "SECGUARD_MARKDOWN": "",
            "SECGUARD_COMMENT": "",
        },
    )
    assert result.returncode == status, result.stderr
    assert _outputs(workspace)["verdict"] == verdict


def test_a_pre_gate_failure_cannot_claim_that_no_reports_were_found(action):
    expression = action["outputs"]["verdict"]["value"]
    assert "steps.collect.outcome == 'success'" in expression
    assert "steps.collect.outputs.count == '0' && 'NO-REPORTS'" in expression
    assert expression.endswith("|| 'ERROR' }}")


@pytest.mark.parametrize(
    "event,provenance,failed_job,expected",
    [
        ("pull_request", "skipped", None, 0),
        ("push", "success", None, 0),
        ("push", "skipped", None, 1),
        ("pull_request", "success", None, 1),
        ("pull_request", "skipped", "test", 1),
        ("pull_request", "skipped", "action", 1),
        ("pull_request", "skipped", "build", 1),
        ("pull_request", "skipped", "security", 1),
        ("pull_request", "skipped", "self-check", 1),
    ],
)
def test_release_check_runs_its_real_assertions(event, provenance, failed_job, expected, tmp_path):
    workflow = yaml.safe_load(
        (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["release-checks"]
    assert job["if"] == "always()"
    assert job["name"] == "Release checks"
    body = job["steps"][0]["run"]
    script = body.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    results = {name: {"result": "success"} for name in job["needs"]}
    results["provenance"]["result"] = provenance
    if failed_job is not None:
        results[failed_job]["result"] = "cancelled"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={
            **os.environ,
            "RESULTS": json.dumps(results),
            "EVENT_NAME": event,
            "REF": "refs/heads/main",
        },
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == expected, result.stderr
