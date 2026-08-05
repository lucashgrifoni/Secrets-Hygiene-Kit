from pathlib import Path

from secguard.core.scaffold import initialize_project


def _actions_by_destination(tmp_path: Path, *, dry_run: bool = False, force: bool = False):
    results = initialize_project(tmp_path, dry_run=dry_run, force=force)
    return {result.destination.as_posix(): result.action for result in results}


def test_initialize_project_creates_expected_files(tmp_path):
    actions = _actions_by_destination(tmp_path)

    waiver_file = tmp_path / ".secguard" / "waivers.yaml"
    pre_commit_file = tmp_path / ".pre-commit-config.yaml"
    workflow_file = tmp_path / ".github" / "workflows" / "secguard.yml"

    assert actions == {
        ".secguard/waivers.yaml": "created",
        ".pre-commit-config.yaml": "created",
        ".github/workflows/secguard.yml": "created",
    }
    assert 'schema: "secguard.waiver/v1"' in waiver_file.read_text(encoding="utf-8")
    assert "waivers: []" in waiver_file.read_text(encoding="utf-8")
    assert "secguard waivers check" in pre_commit_file.read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow_file.read_text(encoding="utf-8")


def _active_yaml(workflow: str) -> str:
    """Drop comment lines so assertions test what the workflow actually runs."""
    return "\n".join(line for line in workflow.splitlines() if not line.lstrip().startswith("#"))


def _workflow(tmp_path: Path) -> str:
    initialize_project(tmp_path)
    return (tmp_path / ".github" / "workflows" / "secguard.yml").read_text(encoding="utf-8")


def test_generated_workflow_never_executes_a_scanner(tmp_path):
    """secguard reads reports. A starter workflow that silently ran a detector
    would pull an unpinned third-party binary into the user's pipeline."""
    workflow = _workflow(tmp_path)
    active = _active_yaml(workflow)

    assert "gitleaks detect" not in active
    assert "trufflehog git" not in active
    # gitleaks is still named, as a report file the gate reads and as commented guidance.
    assert "gitleaks.json" in active
    assert "gitleaks detect" in workflow


def test_generated_workflow_grants_only_read_permission(tmp_path):
    workflow = _workflow(tmp_path)
    active = _active_yaml(workflow)

    assert "permissions:\n  contents: read" in active
    assert "security-events: write" not in active
    assert "persist-credentials: false" in active


def test_initialize_project_dry_run_does_not_write_files(tmp_path):
    actions = _actions_by_destination(tmp_path, dry_run=True)

    assert actions == {
        ".secguard/waivers.yaml": "would-create",
        ".pre-commit-config.yaml": "would-create",
        ".github/workflows/secguard.yml": "would-create",
    }
    assert not (tmp_path / ".secguard").exists()
    assert not (tmp_path / ".pre-commit-config.yaml").exists()
    assert not (tmp_path / ".github").exists()


def test_initialize_project_skips_existing_files_without_force(tmp_path):
    pre_commit_file = tmp_path / ".pre-commit-config.yaml"
    pre_commit_file.write_text("existing config\n", encoding="utf-8")

    actions = _actions_by_destination(tmp_path)

    assert actions[".pre-commit-config.yaml"] == "skipped"
    assert pre_commit_file.read_text(encoding="utf-8") == "existing config\n"
    assert (tmp_path / ".secguard" / "waivers.yaml").exists()
    assert (tmp_path / ".github" / "workflows" / "secguard.yml").exists()


def test_initialize_project_force_overwrites_existing_files(tmp_path):
    pre_commit_file = tmp_path / ".pre-commit-config.yaml"
    pre_commit_file.write_text("existing config\n", encoding="utf-8")

    actions = _actions_by_destination(tmp_path, force=True)

    assert actions[".pre-commit-config.yaml"] == "overwritten"
    assert "secguard waivers check" in pre_commit_file.read_text(encoding="utf-8")
