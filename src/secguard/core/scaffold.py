"""Project scaffold helpers for secguard starter files."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib.resources import files
from pathlib import Path
from typing import Literal

TEMPLATE_DIRECTORY = "templates"


class CiProvider(StrEnum):
    """Which CI starter workflow `secguard init` should create."""

    github = "github"
    gitlab = "gitlab"
    both = "both"
    none = "none"


InitAction = Literal[
    "created",
    "overwritten",
    "skipped",
    "would-create",
    "would-overwrite",
    "would-skip",
]


@dataclass(frozen=True)
class InitTemplate:
    """A packaged template and the local destination it should create."""

    source_name: str
    destination: Path


@dataclass(frozen=True)
class InitResult:
    """The result of one secguard initialization file operation."""

    destination: Path
    path: Path
    action: InitAction


class InitError(Exception):
    """Base class for secguard project initialization errors."""


class InitDestinationError(InitError):
    """Raised when the destination cannot safely receive starter files."""


class InitSafetyError(InitError):
    """Raised when initialization would write outside the intended tree."""


BASE_TEMPLATES: tuple[InitTemplate, ...] = (
    InitTemplate("waivers.yaml", Path(".secguard/waivers.yaml")),
    InitTemplate("pre-commit-config.yaml", Path(".pre-commit-config.yaml")),
)

GITHUB_TEMPLATE = InitTemplate(
    "github-actions-secguard.yml",
    Path(".github/workflows/secguard.yml"),
)

# GitLab keeps its pipeline in a single `.gitlab-ci.yml`, so secguard writes an
# includable snippet instead of clobbering the file a team already depends on.
GITLAB_TEMPLATE = InitTemplate(
    "gitlab-ci-secguard.yml",
    Path(".gitlab/secguard.gitlab-ci.yml"),
)

INIT_TEMPLATES: tuple[InitTemplate, ...] = (*BASE_TEMPLATES, GITHUB_TEMPLATE)


def templates_for(ci: CiProvider) -> tuple[InitTemplate, ...]:
    """Return the starter templates for a CI provider selection."""
    if ci is CiProvider.none:
        return BASE_TEMPLATES
    if ci is CiProvider.gitlab:
        return (*BASE_TEMPLATES, GITLAB_TEMPLATE)
    if ci is CiProvider.both:
        return (*BASE_TEMPLATES, GITHUB_TEMPLATE, GITLAB_TEMPLATE)
    return (*BASE_TEMPLATES, GITHUB_TEMPLATE)


def initialize_project(
    destination: Path,
    *,
    ci: CiProvider = CiProvider.github,
    dry_run: bool = False,
    force: bool = False,
) -> list[InitResult]:
    """Create secguard starter files in a destination directory."""
    resolved_destination = _resolve_destination(destination)
    results: list[InitResult] = []

    for template in templates_for(ci):
        _validate_template_destination(template.destination)
        target = resolved_destination / template.destination

        if dry_run:
            action = _planned_action(target, force=force)
        else:
            action = _write_template(
                resolved_destination,
                target,
                template.source_name,
                force=force,
            )

        results.append(
            InitResult(
                destination=template.destination,
                path=target,
                action=action,
            )
        )

    return results


def _resolve_destination(destination: Path) -> Path:
    resolved = destination.expanduser().resolve(strict=False)
    if resolved.exists() and not resolved.is_dir():
        raise InitDestinationError(f"destination is not a directory: {resolved}")
    return resolved


def _validate_template_destination(destination: Path) -> None:
    if destination.is_absolute() or ".." in destination.parts:
        raise InitSafetyError(f"unsafe template destination: {destination}")


def _planned_action(target: Path, *, force: bool) -> InitAction:
    if target.is_symlink():
        return "would-overwrite" if force else "would-skip"
    if target.exists():
        if target.is_dir():
            raise InitDestinationError(f"target path is a directory: {target}")
        return "would-overwrite" if force else "would-skip"
    return "would-create"


def _write_template(
    destination: Path,
    target: Path,
    source_name: str,
    *,
    force: bool,
) -> InitAction:
    if target.is_symlink():
        if force:
            raise InitSafetyError(f"refusing to overwrite symlink: {target}")
        return "skipped"

    if target.exists():
        if target.is_dir():
            raise InitDestinationError(f"target path is a directory: {target}")
        if not force:
            return "skipped"

        _assert_write_path_is_safe(destination, target)
        target.write_text(_read_template(source_name), encoding="utf-8", newline="\n")
        return "overwritten"

    _assert_write_path_is_safe(destination, target)
    _create_parent_directory(target.parent)

    try:
        with target.open("x", encoding="utf-8", newline="\n") as output:
            output.write(_read_template(source_name))
    except FileExistsError:
        return "skipped"

    return "created"


def _assert_write_path_is_safe(destination: Path, target: Path) -> None:
    relative_parent = target.parent.relative_to(destination)
    current = destination

    for part in relative_parent.parts:
        current /= part
        if current.exists() and current.is_symlink():
            raise InitSafetyError(f"refusing to write through symlinked directory: {current}")

    if target.is_symlink():
        raise InitSafetyError(f"refusing to overwrite symlink: {target}")


def _create_parent_directory(parent: Path) -> None:
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InitDestinationError(f"cannot create directory {parent}: {exc}") from exc


def _read_template(source_name: str) -> str:
    return files("secguard").joinpath(TEMPLATE_DIRECTORY, source_name).read_text(encoding="utf-8")
