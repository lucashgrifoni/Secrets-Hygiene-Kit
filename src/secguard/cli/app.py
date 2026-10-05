"""Typer application for the secguard command-line interface.

Exit codes are stable across commands so CI can rely on them:

- ``0`` the check passed
- ``1`` the check failed on purpose (expired waiver, blocking finding, stale playbook)
- ``2`` the input was missing, malformed, or rejected by policy
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import typer

from secguard import __version__
from secguard.core import report as report_renderer
from secguard.core.catalog import (
    LOCAL_CATALOG_PATH,
    CatalogError,
    RuleCatalog,
    load_catalog,
    severity_rank,
)
from secguard.core.detectors import SUPPORTED_FORMATS, is_empty_report, load_reports
from secguard.core.findings import FindingDocument, FindingError, load_synthetic_scan_file
from secguard.core.incident import render_incident
from secguard.core.playbooks import (
    DEFAULT_MAX_AGE_DAYS,
    PlaybookError,
    load_all,
    load_playbook,
    stale_playbooks,
)
from secguard.core.reconcile import EXIT_GATE_FAILED, FAIL_ON_CHOICES, ScanOutcome, reconcile
from secguard.core.redaction import sanitize_text
from secguard.core.sarif import build_sarif, waiver_summary
from secguard.core.scaffold import CiProvider, InitError, initialize_project
from secguard.core.waivers import (
    WaiverDocument,
    WaiverError,
    add_waiver,
    load_waiver_file,
    load_waiver_file_or_empty,
)
from secguard.core.writing import UnsafeWriteError, assert_writable

DEFAULT_WAIVER_FILE = Path(".secguard/waivers.yaml")
EXIT_INPUT_ERROR = 2

# The audited pre-commit bypass. Local prevention only; the CI gate ignores it.
OVERRIDE_ENV = "SECGUARD_OVERRIDE"
OVERRIDE_REASON_ENV = "SECGUARD_OVERRIDE_REASON"
MIN_OVERRIDE_REASON_LENGTH = 12

FAIL_ON_HELP = f"Blocking severity threshold: {', '.join(FAIL_ON_CHOICES)}."
RULES_HELP = (
    "Local rule catalog merged over the packaged one, conventionally "
    f"{LOCAL_CATALOG_PATH.as_posix()}. Never loaded implicitly: an override can "
    "lower a severity, so adopting one is the workflow author's decision."
)

app = typer.Typer(
    help=(
        "Secret hygiene kit: normalize detector reports, apply the waiver lifecycle, "
        "and print the response playbook. secguard never runs a scanner and never "
        "rotates or revokes a credential."
    ),
    no_args_is_help=True,
)
waivers_app = typer.Typer(
    help="Inspect, validate, and extend secguard waiver files.",
    no_args_is_help=True,
)
scan_app = typer.Typer(help="Normalize and gate scanner reports.", no_args_is_help=True)
playbooks_app = typer.Typer(help="Inspect packaged remediation playbooks.", no_args_is_help=True)
incident_app = typer.Typer(help="Start a guided leak response.", no_args_is_help=True)

app.add_typer(waivers_app, name="waivers")
app.add_typer(scan_app, name="scan")
app.add_typer(playbooks_app, name="playbooks")
app.add_typer(incident_app, name="incident")


def main() -> None:
    """Console script entry point."""
    use_utf8_output()
    # Windows Click expands globs in argv against the working directory before
    # parsing. `--path 'tests/fixtures/**'` would then be rewritten to whatever
    # happened to match: one hit becomes a literal directory the operator never
    # approved, several become "unexpected extra arguments". A waiver scope is a
    # pattern, not a file list, so argv is taken literally on every platform.
    app(windows_expand_args=False)


def use_utf8_output() -> None:
    """Write UTF-8 with LF line endings on every platform.

    A redirected stream on Windows defaults to the ANSI code page, so
    `secguard playbooks show generic-private-key > playbook.md` produced a file
    that is not valid UTF-8 — for a document a responder attaches to an incident
    record. Files written through `--output` were already UTF-8; this makes the
    redirect path agree with them.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        # A detached or already-wrapped stream cannot be reconfigured, and that
        # is not worth failing a scan over.
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------- helpers


def _fail(message: str, code: int = EXIT_INPUT_ERROR) -> typer.Exit:
    typer.secho(message, err=True, fg=typer.colors.RED)
    return typer.Exit(code=code)


def _note(message: str) -> None:
    typer.secho(message, err=True, fg=typer.colors.YELLOW)


def _parse_today(today: str | None) -> date:
    if today is None:
        return datetime.now(UTC).date()

    try:
        return date.fromisoformat(today)
    except ValueError as exc:
        raise typer.BadParameter("expected ISO date in YYYY-MM-DD format") from exc


def _parse_expiry(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise typer.BadParameter("expected ISO date in YYYY-MM-DD format") from exc


def _load_catalog(rules: Path | None) -> RuleCatalog:
    """Load the packaged catalog, merging a local override only when asked.

    A local catalog is never picked up implicitly. It lives inside the scanned
    checkout, and the packaged workflow runs on `pull_request`, so its content
    is supplied by whoever opened the pull request. A catalog can lower a
    severity, and a severity below the threshold is a finding that does not
    block — so auto-loading it would let one added file turn BLOCK into PASS,
    with none of the waiver lifecycle's owner, approver, or expiry.

    Requiring `--rules` keeps that decision with whoever wrote the workflow.
    """
    try:
        catalog = load_catalog(rules)
    except CatalogError as exc:
        raise _fail(str(exc)) from exc
    except OSError as exc:
        raise _fail(f"cannot access rule catalog: {exc.strerror or 'filesystem error'}") from exc

    if rules is not None:
        _warn_about_downgrades(catalog)
        _warn_about_missing_playbooks(catalog)

    return catalog


def _warn_about_missing_playbooks(catalog: RuleCatalog) -> None:
    """Name secret types whose playbook is not installed.

    The catalog validates that a playbook slug is well formed, not that it
    exists. A finding routed to a missing playbook still prints
    `secguard incident start --secret-type X` on the gate summary, and that
    command fails — mid-incident, which is the worst possible moment to
    discover a typo in a config file.
    """
    try:
        installed = {playbook.slug for playbook in load_all()}
    except PlaybookError:  # pragma: no cover - the playbooks check reports this properly
        return

    missing = sorted(
        {
            definition.playbook
            for definition in catalog.secret_types.values()
            if definition.playbook not in installed
        }
    )
    if missing:
        _note(
            f"the rule override routes to {len(missing)} playbook(s) that are not installed: "
            f"{', '.join(missing)}. `secguard incident start` will fail for those secret types."
        )


def _warn_about_downgrades(catalog: RuleCatalog) -> None:
    """Name every way an override lowers the severity a finding would actually get.

    An override is a legitimate feature, and lowering a severity is a legitimate
    use of it. What is not legitimate is doing so invisibly: the reviewer of a
    passing gate deserves to know the threshold was met by re-rating rather than
    by remediation.

    Comparing secret-type defaults alone was not enough, and the gap was the
    whole point of the warning. A catalog can lower what a rule resolves to in
    four ways, and three of them left that default untouched: a per-rule
    `severity:`, a remap to a different secret type that happens to be milder,
    and a remap to a brand-new mild type. Each one flipped BLOCK to PASS in
    silence. So the comparison runs on the *resolved* classification of every
    detector rule either catalog knows.
    """
    packaged = load_catalog()
    lowered: set[str] = set()

    before_fallback = packaged.secret_types[packaged.fallback_secret_type]
    after_fallback = catalog.secret_types[catalog.fallback_secret_type]
    if severity_rank(after_fallback.severity) < severity_rank(before_fallback.severity):
        lowered.add(f"fallback {before_fallback.severity}->{after_fallback.severity}")

    for scanner in set(packaged.detectors) | set(catalog.detectors):
        rules = set(packaged.detectors.get(scanner, {})) | set(catalog.detectors.get(scanner, {}))
        for rule_id in rules:
            before = packaged.classify(scanner, rule_id)
            after = catalog.classify(scanner, rule_id)
            if severity_rank(after.severity) < severity_rank(before.severity):
                lowered.add(
                    f"{scanner}:{rule_id} {before.severity}->{after.severity}"
                    + (
                        f" (now {after.secret_type})"
                        if after.secret_type != before.secret_type
                        else ""
                    )
                )

    # A secret type nothing currently maps to can still be lowered, and a rule
    # added later would inherit it.
    for name, definition in catalog.secret_types.items():
        packaged_definition = packaged.secret_types.get(name)
        if packaged_definition and severity_rank(definition.severity) < severity_rank(
            packaged_definition.severity
        ):
            lowered.add(f"{name} {packaged_definition.severity}->{definition.severity}")

    if lowered:
        _note(
            f"the rule override lowers {len(lowered)} severity value(s): "
            + ", ".join(sorted(lowered))
        )


def _audited_override(allow: bool, *, bypassing: str) -> bool:
    """Return whether an audited local bypass applies, failing if it is unjustified.

    The spec's prevention layer needs an escape hatch a developer can reach at
    2am without deleting the hook, but an unexplained bypass is indistinguishable
    from a broken check. So the reason is mandatory, the finding is still printed
    before the bypass is granted, and the record names who allowed what.

    Only commands that opt in with `--allow-override` consult this, and only the
    packaged pre-commit hooks pass that flag. `scan check` never does: a CI gate
    an environment variable can switch off is not a gate.
    """
    if not allow or os.environ.get(OVERRIDE_ENV) != "1":
        return False

    reason = sanitize_text(os.environ.get(OVERRIDE_REASON_ENV, ""), max_length=200)
    if len(reason) < MIN_OVERRIDE_REASON_LENGTH:
        raise _fail(
            f"{OVERRIDE_ENV}=1 needs {OVERRIDE_REASON_ENV} set to at least "
            f"{MIN_OVERRIDE_REASON_LENGTH} characters explaining why this commit "
            "cannot wait for the check to pass"
        )

    _note(
        f"OVERRIDE: {bypassing} was bypassed on "
        f"{datetime.now(UTC).date().isoformat()} because: {reason}"
    )
    _note("Record this in the commit message. The check still fails in CI.")
    return True


def _load_waivers(file: Path, *, required: bool) -> WaiverDocument:
    try:
        if required:
            return load_waiver_file(file)
        if not file.exists():
            _note(f"no waiver file at {file.as_posix()}; continuing with zero waivers")
        return load_waiver_file_or_empty(file)
    except WaiverError as exc:
        raise _fail(str(exc)) from exc
    except OSError as exc:
        raise _fail(f"cannot access waiver file: {exc.strerror or 'filesystem error'}") from exc


def _load_findings(
    inputs: list[Path],
    report_format: str,
    catalog: RuleCatalog,
) -> FindingDocument:
    empty = [path for path in inputs if is_empty_report(path)]
    for path in empty:
        _note(
            f"{path.as_posix()} is empty; treating it as zero findings. "
            "A detector that failed to run leaves the same file behind."
        )

    # One empty report is normal: a clean trufflehog run writes JSON Lines with
    # no lines. Every report empty is still legitimate for a trufflehog-only
    # setup, so it cannot fail the run, but it is also what a whole detector
    # stage that never executed looks like — and that deserves more than one
    # line among several.
    if empty and len(empty) == len(inputs):
        _note(
            f"every one of the {len(inputs)} report(s) was empty, so nothing was actually "
            "examined. That is expected only if every detector you ran found nothing and "
            "writes JSON Lines. Confirm the detector step ran and wrote where you think."
        )

    try:
        return load_reports(inputs, report_format=report_format, catalog=catalog)  # type: ignore[arg-type]
    except FindingError as exc:
        raise _fail(str(exc)) from exc
    except OSError as exc:
        raise _fail(f"cannot access scanner report: {exc.strerror or 'filesystem error'}") from exc


def _write_output(path: Path, content: str) -> None:
    try:
        assert_writable(path)
    except UnsafeWriteError as exc:
        raise _fail(str(exc)) from exc
    except OSError as exc:
        raise _fail(
            f"cannot write {path.as_posix()}: {exc.strerror or 'filesystem error'}"
        ) from exc

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise _fail(f"cannot write {path.as_posix()}: {exc}") from exc

    typer.echo(f"wrote\t{path.as_posix()}", err=True)


def _require_inputs(inputs: list[Path] | None) -> list[Path]:
    if not inputs:
        raise _fail(
            "at least one --input scanner report is required; "
            f"supported formats: {', '.join(SUPPORTED_FORMATS)}"
        )
    return inputs


def _dump_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


# --------------------------------------------------------------------------- top level


@app.command("version")
def show_version() -> None:
    """Print the secguard version."""
    typer.echo(__version__)


@app.command("init")
def init_project(
    destination: Annotated[
        Path,
        typer.Argument(help="Directory that will receive secguard starter files."),
    ] = Path("."),
    ci: Annotated[
        CiProvider,
        typer.Option("--ci", help="Which CI starter workflow to create."),
    ] = CiProvider.github,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show planned file actions without writing anything."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite existing secguard starter files."),
    ] = False,
) -> None:
    """Create local secguard waiver, pre-commit, and CI starter files."""
    try:
        results = initialize_project(destination, ci=ci, dry_run=dry_run, force=force)
    except InitError as exc:
        raise _fail(str(exc)) from exc
    except OSError as exc:
        raise _fail(
            f"cannot access scaffold destination: {exc.strerror or 'filesystem error'}"
        ) from exc

    for result in results:
        typer.echo(f"{result.action}\t{result.destination.as_posix()}")


@app.command("report")
def render_report_command(
    inputs: Annotated[
        list[Path] | None,
        typer.Option("--input", "-i", help="Scanner report file. Repeat to merge reports."),
    ] = None,
    report_format: Annotated[
        str,
        typer.Option("--format", help="Report format, or `auto` to infer it from structure."),
    ] = "auto",
    waiver_file: Annotated[
        Path,
        typer.Option("--waivers", help="Waiver file used to mark findings as accepted."),
    ] = DEFAULT_WAIVER_FILE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write Markdown here instead of stdout."),
    ] = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", help=RULES_HELP),
    ] = None,
    today: Annotated[
        str | None,
        typer.Option("--today", help="Override the current date for deterministic output."),
    ] = None,
) -> None:
    """Render a Markdown scan report without failing the build."""
    resolved_inputs = _require_inputs(inputs)
    catalog = _load_catalog(rules)
    check_date = _parse_today(today)

    outcome = reconcile(
        _load_findings(resolved_inputs, report_format, catalog),
        _load_waivers(waiver_file, required=False),
        today=check_date,
        fail_on="none",
    )
    markdown = report_renderer.render_report(outcome, generated_on=check_date, version=__version__)

    if output is None:
        typer.echo(markdown, nl=False)
    else:
        _write_output(output, markdown)


# --------------------------------------------------------------------------- scan


@scan_app.command("check")
def scan_check(
    inputs: Annotated[
        list[Path] | None,
        typer.Option("--input", "-i", help="Scanner report file. Repeat to merge reports."),
    ] = None,
    report_format: Annotated[
        str,
        typer.Option("--format", help="Report format, or `auto` to infer it from structure."),
    ] = "auto",
    waiver_file: Annotated[
        Path,
        typer.Option("--waivers", help="Waiver file applied to the findings."),
    ] = DEFAULT_WAIVER_FILE,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help=FAIL_ON_HELP),
    ] = "high",
    json_output: Annotated[
        Path | None,
        typer.Option("--json", help="Write the canonical finding document here."),
    ] = None,
    sarif_output: Annotated[
        Path | None,
        typer.Option("--sarif", help="Write a SARIF 2.1.0 log here."),
    ] = None,
    markdown_output: Annotated[
        Path | None,
        typer.Option("--markdown", help="Write the full Markdown report here."),
    ] = None,
    comment_output: Annotated[
        Path | None,
        typer.Option("--pr-comment", help="Write a compact pull-request comment here."),
    ] = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", help=RULES_HELP),
    ] = None,
    today: Annotated[
        str | None,
        typer.Option("--today", help="Override the current date for deterministic checks."),
    ] = None,
) -> None:
    """Reconcile scanner reports against waivers and fail when the gate blocks."""
    if fail_on not in FAIL_ON_CHOICES:
        raise typer.BadParameter(f"--fail-on must be one of: {', '.join(FAIL_ON_CHOICES)}")

    resolved_inputs = _require_inputs(inputs)
    catalog = _load_catalog(rules)
    check_date = _parse_today(today)

    outcome = reconcile(
        _load_findings(resolved_inputs, report_format, catalog),
        _load_waivers(waiver_file, required=False),
        today=check_date,
        fail_on=fail_on,
    )

    if json_output is not None:
        _write_output(
            json_output,
            _dump_json(outcome.document().model_dump(mode="json", by_alias=True)),
        )
    if sarif_output is not None:
        _write_output(
            sarif_output,
            _dump_json(build_sarif(outcome, catalog=catalog, version=__version__)),
        )
    if markdown_output is not None:
        _write_output(
            markdown_output,
            report_renderer.render_report(outcome, generated_on=check_date, version=__version__),
        )
    if comment_output is not None:
        _write_output(
            comment_output,
            report_renderer.render_pr_comment(outcome, generated_on=check_date),
        )

    _print_scan_summary(outcome, check_date)

    if outcome.failed:
        raise typer.Exit(code=EXIT_GATE_FAILED)


def _print_scan_summary(outcome: ScanOutcome, check_date: date) -> None:
    typer.echo(
        f"{len(outcome.results)} finding(s): {len(outcome.active)} active, "
        f"{len(outcome.waived)} waived, threshold={outcome.fail_on}, "
        f"date={check_date.isoformat()}"
    )

    for result in outcome.active:
        finding = result.finding
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        suffix = f" expired-waiver={result.expired_waiver_id}" if result.expired_waiver_id else ""
        verified = " verified=live" if finding.verified else ""
        # A merged finding shows every rule that contributed, because a waiver
        # has to cover all of them before it suppresses anything.
        also = (
            f"\talso={','.join(finding.corroborated_rules)}" if finding.corroborated_rules else ""
        )
        # A guessed classification has to look different from a confident one
        # here, not only in the JSON. This line is what a responder reads first.
        mapping = "\tmapping=fallback" if finding.mapping == "fallback" else ""
        typer.echo(
            f"- {finding.severity}\t{finding.secret_type}\t{location}\t"
            f"rule={finding.rule}{also}\tplaybook={finding.playbook}{mapping}{verified}{suffix}"
        )

    for waiver in outcome.expired_waivers:
        typer.echo(f"- expired-waiver\t{waiver_summary(waiver)}")

    narrowed = {waiver.id for waiver in outcome.narrowed_waivers}
    for waiver in outcome.unused_waivers:
        reason = (
            "\tcovers only one detector of a finding several reported; widen it to secret-type:"
            if waiver.id in narrowed
            else ""
        )
        typer.echo(f"- unused-waiver\t{waiver.id} rule={waiver.rule} path={waiver.path}{reason}")

    unused_ids = {waiver.id for waiver in outcome.unused_waivers}
    for waiver in outcome.narrowed_waivers:
        if waiver.id not in unused_ids:
            typer.echo(
                f"- partial-waiver\t{waiver.id} rule={waiver.rule} path={waiver.path}"
                "\tcovers only part of a corroborated finding; review secret-type: scope"
            )

    if outcome.failed:
        reasons = []
        if outcome.blocking:
            reasons.append(f"{len(outcome.blocking)} finding(s) at or above {outcome.fail_on}")
        if outcome.expired_waivers:
            reasons.append(f"{len(outcome.expired_waivers)} expired waiver(s)")
        typer.secho(f"BLOCK: {'; '.join(reasons)}", fg=typer.colors.RED)
    else:
        typer.secho("PASS: no blocking finding and no expired waiver.", fg=typer.colors.GREEN)


@scan_app.command("normalize")
def normalize_scan(
    input_file: Annotated[
        Path,
        typer.Option("--input", "-i", help="Path to a scanner findings file."),
    ],
    report_format: Annotated[
        str,
        typer.Option("--format", help="Report format, or `auto` to infer it from structure."),
    ] = "auto",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write canonical JSON here instead of stdout."),
    ] = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", help=RULES_HELP),
    ] = None,
) -> None:
    """Normalize one scanner report into the canonical secguard finding schema."""
    catalog = _load_catalog(rules)
    document = _load_findings([input_file], report_format, catalog)
    payload = _dump_json(document.model_dump(mode="json", by_alias=True))

    if output is None:
        typer.echo(payload, nl=False)
    else:
        _write_output(output, payload)


# --------------------------------------------------------------------------- waivers


@waivers_app.command("check")
def check_waivers(
    file: Annotated[
        Path,
        typer.Option("--file", "-f", help="Path to a secguard waiver YAML file."),
    ] = DEFAULT_WAIVER_FILE,
    today: Annotated[
        str | None,
        typer.Option("--today", help="Override current date for deterministic checks."),
    ] = None,
    allow_override: Annotated[
        bool,
        typer.Option(
            "--allow-override",
            help=(
                f"Honor an audited local bypass: {OVERRIDE_ENV}=1 plus "
                f"{OVERRIDE_REASON_ENV}. For pre-commit only; never pass this in CI."
            ),
        ),
    ] = False,
) -> None:
    """Fail when any waiver is expired."""
    document = _load_waivers(file, required=True)
    check_date = _parse_today(today)
    expired = document.expired(check_date)

    if expired:
        typer.echo(f"{len(expired)} expired waiver(s) found as of {check_date.isoformat()}:")
        for waiver in expired:
            typer.echo(
                f"- {waiver.id} rule={waiver.rule} path={waiver.path} "
                f"expires_at={waiver.expires_at.isoformat()} owner={waiver.owner}"
            )
        # Printed first, then bypassed: a developer who overrides still sees
        # exactly what they are carrying past the hook.
        if _audited_override(allow_override, bypassing="the waiver expiry check"):
            return
        raise typer.Exit(code=EXIT_GATE_FAILED)

    typer.echo(f"All {len(document.waivers)} waiver(s) are active as of {check_date.isoformat()}.")


@waivers_app.command("list")
def list_waivers(
    file: Annotated[
        Path,
        typer.Option("--file", "-f", help="Path to a secguard waiver YAML file."),
    ] = DEFAULT_WAIVER_FILE,
    today: Annotated[
        str | None,
        typer.Option("--today", help="Override current date for deterministic status output."),
    ] = None,
) -> None:
    """List waiver metadata without printing detector match values."""
    document = _load_waivers(file, required=True)
    check_date = _parse_today(today)

    if not document.waivers:
        typer.echo("No waivers defined.")
        return

    for waiver in document.waivers:
        status = "expired" if waiver.is_expired(check_date) else "active"
        typer.echo(
            f"{waiver.id}\t{status}\t{waiver.rule}\t{waiver.path}\t"
            f"expires_at={waiver.expires_at.isoformat()}\towner={waiver.owner}"
        )


@waivers_app.command("add")
def add_waiver_command(
    rule: Annotated[
        str,
        typer.Option("--rule", help="Rule pattern, e.g. gitleaks:aws-access-token or gitleaks:*."),
    ],
    scope_path: Annotated[
        str,
        typer.Option("--path", help="Repository path or glob covered by the waiver."),
    ],
    reason: Annotated[
        str,
        typer.Option("--reason", help="Why the match is accepted. Never include the secret."),
    ],
    owner: Annotated[str, typer.Option("--owner", help="Accountable person or team.")],
    approver: Annotated[str, typer.Option("--approver", help="Who approved the exception.")],
    expires: Annotated[str, typer.Option("--expires", help="Expiry date in YYYY-MM-DD.")],
    file: Annotated[
        Path,
        typer.Option("--file", "-f", help="Waiver file to append to."),
    ] = DEFAULT_WAIVER_FILE,
    waiver_id: Annotated[
        str | None,
        typer.Option("--id", help="Explicit waiver id; generated sequentially when omitted."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Validate without writing the file."),
    ] = False,
    today: Annotated[
        str | None,
        typer.Option("--today", help="Override current date for deterministic checks."),
    ] = None,
) -> None:
    """Append a validated, time-bound waiver to the waiver file."""
    try:
        waiver, warnings = add_waiver(
            file,
            rule=rule,
            scope_path=scope_path,
            reason=reason,
            owner=owner,
            approver=approver,
            expires_at=_parse_expiry(expires),
            today=_parse_today(today),
            waiver_id=waiver_id,
            dry_run=dry_run,
        )
    except WaiverError as exc:
        raise _fail(str(exc)) from exc
    except OSError as exc:
        raise _fail(f"cannot write waiver file: {exc.strerror or 'filesystem error'}") from exc

    for warning in warnings:
        _note(f"warning: {warning}")

    action = "would-add" if dry_run else "added"
    typer.echo(
        f"{action}\t{waiver.id}\trule={waiver.rule}\tpath={waiver.path}\t"
        f"expires_at={waiver.expires_at.isoformat()}"
    )


# --------------------------------------------------------------------------- playbooks


@playbooks_app.command("list")
def list_playbooks(
    today: Annotated[
        str | None,
        typer.Option("--today", help="Override current date for freshness output."),
    ] = None,
    max_age_days: Annotated[
        int,
        typer.Option("--max-age-days", help="Review window before a playbook counts as stale."),
    ] = DEFAULT_MAX_AGE_DAYS,
) -> None:
    """List packaged playbooks with their vetted date and freshness."""
    check_date = _parse_today(today)

    for playbook in _load_playbooks():
        typer.echo(
            f"{playbook.slug}\t{playbook.freshness(check_date, max_age_days)}\t"
            f"vetted={playbook.vetted.isoformat()}\tage_days={playbook.age_days(check_date)}\t"
            f"{playbook.title}"
        )


@playbooks_app.command("show")
def show_playbook(
    slug: Annotated[str, typer.Argument(help="Playbook slug, e.g. aws-access-key.")],
) -> None:
    """Print one playbook."""
    try:
        playbook = load_playbook(slug)
    except PlaybookError as exc:
        raise _fail(str(exc)) from exc

    typer.echo(playbook.body)


@playbooks_app.command("check")
def check_playbooks(
    today: Annotated[
        str | None,
        typer.Option("--today", help="Override current date for deterministic checks."),
    ] = None,
    max_age_days: Annotated[
        int,
        typer.Option("--max-age-days", help="Review window before a playbook counts as stale."),
    ] = DEFAULT_MAX_AGE_DAYS,
    allow_override: Annotated[
        bool,
        typer.Option(
            "--allow-override",
            help=(
                f"Honor an audited local bypass: {OVERRIDE_ENV}=1 plus "
                f"{OVERRIDE_REASON_ENV}. For pre-commit only; never pass this in CI."
            ),
        ),
    ] = False,
) -> None:
    """Fail when a playbook has not been vetted inside the review window."""
    check_date = _parse_today(today)
    playbooks = _load_playbooks()
    stale = stale_playbooks(playbooks, today=check_date, max_age_days=max_age_days)

    if stale:
        typer.echo(
            f"{len(stale)} playbook(s) exceeded the {max_age_days}-day review window "
            f"as of {check_date.isoformat()}:"
        )
        for playbook in stale:
            typer.echo(
                f"- {playbook.slug} vetted={playbook.vetted.isoformat()} "
                f"age_days={playbook.age_days(check_date)}"
            )
        if _audited_override(allow_override, bypassing="the playbook freshness check"):
            return
        raise typer.Exit(code=EXIT_GATE_FAILED)

    typer.echo(
        f"All {len(playbooks)} playbook(s) were vetted within {max_age_days} days "
        f"as of {check_date.isoformat()}."
    )


def _load_playbooks():  # noqa: ANN202 - thin wrapper around the loader
    try:
        return load_all()
    except PlaybookError as exc:
        raise _fail(str(exc)) from exc


# --------------------------------------------------------------------------- incident


@incident_app.command("start")
def start_incident(
    secret_type: Annotated[
        str | None,
        typer.Option("--secret-type", help="Canonical secret type, e.g. aws-access-key."),
    ] = None,
    playbook_slug: Annotated[
        str | None,
        typer.Option("--playbook", help="Playbook slug when it differs from the secret type."),
    ] = None,
    leaked_via: Annotated[
        str | None,
        typer.Option("--leaked-via", help="Where the exposure happened, e.g. github-issue."),
    ] = None,
    reference: Annotated[
        str | None,
        typer.Option("--reference", help="Ticket, incident id, or finding id for traceability."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the checklist here instead of stdout."),
    ] = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", help=RULES_HELP),
    ] = None,
    max_age_days: Annotated[
        int,
        typer.Option("--max-age-days", help="Review window before a playbook counts as stale."),
    ] = DEFAULT_MAX_AGE_DAYS,
    today: Annotated[
        str | None,
        typer.Option("--today", help="Override the incident open date."),
    ] = None,
) -> None:
    """Print a tickable response checklist for one secret type."""
    if secret_type is None and playbook_slug is None:
        raise _fail("provide --secret-type or --playbook")

    catalog = _load_catalog(rules)
    resolved_slug = playbook_slug

    if resolved_slug is None and secret_type is not None:
        resolved_slug = catalog.playbook_for(secret_type)
        if resolved_slug is None:
            known = ", ".join(sorted(catalog.secret_types))
            raise _fail(f"unknown secret type: {secret_type}; known secret types: {known}")

    try:
        playbook = load_playbook(resolved_slug or "")
    except PlaybookError as exc:
        raise _fail(str(exc)) from exc

    checklist = render_incident(
        playbook,
        secret_type=secret_type or playbook.slug,
        opened_on=_parse_today(today),
        leaked_via=leaked_via,
        reference=reference,
        max_age_days=max_age_days,
    )

    if output is None:
        typer.echo(checklist, nl=False)
    else:
        _write_output(output, checklist)


__all__ = ["app", "load_synthetic_scan_file", "main", "use_utf8_output"]
