"""Publisher trust boundaries and HTTP behavior, using an owned loopback server."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import threading
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
import yaml

from scripts import post_pr_comment as publisher

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "owner/tool"
SHA = "a" * 40
TOKEN = "TEST-PUBLISHER-TOKEN-NOT-A-CREDENTIAL"
BOT = {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"}
ISSUE_URL = f"https://api.github.com/repos/{REPOSITORY}/issues/4"
MARKER = "<!-- secguard:pr-comment:secguard:v1 -->"


def pull_request() -> dict:
    return {
        "number": 4,
        "state": "open",
        "base": {"repo": {"full_name": REPOSITORY}},
        "head": {"repo": {"full_name": REPOSITORY}, "sha": SHA},
    }


def comment(identifier: int, body: str, user: dict | None = None) -> dict:
    return {"id": identifier, "body": body, "user": user or BOT, "issue_url": ISSUE_URL}


def summary_text(verdict: str = "BLOCK") -> str:
    return (
        f"### secguard: {verdict}\n\n"
        "2 active finding(s), 1 waived, threshold `high` (checked 2026-10-05).\n\n"
        "Blocking findings:\n- TOP-SECRET-PATH/SECGUARD-CANARY\n"
        "[malicious](https://attacker.invalid/SECGUARD-CANARY)\n"
        "$(touch PWNED)\n@everyone\n<!-- secguard:pr-comment:hijack:v1 -->\n"
    )


@pytest.fixture
def environment(tmp_path):
    event = {"number": 4, "repository": {"full_name": REPOSITORY}, "pull_request": pull_request()}
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(event), encoding="utf-8")
    report = tmp_path / "comment.md"
    report.write_text(summary_text(), encoding="utf-8")
    return {
        "SECGUARD_PUBLISH_COMMENT": "true",
        "SECGUARD_EXPECTED_REPOSITORY": REPOSITORY,
        "SECGUARD_VERDICT": "BLOCK",
        "SECGUARD_REPORTS_FOUND": "1",
        "SECGUARD_COMMENT_FILE": str(report),
        "SECGUARD_TOKEN": TOKEN,
        "SECGUARD_PR_NUMBER": "4",
        "SECGUARD_PR_HEAD_SHA": SHA,
        "SECGUARD_PR_HEAD_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event_file),
        "GITHUB_RUN_ID": "1234",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_NUMBER": "8",
        "GITHUB_WORKFLOW_REF": "owner/tool/.github/workflows/ci.yml@refs/pull/4/merge",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_OUTPUT": str(tmp_path / "outputs.txt"),
    }


class FakeGitHub:
    def __init__(self):
        self.pr = pull_request()
        self.author = copy.deepcopy(BOT)
        self.comments = []
        self.requests = []
        self.overrides = {}
        self.next_id = 101
        self.endpoint = ""

    @property
    def writes(self):
        return [request for request in self.requests if request["method"] in {"POST", "PATCH"}]

    def respond(self, method, path, query, payload):
        if override := self.overrides.get((method, path)):
            return override
        if method == "GET" and path == f"/repos/{REPOSITORY}/pulls/4":
            return 200, self.pr, {}
        if method == "GET" and path == "/users/github-actions[bot]":
            return 200, self.author, {}
        if path == f"/repos/{REPOSITORY}/issues/4/comments":
            if method == "GET":
                page = int(query["page"][0])
                size = int(query["per_page"][0])
                return 200, self.comments[(page - 1) * size : page * size], {}
            if method == "POST":
                created = comment(self.next_id, payload["body"])
                self.next_id += 1
                self.comments.append(created)
                return 201, created, {}
        if method == "PATCH" and path.startswith(f"/repos/{REPOSITORY}/issues/comments/"):
            identifier = int(path.rsplit("/", 1)[1])
            target = next(item for item in self.comments if item["id"] == identifier)
            target["body"] = payload["body"]
            return 200, target, {}
        return 404, {"message": "not found"}, {}


@contextmanager
def http_server(fake):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def process(self):
            parsed = urlsplit(self.path)
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            payload = json.loads(raw) if raw else None
            path = unquote(parsed.path)
            fake.requests.append(
                {
                    "method": self.command,
                    "path": path,
                    "payload": payload,
                    "headers": dict(self.headers),
                }
            )
            status, body, headers = fake.respond(
                self.command, path, parse_qs(parsed.query), payload
            )
            encoded = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", headers.pop("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(encoded)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(encoded)

        do_GET = process
        do_POST = process
        do_PATCH = process

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    fake.endpoint = f"http://127.0.0.1:{server.server_port}"
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def api_server():
    with http_server(FakeGitHub()) as server:
        yield server


def install_api(monkeypatch, server):
    original = publisher.GitHubAPI
    client = original(publisher.Endpoints(server.endpoint, "https://github.com"), TOKEN)
    monkeypatch.setattr(
        publisher,
        "GitHubAPI",
        lambda endpoints, token: original(
            publisher.Endpoints(server.endpoint, endpoints.server), token
        ),
    )
    return client


def output_values(environment):
    file = Path(environment["GITHUB_OUTPUT"])
    return dict(line.split("=", 1) for line in file.read_text(encoding="utf-8").splitlines())


def test_create_then_repeat_then_update_uses_one_owned_comment(
    environment, api_server, monkeypatch
):
    install_api(monkeypatch, api_server)
    assert publisher.main(environment) == 0
    assert output_values(environment) == {"status": "created", "comment-id": "101"}
    body = api_server.comments[0]["body"]
    assert "### secguard: BLOCK" in body
    assert "2 active finding(s), 1 waived" in body
    assert "https://github.com/owner/tool/actions/runs/1234/attempts/1" in body
    for forbidden in (
        "SECGUARD-CANARY",
        "TOP-SECRET-PATH",
        "attacker.invalid",
        "$(",
        "@everyone",
        TOKEN,
    ):
        assert forbidden not in body
    assert publisher.main(environment) == 0
    assert output_values(environment)["status"] == "unchanged"
    assert len(api_server.writes) == 1
    Path(environment["SECGUARD_COMMENT_FILE"]).write_text(summary_text("PASS"), encoding="utf-8")
    environment["SECGUARD_VERDICT"] = "PASS"
    assert publisher.main(environment) == 0
    assert output_values(environment)["status"] == "updated"
    assert [request["method"] for request in api_server.writes] == ["POST", "PATCH"]
    assert len(api_server.comments) == 1
    for request in api_server.requests:
        assert request["headers"]["Authorization"] == f"Bearer {TOKEN}"
        assert request["headers"]["X-Github-Api-Version"] == publisher.API_VERSION


def test_publication_does_not_change_block_verdict(environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    assert publisher.main(environment) == 0
    assert environment["SECGUARD_VERDICT"] == "BLOCK"
    assert "verdict" not in output_values(environment)


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_EVENT_NAME", "pull_request_target"),
        ("GITHUB_EVENT_NAME", "push"),
        ("SECGUARD_EXPECTED_REPOSITORY", "attacker/tool"),
        ("SECGUARD_EXPECTED_REPOSITORY", "owner/tool\nPWNED"),
        ("GITHUB_REPOSITORY", "owner/tool/../../other"),
        ("SECGUARD_PR_NUMBER", "5"),
        ("SECGUARD_PR_HEAD_SHA", "b" * 40),
        ("SECGUARD_PR_HEAD_REPOSITORY", "attacker/tool"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ATTEMPT", "1\nstatus=created"),
        ("SECGUARD_COMMENT_MARKER", "x --> @everyone"),
        ("SECGUARD_COMMENT_AUTHOR", "human-user"),
        ("SECGUARD_TOKEN", ""),
        ("SECGUARD_TOKEN", "token\nAuthorization: injected"),
        ("SECGUARD_PUBLISH_COMMENT", "TRUE"),
        ("SECGUARD_REPORTS_FOUND", "0"),
        ("GITHUB_API_URL", "https://attacker.invalid"),
    ],
)
def test_bad_environment_never_writes(field, value, environment, api_server, monkeypatch, capsys):
    install_api(monkeypatch, api_server)
    environment[field] = value
    assert publisher.main(environment) == 1
    assert api_server.writes == []
    logs = capsys.readouterr()
    assert TOKEN not in logs.err + logs.out
    assert value not in logs.err if len(value) > 30 else True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda event: event["pull_request"]["head"]["repo"].update(full_name="fork/tool"),
        lambda event: event["pull_request"]["base"]["repo"].update(full_name="fork/tool"),
        lambda event: event["pull_request"].update(state="closed"),
        lambda event: event["pull_request"].update(number=5),
        lambda event: event["pull_request"]["head"].update(sha="b" * 40),
        lambda event: event["pull_request"]["head"].update(repo=None),
        lambda event: event.update(number=True),
        lambda event: event["repository"].update(full_name=[]),
    ],
)
def test_event_forgery_never_writes(mutate, environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    event_path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(event_path.read_text(encoding="utf-8"))
    mutate(event)
    event_path.write_text(json.dumps(event), encoding="utf-8")
    assert publisher.main(environment) == 1
    assert api_server.requests == []


@pytest.mark.parametrize("path_kind", ["summary", "event"])
def test_oversize_or_malformed_input_never_contacts_api(
    path_kind, environment, api_server, monkeypatch
):
    install_api(monkeypatch, api_server)
    key = "SECGUARD_COMMENT_FILE" if path_kind == "summary" else "GITHUB_EVENT_PATH"
    maximum = publisher.MAX_FILE_BYTES if path_kind == "summary" else publisher.MAX_EVENT_BYTES
    Path(environment[key]).write_bytes(b"x" * (maximum + 1))
    assert publisher.main(environment) == 1
    assert api_server.requests == []
    Path(environment[key]).write_bytes(b"\xff\x00")
    assert publisher.main(environment) == 1
    assert api_server.requests == []


@pytest.mark.parametrize(
    "text",
    [
        summary_text("PASS"),
        summary_text().replace("2026-10-05", "2026-02-30"),
        summary_text().replace("2026-10-05).", "2026-10-05). SECRET"),
        summary_text().replace("2 active", "-2 active"),
        summary_text().replace("`high`", "`https://attacker.invalid/secret`"),
    ],
)
def test_malformed_summary_does_not_publish(text, environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    Path(environment["SECGUARD_COMMENT_FILE"]).write_text(text, encoding="utf-8")
    assert publisher.main(environment) == 1
    assert api_server.requests == []


@pytest.mark.parametrize("change", ["closed", "fork", "head", "number"])
def test_live_pr_context_disagreement_is_rejected(change, environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    if change == "closed":
        api_server.pr["state"] = "closed"
    elif change == "fork":
        api_server.pr["head"]["repo"]["full_name"] = "attacker/tool"
    elif change == "head":
        api_server.pr["head"]["sha"] = "b" * 40
    else:
        api_server.pr["number"] = 5
    assert publisher.main(environment) == 1
    assert api_server.writes == []


def test_foreign_author_and_foreign_marker_comments_are_preserved(
    environment, api_server, monkeypatch
):
    install_api(monkeypatch, api_server)
    api_server.comments = [
        comment(1, MARKER + "\nforged", {"id": 123, "type": "User", "login": "attacker"}),
        comment(2, "<!-- secguard:pr-comment:another:v1 -->\nowned by another gate"),
    ]
    before = copy.deepcopy(api_server.comments)
    assert publisher.main(environment) == 0
    assert api_server.comments[:2] == before
    assert api_server.writes[0]["method"] == "POST"


def test_owned_comment_on_later_page_is_updated(environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    api_server.comments = [
        comment(number, "ordinary comment") for number in range(1, publisher.PAGE_SIZE + 1)
    ]
    context = publisher.Context.from_environment(environment)
    old = publisher.Summary.from_file(Path(environment["SECGUARD_COMMENT_FILE"]), "BLOCK").body(
        context
    )
    api_server.comments.append(comment(90, old.replace("2 active", "1 active")))
    assert publisher.main(environment) == 0
    assert [request["method"] for request in api_server.writes] == ["PATCH"]
    assert output_values(environment) == {"status": "updated", "comment-id": "90"}


def test_multiple_owned_comments_fail_without_selecting_one(environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    api_server.comments = [comment(1, MARKER + "\nold"), comment(2, MARKER + "\nold")]
    assert publisher.main(environment) == 1
    assert api_server.writes == []


def test_pagination_is_bounded_and_cannot_create_after_partial_search(
    environment, api_server, monkeypatch
):
    install_api(monkeypatch, api_server)
    api_server.comments = [
        comment(identifier, "unrelated")
        for identifier in range(1, publisher.PAGE_SIZE * publisher.MAX_PAGES + 1)
    ]
    assert publisher.main(environment) == 1
    assert api_server.writes == []
    pages = [request for request in api_server.requests if request["path"].endswith("/comments")]
    assert len(pages) == publisher.MAX_PAGES


def test_newer_attempt_is_not_overwritten(environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    context = publisher.Context.from_environment(environment)
    body = publisher.Summary.from_file(Path(environment["SECGUARD_COMMENT_FILE"]), "BLOCK").body(
        context
    )
    api_server.comments = [comment(1, body.replace("secguard-run:1234:1:", "secguard-run:1234:2:"))]
    assert publisher.main(environment) == 1
    assert api_server.writes == []


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 404, 422, 429, 500, 503])
def test_http_failures_do_not_echo_response_credentials(
    status, environment, api_server, monkeypatch, capsys
):
    install_api(monkeypatch, api_server)
    api_server.overrides[("GET", f"/repos/{REPOSITORY}/pulls/4")] = (
        status,
        {"message": TOKEN},
        {"Location": f"{api_server.endpoint}/credential-sink"},
    )
    assert publisher.main(environment) == 1
    assert api_server.writes == []
    assert len(api_server.requests) == 1
    logs = capsys.readouterr()
    assert TOKEN not in logs.err + logs.out
    assert f"HTTP {status}" in logs.err


@pytest.mark.parametrize(
    "body,headers",
    [
        (b"not-json", {}),
        (b"\xff", {}),
        (b"{}", {"Content-Type": "text/html"}),
        (b"x" * (publisher.MAX_RESPONSE_BYTES + 1), {}),
    ],
    ids=["invalid-json", "invalid-utf8", "wrong-content-type", "oversized"],
)
def test_invalid_http_response_is_not_accepted(body, headers, environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    api_server.overrides[("GET", f"/repos/{REPOSITORY}/pulls/4")] = 200, body, headers
    assert publisher.main(environment) == 1
    assert api_server.writes == []


@pytest.mark.parametrize(
    "response",
    [
        {"id": 999, "login": "different[bot]", "type": "Bot"},
        {"id": BOT["id"], "login": BOT["login"], "type": "User"},
        {"id": True, "login": BOT["login"], "type": "Bot"},
        {"id": BOT["id"], "login": [], "type": "Bot"},
    ],
)
def test_bot_identity_must_be_confirmed(response, environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    api_server.author = response
    assert publisher.main(environment) == 1
    assert api_server.writes == []


def test_mismatched_comment_issue_is_rejected(environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    unrelated = comment(1, MARKER + "\nold")
    unrelated["issue_url"] = ISSUE_URL.replace("/4", "/5")
    api_server.comments = [unrelated]
    assert publisher.main(environment) == 1
    assert api_server.writes == []


def test_create_response_must_confirm_the_exact_body_and_author(
    environment, api_server, monkeypatch
):
    install_api(monkeypatch, api_server)
    api_server.overrides[("POST", f"/repos/{REPOSITORY}/issues/4/comments")] = (
        201,
        comment(123, MARKER + "\nmodified body containing " + TOKEN),
        {},
    )
    assert publisher.main(environment) == 1
    assert not Path(environment["GITHUB_OUTPUT"]).exists()


def test_disabled_publisher_needs_no_token_or_event(monkeypatch):
    monkeypatch.setattr(publisher, "GitHubAPI", lambda *args: pytest.fail("network was attempted"))
    assert publisher.main({"SECGUARD_PUBLISH_COMMENT": "false"}) == 0
    assert publisher.main({}) == 0


@pytest.mark.parametrize("verdict", ["ERROR", "NO-REPORTS", ""])
def test_no_completed_gate_cannot_publish(verdict, environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    environment["SECGUARD_VERDICT"] = verdict
    assert publisher.main(environment) == 0
    assert output_values(environment) == {"status": "not-published"}
    assert api_server.requests == []


@pytest.mark.parametrize(
    "api,server,accepted",
    [
        ("https://api.github.com", "https://github.com", True),
        ("https://github.enterprise.example/api/v3", "https://github.enterprise.example", True),
        ("https://attacker.invalid", "https://github.com", False),
        ("http://api.github.com", "https://github.com", False),
        ("https://api.github.com", "https://github.com/evil", False),
        ("https://api.github.com", "https://user:password@github.com", False),
        ("https://api.github.com", "https://github.com:8443", False),
        (
            "https://github.enterprise.example/api/v3?token=secret",
            "https://github.enterprise.example",
            False,
        ),
    ],
)
def test_api_origin_must_match_the_runtime_server(api, server, accepted):
    if accepted:
        assert publisher.Endpoints.trusted(api, server) == publisher.Endpoints(api, server)
    else:
        with pytest.raises(publisher.PublicationError):
            publisher.Endpoints.trusted(api, server)


def test_cli_does_not_accept_a_token_argument(tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts/post_pr_comment.py"), "--token", TOKEN],
        cwd=tmp_path,
        env={**os.environ, "SECGUARD_PUBLISH_COMMENT": "false"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 1
    assert TOKEN not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "change", ["newer-run", "unknown-stamp", "other-workflow", "inconsistent-id"]
)
def test_existing_stamp_cannot_be_replayed_or_confused(
    change, environment, api_server, monkeypatch
):
    install_api(monkeypatch, api_server)
    context = publisher.Context.from_environment(environment)
    summary = publisher.Summary.from_file(Path(environment["SECGUARD_COMMENT_FILE"]), "BLOCK")
    body = summary.body(context)
    if change == "newer-run":
        body = body.replace(f":8:{context.workflow_key}", f":9:{context.workflow_key}")
        body = body.replace("secguard-run:1234:", "secguard-run:100:")
    elif change == "unknown-stamp":
        body = MARKER + "\nunrecognized summary"
    elif change == "other-workflow":
        body = body.replace(context.workflow_key, "f" * 64)
    else:
        body = body.replace("secguard-run:1234:", "secguard-run:100:")
    api_server.comments = [comment(1, body)]
    assert publisher.main(environment) == 1
    assert api_server.writes == []


def test_newer_run_can_update_an_older_valid_summary(environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    context = publisher.Context.from_environment(environment)
    summary = publisher.Summary.from_file(Path(environment["SECGUARD_COMMENT_FILE"]), "BLOCK")
    old = summary.body(context).replace("secguard-run:1234:", "secguard-run:9000:")
    old = old.replace(f":8:{context.workflow_key}", f":7:{context.workflow_key}")
    api_server.comments = [comment(90, old)]
    assert publisher.main(environment) == 0
    assert output_values(environment) == {"status": "updated", "comment-id": "90"}


def test_live_head_is_rechecked_after_comment_pagination(environment, api_server, monkeypatch):
    install_api(monkeypatch, api_server)
    original = api_server.respond
    count = 0

    def respond(method, path, query, payload):
        nonlocal count
        if path == f"/repos/{REPOSITORY}/pulls/4":
            count += 1
            if count == 2:
                api_server.pr["head"]["sha"] = "b" * 40
        return original(method, path, query, payload)

    api_server.respond = respond
    assert publisher.main(environment) == 1
    assert count == 2
    assert api_server.writes == []


@pytest.mark.parametrize(
    "method,status", [("POST", 200), ("POST", 403), ("PATCH", 201), ("PATCH", 422)]
)
def test_write_http_status_must_confirm_the_operation(
    method, status, environment, api_server, monkeypatch
):
    install_api(monkeypatch, api_server)
    context = publisher.Context.from_environment(environment)
    body = publisher.Summary.from_file(Path(environment["SECGUARD_COMMENT_FILE"]), "BLOCK").body(
        context
    )
    if method == "PATCH":
        api_server.comments = [comment(1, body.replace("2 active", "1 active"))]
        path = f"/repos/{REPOSITORY}/issues/comments/1"
    else:
        path = f"/repos/{REPOSITORY}/issues/4/comments"
    api_server.overrides[(method, path)] = status, comment(1, body), {}
    assert publisher.main(environment) == 1
    assert not Path(environment["GITHUB_OUTPUT"]).exists()


@pytest.mark.parametrize("threshold,verdict,exit_code", [("none", "PASS", 0), ("high", "BLOCK", 1)])
def test_current_core_report_is_accepted_without_publishing_its_details(
    threshold, verdict, exit_code, environment, api_server, monkeypatch
):
    from typer.testing import CliRunner

    from secguard.cli.app import app

    install_api(monkeypatch, api_server)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "check",
            "--input",
            str(ROOT / "tests/fixtures/gitleaks-report.json"),
            "--fail-on",
            threshold,
            "--pr-comment",
            environment["SECGUARD_COMMENT_FILE"],
            "--today",
            "2026-10-05",
        ],
    )
    assert result.exit_code == exit_code, result.output
    environment["SECGUARD_VERDICT"] = verdict
    assert publisher.main(environment) == 0
    body = api_server.comments[0]["body"]
    assert f"### secguard: {verdict}" in body
    for prohibited in (
        "src/example_config.py",
        "SECGUARD-CANARY",
        "aws-access-token",
        "Blocking findings",
    ):
        assert prohibited not in body


def test_action_keeps_publisher_opt_in_and_runs_it_after_a_block():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert action["inputs"]["publish-pr-comment"]["default"] == "false"
    assert action["inputs"]["comment-repository"]["default"] == ""
    step = next(step for step in action["runs"]["steps"] if step.get("id") == "publish")
    assert "always()" in step["if"]
    assert "!cancelled()" in step["if"]
    assert "continue-on-error" not in step
    assert step["env"]["SECGUARD_TOKEN"] == "${{ github.token }}"
    assert step["run"] == 'python -I "$SECGUARD_ACTION_PATH/scripts/post_pr_comment.py"'
    assert "${{" not in step["run"]
    assert "verdict" not in step["run"]
    assert "token" not in action["inputs"]
