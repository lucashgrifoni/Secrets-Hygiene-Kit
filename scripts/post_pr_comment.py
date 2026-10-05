"""Publish a bounded secguard summary for a trusted same-repository pull request."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_FILE_BYTES = 256 * 1024
MAX_EVENT_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_COMMENT_BYTES = 2048
PAGE_SIZE = 30
MAX_PAGES = 10
API_VERSION = "2022-11-28"
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
SUMMARY_PATTERN = re.compile(
    r"([0-9]{1,9}) active finding\(s\), ([0-9]{1,9}) waived, "
    r"threshold `(none|info|low|medium|high|critical)` \(checked ([0-9]{4}-[0-9]{2}-[0-9]{2})\)\."
)


class PublicationError(Exception):
    """A fixed, credential-free error safe to report to a workflow log."""


def bounded_file(path: Path, maximum: int) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError:
        raise PublicationError("required publisher input is unavailable") from None
    if len(data) > maximum:
        raise PublicationError("publisher input exceeds the size limit")
    return data


def positive_integer(value: object, *, maximum: int = 10**18) -> int:
    if isinstance(value, bool) or not re.fullmatch(r"[1-9][0-9]{0,17}", str(value)):
        raise PublicationError("publisher context contains an invalid numeric identifier")
    number = int(str(value))
    if number > maximum:
        raise PublicationError("publisher identifier exceeds the limit")
    return number


def repository_name(value: object) -> str:
    if not isinstance(value, str) or not REPOSITORY_PATTERN.fullmatch(value):
        raise PublicationError("publisher repository is invalid")
    return value


@dataclass(frozen=True)
class Endpoints:
    api: str
    server: str

    @classmethod
    def trusted(cls, api: str, server: str) -> Endpoints:
        parsed = urlsplit(server)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.path
            or parsed.query
            or parsed.fragment
            or server != f"https://{parsed.hostname}"
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", parsed.hostname)
        ):
            raise PublicationError("publisher requires a canonical HTTPS GitHub server")
        expected = (
            "https://api.github.com" if server == "https://github.com" else f"{server}/api/v3"
        )
        if api != expected:
            raise PublicationError("publisher API does not match the GitHub server")
        return cls(api, server)


@dataclass(frozen=True)
class Context:
    repository: str
    number: int
    head_sha: str
    run_id: int
    run_attempt: int
    run_number: int
    workflow_key: str
    marker: str
    author: str
    endpoints: Endpoints

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> Context:
        if environment.get("GITHUB_EVENT_NAME") != "pull_request":
            raise PublicationError("PR comments require the pull_request event")
        expected = repository_name(environment.get("SECGUARD_EXPECTED_REPOSITORY"))
        repository = repository_name(environment.get("GITHUB_REPOSITORY"))
        if expected.casefold() != repository.casefold():
            raise PublicationError("publisher repository differs from the trusted repository")
        raw = bounded_file(Path(environment.get("GITHUB_EVENT_PATH", "")), MAX_EVENT_BYTES)
        try:
            event = json.loads(raw)
        except (ValueError, UnicodeError):
            raise PublicationError("publisher event is not valid JSON") from None
        if not isinstance(event, dict) or not isinstance(event.get("repository"), dict):
            raise PublicationError("publisher event does not identify a repository")
        event_repository = repository_name(event["repository"].get("full_name"))
        if event_repository.casefold() != repository.casefold():
            raise PublicationError("publisher event repository does not match the workflow")
        pr = event.get("pull_request")
        number, head_sha = validate_pull_request(pr, repository)
        if positive_integer(event.get("number")) != number:
            raise PublicationError("publisher event PR identifiers disagree")
        if (
            positive_integer(environment.get("SECGUARD_PR_NUMBER")) != number
            or environment.get("SECGUARD_PR_HEAD_SHA") != head_sha
            or repository_name(environment.get("SECGUARD_PR_HEAD_REPOSITORY")).casefold()
            != repository.casefold()
        ):
            raise PublicationError("publisher event disagrees with the trusted Action context")
        marker = environment.get("SECGUARD_COMMENT_MARKER", "secguard")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", marker):
            raise PublicationError("comment marker is invalid")
        author = environment.get("SECGUARD_COMMENT_AUTHOR", "github-actions[bot]")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}\[bot\]", author):
            raise PublicationError("comment author must identify a GitHub bot")
        endpoints = Endpoints.trusted(
            environment.get("GITHUB_API_URL", ""), environment.get("GITHUB_SERVER_URL", "")
        )
        workflow = environment.get("GITHUB_WORKFLOW_REF", "").split("@", 1)[0]
        if (
            not workflow.startswith(f"{repository}/.github/workflows/")
            or not re.fullmatch(r"[A-Za-z0-9_./-]+\.ya?ml", workflow)
            or ".." in workflow.split("/")
        ):
            raise PublicationError("publisher workflow identity is invalid")
        return cls(
            repository,
            number,
            head_sha,
            positive_integer(environment.get("GITHUB_RUN_ID")),
            positive_integer(environment.get("GITHUB_RUN_ATTEMPT")),
            positive_integer(environment.get("GITHUB_RUN_NUMBER")),
            hashlib.sha256(workflow.casefold().encode("utf-8")).hexdigest(),
            marker,
            author,
            endpoints,
        )


def validate_pull_request(value: object, repository: str) -> tuple[int, str]:
    if not isinstance(value, dict) or value.get("state") != "open":
        raise PublicationError("publisher requires an open pull request")
    for side in ("base", "head"):
        reference = value.get(side)
        repo = reference.get("repo") if isinstance(reference, dict) else None
        if not isinstance(repo, dict) or not isinstance(repo.get("full_name"), str):
            raise PublicationError("publisher PR repository context is missing")
        if repo["full_name"].casefold() != repository.casefold():
            raise PublicationError("PR comment publication is disabled for forks")
    head_sha = value["head"].get("sha")
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise PublicationError("publisher PR head is invalid")
    return positive_integer(value.get("number")), head_sha


@dataclass(frozen=True)
class Summary:
    verdict: str
    active: int
    waived: int
    threshold: str
    checked: str

    @classmethod
    def from_file(cls, path: Path, verdict: str) -> Summary:
        try:
            lines = bounded_file(path, MAX_FILE_BYTES).decode("utf-8").splitlines()
        except UnicodeError:
            raise PublicationError("publisher summary is not UTF-8") from None
        if verdict not in {"PASS", "BLOCK"} or len(lines) < 3:
            raise PublicationError("publisher requires a completed gate summary")
        if lines[0] != f"### secguard: {verdict}" or lines[1] != "":
            raise PublicationError("publisher summary disagrees with the gate verdict")
        match = SUMMARY_PATTERN.fullmatch(lines[2])
        if match is None:
            raise PublicationError("publisher summary header is invalid")
        active, waived, threshold, checked = match.groups()
        try:
            date.fromisoformat(checked)
        except ValueError:
            raise PublicationError("publisher summary date is invalid") from None
        return cls(verdict, int(active), int(waived), threshold, checked)

    def body(self, context: Context) -> str:
        marker = f"<!-- secguard:pr-comment:{context.marker}:v1 -->"
        run = (
            f"<!-- secguard-run:{context.run_id}:{context.run_attempt}:{context.head_sha}:"
            f"{context.run_number}:{context.workflow_key} -->"
        )
        link = (
            f"{context.endpoints.server}/{context.repository}/actions/runs/{context.run_id}"
            f"/attempts/{context.run_attempt}"
        )
        body = (
            f"{marker}\n{run}\n### secguard: {self.verdict}\n\n"
            f"{self.active} active finding(s), {self.waived} waived; "
            f"threshold `{self.threshold}` (checked {self.checked}).\n\n"
            f"[Workflow results and evidence]({link})\n\n"
            "secguard evaluates scanner reports. Review the workflow evidence before responding.\n"
        )
        if len(body.encode("utf-8")) > MAX_COMMENT_BYTES:
            raise PublicationError("generated PR summary exceeds the comment limit")
        return body


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubAPI:
    def __init__(self, endpoints: Endpoints, token: str) -> None:
        if (
            not token
            or len(token) > 1024
            or any(ord(character) < 33 or ord(character) > 126 for character in token)
        ):
            raise PublicationError("publisher token is missing or invalid")
        self.endpoints = endpoints
        self._token = token
        self._opener = build_opener(NoRedirect())

    def request(self, method: str, path: str, *, body: str | None = None) -> object:
        if not path.startswith("/") or path.startswith("//") or "#" in path:
            raise PublicationError("publisher API path is invalid")
        data = json.dumps({"body": body}).encode("utf-8") if body is not None else None
        request = Request(
            self.endpoints.api + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "secguard-pr-comment",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with self._opener.open(request, timeout=15) as response:
                expected_status = 201 if method == "POST" else 200
                if response.status != expected_status:
                    raise PublicationError("GitHub returned an unexpected publisher status")
                if response.headers.get_content_type() != "application/json":
                    raise PublicationError("GitHub returned a non-JSON publisher response")
                payload = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            code = int(exc.code)
            exc.close()
            raise PublicationError(f"GitHub publisher request failed (HTTP {code})") from None
        except (URLError, OSError, TimeoutError):
            raise PublicationError(
                "GitHub publisher request failed; delivery could not be confirmed"
            ) from None
        if len(payload) > MAX_RESPONSE_BYTES:
            raise PublicationError("GitHub publisher response exceeds the size limit")
        try:
            return json.loads(payload)
        except (ValueError, UnicodeError):
            raise PublicationError("GitHub publisher returned invalid JSON") from None


def comment_matches(comment: object, *, author_id: int, marker: str, issue_url: str) -> bool:
    if not isinstance(comment, dict) or not isinstance(comment.get("user"), dict):
        raise PublicationError("GitHub comment response is invalid")
    body = comment.get("body")
    if not isinstance(body, str):
        raise PublicationError("GitHub comment body is invalid")
    positive_integer(comment.get("id"))
    positive_integer(comment["user"].get("id"))
    if comment.get("issue_url") != issue_url:
        raise PublicationError("GitHub comment belongs to an unexpected issue")
    return (
        comment["user"].get("id") == author_id
        and comment["user"].get("type") == "Bot"
        and body.startswith(marker + "\n")
        and comment.get("issue_url") == issue_url
    )


def publish(context: Context, summary: Summary, api: GitHubAPI) -> tuple[str, int]:
    prefix = f"/repos/{context.repository}"
    live = api.request("GET", f"{prefix}/pulls/{context.number}")
    if validate_pull_request(live, context.repository) != (context.number, context.head_sha):
        raise PublicationError("PR head changed; refusing to publish stale evidence")
    author = api.request("GET", f"/users/{context.author}")
    if (
        not isinstance(author, dict)
        or author.get("login", "").casefold() != context.author.casefold()
        or author.get("type") != "Bot"
    ):
        raise PublicationError("GitHub did not confirm the configured comment bot")
    author_id = positive_integer(author.get("id"))
    issue_url = f"{context.endpoints.api}{prefix}/issues/{context.number}"
    marker = f"<!-- secguard:pr-comment:{context.marker}:v1 -->"
    owned: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        comments = api.request(
            "GET", f"{prefix}/issues/{context.number}/comments?per_page={PAGE_SIZE}&page={page}"
        )
        if not isinstance(comments, list) or len(comments) > PAGE_SIZE:
            raise PublicationError("GitHub comment page is invalid")
        owned.extend(
            comment
            for comment in comments
            if comment_matches(comment, author_id=author_id, marker=marker, issue_url=issue_url)
        )
        if len(comments) < PAGE_SIZE:
            break
    else:
        raise PublicationError("PR comment pagination limit reached; no comment was changed")
    if len(owned) > 1:
        raise PublicationError("multiple owned summaries exist; no comment was changed")
    live = api.request("GET", f"{prefix}/pulls/{context.number}")
    if validate_pull_request(live, context.repository) != (context.number, context.head_sha):
        raise PublicationError("PR head changed; refusing to publish stale evidence")
    body = summary.body(context)
    if owned:
        comment = owned[0]
        comment_id = positive_integer(comment.get("id"))
        old_run = re.match(
            r"<!-- secguard-run:([1-9][0-9]{0,17}):([1-9][0-9]{0,17}):([0-9a-f]{40}):"
            r"([1-9][0-9]{0,17}):([0-9a-f]{64}) -->\n",
            comment["body"].split("\n", 1)[1],
        )
        if old_run is None or old_run[5] != context.workflow_key:
            raise PublicationError("owned comment has an unrecognized publisher workflow stamp")
        old_id, old_attempt, old_number = int(old_run[1]), int(old_run[2]), int(old_run[4])
        if old_number > context.run_number:
            raise PublicationError("a newer workflow run already published this summary")
        if (old_number == context.run_number) != (old_id == context.run_id):
            raise PublicationError("owned comment run identifiers are inconsistent")
        if old_id == context.run_id and old_attempt > context.run_attempt:
            raise PublicationError("a newer attempt already published this run")
        if comment["body"] == body:
            return "unchanged", comment_id
        result = api.request("PATCH", f"{prefix}/issues/comments/{comment_id}", body=body)
        status = "updated"
    else:
        result = api.request("POST", f"{prefix}/issues/{context.number}/comments", body=body)
        status = "created"
    if (
        not comment_matches(result, author_id=author_id, marker=marker, issue_url=issue_url)
        or result["body"] != body
        or (status == "updated" and result.get("id") != comment_id)
    ):
        raise PublicationError("GitHub did not confirm the published comment identity and body")
    return status, positive_integer(result.get("id"))


def outputs(environment: Mapping[str, str], status: str, comment_id: int | None = None) -> None:
    destination = environment.get("GITHUB_OUTPUT")
    if destination:
        with Path(destination).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"status={status}\n")
            if comment_id is not None:
                stream.write(f"comment-id={comment_id}\n")


def main(environment: Mapping[str, str] | None = None) -> int:
    environment = os.environ if environment is None else environment
    try:
        enabled = environment.get("SECGUARD_PUBLISH_COMMENT", "false")
        if enabled == "false":
            return 0
        if enabled != "true":
            raise PublicationError("publish-pr-comment must be true or false")
        context = Context.from_environment(environment)
        verdict = environment.get("SECGUARD_VERDICT", "")
        if verdict not in {"PASS", "BLOCK"}:
            outputs(environment, "not-published")
            return 0
        positive_integer(environment.get("SECGUARD_REPORTS_FOUND"), maximum=10**9)
        summary = Summary.from_file(Path(environment.get("SECGUARD_COMMENT_FILE", "")), verdict)
        api = GitHubAPI(context.endpoints, environment.get("SECGUARD_TOKEN", ""))
        status, comment_id = publish(context, summary, api)
        outputs(environment, status, comment_id)
        print(f"secguard PR comment: {status} (id {comment_id})")
        return 0
    except PublicationError as exc:
        print(f"secguard PR comment error: {exc}", file=sys.stderr)
    except Exception:
        print("secguard PR comment error: publisher could not complete", file=sys.stderr)
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 1:
        print(
            "secguard PR comment error: configure the publisher through environment variables",
            file=sys.stderr,
        )
        raise SystemExit(1)
    raise SystemExit(main())
