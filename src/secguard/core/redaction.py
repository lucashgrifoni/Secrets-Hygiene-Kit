"""Redaction and text-hygiene helpers shared by every scanner adapter.

secguard reads scanner reports that *do* contain live credentials. The rule
that keeps those credentials out of secguard output is simple and applies to
every adapter: **read by allowlist, never by denylist**. An adapter names the
exact metadata keys it needs (rule id, path, line, commit, verification flag)
and ignores everything else, so a new detector field that happens to carry
secret material cannot leak into canonical findings by default.

Known secret-bearing fields, listed here as documentation for reviewers rather
than as a filter:

- gitleaks: ``Secret``, ``Match``, ``Message`` (commit message), ``Author``,
  ``Email``
- trufflehog: ``Raw``, ``RawV2``, ``Redacted``, ``ExtraData``, source ``email``
- detect-secrets: ``hashed_secret`` (a SHA-1 digest of the credential, which is
  recoverable for low-entropy secrets, so secguard derives its own location
  fingerprint instead)
"""

from __future__ import annotations

import re
from typing import Any

MAX_TEXT_LENGTH = 240
TRUNCATION_SUFFIX = "..."

# Full CSI and OSC escape sequences. Stripping only the ESC byte would leave
# the sequence body ("[31m") as literal noise in reports.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")
_WHITESPACE = re.compile(r"\s+")
_COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{7,64}$")
_BACKTICK_RUN = re.compile(r"`+")

_MODEL_FIELDS = frozenset(
    [
        "schema",
        "scanner",
        "findings",
        "rule_id",
        "path",
        "message",
        "severity",
        "line",
        "column",
        "fingerprint",
        "remediation",
        "waivers",
        "id",
        "rule",
        "reason",
        "owner",
        "expires_at",
        "approver",
        "title",
        "playbook",
        "secret_types",
        "detectors",
        "fallback_secret_type",
    ]
)


def validation_error_details(errors: list[dict[str, Any]]) -> str:
    """Describe model errors without echoing input-controlled mapping keys.

    Pydantic's include_input=False removes values, but an unknown field's name
    still appears in loc. A report can put a credential or a forged log line
    in that name, so only declared field names and numeric indexes are retained.
    """
    details: list[str] = []
    for error in errors:
        parts = error["loc"]
        location = ".".join(
            str(part)
            if (isinstance(part, str) and part in _MODEL_FIELDS)
            or (isinstance(part, int) and index == 1 and parts[0] in {"findings", "waivers"})
            else "<field>"
            for index, part in enumerate(parts)
        )
        details.append(f"{location}: {sanitize_text(error['msg'])}")
    return "; ".join(details)


# Backslash stays first so it cannot double-escape the characters after it.
_MARKDOWN_ACTIVE = ("\\", "`", "|", "*", "_", "[", "]", "<", ">")

# Characters a terminal, a log parser, or a human reader treats as structure
# rather than text. One of these in a path or a rule id can forge a line of
# gate output, or make a path render as a filename other than the one reported.
#
# Every code point is written as an escape and every range is spelled out here
# rather than shown: a file that decides which invisible characters are
# dangerous must not contain any of them, or reviewing it means trusting a
# renderer.
#
#   \x00-\x1f   C0 controls: NUL, TAB (the console output is tab-separated),
#               CR, LF, and the ESC that opens an ANSI sequence.
#   \x7f-\x9f   DEL and the C1 controls. This range holds U+0085 NEL, a line
#               terminator to str.splitlines(), to JavaScript, and to most log
#               viewers -- and one an ASCII-only guard misses.
#   \u2028      LINE SEPARATOR and PARAGRAPH SEPARATOR: line terminators to the
#   \u2029      same readers, likewise invisible to an ASCII-only guard.
#   \u061c      ARABIC LETTER MARK, LEFT-TO-RIGHT MARK, RIGHT-TO-LEFT MARK, the
#   \u200e      embedding/override pair, and the isolate set. This is the
#   \u200f      trojan-source class: an override reorders a rendered path so a
#   \u202a-e    reviewer reads a filename other than the one being reported.
#   \u2066-9
#
# Zero-width joiners are deliberately absent. They appear in legitimate emoji
# and Indic filenames and cannot forge structure.
# Lone surrogates are included because they are not text at all: they cannot
# be encoded to UTF-8, so one in a path crashed the fingerprint hash with an
# unhandled UnicodeEncodeError and exit 1.
_BIDI_AND_SEPARATORS = r"\ud800-\udfff\u2028\u2029\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069"

_CONTROL_OR_ESCAPE = re.compile(rf"[\x00-\x1f\x7f-\x9f{_BIDI_AND_SEPARATORS}]")

# The sanitizers replace rather than reject, so they leave the ASCII newline
# family in place for `_WHITESPACE` to collapse into a single space.
_CONTROL_CHARACTERS = re.compile(rf"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f{_BIDI_AND_SEPARATORS}]")


def has_control_characters(value: str) -> bool:
    """Return whether a value carries control, line-terminating, or bidi characters."""
    return _CONTROL_OR_ESCAPE.search(value) is not None


def sanitize_text(value: object, *, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Collapse a scanner-supplied string into a safe single-line summary.

    Removes control characters (including ANSI escape introducers, the newline
    family, and bidi overrides) so a hostile or malformed report cannot forge
    log lines, break Markdown tables, reorder a rendered path, or inject
    terminal escape sequences into secguard output.
    """
    text = value if isinstance(value, str) else str(value)
    text = _ANSI_ESCAPE.sub(" ", text)
    text = _CONTROL_CHARACTERS.sub(" ", text)
    text = _WHITESPACE.sub(" ", text).strip()

    if len(text) > max_length:
        text = text[: max_length - len(TRUNCATION_SUFFIX)].rstrip() + TRUNCATION_SUFFIX

    return text


def sanitize_commit(value: object) -> str | None:
    """Return a commit identifier only when it looks like a hexadecimal hash."""
    if not isinstance(value, str):
        return None

    candidate = value.strip()
    return candidate if _COMMIT_PATTERN.match(candidate) else None


def escape_markdown_cell(value: str) -> str:
    """Escape a value so it cannot break out of a Markdown table cell.

    Scanner-supplied values reach a report that reviewers read and a comment
    posted to a pull request. Escaping only the pipe and the backslash left a
    path free to close a code span and open a link, so the set covers every
    active character that can start markup here.
    """
    text = sanitize_text(value)
    for character in _MARKDOWN_ACTIVE:
        text = text.replace(character, f"\\{character}")
    return text


def markdown_code_span(value: str) -> str:
    """Wrap a value in a code span its own backticks cannot close.

    A backslash does not escape a backtick inside a code span, so the only
    correct defence is a fence longer than the longest backtick run in the
    value, which is what CommonMark specifies. Pipes stay escaped because a
    literal pipe ends a table cell even inside a span.
    """
    text = sanitize_text(value).replace("|", "\\|")
    longest = max((len(run) for run in _BACKTICK_RUN.findall(text)), default=0)
    fence = "`" * (longest + 1)
    # A span whose content starts or ends with a backtick needs one space of
    # padding; CommonMark strips a single leading and trailing space.
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{padding}{text}{padding}{fence}"
