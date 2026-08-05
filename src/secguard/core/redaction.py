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

MAX_TEXT_LENGTH = 240
TRUNCATION_SUFFIX = "..."

# Full CSI and OSC escape sequences. Stripping only the ESC byte would leave
# the sequence body ("[31m") as literal noise in reports.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")
_COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{7,64}$")


def sanitize_text(value: object, *, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Collapse a scanner-supplied string into a safe single-line summary.

    Removes control characters (including ANSI escape introducers and newlines)
    so a hostile or malformed report cannot forge log lines, break Markdown
    tables, or inject terminal escape sequences into secguard output.
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
    """Escape a value so it cannot break out of a Markdown table cell."""
    return sanitize_text(value).replace("\\", "\\\\").replace("|", "\\|")
