"""Opt-in removal of caller prose, without rewriting occurrence or policy identity.

This is minimization, not secret detection. Paths, rules, fingerprints, policy
IDs and repository names remain meaningful and still require review before
sharing. Project only after normalization/merge has derived original IDs.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from secguard.core.catalog import RuleCatalog
from secguard.core.findings import FindingDocument
from secguard.core.waivers import WaiverDocument

_MINIMIZE = ContextVar("secguard_minimize_metadata", default=False)
OMITTED = "Metadata omitted by operator request."
MINIMIZED_TITLE = "Secret finding"


@contextmanager
def metadata_mode(enabled: bool) -> Iterator[None]:
    token = _MINIMIZE.set(enabled)
    try:
        yield
    finally:
        _MINIMIZE.reset(token)


def minimizing_metadata() -> bool:
    return _MINIMIZE.get()


def minimize_findings(document: FindingDocument) -> FindingDocument:
    if not minimizing_metadata():
        return document
    return document.model_copy(
        update={
            "findings": [
                finding.model_copy(
                    update={
                        "message": OMITTED,
                        "remediation": None,
                        "secret_title": MINIMIZED_TITLE,
                    }
                )
                for finding in document.findings
            ]
        }
    )


def minimize_waivers(document: WaiverDocument) -> WaiverDocument:
    if not minimizing_metadata():
        return document
    return document.model_copy(
        update={
            "waivers": [
                waiver.model_copy(
                    update={"reason": OMITTED, "owner": "omitted", "approver": "omitted"}
                )
                for waiver in document.waivers
            ]
        }
    )


def minimize_catalog(catalog: RuleCatalog) -> RuleCatalog:
    if not minimizing_metadata():
        return catalog
    return catalog.model_copy(
        update={
            "secret_types": {
                key: spec.model_copy(update={"title": MINIMIZED_TITLE})
                for key, spec in catalog.secret_types.items()
            }
        }
    )
