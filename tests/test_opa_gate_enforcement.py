"""Exercise the release aggregator with a failed external policy decision."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def job():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["release-checks"]


def test_workflow_waits_for_the_opa_job():
    assert "opa" in job()["needs"]


def test_release_aggregator_rejects_a_failed_opa_job(tmp_path):
    release = job()
    script = release["steps"][0]["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    results = {name: {"result": "success"} for name in release["needs"]}
    results.update(opa={"result": "failure"}, provenance={"result": "skipped"})
    observed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={
            **os.environ,
            "RESULTS": json.dumps(results),
            "EVENT_NAME": "pull_request",
            "REF": "refs/pull/8/merge",
            "PR_HEAD_REPOSITORY": "lucashgrifoni/secrets-hygiene-kit",
            "PR_AUTHOR": "lucashgrifoni",
            "ACTOR": "lucashgrifoni",
        },
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert observed.returncode == 1, observed.stdout + observed.stderr
    assert "opa did not pass" in observed.stderr
