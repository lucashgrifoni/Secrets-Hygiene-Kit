"""Exercise Generic Findings Import on an owned, loopback-only Docker pilot.

This validation script creates a synthetic product and engagement. It obtains
an ephemeral API key inside the local pilot; no key is printed or persisted.
It is separate from secguard, which only exports files and stays offline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    compose = args.compose_file.resolve()
    docker = ["docker", "compose", "-f", str(compose)]
    key = subprocess.run(
        [
            *docker,
            "exec",
            "-T",
            "uwsgi",
            "python",
            "manage.py",
            "shell",
            "-c",
            "from django.contrib.auth import get_user_model; "
            "from rest_framework.authtoken.models import Token; "
            "from django.conf import settings; "
            "dedup=settings.DEDUPLICATION_ALGORITHM_PER_PARSER; "
            "print('PILOT_DEDUP:' + str(dedup.get('secguard Scan (Generic Findings Import)'))); "
            "u=get_user_model().objects.get(username='secguard_pilot'); "
            "print('PILOT_KEY:' + Token.objects.get_or_create(user=u)[0].key)",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    token = next(
        line.split(":", 1)[1] for line in key.stdout.splitlines() if line.startswith("PILOT_KEY:")
    )
    if "PILOT_DEDUP:unique_id_from_tool" not in key.stdout:
        raise SystemExit("The pilot must select unique_id_from_tool for secguard's Test Type")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = "http://127.0.0.1:18087/api/v2/"
    observations: list[dict] = []

    def request(route: str, data=None, *, upload=None, authenticated=True):
        headers = {"Authorization": f"Token {token}"} if authenticated else {}
        body = None
        if upload is not None:
            boundary = "secguard-" + uuid.uuid4().hex
            parts = []
            for name, value in data.items():
                parts.append(
                    (
                        f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n'
                        f"\r\n{value}\r\n"
                    ).encode()
                )
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                'filename="secguard.json"\r\n'
                "Content-Type: application/json\r\n\r\n".encode()
                + upload
                + f"\r\n--{boundary}--\r\n".encode()
            )
            body = b"".join(parts)
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
        elif data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(base + route, data=body, headers=headers)
        try:
            with opener.open(req, timeout=30) as response:
                status, payload = response.status, json.load(response)
        except urllib.error.HTTPError as error:
            # Never dump request headers or credentials on a failure.
            status = error.code
            try:
                payload = json.loads(error.read())
            except json.JSONDecodeError:
                payload = {"non_json_error": True}
        return status, payload

    unauth_status, _ = request("products/", authenticated=False)
    assert unauth_status in (401, 403), "Pilot accepted an unauthenticated product request"
    observations.append({"case": "unauthenticated-request", "http_status": unauth_status})
    suffix = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    status, product_type = request("product_types/", {"name": "secguard internal pilot " + suffix})
    assert status == 201, f"Product type creation failed ({status})"
    status, product = request(
        "products/",
        {
            "name": "secguard synthetic pilot " + suffix,
            "description": "Synthetic data only",
            "prod_type": product_type["id"],
        },
    )
    assert status == 201, f"Product creation failed ({status})"
    today = datetime.now(UTC).date().isoformat()
    status, engagement = request(
        "engagements/",
        {
            "name": "File handoff contract",
            "product": product["id"],
            "target_start": today,
            "target_end": today,
        },
    )
    assert status == 201, f"Engagement creation failed ({status})"

    with tempfile.TemporaryDirectory(prefix="sg-dojo-") as temporary:
        working = Path(temporary)
        raw, truffle, waivers = (
            working / "raw.json",
            working / "truffle.json",
            working / "waivers.yaml",
        )
        raw.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "github-pat",
                        "File": "src/auth.py",
                        "StartLine": 3,
                        "Secret": "SECGUARD-PILOT-CANARY",
                    },
                    {"RuleID": "aws-access-token", "File": "fixtures/sample.env", "StartLine": 2},
                ]
            ),
            encoding="utf-8",
        )
        truffle.write_text(
            json.dumps(
                [
                    {
                        "DetectorName": "Github",
                        "Verified": True,
                        "SourceMetadata": {
                            "Data": {"Filesystem": {"file": "src/auth.py", "line": 3}}
                        },
                    }
                ]
            ),
            encoding="utf-8",
        )
        waivers.write_text(
            "schema: secguard.waiver/v1\nwaivers:\n- id: WV-2026-006\n"
            "  rule: gitleaks:aws-access-token\n  path: fixtures/**\n"
            "  owner: pilot\n  approver: pilot-review\n"
            "  reason: Synthetic local pilot only\n  expires_at: 2099-01-01\n",
            encoding="utf-8",
        )

        def export(*extra):
            destination = working / "defectdojo.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "secguard",
                    "scan",
                    "check",
                    "--input",
                    str(raw),
                    "--today",
                    today,
                    "--defectdojo",
                    str(destination),
                    *extra,
                ],
                cwd=working,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert completed.returncode in (0, 1) and destination.exists(), "secguard export failed"
            payload = destination.read_bytes()
            assert b"SECGUARD-PILOT-CANARY" not in payload, "A raw secret reached the consumer"
            return payload, json.loads(payload)

        first, generated = export()
        status, imported = request(
            "import-scan/",
            {
                "engagement": engagement["id"],
                "scan_type": "Generic Findings Import",
                "scan_date": today,
                "minimum_severity": "Info",
                "verified": "false",
                "active": "true",
                "close_old_findings": "false",
                "test_title": "secguard synthetic file handoff",
            },
            upload=first,
        )
        assert status == 201, f"Import failed ({status})"
        test_id = imported["test"]

        def findings():
            status, payload = request(f"findings/?test={test_id}&limit=100")
            assert status == 200, f"Finding query failed ({status})"
            return payload["results"]

        for _ in range(20):
            stored = findings()
            if len(stored) == 2:
                break
            time.sleep(1)
        assert len(stored) == 2, "Imported count differs from the exported count"
        expected = {item["unique_id_from_tool"]: item for item in generated["findings"]}
        initial_ids = {item["id"] for item in stored}
        for item in stored:
            source = expected[item["unique_id_from_tool"]]
            assert item["severity"] == source["severity"]
            assert item["file_path"] == source["file_path"] and item["line"] == source["line"]
            assert item["verified"] is False and item["active"] is True
        observations.append(
            {
                "case": "initial-import",
                "http_status": status,
                "findings": len(stored),
                "verified": False,
            }
        )

        def reimport(payload):
            status, _ = request(
                "reimport-scan/",
                {
                    "test": test_id,
                    "scan_type": "Generic Findings Import",
                    "scan_date": today,
                    "minimum_severity": "Info",
                    "verified": "false",
                    "active": "true",
                    "close_old_findings": "false",
                    "do_not_reactivate": "true",
                },
                upload=payload,
            )
            assert status == 201, f"Reimport failed ({status})"
            for _ in range(20):
                current = findings()
                if {item["id"] for item in current} == initial_ids:
                    return current
                time.sleep(1)
            raise AssertionError("Reimport changed identities or introduced duplicates")

        repeated = reimport(first)
        observations.append(
            {"case": "same-file-reimport", "findings": len(repeated), "ids_preserved": True}
        )
        corroborated, _ = export("--input", str(truffle))
        updated = reimport(corroborated)
        github = next(item for item in updated if item["file_path"] == "src/auth.py")
        # DefectDojo 3.4.0 retains the existing finding's triage fields on reimport.
        # Stable matching is separate from severity synchronization.
        assert github["severity"] == "High" and github["verified"] is False
        observations.append(
            {
                "case": "corroboration-reimport",
                "exported_severity": "Critical",
                "stored_severity": github["severity"],
                "requires_severity_review": True,
                "verified": github["verified"],
                "ids_preserved": True,
            }
        )
        waived, waived_json = export("--waivers", str(waivers))
        assert len(waived_json["findings"]) == 1
        remaining = reimport(waived)
        assert len(remaining) == 2 and all(item["active"] for item in remaining)
        observations.append(
            {
                "case": "waiver-omission-is-not-remediation",
                "exported": 1,
                "stored_active": 2,
                "close_old_findings": False,
            }
        )
        raw.write_text("[]", encoding="utf-8")
        empty, _ = export()
        remaining = reimport(empty)
        assert len(remaining) == 2 and all(item["active"] for item in remaining)
        observations.append(
            {"case": "empty-report-is-not-remediation", "exported": 0, "stored_active": 2}
        )

        status, critical_product = request(
            "products/",
            {
                "name": "secguard critical mapping " + suffix,
                "description": "Synthetic initial Critical mapping only",
                "prod_type": product_type["id"],
            },
        )
        assert status == 201
        status, critical_engagement = request(
            "engagements/",
            {
                "name": "Initial Critical import",
                "product": critical_product["id"],
                "target_start": today,
                "target_end": today,
            },
        )
        assert status == 201
        status, critical_import = request(
            "import-scan/",
            {
                "engagement": critical_engagement["id"],
                "scan_type": "Generic Findings Import",
                "scan_date": today,
                "minimum_severity": "Info",
                "verified": "false",
                "active": "true",
                "close_old_findings": "false",
            },
            upload=corroborated,
        )
        assert status == 201
        status, critical_rows = request(f"findings/?test={critical_import['test']}&limit=100")
        assert status == 200
        critical = next(
            item for item in critical_rows["results"] if item["file_path"] == "src/auth.py"
        )
        assert critical["severity"] == "Critical" and critical["verified"] is False
        observations.append(
            {"case": "initial-critical-import", "severity": "Critical", "verified": False}
        )

    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(
        json.dumps(
            {
                "schema": "secguard.defectdojo-validation/v1",
                "status": "PASS",
                "checked_at": datetime.now(UTC).isoformat(),
                "scope": "Owned local synthetic pilot only",
                "deduplication": {"secguard Scan (Generic Findings Import)": "unique_id_from_tool"},
                "compose_sha256": hashlib.sha256(compose.read_bytes()).hexdigest(),
                "product_id": product["id"],
                "engagement_id": engagement["id"],
                "test_id": test_id,
                "cases": observations,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"DefectDojo file handoff PASS: {len(observations)} cases")


if __name__ == "__main__":
    main()
