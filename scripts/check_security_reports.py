"""Fail-closed checks for the SARIF, Trivy and Scorecard reports used by this CI."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

SCORECARD_MINIMUMS = {
    "Binary-Artifacts": 10,
    "Dangerous-Workflow": 10,
    "License": 9,
    "Security-Policy": 10,
    "Token-Permissions": 10,
}
BLOCKING_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}


def read_report(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    return report


def check_sarif(report: dict, expected_tool: str) -> int:
    if report.get("version") != "2.1.0":
        raise ValueError("expected SARIF 2.1.0")
    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF has no analysis runs")
    blocking = 0
    for run in runs:
        driver = run["tool"]["driver"]
        if expected_tool.casefold() not in driver["name"].casefold():
            raise ValueError("unexpected SARIF producer")
        extensions = run["tool"].get("extensions", [])
        components = [driver, *extensions]
        rules = [rule for component in components for rule in component.get("rules", [])]
        if expected_tool.casefold() == "codeql" and not rules:
            raise ValueError("SARIF has no analyzed rules")
        if expected_tool.casefold() == "zizmor" and not any(
            invocation.get("executionSuccessful") is True
            for invocation in run.get("invocations", [])
        ):
            raise ValueError("zizmor did not confirm successful analysis")
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                raise ValueError("scanner execution failed")
            notifications = invocation.get("toolExecutionNotifications", [])
            if any(item.get("level") == "error" for item in notifications):
                raise ValueError("scanner reported an execution error")
        results = run.get("results")
        if not isinstance(results, list):
            raise ValueError("SARIF results are missing")
        indexed = {rule["id"]: rule for rule in rules}
        for result in results:
            descriptor = result.get("rule", {})
            rule = indexed.get(result.get("ruleId", descriptor.get("id")))
            component_ref = descriptor.get("toolComponent", {})
            if "index" in component_ref:
                component_index = component_ref["index"]
                if not isinstance(component_index, int) or not 0 <= component_index < len(
                    extensions
                ):
                    raise ValueError("invalid SARIF tool component")
                component_rules = extensions[component_index].get("rules", [])
            else:
                component_rules = driver.get("rules", [])
            index = descriptor.get("index", result.get("ruleIndex"))
            if index is not None:
                if not isinstance(index, int) or not 0 <= index < len(component_rules):
                    raise ValueError("invalid SARIF rule index")
                rule = component_rules[index]
                if rule["id"] != result.get("ruleId", descriptor.get("id", rule["id"])):
                    raise ValueError("inconsistent SARIF rule reference")
            if rule is None and expected_tool.casefold() == "zizmor" and result.get("ruleId"):
                rule = {"id": result["ruleId"]}
            if rule is None:
                raise ValueError("result references an unknown rule")
            score = rule.get("properties", {}).get("security-severity")
            if score is not None:
                number = float(score)
                if not math.isfinite(number) or not 0 <= number <= 10:
                    raise ValueError("invalid security severity")
                blocking += number >= 4
            else:
                level = result.get(
                    "level", rule.get("defaultConfiguration", {}).get("level", "warning")
                )
                if level not in {"error", "warning", "note", "none"}:
                    raise ValueError("unknown SARIF severity")
                blocking += level in {"error", "warning"}
    return blocking


def check_trivy_dependencies(report: dict) -> int:
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Trivy has no dependency targets")
    packages = sum(len(target.get("Packages", [])) for target in results)
    if packages == 0:
        raise ValueError("Trivy examined no packages; --list-all-pkgs is required")
    blocking = 0
    for target in results:
        for finding in target.get("Vulnerabilities", []):
            severity = finding.get("Severity")
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
                raise ValueError("unknown vulnerability severity")
            blocking += severity in BLOCKING_SEVERITIES
    print(f"Trivy inventory: {packages} resolved packages")
    return blocking


def check_scorecard(report: dict) -> int:
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("Scorecard checks are missing")
    indexed = {}
    for check in checks:
        if check["name"] in indexed:
            raise ValueError("duplicate Scorecard check")
        indexed[check["name"]] = check
    failures = 0
    for name, minimum in SCORECARD_MINIMUMS.items():
        check = indexed.get(name)
        if check is None:
            raise ValueError(f"Scorecard did not evaluate {name}")
        score = check.get("score")
        if not isinstance(score, (float, int)) or not 0 <= score <= 10:
            raise ValueError(f"Scorecard could not evaluate {name}")
        print(f"{name}: {score}/10; required {minimum}/10")
        failures += score < minimum
    return failures


def sanitize_trivy_secrets(report: dict, scanner_status: int) -> dict:
    if (
        report.get("SchemaVersion") != 2
        or report.get("ArtifactType") != "filesystem"
        or not isinstance(report.get("ArtifactName"), str)
        or not report["ArtifactName"]
    ):
        raise ValueError("missing Trivy filesystem producer metadata")
    results = report.get("Results")
    # Trivy's Report.Results has json:",omitempty"; a clean scan omits this field.
    if results is None:
        results = []
    if not isinstance(results, list):
        raise ValueError("Trivy secret results are missing")
    findings = []
    for target in results:
        for secret in target.get("Secrets", []):
            severity = secret.get("Severity")
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
                raise ValueError("unknown secret severity")
            findings.append({"rule": secret["RuleID"], "severity": severity})
    blocking = sum(item["severity"] in BLOCKING_SEVERITIES for item in findings)
    return {
        "scanner_status": scanner_status,
        "finding_count": len(findings),
        "blocking_count": blocking,
        "findings": findings,
        "verdict": "PASS" if scanner_status == 0 and blocking == 0 else "BLOCK",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "kind", choices=("sarif", "trivy-dependencies", "scorecard", "trivy-secrets")
    )
    parser.add_argument("report", type=Path)
    parser.add_argument("--tool")
    parser.add_argument("--scanner-status", type=int)
    parser.add_argument("--sanitized-output", type=Path)
    args = parser.parse_args()
    try:
        report = read_report(args.report)
        if args.kind == "sarif":
            if not args.tool:
                raise ValueError("expected SARIF producer is required")
            count = check_sarif(report, args.tool)
        elif args.kind == "trivy-dependencies":
            count = check_trivy_dependencies(report)
        elif args.kind == "scorecard":
            count = check_scorecard(report)
        else:
            if args.scanner_status is None or args.sanitized_output is None:
                raise ValueError("scanner status and sanitized output are required")
            summary = sanitize_trivy_secrets(report, args.scanner_status)
            args.sanitized_output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            if summary["verdict"] != "PASS":
                raise ValueError("secret scan failed or reported blocking findings")
            # Keep derived secret data out of the console; counts stay in the artifact.
            print("trivy-secrets: PASS")
            return 0
        print(f"{args.kind}: {'BLOCK' if count else 'PASS'}; blocking findings/checks: {count}")
        return 1 if count else 0
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        # Do not print malformed report contents: a secret scanner's raw output can contain a token.
        print(f"{args.kind}: ERROR; invalid, incomplete or failing security report")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
