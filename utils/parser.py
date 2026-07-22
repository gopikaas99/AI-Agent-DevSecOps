import json
from pathlib import Path
from typing import Any


def load_json(file_path: Path) -> dict[str, Any]:
    """Load a JSON file and return its content."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def extract_bandit_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract only useful security information from Bandit output."""

    findings = []

    for item in report.get("results", []):
        findings.append(
            {
                "tool": "Bandit",
                "rule_id": item.get("test_id"),
                "rule_name": item.get("test_name"),
                "description": item.get("issue_text"),
                "severity": item.get("issue_severity"),
                "confidence": item.get("issue_confidence"),
                "file": item.get("filename"),
                "line": item.get("line_number"),
                "code": item.get("code"),
                "cwe": item.get("issue_cwe", {}).get("id"),
            }
        )

    return findings


def extract_semgrep_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract only useful security information from Semgrep output."""

    findings = []

    for item in report.get("results", []):
        extra = item.get("extra", {})

        findings.append(
            {
                "tool": "Semgrep",
                "rule_id": item.get("check_id"),
                "description": extra.get("message"),
                "severity": extra.get("severity"),
                "file": item.get("path"),
                "line": item.get("start", {}).get("line"),
                "code": extra.get("lines"),
            }
        )

    return findings