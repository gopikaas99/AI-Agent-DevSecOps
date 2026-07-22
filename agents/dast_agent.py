import json
from pathlib import Path
from typing import Any

from langchain_ollama import ChatOllama


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ZAP_REPORT_PATH = PROJECT_ROOT / "scans" / "zap_report.json"
PROMPT_PATH = PROJECT_ROOT / "prompts" / "dast_prompt.txt"
OUTPUT_PATH = PROJECT_ROOT / "reports" / "dast_report.md"


def load_json_report(path: Path) -> dict[str, Any]:
    """Load and validate the OWASP ZAP JSON report."""

    if not path.exists():
        raise FileNotFoundError(
            f"ZAP report was not found at: {path}"
        )

    raw_content = path.read_text(encoding="utf-8").strip()

    if not raw_content:
        raise ValueError("The ZAP JSON report is empty.")

    if raw_content.startswith("<!DOCTYPE") or raw_content.startswith("<html"):
        raise ValueError(
            "The report contains HTML, not JSON. "
            "Generate a real JSON report from the ZAP API."
        )

    try:
        return json.loads(raw_content)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"The ZAP report is not valid JSON: {error}"
        ) from error


def extract_alerts(report: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract alerts from common OWASP ZAP JSON formats.

    Supports:
    1. Full report:
       {"site": [{"alerts": [...]}]}

    2. Alerts API:
       {"alerts": [...]}
    """

    extracted_alerts: list[dict[str, Any]] = []

    # Format produced by /JSON/core/view/alerts/
    if isinstance(report.get("alerts"), list):
        extracted_alerts.extend(report["alerts"])

    # Format produced by the full JSON report
    sites = report.get("site", [])

    if isinstance(sites, dict):
        sites = [sites]

    if isinstance(sites, list):
        for site in sites:
            if not isinstance(site, dict):
                continue

            alerts = site.get("alerts", [])

            if isinstance(alerts, dict):
                alerts = [alerts]

            if isinstance(alerts, list):
                extracted_alerts.extend(alerts)

    return extracted_alerts


def normalize_alert(alert: dict[str, Any]) -> dict[str, str]:
    """Select only useful fields before sending findings to the LLM."""

    return {
        "name": str(
            alert.get("name")
            or alert.get("alert")
            or alert.get("alertRef")
            or "Unknown finding"
        ),
        "risk": str(
            alert.get("riskdesc")
            or alert.get("risk")
            or alert.get("riskcode")
            or "Unknown"
        ),
        "confidence": str(
            alert.get("confidence")
            or alert.get("confidenceLevel")
            or "Unknown"
        ),
        "url": str(
            alert.get("url")
            or alert.get("uri")
            or "Not specified"
        ),
        "method": str(alert.get("method") or "Not specified"),
        "parameter": str(
            alert.get("param")
            or alert.get("parameter")
            or "Not specified"
        ),
        "evidence": str(alert.get("evidence") or "Not provided"),
        "description": str(
            alert.get("description")
            or alert.get("desc")
            or "Not provided"
        ),
        "solution": str(alert.get("solution") or "Not provided"),
        "cwe_id": str(
            alert.get("cweid")
            or alert.get("cweId")
            or "Not specified"
        ),
        "wasc_id": str(
            alert.get("wascid")
            or alert.get("wascId")
            or "Not specified"
        ),
    }


def remove_duplicates(
    alerts: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """
    Remove repeated findings using the finding name, URL and parameter.
    """

    unique_alerts: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for alert in alerts:
        normalized = normalize_alert(alert)

        key = (
            normalized["name"].lower(),
            normalized["url"].lower(),
            normalized["parameter"].lower(),
        )

        if key not in seen:
            seen.add(key)
            unique_alerts.append(normalized)

    return unique_alerts


def format_findings(alerts: list[dict[str, str]]) -> str:
    """Convert the findings into compact text for Ollama."""

    sections: list[str] = []

    for index, alert in enumerate(alerts, start=1):
        sections.append(
            f"""
Finding {index}
Name: {alert["name"]}
Risk: {alert["risk"]}
Confidence: {alert["confidence"]}
URL: {alert["url"]}
HTTP Method: {alert["method"]}
Parameter: {alert["parameter"]}
Evidence: {alert["evidence"]}
Description: {alert["description"]}
Scanner Solution: {alert["solution"]}
CWE ID: {alert["cwe_id"]}
WASC ID: {alert["wasc_id"]}
""".strip()
        )

    return "\n\n".join(sections)


def generate_dast_report() -> None:
    print("Loading OWASP ZAP report...")

    zap_report = load_json_report(ZAP_REPORT_PATH)
    raw_alerts = extract_alerts(zap_report)

    if not raw_alerts:
        raise ValueError(
            "No alerts were found in zap_report.json. "
            "Check the report structure and scan results."
        )

    unique_alerts = remove_duplicates(raw_alerts)

    print(f"Total ZAP alert instances: {len(raw_alerts)}")
    print(f"Unique findings selected: {len(unique_alerts)}")

    findings_text = format_findings(unique_alerts)

    print("Loading DAST prompt...")

    if not PROMPT_PATH.exists():
        raise FileNotFoundError(
            f"DAST prompt was not found at: {PROMPT_PATH}"
        )

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    final_prompt = prompt_template.replace(
        "{findings}",
        findings_text,
    )

    print("Initializing Ollama LLM...")

    llm = ChatOllama(
        model="llama3.1:8b",
        temperature=0.1,
    )

    print("Sending ZAP findings to Ollama...")

    response = llm.invoke(final_prompt)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    report_header = f"""# AI-Assisted DAST Security Report

## Scan summary

- **Scanner:** OWASP ZAP
- **Source file:** `scans/zap_report.json`
- **Total alert instances:** {len(raw_alerts)}
- **Unique findings analyzed:** {len(unique_alerts)}
- **Analysis model:** Ollama `llama3.1:8b`

---

"""

    OUTPUT_PATH.write_text(
        report_header + response.content,
        encoding="utf-8",
    )

    print("DAST analysis completed successfully.")
    print(f"Report generated at: {OUTPUT_PATH}")


if __name__ == "__main__":
    try:
        generate_dast_report()
    except Exception as error:
        print(f"DAST Agent failed: {error}")
        raise