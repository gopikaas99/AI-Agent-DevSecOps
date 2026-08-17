import json
import time
from pathlib import Path
from typing import Any

from utils.llm import get_llm
from utils.parser import load_json
from utils.report_writer import write_report


BASE_DIR = Path(__file__).resolve().parent.parent

TRIVY_FILE = BASE_DIR / "scans" / "container-trivy.json"
PROMPT_FILE = BASE_DIR / "prompts" / "container_hardener_prompt.txt"
REPORT_FILE = BASE_DIR / "reports" / "container_security_report.md"


def load_prompt() -> str:
    """
    Load the Container Hardener prompt template.
    """

    with open(PROMPT_FILE, "r", encoding="utf-8") as file:
        return file.read()


def normalize_fixed_version(value: Any) -> str:
    """
    Convert Trivy's FixedVersion field into a readable string.

    Trivy may return:
    - an empty string,
    - a normal string,
    - or another unexpected value.
    """

    if not value:
        return "No fixed version currently available"

    return str(value)


def extract_trivy_findings(trivy_report: dict) -> dict:
    """
    Extract a compact summary from the Trivy report.

    All vulnerabilities are counted.

    Only CRITICAL and HIGH findings are included in detail because sending
    every MEDIUM and LOW finding would make the LLM prompt unnecessarily large.
    """

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    prioritized_findings = []

    for result in trivy_report.get("Results", []):
        target = result.get("Target", "Unknown")
        target_class = result.get("Class", "Unknown")
        target_type = result.get("Type", "Unknown")

        vulnerabilities = result.get("Vulnerabilities") or []

        for vulnerability in vulnerabilities:
            severity = str(
                vulnerability.get("Severity", "UNKNOWN")
            ).upper()

            if severity not in severity_counts:
                severity = "UNKNOWN"

            severity_counts[severity] += 1

            # Send only Critical and High details to the LLM.
            if severity not in {"CRITICAL", "HIGH"}:
                continue

            prioritized_findings.append(
                {
                    "target": target,
                    "target_class": target_class,
                    "target_type": target_type,
                    "vulnerability_id": vulnerability.get(
                        "VulnerabilityID",
                        "Unknown",
                    ),
                    "package_name": vulnerability.get(
                        "PkgName",
                        "Unknown",
                    ),
                    "installed_version": vulnerability.get(
                        "InstalledVersion",
                        "Unknown",
                    ),
                    "fixed_version": normalize_fixed_version(
                        vulnerability.get("FixedVersion")
                    ),
                    "severity": severity,
                    "title": vulnerability.get(
                        "Title",
                        "No title provided",
                    ),
                }
            )

    total_vulnerabilities = sum(severity_counts.values())

    metadata = trivy_report.get("Metadata", {})
    os_information = metadata.get("OS") or {}

    return {
        "artifact_name": trivy_report.get(
            "ArtifactName",
            "Unknown",
        ),
        "artifact_type": trivy_report.get(
            "ArtifactType",
            "Unknown",
        ),
        "operating_system": {
            "family": os_information.get("Family", "Unknown"),
            "name": os_information.get("Name", "Unknown"),
        },
        "total_vulnerabilities": total_vulnerabilities,
        "severity_summary": severity_counts,
        "prioritized_findings_count": len(prioritized_findings),
        "prioritized_findings": prioritized_findings,
    }


def determine_deployment_decision(severity_summary: dict) -> dict:
    """
    Apply a deterministic security quality gate.

    Current course rule:

    - BLOCK when one or more Critical vulnerabilities exist.
    - BLOCK when one or more High vulnerabilities exist.
    - Otherwise ALLOW.
    """

    critical_count = severity_summary.get("CRITICAL", 0)
    high_count = severity_summary.get("HIGH", 0)

    if critical_count > 0:
        return {
            "decision": "BLOCK",
            "reason": (
                f"The image contains {critical_count} Critical "
                "vulnerability or vulnerabilities."
            ),
        }

    if high_count > 0:
        return {
            "decision": "BLOCK",
            "reason": (
                f"The image contains {high_count} High-severity "
                "vulnerability or vulnerabilities."
            ),
        }

    return {
        "decision": "ALLOW",
        "reason": (
            "The image contains no Critical or High-severity vulnerabilities."
        ),
    }


def main() -> None:
    print("Loading Trivy container image report...")

    try:
        trivy_report = load_json(TRIVY_FILE)
    except FileNotFoundError:
        print(f"Trivy report not found: {TRIVY_FILE}")
        print(
            "Run the Trivy image scan before executing "
            "the Container Hardener Agent."
        )
        return
    except json.JSONDecodeError as error:
        print(f"Invalid JSON in Trivy report: {error}")
        return
    except Exception as error:
        print(f"Unable to load the Trivy report: {error}")
        return

    print("Extracting and prioritizing vulnerabilities...")
    extracted_data = extract_trivy_findings(trivy_report)

    severity_summary = extracted_data["severity_summary"]

    print(
        f"Total vulnerabilities: "
        f"{extracted_data['total_vulnerabilities']}"
    )
    print(f"Critical: {severity_summary['CRITICAL']}")
    print(f"High: {severity_summary['HIGH']}")
    print(f"Medium: {severity_summary['MEDIUM']}")
    print(f"Low: {severity_summary['LOW']}")
    print(
        "Detailed Critical and High findings sent to the LLM: "
        f"{extracted_data['prioritized_findings_count']}"
    )

    deployment_gate = determine_deployment_decision(
        severity_summary
    )

    extracted_data["deployment_gate"] = deployment_gate

    print(
        "Calculated deployment decision: "
        f"{deployment_gate['decision']}"
    )

    print("Loading Container Hardener prompt...")

    try:
        prompt_template = load_prompt()
    except FileNotFoundError:
        print(f"Prompt file not found: {PROMPT_FILE}")
        return
    except Exception as error:
        print(f"Unable to load the prompt: {error}")
        return

    findings_text = json.dumps(
        extracted_data,
        indent=2,
        ensure_ascii=False,
    )

    final_prompt = f"""
{prompt_template}

## Verified Trivy scan data

{findings_text}

## Mandatory rules

1. Use only the supplied scan data.
2. Do not invent vulnerabilities, versions or package names.
3. Do not include MEDIUM or LOW findings in the detailed findings table.
4. MEDIUM and LOW vulnerabilities may be mentioned only in the summary counts.
5. Do not recommend replacing the current Python image with an older Python version.
6. Do not recommend changing the image to ubuntu:latest.
7. Do not claim that installing a development package automatically fixes a CVE.
8. Use the deployment decision already calculated by the Python security gate.
9. Return only one deployment decision: ALLOW or BLOCK.
10. Do not repeat the raw JSON.
"""

    print(f"Prompt size: {len(final_prompt)} characters")
    print("Initializing Ollama...")

    try:
        llm = get_llm()
    except Exception as error:
        print(f"Failed to initialize Ollama: {error}")
        return

    print("Sending prioritized container findings to Ollama...")
    print(
        "Only Critical and High findings are being sent in detail."
    )

    start_time = time.perf_counter()

    try:
        response = llm.invoke(final_prompt)
    except Exception as error:
        print(
            "Failed to generate the container security report: "
            f"{error}"
        )
        return

    elapsed_time = time.perf_counter() - start_time

    try:
        write_report(response.content, REPORT_FILE)
    except Exception as error:
        print(f"Failed to save the report: {error}")
        return

    print("\nContainer security report generated successfully.")
    print(f"Execution time: {elapsed_time:.2f} seconds")
    print(f"Report location: {REPORT_FILE}")


if __name__ == "__main__":
    main()