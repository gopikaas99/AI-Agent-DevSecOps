import json
from pathlib import Path

from utils.llm import get_llm


CHECKOV_REPORT = Path("scans/checkov-k8s.json")
PROMPT_FILE = Path("prompts/policy_prompt.txt")
OUTPUT_REPORT = Path("reports/kubernetes_policy_report.md")


def load_json_report() -> dict | list:
    if not CHECKOV_REPORT.exists():
        raise FileNotFoundError(
            f"Checkov report not found: {CHECKOV_REPORT}"
        )

    with CHECKOV_REPORT.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_prompt() -> str:
    if not PROMPT_FILE.exists():
        raise FileNotFoundError(
            f"Prompt file not found: {PROMPT_FILE}"
        )

    return PROMPT_FILE.read_text(encoding="utf-8")


def extract_failed_checks(report: dict | list) -> list[dict]:
    """
    Checkov may return:
    1. A single dictionary
    2. A list of framework scan results

    This function handles both formats.
    """
    scan_results = report if isinstance(report, list) else [report]

    failed_checks = []

    for scan_result in scan_results:
        results = scan_result.get("results", {})
        checks = results.get("failed_checks", [])

        for check in checks:
            failed_checks.append(
                {
                    "check_id": check.get("check_id", "Unknown"),
                    "check_name": check.get("check_name", "Unknown"),
                    "resource": check.get("resource", "Unknown"),
                    "file_path": check.get("file_path", "Unknown"),
                    "file_line_range": check.get(
                        "file_line_range", []
                    ),
                    "guideline": check.get("guideline", ""),
                }
            )

    return failed_checks


def calculate_deployment_decision(failed_checks: list[dict]) -> str:
    """
    Checkov Kubernetes findings do not always include severity.
    For this lab, the decision is based on the number of failed checks.
    """
    failed_count = len(failed_checks)

    if failed_count >= 15:
        return "BLOCK"

    if failed_count >= 5:
        return "APPROVE WITH CHANGES"

    return "APPROVE"


def build_findings_text(failed_checks: list[dict]) -> str:
    if not failed_checks:
        return "No failed Checkov checks were found."

    lines = []

    for index, check in enumerate(failed_checks, start=1):
        line_range = check["file_line_range"]

        lines.extend(
            [
                f"Finding {index}",
                f"Check ID: {check['check_id']}",
                f"Check name: {check['check_name']}",
                f"Resource: {check['resource']}",
                f"File: {check['file_path']}",
                f"Line range: {line_range}",
                f"Guideline: {check['guideline'] or 'Not provided'}",
                "",
            ]
        )

    return "\n".join(lines)


def generate_policy_report(
    base_prompt: str,
    failed_checks: list[dict],
    deployment_decision: str,
) -> str:
    findings_text = build_findings_text(failed_checks)

    final_prompt = f"""
{base_prompt}

Checkov scan summary:

Failed checks: {len(failed_checks)}

Deployment decision calculated by the Policy Agent:
{deployment_decision}

Important instructions:

- Analyze only the failed checks listed below.
- Do not invent additional findings.
- Use the exact deployment decision calculated above.
- Explain recommendations in beginner-friendly language.
- Include practical Kubernetes YAML remediation examples where useful.

FAILED CHECKOV FINDINGS:

{findings_text}
"""

    print(f"Prompt size: {len(final_prompt)} characters")
    print("Sending findings to Ollama...")

    llm = get_llm()
    response = llm.invoke(final_prompt)

    return response.content


def save_report(report_content: str) -> None:
    OUTPUT_REPORT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_REPORT.write_text(report_content, encoding="utf-8")


def main() -> None:
    print("Loading Checkov Kubernetes report...")
    report = load_json_report()

    print("Extracting failed checks...")
    failed_checks = extract_failed_checks(report)

    print(f"Failed checks found: {len(failed_checks)}")

    deployment_decision = calculate_deployment_decision(
        failed_checks
    )

    print(
        f"Calculated deployment decision: "
        f"{deployment_decision}"
    )

    prompt = load_prompt()

    policy_report = generate_policy_report(
        prompt,
        failed_checks,
        deployment_decision,
    )

    save_report(policy_report)

    print("Kubernetes policy report generated successfully.")
    print(f"Report saved to: {OUTPUT_REPORT}")


if __name__ == "__main__":
    main()