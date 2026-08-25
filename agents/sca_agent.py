import json
from pathlib import Path
from typing import Any
from utils.llm import get_llm

from langchain_ollama import ChatOllama


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SNYK_REPORT_PATH = PROJECT_ROOT / "scans" / "snyk.json"
PROMPT_PATH = PROJECT_ROOT / "prompts" / "sca_prompt.txt"
OUTPUT_PATH = PROJECT_ROOT / "reports" / "sca_report.md"


def load_snyk_report(path: Path) -> dict[str, Any] | list[Any]:
    """Load and validate the Snyk JSON report."""

    if not path.exists():
        raise FileNotFoundError(f"Snyk report was not found at: {path}")

    content = path.read_text(encoding="utf-8").strip()

    if not content:
        raise ValueError("The Snyk report is empty.")

    try:
        return json.loads(content)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"The Snyk report is not valid JSON: {error}"
        ) from error


def extract_vulnerabilities(
    report: dict[str, Any] | list[Any]
) -> list[dict[str, Any]]:
    """Extract vulnerabilities from common Snyk JSON formats."""

    vulnerabilities: list[dict[str, Any]] = []

    if isinstance(report, dict):
        direct_findings = report.get("vulnerabilities", [])

        if isinstance(direct_findings, list):
            vulnerabilities.extend(direct_findings)

        # Some Snyk outputs contain multiple project results.
        results = report.get("results", [])

        if isinstance(results, list):
            for result in results:
                if not isinstance(result, dict):
                    continue

                result_findings = result.get("vulnerabilities", [])

                if isinstance(result_findings, list):
                    vulnerabilities.extend(result_findings)

    elif isinstance(report, list):
        for project_result in report:
            if not isinstance(project_result, dict):
                continue

            project_findings = project_result.get("vulnerabilities", [])

            if isinstance(project_findings, list):
                vulnerabilities.extend(project_findings)

    return vulnerabilities


def normalize_vulnerability(
    vulnerability: dict[str, Any]
) -> dict[str, str]:
    """Keep only useful fields before sending data to Ollama."""

    identifiers = vulnerability.get("identifiers", {})

    if not isinstance(identifiers, dict):
        identifiers = {}

    cves = identifiers.get("CVE", [])
    cwes = identifiers.get("CWE", [])

    if not isinstance(cves, list):
        cves = [str(cves)]

    if not isinstance(cwes, list):
        cwes = [str(cwes)]

    upgrade_path = vulnerability.get("upgradePath", [])

    if not isinstance(upgrade_path, list):
        upgrade_path = [str(upgrade_path)]

    from_path = vulnerability.get("from", [])

    if not isinstance(from_path, list):
        from_path = [str(from_path)]

    return {
        "title": str(
            vulnerability.get("title")
            or vulnerability.get("name")
            or vulnerability.get("id")
            or "Unknown vulnerability"
        ),
        "severity": str(vulnerability.get("severity") or "Unknown"),
        "package": str(
            vulnerability.get("packageName")
            or vulnerability.get("package")
            or vulnerability.get("name")
            or "Unknown package"
        ),
        "version": str(
            vulnerability.get("version")
            or vulnerability.get("packageVersion")
            or "Unknown"
        ),
        "id": str(vulnerability.get("id") or "Not specified"),
        "cves": ", ".join(str(item) for item in cves) or "Not specified",
        "cwes": ", ".join(str(item) for item in cwes) or "Not specified",
        "dependency_path": " > ".join(
            str(item) for item in from_path
        ) or "Not specified",
        "upgrade_path": " > ".join(
            str(item) for item in upgrade_path if item
        ) or "No upgrade path provided",
        "fixed_in": ", ".join(
            str(item) for item in vulnerability.get("fixedIn", [])
        ) if isinstance(vulnerability.get("fixedIn"), list)
        else str(vulnerability.get("fixedIn") or "Not specified"),
        "description": str(
            vulnerability.get("description")
            or vulnerability.get("overview")
            or "Not provided"
        ),
        "is_upgradable": str(
            vulnerability.get("isUpgradable", "Unknown")
        ),
        "is_patchable": str(
            vulnerability.get("isPatchable", "Unknown")
        ),
    }


def remove_duplicates(
    vulnerabilities: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Remove duplicate Snyk findings."""

    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for vulnerability in vulnerabilities:
        normalized = normalize_vulnerability(vulnerability)

        key = (
            normalized["id"].lower(),
            normalized["package"].lower(),
            normalized["version"].lower(),
        )

        if key not in seen:
            seen.add(key)
            unique.append(normalized)

    return unique


def format_findings(
    vulnerabilities: list[dict[str, str]]
) -> str:
    """Convert vulnerabilities into compact text for the LLM."""

    sections: list[str] = []

    for index, vulnerability in enumerate(vulnerabilities, start=1):
        sections.append(
            f"""
Finding {index}
Title: {vulnerability["title"]}
Snyk ID: {vulnerability["id"]}
Severity: {vulnerability["severity"]}
Package: {vulnerability["package"]}
Installed Version: {vulnerability["version"]}
Dependency Path: {vulnerability["dependency_path"]}
CVEs: {vulnerability["cves"]}
CWEs: {vulnerability["cwes"]}
Fixed In: {vulnerability["fixed_in"]}
Upgrade Path: {vulnerability["upgrade_path"]}
Upgradable: {vulnerability["is_upgradable"]}
Patchable: {vulnerability["is_patchable"]}
Description: {vulnerability["description"]}
""".strip()
        )

    return "\n\n".join(sections)


def generate_sca_report() -> None:
    print("Loading Snyk report...")

    snyk_report = load_snyk_report(SNYK_REPORT_PATH)
    raw_vulnerabilities = extract_vulnerabilities(snyk_report)

    print(f"Total Snyk findings: {len(raw_vulnerabilities)}")

    unique_vulnerabilities = remove_duplicates(raw_vulnerabilities)

    print(
        f"Unique dependency findings selected: "
        f"{len(unique_vulnerabilities)}"
    )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    if not unique_vulnerabilities:
        OUTPUT_PATH.write_text(
            """# AI-Assisted SCA Security Report

## Scan summary

- **Scanner:** Snyk
- **Source file:** `scans/snyk.json`
- **Total vulnerability findings:** 0
- **Result:** No known vulnerable dependencies were reported by Snyk.

> This result applies only to the dependencies and database state used during this scan.
""",
            encoding="utf-8",
        )

        print("No Snyk vulnerabilities were found.")
        print(f"Report generated at: {OUTPUT_PATH}")
        return

    if not PROMPT_PATH.exists():
        raise FileNotFoundError(
            f"SCA prompt was not found at: {PROMPT_PATH}"
        )

    print("Loading SCA prompt...")

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    findings_text = format_findings(unique_vulnerabilities)
    final_prompt = prompt_template.replace("{findings}", findings_text)

    print("Initializing Ollama LLM...")

    llm = get_llm()

    print("Sending dependency findings to Ollama...")

    response = llm.invoke(final_prompt)

    report_header = f"""# AI-Assisted SCA Security Report

## Scan summary

- **Scanner:** Snyk
- **Source file:** `scans/snyk.json`
- **Total vulnerability instances:** {len(raw_vulnerabilities)}
- **Unique findings analyzed:** {len(unique_vulnerabilities)}
- **Analysis model:** Ollama

---

"""

    OUTPUT_PATH.write_text(
        report_header + str(response.content),
        encoding="utf-8",
    )

    print("SCA analysis completed successfully.")
    print(f"Report generated at: {OUTPUT_PATH}")


if __name__ == "__main__":
    try:
        generate_sca_report()
    except Exception as error:
        print(f"SCA Agent failed: {error}")
        raise