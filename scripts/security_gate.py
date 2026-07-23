import json
import sys
from pathlib import Path

REPORT_DIR = Path("scans")

BANDIT_REPORT = REPORT_DIR / "bandit-ci.json"
SEMGREP_REPORT = REPORT_DIR / "semgrep-ci.json"
TRIVY_REPORT = REPORT_DIR / "trivy-sca-ci.json"


def read_json(path: Path) -> dict:
    if not path.exists():
        print(f"ERROR: Report not found: {path}")
        sys.exit(1)

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as error:
        print(f"ERROR: Invalid JSON in {path}: {error}")
        sys.exit(1)


def count_bandit_findings(report: dict) -> dict:
    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in report.get("results", []):
        severity = str(finding.get("issue_severity", "")).upper()

        if severity in counts:
            counts[severity] += 1

    return counts


def count_semgrep_findings(report: dict) -> dict:
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "WARNING": 0,
        "ERROR": 0,
    }

    for finding in report.get("results", []):
        severity = (
            finding.get("extra", {})
            .get("severity", "UNKNOWN")
            .upper()
        )

        if severity in counts:
            counts[severity] += 1

    return counts


def count_trivy_findings(report: dict) -> dict:
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for result in report.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = str(
                vulnerability.get("Severity", "UNKNOWN")
            ).upper()

            if severity in counts:
                counts[severity] += 1
            else:
                counts["UNKNOWN"] += 1

    return counts


def main() -> None:
    bandit = count_bandit_findings(read_json(BANDIT_REPORT))
    semgrep = count_semgrep_findings(read_json(SEMGREP_REPORT))
    trivy = count_trivy_findings(read_json(TRIVY_REPORT))

    print("\nSECURITY QUALITY GATE RESULTS")
    print("-----------------------------------")
    print(f"Bandit High:       {bandit['HIGH']}")
    print(f"Bandit Medium:     {bandit['MEDIUM']}")
    print(f"Semgrep Critical:  {semgrep['CRITICAL']}")
    print(f"Semgrep High:      {semgrep['HIGH']}")
    print(f"Trivy Critical:    {trivy['CRITICAL']}")
    print(f"Trivy High:        {trivy['HIGH']}")
    print("-----------------------------------")

    blocking_reasons = []

    if bandit["HIGH"] > 0:
        blocking_reasons.append(
            f"Bandit detected {bandit['HIGH']} high-severity issue(s)."
        )

    if semgrep["CRITICAL"] > 0:
        blocking_reasons.append(
            f"Semgrep detected {semgrep['CRITICAL']} critical issue(s)."
        )

    if semgrep["HIGH"] > 0:
        blocking_reasons.append(
            f"Semgrep detected {semgrep['HIGH']} high-severity issue(s)."
        )

    if trivy["CRITICAL"] > 0:
        blocking_reasons.append(
            f"Trivy detected {trivy['CRITICAL']} critical vulnerability(s)."
        )

    if blocking_reasons:
        print("\nDEPLOYMENT BLOCKED")

        for reason in blocking_reasons:
            print(f"- {reason}")

        sys.exit(1)

    print("\nQUALITY GATE PASSED")
    print("No blocking security findings were detected.")
    print("Deployment may continue.")

    sys.exit(0)


if __name__ == "__main__":
    main()