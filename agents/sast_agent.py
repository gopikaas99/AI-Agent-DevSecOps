import json
import time
from pathlib import Path

from utils.llm import get_llm
from utils.parser import (
    extract_bandit_findings,
    extract_semgrep_findings,
    load_json,
)
from utils.report_writer import write_report


BASE_DIR = Path(__file__).resolve().parent.parent

BANDIT_FILE = BASE_DIR / "scans" / "bandit.json"
SEMGREP_FILE = BASE_DIR / "scans" / "semgrep.json"
PROMPT_FILE = BASE_DIR / "prompts" / "sast_prompt.txt"
REPORT_FILE = BASE_DIR / "reports" / "sast_report.md"


def load_prompt() -> str:
    with open(PROMPT_FILE, "r", encoding="utf-8") as file:
        return file.read()


def main() -> None:
    print("Loading Bandit report...")
    bandit_report = load_json(BANDIT_FILE)

    print("Loading Semgrep report...")
    semgrep_report = load_json(SEMGREP_FILE)

    print("Extracting relevant findings...")
    bandit_findings = extract_bandit_findings(bandit_report)
    semgrep_findings = extract_semgrep_findings(semgrep_report)

    combined_findings = {
        "bandit_findings": bandit_findings,
        "semgrep_findings": semgrep_findings,
    }

    print(f"Bandit findings: {len(bandit_findings)}")
    print(f"Semgrep findings: {len(semgrep_findings)}")

    prompt_template = load_prompt()

    findings_text = json.dumps(
        combined_findings,
        indent=2,
        ensure_ascii=False,
    )

    final_prompt = f"""
{prompt_template}

## Scan findings

{findings_text}

Keep the report concise. Merge duplicate findings reported by both tools.
Do not repeat raw JSON in the response.
"""

    print(f"Prompt size: {len(final_prompt)} characters")
    print("Initializing Ollama...")
    llm = get_llm()

    print("Sending summarized findings to Ollama...")
    print("This may take one or two minutes when running an 8B model on CPU.")

    start_time = time.perf_counter()

    try:
        response = llm.invoke(final_prompt)
    except Exception as error:
        print(f"Failed to generate the SAST report: {error}")
        return

    elapsed_time = time.perf_counter() - start_time

    write_report(response.content, REPORT_FILE)

    print("\nSAST report generated successfully.")
    print(f"Execution time: {elapsed_time:.2f} seconds")
    print(f"Report location: {REPORT_FILE}")


if __name__ == "__main__":
    main()