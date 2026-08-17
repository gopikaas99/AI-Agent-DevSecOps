import time
from pathlib import Path

from utils.llm import get_llm
from utils.report_writer import write_report


BASE_DIR = Path(__file__).resolve().parent.parent

FALCO_ALERT_FILE = BASE_DIR / "runtime" / "falco_alerts.txt"
PROMPT_FILE = BASE_DIR / "prompts" / "runtime_sentinel_prompt.txt"
REPORT_FILE = BASE_DIR / "reports" / "runtime_incident_report.md"


def load_text_file(file_path: Path) -> str:
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    return file_path.read_text(encoding="utf-8").strip()


def main() -> None:
    print("Loading Falco runtime alerts...")
    falco_alerts = load_text_file(FALCO_ALERT_FILE)

    print("Loading Runtime Sentinel prompt...")
    prompt_template = load_text_file(PROMPT_FILE)

    final_prompt = f"""
{prompt_template}

## Falco Runtime Alerts

{falco_alerts}

Additional instructions:

- Analyze only the alerts provided above.
- Do not invent incidents or evidence that is not present.
- Clearly distinguish between suspicious activity and confirmed malicious activity.
- If the activity could be legitimate administrative activity, mention that.
- Keep the final report concise and actionable.
"""

    print(f"Prompt size: {len(final_prompt)} characters")

    print("Initializing Ollama...")
    llm = get_llm()

    print("Sending Falco alert to Ollama...")
    print("This may take a few minutes when using llama3.1:8b on CPU.")

    start_time = time.perf_counter()

    try:
        response = llm.invoke(final_prompt)
    except Exception as error:
        print(f"Failed to generate runtime incident report: {error}")
        return

    elapsed_time = time.perf_counter() - start_time

    write_report(response.content, REPORT_FILE)

    print("\nRuntime incident report generated successfully.")
    print(f"Execution time: {elapsed_time:.2f} seconds")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()