from pathlib import Path
from langgraph.graph import StateGraph, START, END
from typing import TypedDict
from utils.llm import get_llm
from utils.prompt_loader import load_prompt


# -----------------------------
# State
# -----------------------------
class PipelineState(TypedDict):
    findings: str
    report: str


# -----------------------------
# Read Scan Reports
# -----------------------------
def load_security_reports(state: PipelineState):
    reports = []

    report_files = [
        "reports/bandit_report.txt",
        "reports/detect_secrets_report.txt",
        "reports/zap_report.txt"
    ]

    for file in report_files:
        path = Path(file)
        if path.exists():
            reports.append(f"\n===== {path.name} =====\n")
            reports.append(path.read_text())

    return {"findings": "\n".join(reports)}


# -----------------------------
# Generate AI Report
# -----------------------------
def generate_pipeline_report(state: PipelineState):

    llm = get_llm()

    prompt = load_prompt("prompts/pipeline_guard_prompt.txt")

    final_prompt = f"""
{prompt}

Security Scan Results:

{state['findings']}
"""

    response = llm.invoke(final_prompt)

    return {"report": response.content}


# -----------------------------
# Save Report
# -----------------------------
def save_report(state: PipelineState):

    report_path = Path("reports")
    report_path.mkdir(exist_ok=True)

    output_file = report_path / "pipeline_security_report.md"

    output_file.write_text(state["report"])

    print(f"\n Pipeline report saved to {output_file}")

    return state


# -----------------------------
# Build Graph
# -----------------------------
builder = StateGraph(PipelineState)

builder.add_node("LoadReports", load_security_reports)
builder.add_node("GenerateReport", generate_pipeline_report)
builder.add_node("SaveReport", save_report)

builder.add_edge(START, "LoadReports")
builder.add_edge("LoadReports", "GenerateReport")
builder.add_edge("GenerateReport", "SaveReport")
builder.add_edge("SaveReport", END)

graph = builder.compile()


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":

    print("Loading Security Reports...")

    graph.invoke(
        {
            "findings": "",
            "report": ""
        }
    )

    print("\nPipeline Guard Agent Completed Successfully.")