from pathlib import Path

from langgraph.graph import StateGraph

from state.devsecops_state import DevSecOpsState

from utils.llm import get_llm
from utils.prompt_loader import (
    load_prompt,
    load_application,
)

# =====================================================
# Project Paths
# =====================================================

BASE_DIR = Path(__file__).resolve().parent.parent

PROMPT_FILE = BASE_DIR / "prompts" / "threat_prompt.txt"

APPLICATION_FILE = BASE_DIR / "reports" / "application_description.md"

REPORT_FILE = BASE_DIR / "reports" / "threat_report.md"

# =====================================================
# Load Resources
# =====================================================

print("Loading Prompt...")

prompt_template = load_prompt(PROMPT_FILE)

print("Loading Application Description...")

application = load_application(APPLICATION_FILE)

print("Initializing Ollama...")

llm = get_llm()

print("LLM Initialized Successfully.\n")

# =====================================================
# LangGraph Node
# =====================================================


def analyze_application(state: DevSecOpsState):

    print("=" * 60)
    print("Threat Modeler Agent Started")
    print("=" * 60)

    prompt = prompt_template.format(
        application=state["application"]
    )

    print("Prompt Generated Successfully")

    print("Calling Ollama...")

    response = llm.invoke(prompt)

    print("Response Received.\n")

    return {

        "threat_report": response.content

    }


# =====================================================
# LangGraph Graph
# =====================================================

print("Building LangGraph...")

builder = StateGraph(DevSecOpsState)

builder.add_node(
    "ThreatModeler",
    analyze_application
)

builder.set_entry_point("ThreatModeler")

builder.set_finish_point("ThreatModeler")

graph = builder.compile()

print("Graph Built Successfully.\n")

# =====================================================
# Main
# =====================================================


def main():

    print("=" * 60)
    print("Running Threat Modeler")
    print("=" * 60)

    result = graph.invoke(

        {

            "application": application,

            "threat_report": "",

            "sast_report": "",

            "dependency_report": "",

            "dast_report": "",

            "container_report": "",

            "runtime_report": "",

            "compliance_report": ""

        }

    )

    print("\nThreat Model Generated Successfully\n")

    print(result["threat_report"])

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            result["threat_report"]
        )

    print("\nThreat Report Saved Successfully")

    print(f"Location : {REPORT_FILE}")


if __name__ == "__main__":

    main()