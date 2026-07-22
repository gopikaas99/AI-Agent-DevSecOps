from typing import TypedDict


class DevSecOpsState(TypedDict):
    application: str

    threat_report: str

    sast_report: str

    dependency_report: str

    dast_report: str

    container_report: str

    runtime_report: str

    compliance_report: str