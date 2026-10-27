import json
import os
from datetime import datetime


REPORT_DIRECTORY = "reports/incidents"


def get_recommended_actions(incident):
    """
    Generate investigation actions based on incident severity/type.
    """

    incident_type = incident["incident_type"]
    severity = incident["severity"]

    actions = []

    # --------------------------------------------------------
    # Brute-force attack
    # --------------------------------------------------------

    if incident_type in (
        "BRUTE_FORCE_LOGIN_ATTEMPT",
        "WINDOWS_BRUTE_FORCE"
    ):

        actions.extend([
            "Review failed login attempts from the source IP.",
            "Check whether the source IP is authorized.",
            "Consider temporarily blocking the suspicious source IP.",
            "Review the affected account for unauthorized access."
        ])

    # --------------------------------------------------------
    # Administrator login
    # --------------------------------------------------------

    if incident_type == "ADMINISTRATOR_LOGIN":

        actions.extend([
            "Verify whether the administrator login was authorized.",
            "Review the administrator account activity.",
            "Review authentication logs around the login time."
        ])

    # --------------------------------------------------------
    # Privilege assignment
    # --------------------------------------------------------

    if incident_type == "SPECIAL_PRIVILEGES_ASSIGNED":

        actions.extend([
            "Verify whether elevated privileges were authorized.",
            "Review the account's recent authentication activity.",
            "Check for unauthorized privilege escalation."
        ])

    # --------------------------------------------------------
    # Process creation
    # --------------------------------------------------------

    if incident_type == "PROCESS_CREATION":

        actions.extend([
            "Identify and investigate the created process.",
            "Review the process execution context.",
            "Check whether the process was expected on the server."
        ])

    # --------------------------------------------------------
    # Correlated attack
    # --------------------------------------------------------

    if incident_type == "CORRELATED_PRIVILEGED_ATTACK":

        actions.extend([
            "Immediately investigate the affected privileged account.",
            "Review the complete authentication timeline.",
            "Investigate the source IP for additional suspicious activity.",
            "Review the process created after successful authentication.",
            "Verify whether privilege assignment was authorized.",
            "Preserve relevant authentication and security logs.",
            "Consider rotating the affected privileged credentials.",
            "Escalate the incident for security investigation."
        ])

    # --------------------------------------------------------
    # Additional high/critical severity action
    # --------------------------------------------------------

    if severity in ("HIGH", "CRITICAL"):

        actions.append(
            "Preserve relevant evidence for further investigation."
        )

    return actions


def generate_incident_report(incidents):
    """
    Generate a structured incident investigation report.
    """

    os.makedirs(
        REPORT_DIRECTORY,
        exist_ok=True
    )

    report = {
        "report_generated_at":
            datetime.now().isoformat(),

        "total_incidents":
            len(incidents),

        "incidents": []
    }

    for incident in incidents:

        investigation = {

            "incident_id":
                incident["incident_id"],

            "incident_type":
                incident["incident_type"],

            "severity":
                incident["severity"],

            "source_ip":
                incident["source_ip"],

            "username":
                incident["username"],

            "hostname":
                incident["hostname"],

            "event_count":
                incident["event_count"],

            "description":
                incident["description"],

            "investigation_status":
                "OPEN",

            "recommended_actions":
                get_recommended_actions(incident)
        }

        report["incidents"].append(
            investigation
        )

    report_path = os.path.join(
        REPORT_DIRECTORY,
        "incident_report.json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return report_path