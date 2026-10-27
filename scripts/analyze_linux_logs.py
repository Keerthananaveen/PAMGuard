
import csv
import json
import os
import re
from collections import defaultdict
from datetime import datetime


LOG_FILE = "logs/linux_auth.log"

CSV_REPORT = "reports/incidents/linux_incidents.csv"
JSON_REPORT = "reports/incidents/linux_incidents.json"

FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_MINUTES = 5


def parse_log_line(line):
    """
    Parse a single Linux authentication log line
    and convert it into a structured event.
    """

    # Example:
    # Sep 21 10:15:30
    timestamp_match = re.match(
        r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})",
        line
    )

    timestamp = None

    if timestamp_match:
        timestamp = datetime.strptime(
            f"2026 {timestamp_match.group(1)}",
            "%Y %b %d %H:%M:%S"
    )

    # Failed login
    failed_match = re.search(
        r"Failed password for (?:invalid user )?(\S+) "
        r"from (\d{1,3}(?:\.\d{1,3}){3})",
        line
    )

    # Successful login
    success_match = re.search(
        r"Accepted password for (\S+) "
        r"from (\d{1,3}(?:\.\d{1,3}){3})",
        line
    )

    # sudo command
    sudo_match = re.search(
        r"sudo:\s+(\S+).*USER=(\S+).*COMMAND=(.*)",
        line
    )

    if failed_match:
        return {
            "type": "FAILED_LOGIN",
            "username": failed_match.group(1),
            "source_ip": failed_match.group(2),
            "timestamp": timestamp,
            "raw_log": line.strip()
        }

    if success_match:
        return {
            "type": "SUCCESSFUL_LOGIN",
            "username": success_match.group(1),
            "source_ip": success_match.group(2),
            "timestamp": timestamp,
            "raw_log": line.strip()
        }

    if sudo_match:
        return {
            "type": "PRIVILEGED_COMMAND",
            "username": sudo_match.group(1),
            "target_user": sudo_match.group(2),
            "command": sudo_match.group(3).strip(),
            "timestamp": timestamp,
            "raw_log": line.strip()
        }

    return None


def detect_incidents(events):
    """
    Analyze parsed events and detect security incidents.
    """

    incidents = []

    # ---------------------------------------------------------
    # 1. Detect repeated failed logins
    # ---------------------------------------------------------

    failed_by_ip = defaultdict(list)

    for event in events:
        if (
            event["type"] == "FAILED_LOGIN"
            and event.get("timestamp") is not None
        ):
            failed_by_ip[event["source_ip"]].append(event)

    for source_ip, failed_events in failed_by_ip.items():

        # Sort events chronologically
        failed_events.sort(
            key=lambda event: event["timestamp"]
        )

        for i in range(len(failed_events)):

            window_start = failed_events[i]["timestamp"]

            window_events = [
                event
                for event in failed_events
                if 0 <= (
                    event["timestamp"] - window_start
                ).total_seconds() <= FAILED_LOGIN_WINDOW_MINUTES * 60
            ]

            if len(window_events) >= FAILED_LOGIN_THRESHOLD:

                usernames = sorted(
                    set(
                        event["username"]
                        for event in window_events
                    )
                )

                incidents.append({
                    "incident_id": f"LIN-{len(incidents) + 1:04d}",
                    "incident_type": "BRUTE_FORCE_LOGIN_ATTEMPT",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "username": ", ".join(usernames),
                    "event_count": len(window_events),
                    "description": (
                        f"{len(window_events)} failed login attempts "
                        f"from {source_ip} within "
                        f"{FAILED_LOGIN_WINDOW_MINUTES} minutes."
                    )
                })

                # One incident per IP
                break

    # ---------------------------------------------------------
    # 2. Detect successful root login
    # ---------------------------------------------------------

    for event in events:

        if (
            event["type"] == "SUCCESSFUL_LOGIN"
            and event["username"].lower() == "root"
        ):

            incidents.append({
                "incident_id": f"LIN-{len(incidents) + 1:04d}",
                "incident_type": "ROOT_LOGIN",
                "severity": "HIGH",
                "source_ip": event["source_ip"],
                "username": event["username"],
                "event_count": 1,
                "description": (
                    f"Successful privileged root login "
                    f"from {event['source_ip']}."
                )
            })

    # ---------------------------------------------------------
    # 3. Detect privileged commands
    # ---------------------------------------------------------

    for event in events:

        if event["type"] == "PRIVILEGED_COMMAND":

            incidents.append({
                "incident_id": f"LIN-{len(incidents) + 1:04d}",
                "incident_type": "PRIVILEGED_COMMAND",
                "severity": "MEDIUM",
                "source_ip": "N/A",
                "username": event["username"],
                "event_count": 1,
                "description": (
                    f"Privileged command executed by "
                    f"{event['username']}: "
                    f"{event['command']}"
                )
            })

    return incidents


def save_reports(incidents):
    """
    Save detected incidents as CSV and JSON reports.
    """

    # Create report directory
    os.makedirs(
        os.path.dirname(CSV_REPORT),
        exist_ok=True
    )

    os.makedirs(
        os.path.dirname(JSON_REPORT),
        exist_ok=True
    )

    fields = [
        "incident_id",
        "incident_type",
        "severity",
        "source_ip",
        "username",
        "event_count",
        "description"
    ]

    # ---------------------------------------------------------
    # Save CSV
    # ---------------------------------------------------------

    with open(
        CSV_REPORT,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(incidents)

    # ---------------------------------------------------------
    # Save JSON
    # ---------------------------------------------------------

    with open(
        JSON_REPORT,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            incidents,
            file,
            indent=4
        )


def main():
    """
    Main entry point for Linux log analysis.
    """

    # Check whether log file exists
    if not os.path.exists(LOG_FILE):

        print(
            f"ERROR: Log file not found: {LOG_FILE}"
        )

        return

    events = []

    # ---------------------------------------------------------
    # Read and parse log file
    # ---------------------------------------------------------

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            event = parse_log_line(line)

            if event:
                events.append(event)

    # ---------------------------------------------------------
    # Detect incidents
    # ---------------------------------------------------------

    incidents = detect_incidents(events)

    # ---------------------------------------------------------
    # Generate reports
    # ---------------------------------------------------------

    save_reports(incidents)

    # ---------------------------------------------------------
    # Display summary
    # ---------------------------------------------------------

    print("Linux log analysis completed.")
    print(f"Events analyzed: {len(events)}")
    print(f"Incidents detected: {len(incidents)}")
    print()

    print(f"CSV report: {CSV_REPORT}")
    print(f"JSON report: {JSON_REPORT}")


if __name__ == "__main__":
    main()

