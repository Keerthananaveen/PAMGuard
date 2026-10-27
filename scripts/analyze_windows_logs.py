import csv
import json
import os
import sys
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_ROOT)
from collections import defaultdict
from datetime import datetime
from app.services.incident_service import generate_incident_report
from app.services.correlation_service import correlate_incidents_with_pam
from app.services.siem_service import ingest_incidents
# ============================================================
# Configuration
# ============================================================

LOG_FILE = "logs/windows_security_events.csv"

CSV_REPORT = "reports/incidents/windows_incidents.csv"
JSON_REPORT = "reports/incidents/windows_incidents.json"

# Brute-force detection
FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_MINUTES = 5

# Correlation detection
CORRELATION_WINDOW_MINUTES = 10


# ============================================================
# Load Windows Security Events
# ============================================================

def load_events():
    """
    Load Windows security events from the CSV file.

    Converts:
        event_id -> integer
        timestamp -> datetime object
    """

    events = []

    if not os.path.exists(LOG_FILE):
        print(f"ERROR: Log file not found: {LOG_FILE}")
        return events

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            try:

                row["event_id"] = int(row["event_id"])

                row["timestamp"] = datetime.strptime(
                    row["timestamp"],
                    "%Y-%m-%d %H:%M:%S"
                )

                events.append(row)

            except (ValueError, KeyError) as error:

                print(
                    f"WARNING: Skipping invalid event: {error}"
                )

    return events


# ============================================================
# Detect Individual Windows Security Incidents
# ============================================================

def detect_incidents(events):
    """
    Detect individual Windows security incidents.

    Event IDs used:

        4625 -> Failed login
        4624 -> Successful login
        4672 -> Special privileges assigned
        4688 -> Process creation
    """

    incidents = []

    # --------------------------------------------------------
    # 1. Detect failed login attempts
    # --------------------------------------------------------

    failed_by_ip = defaultdict(list)

    for event in events:

        if event["event_id"] == 4625:

            failed_by_ip[
                event["source_ip"]
            ].append(event)

    # --------------------------------------------------------
    # Detect brute-force attempts
    # --------------------------------------------------------

    for source_ip, failed_events in failed_by_ip.items():

        failed_events.sort(
            key=lambda event: event["timestamp"]
        )

        for i in range(len(failed_events)):

            window_start = failed_events[i]["timestamp"]

            window_events = [
                event
                for event in failed_events
                if (
                    0 <= (
                        event["timestamp"]
                        - window_start
                    ).total_seconds()
                    <= FAILED_LOGIN_WINDOW_MINUTES * 60
                )
            ]

            if len(window_events) >= FAILED_LOGIN_THRESHOLD:

                usernames = sorted(
                    set(
                        event["username"]
                        for event in window_events
                    )
                )

                incidents.append({

                    "incident_id":
                        f"WIN-{len(incidents) + 1:04d}",

                    "incident_type":
                        "WINDOWS_BRUTE_FORCE",

                    "severity":
                        "HIGH",

                    "source_ip":
                        source_ip,

                    "username":
                        ", ".join(usernames),

                    "hostname":
                        window_events[0]["hostname"],

                    "event_timestamp": window_start.isoformat(),

                    "event_count":
                        len(window_events),

                    "description": (
                        f"{len(window_events)} failed "
                        f"Windows login attempts from "
                        f"{source_ip} within "
                        f"{FAILED_LOGIN_WINDOW_MINUTES} "
                        f"minutes."
                    )
                })

                # One brute-force incident per IP
                break

    # --------------------------------------------------------
    # 2. Detect successful Administrator login
    # Event ID 4624
    # --------------------------------------------------------

    for event in events:

        if (
            event["event_id"] == 4624
            and
            event["username"].lower()
            == "administrator"
        ):

            incidents.append({

                "incident_id":
                    f"WIN-{len(incidents) + 1:04d}",

                "incident_type":
                    "ADMINISTRATOR_LOGIN",

                "severity":
                    "HIGH",

                "source_ip":
                    event["source_ip"],

                "username":
                    event["username"],

                    "hostname":
                        event["hostname"],

                    "event_timestamp": event["timestamp"].isoformat(),

                "event_count":
                    1,

                "description": (
                    f"Successful administrator "
                    f"login from "
                    f"{event['source_ip']}."
                )
            })

    # --------------------------------------------------------
    # 3. Detect special privileges
    # Event ID 4672
    # --------------------------------------------------------

    for event in events:

        if event["event_id"] == 4672:

            incidents.append({

                "incident_id":
                    f"WIN-{len(incidents) + 1:04d}",

                "incident_type":
                    "SPECIAL_PRIVILEGES_ASSIGNED",

                "severity":
                    "HIGH",

                "source_ip":
                    event["source_ip"],

                "username":
                    event["username"],

                    "hostname":
                        event["hostname"],

                    "event_timestamp": event["timestamp"].isoformat(),

                "event_count":
                    1,

                "description": (
                    f"Special privileges assigned "
                    f"to {event['username']}."
                )
            })

    # --------------------------------------------------------
    # 4. Detect process creation
    # Event ID 4688
    # --------------------------------------------------------

    for event in events:

        if event["event_id"] == 4688:

            incidents.append({

                "incident_id":
                    f"WIN-{len(incidents) + 1:04d}",

                "incident_type":
                    "PROCESS_CREATION",

                "severity":
                    "MEDIUM",

                "source_ip":
                    event["source_ip"],

                "username":
                    event["username"],

                    "hostname":
                        event["hostname"],

                    "event_timestamp": event["timestamp"].isoformat(),

                "event_count":
                    1,

                "description": (
                    f"New process created by "
                    f"{event['username']}."
                )
            })

    return incidents


# ============================================================
# Correlate Multiple Windows Events
# ============================================================

def detect_correlated_attack(events):
    """
    Detect a multi-stage suspicious activity pattern.

    Pattern:

        Multiple failed logins
                |
                v
        Successful login
                |
                v
        Special privileges
                |
                v
        Process creation

    All related activity must occur within the
    configured correlation window.
    """

    incidents = []

    # --------------------------------------------------------
    # Group events by source IP + username
    # --------------------------------------------------------

    grouped_events = defaultdict(list)

    for event in events:

        key = (
            event["source_ip"],
            event["username"].lower()
        )

        grouped_events[key].append(event)

    # --------------------------------------------------------
    # Analyze each source/user combination
    # --------------------------------------------------------

    for (
        source_ip,
        username
    ), user_events in grouped_events.items():

        user_events.sort(
            key=lambda event: event["timestamp"]
        )

        # ----------------------------------------------------
        # Extract event types
        # ----------------------------------------------------

        failed_events = [
            event
            for event in user_events
            if event["event_id"] == 4625
        ]

        successful_logins = [
            event
            for event in user_events
            if event["event_id"] == 4624
        ]

        privileged_events = [
            event
            for event in user_events
            if event["event_id"] == 4672
        ]

        process_events = [
            event
            for event in user_events
            if event["event_id"] == 4688
        ]

        # ----------------------------------------------------
        # Need at least 3 failed login attempts
        # ----------------------------------------------------

        if len(failed_events) < FAILED_LOGIN_THRESHOLD:
            continue

        # ----------------------------------------------------
        # Examine successful logins
        # ----------------------------------------------------

        for success in successful_logins:

            # ------------------------------------------------
            # Find failed logins BEFORE successful login
            # within correlation window
            # ------------------------------------------------

            failures_before_success = [

                event

                for event in failed_events

                if (
                    event["timestamp"]
                    <= success["timestamp"]
                    and
                    (
                        success["timestamp"]
                        - event["timestamp"]
                    ).total_seconds()
                    <= CORRELATION_WINDOW_MINUTES * 60
                )
            ]

            # Need at least 3 failures
            if (
                len(failures_before_success)
                < FAILED_LOGIN_THRESHOLD
            ):
                continue

            # ------------------------------------------------
            # Find privilege assignment AFTER login
            # ------------------------------------------------

            privilege_after_success = [

                event

                for event in privileged_events

                if (
                    event["timestamp"]
                    >= success["timestamp"]
                    and
                    (
                        event["timestamp"]
                        - success["timestamp"]
                    ).total_seconds()
                    <= CORRELATION_WINDOW_MINUTES * 60
                )
            ]

            # ------------------------------------------------
            # Find process creation AFTER login
            # ------------------------------------------------

            process_after_success = [

                event

                for event in process_events

                if (
                    event["timestamp"]
                    >= success["timestamp"]
                    and
                    (
                        event["timestamp"]
                        - success["timestamp"]
                    ).total_seconds()
                    <= CORRELATION_WINDOW_MINUTES * 60
                )
            ]

            # ------------------------------------------------
            # Full attack sequence detected
            # ------------------------------------------------

            if (
                privilege_after_success
                and
                process_after_success
            ):

                event_count = (

                    len(failures_before_success)

                    + 1

                    + len(privilege_after_success)

                    + len(process_after_success)
                )

                incidents.append({

                    "incident_id":
                        f"WIN-CORR-{len(incidents) + 1:04d}",

                    "incident_type":
                        "CORRELATED_PRIVILEGED_ATTACK",

                    "severity":
                        "CRITICAL",

                    "source_ip":
                        source_ip,

                    "username":
                        username,

                    "hostname":
                        success["hostname"],

                    "event_timestamp": success["timestamp"].isoformat(),

                    "event_count":
                        event_count,

                    "description": (
                        f"Correlated suspicious activity "
                        f"detected: "
                        f"{len(failures_before_success)} "
                        f"failed login attempts followed "
                        f"by a successful login, special "
                        f"privileges, and process creation "
                        f"from {source_ip}."
                    )
                })

                # One correlated incident per user/IP
                break

    return incidents


# ============================================================
# Save Incident Reports
# ============================================================

def save_reports(incidents):
    """
    Save incidents as CSV and JSON reports.
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

        "hostname",

        "event_count",

        "event_timestamp",

        "description"
    ]

    # --------------------------------------------------------
    # Save CSV
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Save JSON
    # --------------------------------------------------------

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


# ============================================================
# Main
# ============================================================

def main():
    """
    Main entry point for Windows log analysis.
    """

    # Load events
    events = load_events()

    if not events:
        return

    # --------------------------------------------------------
    # Detect individual incidents
    # --------------------------------------------------------

    incidents = detect_incidents(events)

    # --------------------------------------------------------
    # Detect correlated multi-stage attacks
    # --------------------------------------------------------

    correlated_incidents = detect_correlated_attack(
        events
    )

    incidents.extend(
        correlated_incidents
    )

    ingested_count = ingest_incidents(incidents, source="windows-csv")

    # --------------------------------------------------------
    # Save reports
    # --------------------------------------------------------

    save_reports(incidents)
    report_path = generate_incident_report(incidents)
    correlation_report = correlate_incidents_with_pam(incidents)
    # --------------------------------------------------------
    # Display summary
    # --------------------------------------------------------

    print(
        "Windows security event analysis completed."
    )

    print(
        f"Events analyzed: {len(events)}"
    )

    print(
        f"Incidents detected: {len(incidents)}"
    )
    print(f"SIEM-style events newly ingested: {ingested_count}")

    print()

    print(
        f"CSV report: {CSV_REPORT}"
    )

    print(
        f"JSON report: {JSON_REPORT}"
    )
    print(
    f"Investigation report: {report_path}"
    )
    print(
    f"PAM correlation report: {correlation_report}"
    )

# ============================================================
# Program Entry
# ============================================================

if __name__ == "__main__":
    main()
