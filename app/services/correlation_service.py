import json
import os
from datetime import datetime, timezone

from app.database import get_connection


REPORT_FILE = "reports/incidents/pam_security_correlation.json"


def correlate_incidents_with_pam(incidents):
    """
    Correlate security incidents with PAMGuard activity.

    Correlation levels:

        ACCOUNT_ONLY
        PAM_ACTIVITY
        SESSION_SOURCE_MATCH
    """

    conn = get_connection()

    correlated_results = []

    for incident in incidents:

        source_ip = incident.get("source_ip")
        username = incident.get("username")
        hostname = incident.get("hostname")
        event_time = _parse_event_time(incident.get("event_timestamp"))

        # ----------------------------------------------------
        # Find matching privileged account
        # ----------------------------------------------------

        account = None

        if username and hostname:

            account = conn.execute(
                """
                SELECT
                    pa.id,
                    pa.username,
                    pa.hostname,
                    pa.status,
                    s.name AS safe_name,
                    p.name AS platform_name
                FROM privileged_accounts pa
                JOIN safes s
                    ON pa.safe_id = s.id
                JOIN platforms p
                    ON pa.platform_id = p.id
                WHERE LOWER(pa.username) = LOWER(?)
                  AND LOWER(pa.hostname) = LOWER(?)
                """,
                (
                    username,
                    hostname
                )
            ).fetchone()

        # ----------------------------------------------------
        # Default result
        # ----------------------------------------------------

        result = {

            "correlation_id":
                f"CORR-{len(correlated_results) + 1:04d}",

            "incident_id":
                incident["incident_id"],

            "incident_type":
                incident["incident_type"],

            "severity":
                incident["severity"],

            "source_ip":
                source_ip,

            "username":
                username,

            "hostname":
                hostname,

            "event_timestamp": incident.get("event_timestamp"),

            "account_exists_in_pam":
                False,

            "pam_session_found":
                False,

            "source_ip_match":
                False,

            "correlation_level":
                "NO_PAM_MATCH",

            "privileged_account":
                None,

            "sessions":
                [],

            "audit_events":
                [],

            "investigation_status":
                "NO_PAM_ACTIVITY",

            "recommendation":
                "Investigate the security event independently."
        }

        # ----------------------------------------------------
        # No matching PAM account
        # ----------------------------------------------------

        if not account:

            correlated_results.append(result)

            continue

        # ----------------------------------------------------
        # PAM account exists
        # ----------------------------------------------------

        result["account_exists_in_pam"] = True

        result["privileged_account"] = {

            "account_id":
                account["id"],

            "username":
                account["username"],

            "hostname":
                account["hostname"],

            "status":
                account["status"],

            "safe":
                account["safe_name"],

            "platform":
                account["platform_name"]
        }

        # ----------------------------------------------------
        # Find sessions for this account
        # ----------------------------------------------------

        sessions = conn.execute(
            """
            SELECT
                session_id,
                user_id,
                start_time,
                end_time,
                status,
                source_ip,
                reason
            FROM sessions
            WHERE account_id = ?
            ORDER BY start_time DESC
            """,
            (account["id"],)
        ).fetchall()

        # ----------------------------------------------------
        # Add session information
        # ----------------------------------------------------

        for session in sessions:

            session_data = {

                "session_id":
                    session["session_id"],

                "start_time":
                    session["start_time"],

                "end_time":
                    session["end_time"],

                "status":
                    session["status"],

                "source_ip":
                    session["source_ip"],

                "reason":
                    session["reason"]
            }

            result["sessions"].append(
                session_data
            )

        # ----------------------------------------------------
        # Determine whether any PAM session exists
        # ----------------------------------------------------

        if sessions:

            result["pam_session_found"] = True

        # ----------------------------------------------------
        # Check whether source IP matches PAM session
        # ----------------------------------------------------

        ip_matching_sessions = [

            session

            for session in sessions

            if (
                session["source_ip"]
                and
                source_ip
                and
                session["source_ip"] == source_ip
            )
        ]

        temporal_matches = [
            session for session in ip_matching_sessions
            if event_time is not None
            and _parse_event_time(session["start_time"]) is not None
            and _parse_event_time(session["start_time"]) <= event_time
            and (
                _parse_event_time(session["end_time"]) is None
                or event_time <= _parse_event_time(session["end_time"])
            )
        ]

        result["source_ip_match"] = bool(ip_matching_sessions)
        result["pam_session_found"] = bool(sessions)
        result["matching_session_ids"] = [s["session_id"] for s in temporal_matches]

        if temporal_matches:

            result["source_ip_match"] = True

        # ----------------------------------------------------
        # Retrieve PAM audit events
        # ----------------------------------------------------

        audit_events = conn.execute(
            """
            SELECT
                timestamp,
                event_type,
                result,
                details,
                source_ip,
                session_id
            FROM audit_logs
            WHERE account_id = ?
            ORDER BY timestamp DESC
            """,
            (account["id"],)
        ).fetchall()

        # ----------------------------------------------------
        # Add audit events
        # ----------------------------------------------------

        for audit in audit_events:

            result["audit_events"].append({

                "timestamp":
                    audit["timestamp"],

                "event_type":
                    audit["event_type"],

                "result":
                    audit["result"],

                "details":
                    audit["details"],

                "source_ip":
                    audit["source_ip"],

                "session_id":
                    audit["session_id"]
            })

        # ----------------------------------------------------
        # Determine correlation level
        # ----------------------------------------------------

        if temporal_matches:

            result["correlation_level"] = (
                "SESSION_SOURCE_MATCH"
            )

            result["investigation_status"] = (
                "PAM_SESSION_CORRELATED"
            )

            result["recommendation"] = (
                "Investigate the matching PAM session, "
                "privileged account activity, access request, "
                "and associated security events."
            )

        elif ip_matching_sessions:

            result["correlation_level"] = "ACCOUNT_AND_IP_MATCH_OUTSIDE_SESSION"
            result["investigation_status"] = "PAM_SESSION_TIME_MISMATCH"
            result["recommendation"] = (
                "The account and source IP match PAM history, but the event timestamp "
                "does not overlap a matching session. Investigate independently."
            )

        elif sessions:

            result["correlation_level"] = (
                "PAM_ACTIVITY"
            )

            result["investigation_status"] = (
                "PAM_ACCOUNT_WITH_SESSION"
            )

            result["recommendation"] = (
                "Investigate the privileged account and "
                "associated PAM sessions. Verify whether "
                "the security event corresponds to an "
                "authorized session."
            )

        else:

            result["correlation_level"] = (
                "ACCOUNT_ONLY"
            )

            result["investigation_status"] = (
                "PAM_ACCOUNT_ONLY"
            )

            result["recommendation"] = (
                "The affected account exists in PAMGuard, "
                "but no PAM session was found. Investigate "
                "whether the security event represents "
                "unauthorized privileged access."
            )

        correlated_results.append(result)

    conn.close()

    # --------------------------------------------------------
    # Build final report
    # --------------------------------------------------------

    report = {

        "generated_at":
            datetime.now().isoformat(),

        "total_incidents":
            len(incidents),

        "correlated_incidents":
            len(correlated_results),

        "results":
            correlated_results
    }

    # --------------------------------------------------------
    # Save report
    # --------------------------------------------------------

    os.makedirs(
        os.path.dirname(REPORT_FILE),
        exist_ok=True
    )

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return REPORT_FILE


def _parse_event_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None
