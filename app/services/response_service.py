"""Bounded and auditable response actions for the simulated PAM environment."""
from datetime import datetime, timezone
from app.database import get_connection


def respond(action, incident_id, account_username=None, hostname=None, session_id=None):
    """Supported actions are disable-account, expire-session, and investigate."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    details = f"incident={incident_id}; action={action}"
    account_id = None
    try:
        if action == "disable-account":
            if not account_username or not hostname:
                return False, "Account username and hostname are required."
            row = conn.execute("SELECT id FROM privileged_accounts WHERE username=? AND hostname=?", (account_username, hostname)).fetchone()
            if not row:
                return False, "Simulated privileged account not found."
            account_id = row["id"]
            conn.execute("UPDATE privileged_accounts SET status='DISABLED' WHERE id=?", (account_id,))
            details += "; simulated account disabled"
        elif action == "expire-session":
            if not session_id:
                return False, "Session ID is required."
            row = conn.execute("SELECT id, account_id, status FROM sessions WHERE session_id=?", (session_id,)).fetchone()
            if not row or row["status"] != "ACTIVE":
                return False, "Active session not found; no action taken."
            account_id = row["account_id"]
            conn.execute("UPDATE sessions SET status='EXPIRED', end_time=? WHERE id=?", (now, row["id"]))
            details += "; simulated session expired"
        elif action == "investigate":
            details += "; investigation record created"
        else:
            return False, "Unsupported action."
        conn.execute("INSERT INTO audit_logs(event_type, account_id, session_id, result, details, source_ip, timestamp) VALUES(?,?,?,?,?,?,?)",
                     ("AUTOMATED_RESPONSE", account_id, session_id, "SUCCESS", details, "SYSTEM", now))
        conn.commit()
        return True, details
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
