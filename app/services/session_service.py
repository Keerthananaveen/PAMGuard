from datetime import datetime, timezone
from app.database import get_connection


def list_sessions():
    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            s.session_id,
            u.username,
            pa.username AS account_username,
            pa.hostname,
            s.start_time,
            s.end_time,
            s.status,
            s.source_ip,
            s.reason
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        JOIN privileged_accounts pa ON s.account_id = pa.id
        ORDER BY s.start_time DESC
        """
    ).fetchall()

    conn.close()

    return rows


def checkin_session(username, session_id):
    conn = get_connection()

    user = conn.execute(
        """
        SELECT id, status
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    if not user:
        conn.close()
        return False, "User not found."

    if user["status"] != "ACTIVE":
        conn.close()
        return False, "User account is disabled."

    session = conn.execute(
        """
        SELECT
            id,
            user_id,
            account_id,
            status
        FROM sessions
        WHERE session_id = ?
        """,
        (session_id,)
    ).fetchone()

    if not session:
        conn.close()
        return False, "Session not found."

    if session["user_id"] != user["id"]:
        conn.close()
        return False, "ACCESS DENIED: This session does not belong to the user."

    if session["status"] != "ACTIVE":
        conn.close()
        return False, f"Session is already {session['status']}."

    now = datetime.now(timezone.utc).isoformat()

    # Close the session
    conn.execute(
        """
        UPDATE sessions
        SET
            end_time = ?,
            status = 'CLOSED'
        WHERE session_id = ?
        """,
        (now, session_id)
    )

    # Record session check-in
    conn.execute(
        """
        INSERT INTO audit_logs
        (
            event_type,
            user_id,
            account_id,
            session_id,
            result,
            details,
            source_ip
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "SESSION_CHECKIN",
            user["id"],
            session["account_id"],
            session_id,
            "SUCCESS",
            "Privileged session checked in by user.",
            "192.168.1.20"
        )
    )

    # Generate a new simulated credential
    import secrets
    import hashlib

    new_credential = secrets.token_urlsafe(24)
    new_hash = hashlib.sha256(
        new_credential.encode()
    ).hexdigest()

    # Rotate credential
    conn.execute(
        """
        UPDATE privileged_accounts
        SET
            credential_hash = ?,
            last_rotation = ?
        WHERE id = ?
        """,
        (
            new_hash,
            now,
            session["account_id"]
        )
    )

    # Record rotation
    conn.execute(
        """
        INSERT INTO password_rotations
        (
            account_id,
            rotation_time,
            result,
            performed_by
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            session["account_id"],
            now,
            "SUCCESS",
            None
        )
    )

    # Audit rotation
    conn.execute(
        """
        INSERT INTO audit_logs
        (
            event_type,
            user_id,
            account_id,
            session_id,
            result,
            details,
            source_ip
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "PASSWORD_ROTATED",
            user["id"],
            session["account_id"],
            session_id,
            "SUCCESS",
            "Automatic simulated credential rotation after session check-in.",
            "SYSTEM"
        )
    )

    conn.commit()
    conn.close()

    return True, (
        "SESSION CHECK-IN SUCCESSFUL.\n"
        "Automatic password rotation completed."
    )

def expire_sessions():
    conn = get_connection()

    now = datetime.now(timezone.utc).isoformat()

    sessions = conn.execute(
        """
        SELECT
            s.id,
            s.session_id,
            s.user_id,
            s.account_id
        FROM sessions s
        WHERE s.status = 'ACTIVE'
        AND s.end_time <= ?
        """,
        (now,)
    ).fetchall()

    expired_count = 0

    import secrets
    import hashlib

    for session in sessions:

        # Mark session expired
        conn.execute(
            """
            UPDATE sessions
            SET status = 'EXPIRED'
            WHERE id = ?
            """,
            (session["id"],)
        )

        # Audit expiration
        conn.execute(
            """
            INSERT INTO audit_logs
            (
                event_type,
                user_id,
                account_id,
                session_id,
                result,
                details,
                source_ip
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "SESSION_EXPIRED",
                session["user_id"],
                session["account_id"],
                session["session_id"],
                "SUCCESS",
                "Privileged session automatically expired.",
                "SYSTEM"
            )
        )

        # Generate new simulated credential
        new_credential = secrets.token_urlsafe(24)

        new_hash = hashlib.sha256(
            new_credential.encode()
        ).hexdigest()

        # Rotate credential
        conn.execute(
            """
            UPDATE privileged_accounts
            SET
                credential_hash = ?,
                last_rotation = ?
            WHERE id = ?
            """,
            (
                new_hash,
                now,
                session["account_id"]
            )
        )

        # Record rotation
        conn.execute(
            """
            INSERT INTO password_rotations
            (
                account_id,
                rotation_time,
                result,
                performed_by
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                session["account_id"],
                now,
                "SUCCESS",
                None
            )
        )

        # Audit rotation
        conn.execute(
            """
            INSERT INTO audit_logs
            (
                event_type,
                user_id,
                account_id,
                session_id,
                result,
                details,
                source_ip
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "PASSWORD_ROTATED",
                session["user_id"],
                session["account_id"],
                session["session_id"],
                "SUCCESS",
                "Automatic simulated credential rotation after session expiration.",
                "SYSTEM"
            )
        )

        expired_count += 1

    conn.commit()
    conn.close()

    return expired_count