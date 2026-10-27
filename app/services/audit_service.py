from app.database import get_connection


def list_audit_logs(limit=50):
    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            a.timestamp,
            a.event_type,
            u.username,
            pa.username AS account_username,
            pa.hostname,
            a.session_id,
            a.result,
            a.details,
            a.source_ip
        FROM audit_logs a
        LEFT JOIN users u
            ON a.user_id = u.id
        LEFT JOIN privileged_accounts pa
            ON a.account_id = pa.id
        ORDER BY a.timestamp DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return rows