from datetime import datetime, timezone
import secrets

from app.database import get_connection


def generate_request_id():
    return "REQ-" + secrets.token_hex(3).upper()


def generate_session_id():
    return "SES-" + secrets.token_hex(3).upper()


def request_access(
    username,
    account_username,
    hostname,
    duration_minutes,
    reason,
    source_ip="192.168.1.20"
):
    conn = get_connection()

    # Check requesting user
    user = conn.execute(
        """
        SELECT id, username, status
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

    # Check RBAC role
    role = conn.execute(
        """
        SELECT r.name
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = ?
        AND r.name IN ('SECURITY_ANALYST', 'PAM_ADMIN')
        """,
        (user["id"],)
    ).fetchone()

    if not role:
        conn.close()
        return False, (
            "ACCESS DENIED: User does not have permission "
            "to request privileged access."
        )

    # Find privileged account
    account = conn.execute(
        """
        SELECT
            pa.id,
            pa.username,
            pa.hostname,
            pa.safe_id,
            pa.status
        FROM privileged_accounts pa
        WHERE pa.username = ?
        AND pa.hostname = ?
        """,
        (account_username, hostname)
    ).fetchone()

    if not account:
        conn.close()
        return False, "Privileged account not found."

    if account["status"] != "ACTIVE":
        conn.close()
        return False, "Privileged account is disabled."

    # Find active policy for the account's Safe
    policy = conn.execute(
        """
        SELECT
            id,
            name,
            max_duration_minutes,
            approval_required,
            enabled
        FROM access_policies
        WHERE safe_id = ?
        AND enabled = 1
        """,
        (account["safe_id"],)
    ).fetchone()

    if not policy:
        conn.close()
        return False, "No active access policy found for this account."

    # Validate requested duration
    if duration_minutes > policy["max_duration_minutes"]:
        conn.execute(
            """
            INSERT INTO audit_logs
            (
                event_type,
                user_id,
                account_id,
                result,
                details,
                source_ip
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "ACCESS_REQUEST_DENIED",
                user["id"],
                account["id"],
                "DENIED",
                (
                    f"Requested duration {duration_minutes} minutes "
                    f"exceeds policy maximum of "
                    f"{policy['max_duration_minutes']} minutes."
                ),
                source_ip
            )
        )

        conn.commit()
        conn.close()

        return False, (
            f"ACCESS DENIED: Maximum allowed duration is "
            f"{policy['max_duration_minutes']} minutes."
        )

    # Generate request ID
    request_id = generate_request_id()
    requested_at = datetime.now(timezone.utc).isoformat()

    # Determine initial status
    if policy["approval_required"]:
        status = "PENDING"
    else:
        status = "APPROVED"

    # Create access request
    conn.execute(
        """
        INSERT INTO access_requests
        (
            request_id,
            user_id,
            account_id,
            reason,
            requested_duration_minutes,
            status,
            requested_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            user["id"],
            account["id"],
            reason,
            duration_minutes,
            status,
            requested_at
        )
    )

    # Audit event
    conn.execute(
        """
        INSERT INTO audit_logs
        (
            event_type,
            user_id,
            account_id,
            result,
            details,
            source_ip
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "ACCESS_REQUESTED",
            user["id"],
            account["id"],
            "SUCCESS",
            (
                f"Privileged access requested for "
                f"{duration_minutes} minutes. "
                f"Reason: {reason}"
            ),
            source_ip
        )
    )

    conn.commit()
    conn.close()

    return True, (
        f"ACCESS REQUEST CREATED: {request_id} "
        f"| Status: {status}"
    )


def list_access_requests():
    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            ar.request_id,
            u.username AS requester,
            pa.username AS account_username,
            pa.hostname,
            ar.reason,
            ar.requested_duration_minutes,
            ar.status,
            ar.requested_at,
            approver.username AS approved_by,
            ar.approved_at
        FROM access_requests ar
        JOIN users u
            ON ar.user_id = u.id
        JOIN privileged_accounts pa
            ON ar.account_id = pa.id
        LEFT JOIN users approver
            ON ar.approved_by = approver.id
        ORDER BY ar.requested_at DESC
        """
    ).fetchall()

    conn.close()

    return rows


def approve_access(approver_username, request_id):
    conn = get_connection()

    # Check approver
    approver = conn.execute(
        """
        SELECT id, username, status
        FROM users
        WHERE username = ?
        """,
        (approver_username,)
    ).fetchone()

    if not approver:
        conn.close()
        return False, "Approver not found."

    if approver["status"] != "ACTIVE":
        conn.close()
        return False, "Approver account is disabled."

    # Approver must have PAM_ADMIN role
    role = conn.execute(
        """
        SELECT 1
        FROM user_roles ur
        JOIN roles r
            ON ur.role_id = r.id
        WHERE ur.user_id = ?
        AND r.name = 'PAM_ADMIN'
        """,
        (approver["id"],)
    ).fetchone()

    if not role:
        conn.close()
        return False, "ACCESS DENIED: PAM_ADMIN role required."

    # Find request
    request = conn.execute(
        """
        SELECT
            id,
            user_id,
            account_id,
            status
        FROM access_requests
        WHERE request_id = ?
        """,
        (request_id,)
    ).fetchone()

    if not request:
        conn.close()
        return False, "Access request not found."

    # Request must be pending
    if request["status"] != "PENDING":
        conn.close()
        return False, (
            f"Request cannot be approved because its "
            f"status is {request['status']}."
        )

    # Separation of duties
    if request["user_id"] == approver["id"]:
        conn.close()
        return False, (
            "ACCESS DENIED: Requester cannot approve "
            "their own access request."
        )

    approved_at = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """
        UPDATE access_requests
        SET
            status = 'APPROVED',
            approved_at = ?,
            approved_by = ?
        WHERE id = ?
        """,
        (
            approved_at,
            approver["id"],
            request["id"]
        )
    )

    conn.execute(
        """
        INSERT INTO audit_logs
        (
            event_type,
            user_id,
            account_id,
            result,
            details,
            source_ip
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "ACCESS_APPROVED",
            approver["id"],
            request["account_id"],
            "SUCCESS",
            f"Access request {request_id} approved.",
            "192.168.1.20"
        )
    )

    conn.commit()
    conn.close()

    return True, "ACCESS REQUEST APPROVED."


def checkout_password(
    username,
    request_id,
    source_ip="192.168.1.20"
):
    conn = get_connection()

    # Check user
    user = conn.execute(
        """
        SELECT id, username, status
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

    # Find request belonging to user
    request = conn.execute(
        """
        SELECT
            ar.id,
            ar.request_id,
            ar.user_id,
            ar.account_id,
            ar.requested_duration_minutes,
            ar.status,
            pa.username AS account_username,
            pa.hostname
        FROM access_requests ar
        JOIN privileged_accounts pa
            ON ar.account_id = pa.id
        WHERE ar.request_id = ?
        AND ar.user_id = ?
        """,
        (
            request_id,
            user["id"]
        )
    ).fetchone()

    if not request:
        conn.close()
        return False, (
            "Access request not found or does not belong "
            "to this user."
        )

    # Request must be approved
    if request["status"] != "APPROVED":
        conn.close()
        return False, (
            f"ACCESS DENIED: Request status is "
            f"{request['status']}."
        )

    # Check for an existing active session
    active_session = conn.execute(
        """
        SELECT session_id
        FROM sessions
        WHERE user_id = ?
        AND account_id = ?
        AND status = 'ACTIVE'
        """,
        (
            user["id"],
            request["account_id"]
        )
    ).fetchone()

    if active_session:
        conn.close()
        return False, (
            f"ACCESS DENIED: User already has an active "
            f"session ({active_session['session_id']})."
        )

    # Create session
    session_id = generate_session_id()

    start_time = datetime.now(timezone.utc)

    from datetime import timedelta

    end_time = (
        start_time
        + timedelta(
            minutes=request["requested_duration_minutes"]
        )
    )

    conn.execute(
        """
        INSERT INTO sessions
        (
            session_id,
            user_id,
            account_id,
            start_time,
            end_time,
            status,
            source_ip,
            reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            user["id"],
            request["account_id"],
            start_time.isoformat(),
            end_time.isoformat(),
            "ACTIVE",
            source_ip,
            "Privileged access request: "
            + request["request_id"]
        )
    )

    # Mark request as consumed
    conn.execute(
        """
        UPDATE access_requests
        SET status = 'CHECKED_OUT'
        WHERE id = ?
        """,
        (request["id"],)
    )

    # Audit checkout
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
            "PASSWORD_CHECKOUT",
            user["id"],
            request["account_id"],
            session_id,
            "SUCCESS",
            (
                f"Privileged session started for "
                f"{request['requested_duration_minutes']} minutes."
            ),
            source_ip
        )
    )

    conn.commit()
    conn.close()

    return True, (
        f"PASSWORD CHECKOUT SUCCESSFUL\n"
        f"Session ID: {session_id}\n"
        f"Account: {request['account_username']}\n"
        f"Hostname: {request['hostname']}\n"
        f"Start: {start_time.isoformat()}\n"
        f"Expires: {end_time.isoformat()}\n"
        f"Duration: {request['requested_duration_minutes']} minutes"
    )