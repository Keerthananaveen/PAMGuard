import secrets
import hashlib
from datetime import datetime, timezone

from app.database import get_connection


def generate_credential():
    return secrets.token_urlsafe(24)


def hash_credential(credential):
    return hashlib.sha256(
        credential.encode()
    ).hexdigest()


def rotate_password(operator, account_username, hostname):
    conn = get_connection()

    operator_row = conn.execute(
        """
        SELECT id, username, status
        FROM users
        WHERE username = ?
        """,
        (operator,)
    ).fetchone()

    if not operator_row:
        conn.close()
        return False, "Operator not found."

    if operator_row["status"] != "ACTIVE":
        conn.close()
        return False, "Operator account is disabled."

    role = conn.execute(
        """
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = ?
        AND r.name = 'PAM_ADMIN'
        """,
        (operator_row["id"],)
    ).fetchone()

    if not role:
        conn.close()
        return False, "ACCESS DENIED: PAM_ADMIN role required."

    account = conn.execute(
        """
        SELECT id
        FROM privileged_accounts
        WHERE username = ?
        AND hostname = ?
        AND status = 'ACTIVE'
        """,
        (account_username, hostname)
    ).fetchone()

    if not account:
        conn.close()
        return False, "Privileged account not found."

    new_credential = generate_credential()
    new_hash = hash_credential(new_credential)

    rotation_time = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """
        UPDATE privileged_accounts
        SET credential_hash = ?,
            last_rotation = ?
        WHERE id = ?
        """,
        (
            new_hash,
            rotation_time,
            account["id"]
        )
    )

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
            account["id"],
            rotation_time,
            "SUCCESS",
            operator_row["id"]
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
            "PASSWORD_ROTATED",
            operator_row["id"],
            account["id"],
            "SUCCESS",
            "Simulated privileged credential rotation completed.",
            "SYSTEM"
        )
    )

    conn.commit()
    conn.close()

    return True, "PASSWORD ROTATION SUCCESSFUL."


def rotate_account_by_id(account_id):
    """
    Internal system rotation used after session check-in/expiry.

    This is a simulation. The new credential is generated and
    only its hash is stored.
    """

    conn = get_connection()

    account = conn.execute(
        """
        SELECT id, username, hostname, status
        FROM privileged_accounts
        WHERE id = ?
        """,
        (account_id,)
    ).fetchone()

    if not account:
        conn.close()
        return False, "Account not found."

    if account["status"] != "ACTIVE":
        conn.close()
        return False, "Account is disabled."

    new_credential = generate_credential()
    new_hash = hash_credential(new_credential)

    rotation_time = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """
        UPDATE privileged_accounts
        SET credential_hash = ?,
            last_rotation = ?
        WHERE id = ?
        """,
        (
            new_hash,
            rotation_time,
            account_id
        )
    )

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
            account_id,
            rotation_time,
            "SUCCESS",
            None
        )
    )

    conn.execute(
        """
        INSERT INTO audit_logs
        (
            event_type,
            account_id,
            result,
            details,
            source_ip
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "PASSWORD_ROTATED",
            account_id,
            "SUCCESS",
            "Automatic simulated credential rotation after privileged session ended.",
            "SYSTEM"
        )
    )

    conn.commit()
    conn.close()

    return True, "Automatic password rotation successful."