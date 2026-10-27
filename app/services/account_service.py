from datetime import datetime, timezone
import hashlib
import secrets

from app.database import get_connection
from app.services.rbac_service import has_role


def generate_credential():
    """
    Generate a simulated privileged credential.

    The actual credential is never stored in plaintext.
    """

    return secrets.token_urlsafe(24)


def hash_credential(credential):
    """
    Create a SHA-256 representation of a credential.
    """

    return hashlib.sha256(
        credential.encode("utf-8")
    ).hexdigest()


def create_privileged_account(
    operator,
    username,
    hostname,
    platform,
    safe
):
    """
    Create a privileged account.

    Only PAM_ADMIN users can create privileged accounts.
    """

    if not has_role(operator, "PAM_ADMIN"):
        print(
            f"ACCESS DENIED: {operator} is not authorized "
            "to create privileged accounts."
        )
        return False

    connection = get_connection()

    try:

        platform_row = connection.execute(
            """
            SELECT id
            FROM platforms
            WHERE name = ?
            """,
            (platform,)
        ).fetchone()

        safe_row = connection.execute(
            """
            SELECT id
            FROM safes
            WHERE name = ?
            """,
            (safe,)
        ).fetchone()

        if not platform_row:
            print(f"Platform not found: {platform}")
            return False

        if not safe_row:
            print(f"Safe not found: {safe}")
            return False

        credential = generate_credential()
        credential_hash = hash_credential(credential)

        cursor = connection.execute(
            """
            INSERT INTO privileged_accounts
            (
                username,
                hostname,
                platform_id,
                safe_id,
                credential_hash,
                status,
                last_rotation
            )
            VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
            """,
            (
                username,
                hostname,
                platform_row["id"],
                safe_row["id"],
                credential_hash,
                datetime.now(timezone.utc).isoformat()
            )
        )

        account_id = cursor.lastrowid

        connection.execute(
            """
            INSERT INTO audit_logs
            (
                event_type,
                user_id,
                account_id,
                result,
                details
            )
            SELECT
                'ACCOUNT_CREATED',
                id,
                ?,
                'SUCCESS',
                ?
            FROM users
            WHERE username = ?
            """,
            (
                account_id,
                f"Created {username}@{hostname}",
                operator
            )
        )

        connection.commit()

        print()
        print("PRIVILEGED ACCOUNT CREATED")
        print("-" * 40)
        print(f"Account  : {username}")
        print(f"Hostname : {hostname}")
        print(f"Platform : {platform}")
        print(f"Safe     : {safe}")
        print(f"Account ID: {account_id}")
        print()

        return True

    except Exception as error:

        connection.rollback()

        print(f"Error creating privileged account: {error}")

        return False

    finally:
        connection.close()


def list_privileged_accounts():

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                pa.id,
                pa.username,
                pa.hostname,
                p.name AS platform,
                s.name AS safe,
                pa.status,
                pa.last_rotation
            FROM privileged_accounts pa
            JOIN platforms p
                ON pa.platform_id = p.id
            JOIN safes s
                ON pa.safe_id = s.id
            ORDER BY pa.id
            """
        ).fetchall()

        return rows

    finally:
        connection.close()