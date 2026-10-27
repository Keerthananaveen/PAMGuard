from app.database import get_connection
from app.services.rbac_service import has_role


def create_policy(
    operator,
    name,
    safe,
    max_duration,
    approval_required,
    rotation_interval
):
    """
    Create an access policy for a Safe.

    Only PAM_ADMIN users can create policies.
    """

    if not has_role(operator, "PAM_ADMIN"):
        print(
            f"ACCESS DENIED: {operator} cannot create access policies."
        )
        return False

    connection = get_connection()

    try:

        safe_row = connection.execute(
            """
            SELECT id
            FROM safes
            WHERE name = ?
            """,
            (safe,)
        ).fetchone()

        if not safe_row:
            print(f"Safe not found: {safe}")
            return False

        connection.execute(
            """
            INSERT INTO access_policies
            (
                name,
                safe_id,
                max_duration_minutes,
                approval_required,
                rotation_interval_hours,
                enabled
            )
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (
                name,
                safe_row["id"],
                max_duration,
                int(approval_required),
                rotation_interval
            )
        )

        connection.commit()

        print()
        print("ACCESS POLICY CREATED")
        print("-" * 40)
        print(f"Policy              : {name}")
        print(f"Safe                : {safe}")
        print(f"Maximum duration    : {max_duration} minutes")
        print(
            f"Approval required   : "
            f"{'YES' if approval_required else 'NO'}"
        )
        print(
            f"Rotation interval   : "
            f"{rotation_interval} hours"
        )
        print()

        return True

    except Exception as error:

        connection.rollback()

        print(f"Error creating policy: {error}")

        return False

    finally:
        connection.close()


def list_policies():

    connection = get_connection()

    try:

        return connection.execute(
            """
            SELECT
                ap.id,
                ap.name,
                s.name AS safe,
                ap.max_duration_minutes,
                ap.approval_required,
                ap.rotation_interval_hours,
                ap.enabled
            FROM access_policies ap
            JOIN safes s
                ON ap.safe_id = s.id
            ORDER BY ap.id
            """
        ).fetchall()

    finally:
        connection.close()