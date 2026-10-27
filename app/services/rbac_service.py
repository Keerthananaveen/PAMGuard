from app.database import get_connection


def create_user(username, email):
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO users (username, email)
            VALUES (?, ?)
            """,
            (username, email)
        )

        connection.commit()

        print(f"User created: {username}")
        return cursor.lastrowid

    except Exception as error:
        connection.rollback()
        print(f"Error creating user: {error}")
        return None

    finally:
        connection.close()


def create_role(name, description):
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO roles (name, description)
            VALUES (?, ?)
            """,
            (name, description)
        )

        connection.commit()

        print(f"Role created: {name}")
        return cursor.lastrowid

    except Exception as error:
        connection.rollback()
        print(f"Error creating role: {error}")
        return None

    finally:
        connection.close()


def assign_role(username, role_name):
    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        role = connection.execute(
            """
            SELECT id
            FROM roles
            WHERE name = ?
            """,
            (role_name,)
        ).fetchone()

        if not user:
            print(f"User not found: {username}")
            return False

        if not role:
            print(f"Role not found: {role_name}")
            return False

        connection.execute(
            """
            INSERT INTO user_roles (user_id, role_id)
            VALUES (?, ?)
            """,
            (user["id"], role["id"])
        )

        connection.commit()

        print(f"Assigned {role_name} to {username}")
        return True

    except Exception as error:
        connection.rollback()
        print(f"Error assigning role: {error}")
        return False

    finally:
        connection.close()


def get_user_roles(username):
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT r.name
            FROM roles r
            JOIN user_roles ur
                ON r.id = ur.role_id
            JOIN users u
                ON u.id = ur.user_id
            WHERE u.username = ?
            ORDER BY r.name
            """,
            (username,)
        ).fetchall()

        return [row["name"] for row in rows]

    finally:
        connection.close()


def has_role(username, required_role):
    roles = get_user_roles(username)

    return required_role in roles


def list_users():
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                u.username,
                u.email,
                u.status,
                GROUP_CONCAT(r.name, ', ') AS roles
            FROM users u
            LEFT JOIN user_roles ur
                ON u.id = ur.user_id
            LEFT JOIN roles r
                ON ur.role_id = r.id
            GROUP BY u.id
            ORDER BY u.username
            """
        ).fetchall()

        return rows

    finally:
        connection.close()