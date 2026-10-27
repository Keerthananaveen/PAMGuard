import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_DIR = BASE_DIR / "database"
DATABASE_FILE = DATABASE_DIR / "pamguard.db"
SCHEMA_FILE = DATABASE_DIR / "schema.sql"


def get_connection():
    """
    Create and return a connection to the PAMGuard SQLite database.
    """

    DATABASE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_FILE)

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON;")

    return connection


def initialize_database():
    """
    Create all PAMGuard database tables from schema.sql.
    """

    connection = get_connection()

    try:
        schema = SCHEMA_FILE.read_text(encoding="utf-8")

        connection.executescript(schema)

        connection.commit()

        print("PAMGuard database initialized successfully.")

    finally:
        connection.close()

def seed_database():
    """
    Insert initial PAMGuard users, roles, safes and platforms.
    """

    connection = get_connection()

    try:
        seed_file = DATABASE_DIR / "seed.sql"

        seed = seed_file.read_text(encoding="utf-8")

        connection.executescript(seed)

        connection.commit()

        print("PAMGuard seed data inserted successfully.")

    except Exception as error:
        connection.rollback()
        print(f"Error seeding database: {error}")

    finally:
        connection.close()

        
if __name__ == "__main__":
    initialize_database()