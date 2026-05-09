"""
0xDay Feedback Loop — Database Initialiser
Creates feedback.db from schema.sql.
Safe to run multiple times — uses CREATE TABLE IF NOT EXISTS.
"""

import sqlite3
import sys
from pathlib import Path

# Resolve paths relative to this file
HERE = Path(__file__).parent.resolve()
PROJECT_ROOT = HERE.parent
SCHEMA_PATH = HERE / "schema.sql"
DB_PATH = PROJECT_ROOT / "feedback.db"


def init_database():
    """Create or update the feedback database from schema.sql."""

    if not SCHEMA_PATH.exists():
        print(f"ERROR: schema.sql not found at {SCHEMA_PATH}")
        sys.exit(1)

    print(f"Reading schema from: {SCHEMA_PATH}")
    with open(SCHEMA_PATH, "r") as f:
        schema_sql = f.read()

    print(f"Connecting to database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)

    # Enable foreign key constraints (off by default in SQLite)
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        conn.executescript(schema_sql)
        conn.commit()
        print("Schema applied successfully.")
    except sqlite3.Error as e:
        print(f"ERROR applying schema: {e}")
        conn.close()
        sys.exit(1)

    # Verify tables exist
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in cursor.fetchall()]

    print(f"\nDatabase ready at: {DB_PATH}")
    print(f"Tables created: {tables}")

    # Quick sanity check — count rows in each table
    print("\nRow counts:")
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  {table}: {count} rows")

    conn.close()
    print("\nDone.")


if __name__ == "__main__":
    init_database()
