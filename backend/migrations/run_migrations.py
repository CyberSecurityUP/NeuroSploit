#!/usr/bin/env python3
"""
Run database migrations for NeuroSploit v3

Usage:
    python -m backend.migrations.run_migrations

Or from backend directory:
    python migrations/run_migrations.py
"""
import sqlite3
import os
from pathlib import Path


def get_db_path():
    """Get the database file path"""
    # Try common locations
    possible_paths = [
        Path("./data/neurosploit.db"),
        Path("../data/neurosploit.db"),
        Path("/opt/NeuroSploitv2/data/neurosploit.db"),
        Path("/opt/NeuroSploitv2/backend/data/neurosploit.db"),
    ]

    for path in possible_paths:
        if path.exists():
            return str(path.resolve())

    # Default path
    return "./data/neurosploit.db"


def column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns


def table_exists(cursor, table_name):
    """Check if a table exists"""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,)
    )
    return cursor.fetchone() is not None


def run_migration(db_path: str):
    """Run the database migration"""
    print(f"Running migration on database: {db_path}")

    if not os.path.exists(db_path):
        print(f"Database file not found at {db_path}")
        print("Creating data directory and database will be created on first run")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Migration 1: Add duration column to scans table
        if not column_exists(cursor, "scans", "duration"):
            print("Adding 'duration' column to scans table...")
            cursor.execute("ALTER TABLE scans ADD COLUMN duration INTEGER")
            print("  Done!")
        else:
            print("Column 'duration' already exists in scans table")

        # Migration 2: Add auto_generated column to reports table
        if table_exists(cursor, "reports"):
            if not column_exists(cursor, "reports", "auto_generated"):
                print("Adding 'auto_generated' column to reports table...")
                cursor.execute("ALTER TABLE reports ADD COLUMN auto_generated BOOLEAN DEFAULT 0")
                print("  Done!")
            else:
                print("Column 'auto_generated' already exists in reports table")

            # Migration 3: Add is_partial column to reports table
            if not column_exists(cursor, "reports", "is_partial"):
                print("Adding 'is_partial' column to reports table...")
                cursor.execute("ALTER TABLE reports ADD COLUMN is_partial BOOLEAN DEFAULT 0")
                print("  Done!")
            else:
                print("Column 'is_partial' already exists in reports table")
        else:
            print("Reports table does not exist yet, will be created on first run")

        # Migration 4: Create agent_tasks table
        if not table_exists(cursor, "agent_tasks"):
            print("Creating 'agent_tasks' table...")
            cursor.execute("""
                CREATE TABLE agent_tasks (
                    id VARCHAR(36) PRIMARY KEY,
                    scan_id VARCHAR(36) NOT NULL,
                    task_type VARCHAR(50) NOT NULL,
                    task_name VARCHAR(255) NOT NULL,
                    description TEXT,
                    tool_name VARCHAR(100),
                    tool_category VARCHAR(100),
                    status VARCHAR(20) DEFAULT 'pending',
                    started_at DATETIME,
                    completed_at DATETIME,
                    duration_ms INTEGER,
                    items_processed INTEGER DEFAULT 0,
                    items_found INTEGER DEFAULT 0,
                    result_summary TEXT,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX idx_agent_tasks_scan_id ON agent_tasks(scan_id)")
            cursor.execute("CREATE INDEX idx_agent_tasks_status ON agent_tasks(status)")
            cursor.execute("CREATE INDEX idx_agent_tasks_task_type ON agent_tasks(task_type)")
            print("  Done!")
        else:
            print("Table 'agent_tasks' already exists")

        conn.commit()
        print("\nMigration completed successfully!")

    except Exception as e:
        conn.rollback()
        print(f"\nMigration failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    db_path = get_db_path()
    run_migration(db_path)
