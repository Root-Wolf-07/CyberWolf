"""Unit tests for CYBERWOLF Database Schema Migrations."""

import sqlite3
import pytest
from app.database.migrations import MigrationRunner


def test_migrations_execute_idempotently(tmp_path):
    """Verify migrations apply cleanly on a new database and are safe on repeated runs."""
    test_db = tmp_path / "test_migration.db"
    runner = MigrationRunner(db_path=test_db)

    # Initial run
    success = runner.run_all_migrations()
    assert success

    with sqlite3.connect(test_db) as conn:
        # Verify schema_migrations table
        applied = conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
        assert len(applied) >= 3

        # Verify tables created
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "assets" in tables
        assert "findings" in tables
        assert "evidence" in tables
        assert "scans" in tables
        assert "reports" in tables

    # Second run should be a no-op and succeed without error
    success_again = runner.run_all_migrations()
    assert success_again
