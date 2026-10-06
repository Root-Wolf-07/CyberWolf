"""CYBERWOLF SQLite Database Connection & Schema Management."""

import os
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Generator
from contextlib import contextmanager
from app.core.config import get_config
from app.core.logger import get_logger
from app.core.exceptions import DatabaseError

class DatabaseManager:
    """Manages SQLite database lifecycle, migrations, and connections."""
    def __init__(self, db_path: Optional[str] = None):
        self.config = get_config()
        self.db_path = Path(db_path or self.config.get_db_path()).resolve()
        self.logger = get_logger()
        self._ensure_db_dir()
        self.init_schema()

    def _ensure_db_dir(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for SQLite connections with foreign key enforcement."""
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=15.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database error on {self.db_path}: {e}")
            raise DatabaseError(f"Database query failed: {e}") from e
        finally:
            if conn:
                conn.close()

    def init_schema(self):
        """Execute schema.sql and apply all pending migrations safely."""
        from app.database.migrations import apply_migrations
        schema_file = self.config.base_dir / "database" / "schema.sql"
        if not schema_file.exists():
            raise DatabaseError(f"Schema file not found at {schema_file}")

        try:
            with open(schema_file, "r", encoding="utf-8") as f:
                schema_sql = f.read()

            with self.get_connection() as conn:
                conn.executescript(schema_sql)
                apply_migrations(conn)
            self.logger.info(f"Database schema & migrations applied successfully at {self.db_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize schema: {e}")
            raise DatabaseError(f"Failed to initialize database schema: {e}") from e

    def backup_database(self, destination_dir: Optional[str] = None) -> str:
        """Create a point-in-time timestamped backup of the database."""
        dest_dir = Path(destination_dir or (self.config.base_dir / "database" / "backups")).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = dest_dir / f"cyberwolf_backup_{timestamp}.db"
        
        try:
            with self.get_connection() as src_conn:
                dest_conn = sqlite3.connect(str(backup_file))
                src_conn.backup(dest_conn)
                dest_conn.close()
            self.logger.info(f"Database backup created at {backup_file}")
            return str(backup_file)
        except Exception as e:
            raise DatabaseError(f"Failed to backup database: {e}") from e

_DB_INSTANCE: Optional[DatabaseManager] = None

def get_db(db_path: Optional[str] = None) -> DatabaseManager:
    global _DB_INSTANCE
    if _DB_INSTANCE is None or (db_path and str(_DB_INSTANCE.db_path) != str(Path(db_path).resolve())):
        _DB_INSTANCE = DatabaseManager(db_path)
    return _DB_INSTANCE
