"""
AY Vault - Database Connection & Transaction Manager
Provides connection pooling, row wrapping, WAL mode initialization, and thread safety.
"""

import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional
from config.settings import DB_PATH
from database.schema import SCHEMA_SQL


class DatabaseManager:
    """Manages SQLite connections and queries with WAL mode and row mapping."""

    _instance: Optional["DatabaseManager"] = None
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DatabaseManager, cls).__new__(cls)
                cls._instance._db_path = str(db_path or DB_PATH)
                cls._instance._local = threading.local()
            return cls._instance

    def get_connection(self) -> sqlite3.Connection:
        """Returns a thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # Enable WAL mode for high reliability and foreign keys
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
        return self._local.conn

    def initialize_schema(self) -> None:
        """Creates tables, triggers, and indexes if they do not exist."""
        conn = self.get_connection()
        with conn:
            conn.executescript(SCHEMA_SQL)

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Transactional context manager with automatic commit/rollback."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

    def execute(self, query: str, params: tuple = ()) -> int:
        """Executes a query and returns the lastrowid or affected rows."""
        with self.transaction() as cur:
            cur.execute(query, params)
            return cur.lastrowid or cur.rowcount

    def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Fetches a single row as a standard dictionary."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            cursor.close()

    def fetch_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Fetches all rows as a list of dictionaries."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            cursor.close()

    def close(self) -> None:
        """Closes the current thread's connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


def get_db() -> DatabaseManager:
    """Convenience helper to retrieve the singleton database manager."""
    return DatabaseManager()
