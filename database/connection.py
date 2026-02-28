"""
SQLite connection manager for ShieldAI.

This module provides a small, safe wrapper around sqlite3 for:
- creating connections with sane defaults
- initializing the database schema on first run
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from config import Settings


_init_lock = threading.Lock()
_initialized_paths: set[str] = set()


def _connect(db_path: str) -> sqlite3.Connection:
    """Create a SQLite connection with recommended settings."""

    conn = sqlite3.connect(
        db_path,
        check_same_thread=False,
        isolation_level=None,  # autocommit; we use explicit BEGIN for transactions
        timeout=30,
    )
    conn.row_factory = sqlite3.Row
    # Better concurrency / reliability on SQLite
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def get_connection(settings: Settings) -> Iterator[sqlite3.Connection]:
    """
    Yield an initialized SQLite connection.

    The schema is created the first time the database is accessed.
    """

    initialize_database(settings)
    conn = _connect(settings.database_path)
    try:
        yield conn
    finally:
        conn.close()


def initialize_database(settings: Settings) -> None:
    """Initialize the database schema if it hasn't been created yet."""

    db_path = settings.database_path
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with _init_lock:
        if db_path in _initialized_paths:
            return

        conn = _connect(db_path)
        try:
            conn.execute("BEGIN;")
            # Required tables per spec: attacks, stats, feedback
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    prompt TEXT NOT NULL,
                    context TEXT,
                    attack_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    pattern_matches TEXT,
                    semantic_result TEXT,
                    anomaly_score REAL,
                    final_verdict TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    total_scans INTEGER NOT NULL,
                    total_attacks_blocked INTEGER NOT NULL,
                    attacks_by_type TEXT NOT NULL,
                    daily_stats TEXT NOT NULL,
                    last_updated TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    prompt_id INTEGER NOT NULL,
                    was_correct INTEGER NOT NULL,
                    correct_label TEXT,
                    feedback_at TEXT NOT NULL,
                    FOREIGN KEY(prompt_id) REFERENCES attacks(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    password_salt BLOB,
                    password_hash BLOB,
                    google_sub TEXT UNIQUE,
                    email_verified INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_attacks_timestamp
                ON attacks(timestamp);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_attacks_attack_type
                ON attacks(attack_type);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_feedback_prompt_id
                ON feedback(prompt_id);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_users_email
                ON users(email);
                """
            )

            # Ensure the single stats row exists.
            row = conn.execute("SELECT id FROM stats WHERE id = 1;").fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO stats (id, total_scans, total_attacks_blocked, attacks_by_type, daily_stats, last_updated)
                    VALUES (1, 0, 0, '{}', '{}', datetime('now'));
                    """
                )
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

        _initialized_paths.add(db_path)

