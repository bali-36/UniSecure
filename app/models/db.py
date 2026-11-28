"""Database connection helpers and audit logging for UniSecure."""

import sqlite3
from flask import current_app, g


def get_db() -> sqlite3.Connection:
    """Return a request-scoped SQLite connection with foreign keys enabled."""
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE_PATH"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exception=None) -> None:
    """Close the request-scoped SQLite connection if open."""
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def log_audit(
    action: str,
    target_type: str,
    target_id: str | int | None = None,
    details: str = "",
    actor_id: int | None = None,
    ip_address: str = "127.0.0.1",
) -> None:
    """Persist an activity record in audit_logs."""
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_logs (actor_id, action, target_type, target_id, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            action,
            target_type,
            str(target_id) if target_id is not None else None,
            details,
            ip_address,
        ),
    )
    db.commit()
