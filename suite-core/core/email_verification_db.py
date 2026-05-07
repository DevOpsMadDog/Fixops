"""
Email verification token store — lightweight SQLite-backed.

Tokens are UUID4, expire in 24 hours, single-use.
Stores email_verified flag per user_id so auth_router can check without
touching the main users table schema.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


_DEFAULT_DB = "data/email_verification.db"
_TOKEN_TTL_HOURS = 24


class EmailVerificationDB:
    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = Path(db_path)
        self._db.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self._db))
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS verification_tokens (
                    token      TEXT PRIMARY KEY,
                    user_id    TEXT NOT NULL,
                    email      TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used       INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS verified_emails (
                    user_id    TEXT PRIMARY KEY,
                    email      TEXT NOT NULL,
                    verified_at TEXT NOT NULL
                );
            """)

    def create_token(self, user_id: str, email: str) -> str:
        token = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(hours=_TOKEN_TTL_HOURS)
        with self._conn() as c:
            c.execute(
                "INSERT INTO verification_tokens (token, user_id, email, expires_at) VALUES (?,?,?,?)",
                (token, user_id, email, expires.isoformat()),
            )
        return token

    def consume_token(self, token: str) -> Optional[dict]:
        """Validate and consume token. Returns {user_id, email} or None."""
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM verification_tokens WHERE token=? AND used=0", (token,)
            ).fetchone()
            if not row:
                return None
            expires = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > expires:
                return None
            c.execute("UPDATE verification_tokens SET used=1 WHERE token=?", (token,))
            c.execute(
                "INSERT OR REPLACE INTO verified_emails (user_id, email, verified_at) VALUES (?,?,?)",
                (row["user_id"], row["email"], datetime.now(timezone.utc).isoformat()),
            )
        return {"user_id": row["user_id"], "email": row["email"]}

    def is_verified(self, user_id: str) -> bool:
        with self._conn() as c:
            row = c.execute(
                "SELECT 1 FROM verified_emails WHERE user_id=?", (user_id,)
            ).fetchone()
        return row is not None
