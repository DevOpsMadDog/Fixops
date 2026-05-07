"""
Password reset token store — lightweight SQLite-backed.

Tokens are UUID4, expire in 1 hour, single-use.
Reuses the same pattern as email_verification_db.py.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


_DEFAULT_DB = "data/password_reset.db"
_TOKEN_TTL_MINUTES = 60


class PasswordResetDB:
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
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    token      TEXT PRIMARY KEY,
                    user_id    TEXT NOT NULL,
                    email      TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used       INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_prt_email
                    ON password_reset_tokens(email);
            """)

    def create_token(self, user_id: str, email: str) -> str:
        """Generate a fresh single-use reset token (invalidates previous ones for that email)."""
        token = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(minutes=_TOKEN_TTL_MINUTES)
        with self._conn() as c:
            # Mark any existing unused tokens for this email as used (one active token per account)
            c.execute(
                "UPDATE password_reset_tokens SET used=1 WHERE email=? AND used=0",
                (email,),
            )
            c.execute(
                "INSERT INTO password_reset_tokens (token, user_id, email, expires_at) "
                "VALUES (?,?,?,?)",
                (token, user_id, email, expires.isoformat()),
            )
        return token

    def consume_token(self, token: str) -> Optional[dict]:
        """Validate and consume a reset token. Returns {user_id, email} or None."""
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM password_reset_tokens WHERE token=? AND used=0",
                (token,),
            ).fetchone()
            if not row:
                return None
            expires = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > expires:
                return None
            c.execute(
                "UPDATE password_reset_tokens SET used=1 WHERE token=?",
                (token,),
            )
        return {"user_id": row["user_id"], "email": row["email"]}

    def get_token_info(self, token: str) -> Optional[dict]:
        """Peek at token metadata without consuming it (for validation UX)."""
        with self._conn() as c:
            row = c.execute(
                "SELECT email, expires_at, used FROM password_reset_tokens WHERE token=?",
                (token,),
            ).fetchone()
        if not row:
            return None
        return {
            "email": row["email"],
            "expires_at": row["expires_at"],
            "used": bool(row["used"]),
        }
