"""
User Session Management — SQLite-backed session lifecycle with security detection.

Provides full session lifecycle: create, validate, refresh, terminate, cleanup.
Includes concurrent session detection and suspicious session flagging.

Thread-safe via per-thread SQLite connections (WAL mode).

Usage::

    mgr = SessionManager()
    session = mgr.create_session(
        user_email="alice@example.com",
        ip_address="10.0.0.1",
        user_agent="Mozilla/5.0",
        org_id="acme",
    )
    validated = mgr.validate_session(session.id)
    mgr.refresh_session(session.id)
    mgr.terminate_session(session.id)

Environment:
    FIXOPS_DATA_DIR   directory for the SQLite DB (default: ``.fixops_data``)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


import json
import logging
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_SESSION_PREFIX = "sess_"
_DB_ENV = "FIXOPS_DATA_DIR"
_DEFAULT_DB_DIR = ".fixops_data"
_DEFAULT_TTL_HOURS = int(os.getenv("FIXOPS_SESSION_TTL_HOURS", "24"))
# Threshold: sessions from 3+ distinct IPs flagged as suspicious
_SUSPICIOUS_IP_THRESHOLD = 3


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class Session(BaseModel):
    """User session record."""

    id: str
    user_email: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_active: datetime
    expires_at: datetime
    is_active: bool
    org_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    return datetime.fromisoformat(val)


def _generate_session_id() -> str:
    return _SESSION_PREFIX + secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class SessionManager:
    """
    SQLite-backed user session manager.

    Thread-safe: each thread keeps its own connection via ``threading.local``.
    Singleton pattern: calling ``SessionManager()`` without arguments returns
    the same instance; pass an explicit ``db_path`` to create a separate
    instance (useful for testing).
    """

    _instance: Optional["SessionManager"] = None
    _class_lock: threading.Lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None) -> "SessionManager":
        with cls._class_lock:
            if db_path is not None:
                inst = object.__new__(cls)
                inst._init(db_path)
                return inst
            if cls._instance is None:
                inst = object.__new__(cls)
                default_path = os.path.join(
                    os.getenv(_DB_ENV, _DEFAULT_DB_DIR), "sessions.db"
                )
                inst._init(default_path)
                cls._instance = inst
            return cls._instance  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init(self, db_path: str) -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id          TEXT PRIMARY KEY,
                    user_email  TEXT NOT NULL,
                    ip_address  TEXT NOT NULL,
                    user_agent  TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    last_active TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    is_active   INTEGER NOT NULL DEFAULT 1,
                    org_id      TEXT NOT NULL,
                    metadata    TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sess_email ON sessions(user_email)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sess_org ON sessions(org_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sess_expires ON sessions(expires_at)"
            )

    # ------------------------------------------------------------------
    # Row converter
    # ------------------------------------------------------------------

    def _row_to_session(self, row: Dict[str, Any]) -> Session:
        return Session(
            id=row["id"],
            user_email=row["user_email"],
            ip_address=row["ip_address"],
            user_agent=row["user_agent"],
            created_at=_parse_dt(row["created_at"]) or _now(),
            last_active=_parse_dt(row["last_active"]) or _now(),
            expires_at=_parse_dt(row["expires_at"]) or _now(),
            is_active=bool(row["is_active"]),
            org_id=row["org_id"],
            metadata=json.loads(row.get("metadata") or "{}"),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_session(
        self,
        user_email: str,
        ip_address: str,
        user_agent: str,
        org_id: str,
        ttl_hours: int = _DEFAULT_TTL_HOURS,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Session:
        """Create a new session with configurable TTL.

        Returns the new ``Session`` record.
        """
        now = _now()
        session_id = _generate_session_id()
        expires_at = now + timedelta(hours=ttl_hours)
        meta = metadata or {}

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO sessions
                    (id, user_email, ip_address, user_agent, created_at,
                     last_active, expires_at, is_active, org_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    session_id,
                    user_email,
                    ip_address,
                    user_agent,
                    now.isoformat(),
                    now.isoformat(),
                    expires_at.isoformat(),
                    org_id,
                    json.dumps(meta),
                ),
            )

        session = Session(
            id=session_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now,
            last_active=now,
            expires_at=expires_at,
            is_active=True,
            org_id=org_id,
            metadata=meta,
        )
        _logger.info(
            "Created session %s for user=%s org=%s ip=%s",
            session_id,
            user_email,
            org_id,
            ip_address,
        )
        _emit_event("session_manager.session_created", {
            "session_id": session_id,
            "user_email": user_email,
            "org_id": org_id,
            "ip_address": ip_address,
            "ttl_hours": ttl_hours,
            "expires_at": expires_at.isoformat(),
        })
        return session

    def validate_session(self, session_id: str) -> Optional[Session]:
        """Check if a session is valid and active.

        Returns the ``Session`` if valid, ``None`` otherwise.
        Does NOT update ``last_active`` — call ``refresh_session`` for that.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()

        if not row:
            return None

        session = self._row_to_session(dict(row))

        if not session.is_active:
            return None

        if session.expires_at < _now():
            return None

        return session

    def refresh_session(
        self,
        session_id: str,
        ttl_hours: Optional[int] = None,
    ) -> Optional[Session]:
        """Extend session expiry on activity.

        Updates ``last_active`` and optionally extends ``expires_at`` by
        ``ttl_hours`` from now.  Returns updated session or ``None`` if
        the session is invalid/expired.
        """
        session = self.validate_session(session_id)
        if session is None:
            return None

        now = _now()
        new_expires = (
            now + timedelta(hours=ttl_hours)
            if ttl_hours is not None
            else session.expires_at
        )

        with self._conn() as conn:
            conn.execute(
                "UPDATE sessions SET last_active = ?, expires_at = ? WHERE id = ?",
                (now.isoformat(), new_expires.isoformat(), session_id),
            )

        session.last_active = now
        session.expires_at = new_expires
        return session

    def terminate_session(self, session_id: str) -> bool:
        """Terminate a single session (logout).

        Returns ``True`` if the session was found and deactivated,
        ``False`` if it did not exist.
        """
        with self._conn() as conn:
            result = conn.execute(
                "UPDATE sessions SET is_active = 0 WHERE id = ? AND is_active = 1",
                (session_id,),
            )

        if result.rowcount == 0:
            return False

        _logger.info("Terminated session %s", session_id)
        _emit_event("session_manager.session_terminated", {
            "session_id": session_id,
        })
        return True

    def terminate_all_sessions(self, user_email: str) -> int:
        """Force logout of all active sessions for a user.

        Returns the count of sessions terminated.
        """
        with self._conn() as conn:
            result = conn.execute(
                "UPDATE sessions SET is_active = 0 WHERE user_email = ? AND is_active = 1",
                (user_email,),
            )

        count = result.rowcount
        _logger.info(
            "Terminated %d session(s) for user=%s", count, user_email
        )
        return count

    def get_active_sessions(self, user_email: str) -> List[Session]:
        """List all active, non-expired sessions for a user."""
        now_str = _now().isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM sessions
                WHERE user_email = ? AND is_active = 1 AND expires_at > ?
                ORDER BY last_active DESC
                """,
                (user_email, now_str),
            ).fetchall()
        return [self._row_to_session(dict(r)) for r in rows]

    def cleanup_expired(self) -> int:
        """Hard-delete expired and inactive sessions.

        Returns the count of sessions purged.
        """
        now_str = _now().isoformat()
        with self._conn() as conn:
            result = conn.execute(
                "DELETE FROM sessions WHERE is_active = 0 OR expires_at <= ?",
                (now_str,),
            )

        count = result.rowcount
        if count:
            _logger.info("Cleaned up %d expired/inactive session(s)", count)
        return count

    def get_session_stats(self, org_id: str) -> Dict[str, Any]:
        """Return session statistics for an org.

        Returns:
            active_count: number of currently active, non-expired sessions
            avg_duration_seconds: average session age in seconds
            by_user: dict mapping user_email -> active session count
        """
        now_str = _now().isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT user_email, created_at, last_active
                FROM sessions
                WHERE org_id = ? AND is_active = 1 AND expires_at > ?
                """,
                (org_id, now_str),
            ).fetchall()

        now = _now()
        by_user: Dict[str, int] = {}
        total_duration = 0.0

        for row in rows:
            email = row["user_email"]
            by_user[email] = by_user.get(email, 0) + 1
            created = _parse_dt(row["created_at"])
            if created:
                total_duration += (now - created).total_seconds()

        active_count = len(rows)
        avg_duration = total_duration / active_count if active_count else 0.0

        return {
            "org_id": org_id,
            "active_count": active_count,
            "avg_duration_seconds": round(avg_duration, 2),
            "by_user": by_user,
        }

    def detect_concurrent_sessions(self, user_email: str) -> Dict[str, Any]:
        """Flag multiple active sessions for a user.

        Returns:
            has_concurrent: True if more than one active session exists
            session_count: total number of active sessions
            sessions: list of active session records
        """
        sessions = self.get_active_sessions(user_email)
        return {
            "user_email": user_email,
            "has_concurrent": len(sessions) > 1,
            "session_count": len(sessions),
            "sessions": sessions,
        }

    def get_suspicious_sessions(self, org_id: str) -> List[Dict[str, Any]]:
        """Return users with suspicious session patterns within an org.

        Suspicious patterns detected:
        - User has sessions from 3+ distinct IP addresses simultaneously
        - User has sessions with 3+ distinct user agents simultaneously

        Returns a list of dicts with ``user_email``, ``reason``,
        ``distinct_ips``, ``distinct_agents``, and ``sessions``.
        """
        now_str = _now().isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM sessions
                WHERE org_id = ? AND is_active = 1 AND expires_at > ?
                ORDER BY user_email, created_at DESC
                """,
                (org_id, now_str),
            ).fetchall()

        # Group by user
        by_user: Dict[str, List[Session]] = {}
        for row in rows:
            session = self._row_to_session(dict(row))
            by_user.setdefault(session.user_email, []).append(session)

        suspicious: List[Dict[str, Any]] = []
        for email, user_sessions in by_user.items():
            distinct_ips = {s.ip_address for s in user_sessions}
            distinct_agents = {s.user_agent for s in user_sessions}

            reasons: List[str] = []
            if len(distinct_ips) >= _SUSPICIOUS_IP_THRESHOLD:
                reasons.append(
                    f"sessions from {len(distinct_ips)} distinct IP addresses"
                )
            if len(distinct_agents) >= _SUSPICIOUS_IP_THRESHOLD:
                reasons.append(
                    f"sessions with {len(distinct_agents)} distinct user agents"
                )

            if reasons:
                suspicious.append(
                    {
                        "user_email": email,
                        "reason": "; ".join(reasons),
                        "distinct_ips": sorted(distinct_ips),
                        "distinct_agents": sorted(distinct_agents),
                        "sessions": user_sessions,
                    }
                )

        return suspicious


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------


def get_session_manager(db_path: Optional[str] = None) -> SessionManager:
    """Return the singleton ``SessionManager`` (or a new instance for a custom path)."""
    return SessionManager(db_path=db_path)
