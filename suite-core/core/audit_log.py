"""
ALDECI Audit Log — write-operation tracking with SQLite persistence.

Provides:
- AuditAction enum (CREATE, UPDATE, DELETE, EXECUTE, LOGIN, LOGOUT, EXPORT)
- AuditEntry Pydantic model
- AuditLogger class (thread-safe singleton, SQLite-backed)

Distinct from the existing audit_logger.py (enterprise event logger used by
AuditMiddleware). This module tracks granular write operations at the API layer
and is wired to the audit_router endpoints.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AuditAction(str, Enum):
    """Actions that can be recorded in the audit log."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    LOGIN = "login"
    LOGOUT = "logout"
    EXPORT = "export"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class AuditEntry(BaseModel):
    """A single audit log entry."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_email: str
    user_role: str
    action: AuditAction
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    user_email      TEXT NOT NULL,
    user_role       TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    details         TEXT NOT NULL DEFAULT '{}',
    ip_address      TEXT,
    correlation_id  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_al_user       ON audit_log (user_email, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_al_resource   ON audit_log (resource_type, resource_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_al_action     ON audit_log (action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_al_timestamp  ON audit_log (timestamp DESC);
"""


class AuditLogger:
    """Thread-safe, SQLite-backed audit log.

    Usage (singleton pattern)::

        logger = AuditLogger.get_instance()
        logger.log(
            action=AuditAction.CREATE,
            resource_type="finding",
            resource_id="f-123",
            details={"severity": "high"},
            user_email="alice@example.com",
            user_role="security_analyst",
        )
    """

    _instance: Optional[AuditLogger] = None
    _instance_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls, db_path: str | Path = ":memory:") -> AuditLogger:
        """Return the process-wide singleton, creating it if needed."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton (useful for tests)."""
        with cls._instance_lock:
            cls._instance = None

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = db_path if isinstance(db_path, Path) else Path(str(db_path))
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._file_conn: Optional[sqlite3.Connection] = None  # persistent file-backed connection
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if str(self._db_path) == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        # Reuse a single persistent connection per instance (thread-safe via self._lock).
        if self._file_conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._file_conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._file_conn.row_factory = sqlite3.Row
        return self._file_conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript(_SCHEMA)
            conn.commit()

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        d = dict(row)
        d["details"] = json.loads(d.get("details") or "{}")
        return AuditEntry(**d)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def log(
        self,
        action: AuditAction,
        resource_type: str,
        resource_id: str,
        *,
        user_email: str = "system",
        user_role: str = "system",
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
        # Convenience: accept an AuthContext-like object
        user: Any = None,
        request: Any = None,
    ) -> AuditEntry:
        """Record an audit entry and return it."""
        # Resolve user_email / user_role from an auth context object when supplied
        if user is not None:
            user_email = getattr(user, "email", user_email) or user_email
            user_role = getattr(user, "role", user_role) or user_role

        # Resolve ip_address and correlation_id from FastAPI Request when supplied
        if request is not None and ip_address is None:
            client = getattr(request, "client", None)
            if client:
                ip_address = getattr(client, "host", None)
            if correlation_id is None:
                headers = getattr(request, "headers", {})
                correlation_id = (
                    headers.get("x-correlation-id")
                    or headers.get("x-request-id")
                    or str(uuid.uuid4())
                )

        entry = AuditEntry(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_email=user_email,
            user_role=user_role,
            details=details or {},
            ip_address=ip_address,
            correlation_id=correlation_id or str(uuid.uuid4()),
        )

        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO audit_log
                    (id, timestamp, user_email, user_role, action,
                     resource_type, resource_id, details, ip_address, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.timestamp.isoformat(),
                    entry.user_email,
                    entry.user_role,
                    entry.action if isinstance(entry.action, str) else entry.action.value,
                    entry.resource_type,
                    entry.resource_id,
                    json.dumps(entry.details),
                    entry.ip_address,
                    entry.correlation_id,
                ),
            )
            conn.commit()

        _logger.debug(
            "audit_log: %s %s/%s by %s",
            entry.action,
            entry.resource_type,
            entry.resource_id,
            entry.user_email,
        )
        return entry

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def query(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """Return audit entries matching *filters*.

        Supported filter keys:
            user_email, user_role, action, resource_type, resource_id
        """
        filters = filters or {}
        clauses: List[str] = []
        params: List[Any] = []

        for col in ("user_email", "user_role", "action", "resource_type", "resource_id"):
            if col in filters and filters[col] is not None:
                clauses.append(f"{col} = ?")
                params.append(filters[col])

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"  # nosec B608
        params += [limit, offset]

        with self._lock:
            conn = self._connect()
            rows = conn.execute(sql, params).fetchall()

        return [self._row_to_entry(r) for r in rows]

    def get_user_activity(self, email: str, days: int = 30) -> List[AuditEntry]:
        """Return entries for *email* within the last *days* days."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        sql = (
            "SELECT * FROM audit_log "
            "WHERE user_email = ? AND timestamp >= ? "
            "ORDER BY timestamp DESC LIMIT 1000"
        )
        with self._lock:
            conn = self._connect()
            rows = conn.execute(sql, [email, since]).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_resource_history(
        self, resource_type: str, resource_id: str
    ) -> List[AuditEntry]:
        """Return full audit trail for a specific resource."""
        sql = (
            "SELECT * FROM audit_log "
            "WHERE resource_type = ? AND resource_id = ? "
            "ORDER BY timestamp DESC LIMIT 1000"
        )
        with self._lock:
            conn = self._connect()
            rows = conn.execute(sql, [resource_type, resource_id]).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def export_csv(self, filters: Optional[Dict[str, Any]] = None) -> str:
        """Export matching entries as CSV string."""
        entries = self.query(filters=filters, limit=100_000)
        buf = io.StringIO()
        if not entries:
            return buf.getvalue()
        fieldnames = list(AuditEntry.model_fields.keys())
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            row = entry.model_dump()
            row["timestamp"] = row["timestamp"].isoformat()
            row["details"] = json.dumps(row["details"])
            writer.writerow(row)
        return buf.getvalue()

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count entries matching filters."""
        return len(self.query(filters=filters, limit=1_000_000))

    # ------------------------------------------------------------------
    # Retention & Purging
    # ------------------------------------------------------------------

    def purge_old(self, retention_days: int = 90) -> int:
        """Delete audit entries older than retention_days.

        Returns the number of rows deleted.
        """
        threshold = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._lock:
            conn = self._connect()
            cursor = conn.execute(
                "DELETE FROM audit_log WHERE timestamp < ?",
                [threshold],
            )
            conn.commit()
            deleted = cursor.rowcount
        _logger.info(
            "audit_log.purge_old: deleted %d entries older than %d days",
            deleted,
            retention_days,
        )
        return deleted


# ---------------------------------------------------------------------------
# Audit Middleware
# ---------------------------------------------------------------------------

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import Response as StarletteResponse

    class AuditMiddleware(BaseHTTPMiddleware):
        """Starlette middleware that auto-logs all write-method requests."""

        _WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
        _SKIP_PATHS = frozenset({"/health", "/healthz", "/metrics", "/docs", "/openapi.json"})

        def __init__(self, app: Any, audit_logger: Optional[AuditLogger] = None) -> None:
            super().__init__(app)
            self._audit = audit_logger or AuditLogger.get_instance()

        async def dispatch(
            self, request: StarletteRequest, call_next: Any
        ) -> StarletteResponse:
            response = await call_next(request)

            method = request.method.upper()
            path = request.url.path

            if method not in self._WRITE_METHODS or path in self._SKIP_PATHS:
                return response

            # Extract auth info from request state (set by require_auth)
            auth = getattr(request.state, "auth", None)
            user_email = getattr(auth, "email", "anonymous") if auth else "anonymous"
            user_role = getattr(auth, "role", "unknown") if auth else "unknown"

            # Map HTTP method → AuditAction
            action_map = {
                "POST": AuditAction.CREATE,
                "PUT": AuditAction.UPDATE,
                "PATCH": AuditAction.UPDATE,
                "DELETE": AuditAction.DELETE,
            }
            action = action_map.get(method, AuditAction.EXECUTE)

            # Detect login/logout paths
            if "login" in path:
                action = AuditAction.LOGIN
            elif "logout" in path:
                action = AuditAction.LOGOUT
            elif "export" in path:
                action = AuditAction.EXPORT

            client = getattr(request, "client", None)
            ip = getattr(client, "host", None) if client else None
            headers = dict(request.headers)
            correlation_id = (
                headers.get("x-correlation-id")
                or headers.get("x-request-id")
                or str(uuid.uuid4())
            )

            self._audit.log(
                action=action,
                resource_type="api_endpoint",
                resource_id=path,
                user_email=user_email,
                user_role=user_role,
                details={"method": method, "status_code": response.status_code},
                ip_address=ip,
                correlation_id=correlation_id,
            )

            return response

except ImportError:
    class AuditMiddleware:  # type: ignore[no-redef]
        """Stub when Starlette is unavailable."""

        def __init__(self, app: Any, audit_logger: Optional[Any] = None) -> None:
            self._audit = audit_logger


__all__ = [
    "AuditAction",
    "AuditEntry",
    "AuditLogger",
    "AuditMiddleware",
]
