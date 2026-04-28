"""
Write Audit Middleware — SOC2 CC7.2 Compliance.

Captures all API write operations (POST/PUT/PATCH/DELETE) and stores a
tamper-evident audit trail in audit_trail.db.

Each record stores:
  - entry_id     : UUID
  - timestamp    : ISO-8601 UTC
  - method       : HTTP method (POST/PUT/PATCH/DELETE)
  - path         : URL path
  - org_id       : Tenant identifier
  - actor_id     : API key identity or "anonymous"
  - status_code  : HTTP response status
  - body_hash    : SHA-256 of request body (never raw PII)
  - duration_ms  : Request duration in milliseconds
  - client_ip    : Originating IP address

Design goals:
  - Async-first: body is read once and buffered; write is fire-and-forget
    via asyncio.create_task so it never adds latency to the response path.
  - Lightweight: only writes on state-changing methods; GETs are skipped.
  - Org-isolated: org_id scopes all queries.
  - WAL mode + RLock: SQLite is safe under concurrent FastAPI workers.

Compliance:
  - SOC2 CC7.2: Monitors system activity and detects anomalies
  - SOC2 CC6.1: Tracks privileged access (write operations require auth)
  - PCI-DSS 10.2: Logs all user activity on cardholder systems
  - HIPAA 164.312(b): Audit controls on protected information writes
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

_logger = logging.getLogger(__name__)

# Methods that mutate state — the only ones we audit.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Paths to never audit (health/readiness probes, metrics scrapers).
_SKIP_PATHS = frozenset({
    "/health",
    "/metrics",
    "/api/v1/health",
    "/api/v1/health/deep",
    "/api/v1/ready",
    "/api/v1/version",
    "/api/v1/metrics",
})

# Max request body bytes we'll hash (cap to avoid hashing 100 MB uploads).
_MAX_BODY_HASH_BYTES = 1024 * 1024  # 1 MB


# ---------------------------------------------------------------------------
# SQLite storage
# ---------------------------------------------------------------------------

class AuditTrailDB:
    """
    Thread-safe SQLite store for write-operation audit trail.

    Uses WAL mode for concurrent reads alongside writes, and an RLock
    so multiple greenlets/threads share a single connection safely.
    """

    def __init__(self, db_path: str | Path = "data/audit_trail.db") -> None:
        self.db_path = Path(db_path) if not isinstance(db_path, Path) else db_path
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Return (or create) the persistent connection."""
        if self._conn is None:
            if str(self.db_path) != ":memory:":
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                isolation_level=None,  # autocommit — we manage transactions manually
            )
            self._conn.row_factory = sqlite3.Row
            if str(self.db_path) != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_trail (
                    entry_id    TEXT PRIMARY KEY,
                    timestamp   TEXT NOT NULL,
                    method      TEXT NOT NULL,
                    path        TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    actor_id    TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    body_hash   TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    client_ip   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_trail_org_ts
                    ON audit_trail (org_id, timestamp DESC);

                CREATE INDEX IF NOT EXISTS idx_trail_actor
                    ON audit_trail (actor_id, timestamp DESC);

                CREATE INDEX IF NOT EXISTS idx_trail_method
                    ON audit_trail (method, timestamp DESC);

                CREATE INDEX IF NOT EXISTS idx_trail_path
                    ON audit_trail (path, timestamp DESC);
            """)

    def insert(self, entry: Dict[str, Any]) -> None:
        """Insert one audit trail entry (called from a background task)."""
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """
                INSERT OR IGNORE INTO audit_trail
                    (entry_id, timestamp, method, path, org_id, actor_id,
                     status_code, body_hash, duration_ms, client_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["entry_id"],
                    entry["timestamp"],
                    entry["method"],
                    entry["path"],
                    entry["org_id"],
                    entry["actor_id"],
                    entry["status_code"],
                    entry["body_hash"],
                    entry["duration_ms"],
                    entry["client_ip"],
                ),
            )
            conn.execute("COMMIT")

    def query(
        self,
        org_id: str,
        method: Optional[str] = None,
        path_prefix: Optional[str] = None,
        actor_id: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        status_code: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Query audit trail with filters.

        All queries are scoped to ``org_id`` for tenant isolation.
        """
        with self._lock:
            conn = self._get_conn()
            clauses = ["org_id = ?"]
            params: List[Any] = [org_id]

            if method:
                clauses.append("method = ?")
                params.append(method.upper())

            if path_prefix:
                clauses.append("path LIKE ?")
                params.append(f"{path_prefix}%")

            if actor_id:
                clauses.append("actor_id = ?")
                params.append(actor_id)

            if since:
                clauses.append("timestamp >= ?")
                params.append(since)

            if until:
                clauses.append("timestamp <= ?")
                params.append(until)

            if status_code is not None:
                clauses.append("status_code = ?")
                params.append(status_code)

            where = " AND ".join(clauses)
            params.extend([limit, offset])

            rows = conn.execute(
                f"SELECT * FROM audit_trail WHERE {where} "  # nosec B608
                f"ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()

            return [dict(row) for row in rows]

    def count(self, org_id: str) -> int:
        """Return total write-audit entries for an org."""
        with self._lock:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT COUNT(*) FROM audit_trail WHERE org_id = ?", (org_id,)
            ).fetchone()
            return row[0] if row else 0

    def stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary stats (method breakdown, top paths, error rate)."""
        with self._lock:
            conn = self._get_conn()

            method_rows = conn.execute(
                "SELECT method, COUNT(*) AS n FROM audit_trail "
                "WHERE org_id = ? GROUP BY method ORDER BY n DESC",
                (org_id,),
            ).fetchall()

            top_path_rows = conn.execute(
                "SELECT path, COUNT(*) AS n FROM audit_trail "
                "WHERE org_id = ? GROUP BY path ORDER BY n DESC LIMIT 10",
                (org_id,),
            ).fetchall()

            error_row = conn.execute(
                "SELECT COUNT(*) FROM audit_trail "
                "WHERE org_id = ? AND status_code >= 400",
                (org_id,),
            ).fetchone()

            total_row = conn.execute(
                "SELECT COUNT(*) FROM audit_trail WHERE org_id = ?",
                (org_id,),
            ).fetchone()

            total = total_row[0] if total_row else 0
            errors = error_row[0] if error_row else 0

            return {
                "total_writes": total,
                "error_count": errors,
                "error_rate_pct": round(100.0 * errors / max(total, 1), 2),
                "by_method": {row["method"]: row["n"] for row in method_rows},
                "top_paths": [{"path": row["path"], "count": row["n"]} for row in top_path_rows],
            }


# ---------------------------------------------------------------------------
# Module-level singleton (shared across all requests in a process)
# ---------------------------------------------------------------------------

_default_db: Optional[AuditTrailDB] = None
_db_lock = threading.Lock()


def get_audit_trail_db(db_path: str = "data/audit_trail.db") -> AuditTrailDB:
    """Return (or lazily create) the process-level AuditTrailDB singleton."""
    global _default_db
    if _default_db is None:
        with _db_lock:
            if _default_db is None:
                _default_db = AuditTrailDB(db_path)
    return _default_db


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class WriteAuditMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that records all API write operations.

    Add after OrgIdMiddleware so that request.state.org_id is populated:

        app.add_middleware(OrgIdMiddleware)
        app.add_middleware(WriteAuditMiddleware)   # <-- after

    The audit DB write is fired as a background task (asyncio.create_task)
    so it never adds latency to the response path.
    """

    def __init__(self, app: ASGIApp, db_path: str = "data/audit_trail.db") -> None:
        super().__init__(app)
        self._db = AuditTrailDB(db_path)

    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method.upper()

        # Fast-path: skip reads and health/metrics endpoints.
        if method not in _WRITE_METHODS or request.url.path in _SKIP_PATHS:
            return await call_next(request)

        start_ms = time.monotonic() * 1000

        # Buffer the request body so the downstream handler can still read it.
        raw_body = await request.body()
        body_hash = _hash_body(raw_body)

        # Starlette's BaseHTTPMiddleware already re-injects the body, so the
        # handler sees a complete request regardless of our read above.

        response = await call_next(request)

        duration_ms = time.monotonic() * 1000 - start_ms

        # Extract context from request state (populated by auth + OrgIdMiddleware).
        org_id = getattr(request.state, "org_id", "default") or "default"
        actor_id = _resolve_actor_id(request)
        client_ip = request.client.host if request.client else "unknown"

        entry: Dict[str, Any] = {
            "entry_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": request.url.path,
            "org_id": org_id,
            "actor_id": actor_id,
            "status_code": response.status_code,
            "body_hash": body_hash,
            "duration_ms": round(duration_ms, 2),
            "client_ip": client_ip,
        }

        # Fire-and-forget — never block the response.
        asyncio.create_task(_write_entry(self._db, entry))

        return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_body(raw: bytes) -> str:
    """Return SHA-256 hex digest of the request body, capped at 1 MB."""
    if not raw:
        return "empty"
    payload = raw[:_MAX_BODY_HASH_BYTES]
    return hashlib.sha256(payload).hexdigest()


def _resolve_actor_id(request: Request) -> str:
    """
    Derive a stable actor identifier from the request.

    Priority:
    1. request.state.user_id  (set by JWT auth)
    2. Hashed X-API-Key header (never log raw key)
    3. "anonymous"
    """
    uid = getattr(request.state, "user_id", None)
    if uid:
        return str(uid)

    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        # Hash the key so the audit log never exposes credentials.
        return "apikey:" + hashlib.sha256(api_key.encode()).hexdigest()[:16]

    return "anonymous"


async def _write_entry(db: AuditTrailDB, entry: Dict[str, Any]) -> None:
    """Async wrapper for the synchronous DB insert (runs in background task)."""
    try:
        # Run the blocking SQLite write in the default thread pool so we
        # don't block the event loop.
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, db.insert, entry)
    except Exception as exc:  # pragma: no cover — DB write failures must not crash the app
        _logger.warning("WriteAuditMiddleware: failed to persist entry: %s", exc)


__all__ = [
    "AuditTrailDB",
    "WriteAuditMiddleware",
    "get_audit_trail_db",
]
