"""Detailed Request/Response Logging — full payload capture + SQLite store + REST API.

Phase 17 of ALdeci Transformation Plan.
"""
from __future__ import annotations

import json, logging, os, re, sqlite3, time, uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Query as FQ, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

MAX_BODY = 10_240
_SENS_HDR = {"x-api-key", "authorization", "cookie", "x-auth-token"}
_SENS_BODY = re.compile(
    r"(password|secret|token|api_key|apikey|credential|private_key|access_token|refresh_token)", re.I
)
_SKIP = ("/docs", "/openapi.json", "/redoc", "/favicon.ico", "/static/")
_log_ring: deque = deque(maxlen=500)
_ring_lock = Lock()


def _mask(v: str) -> str:
    return v[:4] + "***" + v[-4:] if len(v) > 8 else "***"


def _san_hdrs(h: dict) -> dict:
    return {k: (_mask(v) if k.lower() in _SENS_HDR else v) for k, v in h.items()}


def _redact(d: dict) -> dict:
    o = {}
    for k, v in d.items():
        if _SENS_BODY.search(k):
            o[k] = "***REDACTED***"
        elif isinstance(v, dict):
            o[k] = _redact(v)
        elif isinstance(v, list):
            o[k] = [_redact(i) if isinstance(i, dict) else i for i in v]
        else:
            o[k] = v
    return o


def _san_body(raw: str) -> str:
    if not raw:
        return raw
    try:
        d = json.loads(raw)
        return json.dumps(_redact(d) if isinstance(d, dict) else d, default=str)
    except Exception:
        return raw


class DetailedLogStore:
    _instance: Optional["DetailedLogStore"] = None
    _lock = Lock()

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            dd = os.environ.get("FIXOPS_DATA_DIR", ".fixops_data")
            Path(dd).mkdir(parents=True, exist_ok=True)
            db_path = os.path.join(dd, "api_detailed_logs.db")
        self._db = db_path
        self._init_schema()

    def _c(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._db, timeout=5)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _init_schema(self):
        c = self._c()
        c.executescript(
            "CREATE TABLE IF NOT EXISTS api_logs ("
            "id TEXT PRIMARY KEY, ts TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,"
            "query_params TEXT, status_code INTEGER, duration_ms REAL,"
            "client_ip TEXT, user_agent TEXT, correlation_id TEXT,"
            "req_headers TEXT, req_body TEXT, resp_headers TEXT, resp_body TEXT,"
            "req_size INTEGER DEFAULT 0, resp_size INTEGER DEFAULT 0,"
            "error TEXT, error_type TEXT, level TEXT DEFAULT 'info');"
            "CREATE INDEX IF NOT EXISTS ix_ts ON api_logs(ts);"
            "CREATE INDEX IF NOT EXISTS ix_path ON api_logs(path);"
            "CREATE INDEX IF NOT EXISTS ix_status ON api_logs(status_code);"
            "CREATE INDEX IF NOT EXISTS ix_level ON api_logs(level);"
        )
        c.commit()
        c.close()

    def insert(self, r: dict):
        try:
            c = self._c()
            c.execute(
                "INSERT INTO api_logs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["id"], r["ts"], r["method"], r["path"], r.get("query_params", ""),
                 r.get("status_code"), r.get("duration_ms"), r.get("client_ip", ""),
                 r.get("user_agent", ""), r.get("correlation_id", ""),
                 json.dumps(r.get("req_headers", {})), r.get("req_body", ""),
                 json.dumps(r.get("resp_headers", {})), r.get("resp_body", ""),
                 r.get("req_size", 0), r.get("resp_size", 0),
                 r.get("error"), r.get("error_type"), r.get("level", "info")))
            c.commit()
            c.close()
        except Exception as e:
            logger.warning("Log insert failed: %s", e)
        with _ring_lock:
            _log_ring.appendleft(r)

    @classmethod
    def get_instance(cls) -> "DetailedLogStore":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def query(self, *, limit=100, offset=0, method=None, path_pat=None,
              status_min=None, status_max=None, level=None, since=None, search=None):
        c = self._c()
        w, p = [], []
        if method:
            w.append("method=?"); p.append(method.upper())
        if path_pat:
            w.append("path LIKE ?"); p.append(f"%{path_pat}%")
        if status_min is not None:
            w.append("status_code>=?"); p.append(status_min)
        if status_max is not None:
            w.append("status_code<=?"); p.append(status_max)
        if level:
            w.append("level=?"); p.append(level)
        if since:
            w.append("ts>=?"); p.append(since)
        if search:
            w.append("(path LIKE ?1 OR req_body LIKE ?1 OR resp_body LIKE ?1 OR error LIKE ?1)")
            w[-1] = w[-1].replace("?1", "?")
            s = f"%{search}%"
            p.extend([s, s, s, s])
        wh = " AND ".join(w) if w else "1=1"
        sql = f"SELECT * FROM api_logs WHERE {wh} ORDER BY ts DESC LIMIT ? OFFSET ?"
        p.extend([limit, offset])
        rows = c.execute(sql, p).fetchall()
        c.close()
        return [self._to_dict(r) for r in rows]

    def count(self):
        c = self._c()
        n = c.execute("SELECT COUNT(*) FROM api_logs").fetchone()[0]
        c.close()
        return n

    def stats(self):
        c = self._c()
        total = c.execute("SELECT COUNT(*) FROM api_logs").fetchone()[0]
        errs = c.execute("SELECT COUNT(*) FROM api_logs WHERE status_code>=400").fetchone()[0]
        avg = c.execute("SELECT AVG(duration_ms) FROM api_logs WHERE duration_ms IS NOT NULL").fetchone()[0]
        by_m = {r[0]: r[1] for r in c.execute("SELECT method, COUNT(*) FROM api_logs GROUP BY method")}
        by_s = {r[0]: r[1] for r in c.execute(
            "SELECT CASE WHEN status_code<300 THEN '2xx' WHEN status_code<400 THEN '3xx' "
            "WHEN status_code<500 THEN '4xx' ELSE '5xx' END, COUNT(*) "
            "FROM api_logs WHERE status_code IS NOT NULL GROUP BY 1"
        )}
        c.close()
        return {"total": total, "errors": errs, "avg_duration_ms": round(avg or 0, 2),
                "by_method": by_m, "by_status": by_s}

    def clear(self):
        c = self._c()
        c.execute("DELETE FROM api_logs")
        c.commit()
        c.close()
        with _ring_lock:
            _log_ring.clear()

    @staticmethod
    def _to_dict(row) -> dict:
        d = dict(row)
        for k in ("req_headers", "resp_headers"):
            if k in d and isinstance(d[k], str):
                try:
                    d[k] = json.loads(d[k])
                except Exception:
                    pass
        return d


# ── Middleware ──────────────────────────────────────────────────────────────
class DetailedLoggingMiddleware(BaseHTTPMiddleware):
    """Captures full request/response payloads for every API call."""

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self._enabled = enabled
        self._store: Optional[DetailedLogStore] = None

    def _get_store(self) -> Optional[DetailedLogStore]:
        if self._store is None:
            try:
                self._store = DetailedLogStore.get_instance()
            except Exception as e:
                logger.warning("DetailedLogStore init failed: %s", e)
                self._enabled = False
        return self._store

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self._enabled:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(s) for s in _SKIP):
            return await call_next(request)

        # Also skip the logs endpoint itself to avoid infinite recursion
        if "/api/v1/logs" in path:
            return await call_next(request)

        store = self._get_store()
        if store is None:
            return await call_next(request)

        log_id = str(uuid.uuid4())
        method = request.method
        client_ip = request.client.host if request.client else ""
        user_agent = request.headers.get("user-agent", "")
        corr_id = request.headers.get("x-correlation-id", "")
        qp = str(dict(request.query_params)) if request.query_params else ""

        # Capture request headers (sanitized)
        req_headers = _san_hdrs(dict(request.headers))

        # Capture request body
        req_body_raw = ""
        req_size = 0
        try:
            body_bytes = await request.body()
            req_size = len(body_bytes)
            if req_size > 0 and req_size <= MAX_BODY:
                req_body_raw = _san_body(body_bytes.decode("utf-8", errors="replace"))
            elif req_size > MAX_BODY:
                req_body_raw = body_bytes[:MAX_BODY].decode("utf-8", errors="replace") + "...[TRUNCATED]"
        except Exception:
            req_body_raw = "[UNREADABLE]"

        start = time.perf_counter()
        error_msg = None
        error_type = None
        status_code = 500
        resp_headers: dict = {}
        resp_body_raw = ""
        resp_size = 0

        try:
            response = await call_next(request)
            status_code = response.status_code
            resp_headers = _san_hdrs(dict(response.headers))

            # Capture response body by consuming the streaming response
            body_chunks = []
            async for chunk in response.body_iterator:
                if isinstance(chunk, bytes):
                    body_chunks.append(chunk)
                else:
                    body_chunks.append(chunk.encode("utf-8"))
            full_body = b"".join(body_chunks)
            resp_size = len(full_body)

            if resp_size <= MAX_BODY:
                resp_body_raw = _san_body(full_body.decode("utf-8", errors="replace"))
            else:
                resp_body_raw = full_body[:MAX_BODY].decode("utf-8", errors="replace") + "...[TRUNCATED]"

            # Reconstruct response with the consumed body
            from starlette.responses import Response as StarletteResponse
            new_response = StarletteResponse(
                content=full_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            level = "error" if status_code >= 500 else ("warn" if status_code >= 400 else "info")

            record = {
                "id": log_id, "ts": datetime.now(timezone.utc).isoformat(),
                "method": method, "path": path, "query_params": qp,
                "status_code": status_code, "duration_ms": duration_ms,
                "client_ip": client_ip, "user_agent": user_agent,
                "correlation_id": corr_id,
                "req_headers": req_headers, "req_body": req_body_raw,
                "resp_headers": resp_headers, "resp_body": resp_body_raw,
                "req_size": req_size, "resp_size": resp_size,
                "error": error_msg, "error_type": error_type, "level": level,
            }
            store.insert(record)
            return new_response

        except Exception as exc:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            error_msg = str(exc)
            error_type = type(exc).__name__
            record = {
                "id": log_id, "ts": datetime.now(timezone.utc).isoformat(),
                "method": method, "path": path, "query_params": qp,
                "status_code": 500, "duration_ms": duration_ms,
                "client_ip": client_ip, "user_agent": user_agent,
                "correlation_id": corr_id,
                "req_headers": req_headers, "req_body": req_body_raw,
                "resp_headers": {}, "resp_body": "",
                "req_size": req_size, "resp_size": 0,
                "error": error_msg, "error_type": error_type, "level": "error",
            }
            try:
                store.insert(record)
            except Exception:
                pass
            raise



# ── REST API Router ──────────────────────────────────────────────────────
logs_router = APIRouter(prefix="/logs", tags=["logs"])


@logs_router.get("")
async def get_logs(
    limit: int = FQ(100, ge=1, le=1000),
    offset: int = FQ(0, ge=0),
    method: Optional[str] = None,
    path_pattern: Optional[str] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    level: Optional[str] = None,
    since: Optional[str] = None,
    search: Optional[str] = None,
):
    """Query detailed API logs with filtering."""
    store = DetailedLogStore.get_instance()
    logs = store.query(
        limit=limit, offset=offset, method=method, path_pat=path_pattern,
        status_min=status_min, status_max=status_max, level=level,
        since=since, search=search,
    )
    total = store.count()
    return {"logs": logs, "total": total, "limit": limit, "offset": offset}


@logs_router.get("/stats")
async def get_log_stats():
    """Get log statistics."""
    store = DetailedLogStore.get_instance()
    return store.stats()


@logs_router.get("/recent")
async def get_recent_logs(limit: int = FQ(50, ge=1, le=500)):
    """Get recent logs from in-memory ring buffer (fastest)."""
    with _ring_lock:
        items = list(_log_ring)[:limit]
    return {"logs": items, "count": len(items)}


@logs_router.delete("")
async def clear_logs():
    """Clear all logs."""
    store = DetailedLogStore.get_instance()
    store.clear()
    return {"status": "cleared"}


@logs_router.get("/stream")
async def stream_logs(request: Request):
    """SSE stream for real-time log updates."""
    import asyncio

    async def event_generator():
        last_count = 0
        while True:
            if await request.is_disconnected():
                break
            with _ring_lock:
                current = len(_log_ring)
            if current != last_count and current > 0:
                with _ring_lock:
                    new_logs = list(_log_ring)[:max(1, current - last_count)]
                last_count = current
                data = json.dumps(new_logs, default=str)
                yield f"data: {data}\n\n"
            await asyncio.sleep(1)

    from starlette.responses import StreamingResponse as SSEResponse
    return SSEResponse(event_generator(), media_type="text/event-stream")