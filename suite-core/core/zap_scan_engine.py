"""ALDECI OWASP ZAP Scan Engine — DAST scan orchestration over the ZAP daemon.

This engine is the persistence + lifecycle layer for ZAP scans triggered via
the ``/api/v1/zap`` REST surface. It does NOT bundle the ZAP binary; instead
it talks to whatever ZAP daemon is reachable via the ``zaproxy`` Python client
when available, and otherwise records scans in a queued/degraded state so the
control plane (UI, MCP, AQUA) can plan around capacity.

Profiles
--------
- baseline  — passive scan only (HTTP traffic spidered + passive rules)
- active    — full active scan (passive + injection / fuzzing)
- api       — OpenAPI / GraphQL schema-driven scan

Persistence
-----------
SQLite at ``data/security/zap_scans.db`` with the canonical schema::

    CREATE TABLE IF NOT EXISTS zap_scans (
        scan_id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        profile TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        finding_summary_json TEXT,
        scan_metadata_json TEXT
    );

The engine emits TrustGraph events (``zap.scan.started``,
``zap.scan.completed``, ``zap.scan.failed``) so the second-brain coverage map
includes this DAST surface. Failures are swallowed — no engine call should
raise because of TrustGraph wiring.

The engine is intentionally light on dependencies so ``get_zap_scan_engine()``
returns a working singleton in any environment, including unit tests.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TrustGraph emit (non-fatal)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit TrustGraph event. Never raises."""
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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROFILES = ("baseline", "active", "api")

VALID_STATUSES = (
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
)

_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",  # nosec B104 — SSRF blocklist
    "metadata.google.internal", "169.254.169.254",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_private_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
        )
    except ValueError:
        return False


def _validate_target_url(url: str) -> str:
    """Validate target URL against SSRF + scheme restrictions."""
    if not isinstance(url, str) or not url:
        raise ValueError("target_url is required")
    if len(url) > 2048:
        raise ValueError("target_url exceeds 2048 character limit")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https schemes are allowed")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("target_url must include a hostname")
    if host in _BLOCKED_HOSTS:
        raise ValueError(f"Target host is blocked (internal address): {host}")
    if _is_private_ip(host):
        raise ValueError("Private/reserved IP addresses are blocked")
    return url


def _validate_profile(profile: str) -> str:
    if profile not in PROFILES:
        raise ValueError(
            f"Invalid profile {profile!r}. Must be one of: {list(PROFILES)}"
        )
    return profile


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ZapScanEngine:
    """OWASP ZAP scan engine — persistence + lifecycle + capability summary."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        # Resolve DB path: explicit > env > default under repo data/security
        if db_path is None:
            env_path = os.getenv("FIXOPS_ZAP_DB_PATH")
            if env_path:
                db_path = env_path
            else:
                # Default is repo-rooted data/security/zap_scans.db
                here = Path(__file__).resolve().parents[2]
                db_path = str(here / "data" / "security" / "zap_scans.db")
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

        # Detect ZAP client availability (zaproxy package)
        self._zap_available = False
        self._zap_module: Any = None
        try:
            import zapv2  # type: ignore  # pragma: no cover
            self._zap_available = True
            self._zap_module = zapv2
        except Exception:  # noqa: BLE001
            try:
                import zaproxy  # type: ignore  # pragma: no cover
                self._zap_available = True
                self._zap_module = zaproxy
            except Exception:  # noqa: BLE001
                self._zap_available = False
                self._zap_module = None

        try:
            _emit_event(
                "engine.loaded",
                {
                    "module": __name__,
                    "db_path": self.db_path,
                    "zap_client_available": self._zap_available,
                },
            )
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------
    # SQLite init
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS zap_scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    finding_summary_json TEXT,
                    scan_metadata_json TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_zap_scans_target ON zap_scans(target)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_zap_scans_status ON zap_scans(status)"
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------
    def capability_summary(self) -> Dict[str, Any]:
        """Capability snapshot for the GET / endpoint.

        Returns a dict with the 3-state envelope expected by the platform
        UI: ``status`` is one of ``ok|empty|degraded``.
        """
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM zap_scans"
            ).fetchone()
        scan_count = int(row["c"] or 0) if row else 0

        if not self._zap_available:
            envelope_status = "degraded"
        elif scan_count == 0:
            envelope_status = "empty"
        else:
            envelope_status = "ok"

        return {
            "engine": "zap_scan_engine",
            "status": envelope_status,
            "zap_client_available": self._zap_available,
            "profiles": list(PROFILES),
            "supported_scan_types": list(PROFILES),
            "scan_count": scan_count,
            "db_path": self.db_path,
        }

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def queue_scan(
        self,
        target_url: str,
        profile: str = "baseline",
        depth: Optional[int] = None,
        contexts: Optional[List[str]] = None,
        scan_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Queue a new ZAP scan. Returns the scan record."""
        target = _validate_target_url(target_url)
        prof = _validate_profile(profile)

        if depth is not None:
            if not isinstance(depth, int) or depth < 1 or depth > 10:
                raise ValueError("depth must be an integer in [1, 10]")

        if contexts is not None:
            if not isinstance(contexts, list) or not all(
                isinstance(c, str) for c in contexts
            ):
                raise ValueError("contexts must be a list of strings")

        scan_id = f"zap-{uuid.uuid4().hex[:16]}"
        started_at = _now_iso()

        meta: Dict[str, Any] = {
            "depth": depth,
            "contexts": contexts or [],
            "zap_client_available": self._zap_available,
            "queued_at": started_at,
        }
        if scan_metadata:
            meta.update(scan_metadata)

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO zap_scans (
                    scan_id, target, profile, status, started_at,
                    completed_at, finding_summary_json, scan_metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target,
                    prof,
                    "queued",
                    started_at,
                    None,
                    json.dumps({}),
                    json.dumps(meta),
                ),
            )
            conn.commit()

        try:
            _emit_event(
                "zap.scan.started",
                {
                    "scan_id": scan_id,
                    "target": target,
                    "profile": prof,
                },
            )
        except Exception:  # pragma: no cover
            pass

        return {
            "scan_id": scan_id,
            "target": target,
            "profile": prof,
            "status": "queued",
            "started_at": started_at,
            "scan_metadata": meta,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if not isinstance(scan_id, str) or not scan_id:
            raise ValueError("scan_id is required")
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM zap_scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_scans(self, limit: int = 100) -> List[Dict[str, Any]]:
        if limit < 1:
            limit = 1
        if limit > 1000:
            limit = 1000
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM zap_scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_status(
        self,
        scan_id: str,
        status: str,
        finding_summary: Optional[Dict[str, int]] = None,
        scan_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Must be one of: {list(VALID_STATUSES)}"
            )
        completed_at = (
            _now_iso() if status in ("completed", "failed", "cancelled") else None
        )
        existing = self.get_scan(scan_id)
        if existing is None:
            raise KeyError(f"Unknown scan_id: {scan_id}")

        merged_summary = dict(existing.get("finding_summary") or {})
        if finding_summary:
            for k, v in finding_summary.items():
                merged_summary[k] = int(v)

        merged_meta = dict(existing.get("scan_metadata") or {})
        if scan_metadata:
            merged_meta.update(scan_metadata)
        merged_meta["last_status_change"] = _now_iso()

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE zap_scans
                   SET status = ?,
                       completed_at = COALESCE(?, completed_at),
                       finding_summary_json = ?,
                       scan_metadata_json = ?
                 WHERE scan_id = ?
                """,
                (
                    status,
                    completed_at,
                    json.dumps(merged_summary),
                    json.dumps(merged_meta),
                    scan_id,
                ),
            )
            conn.commit()

        try:
            evt = (
                "zap.scan.completed"
                if status == "completed"
                else "zap.scan.failed"
                if status == "failed"
                else "zap.scan.updated"
            )
            _emit_event(
                evt,
                {
                    "scan_id": scan_id,
                    "status": status,
                    "finding_summary": merged_summary,
                },
            )
        except Exception:  # pragma: no cover
            pass

        return self.get_scan(scan_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        try:
            finding_summary = json.loads(row["finding_summary_json"] or "{}")
        except Exception:  # noqa: BLE001
            finding_summary = {}
        try:
            scan_metadata = json.loads(row["scan_metadata_json"] or "{}")
        except Exception:  # noqa: BLE001
            scan_metadata = {}
        return {
            "scan_id": row["scan_id"],
            "target": row["target"],
            "profile": row["profile"],
            "status": row["status"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "finding_summary": finding_summary,
            "scan_metadata": scan_metadata,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_singleton_lock = threading.Lock()
_singleton: Optional[ZapScanEngine] = None


def get_zap_scan_engine(db_path: Optional[str] = None) -> ZapScanEngine:
    """Return the process-wide ZAP scan engine singleton.

    A non-default ``db_path`` returns a fresh, non-singleton instance so tests
    can isolate state with ``tmp_path``.
    """
    global _singleton
    if db_path is not None:
        return ZapScanEngine(db_path=db_path)
    with _singleton_lock:
        if _singleton is None:
            _singleton = ZapScanEngine()
        return _singleton


# Module-load heartbeat — observable in TrustGraph second-brain.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass
