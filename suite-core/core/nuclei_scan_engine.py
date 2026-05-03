"""ALDECI Nuclei DAST Scan Engine — async-queue model with SQLite persistence.

Complementary to the Nuclei templates importer (feeds.nuclei_templates.importer)
which manages the local catalog of YAML templates. This engine is the
persistence + lifecycle layer for ProjectDiscovery Nuclei scans triggered
through the ``/api/v1/nuclei`` REST surface.

Endpoints exposed by nuclei_router (prefix /api/v1/nuclei):
  GET  /                  — capability summary (template categories, severity
                            levels, status envelope)
  GET  /templates         — local template catalog with category counts
  POST /scan              — queue a scan, returns
                            {scan_id, target_url, template_categories, queued_at}
  GET  /scan/{scan_id}    — fetch a scan record (status + severity counts +
                            category counts + findings)

Storage: SQLite at data/security/nuclei_scans.db
Schema:  nuclei_scans (scan_id PK, target_url, template_categories_json, status,
                       severity_counts_json, category_counts_json,
                       findings_json, started_at, completed_at, exit_code)

When the ``nuclei`` CLI binary is not present we record the scan with
``status="unavailable"`` rather than fabricating findings — honoring the
NO-MOCKS rule. Callers can poll the scan_id, see the unavailable status,
and decide whether to re-run after installing nuclei.

SSRF defence:
- Only http/https schemes allowed
- Localhost / loopback / link-local / private IPs blocked
- Cloud-metadata endpoints (169.254.169.254, metadata.google.internal) blocked

TrustGraph emit (non-fatal): nuclei.scan.queued / completed / failed.

Vision pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence),
V9 (Air-Gapped — DB schema + catalog work without network).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import sqlite3
import subprocess  # nosec B404 — nuclei CLI invocation only
import threading
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

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DB_DIR = _REPO_ROOT / "data" / "security"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "nuclei_scans.db"

TEMPLATE_CATEGORIES: List[str] = [
    "cves",
    "exposures",
    "misconfigurations",
    "technologies",
    "vulnerabilities",
    "takeovers",
    "default-logins",
    "fuzzing",
    "exposed-panels",
    "exposed-tokens",
]

SEVERITY_LEVELS: List[str] = ["info", "low", "medium", "high", "critical"]

VALID_STATUSES = (
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
    "unavailable",
)

_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",  # nosec B104 — SSRF blocklist
    "metadata.google.internal", "169.254.169.254",
})

_NUCLEI_BIN = os.environ.get("NUCLEI_BIN", "nuclei")


# ---------------------------------------------------------------------------
# Validation helpers
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


def _normalize_template_categories(
    categories: Optional[List[str]],
) -> List[str]:
    """Filter to known template categories. Empty/None → full set."""
    if not categories:
        return list(TEMPLATE_CATEGORIES)
    if not isinstance(categories, list):
        raise ValueError("template_categories must be a list of strings")
    seen: set = set()
    out: List[str] = []
    for raw in categories:
        if not isinstance(raw, str):
            raise ValueError("template_categories entries must be strings")
        cat = raw.strip().lower()
        if not cat:
            continue
        if cat not in TEMPLATE_CATEGORIES:
            raise ValueError(
                f"Unknown template category {cat!r}. "
                f"Allowed: {TEMPLATE_CATEGORIES}"
            )
        if cat in seen:
            continue
        seen.add(cat)
        out.append(cat)
    return out or list(TEMPLATE_CATEGORIES)


def _normalize_severity_threshold(value: Optional[str]) -> str:
    if not value:
        return "medium"
    v = value.strip().lower()
    if v not in SEVERITY_LEVELS:
        raise ValueError(
            f"invalid severity_threshold {value!r}; allowed: {SEVERITY_LEVELS}"
        )
    return v


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class NucleiScanEngine:
    """Async-queue Nuclei DAST scan engine with SQLite persistence."""

    DEFAULT_TIMEOUT = 600

    def __init__(
        self,
        db_path: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if db_path is None:
            env_path = os.environ.get("FIXOPS_NUCLEI_DB_PATH")
            db_path = env_path or str(_DEFAULT_DB_PATH)
        self._db_path = db_path
        self._timeout = timeout
        self._lock = threading.RLock()
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

        try:
            _emit_event(
                "engine.loaded",
                {
                    "module": __name__,
                    "db_path": self._db_path,
                    "nuclei_binary_available": self.is_nuclei_available(),
                },
            )
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------
    # SQLite init
    # ------------------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nuclei_scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    template_categories_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL,
                    severity_counts_json TEXT NOT NULL DEFAULT '{}',
                    category_counts_json TEXT NOT NULL DEFAULT '{}',
                    findings_json TEXT NOT NULL DEFAULT '[]',
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    exit_code INTEGER
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_nuclei_scans_status ON nuclei_scans(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_nuclei_scans_target ON nuclei_scans(target_url)"
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Catalog / availability
    # ------------------------------------------------------------------
    def is_nuclei_available(self) -> bool:
        return shutil.which(_NUCLEI_BIN) is not None

    @staticmethod
    def list_template_categories() -> List[str]:
        return list(TEMPLATE_CATEGORIES)

    def template_catalog(self) -> Dict[str, Any]:
        """Catalog summary — category counts come from the Nuclei templates
        importer when available; falls back to a zero-count list otherwise.

        Air-gap friendly: never raises if the importer module is absent.
        """
        category_counts: Dict[str, int] = {c: 0 for c in TEMPLATE_CATEGORIES}
        total = 0
        try:  # pragma: no cover - optional importer module
            from feeds.nuclei_templates.importer import get_store_stats  # type: ignore
            stats = get_store_stats() or {}
            by_cat = (
                stats.get("by_category")
                or stats.get("category_counts")
                or {}
            )
            if isinstance(by_cat, dict):
                for cat, val in by_cat.items():
                    key = str(cat).strip().lower()
                    if key in category_counts:
                        try:
                            category_counts[key] = int(val)
                        except Exception:  # noqa: BLE001
                            continue
            total = int(stats.get("total") or stats.get("count") or 0)
        except Exception:  # noqa: BLE001
            total = 0
        # If importer didn't give us a total, sum the buckets we populated.
        if total <= 0:
            total = sum(category_counts.values())
        return {
            "categories": [
                {"name": cat, "template_count": category_counts.get(cat, 0)}
                for cat in TEMPLATE_CATEGORIES
            ],
            "total_templates": total,
            "category_counts": category_counts,
        }

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------
    def capability_summary(self) -> Dict[str, Any]:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM nuclei_scans"
            ).fetchone()
        scan_count = int(row["c"] or 0) if row else 0

        if not self.is_nuclei_available():
            envelope_status = "unavailable"
        elif scan_count == 0:
            envelope_status = "empty"
        else:
            envelope_status = "ok"

        return {
            "service": "Nuclei",
            "engine": "nuclei_scan_engine",
            "status": envelope_status,
            "nuclei_binary_available": self.is_nuclei_available(),
            "template_categories": list(TEMPLATE_CATEGORIES),
            "severity_levels": list(SEVERITY_LEVELS),
            "scan_count": scan_count,
            "db_path": self._db_path,
        }

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def queue_scan(
        self,
        target_url: str,
        template_categories: Optional[List[str]] = None,
        severity_threshold: Optional[str] = None,
        follow_redirects: Optional[bool] = None,
        rate_limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        target = _validate_target_url(target_url)
        cats = _normalize_template_categories(template_categories)
        sev = _normalize_severity_threshold(severity_threshold)

        if rate_limit is not None:
            if not isinstance(rate_limit, int) or rate_limit < 1 or rate_limit > 10000:
                raise ValueError("rate_limit must be an integer in [1, 10000]")
        if follow_redirects is not None and not isinstance(follow_redirects, bool):
            raise ValueError("follow_redirects must be a boolean")

        scan_id = f"nuclei-{uuid.uuid4().hex[:16]}"
        started_at = _now_iso()

        # If the binary is absent, record as unavailable up-front.
        status = "queued" if self.is_nuclei_available() else "unavailable"
        completed_at: Optional[str] = None if status == "queued" else started_at

        category_counts: Dict[str, int] = {c: 0 for c in cats}
        severity_counts: Dict[str, int] = {s: 0 for s in SEVERITY_LEVELS}

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO nuclei_scans (
                    scan_id, target_url, template_categories_json, status,
                    severity_counts_json, category_counts_json,
                    findings_json, started_at, completed_at, exit_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target,
                    json.dumps(cats),
                    status,
                    json.dumps(severity_counts),
                    json.dumps(category_counts),
                    json.dumps([]),
                    started_at,
                    completed_at,
                    None,
                ),
            )
            conn.commit()

        try:
            _emit_event(
                "nuclei.scan.queued",
                {
                    "scan_id": scan_id,
                    "target_url": target,
                    "template_categories": cats,
                    "status": status,
                    "severity_threshold": sev,
                },
            )
        except Exception:  # pragma: no cover
            pass

        return {
            "scan_id": scan_id,
            "target_url": target,
            "template_categories": cats,
            "severity_threshold": sev,
            "follow_redirects": bool(follow_redirects) if follow_redirects is not None else False,
            "rate_limit": rate_limit,
            "status": status,
            "queued_at": started_at,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if not isinstance(scan_id, str) or not scan_id:
            raise ValueError("scan_id is required")
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM nuclei_scans WHERE scan_id = ?",
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
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM nuclei_scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_status(
        self,
        scan_id: str,
        status: str,
        severity_counts: Optional[Dict[str, int]] = None,
        category_counts: Optional[Dict[str, int]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        exit_code: Optional[int] = None,
    ) -> Dict[str, Any]:
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Must be one of: {list(VALID_STATUSES)}"
            )
        existing = self.get_scan(scan_id)
        if existing is None:
            raise KeyError(f"Unknown scan_id: {scan_id}")

        completed_at = (
            _now_iso()
            if status in ("completed", "failed", "cancelled", "unavailable")
            else None
        )

        merged_sev = dict(existing.get("severity_counts") or {})
        if severity_counts:
            for k, v in severity_counts.items():
                kk = str(k).strip().lower()
                if kk in SEVERITY_LEVELS:
                    merged_sev[kk] = int(v)

        merged_cat = dict(existing.get("category_counts") or {})
        if category_counts:
            for k, v in category_counts.items():
                kk = str(k).strip().lower()
                if kk in TEMPLATE_CATEGORIES:
                    merged_cat[kk] = int(v)

        merged_findings = list(existing.get("findings") or [])
        if findings is not None:
            merged_findings = list(findings)

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE nuclei_scans
                   SET status = ?,
                       completed_at = COALESCE(?, completed_at),
                       severity_counts_json = ?,
                       category_counts_json = ?,
                       findings_json = ?,
                       exit_code = COALESCE(?, exit_code)
                 WHERE scan_id = ?
                """,
                (
                    status,
                    completed_at,
                    json.dumps(merged_sev),
                    json.dumps(merged_cat),
                    json.dumps(merged_findings),
                    exit_code,
                    scan_id,
                ),
            )
            conn.commit()

        try:
            evt = (
                "nuclei.scan.completed"
                if status == "completed"
                else "nuclei.scan.failed"
                if status == "failed"
                else "nuclei.scan.updated"
            )
            _emit_event(
                evt,
                {
                    "scan_id": scan_id,
                    "status": status,
                    "severity_counts": merged_sev,
                    "category_counts": merged_cat,
                    "exit_code": exit_code,
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
        def _ld(text: Any, fallback: Any) -> Any:
            try:
                if text is None:
                    return fallback
                return json.loads(text)
            except Exception:  # noqa: BLE001
                return fallback

        return {
            "scan_id": row["scan_id"],
            "target_url": row["target_url"],
            "template_categories": _ld(row["template_categories_json"], []),
            "status": row["status"],
            "severity_counts": _ld(row["severity_counts_json"], {}),
            "category_counts": _ld(row["category_counts_json"], {}),
            "findings": _ld(row["findings_json"], []),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "exit_code": row["exit_code"],
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_singleton_lock = threading.Lock()
_singleton: Optional[NucleiScanEngine] = None


def get_nuclei_scan_engine(
    db_path: Optional[str] = None,
    timeout: int = NucleiScanEngine.DEFAULT_TIMEOUT,
) -> NucleiScanEngine:
    """Return the process-wide Nuclei scan engine singleton.

    A non-default ``db_path`` returns a fresh, non-singleton instance so tests
    can isolate state with ``tmp_path``.
    """
    global _singleton
    if db_path is not None:
        return NucleiScanEngine(db_path=db_path, timeout=timeout)
    with _singleton_lock:
        if _singleton is None:
            _singleton = NucleiScanEngine(timeout=timeout)
        return _singleton


# Module-load heartbeat — observable in TrustGraph second-brain.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass
