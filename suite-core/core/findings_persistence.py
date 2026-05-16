"""Findings Persistence Layer — ALDECI.

Production-grade SQLite persistence for security findings with:
  - Per-tenant database isolation (data/findings_{tenant_id}.db)
  - SARIF-compatible schema with indexed columns
  - SHA-256 fingerprint deduplication (rule_id + file_path + line + tenant_id)
  - Async via aiosqlite with thread-executor fallback for sync callers
  - Risk score computation via VulnRiskScorer on insert

Compliance: NIST SP 800-53 SI-7, ISO 27001 A.12.6, SOC2 CC7.1
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite

_logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parents[2] / "data"

# ---------------------------------------------------------------------------
# Severity ordering for sorting / counting
# ---------------------------------------------------------------------------
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

# ---------------------------------------------------------------------------
# Schema — one DB per tenant, WAL mode
# ---------------------------------------------------------------------------
_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    asset_id        TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT '',

    -- SARIF-compatible identification
    rule_id         TEXT NOT NULL DEFAULT '',
    rule_name       TEXT NOT NULL DEFAULT '',
    fingerprint     TEXT NOT NULL UNIQUE,

    -- Location
    file_path       TEXT NOT NULL DEFAULT '',
    start_line      INTEGER NOT NULL DEFAULT 0,
    end_line        INTEGER NOT NULL DEFAULT 0,
    column_number   INTEGER NOT NULL DEFAULT 0,
    snippet         TEXT NOT NULL DEFAULT '',

    -- Classification
    severity        TEXT NOT NULL DEFAULT 'medium',
    level           TEXT NOT NULL DEFAULT 'warning',
    confidence      TEXT NOT NULL DEFAULT 'medium',
    tags            TEXT NOT NULL DEFAULT '[]',      -- JSON array

    -- Description
    title           TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    help_uri        TEXT NOT NULL DEFAULT '',

    -- CVE / package info
    cve_id          TEXT NOT NULL DEFAULT '',
    cwe_ids         TEXT NOT NULL DEFAULT '[]',      -- JSON array
    package_name    TEXT NOT NULL DEFAULT '',
    package_version TEXT NOT NULL DEFAULT '',

    -- Risk scoring (computed at insert by VulnRiskScorer)
    risk_score      REAL NOT NULL DEFAULT 0.0,
    priority        TEXT NOT NULL DEFAULT 'P4',
    cvss_score      REAL NOT NULL DEFAULT 0.0,
    epss_score      REAL NOT NULL DEFAULT 0.0,

    -- Status lifecycle
    status          TEXT NOT NULL DEFAULT 'open',
    assigned_to     TEXT NOT NULL DEFAULT '',

    -- Timestamps
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    resolved_at     TEXT,

    -- Raw payload for forward compatibility
    raw_sarif       TEXT NOT NULL DEFAULT '{}'
);

-- Indexes for the common query patterns
CREATE INDEX IF NOT EXISTS idx_findings_tenant_severity
    ON findings(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_source
    ON findings(tenant_id, source);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_file
    ON findings(tenant_id, file_path);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_created
    ON findings(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint
    ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status
    ON findings(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_asset
    ON findings(tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve
    ON findings(tenant_id, cve_id);
"""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Finding:
    """Represents a single security finding (SARIF-compatible)."""

    __slots__ = (
        "id", "tenant_id", "asset_id", "source",
        "rule_id", "rule_name", "fingerprint",
        "file_path", "start_line", "end_line", "column_number", "snippet",
        "severity", "level", "confidence", "tags",
        "title", "description", "help_uri",
        "cve_id", "cwe_ids", "package_name", "package_version",
        "risk_score", "priority", "cvss_score", "epss_score",
        "status", "assigned_to",
        "created_at", "updated_at", "last_seen", "resolved_at",
        "raw_sarif",
    )

    def __init__(self, **kwargs: Any) -> None:
        now = _now_iso()
        self.id = kwargs.get("id") or str(uuid.uuid4())
        self.tenant_id = kwargs.get("tenant_id", "")
        self.asset_id = kwargs.get("asset_id", "")
        self.source = kwargs.get("source", "")
        self.rule_id = kwargs.get("rule_id", "")
        self.rule_name = kwargs.get("rule_name", "")
        self.fingerprint = kwargs.get("fingerprint", "")
        self.file_path = kwargs.get("file_path", "")
        self.start_line = int(kwargs.get("start_line", 0))
        self.end_line = int(kwargs.get("end_line", 0))
        self.column_number = int(kwargs.get("column_number", 0))
        self.snippet = kwargs.get("snippet", "")
        self.severity = kwargs.get("severity", "medium").lower()
        self.level = kwargs.get("level", "warning")
        self.confidence = kwargs.get("confidence", "medium")
        self.tags = kwargs.get("tags", [])
        self.title = kwargs.get("title", "")
        self.description = kwargs.get("description", "")
        self.help_uri = kwargs.get("help_uri", "")
        self.cve_id = kwargs.get("cve_id", "")
        self.cwe_ids = kwargs.get("cwe_ids", [])
        self.package_name = kwargs.get("package_name", "")
        self.package_version = kwargs.get("package_version", "")
        self.risk_score = float(kwargs.get("risk_score", 0.0))
        self.priority = kwargs.get("priority", "P4")
        self.cvss_score = float(kwargs.get("cvss_score", 0.0))
        self.epss_score = float(kwargs.get("epss_score", 0.0))
        self.status = kwargs.get("status", "open")
        self.assigned_to = kwargs.get("assigned_to", "")
        self.created_at = kwargs.get("created_at", now)
        self.updated_at = kwargs.get("updated_at", now)
        self.last_seen = kwargs.get("last_seen", now)
        self.resolved_at = kwargs.get("resolved_at")
        self.raw_sarif = kwargs.get("raw_sarif", {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "source": self.source,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "fingerprint": self.fingerprint,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "column_number": self.column_number,
            "snippet": self.snippet,
            "severity": self.severity,
            "level": self.level,
            "confidence": self.confidence,
            "tags": self.tags,
            "title": self.title,
            "description": self.description,
            "help_uri": self.help_uri,
            "cve_id": self.cve_id,
            "cwe_ids": self.cwe_ids,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "risk_score": self.risk_score,
            "priority": self.priority,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_seen": self.last_seen,
            "resolved_at": self.resolved_at,
            "raw_sarif": self.raw_sarif,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_fingerprint(rule_id: str, file_path: str, line: int, tenant_id: str) -> str:
    """SHA-256 fingerprint for deduplication.

    Inputs: rule_id + file_path + str(line) + tenant_id — all lower-cased and
    stripped so that minor normalisation differences don't produce false duplicates.
    """
    raw = "|".join([
        str(rule_id).strip().lower(),
        str(file_path).strip().lower(),
        str(line),
        str(tenant_id).strip().lower(),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


def _db_path(tenant_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)
    return _DATA_DIR / f"findings_{safe}.db"


def _row_to_finding(row: sqlite3.Row) -> Finding:
    d = dict(row)
    for json_col in ("tags", "cwe_ids", "raw_sarif"):
        raw = d.get(json_col, "")
        if isinstance(raw, str):
            try:
                d[json_col] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                d[json_col] = [] if json_col != "raw_sarif" else {}
    return Finding(**d)


# ---------------------------------------------------------------------------
# Risk scoring integration — lazy-loaded to avoid circular imports
# ---------------------------------------------------------------------------

def _score_finding(finding: Finding) -> Finding:
    """Call VulnRiskScorer._compute with available context. Mutates in-place."""
    try:
        from core.vuln_risk_scoring import VulnRiskScorer  # noqa: PLC0415
        context = {
            "cvss_base": finding.cvss_score,
            "epss_score": finding.epss_score,
            "kev": False,
            "internet_exposed": False,
            "has_known_exploit": bool(finding.cve_id),
            "asset_criticality": finding.severity if finding.severity in (
                "critical", "high", "medium", "low"
            ) else "medium",
        }
        result = VulnRiskScorer._compute(context)
        finding.risk_score = result["composite_score"]
        finding.priority = result["priority"]
    except Exception as exc:  # noqa: BLE001
        _logger.debug("risk_scoring unavailable, using default: %s", exc)
        # Fallback: map severity → simple score
        _sev_score = {"critical": 90.0, "high": 70.0, "medium": 45.0, "low": 20.0, "informational": 5.0}
        finding.risk_score = _sev_score.get(finding.severity, 20.0)
        _pri = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "informational": "P4"}
        finding.priority = _pri.get(finding.severity, "P4")
    return finding


# ---------------------------------------------------------------------------
# FindingsStore — async-first, sync-compatible
# ---------------------------------------------------------------------------

class FindingsStore:
    """Per-tenant SQLite findings store with dedup, indexes, and risk scoring.

    Usage (async):
        store = FindingsStore()
        result = await store.persist_findings(tenant_id, asset_id, source, findings)
        rows   = await store.list_findings(tenant_id, filters={"severity": "high"})
        counts = await store.count_findings(tenant_id, {})
        row    = await store.get_finding(tenant_id, finding_id)

    Usage (sync via run_sync):
        result = store.run_sync(store.persist_findings, tenant_id, asset_id, source, findings)
    """

    _db_init_lock = threading.Lock()
    _initialized_dbs: set[str] = set()
    _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="findings-store")

    def __init__(self) -> None:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # DB lifecycle
    # ------------------------------------------------------------------

    async def _get_db(self, tenant_id: str) -> str:
        """Return the DB path string, initialising schema if first use."""
        path = str(_db_path(tenant_id))
        if path not in self._initialized_dbs:
            await self._init_schema(path)
            with self._db_init_lock:
                self._initialized_dbs.add(path)
        return path

    async def _init_schema(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(path) as db:
            await db.executescript(_SCHEMA)
            await db.commit()

    # ------------------------------------------------------------------
    # Core public methods
    # ------------------------------------------------------------------

    async def persist_findings(
        self,
        tenant_id: str,
        asset_id: str,
        source: str,
        findings: List[Finding],
    ) -> Dict[str, int]:
        """Insert findings into tenant DB; dedup by fingerprint.

        For existing fingerprints: update last_seen + updated_at only.

        Returns:
            {"inserted": int, "deduped": int}
        """
        if not findings:
            return {"inserted": 0, "deduped": 0}

        db_path = await self._get_db(tenant_id)
        now = _now_iso()
        inserted = 0
        deduped = 0

        # Compute fingerprints and risk scores for new findings
        prepared: List[Finding] = []
        for f in findings:
            f.tenant_id = tenant_id
            f.asset_id = asset_id or f.asset_id
            f.source = source or f.source
            if not f.fingerprint:
                f.fingerprint = compute_fingerprint(
                    f.rule_id, f.file_path, f.start_line, tenant_id
                )
            f = _score_finding(f)
            prepared.append(f)

        async with aiosqlite.connect(db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            for f in prepared:
                # Check if fingerprint exists
                cursor = await db.execute(
                    "SELECT id FROM findings WHERE fingerprint = ?",
                    (f.fingerprint,),
                )
                existing = await cursor.fetchone()
                if existing:
                    # Dedup: update last_seen and updated_at only
                    await db.execute(
                        "UPDATE findings SET last_seen=?, updated_at=? WHERE fingerprint=?",
                        (now, now, f.fingerprint),
                    )
                    deduped += 1
                else:
                    tags_json = json.dumps(f.tags if isinstance(f.tags, list) else [])
                    cwe_json = json.dumps(f.cwe_ids if isinstance(f.cwe_ids, list) else [])
                    raw_json = json.dumps(f.raw_sarif if isinstance(f.raw_sarif, dict) else {})

                    await db.execute(
                        """INSERT INTO findings (
                            id, tenant_id, asset_id, source,
                            rule_id, rule_name, fingerprint,
                            file_path, start_line, end_line, column_number, snippet,
                            severity, level, confidence, tags,
                            title, description, help_uri,
                            cve_id, cwe_ids, package_name, package_version,
                            risk_score, priority, cvss_score, epss_score,
                            status, assigned_to,
                            created_at, updated_at, last_seen, resolved_at, raw_sarif
                        ) VALUES (
                            ?,?,?,?,
                            ?,?,?,
                            ?,?,?,?,?,
                            ?,?,?,?,
                            ?,?,?,
                            ?,?,?,?,
                            ?,?,?,?,
                            ?,?,
                            ?,?,?,?,?
                        )""",
                        (
                            f.id, tenant_id, f.asset_id, f.source,
                            f.rule_id, f.rule_name, f.fingerprint,
                            f.file_path, f.start_line, f.end_line,
                            f.column_number, f.snippet,
                            f.severity, f.level, f.confidence, tags_json,
                            f.title, f.description, f.help_uri,
                            f.cve_id, cwe_json, f.package_name, f.package_version,
                            f.risk_score, f.priority, f.cvss_score, f.epss_score,
                            f.status, f.assigned_to,
                            f.created_at or now, f.updated_at or now,
                            f.last_seen or now, f.resolved_at, raw_json,
                        ),
                    )
                    inserted += 1

            await db.commit()

        _logger.info(
            "persist_findings tenant=%s asset=%s source=%s inserted=%d deduped=%d",
            tenant_id, asset_id, source, inserted, deduped,
        )
        return {"inserted": inserted, "deduped": deduped}

    async def list_findings(
        self,
        tenant_id: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[Finding]:
        """Query findings with optional filters and pagination.

        Supported filter keys:
            severity        str   exact match
            source          str   exact match
            file_path       str   LIKE %value%
            asset_id        str   exact match
            status          str   exact match
            cve_id          str   exact match
            rule_id         str   exact match
            date_from       str   ISO-8601 — created_at >=
            date_to         str   ISO-8601 — created_at <=
        """
        db_path = await self._get_db(tenant_id)
        filters = filters or {}
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)

        clauses = ["tenant_id = ?"]
        params: List[Any] = [tenant_id]

        if filters.get("severity"):
            clauses.append("severity = ?")
            params.append(filters["severity"])
        if filters.get("source"):
            clauses.append("source = ?")
            params.append(filters["source"])
        if filters.get("file_path"):
            clauses.append("file_path LIKE ?")
            params.append(f"%{filters['file_path']}%")
        if filters.get("asset_id"):
            clauses.append("asset_id = ?")
            params.append(filters["asset_id"])
        if filters.get("status"):
            clauses.append("status = ?")
            params.append(filters["status"])
        if filters.get("cve_id"):
            clauses.append("cve_id = ?")
            params.append(filters["cve_id"])
        if filters.get("rule_id"):
            clauses.append("rule_id = ?")
            params.append(filters["rule_id"])
        if filters.get("date_from"):
            clauses.append("created_at >= ?")
            params.append(filters["date_from"])
        if filters.get("date_to"):
            clauses.append("created_at <= ?")
            params.append(filters["date_to"])

        where = " AND ".join(clauses)
        sql = (
            f"SELECT * FROM findings WHERE {where} "
            f"ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])

        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode=WAL")
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()

        return [_row_to_finding(r) for r in rows]

    async def count_findings(
        self,
        tenant_id: str,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, int]:
        """Return severity-keyed counts matching the given filters.

        Returns:
            {"critical": int, "high": int, "medium": int, "low": int,
             "informational": int, "total": int}
        """
        db_path = await self._get_db(tenant_id)
        filters = filters or {}

        clauses = ["tenant_id = ?"]
        params: List[Any] = [tenant_id]

        if filters.get("source"):
            clauses.append("source = ?")
            params.append(filters["source"])
        if filters.get("asset_id"):
            clauses.append("asset_id = ?")
            params.append(filters["asset_id"])
        if filters.get("status"):
            clauses.append("status = ?")
            params.append(filters["status"])
        if filters.get("date_from"):
            clauses.append("created_at >= ?")
            params.append(filters["date_from"])
        if filters.get("date_to"):
            clauses.append("created_at <= ?")
            params.append(filters["date_to"])

        where = " AND ".join(clauses)
        sql = (
            f"SELECT severity, COUNT(*) as cnt FROM findings "
            f"WHERE {where} GROUP BY severity"
        )

        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode=WAL")
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()

        counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0,
            "low": 0, "informational": 0,
        }
        for row in rows:
            sev = (row["severity"] or "medium").lower()
            if sev in counts:
                counts[sev] += int(row["cnt"])
            else:
                counts.setdefault(sev, 0)
                counts[sev] += int(row["cnt"])

        counts["total"] = sum(counts.values())
        return counts

    async def get_finding(
        self,
        tenant_id: str,
        finding_id: str,
    ) -> Optional[Finding]:
        """Retrieve a single finding by id, scoped to tenant.

        Returns None if not found or tenant mismatch (no enumeration leak).
        """
        db_path = await self._get_db(tenant_id)
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode=WAL")
            cursor = await db.execute(
                "SELECT * FROM findings WHERE id = ? AND tenant_id = ?",
                (finding_id, tenant_id),
            )
            row = await cursor.fetchone()

        if row is None:
            return None
        return _row_to_finding(row)

    # ------------------------------------------------------------------
    # Sync bridge — for callers that cannot use async
    # ------------------------------------------------------------------

    def run_sync(self, coro_fn, *args, **kwargs):
        """Run an async method synchronously via a thread-local event loop."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're inside an existing event loop; use run_in_executor
                import concurrent.futures
                future = concurrent.futures.Future()

                async def _runner():
                    try:
                        result = await coro_fn(*args, **kwargs)
                        future.set_result(result)
                    except Exception as e:
                        future.set_exception(e)

                asyncio.ensure_future(_runner())
                return future.result(timeout=30)
            else:
                return loop.run_until_complete(coro_fn(*args, **kwargs))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro_fn(*args, **kwargs))
            finally:
                loop.close()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_store: Optional[FindingsStore] = None
_store_lock = threading.Lock()


def get_findings_store() -> FindingsStore:
    """Return the module-level FindingsStore singleton."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = FindingsStore()
    return _store
