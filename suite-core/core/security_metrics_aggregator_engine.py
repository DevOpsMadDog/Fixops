"""Security Metrics Aggregator Engine — ALDECI.

Aggregates and normalizes security metrics from multiple sources.

Capabilities:
  - Source registry (SIEM/EDR/SCA/DAST/DLP/firewall/IAM/vuln_scanner/cloud_security/custom)
  - Metric recording with type, category, unit, and tags
  - Aggregation computation (sum/avg/min/max/count/weighted_avg)
  - Latest metric lookup per metric_name
  - Multi-tenant org_id isolation
  - SQLite WAL + threading.RLock

Compliance: NIST SP 800-55, ISO/IEC 27004
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SOURCE_TYPES = {
    "siem", "edr", "sca", "dast", "dlp", "firewall",
    "iam", "vulnerability_scanner", "cloud_security", "custom",
}
_VALID_METRIC_TYPES = {"counter", "gauge", "histogram", "percentage", "score"}
_VALID_CATEGORIES = {"security", "compliance", "operational", "risk", "performance"}
_VALID_AGGREGATION_TYPES = {"sum", "avg", "min", "max", "count", "weighted_avg"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityMetricsAggregatorEngine:
    """SQLite WAL-backed Security Metrics Aggregator engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB at .fixops_data/security_metrics_aggregator.db (shared, org_id column).
    """

    def __init__(self, db_dir: Optional[str] = None) -> None:
        self._db_dir = Path(db_dir) if db_dir else _DEFAULT_DB_DIR
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialized = False

    def _db_path(self) -> str:
        return str(self._db_dir / "security_metrics_aggregator.db")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sma_sources (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    source_name     TEXT NOT NULL,
                    source_type     TEXT NOT NULL DEFAULT 'custom',
                    endpoint_url    TEXT NOT NULL DEFAULT '',
                    active          INTEGER NOT NULL DEFAULT 1,
                    last_sync       DATETIME,
                    metric_count    INTEGER NOT NULL DEFAULT 0,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sma_sources_org
                    ON sma_sources (org_id, source_type, active);

                CREATE TABLE IF NOT EXISTS sma_metrics (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    source_id       TEXT NOT NULL,
                    metric_name     TEXT NOT NULL,
                    metric_type     TEXT NOT NULL DEFAULT 'gauge',
                    value           REAL NOT NULL,
                    unit            TEXT NOT NULL DEFAULT '',
                    category        TEXT NOT NULL DEFAULT 'security',
                    tags            TEXT NOT NULL DEFAULT '{}',
                    collected_at    DATETIME NOT NULL,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sma_metrics_org_name
                    ON sma_metrics (org_id, metric_name, collected_at);

                CREATE INDEX IF NOT EXISTS idx_sma_metrics_org_source
                    ON sma_metrics (org_id, source_id);

                CREATE INDEX IF NOT EXISTS idx_sma_metrics_org_category
                    ON sma_metrics (org_id, category, metric_type);

                CREATE TABLE IF NOT EXISTS sma_aggregations (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    aggregation_name    TEXT NOT NULL,
                    metric_names        TEXT NOT NULL DEFAULT '[]',
                    aggregation_type    TEXT NOT NULL DEFAULT 'avg',
                    time_window_hours   INTEGER NOT NULL DEFAULT 24,
                    result_value        REAL NOT NULL DEFAULT 0.0,
                    confidence          REAL NOT NULL DEFAULT 100.0,
                    computed_at         DATETIME NOT NULL,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sma_aggregations_org
                    ON sma_aggregations (org_id, aggregation_type);
            """)

    def _ensure_db(self) -> None:
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    self._init_db()
                    self._initialized = True

    @staticmethod
    def _row_metric(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "tags" in d and isinstance(d["tags"], str):
            try:
                d["tags"] = json.loads(d["tags"])
            except (json.JSONDecodeError, TypeError):
                d["tags"] = {}
        if "active" in d:
            d["active"] = bool(d["active"])
        return d

    @staticmethod
    def _row_aggregation(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "metric_names" in d and isinstance(d["metric_names"], str):
            try:
                d["metric_names"] = json.loads(d["metric_names"])
            except (json.JSONDecodeError, TypeError):
                d["metric_names"] = []
        return d

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def register_source(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new metrics source."""
        self._ensure_db()
        source_name = data.get("source_name", "").strip()
        if not source_name:
            raise ValueError("source_name is required")

        source_type = data.get("source_type", "custom")
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {sorted(_VALID_SOURCE_TYPES)}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_name": source_name,
            "source_type": source_type,
            "endpoint_url": data.get("endpoint_url", ""),
            "active": 1 if data.get("active", True) else 0,
            "last_sync": data.get("last_sync"),
            "metric_count": int(data.get("metric_count", 0)),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sma_sources
                       (id, org_id, source_name, source_type, endpoint_url, active,
                        last_sync, metric_count, created_at)
                       VALUES (:id,:org_id,:source_name,:source_type,:endpoint_url,:active,
                               :last_sync,:metric_count,:created_at)""",
                    record,
                )
        record["active"] = bool(record["active"])
        return record

    def list_sources(
        self,
        org_id: str,
        source_type: Optional[str] = None,
        active: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List sources for an org, optionally filtered."""
        self._ensure_db()
        query = "SELECT * FROM sma_sources WHERE org_id = ?"
        params: list = [org_id]
        if source_type:
            query += " AND source_type = ?"
            params.append(source_type)
        if active is not None:
            query += " AND active = ?"
            params.append(1 if active else 0)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_metric(r) for r in rows]

    def sync_source(
        self,
        org_id: str,
        source_id: str,
        metric_count_delta: int,
    ) -> Dict[str, Any]:
        """Increment metric_count by delta and update last_sync."""
        self._ensure_db()
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    "SELECT id FROM sma_sources WHERE id = ? AND org_id = ?",
                    (source_id, org_id),
                ).fetchone()
                if not result:
                    raise KeyError(f"Source {source_id!r} not found for org {org_id!r}")
                conn.execute(
                    """UPDATE sma_sources
                       SET metric_count = metric_count + ?, last_sync = ?
                       WHERE id = ? AND org_id = ?""",
                    (metric_count_delta, now, source_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM sma_sources WHERE id = ?", (source_id,)
                ).fetchone()
        return self._row_metric(row)

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def record_metric(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new metric observation."""
        self._ensure_db()
        source_id = data.get("source_id", "").strip()
        if not source_id:
            raise ValueError("source_id is required")

        metric_name = data.get("metric_name", "").strip()
        if not metric_name:
            raise ValueError("metric_name is required")

        metric_type = data.get("metric_type", "gauge")
        if metric_type not in _VALID_METRIC_TYPES:
            raise ValueError(f"metric_type must be one of {sorted(_VALID_METRIC_TYPES)}")

        category = data.get("category", "security")
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(_VALID_CATEGORIES)}")

        tags = data.get("tags", {})
        if not isinstance(tags, dict):
            tags = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_id": source_id,
            "metric_name": metric_name,
            "metric_type": metric_type,
            "value": float(data.get("value", 0.0)),
            "unit": data.get("unit", ""),
            "category": category,
            "tags": json.dumps(tags),
            "collected_at": data.get("collected_at", now),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sma_metrics
                       (id, org_id, source_id, metric_name, metric_type, value, unit,
                        category, tags, collected_at, created_at)
                       VALUES (:id,:org_id,:source_id,:metric_name,:metric_type,:value,:unit,
                               :category,:tags,:collected_at,:created_at)""",
                    record,
                )
        record["tags"] = tags
        return record

    def list_metrics(
        self,
        org_id: str,
        source_id: Optional[str] = None,
        category: Optional[str] = None,
        metric_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List metrics for an org, optionally filtered."""
        self._ensure_db()
        query = "SELECT * FROM sma_metrics WHERE org_id = ?"
        params: list = [org_id]
        if source_id:
            query += " AND source_id = ?"
            params.append(source_id)
        if category:
            query += " AND category = ?"
            params.append(category)
        if metric_type:
            query += " AND metric_type = ?"
            params.append(metric_type)
        query += " ORDER BY collected_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_metric(r) for r in rows]

    def get_latest_metric(self, org_id: str, metric_name: str) -> Optional[Dict[str, Any]]:
        """Return most recent metric by collected_at for org, or None."""
        self._ensure_db()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """SELECT * FROM sma_metrics
                       WHERE org_id = ? AND metric_name = ?
                       ORDER BY collected_at DESC LIMIT 1""",
                    (org_id, metric_name),
                ).fetchone()
        if not row:
            return None
        return self._row_metric(row)

    # ------------------------------------------------------------------
    # Aggregations
    # ------------------------------------------------------------------

    def create_aggregation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an aggregation computation record."""
        self._ensure_db()
        aggregation_name = data.get("aggregation_name", "").strip()
        if not aggregation_name:
            raise ValueError("aggregation_name is required")

        aggregation_type = data.get("aggregation_type", "avg")
        if aggregation_type not in _VALID_AGGREGATION_TYPES:
            raise ValueError(f"aggregation_type must be one of {sorted(_VALID_AGGREGATION_TYPES)}")

        metric_names = data.get("metric_names", [])
        if not isinstance(metric_names, list):
            metric_names = list(metric_names)

        # Clamp confidence 0-100
        confidence = min(100.0, max(0.0, float(data.get("confidence", 100.0))))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "aggregation_name": aggregation_name,
            "metric_names": json.dumps(metric_names),
            "aggregation_type": aggregation_type,
            "time_window_hours": int(data.get("time_window_hours", 24)),
            "result_value": float(data.get("result_value", 0.0)),
            "confidence": confidence,
            "computed_at": data.get("computed_at", now),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sma_aggregations
                       (id, org_id, aggregation_name, metric_names, aggregation_type,
                        time_window_hours, result_value, confidence, computed_at, created_at)
                       VALUES (:id,:org_id,:aggregation_name,:metric_names,:aggregation_type,
                               :time_window_hours,:result_value,:confidence,:computed_at,:created_at)""",
                    record,
                )
        record["metric_names"] = metric_names
        return record

    def list_aggregations(
        self,
        org_id: str,
        aggregation_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List aggregations for an org, optionally filtered."""
        self._ensure_db()
        query = "SELECT * FROM sma_aggregations WHERE org_id = ?"
        params: list = [org_id]
        if aggregation_type:
            query += " AND aggregation_type = ?"
            params.append(aggregation_type)
        query += " ORDER BY computed_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_aggregation(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_aggregator_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated stats for an org."""
        self._ensure_db()
        with self._lock:
            with self._conn() as conn:
                total_sources = conn.execute(
                    "SELECT COUNT(*) FROM sma_sources WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                active_sources = conn.execute(
                    "SELECT COUNT(*) FROM sma_sources WHERE org_id = ? AND active = 1",
                    (org_id,),
                ).fetchone()[0]
                total_metrics = conn.execute(
                    "SELECT COUNT(*) FROM sma_metrics WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                total_aggregations = conn.execute(
                    "SELECT COUNT(*) FROM sma_aggregations WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                # By source_type
                by_source_type: Dict[str, int] = {}
                for row in conn.execute(
                    "SELECT source_type, COUNT(*) AS cnt FROM sma_sources WHERE org_id = ? GROUP BY source_type",
                    (org_id,),
                ).fetchall():
                    by_source_type[row["source_type"]] = row["cnt"]

                # By category
                by_category: Dict[str, int] = {}
                for row in conn.execute(
                    "SELECT category, COUNT(*) AS cnt FROM sma_metrics WHERE org_id = ? GROUP BY category",
                    (org_id,),
                ).fetchall():
                    by_category[row["category"]] = row["cnt"]

                # By metric_type
                by_metric_type: Dict[str, int] = {}
                for row in conn.execute(
                    "SELECT metric_type, COUNT(*) AS cnt FROM sma_metrics WHERE org_id = ? GROUP BY metric_type",
                    (org_id,),
                ).fetchall():
                    by_metric_type[row["metric_type"]] = row["cnt"]

        return {
            "total_sources": total_sources,
            "active_sources": active_sources,
            "total_metrics": total_metrics,
            "total_aggregations": total_aggregations,
            "by_source_type": by_source_type,
            "by_category": by_category,
            "by_metric_type": by_metric_type,
        }
