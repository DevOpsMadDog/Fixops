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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SOURCE_TYPES = {
    "siem", "edr", "sca", "dast", "dlp", "firewall",
    "iam", "vulnerability_scanner", "cloud_security", "custom",
}
_VALID_METRIC_TYPES = {"counter", "gauge", "histogram", "percentage", "score"}
_VALID_CATEGORIES = {"security", "compliance", "operational", "risk", "performance"}
_VALID_AGGREGATION_TYPES = {"sum", "avg", "min", "max", "count", "weighted_avg"}
_VALID_TS_BUCKETS = {"daily", "weekly", "monthly"}
_MAX_TS_METRIC_KEYS = 20
_MAX_TS_DAYS = 365


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
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_metrics_aggregator", "org_id": org_id, "source_engine": "security_metrics_aggregator"})
            except Exception:
                pass

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

    # ------------------------------------------------------------------
    # Timeseries (GAP-060)
    # ------------------------------------------------------------------

    @staticmethod
    def _bucket_start(ts_iso: str, bucket: str) -> Optional[str]:
        """Normalize a collected_at ISO timestamp to bucket start ISO (UTC)."""
        if not ts_iso:
            return None
        try:
            # Handle both 'Z' and '+00:00' offsets
            raw = ts_iso.replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            return None

        if bucket == "daily":
            start = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        elif bucket == "weekly":
            # Monday UTC midnight
            start = dt.replace(hour=0, minute=0, second=0, microsecond=0)
            start = start - timedelta(days=start.weekday())
        elif bucket == "monthly":
            start = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            return None
        return start.isoformat()

    @staticmethod
    def _generate_buckets(days: int, bucket: str) -> List[str]:
        """Generate bucket-start ISO timestamps covering last `days`, oldest first."""
        now = datetime.now(timezone.utc)
        end = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if bucket == "weekly":
            end = end - timedelta(days=end.weekday())
        elif bucket == "monthly":
            end = end.replace(day=1)

        start_dt = (now - timedelta(days=days)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        if bucket == "weekly":
            start_dt = start_dt - timedelta(days=start_dt.weekday())
        elif bucket == "monthly":
            start_dt = start_dt.replace(day=1)

        out: List[str] = []
        cur = start_dt
        # Cap iterations defensively (max ~365 daily buckets + small margin)
        max_iter = 400
        iterations = 0
        while cur <= end and iterations < max_iter:
            out.append(cur.isoformat())
            if bucket == "daily":
                cur = cur + timedelta(days=1)
            elif bucket == "weekly":
                cur = cur + timedelta(days=7)
            else:  # monthly
                year = cur.year + (1 if cur.month == 12 else 0)
                month = 1 if cur.month == 12 else cur.month + 1
                cur = cur.replace(year=year, month=month)
            iterations += 1
        return out

    def export_timeseries(
        self,
        org_id: str,
        metric_keys: List[str],
        days: int = 90,
        bucket: str = "daily",
    ) -> Dict[str, Any]:
        """Export bucketed timeseries for 1..N metric keys.

        Output shape:
          {"metric_keys": [...], "buckets": [iso,...],
           "series": {key: [v|None, ...], ...}}

        Missing datapoints are ``None`` (not 0) so the UI can draw gaps.
        Within a bucket, multiple samples are averaged.
        """
        if not isinstance(metric_keys, list) or not metric_keys:
            raise ValueError("metric_keys must be a non-empty list")
        if len(metric_keys) > _MAX_TS_METRIC_KEYS:
            raise ValueError(
                f"metric_keys exceeds limit of {_MAX_TS_METRIC_KEYS}"
            )
        # Dedup and stringify
        unique_keys: List[str] = []
        seen = set()
        for k in metric_keys:
            s = str(k).strip()
            if s and s not in seen:
                seen.add(s)
                unique_keys.append(s)
        if not unique_keys:
            raise ValueError("metric_keys must contain at least one non-empty string")

        try:
            days = int(days)
        except (TypeError, ValueError):
            raise ValueError("days must be an integer")
        if days <= 0:
            raise ValueError("days must be >= 1")
        if days > _MAX_TS_DAYS:
            raise ValueError(f"days exceeds limit of {_MAX_TS_DAYS}")

        if bucket not in _VALID_TS_BUCKETS:
            raise ValueError(
                f"bucket must be one of {sorted(_VALID_TS_BUCKETS)}"
            )

        self._ensure_db()
        buckets = self._generate_buckets(days, bucket)
        bucket_index = {b: i for i, b in enumerate(buckets)}

        # Accumulators: key -> list[list[float]] per bucket
        accum: Dict[str, List[List[float]]] = {
            k: [[] for _ in buckets] for k in unique_keys
        }

        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).isoformat()
        placeholders = ",".join(["?"] * len(unique_keys))
        params: list = [org_id, cutoff, *unique_keys]
        sql = (
            "SELECT metric_name, value, collected_at FROM sma_metrics "
            "WHERE org_id = ? AND collected_at >= ? "
            f"AND metric_name IN ({placeholders})"
        )
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()

        for row in rows:
            start_iso = self._bucket_start(row["collected_at"], bucket)
            if start_iso is None:
                continue
            idx = bucket_index.get(start_iso)
            if idx is None:
                continue
            key = row["metric_name"]
            if key not in accum:
                continue
            try:
                accum[key][idx].append(float(row["value"]))
            except (TypeError, ValueError):
                continue

        series: Dict[str, List[Optional[float]]] = {}
        for key in unique_keys:
            slots = accum[key]
            out_vals: List[Optional[float]] = []
            for slot in slots:
                if not slot:
                    out_vals.append(None)
                else:
                    out_vals.append(round(sum(slot) / len(slot), 6))
            series[key] = out_vals

        return {
            "metric_keys": unique_keys,
            "buckets": buckets,
            "series": series,
            "bucket": bucket,
            "days": days,
        }

    def list_metric_keys(self, org_id: str) -> List[str]:
        """Return distinct metric names available for an org."""
        self._ensure_db()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT DISTINCT metric_name FROM sma_metrics WHERE org_id = ? "
                    "ORDER BY metric_name",
                    (org_id,),
                ).fetchall()
        return [r["metric_name"] for r in rows]

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
