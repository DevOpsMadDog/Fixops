"""Security Telemetry Engine — ALDECI.

Ingests and aggregates security telemetry datapoints (EPS, alert volume,
false-positive rate, MTTR, etc.) with alert rule evaluation.

Compliance: NIST SP 800-137, SOC 2 CC7.2, ISO 27001 A.12.4
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_telemetry.db"
)

_VALID_TELEMETRY_TYPES = {
    "events_per_second", "alert_volume", "false_positive_rate",
    "detection_latency", "mttr", "coverage_score", "threat_score", "noise_ratio",
}
_VALID_SOURCES = {"siem", "edr", "ndr", "firewall", "ids", "cloud", "custom"}
_VALID_AGGREGATIONS = {"avg", "sum", "max", "min", "count", "p95", "p99"}
_VALID_OPERATORS = {"gt", "lt", "gte", "lte"}


class SecurityTelemetryEngine:
    """SQLite WAL-backed Security Telemetry engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS st_datapoints (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    telemetry_type TEXT NOT NULL DEFAULT 'events_per_second',
                    source         TEXT NOT NULL DEFAULT 'siem',
                    value          REAL NOT NULL DEFAULT 0.0,
                    unit           TEXT NOT NULL DEFAULT '',
                    tags_json      TEXT NOT NULL DEFAULT '{}',
                    collected_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_st_datapoints_org
                    ON st_datapoints (org_id, telemetry_type, source, collected_at);

                CREATE TABLE IF NOT EXISTS st_rules (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL DEFAULT '',
                    telemetry_type TEXT NOT NULL DEFAULT 'events_per_second',
                    aggregation    TEXT NOT NULL DEFAULT 'avg',
                    threshold      REAL NOT NULL DEFAULT 0.0,
                    operator       TEXT NOT NULL DEFAULT 'gt',
                    source         TEXT NOT NULL DEFAULT '',
                    enabled        INTEGER NOT NULL DEFAULT 1,
                    trigger_count  INTEGER NOT NULL DEFAULT 0,
                    last_triggered DATETIME,
                    created_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_st_rules_org
                    ON st_rules (org_id, enabled);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Telemetry Ingest
    # ------------------------------------------------------------------

    def ingest_telemetry(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a telemetry datapoint."""
        telemetry_type = data.get("telemetry_type", "events_per_second")
        if telemetry_type not in _VALID_TELEMETRY_TYPES:
            raise ValueError(
                f"telemetry_type must be one of {sorted(_VALID_TELEMETRY_TYPES)}"
            )

        source = data.get("source", "siem")
        if source not in _VALID_SOURCES:
            raise ValueError(f"source must be one of {sorted(_VALID_SOURCES)}")

        now = self._now()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "telemetry_type": telemetry_type,
            "source": source,
            "value": float(data.get("value", 0.0)),
            "unit": data.get("unit", ""),
            "tags_json": __import__("json").dumps(data.get("tags", {})),
            "collected_at": data.get("collected_at", now),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO st_datapoints VALUES
                       (:id,:org_id,:telemetry_type,:source,:value,:unit,:tags_json,:collected_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_telemetry", "org_id": org_id, "source_engine": "security_telemetry"})
            except Exception:
                pass

        return dict(row)

    def list_telemetry(
        self,
        org_id: str,
        telemetry_type: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List telemetry datapoints with optional filters, ordered newest first."""
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]
        if telemetry_type:
            clauses.append("telemetry_type = ?")
            params.append(telemetry_type)
        if source:
            clauses.append("source = ?")
            params.append(source)

        sql = (
            f"SELECT * FROM st_datapoints WHERE {' AND '.join(clauses)}"  # nosec B608
            " ORDER BY collected_at DESC LIMIT ?"
        )
        params.append(limit)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_latest(
        self,
        org_id: str,
        telemetry_type: str,
        source: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Return the most recent datapoint for a telemetry_type (+ optional source)."""
        clauses = ["org_id = ?", "telemetry_type = ?"]
        params: List[Any] = [org_id, telemetry_type]
        if source:
            clauses.append("source = ?")
            params.append(source)

        sql = (
            f"SELECT * FROM st_datapoints WHERE {' AND '.join(clauses)}"  # nosec B608
            " ORDER BY collected_at DESC LIMIT 1"
        )
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(sql, params).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def aggregate_telemetry(
        self,
        org_id: str,
        telemetry_type: str,
        aggregation: str,
        source: Optional[str] = None,
        hours: int = 24,
    ) -> Dict[str, Any]:
        """Compute an aggregation over the last N hours for a telemetry type."""
        if aggregation not in _VALID_AGGREGATIONS:
            raise ValueError(f"aggregation must be one of {sorted(_VALID_AGGREGATIONS)}")

        clauses = [
            "org_id = ?",
            "telemetry_type = ?",
            "collected_at >= datetime('now', ?)",
        ]
        params: List[Any] = [org_id, telemetry_type, f"-{hours} hours"]
        if source:
            clauses.append("source = ?")
            params.append(source)

        where = " AND ".join(clauses)

        # Build aggregate SQL — p95/p99 done in Python
        if aggregation in ("p95", "p99"):
            sql_values = f"SELECT value FROM st_datapoints WHERE {where} ORDER BY value"  # nosec B608
        elif aggregation == "count":
            sql_values = f"SELECT COUNT(*) as agg_val FROM st_datapoints WHERE {where}"  # nosec B608
        else:
            agg_fn = aggregation.upper()
            sql_values = f"SELECT {agg_fn}(value) as agg_val FROM st_datapoints WHERE {where}"  # nosec B608

        with self._lock:
            with self._conn() as conn:
                count_row = conn.execute(
                    f"SELECT COUNT(*) FROM st_datapoints WHERE {where}", params  # nosec B608
                ).fetchone()
                datapoint_count = count_row[0]

                if aggregation in ("p95", "p99"):
                    rows = conn.execute(sql_values, params).fetchall()
                    values = [r[0] for r in rows]
                    if not values:
                        agg_value = 0.0
                    else:
                        pct = 95 if aggregation == "p95" else 99
                        idx = max(0, int(len(values) * pct / 100) - 1)
                        agg_value = float(values[idx])
                elif aggregation == "count":
                    agg_value = float(datapoint_count)
                else:
                    row = conn.execute(sql_values, params).fetchone()
                    agg_value = float(row[0] if row[0] is not None else 0.0)

        return {
            "telemetry_type": telemetry_type,
            "aggregation": aggregation,
            "value": round(agg_value, 4),
            "source": source,
            "hours": hours,
            "datapoint_count": datapoint_count,
        }

    # ------------------------------------------------------------------
    # Alert Rules
    # ------------------------------------------------------------------

    def create_alert_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a telemetry alert rule."""
        telemetry_type = data.get("telemetry_type", "events_per_second")
        if telemetry_type not in _VALID_TELEMETRY_TYPES:
            raise ValueError(
                f"telemetry_type must be one of {sorted(_VALID_TELEMETRY_TYPES)}"
            )

        aggregation = data.get("aggregation", "avg")
        if aggregation not in _VALID_AGGREGATIONS:
            raise ValueError(f"aggregation must be one of {sorted(_VALID_AGGREGATIONS)}")

        operator = data.get("operator", "gt")
        if operator not in _VALID_OPERATORS:
            raise ValueError(f"operator must be one of {sorted(_VALID_OPERATORS)}")

        now = self._now()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": data.get("name", ""),
            "telemetry_type": telemetry_type,
            "aggregation": aggregation,
            "threshold": float(data.get("threshold", 0.0)),
            "operator": operator,
            "source": data.get("source", ""),
            "enabled": 1,
            "trigger_count": 0,
            "last_triggered": None,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO st_rules VALUES
                       (:id,:org_id,:name,:telemetry_type,:aggregation,:threshold,
                        :operator,:source,:enabled,:trigger_count,:last_triggered,:created_at)""",
                    row,
                )
        return dict(row)

    def list_alert_rules(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List alert rules, optionally filtered by enabled status."""
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]
        if enabled is not None:
            clauses.append("enabled = ?")
            params.append(1 if enabled else 0)

        sql = (
            f"SELECT * FROM st_rules WHERE {' AND '.join(clauses)}"  # nosec B608
            " ORDER BY created_at DESC"
        )
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def check_alert_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """Evaluate all enabled rules; return list of triggered rules with current values."""
        rules = self.list_alert_rules(org_id, enabled=True)
        triggered = []

        for rule in rules:
            source = rule["source"] or None
            agg_result = self.aggregate_telemetry(
                org_id,
                rule["telemetry_type"],
                rule["aggregation"],
                source=source,
                hours=1,
            )
            current_value = agg_result["value"]
            threshold = float(rule["threshold"])
            op = rule["operator"]

            fired = (
                (op == "gt" and current_value > threshold)
                or (op == "lt" and current_value < threshold)
                or (op == "gte" and current_value >= threshold)
                or (op == "lte" and current_value <= threshold)
            )

            if fired:
                now = self._now()
                with self._lock:
                    with self._conn() as conn:
                        conn.execute(
                            """UPDATE st_rules
                               SET trigger_count = trigger_count + 1,
                                   last_triggered = ?
                               WHERE id = ? AND org_id = ?""",
                            (now, rule["id"], org_id),
                        )
                triggered.append({
                    **rule,
                    "current_value": current_value,
                    "triggered_at": now,
                })

        return triggered

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_telemetry_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated telemetry statistics for an org."""
        today = datetime.now(timezone.utc).date().isoformat()

        with self._lock:
            with self._conn() as conn:
                total_datapoints = conn.execute(
                    "SELECT COUNT(*) FROM st_datapoints WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                active_sources = conn.execute(
                    "SELECT COUNT(DISTINCT source) FROM st_datapoints WHERE org_id = ?",
                    (org_id,),
                ).fetchone()[0]

                telemetry_types_tracked = conn.execute(
                    "SELECT COUNT(DISTINCT telemetry_type) FROM st_datapoints WHERE org_id = ?",
                    (org_id,),
                ).fetchone()[0]

                alert_rules_count = conn.execute(
                    "SELECT COUNT(*) FROM st_rules WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                triggered_rules_today = conn.execute(
                    "SELECT COUNT(*) FROM st_rules WHERE org_id = ? AND last_triggered LIKE ?",
                    (org_id, f"{today}%"),
                ).fetchone()[0]

                by_type_rows = conn.execute(
                    """SELECT telemetry_type, COUNT(*) as cnt
                       FROM st_datapoints WHERE org_id = ?
                       GROUP BY telemetry_type""",
                    (org_id,),
                ).fetchall()

        return {
            "total_datapoints": total_datapoints,
            "active_sources": active_sources,
            "telemetry_types_tracked": telemetry_types_tracked,
            "alert_rules_count": alert_rules_count,
            "triggered_rules_today": triggered_rules_today,
            "by_type": {r["telemetry_type"]: r["cnt"] for r in by_type_rows},
        }
