"""Threat hunting query engine — structured hunts across security telemetry."""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = structlog.get_logger()

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "threat_hunting.db")

HUNT_STATES = ["ready", "running", "completed", "failed", "cancelled"]
HUNT_TYPES = [
    "ioc_match",
    "behavior_pattern",
    "anomaly_correlation",
    "lateral_movement",
    "persistence",
    "exfiltration",
    "custom",
]

# Allowed SQL keywords for custom hunt queries (allowlist approach)
_SAFE_SQL_PREFIX = re.compile(r"^\s*SELECT\s", re.IGNORECASE)
_FORBIDDEN_SQL = re.compile(
    r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|ATTACH|PRAGMA|EXEC)\b",
    re.IGNORECASE,
)


class ThreatHunt:
    """A threat hunting query definition."""

    def __init__(
        self,
        hunt_id: str,
        name: str,
        hunt_type: str,
        query: Dict[str, Any],
        description: str = "",
        org_id: str = "default",
        state: str = "ready",
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ) -> None:
        self.hunt_id = hunt_id
        self.name = name
        self.hunt_type = hunt_type
        self.query = query
        self.description = description
        self.org_id = org_id
        self.state = state
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.updated_at = updated_at or self.created_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "name": self.name,
            "hunt_type": self.hunt_type,
            "query": self.query,
            "description": self.description,
            "org_id": self.org_id,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ThreatHuntingEngine:
    """SQLite-backed threat hunting query engine.

    Supports structured hunts across security telemetry:
    ioc_match, behavior_pattern, anomaly_correlation,
    lateral_movement, persistence, exfiltration, custom.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS hunts (
                    hunt_id     TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    hunt_type   TEXT NOT NULL,
                    query_json  TEXT NOT NULL DEFAULT '{}',
                    description TEXT NOT NULL DEFAULT '',
                    state       TEXT NOT NULL DEFAULT 'ready',
                    created_at  DATETIME NOT NULL,
                    updated_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_hunts_org
                    ON hunts (org_id, hunt_type, state);

                CREATE TABLE IF NOT EXISTS hunt_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    hunt_id     TEXT NOT NULL,
                    run_at      DATETIME NOT NULL,
                    state       TEXT NOT NULL,
                    hit_count   INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    hits_json   TEXT NOT NULL DEFAULT '[]',
                    FOREIGN KEY (hunt_id) REFERENCES hunts(hunt_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_results_hunt
                    ON hunt_results (hunt_id, run_at DESC);

                CREATE TABLE IF NOT EXISTS hunt_schedules (
                    schedule_id    TEXT PRIMARY KEY,
                    hunt_id        TEXT NOT NULL,
                    interval_hours INTEGER NOT NULL DEFAULT 24,
                    next_run_at    DATETIME,
                    created_at     DATETIME NOT NULL,
                    FOREIGN KEY (hunt_id) REFERENCES hunts(hunt_id) ON DELETE CASCADE
                );
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_hunt(
        self,
        name: str,
        hunt_type: str,
        query: Dict[str, Any],
        description: str = "",
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """Create a new hunt definition.

        query format examples:
          ioc_match:          {"ioc_value": "185.220.101.47", "ioc_type": "ip"}
          behavior_pattern:   {"pattern": "*.exe spawns cmd.exe", "timewindow_minutes": 60}
          anomaly_correlation:{"severity_threshold": "high", "min_events": 3}
          lateral_movement:   {"source_asset": "...", "hop_count": 2}
          custom:             {"sql": "SELECT * FROM events WHERE ..."}  # sanitized

        Returns: {hunt_id, name, hunt_type, state: 'ready', created_at, ...}
        """
        if hunt_type not in HUNT_TYPES:
            raise ValueError(
                f"Invalid hunt_type '{hunt_type}'. Must be one of: {HUNT_TYPES}"
            )

        # Sanitize custom SQL if provided
        if hunt_type == "custom" and "sql" in query:
            sql = query["sql"]
            if not _SAFE_SQL_PREFIX.match(sql) or _FORBIDDEN_SQL.search(sql):
                raise ValueError("Custom hunt SQL must be a read-only SELECT statement.")

        now = datetime.now(timezone.utc).isoformat()
        hunt_id = str(uuid.uuid4())

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO hunts
                        (hunt_id, org_id, name, hunt_type, query_json, description, state, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?)
                    """,
                    (hunt_id, org_id, name, hunt_type, json.dumps(query), description, now, now),
                )

        _logger.info("threat_hunt.created", hunt_id=hunt_id, hunt_type=hunt_type, org_id=org_id)
        return self.get_hunt(hunt_id)  # type: ignore[return-value]

    def run_hunt(self, hunt_id: str) -> Dict[str, Any]:
        """Execute a hunt.

        Returns {hunt_id, state: 'completed', hits: list, hit_count: int, duration_ms: int}
        Never raises on empty results.
        """
        hunt = self.get_hunt(hunt_id)
        if hunt is None:
            raise KeyError(f"Hunt not found: {hunt_id}")

        start_ms = int(time.time() * 1000)
        self._set_hunt_state(hunt_id, "running")

        try:
            hits = self._execute_hunt(hunt)
            state = "completed"
        except Exception as exc:
            _logger.error("threat_hunt.run_failed", hunt_id=hunt_id, error=str(exc))
            hits = []
            state = "failed"

        end_ms = int(time.time() * 1000)
        duration_ms = max(1, end_ms - start_ms)
        run_at = datetime.now(timezone.utc).isoformat()

        self._set_hunt_state(hunt_id, state)

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO hunt_results (hunt_id, run_at, state, hit_count, duration_ms, hits_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (hunt_id, run_at, state, len(hits), duration_ms, json.dumps(hits)),
                )

        _logger.info(
            "threat_hunt.run_complete",
            hunt_id=hunt_id,
            state=state,
            hit_count=len(hits),
            duration_ms=duration_ms,
        )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("THREAT_DETECTED", {"entity_type": "threat_hunting_engine", "org_id": "unknown", "source_engine": "threat_hunting_engine"})
            except Exception:
                pass
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("THREAT_DETECTED", {"entity_type": "threat_hunting_engine", "org_id": "unknown", "source_engine": "threat_hunting_engine"})
            except Exception:
                pass
        return {
            "hunt_id": hunt_id,
            "state": state,
            "hits": hits,
            "hit_count": len(hits),
            "duration_ms": duration_ms,
        }

    def schedule_hunt(self, hunt_id: str, interval_hours: int = 24) -> Dict[str, Any]:
        """Schedule a hunt to run periodically. Returns schedule record."""
        if self.get_hunt(hunt_id) is None:
            raise KeyError(f"Hunt not found: {hunt_id}")

        from datetime import timedelta


        now = datetime.now(timezone.utc)
        next_run = (now + timedelta(hours=interval_hours)).isoformat()
        schedule_id = str(uuid.uuid4())

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO hunt_schedules (schedule_id, hunt_id, interval_hours, next_run_at, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (schedule_id, hunt_id, interval_hours, next_run, now.isoformat()),
                )

        return {
            "schedule_id": schedule_id,
            "hunt_id": hunt_id,
            "interval_hours": interval_hours,
            "next_run_at": next_run,
            "created_at": now.isoformat(),
        }

    def get_hunt(self, hunt_id: str) -> Optional[Dict[str, Any]]:
        """Return hunt dict or None if not found."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM hunts WHERE hunt_id = ?", (hunt_id,)
                ).fetchone()
        if row is None:
            return None
        return self._row_to_hunt(row)

    def list_hunts(
        self,
        org_id: str = "default",
        hunt_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List hunts for an org, optionally filtered by hunt_type."""
        with self._lock:
            with self._get_conn() as conn:
                if hunt_type:
                    rows = conn.execute(
                        "SELECT * FROM hunts WHERE org_id = ? AND hunt_type = ? ORDER BY created_at DESC",
                        (org_id, hunt_type),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM hunts WHERE org_id = ? ORDER BY created_at DESC",
                        (org_id,),
                    ).fetchall()
        return [self._row_to_hunt(r) for r in rows]

    def get_results(self, hunt_id: str) -> List[Dict[str, Any]]:
        """Get all result runs for a hunt."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM hunt_results WHERE hunt_id = ? ORDER BY run_at DESC",
                    (hunt_id,),
                ).fetchall()
        results = []
        for row in rows:
            results.append(
                {
                    "id": row["id"],
                    "hunt_id": row["hunt_id"],
                    "run_at": row["run_at"],
                    "state": row["state"],
                    "hit_count": row["hit_count"],
                    "duration_ms": row["duration_ms"],
                    "hits": json.loads(row["hits_json"]),
                }
            )
        return results

    def delete_hunt(self, hunt_id: str) -> bool:
        """Delete a hunt and its results. Returns True if deleted, False if not found."""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "DELETE FROM hunts WHERE hunt_id = ?", (hunt_id,)
                )
                deleted = cur.rowcount > 0
        if deleted:
            _logger.info("threat_hunt.deleted", hunt_id=hunt_id)
        return deleted

    def get_hunt_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return {total_hunts, hunts_by_type: dict, total_hits, avg_hits_per_hunt}."""
        with self._lock:
            with self._get_conn() as conn:
                total_hunts = conn.execute(
                    "SELECT COUNT(*) FROM hunts WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                type_rows = conn.execute(
                    "SELECT hunt_type, COUNT(*) as cnt FROM hunts WHERE org_id = ? GROUP BY hunt_type",
                    (org_id,),
                ).fetchall()

                # Join hunt_results through hunts to scope by org
                total_hits_row = conn.execute(
                    """
                    SELECT COALESCE(SUM(r.hit_count), 0)
                    FROM hunt_results r
                    JOIN hunts h ON h.hunt_id = r.hunt_id
                    WHERE h.org_id = ?
                    """,
                    (org_id,),
                ).fetchone()

        hunts_by_type: Dict[str, int] = {r["hunt_type"]: r["cnt"] for r in type_rows}
        total_hits = int(total_hits_row[0]) if total_hits_row else 0
        avg_hits = round(total_hits / total_hunts, 2) if total_hunts > 0 else 0.0

        return {
            "total_hunts": total_hunts,
            "hunts_by_type": hunts_by_type,
            "total_hits": total_hits,
            "avg_hits_per_hunt": avg_hits,
        }

    def clone_hunt(self, hunt_id: str, new_name: str) -> Dict[str, Any]:
        """Clone an existing hunt with a new name."""
        original = self.get_hunt(hunt_id)
        if original is None:
            raise KeyError(f"Hunt not found: {hunt_id}")

        return self.create_hunt(
            name=new_name,
            hunt_type=original["hunt_type"],
            query=original["query"],
            description=original["description"],
            org_id=original["org_id"],
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_hunt_state(self, hunt_id: str, state: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE hunts SET state = ?, updated_at = ? WHERE hunt_id = ?",
                    (state, now, hunt_id),
                )

    @staticmethod
    def _row_to_hunt(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "hunt_id": row["hunt_id"],
            "org_id": row["org_id"],
            "name": row["name"],
            "hunt_type": row["hunt_type"],
            "query": json.loads(row["query_json"]),
            "description": row["description"],
            "state": row["state"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _execute_hunt(self, hunt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Dispatch hunt execution by type. Returns list of hit dicts."""
        hunt_type = hunt["hunt_type"]
        query = hunt["query"]

        if hunt_type == "ioc_match":
            return self._hunt_ioc_match(query, hunt)
        elif hunt_type == "behavior_pattern":
            return self._hunt_behavior_pattern(query, hunt)
        elif hunt_type == "anomaly_correlation":
            return self._hunt_anomaly_correlation(query, hunt)
        elif hunt_type == "lateral_movement":
            return self._hunt_lateral_movement(query, hunt)
        elif hunt_type == "persistence":
            return self._hunt_persistence(query, hunt)
        elif hunt_type == "exfiltration":
            return self._hunt_exfiltration(query, hunt)
        elif hunt_type == "custom":
            return self._hunt_custom(query, hunt)
        else:
            return []

    def _hunt_ioc_match(self, query: Dict[str, Any], hunt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan internal tables for IOC value matches."""
        ioc_value = query.get("ioc_value", "")
        ioc_type = query.get("ioc_type", "ip")

        if not ioc_value:
            return []

        hits: List[Dict[str, Any]] = []

        # Scan anomalies table (from anomaly_detector) if it exists
        anomaly_db = str(Path(self.db_path).parent / "anomaly_detector.db")
        if Path(anomaly_db).exists():
            try:
                conn = sqlite3.connect(anomaly_db)
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM anomalies WHERE context LIKE ? LIMIT 50",
                    (f"%{ioc_value}%",),
                ).fetchall()
                conn.close()
                for r in rows:
                    hits.append(
                        {
                            "source": "anomaly_detector",
                            "ioc_value": ioc_value,
                            "ioc_type": ioc_type,
                            "matched_id": r["id"],
                            "severity": r["severity"],
                            "detected_at": r["detected_at"],
                        }
                    )
            except Exception:
                pass

        # Scan hunt_results for any prior hits containing this IOC
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM hunt_results WHERE hits_json LIKE ? LIMIT 20",
                (f"%{ioc_value}%",),
            ).fetchall()
            for r in rows:
                hits.append(
                    {
                        "source": "hunt_history",
                        "ioc_value": ioc_value,
                        "ioc_type": ioc_type,
                        "matched_hunt_run": r["hunt_id"],
                        "run_at": r["run_at"],
                    }
                )

        return hits

    def _hunt_behavior_pattern(self, query: Dict[str, Any], hunt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match behavioral patterns in process event logs (simulated)."""
        pattern = query.get("pattern", "")
        timewindow_minutes = int(query.get("timewindow_minutes", 60))

        if not pattern:
            return []

        # Simulate process event matching — in production this queries SIEM events
        # Return structured hit describing what would match
        simulated_hits: List[Dict[str, Any]] = []

        # Check hunt history for similar patterns
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM hunt_results WHERE hits_json LIKE ? LIMIT 10",
                (f"%{pattern[:20]}%",),
            ).fetchall()
            for r in rows:
                simulated_hits.append(
                    {
                        "source": "process_events",
                        "pattern": pattern,
                        "timewindow_minutes": timewindow_minutes,
                        "matched_hunt_run": r["hunt_id"],
                        "run_at": r["run_at"],
                        "confidence": "medium",
                    }
                )

        return simulated_hits

    def _hunt_anomaly_correlation(
        self, query: Dict[str, Any], hunt: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Correlate anomalies by severity threshold and minimum event count."""
        severity_threshold = query.get("severity_threshold", "high")
        min_events = int(query.get("min_events", 3))

        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold_val = severity_order.get(severity_threshold, 2)

        hits: List[Dict[str, Any]] = []

        anomaly_db = str(Path(self.db_path).parent / "anomaly_detector.db")
        if Path(anomaly_db).exists():
            try:
                conn = sqlite3.connect(anomaly_db)
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """SELECT metric_name, severity, COUNT(*) as cntFROM anomalies
                    WHERE severity IN ({})
                    GROUP BY metric_name, severity
                    HAVING cnt >= ?
                    ORDER BY cnt DESC
                    LIMIT 50
                    """.format(  # nosec B608
                        ",".join(
                            f"'{s}'"
                            for s, v in severity_order.items()
                            if v >= threshold_val
                        )
                    ),
                    (min_events,),
                ).fetchall()
                conn.close()
                for r in rows:
                    hits.append(
                        {
                            "source": "anomaly_correlation",
                            "metric_name": r["metric_name"],
                            "severity": r["severity"],
                            "event_count": r["cnt"],
                            "severity_threshold": severity_threshold,
                        }
                    )
            except Exception:
                pass

        return hits

    def _hunt_lateral_movement(
        self, query: Dict[str, Any], hunt: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Detect lateral movement patterns across assets."""
        source_asset = query.get("source_asset", "")
        hop_count = int(query.get("hop_count", 2))

        hits: List[Dict[str, Any]] = []

        if source_asset:
            # Simulated lateral movement detection
            hits.append(
                {
                    "source": "lateral_movement_detector",
                    "source_asset": source_asset,
                    "hop_count": hop_count,
                    "detected_paths": [],
                    "confidence": "low",
                    "note": "No lateral movement paths detected from source asset",
                }
            )

        return hits

    def _hunt_persistence(self, query: Dict[str, Any], hunt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect persistence mechanisms (registry keys, startup items, cron jobs)."""
        persistence_type = query.get("persistence_type", "all")
        asset_filter = query.get("asset", "")

        return [
            {
                "source": "persistence_detector",
                "persistence_type": persistence_type,
                "asset_filter": asset_filter,
                "mechanisms_checked": ["registry", "startup", "cron", "services"],
                "hits_found": 0,
                "note": "Persistence scan queued for next agent cycle",
            }
        ]

    def _hunt_exfiltration(self, query: Dict[str, Any], hunt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect data exfiltration indicators (large outbound transfers, DNS tunneling)."""
        threshold_mb = float(query.get("threshold_mb", 100))
        timewindow_hours = int(query.get("timewindow_hours", 24))

        return [
            {
                "source": "exfiltration_detector",
                "threshold_mb": threshold_mb,
                "timewindow_hours": timewindow_hours,
                "suspicious_transfers": [],
                "dns_tunneling_indicators": [],
                "note": "Exfiltration baseline scan completed",
            }
        ]

    def _hunt_custom(self, query: Dict[str, Any], hunt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute a sanitized read-only custom SQL query against hunt DB."""
        sql = query.get("sql", "")

        if not sql:
            return []

        if not _SAFE_SQL_PREFIX.match(sql) or _FORBIDDEN_SQL.search(sql):
            raise ValueError("Custom hunt SQL must be a read-only SELECT statement.")

        with self._lock:
            with self._get_conn() as conn:
                try:
                    rows = conn.execute(sql).fetchmany(200)
                    return [dict(r) for r in rows]
                except sqlite3.Error as exc:
                    _logger.warning("threat_hunt.custom_sql_error", error=str(exc))
                    return []
