"""Security Data Pipeline Engine — ALDECI.

Manages ingestion pipelines that pull security data from heterogeneous sources
(SIEM, EDR, NDR, cloud APIs, databases, files, streaming) and normalize it into
ALDECI's unified format.  Tracks per-pipeline run history, throughput counters,
and error rates.

Compliance: NIST CSF ID.AM, ISO/IEC 27001 A.12.4, SOC 2 CC6.1
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_data_pipeline.db"
)

_VALID_SOURCE_TYPES = {"siem", "edr", "ndr", "cloud", "api", "database", "file", "streaming"}
_VALID_PIPELINE_STATUSES = {"active", "paused", "error", "stopped", "testing"}
_VALID_RUN_STATUSES = {"queued", "running", "completed", "failed", "partial"}
_VALID_DATA_FORMATS = {"json", "cef", "leef", "syslog", "csv", "parquet", "avro"}


class SecurityDataPipelineEngine:
    """SQLite WAL-backed Security Data Pipeline engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS sdp_pipelines (
                    id                       TEXT PRIMARY KEY,
                    org_id                   TEXT NOT NULL,
                    name                     TEXT NOT NULL DEFAULT '',
                    source_type              TEXT NOT NULL DEFAULT 'siem',
                    source_endpoint          TEXT NOT NULL DEFAULT '',
                    data_format              TEXT NOT NULL DEFAULT 'json',
                    transformation_rules_json TEXT NOT NULL DEFAULT '{}',
                    destination              TEXT NOT NULL DEFAULT '',
                    status                   TEXT NOT NULL DEFAULT 'active',
                    records_processed        INTEGER NOT NULL DEFAULT 0,
                    last_run                 DATETIME,
                    error_count              INTEGER NOT NULL DEFAULT 0,
                    created_at               DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_sdp_org
                    ON sdp_pipelines (org_id, status, source_type);

                CREATE TABLE IF NOT EXISTS sdp_runs (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    pipeline_id      TEXT NOT NULL,
                    run_status       TEXT NOT NULL DEFAULT 'queued',
                    records_in       INTEGER NOT NULL DEFAULT 0,
                    records_out      INTEGER NOT NULL DEFAULT 0,
                    records_failed   INTEGER NOT NULL DEFAULT 0,
                    duration_seconds INTEGER NOT NULL DEFAULT 0,
                    error_message    TEXT NOT NULL DEFAULT '',
                    started_at       DATETIME,
                    completed_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_sdp_runs_pipeline
                    ON sdp_runs (org_id, pipeline_id, started_at);

                CREATE INDEX IF NOT EXISTS idx_sdp_runs_status
                    ON sdp_runs (org_id, run_status, started_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Pipelines
    # ------------------------------------------------------------------

    def register_pipeline(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new data ingestion pipeline.

        Required keys: name
        Optional keys: source_type, source_endpoint, data_format,
                       transformation_rules_json, destination
        """
        name = data.get("name", "")
        if not name:
            raise ValueError("name is required")

        source_type = data.get("source_type", "siem")
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {_VALID_SOURCE_TYPES}")

        data_format = data.get("data_format", "json")
        if data_format not in _VALID_DATA_FORMATS:
            raise ValueError(f"data_format must be one of {_VALID_DATA_FORMATS}")

        pipeline_id = str(uuid.uuid4())
        now = self._now()

        row = {
            "id": pipeline_id,
            "org_id": org_id,
            "name": name,
            "source_type": source_type,
            "source_endpoint": data.get("source_endpoint", ""),
            "data_format": data_format,
            "transformation_rules_json": data.get("transformation_rules_json", "{}"),
            "destination": data.get("destination", ""),
            "status": "active",
            "records_processed": 0,
            "last_run": None,
            "error_count": 0,
            "created_at": now,
        }

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO sdp_pipelines
                    (id, org_id, name, source_type, source_endpoint, data_format,
                     transformation_rules_json, destination, status, records_processed,
                     last_run, error_count, created_at)
                VALUES
                    (:id, :org_id, :name, :source_type, :source_endpoint, :data_format,
                     :transformation_rules_json, :destination, :status, :records_processed,
                     :last_run, :error_count, :created_at)
                """,
                row,
            )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_data_pipeline", "org_id": org_id, "source_engine": "security_data_pipeline"})
            except Exception:
                pass

        return dict(row)

    def list_pipelines(
        self,
        org_id: str,
        source_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List pipelines for an org with optional filters."""
        query = "SELECT * FROM sdp_pipelines WHERE org_id = ?"
        params: list = [org_id]
        if source_type:
            query += " AND source_type = ?"
            params.append(source_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_pipeline(self, org_id: str, pipeline_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single pipeline or None if not found."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sdp_pipelines WHERE id = ? AND org_id = ?",
                (pipeline_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_pipeline_status(
        self, org_id: str, pipeline_id: str, status: str
    ) -> Dict[str, Any]:
        """Update the operational status of a pipeline."""
        if status not in _VALID_PIPELINE_STATUSES:
            raise ValueError(f"status must be one of {_VALID_PIPELINE_STATUSES}")

        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE sdp_pipelines SET status = ? WHERE id = ? AND org_id = ?",
                (status, pipeline_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM sdp_pipelines WHERE id = ? AND org_id = ?",
                (pipeline_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Pipeline {pipeline_id} not found for org {org_id}")
        return self._row(row)

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------

    def record_pipeline_run(
        self, org_id: str, pipeline_id: str, run_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a pipeline execution run and update pipeline counters.

        Required keys: run_status
        Optional keys: records_in, records_out, records_failed,
                       duration_seconds, error_message, started_at, completed_at
        """
        run_status = run_data.get("run_status", "completed")
        if run_status not in _VALID_RUN_STATUSES:
            raise ValueError(f"run_status must be one of {_VALID_RUN_STATUSES}")

        run_id = str(uuid.uuid4())
        now = self._now()
        records_out = int(run_data.get("records_out", 0))
        is_failed = run_status == "failed"

        row = {
            "id": run_id,
            "org_id": org_id,
            "pipeline_id": pipeline_id,
            "run_status": run_status,
            "records_in": int(run_data.get("records_in", 0)),
            "records_out": records_out,
            "records_failed": int(run_data.get("records_failed", 0)),
            "duration_seconds": int(run_data.get("duration_seconds", 0)),
            "error_message": run_data.get("error_message", ""),
            "started_at": run_data.get("started_at", now),
            "completed_at": run_data.get("completed_at", now),
        }

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO sdp_runs
                    (id, org_id, pipeline_id, run_status, records_in, records_out,
                     records_failed, duration_seconds, error_message, started_at, completed_at)
                VALUES
                    (:id, :org_id, :pipeline_id, :run_status, :records_in, :records_out,
                     :records_failed, :duration_seconds, :error_message, :started_at, :completed_at)
                """,
                row,
            )
            # Update pipeline counters
            if is_failed:
                conn.execute(
                    """
                    UPDATE sdp_pipelines
                    SET records_processed = records_processed + ?,
                        last_run = ?,
                        error_count = error_count + 1
                    WHERE id = ? AND org_id = ?
                    """,
                    (records_out, now, pipeline_id, org_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE sdp_pipelines
                    SET records_processed = records_processed + ?,
                        last_run = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (records_out, now, pipeline_id, org_id),
                )

        return dict(row)

    def list_runs(
        self,
        org_id: str,
        pipeline_id: Optional[str] = None,
        run_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List runs with optional pipeline_id / run_status filters, newest first."""
        query = "SELECT * FROM sdp_runs WHERE org_id = ?"
        params: list = [org_id]
        if pipeline_id:
            query += " AND pipeline_id = ?"
            params.append(pipeline_id)
        if run_status:
            query += " AND run_status = ?"
            params.append(run_status)
        query += " ORDER BY started_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_pipeline_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated pipeline statistics for the org."""
        today_prefix = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        with self._lock, self._conn() as conn:
            total_pipelines = conn.execute(
                "SELECT COUNT(*) FROM sdp_pipelines WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_pipelines = conn.execute(
                "SELECT COUNT(*) FROM sdp_pipelines WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            total_records = conn.execute(
                "SELECT COALESCE(SUM(records_processed), 0) FROM sdp_pipelines WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            failed_today = conn.execute(
                """
                SELECT COUNT(*) FROM sdp_runs
                WHERE org_id = ? AND run_status = 'failed'
                  AND started_at LIKE ?
                """,
                (org_id, today_prefix + "%"),
            ).fetchone()[0]

            avg_row = conn.execute(
                "SELECT AVG(records_out) FROM sdp_runs WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            avg_throughput = round(avg_row, 2) if avg_row is not None else 0.0

            source_rows = conn.execute(
                """
                SELECT source_type, COUNT(*) AS cnt
                FROM sdp_pipelines WHERE org_id = ?
                GROUP BY source_type
                """,
                (org_id,),
            ).fetchall()
            by_source_type = {r["source_type"]: r["cnt"] for r in source_rows}

            total_runs = conn.execute(
                "SELECT COUNT(*) FROM sdp_runs WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            failed_runs = conn.execute(
                "SELECT COUNT(*) FROM sdp_runs WHERE org_id = ? AND run_status = 'failed'",
                (org_id,),
            ).fetchone()[0]

        error_rate = round(failed_runs / total_runs * 100, 2) if total_runs > 0 else 0.0

        return {
            "org_id": org_id,
            "total_pipelines": total_pipelines,
            "active_pipelines": active_pipelines,
            "total_records_processed": total_records,
            "failed_runs_today": failed_today,
            "avg_throughput": avg_throughput,
            "by_source_type": by_source_type,
            "error_rate": error_rate,
        }
