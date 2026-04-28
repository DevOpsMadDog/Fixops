"""Alert Enrichment Engine — ALDECI.

Enriches security alerts with threat context, asset data, and IOC correlation
from multiple enrichment sources. Supports confidence scoring, risk scoring,
and enrichment history tracking.

Compliance: NIST CSF DE.AE-3, ISO/IEC 27001 A.16.1.4, SOC 2 CC7.2
"""

from __future__ import annotations

import hashlib
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "alert_enrichment.db"
)

_VALID_INDICATOR_TYPES = {"ip", "domain", "url", "hash", "email", "user", "process", "registry"}
_VALID_SOURCE_TYPES = {"threat_intel", "asset_db", "vuln_db", "geolocation", "reputation"}
_VALID_RESULT_TYPES = {"ioc_match", "geolocation", "asset_info", "vuln_info", "reputation", "error"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_SEVERITY_MULTIPLIER = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
}


class AlertEnrichmentEngine:
    """SQLite WAL-backed Alert Enrichment engine.

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
                CREATE TABLE IF NOT EXISTS enriched_alerts (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    alert_id            TEXT NOT NULL,
                    alert_source        TEXT NOT NULL DEFAULT '',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    raw_indicator       TEXT NOT NULL DEFAULT '',
                    indicator_type      TEXT NOT NULL DEFAULT 'ip',
                    enrichment_status   TEXT NOT NULL DEFAULT 'pending',
                    threat_context      TEXT NOT NULL DEFAULT '',
                    asset_context       TEXT NOT NULL DEFAULT '',
                    ioc_matches         INTEGER NOT NULL DEFAULT 0,
                    confidence_score    REAL NOT NULL DEFAULT 0.0,
                    risk_score          REAL NOT NULL DEFAULT 0.0,
                    enriched_at         TEXT,
                    created_at          TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_ae_alert_org
                    ON enriched_alerts (alert_id, org_id);

                CREATE INDEX IF NOT EXISTS idx_ae_org_status
                    ON enriched_alerts (org_id, enrichment_status);

                CREATE INDEX IF NOT EXISTS idx_ae_org_risk
                    ON enriched_alerts (org_id, risk_score);

                CREATE TABLE IF NOT EXISTS enrichment_sources (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    source_name     TEXT NOT NULL,
                    source_type     TEXT NOT NULL DEFAULT 'threat_intel',
                    priority        INTEGER NOT NULL DEFAULT 1,
                    api_key_hash    TEXT NOT NULL DEFAULT '',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    last_used       TEXT,
                    success_count   INTEGER NOT NULL DEFAULT 0,
                    error_count     INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_es_org
                    ON enrichment_sources (org_id, enabled);

                CREATE TABLE IF NOT EXISTS enrichment_history (
                    id          TEXT PRIMARY KEY,
                    alert_id    TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    source_name TEXT NOT NULL DEFAULT '',
                    result_type TEXT NOT NULL DEFAULT 'ioc_match',
                    result_data TEXT NOT NULL DEFAULT '',
                    enriched_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_eh_alert_org
                    ON enrichment_history (alert_id, org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit_alert(
        self,
        org_id: str,
        alert_id: str,
        alert_source: str,
        severity: str,
        raw_indicator: str,
        indicator_type: str,
    ) -> Dict[str, Any]:
        """Submit an alert for enrichment.

        If alert_id already exists for org, returns the existing record.
        """
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Valid: {sorted(_VALID_SEVERITIES)}")
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(
                f"Invalid indicator_type '{indicator_type}'. Valid: {sorted(_VALID_INDICATOR_TYPES)}"
            )

        # Check for existing alert
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT * FROM enriched_alerts WHERE alert_id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
        if existing:
            return self._row(existing)

        record_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO enriched_alerts
                        (id, org_id, alert_id, alert_source, severity, raw_indicator,
                         indicator_type, enrichment_status, threat_context, asset_context,
                         ioc_matches, confidence_score, risk_score, enriched_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record_id, org_id, alert_id, alert_source, severity, raw_indicator,
                        indicator_type, "pending", "", "", 0, 0.0, 0.0, None, now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM enriched_alerts WHERE id = ?", (record_id,)
            ).fetchone()
        return self._row(row)

    def enrich_alert(
        self,
        alert_id: str,
        org_id: str,
        source_name: str,
        result_type: str,
        result_data: str,
        ioc_matches: int = 0,
        confidence_score: float = 0.0,
    ) -> Dict[str, Any]:
        """Record enrichment result for an alert.

        Updates: enrichment_status=enriched, ioc_matches+=ioc_matches,
        confidence_score = max(existing, new), risk_score = confidence * severity_multiplier * 10.
        Also increments success_count on the matching source.
        """
        if result_type not in _VALID_RESULT_TYPES:
            raise ValueError(
                f"Invalid result_type '{result_type}'. Valid: {sorted(_VALID_RESULT_TYPES)}"
            )

        now = self._now()
        hist_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                # Fetch current alert state
                row = conn.execute(
                    "SELECT * FROM enriched_alerts WHERE alert_id = ? AND org_id = ?",
                    (alert_id, org_id),
                ).fetchone()
                if row is None:
                    raise KeyError(f"Alert '{alert_id}' not found for org '{org_id}'")

                current = self._row(row)
                new_ioc = current["ioc_matches"] + ioc_matches
                new_confidence = max(float(current["confidence_score"]), float(confidence_score))
                multiplier = _SEVERITY_MULTIPLIER.get(current["severity"], 0.5)
                new_risk = new_confidence * multiplier * 10.0

                conn.execute(
                    """
                    UPDATE enriched_alerts
                    SET enrichment_status = 'enriched',
                        ioc_matches = ?,
                        confidence_score = ?,
                        risk_score = ?,
                        enriched_at = ?
                    WHERE alert_id = ? AND org_id = ?
                    """,
                    (new_ioc, new_confidence, new_risk, now, alert_id, org_id),
                )

                # Insert enrichment history record
                conn.execute(
                    """
                    INSERT INTO enrichment_history
                        (id, alert_id, org_id, source_name, result_type, result_data, enriched_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (hist_id, alert_id, org_id, source_name, result_type, result_data, now),
                )

                # Increment source success_count
                conn.execute(
                    """
                    UPDATE enrichment_sources
                    SET success_count = success_count + 1, last_used = ?
                    WHERE org_id = ? AND source_name = ?
                    """,
                    (now, org_id, source_name),
                )

        with self._conn() as conn:
            updated = conn.execute(
                "SELECT * FROM enriched_alerts WHERE alert_id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
        return self._row(updated)

    def mark_failed(
        self,
        alert_id: str,
        org_id: str,
        source_name: str,
        error_msg: str,
    ) -> Dict[str, Any]:
        """Mark enrichment as failed for an alert from a specific source."""
        now = self._now()
        hist_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM enriched_alerts WHERE alert_id = ? AND org_id = ?",
                    (alert_id, org_id),
                ).fetchone()
                if row is None:
                    raise KeyError(f"Alert '{alert_id}' not found for org '{org_id}'")

                conn.execute(
                    """
                    UPDATE enriched_alerts
                    SET enrichment_status = 'failed'
                    WHERE alert_id = ? AND org_id = ?
                    """,
                    (alert_id, org_id),
                )

                conn.execute(
                    """
                    INSERT INTO enrichment_history
                        (id, alert_id, org_id, source_name, result_type, result_data, enriched_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (hist_id, alert_id, org_id, source_name, "error", error_msg, now),
                )

                # Increment source error_count
                conn.execute(
                    """
                    UPDATE enrichment_sources
                    SET error_count = error_count + 1, last_used = ?
                    WHERE org_id = ? AND source_name = ?
                    """,
                    (now, org_id, source_name),
                )

        with self._conn() as conn:
            updated = conn.execute(
                "SELECT * FROM enriched_alerts WHERE alert_id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
        return self._row(updated)

    def add_context(
        self,
        alert_id: str,
        org_id: str,
        threat_context: str = "",
        asset_context: str = "",
    ) -> Dict[str, Any]:
        """Update threat_context and asset_context (non-empty values only)."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM enriched_alerts WHERE alert_id = ? AND org_id = ?",
                    (alert_id, org_id),
                ).fetchone()
                if row is None:
                    raise KeyError(f"Alert '{alert_id}' not found for org '{org_id}'")

                current = self._row(row)
                new_threat = threat_context if threat_context else current["threat_context"]
                new_asset = asset_context if asset_context else current["asset_context"]

                conn.execute(
                    """
                    UPDATE enriched_alerts
                    SET threat_context = ?, asset_context = ?
                    WHERE alert_id = ? AND org_id = ?
                    """,
                    (new_threat, new_asset, alert_id, org_id),
                )

        with self._conn() as conn:
            updated = conn.execute(
                "SELECT * FROM enriched_alerts WHERE alert_id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
        return self._row(updated)

    def register_source(
        self,
        org_id: str,
        source_name: str,
        source_type: str,
        priority: int,
        api_key: str = "",
    ) -> Dict[str, Any]:
        """Register an enrichment source.

        api_key_hash = SHA-256(api_key) if api_key else ''.
        """
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(
                f"Invalid source_type '{source_type}'. Valid: {sorted(_VALID_SOURCE_TYPES)}"
            )

        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest() if api_key else ""
        source_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO enrichment_sources
                        (id, org_id, source_name, source_type, priority, api_key_hash,
                         enabled, last_used, success_count, error_count, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (source_id, org_id, source_name, source_type, priority, api_key_hash,
                     1, None, 0, 0, now),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM enrichment_sources WHERE id = ?", (source_id,)
            ).fetchone()
        return self._row(row)

    def toggle_source(self, source_id: str, org_id: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable an enrichment source."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM enrichment_sources WHERE id = ? AND org_id = ?",
                    (source_id, org_id),
                ).fetchone()
                if row is None:
                    raise KeyError(f"Source '{source_id}' not found for org '{org_id}'")

                conn.execute(
                    "UPDATE enrichment_sources SET enabled = ? WHERE id = ? AND org_id = ?",
                    (1 if enabled else 0, source_id, org_id),
                )

        with self._conn() as conn:
            updated = conn.execute(
                "SELECT * FROM enrichment_sources WHERE id = ?", (source_id,)
            ).fetchone()
        return self._row(updated)

    def get_enrichment_queue(self, org_id: str) -> List[Dict[str, Any]]:
        """Return pending alerts ordered by severity (critical first), then created_at."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM enriched_alerts
                WHERE org_id = ? AND enrichment_status = 'pending'
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high'     THEN 2
                        WHEN 'medium'   THEN 3
                        WHEN 'low'      THEN 4
                        ELSE 5
                    END,
                    created_at ASC
                """,
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_alert_detail(self, alert_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return enriched alert record plus enrichment history."""
        with self._conn() as conn:
            alert_row = conn.execute(
                "SELECT * FROM enriched_alerts WHERE alert_id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
            if alert_row is None:
                return None

            history_rows = conn.execute(
                """
                SELECT * FROM enrichment_history
                WHERE alert_id = ? AND org_id = ?
                ORDER BY enriched_at ASC
                """,
                (alert_id, org_id),
            ).fetchall()

        alert = self._row(alert_row)
        alert["history"] = [self._row(r) for r in history_rows]
        return alert

    def get_enrichment_summary(self, org_id: str) -> Dict[str, Any]:
        """Return summary stats: total, by_status, by_severity, avg_confidence, avg_risk_score, top_sources."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM enriched_alerts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            status_rows = conn.execute(
                """
                SELECT enrichment_status, COUNT(*) as cnt
                FROM enriched_alerts WHERE org_id = ?
                GROUP BY enrichment_status
                """,
                (org_id,),
            ).fetchall()
            by_status = {r["enrichment_status"]: r["cnt"] for r in status_rows}

            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM enriched_alerts WHERE org_id = ?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            agg = conn.execute(
                """
                SELECT AVG(confidence_score) as avg_conf, AVG(risk_score) as avg_risk
                FROM enriched_alerts WHERE org_id = ?
                """,
                (org_id,),
            ).fetchone()
            avg_confidence = round(float(agg["avg_conf"] or 0.0), 4)
            avg_risk_score = round(float(agg["avg_risk"] or 0.0), 4)

            top_sources_rows = conn.execute(
                """
                SELECT source_name, success_count, error_count
                FROM enrichment_sources
                WHERE org_id = ?
                ORDER BY success_count DESC
                LIMIT 5
                """,
                (org_id,),
            ).fetchall()
            top_sources = [self._row(r) for r in top_sources_rows]

        return {
            "total": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "avg_confidence": avg_confidence,
            "avg_risk_score": avg_risk_score,
            "top_sources": top_sources,
        }

    def get_high_risk_alerts(self, org_id: str, min_risk: float = 7.0) -> List[Dict[str, Any]]:
        """Return enriched alerts with risk_score >= min_risk, highest risk first."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM enriched_alerts
                WHERE org_id = ? AND risk_score >= ?
                ORDER BY risk_score DESC
                """,
                (org_id, min_risk),
            ).fetchall()
        return [self._row(r) for r in rows]
