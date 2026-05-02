"""Threat Score Engine — ALDECI.

Aggregates multi-source security signals into composite asset threat scores.
Supports weighted averaging across vuln scanners, threat intel, SIEM, UBA,
and network sources.

Compliance: CVSS v3.1, NIST SP 800-115, MITRE ATT&CK risk quantification
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_score.db"
)

_VALID_ASSET_TYPES = {"host", "application", "user", "network", "cloud"}
_VALID_SIGNAL_SOURCES = {
    "vuln_scanner", "threat_intel", "siem", "uba", "network"
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_level(score: float) -> str:
    """Map numeric score (0-100) to risk level string."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


class ThreatScoreEngine:
    """SQLite WAL-backed composite threat scoring engine.

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
                CREATE TABLE IF NOT EXISTS threat_scores (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    asset_id            TEXT NOT NULL,
                    asset_type          TEXT NOT NULL DEFAULT 'host',
                    score               REAL NOT NULL DEFAULT 0.0,
                    risk_level          TEXT NOT NULL DEFAULT 'info',
                    contributing_factors TEXT NOT NULL DEFAULT '[]',
                    score_version       INTEGER NOT NULL DEFAULT 1,
                    calculated_at       TEXT NOT NULL,
                    UNIQUE(org_id, asset_id)
                );

                CREATE TABLE IF NOT EXISTS score_signals (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    asset_id        TEXT NOT NULL,
                    signal_source   TEXT NOT NULL,
                    signal_type     TEXT NOT NULL DEFAULT '',
                    signal_value    REAL NOT NULL DEFAULT 0.0,
                    signal_weight   REAL NOT NULL DEFAULT 1.0,
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS score_history (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    asset_id    TEXT NOT NULL,
                    score       REAL NOT NULL,
                    risk_level  TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for f in ("contributing_factors",):
            if f in d and isinstance(d[f], str):
                try:
                    d[f] = json.loads(d[f])
                except Exception:
                    d[f] = []
        return d

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------

    def ingest_signal(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a security signal for an asset."""
        asset_id = data.get("asset_id", "").strip()
        if not asset_id:
            raise ValueError("asset_id is required")
        signal_source = data.get("signal_source", "").strip()
        if signal_source not in _VALID_SIGNAL_SOURCES:
            raise ValueError(
                f"signal_source must be one of {sorted(_VALID_SIGNAL_SOURCES)}"
            )
        try:
            signal_value = float(data["signal_value"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("signal_value must be a float between 0 and 100")

        signal_weight = float(data.get("signal_weight", 1.0))
        now = _now_iso()
        rec_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO score_signals
                        (id, org_id, asset_id, signal_source, signal_type,
                         signal_value, signal_weight, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        rec_id,
                        org_id,
                        asset_id,
                        signal_source,
                        data.get("signal_type", ""),
                        signal_value,
                        signal_weight,
                        now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM score_signals WHERE id = ?", (rec_id,)
            ).fetchone()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_score", "org_id": org_id, "source_engine": "threat_score"})
            except Exception:
                pass

        return dict(row)

    # ------------------------------------------------------------------
    # Score calculation
    # ------------------------------------------------------------------

    def calculate_score(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Calculate weighted composite threat score from last 30 signals."""
        with self._conn() as conn:
            signals = conn.execute(
                """
                SELECT signal_source, signal_type, signal_value, signal_weight
                FROM score_signals
                WHERE org_id = ? AND asset_id = ?
                ORDER BY created_at DESC
                LIMIT 30
                """,
                (org_id, asset_id),
            ).fetchall()

            # Determine asset_type from existing score record or default
            existing = conn.execute(
                "SELECT asset_type, score_version FROM threat_scores WHERE org_id = ? AND asset_id = ?",
                (org_id, asset_id),
            ).fetchone()

        if not signals:
            # No signals — score stays 0
            weighted_score = 0.0
            contributing = []
        else:
            total_weight = sum(s["signal_weight"] for s in signals)
            if total_weight == 0:
                weighted_score = 0.0
            else:
                weighted_score = sum(
                    s["signal_value"] * s["signal_weight"] for s in signals
                ) / total_weight
            weighted_score = round(min(max(weighted_score, 0.0), 100.0), 4)
            contributing = [
                {
                    "factor": f"{s['signal_source']}:{s['signal_type']}",
                    "value": s["signal_value"],
                    "weight": s["signal_weight"],
                }
                for s in signals
            ]

        level = _risk_level(weighted_score)
        now = _now_iso()
        score_id = str(uuid.uuid4())
        asset_type = existing["asset_type"] if existing else "host"
        version = (existing["score_version"] + 1) if existing else 1

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO threat_scores
                        (id, org_id, asset_id, asset_type, score, risk_level,
                         contributing_factors, score_version, calculated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(org_id, asset_id) DO UPDATE SET
                        score = excluded.score,
                        risk_level = excluded.risk_level,
                        contributing_factors = excluded.contributing_factors,
                        score_version = excluded.score_version,
                        calculated_at = excluded.calculated_at
                    """,
                    (
                        score_id,
                        org_id,
                        asset_id,
                        asset_type,
                        weighted_score,
                        level,
                        json.dumps(contributing),
                        version,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO score_history
                        (id, org_id, asset_id, score, risk_level, recorded_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (str(uuid.uuid4()), org_id, asset_id, weighted_score, level, now),
                )

        return self.get_score(org_id, asset_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_score(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Return latest score record or None if not yet calculated."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM threat_scores WHERE org_id = ? AND asset_id = ?",
                (org_id, asset_id),
            ).fetchone()
        return self._row(row) if row else None

    def list_scores(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all scores with optional filters."""
        query = "SELECT * FROM threat_scores WHERE org_id = ?"
        params: list = [org_id]
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)
        query += " ORDER BY score DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_score_history(
        self,
        org_id: str,
        asset_id: str,
        limit: int = 30,
    ) -> List[Dict[str, Any]]:
        """Return score history ordered by most recent first."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM score_history
                WHERE org_id = ? AND asset_id = ?
                ORDER BY recorded_at DESC
                LIMIT ?
                """,
                (org_id, asset_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_top_threats(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Return top-scoring assets ordered by score descending."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM threat_scores
                WHERE org_id = ?
                ORDER BY score DESC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_threat_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated threat score statistics for an org."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        with self._conn() as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM threat_scores WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            by_risk_rows = conn.execute(
                """
                SELECT risk_level, COUNT(*) AS cnt
                FROM threat_scores WHERE org_id = ?
                GROUP BY risk_level
                """,
                (org_id,),
            ).fetchall()
            by_risk_level = {r["risk_level"]: r["cnt"] for r in by_risk_rows}

            avg_row = conn.execute(
                "SELECT AVG(score) FROM threat_scores WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_score = round(avg_row[0], 4) if avg_row[0] is not None else 0.0

            critical_count = conn.execute(
                "SELECT COUNT(*) FROM threat_scores WHERE org_id = ? AND risk_level = 'critical'",
                (org_id,),
            ).fetchone()[0]

            assets_scored_24h = conn.execute(
                "SELECT COUNT(*) FROM threat_scores WHERE org_id = ? AND calculated_at >= ?",
                (org_id, cutoff),
            ).fetchone()[0]

        return {
            "total_assets": total_assets,
            "by_risk_level": by_risk_level,
            "avg_score": avg_score,
            "critical_count": critical_count,
            "assets_scored_24h": assets_scored_24h,
        }
