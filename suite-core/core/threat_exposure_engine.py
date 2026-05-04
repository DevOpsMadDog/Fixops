"""Threat Exposure Engine — ALDECI.

Correlates threat intelligence with asset exposure to compute actual threat
exposure scores per asset, with history tracking and top-exposed reporting.

Capabilities:
  - Asset registry with type and exposure tracking
  - Threat correlation with severity-weighted exposure scoring
  - Exposure history for trend analysis
  - Stats: totals, by_level, avg_exposure, critical count

Compliance: NIST CSF ID.RA, CVSS, MITRE ATT&CK
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_ASSET_TYPES = {"host", "application", "network", "cloud", "user", "api"}
_VALID_EXPOSURE_LEVELS = {"critical", "high", "medium", "low", "none"}
_VALID_THREAT_TYPES = {"malware", "apt", "ransomware", "phishing", "exploit", "insider"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 40.0,
    "high": 30.0,
    "medium": 20.0,
    "low": 10.0,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _exposure_level_from_score(score: float) -> str:
    if score >= 80.0:
        return "critical"
    if score >= 60.0:
        return "high"
    if score >= 40.0:
        return "medium"
    if score >= 20.0:
        return "low"
    return "none"


class ThreatExposureEngine:
    """SQLite WAL-backed Threat Exposure engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/threat_exposure.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "threat_exposure.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS exposure_records (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    asset_id        TEXT NOT NULL,
                    asset_name      TEXT NOT NULL,
                    asset_type      TEXT NOT NULL DEFAULT 'host',
                    exposure_score  REAL NOT NULL DEFAULT 0.0,
                    exposure_level  TEXT NOT NULL DEFAULT 'none',
                    threat_count    INTEGER NOT NULL DEFAULT 0,
                    vuln_count      INTEGER NOT NULL DEFAULT 0,
                    last_assessed   TEXT,
                    created_at      TEXT NOT NULL,
                    UNIQUE(org_id, asset_id)
                );

                CREATE INDEX IF NOT EXISTS idx_exposure_records_org
                    ON exposure_records (org_id, asset_type, exposure_level, exposure_score DESC);

                CREATE TABLE IF NOT EXISTS threat_correlations (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    asset_id     TEXT NOT NULL,
                    threat_id    TEXT NOT NULL,
                    threat_type  TEXT NOT NULL,
                    confidence   REAL NOT NULL DEFAULT 50.0,
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    ioc_matched  INTEGER NOT NULL DEFAULT 0,
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_threat_correlations_org
                    ON threat_correlations (org_id, asset_id, threat_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS exposure_history (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    asset_id        TEXT NOT NULL,
                    exposure_score  REAL NOT NULL,
                    exposure_level  TEXT NOT NULL,
                    recorded_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_exposure_history_org
                    ON exposure_history (org_id, asset_id, recorded_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new asset for exposure tracking."""
        asset_id = (data.get("asset_id") or "").strip()
        if not asset_id:
            raise ValueError("asset_id is required.")

        asset_name = (data.get("asset_name") or "").strip()
        if not asset_name:
            raise ValueError("asset_name is required.")

        asset_type = data.get("asset_type", "host")
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(
                f"Invalid asset_type: '{asset_type}'. "
                f"Must be one of {sorted(_VALID_ASSET_TYPES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "exposure_score": 0.0,
            "exposure_level": "none",
            "threat_count": 0,
            "vuln_count": int(data.get("vuln_count", 0)),
            "last_assessed": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO exposure_records
                       (id, org_id, asset_id, asset_name, asset_type,
                        exposure_score, exposure_level, threat_count, vuln_count,
                        last_assessed, created_at)
                       VALUES (:id, :org_id, :asset_id, :asset_name, :asset_type,
                               :exposure_score, :exposure_level, :threat_count, :vuln_count,
                               :last_assessed, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_exposure", "org_id": org_id, "source_engine": "threat_exposure"})
            except Exception:
                pass

        return record

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        exposure_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assets with optional type and exposure_level filters."""
        sql = "SELECT * FROM exposure_records WHERE org_id = ?"
        params: list = [org_id]
        if asset_type:
            sql += " AND asset_type = ?"
            params.append(asset_type)
        if exposure_level:
            sql += " AND exposure_level = ?"
            params.append(exposure_level)
        sql += " ORDER BY exposure_score DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single asset record."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM exposure_records WHERE org_id = ? AND asset_id = ?",
                (org_id, asset_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Threat Correlations
    # ------------------------------------------------------------------

    def correlate_threat(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate a threat with an asset and increment threat_count."""
        asset_id = (data.get("asset_id") or "").strip()
        if not asset_id:
            raise ValueError("asset_id is required.")

        asset = self.get_asset(org_id, asset_id)
        if not asset:
            raise KeyError(f"Asset '{asset_id}' not found for org '{org_id}'.")

        threat_type = data.get("threat_type", "exploit")
        if threat_type not in _VALID_THREAT_TYPES:
            raise ValueError(
                f"Invalid threat_type: '{threat_type}'. "
                f"Must be one of {sorted(_VALID_THREAT_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: '{severity}'. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        confidence = float(data.get("confidence", 50.0))
        confidence = max(0.0, min(100.0, confidence))

        ioc_matched = bool(data.get("ioc_matched", False))
        threat_id = data.get("threat_id") or str(uuid.uuid4())

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "threat_id": threat_id,
            "threat_type": threat_type,
            "confidence": confidence,
            "severity": severity,
            "ioc_matched": 1 if ioc_matched else 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO threat_correlations
                       (id, org_id, asset_id, threat_id, threat_type,
                        confidence, severity, ioc_matched, created_at)
                       VALUES (:id, :org_id, :asset_id, :threat_id, :threat_type,
                               :confidence, :severity, :ioc_matched, :created_at)""",
                    record,
                )
                # Increment threat_count
                conn.execute(
                    "UPDATE exposure_records SET threat_count = threat_count + 1 "
                    "WHERE org_id = ? AND asset_id = ?",
                    (org_id, asset_id),
                )
        return record

    def list_correlations(
        self,
        org_id: str,
        asset_id: Optional[str] = None,
        threat_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threat correlations with optional filters."""
        sql = "SELECT * FROM threat_correlations WHERE org_id = ?"
        params: list = [org_id]
        if asset_id:
            sql += " AND asset_id = ?"
            params.append(asset_id)
        if threat_type:
            sql += " AND threat_type = ?"
            params.append(threat_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Exposure Calculation
    # ------------------------------------------------------------------

    def calculate_exposure(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Recalculate exposure score from all correlations and save history."""
        asset = self.get_asset(org_id, asset_id)
        if not asset:
            return None

        with self._conn() as conn:
            corr_rows = conn.execute(
                "SELECT confidence, severity FROM threat_correlations "
                "WHERE org_id = ? AND asset_id = ?",
                (org_id, asset_id),
            ).fetchall()

        # Weighted sum: each correlation adds (confidence/100) * severity_weight
        raw_score = sum(
            (row["confidence"] / 100.0) * _SEVERITY_WEIGHTS.get(row["severity"], 20.0)
            for row in corr_rows
        )
        exposure_score = max(0.0, min(100.0, raw_score))
        exposure_level = _exposure_level_from_score(exposure_score)
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE exposure_records
                       SET exposure_score = ?, exposure_level = ?, last_assessed = ?
                       WHERE org_id = ? AND asset_id = ?""",
                    (exposure_score, exposure_level, now, org_id, asset_id),
                )
                conn.execute(
                    """INSERT INTO exposure_history
                       (id, org_id, asset_id, exposure_score, exposure_level, recorded_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (str(uuid.uuid4()), org_id, asset_id, exposure_score, exposure_level, now),
                )

        updated = self.get_asset(org_id, asset_id)
        return updated

    # ------------------------------------------------------------------
    # History & Top Exposed
    # ------------------------------------------------------------------

    def get_exposure_history(
        self, org_id: str, asset_id: str, limit: int = 30
    ) -> List[Dict[str, Any]]:
        """Return exposure history for an asset, ordered by recorded_at DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM exposure_history WHERE org_id = ? AND asset_id = ? "
                "ORDER BY recorded_at DESC LIMIT ?",
                (org_id, asset_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_top_exposed_assets(
        self, org_id: str, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Return assets ordered by exposure_score DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM exposure_records WHERE org_id = ? "
                "ORDER BY exposure_score DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_exposure_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated exposure statistics for an org.

        Collapsed from 6 sequential SELECTs into 2 queries:
        one aggregating CTE over exposure_records, one COUNT on threat_correlations.
        """
        today_prefix = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._conn() as conn:
            # Single pass: total, avg, critical count, assessed-today, and per-level counts
            agg_row = conn.execute(
                """
                SELECT
                    COUNT(*)                                                AS total_assets,
                    AVG(exposure_score)                                     AS avg_score,
                    SUM(CASE WHEN exposure_level = 'critical' THEN 1 ELSE 0 END) AS critical_assets,
                    SUM(CASE WHEN last_assessed LIKE ? THEN 1 ELSE 0 END)  AS assessed_today
                FROM exposure_records
                WHERE org_id = ?
                """,
                (f"{today_prefix}%", org_id),
            ).fetchone()

            level_rows = conn.execute(
                "SELECT exposure_level, COUNT(*) AS cnt FROM exposure_records "
                "WHERE org_id = ? GROUP BY exposure_level",
                (org_id,),
            ).fetchall()

            total_correlations = conn.execute(
                "SELECT COUNT(*) FROM threat_correlations WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

        by_level = {r["exposure_level"]: r["cnt"] for r in level_rows}
        avg_score_raw = agg_row["avg_score"]
        avg_exposure_score = round(avg_score_raw, 4) if avg_score_raw is not None else 0.0

        return {
            "total_assets": agg_row["total_assets"],
            "by_level": by_level,
            "avg_exposure_score": avg_exposure_score,
            "critical_assets": agg_row["critical_assets"],
            "total_correlations": total_correlations,
            "assessed_today": agg_row["assessed_today"],
        }
