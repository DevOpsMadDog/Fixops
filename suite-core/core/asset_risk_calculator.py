"""Asset Risk Calculator — ALDECI.

Computes weighted risk scores for registered assets across four risk dimensions:
vulnerability, threat intelligence, exposure, and compliance.

Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "asset_risk.db"
)

# Composite score weights — must sum to 1.0
_SCORE_WEIGHTS: Dict[str, float] = {
    "vuln_score": 0.35,
    "threat_score": 0.25,
    "exposure_score": 0.20,
    "compliance_score": 0.20,
}

_VALID_ASSET_TYPES = {
    "server", "workstation", "network_device", "cloud_instance",
    "database", "application", "iot",
}
_VALID_CRITICALITIES = {"critical", "high", "medium", "low"}
_VALID_EXPOSURES = {"internet_facing", "internal", "air_gapped"}
_VALID_FACTOR_TYPES = {
    "vulnerability", "misconfiguration", "exposure", "threat_intel", "compliance",
}
_VALID_RISK_LEVELS = ("critical", "high", "medium", "low", "minimal")


def _score_to_risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


class AssetRiskCalculator:
    """SQLite WAL-backed asset risk scoring engine.

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
                CREATE TABLE IF NOT EXISTS asset_profiles (
                    asset_id    TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    asset_type  TEXT NOT NULL DEFAULT 'server',
                    criticality TEXT NOT NULL DEFAULT 'medium',
                    exposure    TEXT NOT NULL DEFAULT 'internal',
                    owner       TEXT NOT NULL DEFAULT '',
                    tags        TEXT NOT NULL DEFAULT '[]',
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ap_org
                    ON asset_profiles (org_id);

                CREATE TABLE IF NOT EXISTS risk_scores (
                    score_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    asset_id        TEXT NOT NULL,
                    calculated_at   DATETIME NOT NULL,
                    base_score      REAL NOT NULL DEFAULT 0.0,
                    vuln_score      REAL NOT NULL DEFAULT 0.0,
                    threat_score    REAL NOT NULL DEFAULT 0.0,
                    exposure_score  REAL NOT NULL DEFAULT 0.0,
                    compliance_score REAL NOT NULL DEFAULT 0.0,
                    composite_score REAL NOT NULL DEFAULT 0.0,
                    risk_level      TEXT NOT NULL DEFAULT 'minimal',
                    score_version   INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_rs_org_asset
                    ON risk_scores (org_id, asset_id, calculated_at DESC);

                CREATE TABLE IF NOT EXISTS risk_factors (
                    factor_id   TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    asset_id    TEXT NOT NULL,
                    factor_type TEXT NOT NULL DEFAULT 'vulnerability',
                    factor_name TEXT NOT NULL,
                    impact      REAL NOT NULL DEFAULT 0.0,
                    description TEXT NOT NULL DEFAULT '',
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rf_org_asset
                    ON risk_factors (org_id, asset_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Asset CRUD
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new asset profile. Returns the created record."""
        asset_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        asset_type = data.get("asset_type", "server")
        criticality = data.get("criticality", "medium")
        exposure = data.get("exposure", "internal")

        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(f"Invalid asset_type: {asset_type}. Must be one of {_VALID_ASSET_TYPES}")
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(f"Invalid criticality: {criticality}.")
        if exposure not in _VALID_EXPOSURES:
            raise ValueError(f"Invalid exposure: {exposure}.")

        tags = json.dumps(data.get("tags", []))
        name = data.get("name", "")
        if not name:
            raise ValueError("Asset name is required.")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO asset_profiles
                        (asset_id, org_id, name, asset_type, criticality, exposure,
                         owner, tags, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        asset_id, org_id, name, asset_type, criticality, exposure,
                        data.get("owner", ""), tags, now,
                    ),
                )
        return {
            "asset_id": asset_id,
            "org_id": org_id,
            "name": name,
            "asset_type": asset_type,
            "criticality": criticality,
            "exposure": exposure,
            "owner": data.get("owner", ""),
            "tags": data.get("tags", []),
            "created_at": now,
        }

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assets for an org with optional filters."""
        query = "SELECT * FROM asset_profiles WHERE org_id=?"
        params: list = [org_id]
        if asset_type:
            query += " AND asset_type=?"
            params.append(asset_type)
        if criticality:
            query += " AND criticality=?"
            params.append(criticality)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = self._row(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            result.append(d)
        return result

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single asset by ID, scoped to org_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM asset_profiles WHERE org_id=? AND asset_id=?",
                (org_id, asset_id),
            ).fetchone()
        if not row:
            return None
        d = self._row(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return d

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def calculate_risk(
        self, org_id: str, asset_id: str, factors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate a composite risk score from provided factor scores.

        factors: list of dicts with keys: vuln_score, threat_score,
                 exposure_score, compliance_score (all 0-100).
        Returns the saved risk_score record.
        """
        asset = self.get_asset(org_id, asset_id)
        if not asset:
            raise ValueError(f"Asset {asset_id} not found for org {org_id}")

        # Aggregate factor scores — average per dimension if multiple factors provided
        def _avg(key: str) -> float:
            vals = [float(f.get(key, 0.0)) for f in factors if key in f]
            return sum(vals) / len(vals) if vals else 0.0

        vuln_score = min(100.0, max(0.0, _avg("vuln_score")))
        threat_score = min(100.0, max(0.0, _avg("threat_score")))
        exposure_score = min(100.0, max(0.0, _avg("exposure_score")))
        compliance_score = min(100.0, max(0.0, _avg("compliance_score")))

        # Base score: criticality modifier
        criticality_weights = {
            "critical": 1.20, "high": 1.10, "medium": 1.00,
            "low": 0.90,
        }
        base_score = criticality_weights.get(asset["criticality"], 1.0) * 50.0
        base_score = min(100.0, base_score)

        composite_score = round(
            vuln_score * _SCORE_WEIGHTS["vuln_score"]
            + threat_score * _SCORE_WEIGHTS["threat_score"]
            + exposure_score * _SCORE_WEIGHTS["exposure_score"]
            + compliance_score * _SCORE_WEIGHTS["compliance_score"],
            2,
        )
        risk_level = _score_to_risk_level(composite_score)

        score_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO risk_scores
                        (score_id, org_id, asset_id, calculated_at, base_score,
                         vuln_score, threat_score, exposure_score, compliance_score,
                         composite_score, risk_level, score_version)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,1)
                    """,
                    (
                        score_id, org_id, asset_id, now, base_score,
                        vuln_score, threat_score, exposure_score, compliance_score,
                        composite_score, risk_level,
                    ),
                )
        return {
            "score_id": score_id,
            "org_id": org_id,
            "asset_id": asset_id,
            "calculated_at": now,
            "base_score": base_score,
            "vuln_score": vuln_score,
            "threat_score": threat_score,
            "exposure_score": exposure_score,
            "compliance_score": compliance_score,
            "composite_score": composite_score,
            "risk_level": risk_level,
            "score_version": 1,
        }

    def get_latest_score(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Return the most recent risk score for an asset."""
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM risk_scores
                WHERE org_id=? AND asset_id=?
                ORDER BY calculated_at DESC LIMIT 1
                """,
                (org_id, asset_id),
            ).fetchone()
        return self._row(row) if row else None

    def list_scores(
        self, org_id: str, risk_level: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return latest risk score per asset for an org, with optional risk_level filter."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT rs.* FROM risk_scores rs
                INNER JOIN (
                    SELECT asset_id, MAX(calculated_at) AS max_at
                    FROM risk_scores WHERE org_id=?
                    GROUP BY asset_id
                ) latest ON rs.asset_id=latest.asset_id AND rs.calculated_at=latest.max_at
                WHERE rs.org_id=?
                ORDER BY rs.composite_score DESC
                """,
                (org_id, org_id),
            ).fetchall()
        result = [self._row(r) for r in rows]
        if risk_level:
            result = [r for r in result if r["risk_level"] == risk_level]
        return result

    # ------------------------------------------------------------------
    # Risk factors
    # ------------------------------------------------------------------

    def add_risk_factor(
        self, org_id: str, asset_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a risk factor for an asset."""
        asset = self.get_asset(org_id, asset_id)
        if not asset:
            raise ValueError(f"Asset {asset_id} not found for org {org_id}")

        factor_type = data.get("factor_type", "vulnerability")
        if factor_type not in _VALID_FACTOR_TYPES:
            raise ValueError(f"Invalid factor_type: {factor_type}")

        factor_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO risk_factors
                        (factor_id, org_id, asset_id, factor_type, factor_name,
                         impact, description, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        factor_id, org_id, asset_id, factor_type,
                        data.get("factor_name", ""),
                        float(data.get("impact", 0.0)),
                        data.get("description", ""),
                        now,
                    ),
                )
        return {
            "factor_id": factor_id,
            "org_id": org_id,
            "asset_id": asset_id,
            "factor_type": factor_type,
            "factor_name": data.get("factor_name", ""),
            "impact": float(data.get("impact", 0.0)),
            "description": data.get("description", ""),
            "created_at": now,
        }

    def list_risk_factors(self, org_id: str, asset_id: str) -> List[Dict[str, Any]]:
        """List all risk factors for a specific asset."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM risk_factors
                WHERE org_id=? AND asset_id=?
                ORDER BY created_at DESC
                """,
                (org_id, asset_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_risk_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate risk statistics for an org."""
        assets = self.list_assets(org_id)
        total_assets = len(assets)

        # Build asset_id -> name map
        id_to_name: Dict[str, str] = {a["asset_id"]: a["name"] for a in assets}

        scores = self.list_scores(org_id)

        by_risk_level: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0,
        }
        composite_scores: List[float] = []
        internet_facing_critical = 0

        for score in scores:
            rl = score.get("risk_level", "minimal")
            by_risk_level[rl] = by_risk_level.get(rl, 0) + 1
            composite_scores.append(score["composite_score"])

        # internet_facing + critical criticality assets with high/critical scores
        asset_map = {a["asset_id"]: a for a in assets}
        for score in scores:
            aid = score["asset_id"]
            asset = asset_map.get(aid, {})
            if (
                asset.get("exposure") == "internet_facing"
                and asset.get("criticality") in ("critical", "high")
                and score["risk_level"] in ("critical", "high")
            ):
                internet_facing_critical += 1

        avg_composite = round(
            sum(composite_scores) / len(composite_scores), 2
        ) if composite_scores else 0.0

        # Top 5 highest-scoring assets by name
        top_scores = sorted(scores, key=lambda s: s["composite_score"], reverse=True)[:5]
        critical_assets = [
            id_to_name.get(s["asset_id"], s["asset_id"]) for s in top_scores
        ]

        return {
            "total_assets": total_assets,
            "by_risk_level": by_risk_level,
            "avg_composite_score": avg_composite,
            "critical_assets": critical_assets,
            "internet_facing_critical": internet_facing_critical,
        }
