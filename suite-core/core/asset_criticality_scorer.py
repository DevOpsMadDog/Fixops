"""
Asset Criticality Scorer — ALDECI.

Scores asset business criticality for risk prioritization.
Multi-tenant via org_id. Thread-safe via RLock. SQLite WAL mode.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

# Base scores by asset type (out of 10)
_ASSET_TYPE_BASE = {
    "server": 5.0,
    "database": 7.0,
    "application": 5.0,
    "network": 6.0,
    "endpoint": 3.0,
    "cloud": 5.0,
}

# Data classification multipliers
_DATA_CLASSIFICATION_MULT = {
    "public": 1.0,
    "internal": 1.2,
    "confidential": 1.5,
    "secret": 1.8,
}

# Criticality tiers
_CRITICALITY_TIERS = [
    (8.0, "critical"),
    (6.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
]

_REGULATORY_FRAMEWORKS = {
    "pci-dss", "hipaa", "sox", "gdpr", "fedramp", "fisma", "iso27001", "nist"
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _criticality_tier(score: float) -> str:
    for threshold, tier in _CRITICALITY_TIERS:
        if score >= threshold:
            return tier
    return "low"


class AssetCriticalityScorer:
    """SQLite WAL-backed Asset Criticality Scorer.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = "") -> None:
        if not db_path:
            db_path = str(_DEFAULT_DB_DIR / "asset_criticality.db")
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    asset_name          TEXT NOT NULL,
                    asset_type          TEXT NOT NULL DEFAULT 'server',
                    business_owner      TEXT NOT NULL DEFAULT '',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    internet_facing     INTEGER NOT NULL DEFAULT 0,
                    regulatory_scope    TEXT NOT NULL DEFAULT '[]',
                    dependencies_count  INTEGER NOT NULL DEFAULT 0,
                    criticality_score   REAL NOT NULL DEFAULT 0.0,
                    criticality_tier    TEXT NOT NULL DEFAULT 'low',
                    created_at          DATETIME NOT NULL,
                    updated_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_assets_org_tier
                    ON assets (org_id, criticality_tier, criticality_score);

                CREATE INDEX IF NOT EXISTS idx_assets_org_internet
                    ON assets (org_id, internet_facing);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _compute_score(self, data: Dict[str, Any]) -> tuple[float, Dict[str, Any]]:
        """Compute criticality score and return (score, factors)."""
        import json

        asset_type = data.get("asset_type", "server")
        data_classification = data.get("data_classification", "internal")
        internet_facing = bool(data.get("internet_facing", False))
        regulatory_scope = data.get("regulatory_scope", [])
        if isinstance(regulatory_scope, str):
            try:
                regulatory_scope = json.loads(regulatory_scope)
            except Exception:
                regulatory_scope = []
        dependencies_count = int(data.get("dependencies_count", 0))

        if asset_type not in _ASSET_TYPE_BASE:
            raise ValueError(f"Invalid asset_type '{asset_type}'. Valid: {sorted(_ASSET_TYPE_BASE)}")
        if data_classification not in _DATA_CLASSIFICATION_MULT:
            raise ValueError(
                f"Invalid data_classification '{data_classification}'. "
                f"Valid: {sorted(_DATA_CLASSIFICATION_MULT)}"
            )

        base = _ASSET_TYPE_BASE[asset_type]
        dc_mult = _DATA_CLASSIFICATION_MULT[data_classification]

        # Apply data classification multiplier (scaled to stay near base range)
        score = base * dc_mult

        # Internet-facing bonus (+1.5)
        internet_bonus = 1.5 if internet_facing else 0.0
        score += internet_bonus

        # Regulatory scope bonus (up to +1.0)
        valid_reg = [r for r in regulatory_scope if r.lower() in _REGULATORY_FRAMEWORKS]
        reg_bonus = min(len(valid_reg) * 0.25, 1.0)
        score += reg_bonus

        # Dependencies factor (up to +0.5)
        dep_bonus = min(dependencies_count / 20.0, 0.5)
        score += dep_bonus

        # Clamp to [1, 10]
        score = max(1.0, min(10.0, round(score, 2)))

        factors = {
            "base_score": base,
            "data_classification_multiplier": dc_mult,
            "internet_facing_bonus": internet_bonus,
            "regulatory_bonus": reg_bonus,
            "dependencies_bonus": dep_bonus,
        }
        return score, factors

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new asset and compute its criticality score."""
        import json

        asset_type = data.get("asset_type", "server")
        data_classification = data.get("data_classification", "internal")
        internet_facing = bool(data.get("internet_facing", False))
        regulatory_scope = data.get("regulatory_scope", [])
        if isinstance(regulatory_scope, str):
            try:
                regulatory_scope = json.loads(regulatory_scope)
            except Exception:
                regulatory_scope = []

        score, factors = self._compute_score(data)
        tier = _criticality_tier(score)
        now_str = _now()

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_name": data.get("asset_name", ""),
            "asset_type": asset_type,
            "business_owner": data.get("business_owner", ""),
            "data_classification": data_classification,
            "internet_facing": int(internet_facing),
            "regulatory_scope": json.dumps(regulatory_scope),
            "dependencies_count": int(data.get("dependencies_count", 0)),
            "criticality_score": score,
            "criticality_tier": tier,
            "created_at": now_str,
            "updated_at": now_str,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO assets
                       (id, org_id, asset_name, asset_type, business_owner,
                        data_classification, internet_facing, regulatory_scope,
                        dependencies_count, criticality_score, criticality_tier,
                        created_at, updated_at)
                       VALUES (:id, :org_id, :asset_name, :asset_type, :business_owner,
                               :data_classification, :internet_facing, :regulatory_scope,
                               :dependencies_count, :criticality_score, :criticality_tier,
                               :created_at, :updated_at)""",
                    record,
                )

        result = dict(record)
        result["regulatory_scope"] = regulatory_scope
        result["internet_facing"] = internet_facing
        result["factors"] = factors
        return result

    def score_asset(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Recompute and return criticality score for an existing asset."""
        import json

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM assets WHERE id = ? AND org_id = ?",
                    (asset_id, org_id),
                ).fetchone()

        if row is None:
            raise ValueError(f"Asset '{asset_id}' not found for org '{org_id}'")

        asset = dict(row)
        reg_scope = asset.get("regulatory_scope", "[]")
        if isinstance(reg_scope, str):
            try:
                reg_scope = json.loads(reg_scope)
            except Exception:
                reg_scope = []
        asset["regulatory_scope"] = reg_scope

        score, factors = self._compute_score(asset)
        tier = _criticality_tier(score)

        # Update stored score
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE assets SET criticality_score=?, criticality_tier=?, updated_at=? WHERE id=? AND org_id=?",
                    (score, tier, _now(), asset_id, org_id),
                )

        return {
            "asset_id": asset_id,
            "asset_name": asset["asset_name"],
            "criticality_score": score,
            "criticality_tier": tier,
            "factors": factors,
        }

    def update_asset(self, org_id: str, asset_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update asset fields and recompute criticality score."""
        import json

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM assets WHERE id = ? AND org_id = ?",
                    (asset_id, org_id),
                ).fetchone()

        if row is None:
            raise ValueError(f"Asset '{asset_id}' not found for org '{org_id}'")

        asset = dict(row)
        # Parse stored regulatory_scope
        reg_scope = asset.get("regulatory_scope", "[]")
        if isinstance(reg_scope, str):
            try:
                asset["regulatory_scope"] = json.loads(reg_scope)
            except Exception:
                asset["regulatory_scope"] = []

        # Apply updates
        allowed_fields = {
            "asset_name", "asset_type", "business_owner",
            "data_classification", "internet_facing",
            "regulatory_scope", "dependencies_count",
        }
        for k, v in updates.items():
            if k in allowed_fields:
                asset[k] = v

        score, factors = self._compute_score(asset)
        tier = _criticality_tier(score)
        now_str = _now()

        reg_scope_list = asset.get("regulatory_scope", [])
        if isinstance(reg_scope_list, str):
            try:
                reg_scope_list = json.loads(reg_scope_list)
            except Exception:
                reg_scope_list = []

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE assets SET
                        asset_name=:asset_name, asset_type=:asset_type,
                        business_owner=:business_owner, data_classification=:data_classification,
                        internet_facing=:internet_facing, regulatory_scope=:regulatory_scope,
                        dependencies_count=:dependencies_count,
                        criticality_score=:criticality_score, criticality_tier=:criticality_tier,
                        updated_at=:updated_at
                       WHERE id=:id AND org_id=:org_id""",
                    {
                        "asset_name": asset.get("asset_name", ""),
                        "asset_type": asset.get("asset_type", "server"),
                        "business_owner": asset.get("business_owner", ""),
                        "data_classification": asset.get("data_classification", "internal"),
                        "internet_facing": int(bool(asset.get("internet_facing", False))),
                        "regulatory_scope": json.dumps(reg_scope_list),
                        "dependencies_count": int(asset.get("dependencies_count", 0)),
                        "criticality_score": score,
                        "criticality_tier": tier,
                        "updated_at": now_str,
                        "id": asset_id,
                        "org_id": org_id,
                    },
                )

        return {
            "asset_id": asset_id,
            "asset_name": asset.get("asset_name", ""),
            "criticality_score": score,
            "criticality_tier": tier,
            "factors": factors,
            "updated_at": now_str,
        }

    def list_assets(
        self,
        org_id: str,
        criticality_tier: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assets for an org, optionally filtered by criticality tier."""
        import json

        query = "SELECT * FROM assets WHERE org_id = ?"
        params: List[Any] = [org_id]
        if criticality_tier:
            query += " AND criticality_tier = ?"
            params.append(criticality_tier)
        query += " ORDER BY criticality_score DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            item = dict(row)
            reg_scope = item.get("regulatory_scope", "[]")
            if isinstance(reg_scope, str):
                try:
                    item["regulatory_scope"] = json.loads(reg_scope)
                except Exception:
                    item["regulatory_scope"] = []
            item["internet_facing"] = bool(item["internet_facing"])
            results.append(item)
        return results

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get a single asset by ID."""
        import json

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM assets WHERE id = ? AND org_id = ?",
                    (asset_id, org_id),
                ).fetchone()
        if row is None:
            return None
        item = dict(row)
        reg_scope = item.get("regulatory_scope", "[]")
        if isinstance(reg_scope, str):
            try:
                item["regulatory_scope"] = json.loads(reg_scope)
            except Exception:
                item["regulatory_scope"] = []
        item["internet_facing"] = bool(item["internet_facing"])
        return item

    def get_criticality_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated criticality stats for an org."""
        with self._lock:
            with self._conn() as conn:
                total_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM assets WHERE org_id = ?", (org_id,)
                ).fetchone()

                tier_rows = conn.execute(
                    """SELECT criticality_tier, COUNT(*) as cnt
                       FROM assets WHERE org_id = ?
                       GROUP BY criticality_tier""",
                    (org_id,),
                ).fetchall()

                avg_row = conn.execute(
                    "SELECT AVG(criticality_score) as avg FROM assets WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                internet_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM assets WHERE org_id = ? AND internet_facing = 1",
                    (org_id,),
                ).fetchone()

                # Count assets with at least one regulatory framework
                reg_row = conn.execute(
                    """SELECT COUNT(*) as cnt FROM assets
                       WHERE org_id = ? AND regulatory_scope != '[]' AND regulatory_scope != ''""",
                    (org_id,),
                ).fetchone()

        by_tier = {r["criticality_tier"]: r["cnt"] for r in tier_rows}

        return {
            "total_assets": total_row["cnt"] if total_row else 0,
            "by_tier": by_tier,
            "avg_score": round(float(avg_row["avg"] or 0.0), 2) if avg_row else 0.0,
            "internet_facing_count": internet_row["cnt"] if internet_row else 0,
            "in_regulatory_scope_count": reg_row["cnt"] if reg_row else 0,
        }
