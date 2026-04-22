"""Asset Criticality Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Systematic asset criticality scoring for risk prioritization.

Tables:
  assets              — registered assets with criticality scores and tiers
  criticality_factors — weighted factor scoring per asset
  dependency_map      — directed asset dependency graph

Compliance: NIST SP 800-53 RA-2, ISO/IEC 27005, FAIR model
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "asset_criticality_engine.db"
)

_VALID_ASSET_TYPES = {
    "server", "workstation", "network", "application", "database",
    "cloud", "iot", "mobile", "container",
}
_VALID_DATA_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted", "secret"}
_VALID_REQUIREMENTS = {"low", "medium", "high", "critical"}
_VALID_DEPENDENCY_TYPES = {"technical", "business", "data", "process"}
_VALID_CRITICALITY_IMPACTS = {"low", "medium", "high", "critical"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_tier(score: float) -> str:
    if score >= 80.0:
        return "tier-1-critical"
    if score >= 60.0:
        return "tier-2-high"
    if score >= 40.0:
        return "tier-3-medium"
    return "tier-4-low"


class AssetCriticalityEngine:
    """SQLite WAL-backed Asset Criticality engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/asset_criticality_engine.db
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
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS assets (
                        id                          TEXT PRIMARY KEY,
                        org_id                      TEXT NOT NULL,
                        asset_name                  TEXT NOT NULL DEFAULT '',
                        asset_type                  TEXT NOT NULL DEFAULT 'server',
                        owner                       TEXT NOT NULL DEFAULT '',
                        business_function           TEXT NOT NULL DEFAULT '',
                        data_classification         TEXT NOT NULL DEFAULT 'internal',
                        criticality_score           REAL NOT NULL DEFAULT 0.0,
                        criticality_tier            TEXT NOT NULL DEFAULT 'unassessed',
                        availability_requirement    TEXT NOT NULL DEFAULT 'medium',
                        integrity_requirement       TEXT NOT NULL DEFAULT 'medium',
                        confidentiality_requirement TEXT NOT NULL DEFAULT 'medium',
                        last_assessed               TEXT NOT NULL DEFAULT '',
                        created_at                  TEXT NOT NULL DEFAULT ''
                    );

                    CREATE INDEX IF NOT EXISTS idx_ac_assets_org
                        ON assets (org_id, asset_type, criticality_tier);

                    CREATE TABLE IF NOT EXISTS criticality_factors (
                        id                 TEXT PRIMARY KEY,
                        asset_id           TEXT NOT NULL,
                        org_id             TEXT NOT NULL,
                        factor_name        TEXT NOT NULL DEFAULT '',
                        factor_category    TEXT NOT NULL DEFAULT '',
                        weight             REAL NOT NULL DEFAULT 1.0,
                        value              REAL NOT NULL DEFAULT 0.0,
                        score_contribution REAL NOT NULL DEFAULT 0.0,
                        assessed_at        TEXT NOT NULL DEFAULT ''
                    );

                    CREATE INDEX IF NOT EXISTS idx_ac_factors_asset
                        ON criticality_factors (asset_id, org_id);

                    CREATE TABLE IF NOT EXISTS dependency_map (
                        id                  TEXT PRIMARY KEY,
                        asset_id            TEXT NOT NULL,
                        org_id              TEXT NOT NULL,
                        depends_on_asset_id TEXT NOT NULL,
                        dependency_type     TEXT NOT NULL DEFAULT 'technical',
                        criticality_impact  TEXT NOT NULL DEFAULT 'medium',
                        created_at          TEXT NOT NULL DEFAULT ''
                    );

                    CREATE INDEX IF NOT EXISTS idx_ac_deps_asset
                        ON dependency_map (asset_id, org_id);

                    CREATE TABLE IF NOT EXISTS crown_jewel_tags (
                        id          TEXT PRIMARY KEY,
                        org_id      TEXT NOT NULL,
                        asset_ref   TEXT NOT NULL,
                        reason      TEXT NOT NULL DEFAULT '',
                        tagged_at   TEXT NOT NULL DEFAULT '',
                        UNIQUE(org_id, asset_ref)
                    );

                    CREATE INDEX IF NOT EXISTS idx_ac_crown_jewel_org
                        ON crown_jewel_tags (org_id);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def register_asset(
        self,
        org_id: str,
        asset_name: str,
        asset_type: str,
        owner: str = "",
        business_function: str = "",
        data_classification: str = "internal",
        availability_requirement: str = "medium",
        integrity_requirement: str = "medium",
        confidentiality_requirement: str = "medium",
    ) -> Dict[str, Any]:
        """Register a new asset. criticality_score=0, criticality_tier=unassessed."""
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(
                f"Invalid asset_type '{asset_type}'. "
                f"Must be one of {sorted(_VALID_ASSET_TYPES)}"
            )
        if data_classification not in _VALID_DATA_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid data_classification '{data_classification}'. "
                f"Must be one of {sorted(_VALID_DATA_CLASSIFICATIONS)}"
            )
        for req_name, req_val in [
            ("availability_requirement", availability_requirement),
            ("integrity_requirement", integrity_requirement),
            ("confidentiality_requirement", confidentiality_requirement),
        ]:
            if req_val not in _VALID_REQUIREMENTS:
                raise ValueError(
                    f"Invalid {req_name} '{req_val}'. "
                    f"Must be one of {sorted(_VALID_REQUIREMENTS)}"
                )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "owner": owner,
            "business_function": business_function,
            "data_classification": data_classification,
            "criticality_score": 0.0,
            "criticality_tier": "unassessed",
            "availability_requirement": availability_requirement,
            "integrity_requirement": integrity_requirement,
            "confidentiality_requirement": confidentiality_requirement,
            "last_assessed": "",
            "created_at": now,
        }
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """INSERT INTO assets
                       (id, org_id, asset_name, asset_type, owner, business_function,
                        data_classification, criticality_score, criticality_tier,
                        availability_requirement, integrity_requirement,
                        confidentiality_requirement, last_assessed, created_at)
                       VALUES (:id, :org_id, :asset_name, :asset_type, :owner,
                               :business_function, :data_classification,
                               :criticality_score, :criticality_tier,
                               :availability_requirement, :integrity_requirement,
                               :confidentiality_requirement, :last_assessed, :created_at)""",
                    record,
                )
                conn.commit()
            finally:
                conn.close()
        return record

    def score_asset(
        self,
        asset_id: str,
        org_id: str,
        factors: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Score an asset using weighted factors.

        Each factor: {factor_name, factor_category, weight, value (0-10)}
        score_contribution = weight * value / 10
        criticality_score = sum(score_contributions) / sum(weights) * 100
        """
        if not factors:
            raise ValueError("factors list must not be empty")

        now = _now_iso()
        factor_records = []
        total_weighted = 0.0
        total_weight = 0.0

        for f in factors:
            weight = float(f.get("weight", 1.0))
            value = float(f.get("value", 0.0))
            contribution = weight * value / 10.0
            total_weighted += contribution
            total_weight += weight
            factor_records.append({
                "id": str(uuid.uuid4()),
                "asset_id": asset_id,
                "org_id": org_id,
                "factor_name": f.get("factor_name", ""),
                "factor_category": f.get("factor_category", ""),
                "weight": weight,
                "value": value,
                "score_contribution": contribution,
                "assessed_at": now,
            })

        criticality_score = (total_weighted / total_weight * 100.0) if total_weight > 0 else 0.0
        criticality_tier = _compute_tier(criticality_score)

        with self._lock:
            conn = self._conn()
            try:
                # Remove old factors for this asset+org
                conn.execute(
                    "DELETE FROM criticality_factors WHERE asset_id = ? AND org_id = ?",
                    (asset_id, org_id),
                )
                for fr in factor_records:
                    conn.execute(
                        """INSERT INTO criticality_factors
                           (id, asset_id, org_id, factor_name, factor_category,
                            weight, value, score_contribution, assessed_at)
                           VALUES (:id, :asset_id, :org_id, :factor_name, :factor_category,
                                   :weight, :value, :score_contribution, :assessed_at)""",
                        fr,
                    )
                conn.execute(
                    """UPDATE assets
                       SET criticality_score = ?, criticality_tier = ?, last_assessed = ?
                       WHERE id = ? AND org_id = ?""",
                    (criticality_score, criticality_tier, now, asset_id, org_id),
                )
                conn.commit()
            finally:
                conn.close()

        return self.get_asset(asset_id, org_id)

    def add_dependency(
        self,
        asset_id: str,
        org_id: str,
        depends_on_asset_id: str,
        dependency_type: str = "technical",
        criticality_impact: str = "medium",
    ) -> Dict[str, Any]:
        """Add a dependency between two assets."""
        if dependency_type not in _VALID_DEPENDENCY_TYPES:
            raise ValueError(
                f"Invalid dependency_type '{dependency_type}'. "
                f"Must be one of {sorted(_VALID_DEPENDENCY_TYPES)}"
            )
        if criticality_impact not in _VALID_CRITICALITY_IMPACTS:
            raise ValueError(
                f"Invalid criticality_impact '{criticality_impact}'. "
                f"Must be one of {sorted(_VALID_CRITICALITY_IMPACTS)}"
            )
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "asset_id": asset_id,
            "org_id": org_id,
            "depends_on_asset_id": depends_on_asset_id,
            "dependency_type": dependency_type,
            "criticality_impact": criticality_impact,
            "created_at": now,
        }
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """INSERT INTO dependency_map
                       (id, asset_id, org_id, depends_on_asset_id, dependency_type,
                        criticality_impact, created_at)
                       VALUES (:id, :asset_id, :org_id, :depends_on_asset_id,
                               :dependency_type, :criticality_impact, :created_at)""",
                    record,
                )
                conn.commit()
            finally:
                conn.close()
        return record

    def get_asset(self, asset_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return asset with its factors and dependencies."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM assets WHERE id = ? AND org_id = ?",
                (asset_id, org_id),
            ).fetchone()
            if not row:
                return None
            asset = self._row(row)
            factors = conn.execute(
                "SELECT * FROM criticality_factors WHERE asset_id = ? AND org_id = ? ORDER BY assessed_at DESC",
                (asset_id, org_id),
            ).fetchall()
            deps = conn.execute(
                "SELECT * FROM dependency_map WHERE asset_id = ? AND org_id = ? ORDER BY created_at DESC",
                (asset_id, org_id),
            ).fetchall()
        finally:
            conn.close()
        asset["factors"] = [self._row(f) for f in factors]
        asset["dependencies"] = [self._row(d) for d in deps]
        return asset

    def list_assets(
        self,
        org_id: str,
        criticality_tier: Optional[str] = None,
        asset_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assets with optional filters."""
        sql = "SELECT * FROM assets WHERE org_id = ?"
        params: List[Any] = [org_id]
        if criticality_tier:
            sql += " AND criticality_tier = ?"
            params.append(criticality_tier)
        if asset_type:
            sql += " AND asset_type = ?"
            params.append(asset_type)
        sql += " ORDER BY criticality_score DESC, created_at DESC"
        conn = self._conn()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        return [self._row(r) for r in rows]

    def get_critical_path(
        self, org_id: str, asset_id: str, max_hops: int = 3
    ) -> List[Dict[str, Any]]:
        """BFS traversal of asset dependencies up to max_hops (default 3).

        Returns all assets that asset_id transitively depends on.
        Circular dependency safe (visited set).
        """
        visited: set = set()
        result: List[Dict[str, Any]] = []
        queue: deque = deque()
        queue.append((asset_id, 0))
        visited.add(asset_id)

        conn = self._conn()
        try:
            while queue:
                current_id, hop = queue.popleft()
                if hop >= max_hops:
                    continue
                dep_rows = conn.execute(
                    """SELECT depends_on_asset_id FROM dependency_map
                       WHERE asset_id = ? AND org_id = ?""",
                    (current_id, org_id),
                ).fetchall()
                for dep_row in dep_rows:
                    dep_id = dep_row["depends_on_asset_id"]
                    if dep_id in visited:
                        continue
                    visited.add(dep_id)
                    asset_row = conn.execute(
                        "SELECT * FROM assets WHERE id = ? AND org_id = ?",
                        (dep_id, org_id),
                    ).fetchone()
                    if asset_row:
                        result.append(self._row(asset_row))
                    queue.append((dep_id, hop + 1))
        finally:
            conn.close()
        return result

    # ------------------------------------------------------------------
    # Crown Jewel Tagging (GAP-046)
    # ------------------------------------------------------------------

    def tag_crown_jewel(
        self, org_id: str, asset_ref: str, reason: str = ""
    ) -> Dict[str, Any]:
        """Idempotently tag an asset as a crown jewel.

        UNIQUE(org_id, asset_ref) — re-tagging with the same asset_ref updates reason.
        Returns the persisted record.
        """
        if not org_id or not asset_ref:
            raise ValueError("org_id and asset_ref are required")

        now = _now_iso()
        record_id = str(uuid.uuid4())
        with self._lock:
            conn = self._conn()
            try:
                existing = conn.execute(
                    "SELECT id FROM crown_jewel_tags WHERE org_id = ? AND asset_ref = ?",
                    (org_id, asset_ref),
                ).fetchone()
                if existing:
                    conn.execute(
                        """UPDATE crown_jewel_tags
                           SET reason = ?, tagged_at = ?
                           WHERE id = ?""",
                        (reason, now, existing["id"]),
                    )
                    record_id = existing["id"]
                else:
                    conn.execute(
                        """INSERT INTO crown_jewel_tags
                           (id, org_id, asset_ref, reason, tagged_at)
                           VALUES (?, ?, ?, ?, ?)""",
                        (record_id, org_id, asset_ref, reason, now),
                    )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM crown_jewel_tags WHERE id = ?",
                    (record_id,),
                ).fetchone()
            finally:
                conn.close()
        return self._row(row) if row else {}

    def list_crown_jewels(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all crown-jewel tags for an org."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM crown_jewel_tags WHERE org_id = ? ORDER BY tagged_at DESC",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()
        return [self._row(r) for r in rows]

    def is_crown_jewel(self, org_id: str, asset_ref: str) -> bool:
        """Convenience helper for scoring engines."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT 1 FROM crown_jewel_tags WHERE org_id = ? AND asset_ref = ?",
                (org_id, asset_ref),
            ).fetchone()
        finally:
            conn.close()
        return row is not None

    # ------------------------------------------------------------------
    # Blast Radius (GAP-027)
    # ------------------------------------------------------------------

    def compute_blast_radius_score(
        self, org_id: str, asset_ref: str, max_hops: int = 3
    ) -> Dict[str, Any]:
        """Walk asset dependency graph up to ``max_hops`` and compute 0-100 blast radius.

        Scoring:
          - Seed asset tier contributes a tier-weighted base (tier-1=40, tier-2=25, tier-3=15, tier-4=5).
          - Each transitively-reachable asset contributes (tier_weight * hop_decay) where
            hop_decay = 1.0, 0.6, 0.3 for hops 1, 2, 3.
          - Crown-jewel tags on ANY reachable asset add a +15 bonus (once per asset).
          - Final score is clamped to [0, 100].

        Returns dict with:
          score                  — 0-100
          hops_walked            — number of hops actually walked
          reachable_asset_count  — distinct downstream assets
          contributing_factors   — list[{asset_ref, tier, hop, weight, crown_jewel}]
        """
        tier_weight = {
            "tier-1-critical": 40.0,
            "tier-2-high": 25.0,
            "tier-3-medium": 15.0,
            "tier-4-low": 5.0,
            "unassessed": 5.0,
        }
        hop_decay = {0: 1.0, 1: 1.0, 2: 0.6, 3: 0.3}

        contributors: List[Dict[str, Any]] = []
        visited: set = {asset_ref}
        queue: deque = deque([(asset_ref, 0)])
        score = 0.0
        max_hop_seen = 0

        conn = self._conn()
        try:
            crown_rows = conn.execute(
                "SELECT asset_ref FROM crown_jewel_tags WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            crown_set = {r["asset_ref"] for r in crown_rows}

            while queue:
                current, hop = queue.popleft()
                max_hop_seen = max(max_hop_seen, hop)
                asset_row = conn.execute(
                    "SELECT id, criticality_tier FROM assets WHERE id = ? AND org_id = ?",
                    (current, org_id),
                ).fetchone()
                if not asset_row:
                    # Allow asset_ref to be a raw reference even if not registered.
                    tier = "unassessed"
                else:
                    tier = asset_row["criticality_tier"] or "unassessed"

                weight = tier_weight.get(tier, 5.0) * hop_decay.get(hop, 0.0)
                is_crown = current in crown_set
                if is_crown:
                    weight += 15.0
                score += weight

                contributors.append({
                    "asset_ref": current,
                    "tier": tier,
                    "hop": hop,
                    "weight": round(weight, 2),
                    "crown_jewel": is_crown,
                })

                if hop >= max_hops:
                    continue

                dep_rows = conn.execute(
                    """SELECT depends_on_asset_id FROM dependency_map
                       WHERE asset_id = ? AND org_id = ?""",
                    (current, org_id),
                ).fetchall()
                for dep_row in dep_rows:
                    dep_id = dep_row["depends_on_asset_id"]
                    if dep_id in visited:
                        continue
                    visited.add(dep_id)
                    queue.append((dep_id, hop + 1))
        finally:
            conn.close()

        score = max(0.0, min(100.0, round(score, 2)))
        return {
            "org_id": org_id,
            "asset_ref": asset_ref,
            "score": score,
            "hops_walked": max_hop_seen,
            "reachable_asset_count": max(0, len(visited) - 1),
            "contributing_factors": contributors,
        }

    def get_criticality_summary(self, org_id: str) -> Dict[str, Any]:
        """Return count by tier, avg score, unassessed count, top 5 most critical."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT id, asset_name, criticality_score, criticality_tier FROM assets WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        if not rows:
            return {
                "count_by_tier": {},
                "avg_score": 0.0,
                "unassessed_count": 0,
                "most_critical": [],
            }

        count_by_tier: Dict[str, int] = {}
        unassessed = 0
        scores = []
        for r in rows:
            tier = r["criticality_tier"]
            count_by_tier[tier] = count_by_tier.get(tier, 0) + 1
            if tier == "unassessed":
                unassessed += 1
            else:
                scores.append(r["criticality_score"])

        avg_score = sum(scores) / len(scores) if scores else 0.0

        sorted_rows = sorted(rows, key=lambda r: r["criticality_score"], reverse=True)
        most_critical = [
            {"id": r["id"], "asset_name": r["asset_name"],
             "criticality_score": r["criticality_score"],
             "criticality_tier": r["criticality_tier"]}
            for r in sorted_rows[:5]
        ]

        return {
            "count_by_tier": count_by_tier,
            "avg_score": avg_score,
            "unassessed_count": unassessed,
            "most_critical": most_critical,
        }
