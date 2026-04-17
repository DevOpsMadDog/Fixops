"""Vulnerability Intelligence Fusion Engine — ALDECI.

Fuses vulnerability intelligence from multiple sources into a consensus view.

Capabilities:
  - Ingest CVE data from multiple sources (NVD, vendor advisories, threat intel)
  - Compute consensus severity, priority, and fusion score from all sources
  - Track asset impact and affected asset counts
  - KEV (Known Exploited Vulnerabilities) tracking
  - Priority queue ordered by consensus_priority + fusion_score
  - Multi-tenant isolation via org_id

Compliance: NIST SP 800-40 (patch management), CISA KEV guidance
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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_VALID_SOURCE_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_VALID_CONSENSUS_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ASSET_CRITICALITIES = {"critical", "high", "medium", "low"}
_VALID_EXPOSURES = {"direct", "indirect", "unknown"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class VulnIntelFusionEngine:
    """SQLite WAL-backed Vulnerability Intelligence Fusion engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB: .fixops_data/vuln_intel_fusion.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "vuln_intel_fusion.db")
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
                CREATE TABLE IF NOT EXISTS fused_vulns (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    cve_id              TEXT NOT NULL,
                    title               TEXT NOT NULL DEFAULT '',
                    cvss_base           REAL NOT NULL DEFAULT 0.0,
                    epss_score          REAL NOT NULL DEFAULT 0.0,
                    kev_listed          INTEGER NOT NULL DEFAULT 0,
                    source_count        INTEGER NOT NULL DEFAULT 0,
                    consensus_severity  TEXT NOT NULL DEFAULT 'medium',
                    consensus_priority  INTEGER NOT NULL DEFAULT 3,
                    affected_assets     INTEGER NOT NULL DEFAULT 0,
                    exploited_in_wild   INTEGER NOT NULL DEFAULT 0,
                    patch_available     INTEGER NOT NULL DEFAULT 0,
                    fusion_score        REAL NOT NULL DEFAULT 0.0,
                    first_seen          TEXT NOT NULL,
                    last_updated        TEXT NOT NULL,
                    created_at          TEXT NOT NULL,
                    UNIQUE(org_id, cve_id)
                );

                CREATE INDEX IF NOT EXISTS idx_fv_org_priority
                    ON fused_vulns (org_id, consensus_priority ASC, fusion_score DESC);

                CREATE INDEX IF NOT EXISTS idx_fv_org_kev
                    ON fused_vulns (org_id, kev_listed);

                CREATE TABLE IF NOT EXISTS vuln_source_feeds (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    cve_id          TEXT NOT NULL,
                    source_name     TEXT NOT NULL,
                    source_severity TEXT NOT NULL DEFAULT 'medium',
                    cvss_score      REAL NOT NULL DEFAULT 0.0,
                    epss_score      REAL NOT NULL DEFAULT 0.0,
                    kev_listed      INTEGER NOT NULL DEFAULT 0,
                    additional_data TEXT NOT NULL DEFAULT '{}',
                    ingested_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vsf_org_cve
                    ON vuln_source_feeds (org_id, cve_id);

                CREATE TABLE IF NOT EXISTS vuln_asset_impacts (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    cve_id               TEXT NOT NULL,
                    asset_id             TEXT NOT NULL,
                    asset_name           TEXT NOT NULL DEFAULT '',
                    asset_criticality    TEXT NOT NULL DEFAULT 'medium',
                    exposure             TEXT NOT NULL DEFAULT 'unknown',
                    remediation_priority INTEGER NOT NULL DEFAULT 3,
                    created_at           TEXT NOT NULL,
                    UNIQUE(org_id, cve_id, asset_id)
                );

                CREATE INDEX IF NOT EXISTS idx_vai_org_cve
                    ON vuln_asset_impacts (org_id, cve_id);
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
    # Fusion computation
    # ------------------------------------------------------------------

    def _compute_fusion(self, org_id: str, cve_id: str, conn: sqlite3.Connection) -> Dict[str, Any]:
        """Recompute fusion fields from all source feeds for this cve_id+org_id.

        Returns dict with updated fields to be written to fused_vulns.
        """
        rows = conn.execute(
            """SELECT cvss_score, epss_score, kev_listed, source_name
               FROM vuln_source_feeds WHERE org_id=? AND cve_id=?""",
            (org_id, cve_id),
        ).fetchall()

        if not rows:
            return {}

        source_count = len(rows)
        cvss_values = [r["cvss_score"] for r in rows]
        epss_values = [r["epss_score"] for r in rows]
        kev_values = [r["kev_listed"] for r in rows]

        cvss_base = sum(cvss_values) / len(cvss_values) if cvss_values else 0.0
        epss_score = max(epss_values) if epss_values else 0.0
        kev_listed = 1 if any(v == 1 for v in kev_values) else 0
        exploited_in_wild = 1 if kev_listed else 0

        # Consensus severity: kev override first, then CVSS thresholds
        if kev_listed:
            consensus_severity = "critical"
        elif cvss_base >= 9.0:
            consensus_severity = "critical"
        elif cvss_base >= 7.0:
            consensus_severity = "high"
        elif cvss_base >= 4.0:
            consensus_severity = "medium"
        else:
            consensus_severity = "low"

        # Fusion score: cvss*0.4 + epss*30 + kev*30 + min(10, source_count)*1
        fusion_score = (
            cvss_base * 0.4
            + epss_score * 30.0
            + kev_listed * 30.0
            + min(10, source_count) * 1.0
        )

        priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        consensus_priority = priority_map.get(consensus_severity, 3)

        return {
            "cvss_base": cvss_base,
            "epss_score": epss_score,
            "kev_listed": kev_listed,
            "exploited_in_wild": exploited_in_wild,
            "source_count": source_count,
            "consensus_severity": consensus_severity,
            "consensus_priority": consensus_priority,
            "fusion_score": fusion_score,
        }

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_from_source(
        self,
        org_id: str,
        cve_id: str,
        source_name: str,
        source_severity: str,
        cvss_score: float,
        epss_score: float,
        kev_listed: int,
        title: str = "",
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Ingest CVE data from a source feed.

        If fused_vuln exists: source_count+=1, recalculate fusion.
        If new: INSERT fused_vuln with computed fusion values.
        """
        if additional_data is None:
            additional_data = {}
        add_data_json = json.dumps(additional_data)
        now = _now_iso()
        kev_listed = 1 if kev_listed else 0

        feed_record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cve_id": cve_id,
            "source_name": source_name,
            "source_severity": source_severity,
            "cvss_score": float(cvss_score),
            "epss_score": float(epss_score),
            "kev_listed": kev_listed,
            "additional_data": add_data_json,
            "ingested_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                # Insert source feed
                conn.execute(
                    """INSERT INTO vuln_source_feeds
                       (id, org_id, cve_id, source_name, source_severity, cvss_score,
                        epss_score, kev_listed, additional_data, ingested_at)
                       VALUES (:id, :org_id, :cve_id, :source_name, :source_severity,
                               :cvss_score, :epss_score, :kev_listed, :additional_data, :ingested_at)""",
                    feed_record,
                )

                # Check if fused_vuln exists
                existing = conn.execute(
                    "SELECT * FROM fused_vulns WHERE org_id=? AND cve_id=?",
                    (org_id, cve_id),
                ).fetchone()

                fusion = self._compute_fusion(org_id, cve_id, conn)

                if existing:
                    # Update existing fused vuln
                    conn.execute(
                        """UPDATE fused_vulns SET
                               source_count = :source_count,
                               cvss_base = :cvss_base,
                               epss_score = :epss_score,
                               kev_listed = :kev_listed,
                               exploited_in_wild = :exploited_in_wild,
                               consensus_severity = :consensus_severity,
                               consensus_priority = :consensus_priority,
                               fusion_score = :fusion_score,
                               last_updated = :last_updated
                           WHERE org_id=:org_id AND cve_id=:cve_id""",
                        {
                            **fusion,
                            "last_updated": now,
                            "org_id": org_id,
                            "cve_id": cve_id,
                        },
                    )
                    if title:
                        conn.execute(
                            "UPDATE fused_vulns SET title=? WHERE org_id=? AND cve_id=?",
                            (title, org_id, cve_id),
                        )
                else:
                    # Insert new fused vuln
                    fused_record = {
                        "id": str(uuid.uuid4()),
                        "org_id": org_id,
                        "cve_id": cve_id,
                        "title": title,
                        "affected_assets": 0,
                        "patch_available": 0,
                        "first_seen": now,
                        "last_updated": now,
                        "created_at": now,
                        **fusion,
                    }
                    conn.execute(
                        """INSERT INTO fused_vulns
                           (id, org_id, cve_id, title, cvss_base, epss_score, kev_listed,
                            source_count, consensus_severity, consensus_priority,
                            affected_assets, exploited_in_wild, patch_available,
                            fusion_score, first_seen, last_updated, created_at)
                           VALUES (:id, :org_id, :cve_id, :title, :cvss_base, :epss_score,
                                   :kev_listed, :source_count, :consensus_severity,
                                   :consensus_priority, :affected_assets, :exploited_in_wild,
                                   :patch_available, :fusion_score, :first_seen,
                                   :last_updated, :created_at)""",
                        fused_record,
                    )

                result = conn.execute(
                    "SELECT * FROM fused_vulns WHERE org_id=? AND cve_id=?",
                    (org_id, cve_id),
                ).fetchone()

        return self._row(result)

    # ------------------------------------------------------------------
    # Patch availability
    # ------------------------------------------------------------------

    def mark_patch_available(self, cve_id: str, org_id: str) -> Dict[str, Any]:
        """Mark patch as available for a CVE."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM fused_vulns WHERE org_id=? AND cve_id=?",
                    (org_id, cve_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"CVE {cve_id!r} not found for org {org_id!r}.")
                conn.execute(
                    "UPDATE fused_vulns SET patch_available=1, last_updated=? WHERE org_id=? AND cve_id=?",
                    (now, org_id, cve_id),
                )
                updated = conn.execute(
                    "SELECT * FROM fused_vulns WHERE org_id=? AND cve_id=?",
                    (org_id, cve_id),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Asset impact
    # ------------------------------------------------------------------

    def add_asset_impact(
        self,
        org_id: str,
        cve_id: str,
        asset_id: str,
        asset_name: str,
        asset_criticality: str,
        exposure: str,
        remediation_priority: int,
    ) -> Dict[str, Any]:
        """Add asset impact. INSERT OR IGNORE on (org_id, cve_id, asset_id).
        Increments fused_vulns.affected_assets only on new insert.
        """
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cve_id": cve_id,
            "asset_id": asset_id,
            "asset_name": asset_name,
            "asset_criticality": asset_criticality if asset_criticality in _VALID_ASSET_CRITICALITIES else "medium",
            "exposure": exposure if exposure in _VALID_EXPOSURES else "unknown",
            "remediation_priority": int(remediation_priority),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                cursor = conn.execute(
                    """INSERT OR IGNORE INTO vuln_asset_impacts
                       (id, org_id, cve_id, asset_id, asset_name, asset_criticality,
                        exposure, remediation_priority, created_at)
                       VALUES (:id, :org_id, :cve_id, :asset_id, :asset_name,
                               :asset_criticality, :exposure, :remediation_priority, :created_at)""",
                    record,
                )
                if cursor.rowcount > 0:
                    # New insert — increment affected_assets
                    conn.execute(
                        "UPDATE fused_vulns SET affected_assets=affected_assets+1 WHERE org_id=? AND cve_id=?",
                        (org_id, cve_id),
                    )
        return record

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_fusion_summary(self, org_id: str) -> Dict[str, Any]:
        """Org-level summary of fused vulnerability intelligence."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM fused_vulns WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            kev_count = conn.execute(
                "SELECT COUNT(*) FROM fused_vulns WHERE org_id=? AND kev_listed=1",
                (org_id,),
            ).fetchone()[0]

            critical_count = conn.execute(
                "SELECT COUNT(*) FROM fused_vulns WHERE org_id=? AND consensus_severity='critical'",
                (org_id,),
            ).fetchone()[0]

            by_sev_rows = conn.execute(
                """SELECT consensus_severity, COUNT(*) as cnt
                   FROM fused_vulns WHERE org_id=? GROUP BY consensus_severity""",
                (org_id,),
            ).fetchall()
            by_consensus_severity = {r["consensus_severity"]: r["cnt"] for r in by_sev_rows}

            avg_row = conn.execute(
                "SELECT AVG(fusion_score) as avg_fs FROM fused_vulns WHERE org_id=?",
                (org_id,),
            ).fetchone()
            avg_fusion_score = avg_row["avg_fs"] if avg_row and avg_row["avg_fs"] is not None else 0.0

            patch_available = conn.execute(
                "SELECT COUNT(*) FROM fused_vulns WHERE org_id=? AND patch_available=1",
                (org_id,),
            ).fetchone()[0]

            patch_missing = conn.execute(
                "SELECT COUNT(*) FROM fused_vulns WHERE org_id=? AND patch_available=0",
                (org_id,),
            ).fetchone()[0]

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "vuln_intel_fusion_engine", "org_id": org_id, "source_engine": "vuln_intel_fusion_engine"})
            except Exception:
                pass
        return {
            "total_vulns": total,
            "kev_listed_count": kev_count,
            "critical_count": critical_count,
            "by_consensus_severity": by_consensus_severity,
            "avg_fusion_score": avg_fusion_score,
            "patch_available_count": patch_available,
            "patch_missing_count": patch_missing,
        }

    def get_priority_queue(self, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return fused vulns ordered by consensus_priority ASC, fusion_score DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM fused_vulns WHERE org_id=?
                   ORDER BY consensus_priority ASC, fusion_score DESC
                   LIMIT ?""",
                (org_id, int(limit)),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_vuln_detail(self, cve_id: str, org_id: str) -> Dict[str, Any]:
        """Return fused_vuln + source_feeds + asset_impacts for a CVE."""
        with self._conn() as conn:
            fv_row = conn.execute(
                "SELECT * FROM fused_vulns WHERE org_id=? AND cve_id=?",
                (org_id, cve_id),
            ).fetchone()
            if not fv_row:
                return {}

            feeds = conn.execute(
                "SELECT * FROM vuln_source_feeds WHERE org_id=? AND cve_id=? ORDER BY ingested_at",
                (org_id, cve_id),
            ).fetchall()

            impacts = conn.execute(
                "SELECT * FROM vuln_asset_impacts WHERE org_id=? AND cve_id=?",
                (org_id, cve_id),
            ).fetchall()

        result = self._row(fv_row)
        result["source_feeds"] = [self._row(f) for f in feeds]
        result["asset_impacts"] = [self._row(i) for i in impacts]
        return result

    def get_kev_vulns(self, org_id: str) -> List[Dict[str, Any]]:
        """Return vulns where kev_listed=1, ordered by fusion_score DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM fused_vulns WHERE org_id=? AND kev_listed=1
                   ORDER BY fusion_score DESC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]
