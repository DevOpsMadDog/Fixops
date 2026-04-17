"""Threat Landscape Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Provides holistic view of the current threat environment:
  - Threat actor tracking with TTP and target sector intel
  - Emerging threat monitoring with lifecycle management
  - Landscape assessments with auto-computed overall_risk
  - Summary statistics across actors and threats

Compliance: MITRE ATT&CK, STIX 2.1, ISO 27001 A.12.6
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_landscape_engine.db"
)

_VALID_ACTOR_TYPES = {"nation-state", "criminal", "hacktivist", "insider", "competitor", "unknown"}
_VALID_MOTIVATIONS = {"financial", "espionage", "disruption", "ideology", "revenge", "unknown"}
_VALID_SOPHISTICATIONS = {"advanced", "intermediate", "basic", "unknown"}
_VALID_THREAT_CATEGORIES = {
    "ransomware", "phishing", "supply-chain", "zero-day", "insider", "ddos", "data-breach", "malware"
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_json(value: Any) -> str:
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value) if value is not None else "[]"


def _from_json(value: str) -> Any:
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


class ThreatLandscapeEngine:
    """SQLite WAL-backed Threat Landscape engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/threat_landscape_engine.db
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
                CREATE TABLE IF NOT EXISTS threat_actors (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    actor_name      TEXT NOT NULL DEFAULT '',
                    actor_type      TEXT NOT NULL DEFAULT 'unknown',
                    motivation      TEXT NOT NULL DEFAULT 'unknown',
                    sophistication  TEXT NOT NULL DEFAULT 'unknown',
                    active          INTEGER NOT NULL DEFAULT 1,
                    ttps            TEXT NOT NULL DEFAULT '[]',
                    target_sectors  TEXT NOT NULL DEFAULT '[]',
                    confidence      REAL NOT NULL DEFAULT 0.5,
                    last_seen       TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tl_actors_org
                    ON threat_actors (org_id, actor_type, active);

                CREATE TABLE IF NOT EXISTS emerging_threats (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    threat_name      TEXT NOT NULL DEFAULT '',
                    threat_category  TEXT NOT NULL DEFAULT 'malware',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    description      TEXT NOT NULL DEFAULT '',
                    affected_sectors TEXT NOT NULL DEFAULT '[]',
                    indicators       TEXT NOT NULL DEFAULT '[]',
                    mitigations      TEXT NOT NULL DEFAULT '[]',
                    first_observed   TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tl_threats_org
                    ON emerging_threats (org_id, severity, status);

                CREATE TABLE IF NOT EXISTS landscape_assessments (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    assessment_date TEXT NOT NULL,
                    overall_risk  TEXT NOT NULL DEFAULT 'medium',
                    sector        TEXT NOT NULL DEFAULT '',
                    key_findings  TEXT NOT NULL DEFAULT '[]',
                    recommendations TEXT NOT NULL DEFAULT '[]',
                    threat_count  INTEGER NOT NULL DEFAULT 0,
                    actor_count   INTEGER NOT NULL DEFAULT 0,
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tl_assessments_org
                    ON landscape_assessments (org_id, sector);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _deserialize_actor(self, row: Dict[str, Any]) -> Dict[str, Any]:
        row["ttps"] = _from_json(row.get("ttps", "[]"))
        row["target_sectors"] = _from_json(row.get("target_sectors", "[]"))
        return row

    def _deserialize_threat(self, row: Dict[str, Any]) -> Dict[str, Any]:
        row["affected_sectors"] = _from_json(row.get("affected_sectors", "[]"))
        row["indicators"] = _from_json(row.get("indicators", "[]"))
        row["mitigations"] = _from_json(row.get("mitigations", "[]"))
        return row

    def _deserialize_assessment(self, row: Dict[str, Any]) -> Dict[str, Any]:
        row["key_findings"] = _from_json(row.get("key_findings", "[]"))
        row["recommendations"] = _from_json(row.get("recommendations", "[]"))
        return row

    # ------------------------------------------------------------------
    # Threat Actors
    # ------------------------------------------------------------------

    def add_threat_actor(
        self,
        org_id: str,
        actor_name: str,
        actor_type: str,
        motivation: str,
        sophistication: str,
        ttps: Any,
        target_sectors: Any,
        confidence: float,
    ) -> Dict[str, Any]:
        """Add a threat actor; confidence clamped to [0, 1]."""
        if actor_type not in _VALID_ACTOR_TYPES:
            raise ValueError(f"Invalid actor_type '{actor_type}'. Must be one of {sorted(_VALID_ACTOR_TYPES)}")
        if motivation not in _VALID_MOTIVATIONS:
            raise ValueError(f"Invalid motivation '{motivation}'. Must be one of {sorted(_VALID_MOTIVATIONS)}")
        if sophistication not in _VALID_SOPHISTICATIONS:
            raise ValueError(f"Invalid sophistication '{sophistication}'. Must be one of {sorted(_VALID_SOPHISTICATIONS)}")

        confidence = max(0.0, min(1.0, float(confidence)))
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "actor_name": actor_name,
            "actor_type": actor_type,
            "motivation": motivation,
            "sophistication": sophistication,
            "active": 1,
            "ttps": _to_json(ttps),
            "target_sectors": _to_json(target_sectors),
            "confidence": confidence,
            "last_seen": now,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO threat_actors
                       (id, org_id, actor_name, actor_type, motivation, sophistication,
                        active, ttps, target_sectors, confidence, last_seen, created_at)
                       VALUES (:id, :org_id, :actor_name, :actor_type, :motivation, :sophistication,
                               :active, :ttps, :target_sectors, :confidence, :last_seen, :created_at)""",
                    record,
                )
        result = dict(record)
        result["ttps"] = ttps if isinstance(ttps, list) else ttps
        result["target_sectors"] = target_sectors if isinstance(target_sectors, list) else target_sectors
        return result

    def update_actor_activity(
        self,
        actor_id: str,
        org_id: str,
        active: int,
        last_seen: str,
    ) -> Optional[Dict[str, Any]]:
        """Update actor active status and last_seen timestamp."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE threat_actors SET active = ?, last_seen = ? WHERE id = ? AND org_id = ?",
                    (active, last_seen, actor_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM threat_actors WHERE id = ? AND org_id = ?",
                    (actor_id, org_id),
                ).fetchone()
        if not row:
            return None
        return self._deserialize_actor(self._row(row))

    def get_active_actors(
        self,
        org_id: str,
        actor_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List active threat actors, optionally filtered by actor_type."""
        sql = "SELECT * FROM threat_actors WHERE org_id = ? AND active = 1"
        params: List[Any] = [org_id]
        if actor_type:
            sql += " AND actor_type = ?"
            params.append(actor_type)
        sql += " ORDER BY confidence DESC, created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_actor(self._row(r)) for r in rows]

    # ------------------------------------------------------------------
    # Emerging Threats
    # ------------------------------------------------------------------

    def add_emerging_threat(
        self,
        org_id: str,
        threat_name: str,
        threat_category: str,
        severity: str,
        description: str,
        affected_sectors: Any,
        indicators: Any,
        mitigations: Any,
    ) -> Dict[str, Any]:
        """Add an emerging threat with status=active."""
        if threat_category not in _VALID_THREAT_CATEGORIES:
            raise ValueError(f"Invalid threat_category '{threat_category}'. Must be one of {sorted(_VALID_THREAT_CATEGORIES)}")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of {sorted(_VALID_SEVERITIES)}")

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "threat_name": threat_name,
            "threat_category": threat_category,
            "severity": severity,
            "description": description,
            "affected_sectors": _to_json(affected_sectors),
            "indicators": _to_json(indicators),
            "mitigations": _to_json(mitigations),
            "first_observed": now,
            "status": "active",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO emerging_threats
                       (id, org_id, threat_name, threat_category, severity, description,
                        affected_sectors, indicators, mitigations, first_observed, status, created_at)
                       VALUES (:id, :org_id, :threat_name, :threat_category, :severity, :description,
                               :affected_sectors, :indicators, :mitigations, :first_observed, :status, :created_at)""",
                    record,
                )
        result = dict(record)
        result["affected_sectors"] = affected_sectors if isinstance(affected_sectors, list) else affected_sectors
        result["indicators"] = indicators if isinstance(indicators, list) else indicators
        result["mitigations"] = mitigations if isinstance(mitigations, list) else mitigations
        return result

    def resolve_threat(self, threat_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Mark a threat as resolved."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE emerging_threats SET status = 'resolved' WHERE id = ? AND org_id = ?",
                    (threat_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM emerging_threats WHERE id = ? AND org_id = ?",
                    (threat_id, org_id),
                ).fetchone()
        if not row:
            return None
        return self._deserialize_threat(self._row(row))

    def get_active_threats(
        self,
        org_id: str,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List active threats, optionally filtered by severity."""
        sql = "SELECT * FROM emerging_threats WHERE org_id = ? AND status = 'active'"
        params: List[Any] = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_threat(self._row(r)) for r in rows]

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def _compute_overall_risk(self, org_id: str) -> str:
        """Compute overall risk from active critical/high threat counts."""
        with self._conn() as conn:
            critical_count = conn.execute(
                "SELECT COUNT(*) FROM emerging_threats WHERE org_id = ? AND status = 'active' AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]
            high_count = conn.execute(
                "SELECT COUNT(*) FROM emerging_threats WHERE org_id = ? AND status = 'active' AND severity = 'high'",
                (org_id,),
            ).fetchone()[0]
            any_active = conn.execute(
                "SELECT COUNT(*) FROM emerging_threats WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

        if critical_count >= 3:
            return "critical"
        if critical_count >= 1 or high_count >= 1:
            return "high"
        if any_active > 0:
            return "medium"
        return "low"

    def create_assessment(
        self,
        org_id: str,
        sector: str,
        key_findings: Any,
        recommendations: Any,
    ) -> Dict[str, Any]:
        """Create a landscape assessment with auto-computed risk and counts."""
        overall_risk = self._compute_overall_risk(org_id)
        now = _now_iso()

        with self._conn() as conn:
            threat_count = conn.execute(
                "SELECT COUNT(*) FROM emerging_threats WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]
            actor_count = conn.execute(
                "SELECT COUNT(*) FROM threat_actors WHERE org_id = ? AND active = 1",
                (org_id,),
            ).fetchone()[0]

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "assessment_date": now,
            "overall_risk": overall_risk,
            "sector": sector,
            "key_findings": _to_json(key_findings),
            "recommendations": _to_json(recommendations),
            "threat_count": threat_count,
            "actor_count": actor_count,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO landscape_assessments
                       (id, org_id, assessment_date, overall_risk, sector,
                        key_findings, recommendations, threat_count, actor_count, created_at)
                       VALUES (:id, :org_id, :assessment_date, :overall_risk, :sector,
                               :key_findings, :recommendations, :threat_count, :actor_count, :created_at)""",
                    record,
                )
        result = dict(record)
        result["key_findings"] = key_findings if isinstance(key_findings, list) else key_findings
        result["recommendations"] = recommendations if isinstance(recommendations, list) else recommendations
        return result

    def get_assessment(self, assessment_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get a single assessment by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM landscape_assessments WHERE id = ? AND org_id = ?",
                (assessment_id, org_id),
            ).fetchone()
        if not row:
            return None
        return self._deserialize_assessment(self._row(row))

    def list_assessments(
        self,
        org_id: str,
        sector: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assessments with optional sector filter."""
        sql = "SELECT * FROM landscape_assessments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if sector:
            sql += " AND sector = ?"
            params.append(sector)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_assessment(self._row(r)) for r in rows]

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_landscape_summary(self, org_id: str) -> Dict[str, Any]:
        """Return summary stats across actors and threats."""
        with self._conn() as conn:
            total_actors = conn.execute(
                "SELECT COUNT(*) FROM threat_actors WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            active_actors = conn.execute(
                "SELECT COUNT(*) FROM threat_actors WHERE org_id = ? AND active = 1", (org_id,)
            ).fetchone()[0]
            total_threats = conn.execute(
                "SELECT COUNT(*) FROM emerging_threats WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            active_threats = conn.execute(
                "SELECT COUNT(*) FROM emerging_threats WHERE org_id = ? AND status = 'active'", (org_id,)
            ).fetchone()[0]

            severity_rows = conn.execute(
                """SELECT severity, COUNT(*) AS cnt FROM emerging_threats
                   WHERE org_id = ? AND status = 'active' GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

            # Top target sectors from actors (aggregate JSON arrays)
            actor_rows = conn.execute(
                "SELECT target_sectors FROM threat_actors WHERE org_id = ? AND active = 1",
                (org_id,),
            ).fetchall()
            sector_counts: Dict[str, int] = {}
            for ar in actor_rows:
                sectors = _from_json(ar["target_sectors"])
                if isinstance(sectors, list):
                    for s in sectors:
                        sector_counts[s] = sector_counts.get(s, 0) + 1
            top_target_sectors = sorted(sector_counts, key=lambda x: sector_counts[x], reverse=True)[:5]

        return {
            "total_actors": total_actors,
            "active_actors": active_actors,
            "total_threats": total_threats,
            "active_threats": active_threats,
            "by_severity": by_severity,
            "top_target_sectors": top_target_sectors,
        }
