"""Zero Day Intelligence Engine — ALDECI.

Tracks zero-day vulnerabilities, associated threat actors, and mitigations.

Capabilities:
  - Vulnerability registry with CVE tracking, CVSS scoring, exploitation status
  - Threat actor attribution with confidence scoring
  - Mitigation tracking with lifecycle states
  - Stats: totals, unpatched, actively exploited, by severity/status

Compliance: NIST NVD, CISA KEV, MITRE CVE
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_DISCLOSURE_TYPES = {"full", "limited", "coordinated", "zero_day"}
_VALID_PATCH_STATUSES = {"unpatched", "partial", "patched"}
_VALID_EXPLOITATION_STATUSES = {
    "unconfirmed",
    "poc_available",
    "actively_exploited",
    "weaponized",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ACTOR_TYPES = {
    "apt",
    "criminal",
    "hacktivist",
    "state_sponsored",
    "unknown",
}
_VALID_MITIGATION_TYPES = {
    "workaround",
    "patch",
    "configuration",
    "network_isolation",
    "disable_feature",
}
_VALID_MITIGATION_STATUSES = {"proposed", "approved", "implemented", "verified"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ZeroDayIntelligenceEngine:
    """SQLite WAL-backed Zero Day Intelligence engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/zero_day_intelligence.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "zero_day_intelligence.db")
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
                CREATE TABLE IF NOT EXISTS zdi_vulnerabilities (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    cve_id               TEXT NOT NULL,
                    title                TEXT NOT NULL DEFAULT '',
                    description          TEXT NOT NULL DEFAULT '',
                    cvss_score           REAL NOT NULL DEFAULT 0.0,
                    exploitability_score REAL NOT NULL DEFAULT 0.0,
                    affected_products    TEXT NOT NULL DEFAULT '[]',
                    disclosure_type      TEXT NOT NULL DEFAULT 'coordinated',
                    patch_status         TEXT NOT NULL DEFAULT 'unpatched',
                    exploitation_status  TEXT NOT NULL DEFAULT 'unconfirmed',
                    severity             TEXT NOT NULL DEFAULT 'medium',
                    discovered_at        TEXT,
                    disclosed_at         TEXT,
                    patched_at           TEXT,
                    created_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_zdi_vulns_org
                    ON zdi_vulnerabilities (org_id, severity, patch_status, exploitation_status, created_at DESC);

                CREATE TABLE IF NOT EXISTS zdi_threat_actors (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    vulnerability_id TEXT NOT NULL,
                    actor_name       TEXT NOT NULL,
                    actor_type       TEXT NOT NULL DEFAULT 'unknown',
                    confidence_score REAL NOT NULL DEFAULT 50.0,
                    first_seen       TEXT,
                    last_seen        TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_zdi_actors_org
                    ON zdi_threat_actors (org_id, vulnerability_id, actor_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS zdi_mitigations (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    vulnerability_id TEXT NOT NULL,
                    mitigation_type  TEXT NOT NULL,
                    description      TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'proposed',
                    applied_by       TEXT NOT NULL DEFAULT '',
                    applied_at       TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_zdi_mitigations_org
                    ON zdi_mitigations (org_id, vulnerability_id, status, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("affected_products",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        return d

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    def register_vulnerability(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new zero-day vulnerability."""
        cve_id = (data.get("cve_id") or "").strip()
        if not cve_id:
            raise ValueError("cve_id is required.")

        disclosure_type = data.get("disclosure_type", "coordinated")
        if disclosure_type not in _VALID_DISCLOSURE_TYPES:
            raise ValueError(
                f"Invalid disclosure_type: {disclosure_type}. "
                f"Must be one of {sorted(_VALID_DISCLOSURE_TYPES)}"
            )

        patch_status = data.get("patch_status", "unpatched")
        if patch_status not in _VALID_PATCH_STATUSES:
            raise ValueError(
                f"Invalid patch_status: {patch_status}. "
                f"Must be one of {sorted(_VALID_PATCH_STATUSES)}"
            )

        exploitation_status = data.get("exploitation_status", "unconfirmed")
        if exploitation_status not in _VALID_EXPLOITATION_STATUSES:
            raise ValueError(
                f"Invalid exploitation_status: {exploitation_status}. "
                f"Must be one of {sorted(_VALID_EXPLOITATION_STATUSES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        affected_products = data.get("affected_products", [])
        if not isinstance(affected_products, list):
            affected_products = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cve_id": cve_id,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "exploitability_score": float(data.get("exploitability_score", 0.0)),
            "affected_products": json.dumps(affected_products),
            "disclosure_type": disclosure_type,
            "patch_status": patch_status,
            "exploitation_status": exploitation_status,
            "severity": severity,
            "discovered_at": data.get("discovered_at"),
            "disclosed_at": data.get("disclosed_at"),
            "patched_at": data.get("patched_at"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO zdi_vulnerabilities
                       (id, org_id, cve_id, title, description, cvss_score, exploitability_score,
                        affected_products, disclosure_type, patch_status, exploitation_status,
                        severity, discovered_at, disclosed_at, patched_at, created_at)
                       VALUES (:id, :org_id, :cve_id, :title, :description, :cvss_score, :exploitability_score,
                               :affected_products, :disclosure_type, :patch_status, :exploitation_status,
                               :severity, :discovered_at, :disclosed_at, :patched_at, :created_at)""",
                    record,
                )
        record["affected_products"] = affected_products
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("CVE_DISCOVERED", {
                    "org_id": org_id,
                    "entity": "zero_day_vulnerability",
                    "vuln_id": record["id"],
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss_score": record["cvss_score"],
                    "patch_status": patch_status,
                    "exploitation_status": exploitation_status,
                })
            except Exception:
                pass
        return record

    def list_vulnerabilities(
        self,
        org_id: str,
        severity: Optional[str] = None,
        patch_status: Optional[str] = None,
        exploitation_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List vulnerabilities with optional filters."""
        sql = "SELECT * FROM zdi_vulnerabilities WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if patch_status:
            sql += " AND patch_status = ?"
            params.append(patch_status)
        if exploitation_status:
            sql += " AND exploitation_status = ?"
            params.append(exploitation_status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_vulnerability(self, org_id: str, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single vulnerability by ID with org isolation."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM zdi_vulnerabilities WHERE org_id = ? AND id = ?",
                (org_id, vuln_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_patch_status(
        self,
        org_id: str,
        vuln_id: str,
        patch_status: str,
        patched_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update the patch status of a vulnerability."""
        if patch_status not in _VALID_PATCH_STATUSES:
            raise ValueError(
                f"Invalid patch_status: {patch_status}. "
                f"Must be one of {sorted(_VALID_PATCH_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE zdi_vulnerabilities SET patch_status = ?, patched_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (patch_status, patched_at, org_id, vuln_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Vulnerability {vuln_id} not found in org {org_id}")
                row = conn.execute(
                    "SELECT * FROM zdi_vulnerabilities WHERE org_id = ? AND id = ?",
                    (org_id, vuln_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Threat Actors
    # ------------------------------------------------------------------

    def record_threat_actor(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a threat actor associated with a vulnerability."""
        vulnerability_id = (data.get("vulnerability_id") or "").strip()
        if not vulnerability_id:
            raise ValueError("vulnerability_id is required.")

        actor_name = (data.get("actor_name") or "").strip()
        if not actor_name:
            raise ValueError("actor_name is required.")

        actor_type = data.get("actor_type", "unknown")
        if actor_type not in _VALID_ACTOR_TYPES:
            raise ValueError(
                f"Invalid actor_type: {actor_type}. "
                f"Must be one of {sorted(_VALID_ACTOR_TYPES)}"
            )

        confidence_score = max(0.0, min(100.0, float(data.get("confidence_score", 50.0))))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "vulnerability_id": vulnerability_id,
            "actor_name": actor_name,
            "actor_type": actor_type,
            "confidence_score": confidence_score,
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO zdi_threat_actors
                       (id, org_id, vulnerability_id, actor_name, actor_type,
                        confidence_score, first_seen, last_seen, created_at)
                       VALUES (:id, :org_id, :vulnerability_id, :actor_name, :actor_type,
                               :confidence_score, :first_seen, :last_seen, :created_at)""",
                    record,
                )
        return record

    def list_threat_actors(
        self,
        org_id: str,
        vulnerability_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threat actors with optional vulnerability filter."""
        sql = "SELECT * FROM zdi_threat_actors WHERE org_id = ?"
        params: list = [org_id]
        if vulnerability_id:
            sql += " AND vulnerability_id = ?"
            params.append(vulnerability_id)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Mitigations
    # ------------------------------------------------------------------

    def record_mitigation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a mitigation for a vulnerability."""
        vulnerability_id = (data.get("vulnerability_id") or "").strip()
        if not vulnerability_id:
            raise ValueError("vulnerability_id is required.")

        mitigation_type = data.get("mitigation_type", "workaround")
        if mitigation_type not in _VALID_MITIGATION_TYPES:
            raise ValueError(
                f"Invalid mitigation_type: {mitigation_type}. "
                f"Must be one of {sorted(_VALID_MITIGATION_TYPES)}"
            )

        status = data.get("status", "proposed")
        if status not in _VALID_MITIGATION_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. "
                f"Must be one of {sorted(_VALID_MITIGATION_STATUSES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "vulnerability_id": vulnerability_id,
            "mitigation_type": mitigation_type,
            "description": data.get("description", ""),
            "status": status,
            "applied_by": data.get("applied_by", ""),
            "applied_at": data.get("applied_at"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO zdi_mitigations
                       (id, org_id, vulnerability_id, mitigation_type, description,
                        status, applied_by, applied_at, created_at)
                       VALUES (:id, :org_id, :vulnerability_id, :mitigation_type, :description,
                               :status, :applied_by, :applied_at, :created_at)""",
                    record,
                )
        return record

    def list_mitigations(
        self,
        org_id: str,
        vulnerability_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List mitigations with optional filters."""
        sql = "SELECT * FROM zdi_mitigations WHERE org_id = ?"
        params: list = [org_id]
        if vulnerability_id:
            sql += " AND vulnerability_id = ?"
            params.append(vulnerability_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_zero_day_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated zero-day intelligence statistics."""
        with self._conn() as conn:
            total_vulns = conn.execute(
                "SELECT COUNT(*) FROM zdi_vulnerabilities WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            unpatched_count = conn.execute(
                "SELECT COUNT(*) FROM zdi_vulnerabilities WHERE org_id = ? AND patch_status = 'unpatched'",
                (org_id,),
            ).fetchone()[0]

            actively_exploited = conn.execute(
                "SELECT COUNT(*) FROM zdi_vulnerabilities WHERE org_id = ? AND exploitation_status = 'actively_exploited'",
                (org_id,),
            ).fetchone()[0]

            critical_count = conn.execute(
                "SELECT COUNT(*) FROM zdi_vulnerabilities WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            avg_cvss_row = conn.execute(
                "SELECT AVG(cvss_score) FROM zdi_vulnerabilities WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_cvss = round(float(avg_cvss_row), 2) if avg_cvss_row is not None else 0.0

            by_severity_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM zdi_vulnerabilities WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()

            by_patch_rows = conn.execute(
                "SELECT patch_status, COUNT(*) as cnt FROM zdi_vulnerabilities WHERE org_id = ? GROUP BY patch_status",
                (org_id,),
            ).fetchall()

            by_exploitation_rows = conn.execute(
                "SELECT exploitation_status, COUNT(*) as cnt FROM zdi_vulnerabilities WHERE org_id = ? GROUP BY exploitation_status",
                (org_id,),
            ).fetchall()

        return {
            "total_vulns": total_vulns,
            "unpatched_count": unpatched_count,
            "actively_exploited": actively_exploited,
            "critical_count": critical_count,
            "avg_cvss": avg_cvss,
            "by_severity": {r["severity"]: r["cnt"] for r in by_severity_rows},
            "by_patch_status": {r["patch_status"]: r["cnt"] for r in by_patch_rows},
            "by_exploitation_status": {r["exploitation_status"]: r["cnt"] for r in by_exploitation_rows},
        }
