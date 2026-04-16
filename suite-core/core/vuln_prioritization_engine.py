"""
Vulnerability Prioritization Engine — ALDECI.

Scores vulnerabilities using CVSS + EPSS + KEV + exploitability + exposure +
asset criticality, assigns priority tiers (immediate/urgent/planned/backlog),
and manages SLA assignment with automatic due-date calculation.

Multi-tenant via org_id. Thread-safe via RLock. SQLite WAL mode.
"""
from __future__ import annotations

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

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_ASSET_CRITICALITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.2,
}

_EXPLOITABILITY_WEIGHTS = {
    "weaponized": 1.0,
    "poc_available": 0.6,
    "theoretical": 0.2,
}

_EXPOSURE_WEIGHTS = {
    "internet_facing": 1.0,
    "internal": 0.5,
    "isolated": 0.1,
}

_SLA_DAYS = {
    "immediate": 7,
    "urgent": 30,
    "planned": 90,
    "backlog": 180,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> datetime:
    return datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _compute_priority_score(
    cvss: float,
    epss: float,
    kev_listed: bool,
    exploitability_weight: float,
    exposure_weight: float,
    asset_criticality_weight: float,
) -> float:
    base = (cvss / 10.0) * 0.3
    threat = epss * 0.25
    kev_bonus = 0.2 if kev_listed else 0.0
    exploit = exploitability_weight * 0.15
    exposure = exposure_weight * 0.1
    raw = base + threat + kev_bonus + exploit + exposure
    # Apply asset criticality as amplifier
    final = raw * (0.5 + asset_criticality_weight * 0.5)
    return round(min(final, 1.0), 4)


def _priority_tier(score: float) -> str:
    if score >= 0.75:
        return "immediate"
    if score >= 0.5:
        return "urgent"
    if score >= 0.25:
        return "planned"
    return "backlog"


class VulnerabilityPrioritizationEngine:
    """SQLite WAL-backed Vulnerability Prioritization engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: vuln_scores, prioritization_runs, sla_assignments.
    """

    def __init__(self, org_id: str = "default") -> None:
        self.org_id = org_id
        db_path = _DEFAULT_DB_DIR / f"{org_id}_vuln_prioritization.db"
        self.db_path = str(db_path)
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
                CREATE TABLE IF NOT EXISTS vuln_scores (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    cve_id              TEXT NOT NULL,
                    asset_id            TEXT NOT NULL,
                    asset_criticality   TEXT NOT NULL DEFAULT 'medium',
                    cvss_score          REAL NOT NULL DEFAULT 0.0,
                    epss_score          REAL NOT NULL DEFAULT 0.0,
                    kev_listed          INTEGER NOT NULL DEFAULT 0,
                    exploitability      TEXT NOT NULL DEFAULT 'theoretical',
                    exposure            TEXT NOT NULL DEFAULT 'internal',
                    priority_score      REAL NOT NULL DEFAULT 0.0,
                    priority_tier       TEXT NOT NULL DEFAULT 'backlog',
                    risk_explanation    TEXT NOT NULL DEFAULT '',
                    created_at          DATETIME NOT NULL,
                    updated_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vs_org_tier
                    ON vuln_scores (org_id, priority_tier, priority_score);

                CREATE INDEX IF NOT EXISTS idx_vs_org_kev
                    ON vuln_scores (org_id, kev_listed);

                CREATE TABLE IF NOT EXISTS prioritization_runs (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    run_name            TEXT NOT NULL DEFAULT '',
                    total_vulns         INTEGER NOT NULL DEFAULT 0,
                    immediate_count     INTEGER NOT NULL DEFAULT 0,
                    urgent_count        INTEGER NOT NULL DEFAULT 0,
                    planned_count       INTEGER NOT NULL DEFAULT 0,
                    backlog_count       INTEGER NOT NULL DEFAULT 0,
                    avg_priority_score  REAL NOT NULL DEFAULT 0.0,
                    completed_at        DATETIME NOT NULL,
                    status              TEXT NOT NULL DEFAULT 'completed'
                );

                CREATE INDEX IF NOT EXISTS idx_pr_org
                    ON prioritization_runs (org_id, completed_at);

                CREATE TABLE IF NOT EXISTS sla_assignments (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    vuln_score_id   TEXT NOT NULL,
                    cve_id          TEXT NOT NULL,
                    asset_id        TEXT NOT NULL,
                    assigned_team   TEXT NOT NULL,
                    due_date        DATETIME NOT NULL,
                    sla_days        INTEGER NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sa_org_status
                    ON sla_assignments (org_id, status, due_date);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_vulnerability(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compute priority score + tier + risk explanation, save and return."""
        cve_id = data["cve_id"]
        asset_id = data["asset_id"]
        asset_criticality = data.get("asset_criticality", "medium")
        cvss_score = float(data.get("cvss_score", 0.0))
        epss_score = float(data.get("epss_score", 0.0))
        kev_listed = bool(data.get("kev_listed", False))
        exploitability = data.get("exploitability", "theoretical")
        exposure = data.get("exposure", "internal")

        if asset_criticality not in _ASSET_CRITICALITY_WEIGHTS:
            raise ValueError(f"Invalid asset_criticality '{asset_criticality}'")
        if exploitability not in _EXPLOITABILITY_WEIGHTS:
            raise ValueError(f"Invalid exploitability '{exploitability}'")
        if exposure not in _EXPOSURE_WEIGHTS:
            raise ValueError(f"Invalid exposure '{exposure}'")

        ac_weight = _ASSET_CRITICALITY_WEIGHTS[asset_criticality]
        exp_weight = _EXPLOITABILITY_WEIGHTS[exploitability]
        ex_weight = _EXPOSURE_WEIGHTS[exposure]

        priority_score = _compute_priority_score(
            cvss_score, epss_score, kev_listed, exp_weight, ex_weight, ac_weight
        )
        tier = _priority_tier(priority_score)

        if kev_listed:
            threat_str = "active KEV exploitation"
        else:
            threat_str = f"EPSS {epss_score:.1%} threat probability"

        risk_explanation = (
            f"CVSS {cvss_score}/10 with {threat_str}. "
            f"Asset criticality: {asset_criticality}. Priority: {tier}."
        )

        now_str = _now()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cve_id": cve_id,
            "asset_id": asset_id,
            "asset_criticality": asset_criticality,
            "cvss_score": cvss_score,
            "epss_score": epss_score,
            "kev_listed": int(kev_listed),
            "exploitability": exploitability,
            "exposure": exposure,
            "priority_score": priority_score,
            "priority_tier": tier,
            "risk_explanation": risk_explanation,
            "created_at": now_str,
            "updated_at": now_str,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO vuln_scores
                       (id, org_id, cve_id, asset_id, asset_criticality,
                        cvss_score, epss_score, kev_listed, exploitability, exposure,
                        priority_score, priority_tier, risk_explanation, created_at, updated_at)
                       VALUES (:id, :org_id, :cve_id, :asset_id, :asset_criticality,
                               :cvss_score, :epss_score, :kev_listed, :exploitability, :exposure,
                               :priority_score, :priority_tier, :risk_explanation, :created_at, :updated_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "vuln_prioritization", "org_id": org_id, "source_engine": "vuln_prioritization"})
            except Exception:
                pass

        return record

    def batch_score(self, org_id: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Score multiple vulnerabilities, create a run record, return summary."""
        scored = []
        by_tier: Dict[str, int] = {"immediate": 0, "urgent": 0, "planned": 0, "backlog": 0}

        for vuln in vulnerabilities:
            try:
                result = self.score_vulnerability(org_id, vuln)
                scored.append(result)
                by_tier[result["priority_tier"]] = by_tier.get(result["priority_tier"], 0) + 1
            except Exception as exc:
                _logger.warning("batch_score: skipping vuln due to error: %s", exc)

        avg_score = round(sum(r["priority_score"] for r in scored) / max(len(scored), 1), 4)
        run_id = str(uuid.uuid4())
        now_str = _now()

        run_record = {
            "id": run_id,
            "org_id": org_id,
            "run_name": f"batch-{now_str[:10]}",
            "total_vulns": len(scored),
            "immediate_count": by_tier["immediate"],
            "urgent_count": by_tier["urgent"],
            "planned_count": by_tier["planned"],
            "backlog_count": by_tier["backlog"],
            "avg_priority_score": avg_score,
            "completed_at": now_str,
            "status": "completed",
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO prioritization_runs
                       (id, org_id, run_name, total_vulns, immediate_count, urgent_count,
                        planned_count, backlog_count, avg_priority_score, completed_at, status)
                       VALUES (:id, :org_id, :run_name, :total_vulns, :immediate_count, :urgent_count,
                               :planned_count, :backlog_count, :avg_priority_score, :completed_at, :status)""",
                    run_record,
                )

        return {
            "run_id": run_id,
            "scored_count": len(scored),
            "by_tier": by_tier,
        }

    # ------------------------------------------------------------------
    # Query scored vulns
    # ------------------------------------------------------------------

    def list_scored(
        self,
        org_id: str,
        priority_tier: Optional[str] = None,
        kev_only: bool = False,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List scored vulnerabilities, optionally filtered."""
        query = "SELECT * FROM vuln_scores WHERE org_id = ?"
        params: List[Any] = [org_id]
        if priority_tier:
            query += " AND priority_tier = ?"
            params.append(priority_tier)
        if kev_only:
            query += " AND kev_listed = 1"
        query += " ORDER BY priority_score DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_score(self, org_id: str, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Get a single scored vulnerability by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM vuln_scores WHERE id = ? AND org_id = ?",
                    (vuln_id, org_id),
                ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # SLA assignments
    # ------------------------------------------------------------------

    def assign_sla(self, org_id: str, vuln_id: str, assigned_team: str) -> Dict[str, Any]:
        """Assign SLA to a scored vulnerability, calculate due_date from tier."""
        vuln = self.get_score(org_id, vuln_id)
        if not vuln:
            raise ValueError(f"Vulnerability '{vuln_id}' not found for org '{org_id}'")

        tier = vuln["priority_tier"]
        sla_days = _SLA_DAYS.get(tier, 90)
        due_date = (_today() + timedelta(days=sla_days)).isoformat()
        now_str = _now()

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "vuln_score_id": vuln_id,
            "cve_id": vuln["cve_id"],
            "asset_id": vuln["asset_id"],
            "assigned_team": assigned_team,
            "due_date": due_date,
            "sla_days": sla_days,
            "status": "pending",
            "created_at": now_str,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sla_assignments
                       (id, org_id, vuln_score_id, cve_id, asset_id,
                        assigned_team, due_date, sla_days, status, created_at)
                       VALUES (:id, :org_id, :vuln_score_id, :cve_id, :asset_id,
                               :assigned_team, :due_date, :sla_days, :status, :created_at)""",
                    record,
                )
        return record

    def list_sla_assignments(
        self,
        org_id: str,
        status: Optional[str] = None,
        team: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List SLA assignments, optionally filtered by status or team."""
        query = "SELECT * FROM sla_assignments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        if team:
            query += " AND assigned_team = ?"
            params.append(team)
        query += " ORDER BY due_date ASC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------

    def get_run(self, org_id: str, run_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific prioritization run."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM prioritization_runs WHERE id = ? AND org_id = ?",
                    (run_id, org_id),
                ).fetchone()
        return dict(row) if row else None

    def list_runs(self, org_id: str) -> List[Dict[str, Any]]:
        """List all prioritization runs for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM prioritization_runs WHERE org_id = ? ORDER BY completed_at DESC",
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def bulk_score_vulnerabilities(
        self, org_id: str, vulns_list: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Score multiple vulnerabilities at once and return all results.

        Unlike batch_score, this returns the full scored records list
        instead of just a summary run record.
        """
        results = []
        for vuln in vulns_list:
            try:
                scored = self.score_vulnerability(org_id, vuln)
                results.append(scored)
            except Exception as exc:
                _logger.warning("bulk_score_vulnerabilities: skipping due to error: %s", exc)
        return results

    def get_top_critical(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the top N vulnerabilities by composite priority score."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT * FROM vuln_scores
                       WHERE org_id = ?
                       ORDER BY priority_score DESC
                       LIMIT ?""",
                    (org_id, limit),
                ).fetchall()
        return [dict(r) for r in rows]

    def export_prioritized_csv(self, org_id: str) -> str:
        """Return all scored vulnerabilities as a CSV string ordered by priority.

        Columns: id, cve_id, asset_id, asset_criticality, cvss_score,
                 epss_score, kev_listed, exploitability, exposure,
                 priority_score, priority_tier, risk_explanation, created_at
        """
        import csv
        import io

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT id, cve_id, asset_id, asset_criticality,
                              cvss_score, epss_score, kev_listed,
                              exploitability, exposure, priority_score,
                              priority_tier, risk_explanation, created_at
                       FROM vuln_scores
                       WHERE org_id = ?
                       ORDER BY priority_score DESC""",
                    (org_id,),
                ).fetchall()

        buf = io.StringIO()
        fieldnames = [
            "id", "cve_id", "asset_id", "asset_criticality",
            "cvss_score", "epss_score", "kev_listed",
            "exploitability", "exposure", "priority_score",
            "priority_tier", "risk_explanation", "created_at",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(dict(row))
        return buf.getvalue()

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return high-level prioritization stats for an org."""
        today_str = _today().isoformat()

        with self._lock:
            with self._conn() as conn:
                # Total scored
                total_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM vuln_scores WHERE org_id = ?", (org_id,)
                ).fetchone()

                # By tier
                tier_rows = conn.execute(
                    """SELECT priority_tier, COUNT(*) as cnt
                       FROM vuln_scores WHERE org_id = ?
                       GROUP BY priority_tier""",
                    (org_id,),
                ).fetchall()

                # KEV count
                kev_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM vuln_scores WHERE org_id = ? AND kev_listed = 1",
                    (org_id,),
                ).fetchone()

                # Avg priority score
                avg_row = conn.execute(
                    "SELECT AVG(priority_score) as avg FROM vuln_scores WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                # SLA breached count
                breach_row = conn.execute(
                    """SELECT COUNT(*) as cnt FROM sla_assignments
                       WHERE org_id = ? AND due_date < ? AND status != 'completed'""",
                    (org_id, today_str),
                ).fetchone()

                # Upcoming due (next 5)
                upcoming_rows = conn.execute(
                    """SELECT * FROM sla_assignments
                       WHERE org_id = ? AND status IN ('pending', 'in_progress')
                       ORDER BY due_date ASC LIMIT 5""",
                    (org_id,),
                ).fetchall()

        by_tier = {r["priority_tier"]: r["cnt"] for r in tier_rows}

        return {
            "total_scored": total_row["cnt"] if total_row else 0,
            "by_tier": by_tier,
            "kev_count": kev_row["cnt"] if kev_row else 0,
            "avg_priority_score": round(float(avg_row["avg"] or 0.0), 4) if avg_row else 0.0,
            "sla_breached_count": breach_row["cnt"] if breach_row else 0,
            "upcoming_due": [dict(r) for r in upcoming_rows],
        }


# Module-level singleton (per-org)
_engines: Dict[str, VulnerabilityPrioritizationEngine] = {}
_engines_lock = threading.Lock()


def get_engine(org_id: str = "default") -> VulnerabilityPrioritizationEngine:
    with _engines_lock:
        if org_id not in _engines:
            _engines[org_id] = VulnerabilityPrioritizationEngine(org_id=org_id)
        return _engines[org_id]
