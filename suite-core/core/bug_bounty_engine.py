"""Bug Bounty Engine — ALDECI.

Manages bug bounty programs, researcher reports, and payout tracking.

Capabilities:
  - Program registry (HackerOne, Bugcrowd, Intigriti, YesWeHack, private)
  - Report ingestion with vulnerability classification and severity
  - Report status lifecycle (new → triaging → triaged → resolved → rewarded)
  - Payout tracking with automatic program total + researcher stats updates
  - Researcher registry with hall of fame, reputation, and earnings
  - Stats aggregation per org

Compliance: CVSS v3.1, CWE/NVD taxonomy, ISO/IEC 29147 (vulnerability disclosure)
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "yeswehack", "private"}
_VALID_PROGRAM_STATUSES = {"active", "paused", "private", "public"}

_VALID_VULN_CLASSES = {
    "xss", "sqli", "ssrf", "idor", "rce", "lfi", "csrf",
    "auth_bypass", "info_disclosure", "dos", "other",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_REPORT_STATUSES = {
    "new", "triaging", "triaged", "duplicate", "na",
    "resolved", "rewarded", "closed",
}
_VALID_BOUNTY_DECISIONS = {"pending", "approved", "rejected"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BugBountyEngine:
    """SQLite WAL-backed Bug Bounty engine.

    Thread-safe via RLock. Multi-tenant via org_id — each org gets its own DB.
    """

    def __init__(self, org_id: str = "default", db_dir: str = _DEFAULT_DB_DIR) -> None:
        self.org_id = org_id
        db_path = str(Path(db_dir) / f"{org_id}_bug_bounty.db")
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
                CREATE TABLE IF NOT EXISTS programs (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    program_name         TEXT NOT NULL,
                    platform             TEXT NOT NULL DEFAULT 'private',
                    scope_description    TEXT NOT NULL DEFAULT '',
                    in_scope_assets      TEXT NOT NULL DEFAULT '[]',
                    out_of_scope_assets  TEXT NOT NULL DEFAULT '[]',
                    min_payout_usd       REAL NOT NULL DEFAULT 0.0,
                    max_payout_usd       REAL NOT NULL DEFAULT 0.0,
                    status               TEXT NOT NULL DEFAULT 'active',
                    total_paid_usd       REAL NOT NULL DEFAULT 0.0,
                    program_start_date   TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_programs_org
                    ON programs (org_id, status);

                CREATE TABLE IF NOT EXISTS reports (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    program_id           TEXT NOT NULL,
                    external_report_id   TEXT NOT NULL DEFAULT '',
                    researcher_handle    TEXT NOT NULL DEFAULT '',
                    title                TEXT NOT NULL,
                    vulnerability_class  TEXT NOT NULL DEFAULT 'other',
                    severity             TEXT NOT NULL DEFAULT 'medium',
                    cvss_score           REAL NOT NULL DEFAULT 0.0,
                    affected_asset       TEXT NOT NULL DEFAULT '',
                    description          TEXT NOT NULL DEFAULT '',
                    reproduction_steps   TEXT NOT NULL DEFAULT '',
                    status               TEXT NOT NULL DEFAULT 'new',
                    submitted_at         DATETIME NOT NULL,
                    triaged_at           DATETIME,
                    resolved_at          DATETIME,
                    payout_usd           REAL NOT NULL DEFAULT 0.0,
                    bounty_decision      TEXT NOT NULL DEFAULT 'pending'
                );

                CREATE INDEX IF NOT EXISTS idx_reports_org_program
                    ON reports (org_id, program_id, submitted_at DESC);

                CREATE INDEX IF NOT EXISTS idx_reports_org_status
                    ON reports (org_id, status);

                CREATE TABLE IF NOT EXISTS researchers (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    handle           TEXT NOT NULL,
                    reputation_score REAL NOT NULL DEFAULT 0.0,
                    total_reports    INTEGER NOT NULL DEFAULT 0,
                    valid_reports    INTEGER NOT NULL DEFAULT 0,
                    total_earned_usd REAL NOT NULL DEFAULT 0.0,
                    hall_of_fame     INTEGER NOT NULL DEFAULT 0,
                    skills           TEXT NOT NULL DEFAULT '[]',
                    country          TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_researchers_org
                    ON researchers (org_id, valid_reports DESC);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_researchers_handle
                    ON researchers (org_id, handle);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialize JSON list fields
        for field in ("in_scope_assets", "out_of_scope_assets", "skills"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        # Convert hall_of_fame int to bool
        if "hall_of_fame" in d:
            d["hall_of_fame"] = bool(d["hall_of_fame"])
        return d

    # ------------------------------------------------------------------
    # Programs
    # ------------------------------------------------------------------

    def create_program(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new bug bounty program."""
        program_name = (data.get("program_name") or "").strip()
        if not program_name:
            raise ValueError("program_name is required.")

        platform = data.get("platform", "private")
        if platform not in _VALID_PLATFORMS:
            raise ValueError(f"Invalid platform: {platform}. Must be one of {_VALID_PLATFORMS}")

        status = data.get("status", "active")
        if status not in _VALID_PROGRAM_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_PROGRAM_STATUSES}")

        in_scope = data.get("in_scope_assets", [])
        out_scope = data.get("out_of_scope_assets", [])

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "program_name": program_name,
            "platform": platform,
            "scope_description": data.get("scope_description", ""),
            "in_scope_assets": json.dumps(in_scope if isinstance(in_scope, list) else []),
            "out_of_scope_assets": json.dumps(out_scope if isinstance(out_scope, list) else []),
            "min_payout_usd": float(data.get("min_payout_usd", 0.0)),
            "max_payout_usd": float(data.get("max_payout_usd", 0.0)),
            "status": status,
            "total_paid_usd": 0.0,
            "program_start_date": data.get("program_start_date", ""),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO programs
                       (id, org_id, program_name, platform, scope_description, in_scope_assets,
                        out_of_scope_assets, min_payout_usd, max_payout_usd, status,
                        total_paid_usd, program_start_date)
                       VALUES (:id, :org_id, :program_name, :platform, :scope_description,
                               :in_scope_assets, :out_of_scope_assets, :min_payout_usd,
                               :max_payout_usd, :status, :total_paid_usd, :program_start_date)""",
                    record,
                )
        # Return with deserialized lists
        record["in_scope_assets"] = in_scope if isinstance(in_scope, list) else []
        record["out_of_scope_assets"] = out_scope if isinstance(out_scope, list) else []
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "bug_bounty", "org_id": org_id, "source_engine": "bug_bounty"})
            except Exception:
                pass

        return record

    def list_programs(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List programs, optionally filtered by status."""
        sql = "SELECT * FROM programs WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY program_name ASC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_program(self, org_id: str, program_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single program with report stats."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM programs WHERE org_id = ? AND id = ?",
                (org_id, program_id),
            ).fetchone()
            if not row:
                return None
            record = self._row(row)

            # Attach report stats
            stats_rows = conn.execute(
                """SELECT status, COUNT(*) as cnt FROM reports
                   WHERE org_id = ? AND program_id = ? GROUP BY status""",
                (org_id, program_id),
            ).fetchall()
            record["reports_by_status"] = {r["status"]: r["cnt"] for r in stats_rows}

            total_reports = conn.execute(
                "SELECT COUNT(*) FROM reports WHERE org_id = ? AND program_id = ?",
                (org_id, program_id),
            ).fetchone()[0]
            record["total_reports"] = total_reports
        return record

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def submit_report(self, org_id: str, program_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a new vulnerability report."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        vuln_class = data.get("vulnerability_class", "other")
        if vuln_class not in _VALID_VULN_CLASSES:
            raise ValueError(f"Invalid vulnerability_class: {vuln_class}. Must be one of {_VALID_VULN_CLASSES}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}. Must be one of {_VALID_SEVERITIES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "program_id": program_id,
            "external_report_id": data.get("external_report_id", ""),
            "researcher_handle": data.get("researcher_handle", ""),
            "title": title,
            "vulnerability_class": vuln_class,
            "severity": severity,
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "affected_asset": data.get("affected_asset", ""),
            "description": data.get("description", ""),
            "reproduction_steps": data.get("reproduction_steps", ""),
            "status": "new",
            "submitted_at": now,
            "triaged_at": None,
            "resolved_at": None,
            "payout_usd": 0.0,
            "bounty_decision": "pending",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO reports
                       (id, org_id, program_id, external_report_id, researcher_handle,
                        title, vulnerability_class, severity, cvss_score, affected_asset,
                        description, reproduction_steps, status, submitted_at, triaged_at,
                        resolved_at, payout_usd, bounty_decision)
                       VALUES (:id, :org_id, :program_id, :external_report_id, :researcher_handle,
                               :title, :vulnerability_class, :severity, :cvss_score, :affected_asset,
                               :description, :reproduction_steps, :status, :submitted_at, :triaged_at,
                               :resolved_at, :payout_usd, :bounty_decision)""",
                    record,
                )
        return record

    def list_reports(
        self,
        org_id: str,
        program_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List reports with optional filters."""
        sql = "SELECT * FROM reports WHERE org_id = ?"
        params: list = [org_id]
        if program_id:
            sql += " AND program_id = ?"
            params.append(program_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY submitted_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_report(self, org_id: str, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single report by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE org_id = ? AND id = ?",
                (org_id, report_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_report_status(
        self,
        org_id: str,
        report_id: str,
        status: str,
        payout_usd: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Update report status and optionally set payout.

        Auto-updates:
          - program.total_paid_usd when payout is approved
          - researcher.total_reports, valid_reports, total_earned_usd
        """
        if status not in _VALID_REPORT_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_REPORT_STATUSES}")

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                # Fetch current report
                row = conn.execute(
                    "SELECT * FROM reports WHERE org_id = ? AND id = ?",
                    (org_id, report_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Report {report_id} not found.")
                report = self._row(row)

                # Build update fields
                updates: Dict[str, Any] = {"status": status}
                if status == "triaged" and not report.get("triaged_at"):
                    updates["triaged_at"] = now
                if status in ("resolved", "rewarded") and not report.get("resolved_at"):
                    updates["resolved_at"] = now

                payout_amount = float(payout_usd) if payout_usd is not None else None
                if payout_amount is not None:
                    updates["payout_usd"] = payout_amount
                    if status == "rewarded":
                        updates["bounty_decision"] = "approved"

                # Construct SET clause
                set_clauses = ", ".join(f"{k} = ?" for k in updates)
                values = list(updates.values()) + [org_id, report_id]
                conn.execute(
                    f"UPDATE reports SET {set_clauses} WHERE org_id = ? AND id = ?",  # nosec B608
                    values,
                )

                # Update program total_paid_usd if paying out
                if payout_amount and payout_amount > 0 and status == "rewarded":
                    prev_payout = float(report.get("payout_usd", 0.0))
                    delta = payout_amount - prev_payout
                    if delta > 0:
                        conn.execute(
                            "UPDATE programs SET total_paid_usd = total_paid_usd + ? WHERE org_id = ? AND id = ?",
                            (delta, org_id, report["program_id"]),
                        )

                # Update researcher stats if handle is set
                handle = report.get("researcher_handle", "")
                if handle:
                    is_valid = status in ("triaged", "resolved", "rewarded")
                    researcher_row = conn.execute(
                        "SELECT * FROM researchers WHERE org_id = ? AND handle = ?",
                        (org_id, handle),
                    ).fetchone()
                    if researcher_row:
                        res = self._row(researcher_row)
                        new_total = res["total_reports"] + 1 if status == "new" else res["total_reports"]
                        new_valid = res["valid_reports"] + (1 if is_valid and status != report.get("status") else 0)
                        new_earned = res["total_earned_usd"] + (payout_amount or 0.0) if status == "rewarded" else res["total_earned_usd"]
                        conn.execute(
                            """UPDATE researchers SET total_reports = ?, valid_reports = ?, total_earned_usd = ?
                               WHERE org_id = ? AND handle = ?""",
                            (new_total, new_valid, new_earned, org_id, handle),
                        )

                # Fetch updated record
                updated_row = conn.execute(
                    "SELECT * FROM reports WHERE org_id = ? AND id = ?",
                    (org_id, report_id),
                ).fetchone()
        return self._row(updated_row)

    # ------------------------------------------------------------------
    # Researchers
    # ------------------------------------------------------------------

    def add_researcher(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new researcher to the registry."""
        handle = (data.get("handle") or "").strip()
        if not handle:
            raise ValueError("handle is required.")

        skills = data.get("skills", [])
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "handle": handle,
            "reputation_score": float(data.get("reputation_score", 0.0)),
            "total_reports": int(data.get("total_reports", 0)),
            "valid_reports": int(data.get("valid_reports", 0)),
            "total_earned_usd": float(data.get("total_earned_usd", 0.0)),
            "hall_of_fame": 1 if data.get("hall_of_fame", False) else 0,
            "skills": json.dumps(skills if isinstance(skills, list) else []),
            "country": data.get("country", ""),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO researchers
                       (id, org_id, handle, reputation_score, total_reports, valid_reports,
                        total_earned_usd, hall_of_fame, skills, country)
                       VALUES (:id, :org_id, :handle, :reputation_score, :total_reports,
                               :valid_reports, :total_earned_usd, :hall_of_fame, :skills, :country)""",
                    record,
                )
        record["skills"] = skills if isinstance(skills, list) else []
        record["hall_of_fame"] = bool(record["hall_of_fame"])
        return record

    def list_researchers(
        self, org_id: str, hall_of_fame: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List researchers, optionally filtered to hall of fame members."""
        sql = "SELECT * FROM researchers WHERE org_id = ?"
        params: list = [org_id]
        if hall_of_fame is not None:
            sql += " AND hall_of_fame = ?"
            params.append(1 if hall_of_fame else 0)
        sql += " ORDER BY valid_reports DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated Bug Bounty stats for org."""
        with self._conn() as conn:
            program_count = conn.execute(
                "SELECT COUNT(*) FROM programs WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_reports = conn.execute(
                "SELECT COUNT(*) FROM reports WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_paid = conn.execute(
                "SELECT SUM(total_paid_usd) FROM programs WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            total_paid_usd = round(float(total_paid or 0.0), 2)

            # Reports by severity
            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM reports
                   WHERE org_id = ? GROUP BY severity""",
                (org_id,),
            ).fetchall()
            reports_by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            # Average resolution days (submitted_at → resolved_at)
            res_rows = conn.execute(
                """SELECT submitted_at, resolved_at FROM reports
                   WHERE org_id = ? AND resolved_at IS NOT NULL""",
                (org_id,),
            ).fetchall()
            if res_rows:
                total_days = 0.0
                count = 0
                for r in res_rows:
                    try:
                        sub = datetime.fromisoformat(r["submitted_at"].replace("Z", "+00:00"))
                        res = datetime.fromisoformat(r["resolved_at"].replace("Z", "+00:00"))
                        total_days += (res - sub).total_seconds() / 86400.0
                        count += 1
                    except Exception:
                        pass
                avg_resolution_days = round(total_days / count, 1) if count else 0.0
            else:
                avg_resolution_days = 0.0

            # Top 5 researchers by valid reports
            top_rows = conn.execute(
                """SELECT id, handle, reputation_score, total_reports, valid_reports,
                          total_earned_usd, hall_of_fame, country
                   FROM researchers WHERE org_id = ?
                   ORDER BY valid_reports DESC LIMIT 5""",
                (org_id,),
            ).fetchall()
            top_researchers = [dict(r) for r in top_rows]
            for r in top_researchers:
                r["hall_of_fame"] = bool(r["hall_of_fame"])

        return {
            "program_count": program_count,
            "total_reports": total_reports,
            "reports_by_severity": reports_by_severity,
            "total_paid_usd": total_paid_usd,
            "avg_resolution_days": avg_resolution_days,
            "top_researchers": top_researchers,
        }
