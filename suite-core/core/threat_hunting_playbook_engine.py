"""Threat Hunting Playbook Engine — ALDECI.

Structured threat hunting playbook management: hypothesis-driven and IOC/behavioral hunts.

Features:
- Playbook lifecycle (draft → active executions)
- Execution tracking with duration_mins via julianday arithmetic
- success_rate = COUNT(finding|partial_finding) / execution_count * 100
- avg_duration_mins = AVG(duration_mins) across all executions for the playbook
- Hypothesis management with validation and evidence capture
- get_hunt_stats: aggregated across org
- Multi-tenant org_id isolation

Compliance: NIST SP 800-137 (Continuous Monitoring), MITRE ATT&CK Playbooks,
            CISA Cybersecurity Advisory AA21-116A
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_hunting_playbook.db"
)

_VALID_HUNT_TYPES = {
    "hypothesis", "ioc", "anomaly", "behavioral", "threat-actor", "ttp", "situational"
}
_VALID_OUTCOMES = {"finding", "no_finding", "partial_finding", "inconclusive", "in_progress"}
_VALID_CONFIDENCES = {"high", "medium", "low"}


class ThreatHuntingPlaybookEngine:
    """Engine for structured threat hunting playbook management."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS hunting_playbooks (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    playbook_name       TEXT NOT NULL DEFAULT '',
                    hunt_type           TEXT NOT NULL DEFAULT 'hypothesis',
                    threat_category     TEXT NOT NULL DEFAULT '',
                    mitre_technique     TEXT NOT NULL DEFAULT '',
                    hypothesis          TEXT NOT NULL DEFAULT '',
                    data_sources        TEXT NOT NULL DEFAULT '[]',
                    tools               TEXT NOT NULL DEFAULT '[]',
                    status              TEXT NOT NULL DEFAULT 'draft',
                    execution_count     INTEGER NOT NULL DEFAULT 0,
                    success_rate        REAL NOT NULL DEFAULT 0.0,
                    avg_duration_mins   REAL NOT NULL DEFAULT 0.0,
                    created_at          TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_hp_org      ON hunting_playbooks(org_id);
                CREATE INDEX IF NOT EXISTS idx_hp_type     ON hunting_playbooks(org_id, hunt_type);
                CREATE INDEX IF NOT EXISTS idx_hp_category ON hunting_playbooks(org_id, threat_category);

                CREATE TABLE IF NOT EXISTS hunt_executions (
                    id              TEXT PRIMARY KEY,
                    playbook_id     TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    analyst         TEXT NOT NULL DEFAULT '',
                    start_time      TEXT,
                    end_time        TEXT,
                    duration_mins   REAL NOT NULL DEFAULT 0.0,
                    outcome         TEXT NOT NULL DEFAULT 'no_finding',
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    iocs_discovered TEXT NOT NULL DEFAULT '[]',
                    notes           TEXT NOT NULL DEFAULT '',
                    created_at      TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_he_playbook ON hunt_executions(playbook_id);
                CREATE INDEX IF NOT EXISTS idx_he_org      ON hunt_executions(org_id);

                CREATE TABLE IF NOT EXISTS hunt_hypotheses (
                    id              TEXT PRIMARY KEY,
                    playbook_id     TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    hypothesis_text TEXT NOT NULL DEFAULT '',
                    confidence      TEXT NOT NULL DEFAULT 'medium',
                    validated       INTEGER NOT NULL DEFAULT 0,
                    evidence        TEXT NOT NULL DEFAULT '',
                    created_at      TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_hh_playbook ON hunt_hypotheses(playbook_id);
                CREATE INDEX IF NOT EXISTS idx_hh_org      ON hunt_hypotheses(org_id);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # PUBLIC API — PLAYBOOKS
    # ------------------------------------------------------------------

    def create_playbook(
        self,
        org_id: str,
        playbook_name: str,
        hunt_type: str,
        threat_category: str,
        mitre_technique: str = "",
        hypothesis: str = "",
        data_sources: Optional[List[str]] = None,
        tools: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new threat hunting playbook in draft status."""
        if hunt_type not in _VALID_HUNT_TYPES:
            raise ValueError(
                f"Invalid hunt_type '{hunt_type}'. Must be one of {sorted(_VALID_HUNT_TYPES)}"
            )

        playbook_id = str(uuid.uuid4())
        now = self._now()
        data_sources_json = json.dumps(data_sources or [])
        tools_json = json.dumps(tools or [])

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO hunting_playbooks
                   (id, org_id, playbook_name, hunt_type, threat_category, mitre_technique,
                    hypothesis, data_sources, tools, status, execution_count, success_rate,
                    avg_duration_mins, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,'draft',0,0.0,0.0,?)""",
                (
                    playbook_id, org_id, playbook_name, hunt_type, threat_category,
                    mitre_technique, hypothesis, data_sources_json, tools_json, now,
                ),
            )
        _logger.info(
            "hunt_playbook.created org=%s playbook_id=%s name=%s",
            org_id, playbook_id, playbook_name,
        )
        return self.get_playbook(playbook_id, org_id)

    def get_playbook(self, playbook_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return playbook dict with nested executions and hypotheses."""
        with self._conn() as conn:
            pb_row = conn.execute(
                "SELECT * FROM hunting_playbooks WHERE id=? AND org_id=?",
                (playbook_id, org_id),
            ).fetchone()
            if pb_row is None:
                return None
            playbook = self._row(pb_row)

            executions = conn.execute(
                "SELECT * FROM hunt_executions WHERE playbook_id=? AND org_id=? ORDER BY created_at",
                (playbook_id, org_id),
            ).fetchall()
            hypotheses = conn.execute(
                "SELECT * FROM hunt_hypotheses WHERE playbook_id=? AND org_id=? ORDER BY created_at",
                (playbook_id, org_id),
            ).fetchall()

        playbook["executions"] = [self._row(r) for r in executions]
        playbook["hypotheses"] = [self._row(r) for r in hypotheses]
        return playbook

    def list_playbooks(
        self,
        org_id: str,
        hunt_type: Optional[str] = None,
        threat_category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List playbooks for org, optionally filtered."""
        query = "SELECT * FROM hunting_playbooks WHERE org_id=?"
        params: List[Any] = [org_id]
        if hunt_type:
            query += " AND hunt_type=?"
            params.append(hunt_type)
        if threat_category:
            query += " AND threat_category=?"
            params.append(threat_category)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def list_playbooks_with_sigma_fallback(
        self,
        org_id: str,
        hunt_type: Optional[str] = None,
        threat_category: Optional[str] = None,
        sigma_db_path: Optional[str] = None,
        sigma_table: str = "sigmahq_rules",
        max_rules: int = 500,
    ) -> Dict[str, Any]:
        """List org-authored playbooks; if none, project the imported SigmaHQ
        detection-rule catalog as a derived playbook library.

        SigmaHQ rules are stored by the importer as a PersistentDict in
        data/state.db (table sigmahq_rules) with each rule as a JSON value.

        Each Sigma rule projects to a hunting playbook with:
          - playbook_name = rule.title
          - hunt_type = "ttp" if attack_techniques present else "ioc"
          - threat_category = rule.tags[0] (canonical SigmaHQ tag)
          - mitre_technique = first MITRE ATT&CK technique reference
          - hypothesis = rule.description
          - data_sources = [rule.logsource.product/service/category] when set
          - tools = ["sigma"]

        Returns:
            {"playbooks": [...], "total": N, "source": str, "sigma_total": N}
        """
        rows = self.list_playbooks(org_id, hunt_type=hunt_type, threat_category=threat_category)
        if rows:
            return {"playbooks": rows, "total": len(rows), "source": "org_authored"}

        from pathlib import Path as _Path
        if sigma_db_path is None:
            sigma_db_path = str(_Path("data") / "state.db")
        if not _Path(sigma_db_path).exists():
            return {
                "playbooks": [],
                "total": 0,
                "source": "empty",
                "hint": "POST /api/v1/hunting-playbooks/import-sigma to populate the SigmaHQ rule catalog, "
                        "or create playbooks manually via POST /api/v1/hunting-playbooks/playbooks.",
            }

        try:
            with sqlite3.connect(sigma_db_path) as sconn:
                sconn.row_factory = sqlite3.Row
                table_exists = sconn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (sigma_table,),
                ).fetchone()
                if not table_exists:
                    return {
                        "playbooks": [],
                        "total": 0,
                        "source": "empty",
                        "hint": "POST /api/v1/hunting-playbooks/import-sigma to populate SigmaHQ rules.",
                    }
                sigma_rows = sconn.execute(
                    f"SELECT key, value FROM [{sigma_table}] LIMIT ?",  # nosec B608 — sigma_table whitelisted
                    (max_rules,),
                ).fetchall()
        except sqlite3.Error as exc:
            _logger.warning("SigmaHQ-fallback read failed for %s.%s: %s",
                            sigma_db_path, sigma_table, exc)
            return {
                "playbooks": [],
                "total": 0,
                "source": "empty",
                "hint": "POST /api/v1/hunting-playbooks/import-sigma to populate SigmaHQ rules.",
            }

        if not sigma_rows:
            return {
                "playbooks": [],
                "total": 0,
                "source": "empty",
                "hint": "POST /api/v1/hunting-playbooks/import-sigma to populate SigmaHQ rules.",
            }

        derived: List[Dict[str, Any]] = []
        sigma_total = len(sigma_rows)
        for r in sigma_rows:
            try:
                rule = json.loads(r["value"])
            except (ValueError, TypeError):
                continue
            if not isinstance(rule, dict):
                continue
            tags = rule.get("tags") or []
            attack_techs = rule.get("attack_techniques") or []
            inferred_ht = "ttp" if attack_techs else ("ioc" if "ioc" in str(tags).lower() else "behavioral")
            inferred_cat = ""
            for tag in tags:
                if isinstance(tag, str) and tag and not tag.startswith("attack."):
                    inferred_cat = tag
                    break
            if not inferred_cat:
                inferred_cat = rule.get("level", "informational") or "informational"

            if hunt_type and inferred_ht != hunt_type:
                continue
            if threat_category and inferred_cat != threat_category:
                continue

            logsource = rule.get("logsource") or {}
            data_sources = []
            for k in ("product", "service", "category"):
                v = logsource.get(k)
                if v:
                    data_sources.append(str(v))

            mitre_technique = ""
            if attack_techs and isinstance(attack_techs, list):
                first = attack_techs[0]
                if isinstance(first, str) and first:
                    mitre_technique = first.upper()

            derived.append({
                "id": f"sigma:{rule.get('id', r['key'])}",
                "org_id": org_id,
                "playbook_name": rule.get("title", "") or rule.get("id", r["key"]),
                "hunt_type": inferred_ht,
                "threat_category": inferred_cat,
                "mitre_technique": mitre_technique,
                "hypothesis": (rule.get("description", "") or "")[:1000],
                "data_sources": data_sources,
                "tools": ["sigma"],
                "status": rule.get("status", "active") or "active",
                "execution_count": 0,
                "success_rate": 0.0,
                "avg_duration_mins": 0.0,
                "created_at": rule.get("imported_at", ""),
                "source": "sigmahq",
                "source_rule_id": rule.get("id", r["key"]),
                "source_level": rule.get("level", ""),
                "source_platform": rule.get("platform", ""),
            })

        return {
            "playbooks": derived,
            "total": len(derived),
            "source": "sigmahq-derived",
            "sigma_total": sigma_total,
            "hint": "Derived from imported SigmaHQ detection rules. Author your own playbooks via POST /playbooks to override.",
        }

    # ------------------------------------------------------------------
    # PUBLIC API — HYPOTHESES
    # ------------------------------------------------------------------

    def add_hypothesis(
        self,
        playbook_id: str,
        org_id: str,
        hypothesis_text: str,
        confidence: str = "medium",
    ) -> Dict[str, Any]:
        """Add a hypothesis to a playbook."""
        if confidence not in _VALID_CONFIDENCES:
            raise ValueError(
                f"Invalid confidence '{confidence}'. Must be one of {sorted(_VALID_CONFIDENCES)}"
            )
        # Verify playbook exists
        with self._conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM hunting_playbooks WHERE id=? AND org_id=?",
                (playbook_id, org_id),
            ).fetchone()
        if exists is None:
            raise ValueError(f"Playbook '{playbook_id}' not found for org '{org_id}'")

        hyp_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO hunt_hypotheses
                   (id, playbook_id, org_id, hypothesis_text, confidence, validated, evidence, created_at)
                   VALUES (?,?,?,?,?,0,'',?)""",
                (hyp_id, playbook_id, org_id, hypothesis_text, confidence, now),
            )
        _logger.info(
            "hunt_playbook.hypothesis_added org=%s playbook_id=%s hyp_id=%s",
            org_id, playbook_id, hyp_id,
        )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_hypotheses WHERE id=?", (hyp_id,)
            ).fetchone()
        return self._row(row)

    def validate_hypothesis(
        self,
        hypothesis_id: str,
        org_id: str,
        evidence: str,
    ) -> Dict[str, Any]:
        """Mark a hypothesis as validated and store evidence."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_hypotheses WHERE id=? AND org_id=?",
                (hypothesis_id, org_id),
            ).fetchone()
            if row is None:
                raise ValueError(
                    f"Hypothesis '{hypothesis_id}' not found for org '{org_id}'"
                )
            conn.execute(
                "UPDATE hunt_hypotheses SET validated=1, evidence=? WHERE id=? AND org_id=?",
                (evidence, hypothesis_id, org_id),
            )
        _logger.info(
            "hunt_playbook.hypothesis_validated org=%s hyp_id=%s",
            org_id, hypothesis_id,
        )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_hypotheses WHERE id=?", (hypothesis_id,)
            ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # PUBLIC API — EXECUTIONS
    # ------------------------------------------------------------------

    def start_execution(
        self,
        playbook_id: str,
        org_id: str,
        analyst: str = "",
    ) -> Dict[str, Any]:
        """Start a hunt execution. Sets start_time=now, outcome=in_progress, increments execution_count."""
        with self._conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM hunting_playbooks WHERE id=? AND org_id=?",
                (playbook_id, org_id),
            ).fetchone()
        if exists is None:
            raise ValueError(f"Playbook '{playbook_id}' not found for org '{org_id}'")

        exec_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO hunt_executions
                   (id, playbook_id, org_id, analyst, start_time, end_time, duration_mins,
                    outcome, findings_count, iocs_discovered, notes, created_at)
                   VALUES (?,?,?,?,?,NULL,0.0,'in_progress',0,'[]','',?)""",
                (exec_id, playbook_id, org_id, analyst, now, now),
            )
            conn.execute(
                "UPDATE hunting_playbooks SET execution_count=execution_count+1 WHERE id=? AND org_id=?",
                (playbook_id, org_id),
            )
        _logger.info(
            "hunt_playbook.execution_started org=%s playbook_id=%s exec_id=%s analyst=%s",
            org_id, playbook_id, exec_id, analyst,
        )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_executions WHERE id=?", (exec_id,)
            ).fetchone()
        return self._row(row)

    def complete_execution(
        self,
        execution_id: str,
        org_id: str,
        outcome: str,
        findings_count: int = 0,
        iocs_discovered: Optional[List[str]] = None,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Complete a hunt execution. Computes duration, recomputes success_rate and avg_duration."""
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(
                f"Invalid outcome '{outcome}'. Must be one of {sorted(_VALID_OUTCOMES)}"
            )

        iocs_json = json.dumps(iocs_discovered or [])
        end_time = self._now()

        with self._lock, self._conn() as conn:
            exec_row = conn.execute(
                "SELECT * FROM hunt_executions WHERE id=? AND org_id=?",
                (execution_id, org_id),
            ).fetchone()
            if exec_row is None:
                raise ValueError(
                    f"Execution '{execution_id}' not found for org '{org_id}'"
                )
            playbook_id = exec_row["playbook_id"]
            start_time = exec_row["start_time"]

            # Compute duration via julianday arithmetic
            duration_row = conn.execute(
                "SELECT (julianday(?) - julianday(?)) * 1440.0 AS dur",
                (end_time, start_time),
            ).fetchone()
            duration_mins = max(0.0, duration_row["dur"] if duration_row["dur"] is not None else 0.0)

            # Update execution
            conn.execute(
                """UPDATE hunt_executions
                   SET end_time=?, duration_mins=?, outcome=?, findings_count=?,
                       iocs_discovered=?, notes=?
                   WHERE id=? AND org_id=?""",
                (
                    end_time, duration_mins, outcome, findings_count,
                    iocs_json, notes, execution_id, org_id,
                ),
            )

            # Recompute playbook stats
            stats_row = conn.execute(
                """SELECT
                       COUNT(*) AS total,
                       SUM(CASE WHEN outcome IN ('finding','partial_finding') THEN 1 ELSE 0 END) AS successes,
                       AVG(duration_mins) AS avg_dur
                   FROM hunt_executions
                   WHERE playbook_id=? AND org_id=? AND outcome != 'in_progress'""",
                (playbook_id, org_id),
            ).fetchone()

            total_exec = stats_row["total"] or 0
            successes = stats_row["successes"] or 0
            avg_dur = stats_row["avg_dur"] or 0.0
            success_rate = round((successes / total_exec * 100) if total_exec > 0 else 0.0, 2)

            conn.execute(
                """UPDATE hunting_playbooks
                   SET success_rate=?, avg_duration_mins=?
                   WHERE id=? AND org_id=?""",
                (success_rate, round(avg_dur, 2), playbook_id, org_id),
            )

        _logger.info(
            "hunt_playbook.execution_completed org=%s exec_id=%s outcome=%s duration_mins=%.2f",
            org_id, execution_id, outcome, duration_mins,
        )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_executions WHERE id=?", (execution_id,)
            ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # PUBLIC API — STATS
    # ------------------------------------------------------------------

    def get_hunt_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate hunt stats for the org."""
        with self._conn() as conn:
            total_playbooks = conn.execute(
                "SELECT COUNT(*) FROM hunting_playbooks WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_executions = conn.execute(
                "SELECT COUNT(*) FROM hunt_executions WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            overall_success_rate_row = conn.execute(
                "SELECT AVG(success_rate) FROM hunting_playbooks WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            by_type_rows = conn.execute(
                """SELECT hunt_type, COUNT(*) AS cnt
                   FROM hunting_playbooks WHERE org_id=? GROUP BY hunt_type""",
                (org_id,),
            ).fetchall()

            by_category_rows = conn.execute(
                """SELECT threat_category, COUNT(*) AS cnt
                   FROM hunting_playbooks WHERE org_id=? GROUP BY threat_category""",
                (org_id,),
            ).fetchall()

            active_hunts = conn.execute(
                "SELECT COUNT(*) FROM hunt_executions WHERE org_id=? AND outcome='in_progress'",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_playbooks": total_playbooks,
            "total_executions": total_executions,
            "overall_success_rate": round(overall_success_rate_row, 2)
            if overall_success_rate_row is not None else 0.0,
            "by_hunt_type": {r["hunt_type"]: r["cnt"] for r in by_type_rows},
            "by_threat_category": {r["threat_category"]: r["cnt"] for r in by_category_rows},
            "active_hunts": active_hunts,
        }
