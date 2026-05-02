"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This engine simulates autonomous pentest campaigns for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- Task execution (line 896) uses random.random() < success_prob to decide
  exploit success — no real network probes or exploit payloads are executed.
- Operator "swarm" consists of virtual state machine agents, not real tools.
- Real implementation requires: Metasploit RPC, Nuclei, custom exploit runners,
  or integration with PentestGPT/Pentera/Cymulate.
  Configure via /api/v1/connectors/pentest/configure

Until real integrations are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

OpenClaw Autonomous Pentest Swarm Engine — ALDECI.

Orchestrates coordinated red team campaigns aligned to MITRE ATT&CK, with
up to 5 virtual operators running tasks across reconnaissance, initial access,
privilege escalation, lateral movement, collection, and exfiltration phases.

Capabilities:
  - Multi-phase campaign lifecycle (staged → running → paused → completed)
  - MITRE ATT&CK technique-mapped task queue per phase
  - 5-operator swarm coordination with specialization roles
  - Automatic finding generation from succeeded exploit tasks
  - Full multi-tenant isolation via org_id
  - SQLite WAL persistence, thread-safe via RLock

Compliance: MITRE ATT&CK v14, PTES, OWASP Testing Guide
"""

from __future__ import annotations

import json
import logging
import random
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)
_logger.warning(
    "⚠️  %s loaded in SIMULATION mode — pentest task outcomes use random.random() < success_prob; do not present in demos. "
    "Configure real connectors via /api/v1/connectors/pentest/configure",
    __name__,
)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_CAMPAIGN_TYPES = {
    "network_pentest", "web_app", "cloud_security",
    "social_engineering", "physical_access", "full_red_team",
}
_VALID_STATUSES = {"staged", "running", "paused", "completed", "failed"}
_VALID_PHASES = {
    "recon", "initial_access", "execution", "persistence",
    "privilege_escalation", "lateral_movement", "collection", "exfiltration",
}
_VALID_TASK_TYPES = {
    "recon", "exploit_attempt", "privilege_escalation",
    "lateral_move", "data_access", "persistence", "cleanup",
}
_VALID_TASK_STATUSES = {"queued", "running", "succeeded", "failed", "skipped"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_FINDING_CATEGORIES = {
    "initial_access", "execution", "privilege_escalation",
    "credential_access", "lateral_movement", "data_exfiltration", "persistence",
}
_VALID_FINDING_STATUSES = {"open", "accepted", "remediated"}
_OPERATOR_SPECIALIZATIONS = {
    "network", "web", "cloud", "social_engineering", "physical",
}
_OPERATOR_NAMES = [
    "Operator-Alpha", "Operator-Bravo", "Operator-Charlie",
    "Operator-Delta", "Operator-Echo",
]

# Phase ordering for advance_phase
_PHASE_ORDER = [
    "recon", "initial_access", "execution", "persistence",
    "privilege_escalation", "lateral_movement", "collection", "exfiltration",
]

# ---------------------------------------------------------------------------
# Task templates per MITRE phase
# ---------------------------------------------------------------------------

PHASE_TASKS: Dict[str, List[Dict[str, Any]]] = {
    "recon": [
        {
            "task_type": "recon",
            "technique_id": "T1595",
            "technique_name": "Active Scanning",
            "risk_level": "low",
        },
        {
            "task_type": "recon",
            "technique_id": "T1592",
            "technique_name": "Gather Victim Host Info",
            "risk_level": "low",
        },
        {
            "task_type": "recon",
            "technique_id": "T1590",
            "technique_name": "Gather Victim Network Info",
            "risk_level": "low",
        },
    ],
    "initial_access": [
        {
            "task_type": "exploit_attempt",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "risk_level": "high",
        },
        {
            "task_type": "exploit_attempt",
            "technique_id": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "risk_level": "high",
        },
        {
            "task_type": "exploit_attempt",
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "risk_level": "critical",
        },
    ],
    "execution": [
        {
            "task_type": "exploit_attempt",
            "technique_id": "T1059.001",
            "technique_name": "PowerShell Execution",
            "risk_level": "high",
        },
        {
            "task_type": "exploit_attempt",
            "technique_id": "T1059.003",
            "technique_name": "Windows Command Shell",
            "risk_level": "medium",
        },
    ],
    "persistence": [
        {
            "task_type": "persistence",
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task/Job",
            "risk_level": "medium",
        },
        {
            "task_type": "persistence",
            "technique_id": "T1547.001",
            "technique_name": "Registry Run Keys",
            "risk_level": "medium",
        },
    ],
    "privilege_escalation": [
        {
            "task_type": "privilege_escalation",
            "technique_id": "T1548.002",
            "technique_name": "Bypass UAC",
            "risk_level": "high",
        },
        {
            "task_type": "privilege_escalation",
            "technique_id": "T1134",
            "technique_name": "Access Token Manipulation",
            "risk_level": "critical",
        },
    ],
    "lateral_movement": [
        {
            "task_type": "lateral_move",
            "technique_id": "T1021.001",
            "technique_name": "Remote Desktop Protocol",
            "risk_level": "high",
        },
        {
            "task_type": "lateral_move",
            "technique_id": "T1570",
            "technique_name": "Lateral Tool Transfer",
            "risk_level": "medium",
        },
    ],
    "collection": [
        {
            "task_type": "data_access",
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "risk_level": "medium",
        },
        {
            "task_type": "data_access",
            "technique_id": "T1005",
            "technique_name": "Data from Local System",
            "risk_level": "high",
        },
    ],
    "exfiltration": [
        {
            "task_type": "data_access",
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "risk_level": "critical",
        },
        {
            "task_type": "data_access",
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "risk_level": "high",
        },
    ],
}

# ---------------------------------------------------------------------------
# Finding templates (generated when exploit tasks succeed)
# ---------------------------------------------------------------------------

FINDING_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "title": "Critical: Public-Facing Application Vulnerable to Remote Code Execution",
        "severity": "critical",
        "category": "initial_access",
        "cvss_score": 9.8,
        "remediation": "Apply vendor patches immediately. Enable WAF rules. Conduct full application security review.",
    },
    "T1566.001": {
        "title": "High: Employees Susceptible to Spearphishing Attacks",
        "severity": "high",
        "category": "initial_access",
        "cvss_score": 7.5,
        "remediation": "Implement phishing-resistant MFA. Conduct security awareness training. Deploy email sandboxing.",
    },
    "T1078": {
        "title": "Critical: Valid Credentials Obtained via Credential Stuffing",
        "severity": "critical",
        "category": "credential_access",
        "cvss_score": 9.1,
        "remediation": "Enforce MFA for all accounts. Implement credential breach monitoring. Reset compromised credentials.",
    },
    "T1059.001": {
        "title": "High: Unrestricted PowerShell Execution Allowed",
        "severity": "high",
        "category": "execution",
        "cvss_score": 8.1,
        "remediation": "Enable PowerShell Constrained Language Mode. Enforce execution policy. Enable script block logging.",
    },
    "T1548.002": {
        "title": "High: UAC Bypass via Token Manipulation",
        "severity": "high",
        "category": "privilege_escalation",
        "cvss_score": 7.8,
        "remediation": "Apply Windows hardening benchmarks. Enable UAC at highest level. Monitor token manipulation events.",
    },
    "T1134": {
        "title": "Critical: Access Token Manipulation for Privilege Escalation",
        "severity": "critical",
        "category": "privilege_escalation",
        "cvss_score": 8.8,
        "remediation": "Restrict SeDebugPrivilege. Implement privileged access workstations. Monitor LSASS access.",
    },
    "T1021.001": {
        "title": "Medium: RDP Enabled on Internal Systems Without MFA",
        "severity": "medium",
        "category": "lateral_movement",
        "cvss_score": 6.5,
        "remediation": "Disable RDP where not needed. Enforce Network Level Authentication. Require MFA for RDP sessions.",
    },
    "T1570": {
        "title": "Medium: Lateral Tool Transfer via SMB Shares",
        "severity": "medium",
        "category": "lateral_movement",
        "cvss_score": 6.1,
        "remediation": "Restrict SMB traffic between endpoints. Implement application allowlisting. Monitor file transfer events.",
    },
    "T1005": {
        "title": "High: Sensitive Data Accessible from Local System",
        "severity": "high",
        "category": "data_exfiltration",
        "cvss_score": 7.2,
        "remediation": "Implement least-privilege file access. Enable DLP controls. Encrypt sensitive data at rest.",
    },
    "T1041": {
        "title": "Critical: Data Exfiltration Over Command and Control Channel",
        "severity": "critical",
        "category": "data_exfiltration",
        "cvss_score": 9.0,
        "remediation": "Implement egress filtering. Deploy network DLP. Monitor and alert on anomalous outbound traffic.",
    },
}

# Success probability per task type (simulated)
_SUCCESS_RATES: Dict[str, float] = {
    "recon": 0.95,
    "exploit_attempt": 0.55,
    "privilege_escalation": 0.50,
    "lateral_move": 0.60,
    "data_access": 0.70,
    "persistence": 0.65,
    "cleanup": 0.90,
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class OpenClawEngine:
    """SQLite WAL-backed, multi-tenant OpenClaw pentest swarm engine.

    Thread-safe via RLock. Multi-tenant via org_id column on all tables.
    """

    def __init__(self, org_id: str = "default", db_path: Optional[str] = None) -> None:
        if db_path is None:
            _DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)
            db_path = str(_DEFAULT_DB_DIR / f"{org_id}_openclaw.db")
        self.db_path = db_path
        self.org_id = org_id
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB init
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._lock:
            with self._conn() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys=ON")
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS swarm_campaigns (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        campaign_type TEXT NOT NULL DEFAULT 'network_pentest',
                        target_scope TEXT DEFAULT '[]',
                        attack_tactics TEXT DEFAULT '[]',
                        status TEXT NOT NULL DEFAULT 'staged',
                        phase TEXT NOT NULL DEFAULT 'recon',
                        operators_count INTEGER NOT NULL DEFAULT 3,
                        start_time TEXT,
                        end_time TEXT,
                        findings_count INTEGER DEFAULT 0,
                        critical_findings INTEGER DEFAULT 0,
                        risk_score REAL DEFAULT 0.0,
                        authorization_token TEXT NOT NULL,
                        authorized_by TEXT DEFAULT '',
                        authorized_until TEXT DEFAULT '',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS campaign_tasks (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        campaign_id TEXT NOT NULL,
                        task_type TEXT NOT NULL,
                        target TEXT DEFAULT '',
                        technique_id TEXT DEFAULT '',
                        technique_name TEXT DEFAULT '',
                        status TEXT NOT NULL DEFAULT 'queued',
                        operator_id INTEGER DEFAULT 1,
                        started_at TEXT,
                        completed_at TEXT,
                        output_preview TEXT DEFAULT '',
                        result_data TEXT DEFAULT '{}',
                        risk_level TEXT DEFAULT 'medium'
                    );

                    CREATE TABLE IF NOT EXISTS swarm_findings (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        campaign_id TEXT NOT NULL,
                        task_id TEXT DEFAULT '',
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL DEFAULT 'medium',
                        category TEXT DEFAULT 'initial_access',
                        technique_id TEXT DEFAULT '',
                        technique_name TEXT DEFAULT '',
                        target TEXT DEFAULT '',
                        evidence_preview TEXT DEFAULT '',
                        remediation TEXT DEFAULT '',
                        cvss_score REAL DEFAULT 0.0,
                        status TEXT NOT NULL DEFAULT 'open',
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS swarm_operators (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        campaign_id TEXT NOT NULL,
                        operator_id INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        specialization TEXT DEFAULT 'network',
                        status TEXT NOT NULL DEFAULT 'idle',
                        current_task_id TEXT DEFAULT '',
                        tasks_completed INTEGER DEFAULT 0,
                        tasks_failed INTEGER DEFAULT 0
                    );
                """)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialise JSON columns
        for col in ("target_scope", "attack_tactics", "result_data"):
            if col in d and isinstance(d[col], str):
                try:
                    d[col] = json.loads(d[col])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def create_campaign(self, org_id: str, data: dict) -> dict:
        """Create a new pentest campaign. authorization_token is required."""
        auth_token = data.get("authorization_token", "").strip()
        if not auth_token:
            raise ValueError("authorization_token is required for all pentest campaigns")

        campaign_id = str(uuid.uuid4())
        now = self._now()

        campaign_type = data.get("campaign_type", "network_pentest")
        if campaign_type not in _VALID_CAMPAIGN_TYPES:
            campaign_type = "network_pentest"

        operators_count = max(1, min(5, int(data.get("operators_count", 3))))
        target_scope = json.dumps(data.get("target_scope", []))
        attack_tactics = json.dumps(data.get("attack_tactics", []))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO swarm_campaigns
                        (id, org_id, name, description, campaign_type, target_scope,
                         attack_tactics, status, phase, operators_count,
                         authorization_token, authorized_by, authorized_until,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        campaign_id, org_id,
                        data.get("name", "Unnamed Campaign"),
                        data.get("description", ""),
                        campaign_type,
                        target_scope,
                        attack_tactics,
                        "staged",
                        "recon",
                        operators_count,
                        auth_token,
                        data.get("authorized_by", ""),
                        data.get("authorized_until", ""),
                        now, now,
                    ),
                )

                # Spawn operator records
                specializations = list(_OPERATOR_SPECIALIZATIONS)
                for i in range(1, operators_count + 1):
                    op_id = str(uuid.uuid4())
                    spec = specializations[(i - 1) % len(specializations)]
                    conn.execute(
                        """
                        INSERT INTO swarm_operators
                            (id, org_id, campaign_id, operator_id, name,
                             specialization, status)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (op_id, org_id, campaign_id, i,
                         _OPERATOR_NAMES[i - 1], spec, "idle"),
                    )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "openclaw", "org_id": org_id, "source_engine": "openclaw"})
            except Exception:
                pass

        return self.get_campaign(org_id, campaign_id)  # type: ignore[return-value]

    def list_campaigns(
        self,
        org_id: str,
        status: Optional[str] = None,
        campaign_type: Optional[str] = None,
    ) -> List[dict]:
        clauses = ["org_id=?"]
        params: list = [org_id]
        if status:
            clauses.append("status=?")
            params.append(status)
        if campaign_type:
            clauses.append("campaign_type=?")
            params.append(campaign_type)
        query = (
            f"SELECT * FROM swarm_campaigns WHERE {' AND '.join(clauses)} "  # nosec B608
            "ORDER BY created_at DESC"
        )
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_campaign(self, org_id: str, campaign_id: str) -> Optional[dict]:
        """Return campaign dict with tasks and findings summary."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM swarm_campaigns WHERE id=? AND org_id=?",
                (campaign_id, org_id),
            ).fetchone()
            if row is None:
                return None
            campaign = self._row_to_dict(row)

            # Tasks summary
            task_rows = conn.execute(
                "SELECT * FROM campaign_tasks WHERE campaign_id=? AND org_id=? ORDER BY rowid ASC",
                (campaign_id, org_id),
            ).fetchall()
            campaign["tasks"] = [self._row_to_dict(t) for t in task_rows]

            # Findings summary counts
            finding_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM swarm_findings "
                "WHERE campaign_id=? AND org_id=? GROUP BY severity",
                (campaign_id, org_id),
            ).fetchall()
            campaign["findings_by_severity"] = {r["severity"]: r["cnt"] for r in finding_rows}

            # Operators
            op_rows = conn.execute(
                "SELECT * FROM swarm_operators WHERE campaign_id=? AND org_id=? ORDER BY operator_id ASC",
                (campaign_id, org_id),
            ).fetchall()
            campaign["operators"] = [dict(r) for r in op_rows]

        return campaign

    # ------------------------------------------------------------------
    # Campaign lifecycle
    # ------------------------------------------------------------------

    def start_campaign(self, org_id: str, campaign_id: str) -> dict:
        """Start a staged campaign: queue initial tasks and simulate execution."""
        campaign = self.get_campaign(org_id, campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign {campaign_id} not found")
        if campaign["status"] != "staged":
            raise ValueError(f"Campaign status is '{campaign['status']}', must be 'staged' to start")

        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE swarm_campaigns SET status='running', phase='recon', start_time=?, updated_at=? WHERE id=? AND org_id=?",
                    (now, now, campaign_id, org_id),
                )

        # Queue recon + initial_access tasks
        recon_tasks = self._queue_phase_tasks(org_id, campaign_id, "recon")
        ia_tasks = self._queue_phase_tasks(org_id, campaign_id, "initial_access")
        all_queued = recon_tasks + ia_tasks

        # Simulate execution
        self._simulate_tasks(org_id, campaign_id, all_queued)

        # Update findings count on campaign
        self._refresh_campaign_counts(org_id, campaign_id)

        return {
            "status": "running",
            "phase": "recon",
            "tasks_queued": len(all_queued),
            "estimated_duration_minutes": len(all_queued) * 3,
        }

    def advance_phase(self, org_id: str, campaign_id: str) -> dict:
        """Advance the campaign to the next MITRE phase and queue new tasks."""
        campaign = self.get_campaign(org_id, campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign {campaign_id} not found")
        if campaign["status"] not in ("running", "paused"):
            raise ValueError("Campaign must be running or paused to advance phase")

        current_phase = campaign["phase"]
        try:
            idx = _PHASE_ORDER.index(current_phase)
        except ValueError:
            idx = 0

        if idx >= len(_PHASE_ORDER) - 1:
            raise ValueError(f"Campaign is already at final phase: {current_phase}")

        next_phase = _PHASE_ORDER[idx + 1]
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE swarm_campaigns SET phase=?, status='running', updated_at=? WHERE id=? AND org_id=?",
                    (next_phase, now, campaign_id, org_id),
                )

        new_tasks = self._queue_phase_tasks(org_id, campaign_id, next_phase)
        self._simulate_tasks(org_id, campaign_id, new_tasks)
        self._refresh_campaign_counts(org_id, campaign_id)

        return {
            "previous_phase": current_phase,
            "current_phase": next_phase,
            "tasks_queued": len(new_tasks),
        }

    def pause_campaign(self, org_id: str, campaign_id: str) -> dict:
        """Pause a running campaign."""
        campaign = self.get_campaign(org_id, campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign {campaign_id} not found")
        if campaign["status"] != "running":
            raise ValueError(f"Campaign is not running (status={campaign['status']})")
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE swarm_campaigns SET status='paused', updated_at=? WHERE id=? AND org_id=?",
                    (now, campaign_id, org_id),
                )
        return {"campaign_id": campaign_id, "status": "paused"}

    def resume_campaign(self, org_id: str, campaign_id: str) -> dict:
        """Resume a paused campaign."""
        campaign = self.get_campaign(org_id, campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign {campaign_id} not found")
        if campaign["status"] != "paused":
            raise ValueError(f"Campaign is not paused (status={campaign['status']})")
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE swarm_campaigns SET status='running', updated_at=? WHERE id=? AND org_id=?",
                    (now, campaign_id, org_id),
                )
        return {"campaign_id": campaign_id, "status": "running"}

    def complete_campaign(self, org_id: str, campaign_id: str) -> dict:
        """Complete a campaign and calculate final risk score."""
        campaign = self.get_campaign(org_id, campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign {campaign_id} not found")
        if campaign["status"] not in ("running", "paused"):
            raise ValueError("Campaign must be running or paused to complete")

        # Calculate risk score from findings
        risk_score = self._calculate_risk_score(org_id, campaign_id)
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE swarm_campaigns SET status='completed', end_time=?, risk_score=?, updated_at=? WHERE id=? AND org_id=?",
                    (now, risk_score, now, campaign_id, org_id),
                )
                # Set all operators to idle
                conn.execute(
                    "UPDATE swarm_operators SET status='idle', current_task_id='' WHERE campaign_id=? AND org_id=?",
                    (campaign_id, org_id),
                )

        return {"campaign_id": campaign_id, "status": "completed", "risk_score": risk_score}

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def list_tasks(
        self,
        org_id: str,
        campaign_id: str,
        status: Optional[str] = None,
    ) -> List[dict]:
        clauses = ["campaign_id=?", "org_id=?"]
        params: list = [campaign_id, org_id]
        if status:
            clauses.append("status=?")
            params.append(status)
        query = (
            f"SELECT * FROM campaign_tasks WHERE {' AND '.join(clauses)} ORDER BY rowid ASC"  # nosec B608
        )
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def list_findings(
        self,
        org_id: str,
        campaign_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[dict]:
        clauses = ["org_id=?"]
        params: list = [org_id]
        if campaign_id:
            clauses.append("campaign_id=?")
            params.append(campaign_id)
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        query = (
            f"SELECT * FROM swarm_findings WHERE {' AND '.join(clauses)} "  # nosec B608
            "ORDER BY cvss_score DESC, created_at DESC"
        )
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_finding_status(
        self, org_id: str, finding_id: str, status: str
    ) -> dict:
        if status not in _VALID_FINDING_STATUSES:
            raise ValueError(f"Invalid finding status: {status}. Must be one of {_VALID_FINDING_STATUSES}")
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE swarm_findings SET status=? WHERE id=? AND org_id=?",
                    (status, finding_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM swarm_findings WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                ).fetchone()
        if row is None:
            raise ValueError(f"Finding {finding_id} not found")
        return self._row_to_dict(row)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> dict:
        """Aggregate stats for an org across all campaigns."""
        with self._conn() as conn:
            camp_row = conn.execute(
                """
                SELECT
                    COUNT(*) AS campaign_count,
                    SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) AS active_campaigns,
                    AVG(CASE WHEN risk_score > 0 THEN risk_score ELSE NULL END) AS avg_risk_score
                FROM swarm_campaigns WHERE org_id=?
                """,
                (org_id,),
            ).fetchone()

            finding_rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM swarm_findings WHERE org_id=?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()

            technique_rows = conn.execute(
                """
                SELECT technique_id, COUNT(*) AS cnt
                FROM campaign_tasks
                WHERE org_id=? AND technique_id != '' AND status='succeeded'
                GROUP BY technique_id
                ORDER BY cnt DESC
                LIMIT 5
                """,
                (org_id,),
            ).fetchall()

            op_row = conn.execute(
                "SELECT COUNT(DISTINCT id) AS operators_deployed FROM swarm_operators WHERE org_id=?",
                (org_id,),
            ).fetchone()

        findings_by_severity: Dict[str, int] = {s: 0 for s in _VALID_SEVERITIES}
        for r in finding_rows:
            findings_by_severity[r["severity"]] = r["cnt"]

        return {
            "campaign_count": camp_row["campaign_count"] or 0,
            "active_campaigns": camp_row["active_campaigns"] or 0,
            "total_findings_by_severity": findings_by_severity,
            "avg_risk_score": round(float(camp_row["avg_risk_score"] or 0.0), 1),
            "techniques_used": [r["technique_id"] for r in technique_rows],
            "operators_deployed": op_row["operators_deployed"] or 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _queue_phase_tasks(
        self, org_id: str, campaign_id: str, phase: str
    ) -> List[str]:
        """Insert task records for a phase. Returns list of task IDs."""
        templates = PHASE_TASKS.get(phase, [])
        task_ids: List[str] = []
        self._now()

        # Get campaign target_scope for task target field
        with self._conn() as conn:
            row = conn.execute(
                "SELECT target_scope, operators_count FROM swarm_campaigns WHERE id=? AND org_id=?",
                (campaign_id, org_id),
            ).fetchone()
        target_scope = []
        if row:
            try:
                target_scope = json.loads(row["target_scope"] or "[]")
            except (json.JSONDecodeError, TypeError):
                target_scope = []
        default_target = target_scope[0] if target_scope else "target_scope"
        operators_count = row["operators_count"] if row else 3

        with self._lock:
            with self._conn() as conn:
                for i, tmpl in enumerate(templates):
                    task_id = str(uuid.uuid4())
                    operator_id = (i % operators_count) + 1
                    conn.execute(
                        """
                        INSERT INTO campaign_tasks
                            (id, org_id, campaign_id, task_type, target, technique_id,
                             technique_name, status, operator_id, result_data, risk_level)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            task_id, org_id, campaign_id,
                            tmpl.get("task_type", "recon"),
                            tmpl.get("target", default_target),
                            tmpl.get("technique_id", ""),
                            tmpl.get("technique_name", ""),
                            "queued",
                            operator_id,
                            "{}",
                            tmpl.get("risk_level", "medium"),
                        ),
                    )
                    task_ids.append(task_id)

        return task_ids

    def _simulate_tasks(
        self, org_id: str, campaign_id: str, task_ids: List[str]
    ) -> None:
        """Simulate task execution (synchronous demo — no real network calls)."""
        now = self._now()
        for task_id in task_ids:
            # Fetch the task
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM campaign_tasks WHERE id=? AND org_id=?",
                    (task_id, org_id),
                ).fetchone()
            if row is None:
                continue

            task = dict(row)
            task_type = task["task_type"]
            technique_id = task["technique_id"]
            operator_id = task["operator_id"]

            success_prob = _SUCCESS_RATES.get(task_type, 0.5)
            succeeded = random.random() < success_prob

            result_status = "succeeded" if succeeded else "failed"
            output_preview = (
                f"[Operator-{operator_id}] {task['technique_name']}: "
                f"{'SUCCESS — vulnerability confirmed' if succeeded else 'FAILED — target hardened'}"
            )

            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        """
                        UPDATE campaign_tasks
                        SET status=?, started_at=?, completed_at=?, output_preview=?,
                            result_data=?
                        WHERE id=? AND org_id=?
                        """,
                        (
                            result_status, now, now, output_preview,
                            json.dumps({"success": succeeded, "operator_id": operator_id}),
                            task_id, org_id,
                        ),
                    )
                    # Update operator stats
                    if succeeded:
                        conn.execute(
                            "UPDATE swarm_operators SET tasks_completed=tasks_completed+1, status='active' WHERE campaign_id=? AND operator_id=? AND org_id=?",
                            (campaign_id, operator_id, org_id),
                        )
                    else:
                        conn.execute(
                            "UPDATE swarm_operators SET tasks_failed=tasks_failed+1 WHERE campaign_id=? AND operator_id=? AND org_id=?",
                            (campaign_id, operator_id, org_id),
                        )

            # Generate finding if exploit task succeeded and we have a template
            if succeeded and task_type in ("exploit_attempt", "privilege_escalation", "lateral_move", "data_access"):
                tmpl = FINDING_TEMPLATES.get(technique_id)
                if tmpl:
                    self._create_finding(org_id, campaign_id, task_id, task, tmpl)

    def _create_finding(
        self,
        org_id: str,
        campaign_id: str,
        task_id: str,
        task: dict,
        tmpl: dict,
    ) -> None:
        finding_id = str(uuid.uuid4())
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO swarm_findings
                        (id, org_id, campaign_id, task_id, title, severity, category,
                         technique_id, technique_name, target, evidence_preview,
                         remediation, cvss_score, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        finding_id, org_id, campaign_id, task_id,
                        tmpl.get("title", "Security Finding"),
                        tmpl.get("severity", "medium"),
                        tmpl.get("category", "initial_access"),
                        task.get("technique_id", ""),
                        task.get("technique_name", ""),
                        task.get("target", ""),
                        f"Evidence captured by Operator-{task.get('operator_id', 1)} during {task.get('technique_name', '')} phase",
                        tmpl.get("remediation", "Review and remediate the identified vulnerability."),
                        float(tmpl.get("cvss_score", 5.0)),
                        "open",
                        now,
                    ),
                )

    def _refresh_campaign_counts(self, org_id: str, campaign_id: str) -> None:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """
                    SELECT COUNT(*) AS total,
                           SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS crit
                    FROM swarm_findings WHERE campaign_id=? AND org_id=?
                    """,
                    (campaign_id, org_id),
                ).fetchone()
                conn.execute(
                    "UPDATE swarm_campaigns SET findings_count=?, critical_findings=? WHERE id=? AND org_id=?",
                    (row["total"] or 0, row["crit"] or 0, campaign_id, org_id),
                )

    def _calculate_risk_score(self, org_id: str, campaign_id: str) -> float:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT cvss_score FROM swarm_findings WHERE campaign_id=? AND org_id=?",
                (campaign_id, org_id),
            ).fetchall()
        if not rows:
            return 0.0
        scores = [r["cvss_score"] for r in rows if r["cvss_score"]]
        if not scores:
            return 0.0
        return round(max(scores) * 0.6 + (sum(scores) / len(scores)) * 0.4, 1)


# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------

_engine_cache: Dict[str, OpenClawEngine] = {}
_engine_lock = threading.Lock()


def get_openclaw_engine(org_id: str = "default") -> OpenClawEngine:
    global _engine_cache
    with _engine_lock:
        if org_id not in _engine_cache:
            _engine_cache[org_id] = OpenClawEngine(org_id=org_id)
    return _engine_cache[org_id]
