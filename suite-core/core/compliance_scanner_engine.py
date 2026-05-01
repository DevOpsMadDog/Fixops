"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This engine generates randomized compliance check outcomes for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- Compliance checks use unseeded random.Random() (line 348) — outcomes change
  each run and are not derived from real control evidence.
- Real implementation requires: evidence collection via audit connectors,
  policy-as-code evaluation (OPA/Conftest), and real control testing.
  Configure via /api/v1/connectors/compliance/configure

Until real integrations are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

Compliance Scanner Engine — ALDECI.

Automated compliance scanning across SOC2, ISO 27001, NIST CSF, PCI DSS,
HIPAA, GDPR, and CIS frameworks. Generates scan profiles, runs checks,
tracks remediation tasks, and provides aggregate compliance statistics.

Multi-tenant (org_id), SQLite WAL-backed, thread-safe via RLock.
"""

from __future__ import annotations

import json
import logging
import random
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
_logger.warning(
    "⚠️  %s loaded in SIMULATION mode — output is randomized; do not present in demos. "
    "Configure real connectors via /api/v1/connectors/",
    __name__,
)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "compliance_scanner.db"
)

_FRAMEWORKS = {"SOC2", "ISO27001", "NIST_CSF", "PCI_DSS", "HIPAA", "GDPR", "CIS"}
_SCAN_STATUSES = {"running", "completed", "failed"}
_CHECK_STATUSES = {"pass", "fail", "warning", "skip", "not_applicable"}
_SEVERITIES = {"critical", "high", "medium", "low"}
_TASK_STATUSES = {"open", "in_progress", "resolved", "accepted_risk"}
_TASK_PRIORITIES = {"critical", "high", "medium", "low"}

# Realistic control definitions per framework
_FRAMEWORK_CONTROLS: Dict[str, List[Dict[str, Any]]] = {
    "SOC2": [
        {"control_id": "CC6.1", "control_name": "Logical and Physical Access Controls", "category": "Access Control", "severity": "critical"},
        {"control_id": "CC6.2", "control_name": "Authentication Mechanisms", "category": "Access Control", "severity": "critical"},
        {"control_id": "CC6.3", "control_name": "Role-Based Access Controls", "category": "Access Control", "severity": "high"},
        {"control_id": "CC7.1", "control_name": "System Monitoring", "category": "Monitoring", "severity": "high"},
        {"control_id": "CC7.2", "control_name": "Security Incident Detection", "category": "Monitoring", "severity": "high"},
        {"control_id": "CC8.1", "control_name": "Change Management Process", "category": "Change Management", "severity": "medium"},
        {"control_id": "CC9.1", "control_name": "Risk Mitigation Activities", "category": "Risk Management", "severity": "medium"},
        {"control_id": "A1.1", "control_name": "Availability Commitments", "category": "Availability", "severity": "medium"},
    ],
    "ISO27001": [
        {"control_id": "A.5.1", "control_name": "Information Security Policies", "category": "Policy", "severity": "high"},
        {"control_id": "A.6.1", "control_name": "Internal Organization", "category": "Organization", "severity": "medium"},
        {"control_id": "A.8.1", "control_name": "Responsibility for Assets", "category": "Asset Management", "severity": "medium"},
        {"control_id": "A.9.1", "control_name": "Access Control Policy", "category": "Access Control", "severity": "critical"},
        {"control_id": "A.10.1", "control_name": "Cryptographic Controls", "category": "Cryptography", "severity": "high"},
        {"control_id": "A.12.4", "control_name": "Logging and Monitoring", "category": "Monitoring", "severity": "high"},
        {"control_id": "A.16.1", "control_name": "Management of Security Incidents", "category": "Incident Response", "severity": "high"},
    ],
    "NIST_CSF": [
        {"control_id": "ID.AM-1", "control_name": "Physical devices inventoried", "category": "Identify", "severity": "medium"},
        {"control_id": "ID.RA-1", "control_name": "Asset vulnerabilities identified", "category": "Identify", "severity": "high"},
        {"control_id": "PR.AC-1", "control_name": "Identities and credentials managed", "category": "Protect", "severity": "critical"},
        {"control_id": "PR.AC-3", "control_name": "Remote access managed", "category": "Protect", "severity": "high"},
        {"control_id": "PR.DS-1", "control_name": "Data-at-rest protected", "category": "Protect", "severity": "high"},
        {"control_id": "DE.CM-1", "control_name": "Network monitored for attack events", "category": "Detect", "severity": "high"},
        {"control_id": "DE.CM-4", "control_name": "Malicious code detected", "category": "Detect", "severity": "critical"},
        {"control_id": "RS.RP-1", "control_name": "Response plan executed", "category": "Respond", "severity": "medium"},
    ],
    "PCI_DSS": [
        {"control_id": "Req-1.1", "control_name": "Firewall configuration standards", "category": "Network Security", "severity": "critical"},
        {"control_id": "Req-2.1", "control_name": "Default passwords changed", "category": "Configuration", "severity": "critical"},
        {"control_id": "Req-3.4", "control_name": "PAN rendered unreadable", "category": "Data Protection", "severity": "critical"},
        {"control_id": "Req-6.3", "control_name": "Vulnerability management process", "category": "Vulnerability Management", "severity": "high"},
        {"control_id": "Req-7.1", "control_name": "Limit access to system components", "category": "Access Control", "severity": "high"},
        {"control_id": "Req-8.1", "control_name": "Identify and authenticate access", "category": "Authentication", "severity": "critical"},
        {"control_id": "Req-10.1", "control_name": "Audit logs implemented", "category": "Logging", "severity": "high"},
        {"control_id": "Req-11.2", "control_name": "Vulnerability scans performed", "category": "Testing", "severity": "high"},
    ],
    "HIPAA": [
        {"control_id": "164.308(a)(1)", "control_name": "Security Management Process", "category": "Administrative", "severity": "critical"},
        {"control_id": "164.308(a)(3)", "control_name": "Workforce Authorization", "category": "Administrative", "severity": "high"},
        {"control_id": "164.310(a)(1)", "control_name": "Facility Access Controls", "category": "Physical", "severity": "medium"},
        {"control_id": "164.312(a)(1)", "control_name": "Access Control — Unique User ID", "category": "Technical", "severity": "critical"},
        {"control_id": "164.312(b)", "control_name": "Audit Controls", "category": "Technical", "severity": "high"},
        {"control_id": "164.312(c)(1)", "control_name": "Integrity Controls", "category": "Technical", "severity": "high"},
        {"control_id": "164.312(e)(1)", "control_name": "Transmission Security", "category": "Technical", "severity": "critical"},
    ],
    "GDPR": [
        {"control_id": "Art-5", "control_name": "Principles of Data Processing", "category": "Data Processing", "severity": "critical"},
        {"control_id": "Art-6", "control_name": "Lawfulness of Processing", "category": "Data Processing", "severity": "critical"},
        {"control_id": "Art-17", "control_name": "Right to Erasure", "category": "Data Subject Rights", "severity": "high"},
        {"control_id": "Art-25", "control_name": "Data Protection by Design", "category": "Privacy Engineering", "severity": "high"},
        {"control_id": "Art-30", "control_name": "Records of Processing Activities", "category": "Accountability", "severity": "medium"},
        {"control_id": "Art-32", "control_name": "Security of Processing", "category": "Technical Measures", "severity": "critical"},
        {"control_id": "Art-33", "control_name": "Breach Notification (72h)", "category": "Incident Response", "severity": "high"},
    ],
    "CIS": [
        {"control_id": "CIS-1.1", "control_name": "Authorized Software Inventory", "category": "Inventory Control", "severity": "high"},
        {"control_id": "CIS-2.1", "control_name": "Software Asset Inventory", "category": "Inventory Control", "severity": "medium"},
        {"control_id": "CIS-4.1", "control_name": "Secure Configuration Assessment", "category": "Secure Configuration", "severity": "high"},
        {"control_id": "CIS-5.1", "control_name": "Account Management", "category": "Access Control", "severity": "critical"},
        {"control_id": "CIS-6.1", "control_name": "Access Control Management", "category": "Access Control", "severity": "critical"},
        {"control_id": "CIS-8.1", "control_name": "Audit Log Management", "category": "Audit Logging", "severity": "high"},
        {"control_id": "CIS-10.1", "control_name": "Malware Defense", "category": "Malware Defense", "severity": "high"},
        {"control_id": "CIS-13.1", "control_name": "Network Monitoring", "category": "Network Monitoring", "severity": "high"},
    ],
}

_REMEDIATION_TEMPLATES: Dict[str, str] = {
    "critical": "Immediately remediate: {control_name}. Escalate to security team lead. Target SLA: 24 hours.",
    "high": "Remediate {control_name} within 7 days. Assign to security engineering team.",
    "medium": "Schedule remediation for {control_name} within 30 days. Include in next sprint.",
    "low": "Address {control_name} in next quarterly review. Document acceptance if deferred.",
}


class ComplianceScannerEngine:
    """SQLite WAL-backed Automated Compliance Scanner.

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
                CREATE TABLE IF NOT EXISTS scan_profiles (
                    profile_id          TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    frameworks          TEXT NOT NULL DEFAULT '[]',
                    scan_frequency_hours INTEGER NOT NULL DEFAULT 24,
                    last_scan           DATETIME,
                    next_scan           DATETIME,
                    enabled             INTEGER NOT NULL DEFAULT 1,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_profiles_org
                    ON scan_profiles (org_id, enabled);

                CREATE TABLE IF NOT EXISTS scan_results (
                    result_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    profile_id      TEXT NOT NULL,
                    scan_started    DATETIME NOT NULL,
                    scan_completed  DATETIME,
                    total_checks    INTEGER NOT NULL DEFAULT 0,
                    passed          INTEGER NOT NULL DEFAULT 0,
                    failed          INTEGER NOT NULL DEFAULT 0,
                    warnings        INTEGER NOT NULL DEFAULT 0,
                    score           REAL NOT NULL DEFAULT 0.0,
                    status          TEXT NOT NULL DEFAULT 'running'
                );

                CREATE INDEX IF NOT EXISTS idx_results_org
                    ON scan_results (org_id, profile_id, scan_started);

                CREATE TABLE IF NOT EXISTS compliance_checks (
                    check_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    result_id           TEXT NOT NULL,
                    framework           TEXT NOT NULL,
                    control_id          TEXT NOT NULL,
                    control_name        TEXT NOT NULL,
                    category            TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL DEFAULT 'pass',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    evidence            TEXT NOT NULL DEFAULT '',
                    remediation         TEXT NOT NULL DEFAULT '',
                    check_duration_ms   INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_checks_org
                    ON compliance_checks (org_id, result_id, framework, status);

                CREATE TABLE IF NOT EXISTS remediation_tasks (
                    task_id         TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    check_id        TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    priority        TEXT NOT NULL DEFAULT 'medium',
                    status          TEXT NOT NULL DEFAULT 'open',
                    assigned_to     TEXT NOT NULL DEFAULT '',
                    due_date        TEXT NOT NULL DEFAULT '',
                    resolved_at     DATETIME,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tasks_org
                    ON remediation_tasks (org_id, status, priority);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_json_list(value: Any) -> list:
        if isinstance(value, list):
            return value
        try:
            result = json.loads(value or "[]")
            return result if isinstance(result, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    def _deserialize_profile(self, d: dict) -> dict:
        d["frameworks"] = self._parse_json_list(d.get("frameworks"))
        d["enabled"] = bool(d.get("enabled", 1))
        return d

    # ------------------------------------------------------------------
    # Scan Profiles
    # ------------------------------------------------------------------

    def create_profile(self, org_id: str, data: dict) -> dict:
        """Create a new scan profile for an org."""
        profile_id = str(uuid.uuid4())
        now = self._now()

        frameworks = data.get("frameworks", [])
        if not isinstance(frameworks, list):
            frameworks = []
        frameworks = [f for f in frameworks if f in _FRAMEWORKS]
        if not frameworks:
            frameworks = ["SOC2"]

        freq = int(data.get("scan_frequency_hours", 24))
        next_scan = (datetime.now(timezone.utc) + timedelta(hours=freq)).isoformat()

        record = {
            "profile_id": profile_id,
            "org_id": org_id,
            "name": str(data.get("name", "Default Profile")),
            "frameworks": frameworks,
            "scan_frequency_hours": freq,
            "last_scan": None,
            "next_scan": next_scan,
            "enabled": 1,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scan_profiles
                        (profile_id, org_id, name, frameworks, scan_frequency_hours,
                         last_scan, next_scan, enabled, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["profile_id"], record["org_id"], record["name"],
                        json.dumps(record["frameworks"]), record["scan_frequency_hours"],
                        record["last_scan"], record["next_scan"],
                        record["enabled"], record["created_at"],
                    ),
                )
        _logger.info("Created scan profile %s for org %s", profile_id, org_id)
        record["enabled"] = True
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "compliance_scanner", "org_id": org_id, "source_engine": "compliance_scanner"})
            except Exception:
                pass

        return record

    def list_profiles(self, org_id: str) -> List[dict]:
        """List all scan profiles for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_profiles WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._deserialize_profile(self._row_to_dict(r)) for r in rows]

    def get_profile(self, org_id: str, profile_id: str) -> Optional[dict]:
        """Fetch a single scan profile, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_profiles WHERE profile_id=? AND org_id=?",
                (profile_id, org_id),
            ).fetchone()
        if not row:
            return None
        return self._deserialize_profile(self._row_to_dict(row))

    # ------------------------------------------------------------------
    # Scan Execution
    # ------------------------------------------------------------------

    def start_scan(self, org_id: str, profile_id: str) -> dict:
        """Run a compliance scan for a profile. Returns the completed scan result."""
        profile = self.get_profile(org_id, profile_id)
        if not profile:
            raise ValueError(f"Profile {profile_id} not found for org {org_id}")

        result_id = str(uuid.uuid4())
        scan_started = self._now()

        # Insert scan result with status=running
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scan_results
                        (result_id, org_id, profile_id, scan_started, status)
                    VALUES (?,?,?,?,'running')
                    """,
                    (result_id, org_id, profile_id, scan_started),
                )

        # Generate compliance checks for each framework
        checks = []
        rng = random.Random()  # unseeded for realistic variation
        frameworks = profile["frameworks"]

        for framework in frameworks:
            controls = _FRAMEWORK_CONTROLS.get(framework, [])
            # Select 5-8 controls per framework
            num_controls = min(len(controls), rng.randint(5, 8))
            selected = rng.sample(controls, num_controls)

            for ctrl in selected:
                check_id = str(uuid.uuid4())
                # Realistic pass/fail distribution: ~70% pass, ~15% fail, ~10% warning, ~5% skip
                roll = rng.random()
                if roll < 0.70:
                    status = "pass"
                    evidence = f"Control {ctrl['control_id']} validated. Automated check passed at {scan_started}."
                    remediation = ""
                elif roll < 0.85:
                    status = "fail"
                    evidence = f"Control {ctrl['control_id']} failed. Configuration gap detected."
                    remediation = _REMEDIATION_TEMPLATES[ctrl["severity"]].format(
                        control_name=ctrl["control_name"]
                    )
                elif roll < 0.95:
                    status = "warning"
                    evidence = f"Control {ctrl['control_id']} partially met. Review recommended."
                    remediation = f"Review and strengthen {ctrl['control_name']} implementation."
                else:
                    status = "skip"
                    evidence = "Not applicable to current environment configuration."
                    remediation = ""

                checks.append({
                    "check_id": check_id,
                    "org_id": org_id,
                    "result_id": result_id,
                    "framework": framework,
                    "control_id": ctrl["control_id"],
                    "control_name": ctrl["control_name"],
                    "category": ctrl["category"],
                    "status": status,
                    "severity": ctrl["severity"],
                    "evidence": evidence,
                    "remediation": remediation,
                    "check_duration_ms": rng.randint(50, 800),
                })

        # Tally results
        total = len(checks)
        passed = sum(1 for c in checks if c["status"] == "pass")
        failed = sum(1 for c in checks if c["status"] == "fail")
        warnings = sum(1 for c in checks if c["status"] == "warning")
        score = round((passed / total) * 100, 2) if total > 0 else 0.0
        scan_completed = self._now()

        # Persist checks and update scan result
        with self._lock:
            with self._conn() as conn:
                conn.executemany(
                    """
                    INSERT INTO compliance_checks
                        (check_id, org_id, result_id, framework, control_id,
                         control_name, category, status, severity, evidence,
                         remediation, check_duration_ms)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    [
                        (
                            c["check_id"], c["org_id"], c["result_id"], c["framework"],
                            c["control_id"], c["control_name"], c["category"], c["status"],
                            c["severity"], c["evidence"], c["remediation"], c["check_duration_ms"],
                        )
                        for c in checks
                    ],
                )
                conn.execute(
                    """
                    UPDATE scan_results
                    SET scan_completed=?, total_checks=?, passed=?, failed=?,
                        warnings=?, score=?, status='completed'
                    WHERE result_id=?
                    """,
                    (scan_completed, total, passed, failed, warnings, score, result_id),
                )
                # Update profile last_scan and next_scan
                freq = profile["scan_frequency_hours"]
                next_scan = (
                    datetime.now(timezone.utc) + timedelta(hours=freq)
                ).isoformat()
                conn.execute(
                    "UPDATE scan_profiles SET last_scan=?, next_scan=? WHERE profile_id=?",
                    (scan_completed, next_scan, profile_id),
                )

        _logger.info(
            "Scan %s completed for profile %s org %s: %d checks, score=%.1f",
            result_id, profile_id, org_id, total, score,
        )

        return {
            "result_id": result_id,
            "org_id": org_id,
            "profile_id": profile_id,
            "scan_started": scan_started,
            "scan_completed": scan_completed,
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "score": score,
            "status": "completed",
        }

    # ------------------------------------------------------------------
    # Scan Results
    # ------------------------------------------------------------------

    def get_scan_result(self, org_id: str, result_id: str) -> Optional[dict]:
        """Fetch a single scan result, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_results WHERE result_id=? AND org_id=?",
                (result_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def list_scan_results(
        self,
        org_id: str,
        profile_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[dict]:
        """List scan results for an org, most recent first."""
        query = "SELECT * FROM scan_results WHERE org_id=?"
        params: list = [org_id]
        if profile_id:
            query += " AND profile_id=?"
            params.append(profile_id)
        query += " ORDER BY scan_started DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Compliance Checks
    # ------------------------------------------------------------------

    def list_checks(
        self,
        org_id: str,
        result_id: str,
        status: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> List[dict]:
        """List compliance checks for a scan result, with optional filters."""
        query = "SELECT * FROM compliance_checks WHERE org_id=? AND result_id=?"
        params: list = [org_id, result_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if framework:
            query += " AND framework=?"
            params.append(framework)
        query += " ORDER BY framework, control_id"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Remediation Tasks
    # ------------------------------------------------------------------

    def create_remediation_task(self, org_id: str, check_id: str, data: dict) -> dict:
        """Create a remediation task linked to a compliance check."""
        task_id = str(uuid.uuid4())
        now = self._now()

        priority = data.get("priority", "medium")
        if priority not in _TASK_PRIORITIES:
            priority = "medium"

        record = {
            "task_id": task_id,
            "org_id": org_id,
            "check_id": check_id,
            "title": str(data.get("title", "")),
            "description": str(data.get("description", "")),
            "priority": priority,
            "status": "open",
            "assigned_to": str(data.get("assigned_to", "")),
            "due_date": str(data.get("due_date", "")),
            "resolved_at": None,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO remediation_tasks
                        (task_id, org_id, check_id, title, description, priority,
                         status, assigned_to, due_date, resolved_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["task_id"], record["org_id"], record["check_id"],
                        record["title"], record["description"], record["priority"],
                        record["status"], record["assigned_to"], record["due_date"],
                        record["resolved_at"], record["created_at"],
                    ),
                )
        _logger.info("Created remediation task %s for org %s", task_id, org_id)
        return record

    def list_remediation_tasks(
        self,
        org_id: str,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[dict]:
        """List remediation tasks for an org with optional filters."""
        query = "SELECT * FROM remediation_tasks WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if priority:
            query += " AND priority=?"
            params.append(priority)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_task_status(
        self,
        org_id: str,
        task_id: str,
        status: str,
        resolved_by: Optional[str] = None,
    ) -> bool:
        """Update the status of a remediation task. Returns True if updated."""
        if status not in _TASK_STATUSES:
            return False
        now = self._now()
        resolved_at = now if status == "resolved" else None

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE remediation_tasks
                    SET status=?, resolved_at=?
                    WHERE task_id=? AND org_id=?
                    """,
                    (status, resolved_at, task_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_compliance_stats(self, org_id: str) -> dict:
        """Return aggregate compliance statistics for an org."""
        with self._conn() as conn:
            total_profiles = conn.execute(
                "SELECT COUNT(*) FROM scan_profiles WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_profiles = conn.execute(
                "SELECT COUNT(*) FROM scan_profiles WHERE org_id=? AND enabled=1", (org_id,)
            ).fetchone()[0]

            total_scans = conn.execute(
                "SELECT COUNT(*) FROM scan_results WHERE org_id=? AND status='completed'",
                (org_id,),
            ).fetchone()[0]

            avg_score_row = conn.execute(
                "SELECT AVG(score) FROM scan_results WHERE org_id=? AND status='completed'",
                (org_id,),
            ).fetchone()[0]
            avg_score = round(float(avg_score_row), 2) if avg_score_row is not None else 0.0

            open_tasks = conn.execute(
                "SELECT COUNT(*) FROM remediation_tasks WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            critical_tasks = conn.execute(
                """SELECT COUNT(*) FROM remediation_tasks
                   WHERE org_id=? AND priority='critical' AND status NOT IN ('resolved','accepted_risk')""",
                (org_id,),
            ).fetchone()[0]

            # Per-framework average scores: join scan_results with compliance_checks
            framework_rows = conn.execute(
                """
                SELECT cc.framework,
                       AVG(CASE WHEN cc.status='pass' THEN 100.0 ELSE 0.0 END) as fw_score
                FROM compliance_checks cc
                JOIN scan_results sr ON cc.result_id = sr.result_id
                WHERE cc.org_id=? AND sr.status='completed'
                GROUP BY cc.framework
                """,
                (org_id,),
            ).fetchall()

        by_framework: Dict[str, float] = {
            row[0]: round(float(row[1]), 2) for row in framework_rows
        }

        return {
            "total_profiles": total_profiles,
            "active_profiles": active_profiles,
            "total_scans": total_scans,
            "avg_score": avg_score,
            "open_tasks": open_tasks,
            "critical_tasks": critical_tasks,
            "by_framework": by_framework,
        }
