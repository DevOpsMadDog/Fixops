"""
Compliance Scanner Engine — ALDECI.

REAL IMPLEMENTATION: start_scan() executes the real ``checkov`` binary
against a target directory (or file) of IaC/configuration files and persists
actual pass/fail check results.  There are NO randomised or fabricated results.

Honest degradation:
- checkov not on PATH → ComplianceScanError (router surfaces as HTTP 422)
- target path missing/empty → ComplianceScanError (router surfaces as HTTP 422)
- checkov non-zero exit (checks failed) → normal; results still parsed

Supported frameworks: terraform, dockerfile, kubernetes (skips the ``secrets``
framework which has a broken detect-secrets dependency on this installation).

Control-family mapping is derived entirely from real checkov metadata:
  * check_class module path  (e.g. ``checkov.terraform.checks.resource.aws.S3…``)
  * check_id prefix          (CKV_AWS → terraform/aws, CKV_K8S → kubernetes,
                               CKV_DOCKER → dockerfile, etc.)
No SOC2/PCI/HIPAA control numbers are invented — if checkov provides none,
the control_family is set to the real check_class module prefix.

Profile/remediation-task CRUD, get_scan_result(), list_scan_results(),
list_checks(), get_compliance_stats() are all production-ready SQLite-backed
methods.  Thread-safe via RLock.  Multi-tenant via org_id.
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import subprocess
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
_logger.info(
    "%s loaded — start_scan() runs real checkov IaC/config compliance checks "
    "(frameworks: terraform, dockerfile, kubernetes). No simulated data.",
    __name__,
)

# Frameworks we scan with — excludes 'secrets' which crashes on this install
# due to a broken detect-secrets/checkov integration (AttributeError: JSON).
_CHECKOV_FRAMEWORKS = "terraform,dockerfile,kubernetes"

# Checkov process timeout in seconds
_CHECKOV_TIMEOUT = 120


class ComplianceScanError(ValueError):
    """Raised when a real checkov compliance scan cannot be performed.

    Surfaced by the router as HTTP 422 — never as fabricated results.
    Common causes:
    - checkov binary not on PATH
    - target path does not exist or contains no scannable files
    """

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

    # ------------------------------------------------------------------
    # Internal checkov helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_checkov() -> str:
        """Return the path to the checkov binary, or raise ComplianceScanError."""
        path = shutil.which("checkov")
        if path is None:
            raise ComplianceScanError(
                "checkov not installed — install it to run real compliance scans "
                "(pip install checkov or brew install checkov)"
            )
        return path

    @staticmethod
    def _control_family_from_check(check_id: str, check_class: str) -> str:
        """Derive the control family from REAL checkov metadata — no fabrication.

        Strategy (in order):
        1. check_id prefix  → maps to the IaC domain the check covers
           CKV_AWS / CKV2_AWS  → terraform/aws
           CKV_AZURE / CKV2_AZURE → terraform/azure
           CKV_GCP / CKV2_GCP  → terraform/gcp
           CKV_K8S             → kubernetes
           CKV_DOCKER          → dockerfile
           CKV_LIN             → terraform/linux
           everything else     → terraform (generic)
        2. Fallback: first two segments of check_class module path
           e.g. "checkov.terraform.checks.resource.aws.S3…" → "terraform/aws"
        """
        cid = (check_id or "").upper()
        if cid.startswith(("CKV_AWS", "CKV2_AWS", "BC_AWS")):
            return "terraform/aws"
        if cid.startswith(("CKV_AZURE", "CKV2_AZURE", "BC_AZURE")):
            return "terraform/azure"
        if cid.startswith(("CKV_GCP", "CKV2_GCP", "BC_GCP")):
            return "terraform/gcp"
        if cid.startswith("CKV_K8S"):
            return "kubernetes"
        if cid.startswith("CKV_DOCKER"):
            return "dockerfile"
        if cid.startswith("CKV_LIN"):
            return "terraform/linux"

        # Fall back to check_class module path
        if check_class:
            parts = check_class.split(".")
            # e.g. ["checkov","terraform","checks","resource","aws","S3…"]
            # skip "checkov" prefix; take next 2 meaningful segments
            filtered = [p for p in parts if p not in ("checkov", "checks", "resource", "graph", "common")]
            if len(filtered) >= 2:
                return f"{filtered[0]}/{filtered[1]}"
            if filtered:
                return filtered[0]

        return "terraform"

    @staticmethod
    def _parse_checkov_output(raw_json: str) -> tuple:
        """Parse checkov JSON output into (passed_count, failed_count, check_rows).

        Handles both single-framework output (dict) and multi-framework output
        (list of dicts).  Each item in check_rows is a dict with keys:
          check_id, check_class, check_name, file_path, resource,
          severity, guideline, status.
        """
        data = json.loads(raw_json)
        items: list = data if isinstance(data, list) else [data]

        passed_count = 0
        failed_count = 0
        check_rows: list = []

        for item in items:
            if not isinstance(item, dict):
                continue
            results = item.get("results", {})
            passed_checks = results.get("passed_checks", [])
            failed_checks = results.get("failed_checks", [])

            passed_count += len(passed_checks)
            failed_count += len(failed_checks)

            for chk in passed_checks:
                check_rows.append({
                    "check_id": chk.get("check_id", ""),
                    "check_class": chk.get("check_class", ""),
                    "check_name": chk.get("check_name", ""),
                    "file_path": chk.get("file_path", ""),
                    "resource": chk.get("resource", ""),
                    "severity": chk.get("severity") or "unknown",
                    "guideline": chk.get("guideline", ""),
                    "status": "pass",
                })
            for chk in failed_checks:
                check_rows.append({
                    "check_id": chk.get("check_id", ""),
                    "check_class": chk.get("check_class", ""),
                    "check_name": chk.get("check_name", ""),
                    "file_path": chk.get("file_path", ""),
                    "resource": chk.get("resource", ""),
                    "severity": chk.get("severity") or "unknown",
                    "guideline": chk.get("guideline", ""),
                    "status": "fail",
                })

        return passed_count, failed_count, check_rows

    def _persist_scan(
        self,
        org_id: str,
        profile_id: str,
        target_path: str,
        passed_count: int,
        failed_count: int,
        check_rows: list,
    ) -> dict:
        """Persist real checkov scan result + one compliance_check row per check.

        The framework column on each compliance_check row is set to the real
        control family derived from checkov metadata (check_id prefix +
        check_class module path).  No SOC2/PCI/HIPAA control numbers are
        invented.

        Returns a summary dict.
        """
        result_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        total = passed_count + failed_count
        score = round((passed_count / total) * 100, 2) if total > 0 else 0.0

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scan_results
                        (result_id, org_id, profile_id, scan_started,
                         scan_completed, total_checks, passed, failed,
                         warnings, score, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,'completed')
                    """,
                    (result_id, org_id, profile_id, now, now,
                     total, passed_count, failed_count, 0, score),
                )

                for row in check_rows:
                    control_family = self._control_family_from_check(
                        row["check_id"], row["check_class"]
                    )
                    raw_sev = (row.get("severity") or "unknown").lower()
                    severity = raw_sev if raw_sev in _SEVERITIES else "medium"
                    conn.execute(
                        """
                        INSERT INTO compliance_checks
                            (check_id, org_id, result_id, framework,
                             control_id, control_name, category, status,
                             severity, evidence, remediation, check_duration_ms)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            str(uuid.uuid4()),
                            org_id,
                            result_id,
                            control_family,
                            row["check_id"],
                            row["check_name"],
                            row["check_class"].split(".")[-1] if row["check_class"] else "",
                            row["status"],
                            severity,
                            f"{row['file_path']} | {row['resource']}",
                            row.get("guideline", ""),
                            0,
                        ),
                    )

                # Update profile last_scan
                conn.execute(
                    "UPDATE scan_profiles SET last_scan=? WHERE profile_id=? AND org_id=?",
                    (now, profile_id, org_id),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("COMPLIANCE_SCAN_COMPLETE", {
                        "entity_type": "compliance_scanner",
                        "org_id": org_id,
                        "source_engine": "compliance_scanner",
                        "passed": passed_count,
                        "failed": failed_count,
                        "score": score,
                    })
            except Exception:
                pass

        return {
            "result_id": result_id,
            "org_id": org_id,
            "profile_id": profile_id,
            "target_path": target_path,
            "scan_started": now,
            "scan_completed": now,
            "total_checks": total,
            "passed": passed_count,
            "failed": failed_count,
            "warnings": 0,
            "score": score,
            "status": "completed",
            "scanner": "checkov",
            "frameworks": _CHECKOV_FRAMEWORKS,
        }

    def start_scan(
        self,
        org_id: str,
        profile_id: str,
        target_path: Optional[str] = None,
    ) -> dict:
        """Run a real checkov compliance scan against ``target_path``.

        Parameters
        ----------
        org_id:
            Organisation identifier for multi-tenant isolation.
        profile_id:
            Scan profile to associate the results with.
        target_path:
            Filesystem path to the directory (or single file) to scan.
            Raises ComplianceScanError if not provided or not found.

        Returns
        -------
        dict
            Scan summary with ``result_id``, ``passed``, ``failed``,
            ``score``, ``status``, ``total_checks``.

        Raises
        ------
        ComplianceScanError
            If checkov is not installed, or the target path is missing/empty.
        """
        # --- Guard: checkov must be installed
        checkov_bin = self._find_checkov()

        # --- Guard: target_path must exist and have scannable content
        if not target_path:
            raise ComplianceScanError(
                "target_path is required — provide the directory or file to scan"
            )
        # SCIF hardening: confine scan target to the storage-root allowlist.
        from core.storage_root_guard import assert_path_allowed
        assert_path_allowed(target_path, "FIXOPS_SCANNER_ALLOWED_ROOTS", label="target_path")
        tp = Path(target_path)
        if not tp.exists():
            raise ComplianceScanError(
                f"target path not found: {target_path}"
            )
        if tp.is_dir():
            scannable = [f for f in tp.rglob("*") if f.is_file()]
            if not scannable:
                raise ComplianceScanError(
                    f"target path contains no scannable files: {target_path}"
                )

        # --- Build checkov command
        scan_flag = ["-d", str(tp)] if tp.is_dir() else ["-f", str(tp)]
        cmd = [
            checkov_bin,
            *scan_flag,
            "--framework", _CHECKOV_FRAMEWORKS,
            "-o", "json",
            "--compact",
        ]

        _logger.info(
            "compliance_scanner: running checkov on %s (org=%s, profile=%s)",
            target_path, org_id, profile_id,
        )

        # --- Execute checkov (exit code 1 = checks failed; that's normal)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_CHECKOV_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise ComplianceScanError(
                f"checkov timed out after {_CHECKOV_TIMEOUT}s scanning {target_path}"
            )
        except OSError as exc:
            raise ComplianceScanError(f"checkov execution failed: {exc}") from exc

        # checkov exits 0 (all pass), 1 (some fail), 2 (internal error)
        if proc.returncode == 2:
            stderr_snippet = (proc.stderr or "")[:500]
            raise ComplianceScanError(
                f"checkov exited with error (code 2). stderr: {stderr_snippet}"
            )

        raw_output = proc.stdout.strip()
        if not raw_output:
            raise ComplianceScanError(
                f"checkov produced no output for {target_path} — "
                "no scannable IaC/config files found in the target"
            )

        # --- Parse JSON output
        try:
            passed_count, failed_count, check_rows = self._parse_checkov_output(raw_output)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ComplianceScanError(
                f"failed to parse checkov JSON output: {exc}"
            ) from exc

        if passed_count == 0 and failed_count == 0:
            raise ComplianceScanError(
                f"checkov ran but found 0 checks in {target_path} — "
                "no IaC/config files matched the supported frameworks"
            )

        _logger.info(
            "compliance_scanner: checkov complete — passed=%d failed=%d (org=%s)",
            passed_count, failed_count, org_id,
        )

        return self._persist_scan(
            org_id=org_id,
            profile_id=profile_id,
            target_path=str(tp),
            passed_count=passed_count,
            failed_count=failed_count,
            check_rows=check_rows,
        )

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
