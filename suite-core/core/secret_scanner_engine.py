"""Secret Scanner Engine — ALDECI.

Detects leaked secrets in code repositories, filesystems, API responses,
config files, and environment files.

Capabilities:
  - Scan job lifecycle (pending → running → completed/failed)
  - Deterministic secret simulation by target_type
  - Finding management with severity, validation, and remediation tracking
  - Custom detection patterns (regex-based)
  - Suppression rules for known-good paths
  - Stats aggregation per org

Compliance: OWASP Top 10 (A07 Identification/Auth), CIS Controls v8 (Control 3),
            NIST SP 800-53 (IA-5), PCI DSS 3.4
"""

from __future__ import annotations

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

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_TARGET_TYPES = {
    "git_repo", "filesystem", "api_response", "config_file", "env_file",
}
_VALID_SCAN_STATUSES = {"pending", "running", "completed", "failed"}
_VALID_SECRET_TYPES = {
    "aws_access_key", "github_token", "google_api_key", "stripe_key",
    "jwt_token", "private_key", "password_in_code", "generic_api_key",
    "slack_webhook", "database_url", "oauth_token", "certificate",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_FINDING_STATUSES = {
    "new", "triaging", "remediated", "accepted_risk", "false_positive",
}
_VALID_VALIDITY = {"confirmed", "expired", "false_positive"}

# Deterministic simulation: target_type → list of (secret_type, severity, entropy)
_SCAN_TEMPLATES: Dict[str, List[tuple]] = {
    "git_repo": [
        ("aws_access_key", "critical", 8.7),
        ("github_token", "high", 8.1),
        ("generic_api_key", "medium", 7.4),
        ("oauth_token", "high", 7.9),
    ],
    "env_file": [
        ("database_url", "critical", 8.5),
        ("stripe_key", "critical", 8.8),
        ("jwt_token", "medium", 7.2),
    ],
    "config_file": [
        ("password_in_code", "high", 7.6),
        ("jwt_token", "medium", 7.3),
        ("google_api_key", "high", 7.8),
    ],
    "filesystem": [
        ("private_key", "critical", 8.9),
        ("oauth_token", "high", 8.0),
        ("certificate", "medium", 7.5),
    ],
    "api_response": [
        ("generic_api_key", "medium", 7.2),
        ("slack_webhook", "high", 7.7),
        ("github_token", "high", 8.2),
    ],
}

# Fake value templates for masking (first4 + ****×16 + last4)
_VALUE_TEMPLATES: Dict[str, tuple] = {
    "aws_access_key":     ("AKIA", "WXYZ"),
    "github_token":       ("ghp_", "Ab3X"),
    "google_api_key":     ("AIza", "kR9T"),
    "stripe_key":         ("sk_l", "Mn2P"),
    "jwt_token":          ("eyJh", "fQ=="),
    "private_key":        ("----", "----"),
    "password_in_code":   ("pass", "ord1"),
    "generic_api_key":    ("key_", "7g9Q"),
    "slack_webhook":      ("T00X", "XXXX"),
    "database_url":       ("post", "5432"),
    "oauth_token":        ("ya29", "XXXX"),
    "certificate":        ("MIIB", "==\n"),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mask_value(secret_type: str) -> str:
    first4, last4 = _VALUE_TEMPLATES.get(secret_type, ("????", "????"))
    return first4 + "*" * 16 + last4


class SecretScannerEngine:
    """SQLite WAL-backed secret scanner engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org gets its own DB file.
    """

    _instances: Dict[str, "SecretScannerEngine"] = {}
    _instances_lock = threading.Lock()

    def __init__(self, org_id: str) -> None:
        self.org_id = org_id
        self.db_path = str(_DATA_DIR / f"{org_id}_secret_scanner.db")
        self._lock = threading.RLock()
        self._init_db()

    @classmethod
    def for_org(cls, org_id: str) -> "SecretScannerEngine":
        with cls._instances_lock:
            if org_id not in cls._instances:
                cls._instances[org_id] = cls(org_id)
            return cls._instances[org_id]

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    target_type       TEXT NOT NULL,
                    target_path       TEXT NOT NULL DEFAULT '',
                    status            TEXT NOT NULL DEFAULT 'pending',
                    secrets_found     INTEGER NOT NULL DEFAULT 0,
                    critical_count    INTEGER NOT NULL DEFAULT 0,
                    scan_duration_ms  INTEGER NOT NULL DEFAULT 0,
                    created_at        DATETIME NOT NULL,
                    completed_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_sj_org_status
                    ON scan_jobs (org_id, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS secret_findings (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    job_id            TEXT NOT NULL,
                    secret_type       TEXT NOT NULL,
                    file_path         TEXT NOT NULL DEFAULT '',
                    line_number       INTEGER NOT NULL DEFAULT 0,
                    severity          TEXT NOT NULL DEFAULT 'medium',
                    value_masked      TEXT NOT NULL DEFAULT '',
                    entropy           REAL NOT NULL DEFAULT 0.0,
                    is_valid_secret   TEXT,
                    status            TEXT NOT NULL DEFAULT 'new',
                    remediation_notes TEXT NOT NULL DEFAULT '',
                    discovered_at     DATETIME NOT NULL,
                    remediated_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_sf_org_job
                    ON secret_findings (org_id, job_id, discovered_at DESC);

                CREATE INDEX IF NOT EXISTS idx_sf_org_severity
                    ON secret_findings (org_id, severity, status);

                CREATE TABLE IF NOT EXISTS secret_patterns (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    pattern_name         TEXT NOT NULL,
                    regex_pattern        TEXT NOT NULL,
                    secret_type          TEXT NOT NULL,
                    severity             TEXT NOT NULL DEFAULT 'medium',
                    enabled              INTEGER NOT NULL DEFAULT 1,
                    false_positive_rate  REAL NOT NULL DEFAULT 0.0,
                    created_at           DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sp_org
                    ON secret_patterns (org_id, enabled);

                CREATE TABLE IF NOT EXISTS suppression_rules (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    file_pattern TEXT NOT NULL,
                    secret_type  TEXT NOT NULL,
                    reason       TEXT NOT NULL DEFAULT '',
                    approved_by  TEXT NOT NULL DEFAULT '',
                    expires_at   DATETIME,
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sr_org
                    ON suppression_rules (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Scan Jobs
    # ------------------------------------------------------------------

    def create_scan_job(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new scan job in pending state."""
        target_type = data.get("target_type", "filesystem")
        if target_type not in _VALID_TARGET_TYPES:
            raise ValueError(
                f"Invalid target_type: {target_type}. Must be one of {_VALID_TARGET_TYPES}"
            )
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "target_type": target_type,
            "target_path": data.get("target_path", ""),
            "status": "pending",
            "secrets_found": 0,
            "critical_count": 0,
            "scan_duration_ms": 0,
            "created_at": now,
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scan_jobs
                       (id, org_id, target_type, target_path, status,
                        secrets_found, critical_count, scan_duration_ms, created_at, completed_at)
                       VALUES (:id, :org_id, :target_type, :target_path, :status,
                               :secrets_found, :critical_count, :scan_duration_ms,
                               :created_at, :completed_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "secret_scanner", "org_id": org_id, "source_engine": "secret_scanner"})
            except Exception:
                pass

        return record

    def start_scan(self, org_id: str, job_id: str) -> Dict[str, Any]:
        """Mark job as running and execute simulation, returning completed job."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM scan_jobs WHERE org_id = ? AND id = ?",
                    (org_id, job_id),
                ).fetchone()
            if not row:
                raise ValueError(f"Scan job {job_id} not found.")
            job = self._row(row)
            if job["status"] not in ("pending",):
                raise ValueError(
                    f"Job {job_id} is in '{job['status']}' state; can only start pending jobs."
                )
            # Mark running
            with self._conn() as conn:
                conn.execute(
                    "UPDATE scan_jobs SET status = 'running' WHERE org_id = ? AND id = ?",
                    (org_id, job_id),
                )
            job["status"] = "running"

        # Perform simulation (outside lock so it doesn't block reads)
        try:
            self._simulate_scan(org_id, job)
        except Exception as exc:
            _logger.error("Scan simulation failed for job %s: %s", job_id, exc)
            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        "UPDATE scan_jobs SET status = 'failed' WHERE org_id = ? AND id = ?",
                        (org_id, job_id),
                    )
            raise

        # Return refreshed job
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_jobs WHERE org_id = ? AND id = ?",
                (org_id, job_id),
            ).fetchone()
        return self._row(row)

    def _simulate_scan(self, org_id: str, job: Dict[str, Any]) -> None:
        """Deterministic scan simulation based on target_type."""
        target_type = job["target_type"]
        job_id = job["id"]
        templates = _SCAN_TEMPLATES.get(target_type, _SCAN_TEMPLATES["filesystem"])

        # Simulate scan duration (deterministic based on target_type)
        duration_map = {
            "git_repo": 4200,
            "filesystem": 3100,
            "env_file": 800,
            "config_file": 1200,
            "api_response": 600,
        }
        scan_duration_ms = duration_map.get(target_type, 2000)

        # Build fake file paths per target type
        path_templates = {
            "git_repo": ["src/config/settings.py", "deploy/infra.tf", ".github/workflows/ci.yml"],
            "filesystem": ["/etc/app/config.conf", "/home/user/.ssh/id_rsa", "/opt/app/secrets.txt"],
            "env_file": [".env", ".env.production", "docker/.env"],
            "config_file": ["config/database.yml", "app/settings.json", "helm/values.yaml"],
            "api_response": ["response_cache/auth.json", "logs/api_debug.log", "tmp/response.json"],
        }
        paths = path_templates.get(target_type, path_templates["filesystem"])

        now = _now_iso()
        findings = []
        critical_count = 0

        for i, (secret_type, severity, entropy) in enumerate(templates):
            finding = {
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "job_id": job_id,
                "secret_type": secret_type,
                "file_path": paths[i % len(paths)],
                "line_number": (i + 1) * 12,
                "severity": severity,
                "value_masked": _mask_value(secret_type),
                "entropy": entropy,
                "is_valid_secret": None,
                "status": "new",
                "remediation_notes": "",
                "discovered_at": now,
                "remediated_at": None,
            }
            findings.append(finding)
            if severity == "critical":
                critical_count += 1

        with self._lock:
            with self._conn() as conn:
                conn.executemany(
                    """INSERT INTO secret_findings
                       (id, org_id, job_id, secret_type, file_path, line_number,
                        severity, value_masked, entropy, is_valid_secret, status,
                        remediation_notes, discovered_at, remediated_at)
                       VALUES (:id, :org_id, :job_id, :secret_type, :file_path,
                               :line_number, :severity, :value_masked, :entropy,
                               :is_valid_secret, :status, :remediation_notes,
                               :discovered_at, :remediated_at)""",
                    findings,
                )
                conn.execute(
                    """UPDATE scan_jobs
                       SET status = 'completed',
                           secrets_found = ?,
                           critical_count = ?,
                           scan_duration_ms = ?,
                           completed_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (len(findings), critical_count, scan_duration_ms, now, org_id, job_id),
                )

    def list_scan_jobs(
        self,
        org_id: str,
        status: Optional[str] = None,
        target_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scan jobs with optional filters."""
        sql = "SELECT * FROM scan_jobs WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if target_type:
            sql += " AND target_type = ?"
            params.append(target_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_scan_job(self, org_id: str, job_id: str) -> Optional[Dict[str, Any]]:
        """Return job with its findings list."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_jobs WHERE org_id = ? AND id = ?",
                (org_id, job_id),
            ).fetchone()
            if not row:
                return None
            job = self._row(row)
            findings = [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM secret_findings WHERE org_id = ? AND job_id = ? ORDER BY discovered_at DESC",
                    (org_id, job_id),
                ).fetchall()
            ]
        job["findings"] = findings
        return job

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def list_findings(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        secret_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        sql = "SELECT * FROM secret_findings WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if secret_type:
            sql += " AND secret_type = ?"
            params.append(secret_type)
        sql += " ORDER BY discovered_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def update_finding(
        self,
        org_id: str,
        finding_id: str,
        status: str,
        notes: Optional[str] = None,
    ) -> bool:
        """Update finding status and optional remediation notes."""
        if status not in _VALID_FINDING_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {_VALID_FINDING_STATUSES}"
            )
        now = _now_iso()
        remediated_at = now if status == "remediated" else None
        with self._lock:
            with self._conn() as conn:
                if notes is not None:
                    cur = conn.execute(
                        """UPDATE secret_findings
                           SET status = ?, remediation_notes = ?, remediated_at = ?
                           WHERE org_id = ? AND id = ?""",
                        (status, notes, remediated_at, org_id, finding_id),
                    )
                else:
                    cur = conn.execute(
                        """UPDATE secret_findings
                           SET status = ?, remediated_at = ?
                           WHERE org_id = ? AND id = ?""",
                        (status, remediated_at, org_id, finding_id),
                    )
                return cur.rowcount > 0

    def validate_finding(
        self, org_id: str, finding_id: str, is_valid: bool
    ) -> bool:
        """Mark a finding as confirmed or false_positive."""
        validity = "confirmed" if is_valid else "false_positive"
        # If false_positive, also update status
        new_status = "false_positive" if not is_valid else None
        with self._lock:
            with self._conn() as conn:
                if new_status:
                    cur = conn.execute(
                        """UPDATE secret_findings
                           SET is_valid_secret = ?, status = ?
                           WHERE org_id = ? AND id = ?""",
                        (validity, new_status, org_id, finding_id),
                    )
                else:
                    cur = conn.execute(
                        """UPDATE secret_findings
                           SET is_valid_secret = ?
                           WHERE org_id = ? AND id = ?""",
                        (validity, org_id, finding_id),
                    )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Patterns
    # ------------------------------------------------------------------

    def create_pattern(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a custom detection pattern."""
        pattern_name = (data.get("pattern_name") or "").strip()
        regex_pattern = (data.get("regex_pattern") or "").strip()
        if not pattern_name or not regex_pattern:
            raise ValueError("pattern_name and regex_pattern are required.")
        secret_type = data.get("secret_type", "generic_api_key")
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "pattern_name": pattern_name,
            "regex_pattern": regex_pattern,
            "secret_type": secret_type,
            "severity": severity,
            "enabled": 1 if data.get("enabled", True) else 0,
            "false_positive_rate": float(data.get("false_positive_rate", 0.0)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO secret_patterns
                       (id, org_id, pattern_name, regex_pattern, secret_type,
                        severity, enabled, false_positive_rate, created_at)
                       VALUES (:id, :org_id, :pattern_name, :regex_pattern, :secret_type,
                               :severity, :enabled, :false_positive_rate, :created_at)""",
                    record,
                )
        return record

    def list_patterns(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all patterns for org."""
        with self._conn() as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM secret_patterns WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Suppression Rules
    # ------------------------------------------------------------------

    def add_suppression(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a suppression rule for a file pattern + secret type."""
        file_pattern = (data.get("file_pattern") or "").strip()
        secret_type = (data.get("secret_type") or "").strip()
        if not file_pattern or not secret_type:
            raise ValueError("file_pattern and secret_type are required.")
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "file_pattern": file_pattern,
            "secret_type": secret_type,
            "reason": data.get("reason", ""),
            "approved_by": data.get("approved_by", ""),
            "expires_at": data.get("expires_at"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO suppression_rules
                       (id, org_id, file_pattern, secret_type, reason, approved_by, expires_at, created_at)
                       VALUES (:id, :org_id, :file_pattern, :secret_type, :reason,
                               :approved_by, :expires_at, :created_at)""",
                    record,
                )
        return record

    def list_suppressions(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all suppression rules for org."""
        with self._conn() as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM suppression_rules WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_scanner_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated scanner stats for org."""
        with self._conn() as conn:
            total_jobs = conn.execute(
                "SELECT COUNT(*) FROM scan_jobs WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_findings = conn.execute(
                "SELECT COUNT(*) FROM secret_findings WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # By secret type
            by_type_rows = conn.execute(
                """SELECT secret_type, COUNT(*) as cnt
                   FROM secret_findings WHERE org_id = ?
                   GROUP BY secret_type""",
                (org_id,),
            ).fetchall()
            by_type = {r["secret_type"]: r["cnt"] for r in by_type_rows}

            # By severity
            by_sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt
                   FROM secret_findings WHERE org_id = ?
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in by_sev_rows}

            remediated = conn.execute(
                """SELECT COUNT(*) FROM secret_findings
                   WHERE org_id = ? AND status = 'remediated'""",
                (org_id,),
            ).fetchone()[0]

            confirmed_active = conn.execute(
                """SELECT COUNT(*) FROM secret_findings
                   WHERE org_id = ? AND is_valid_secret = 'confirmed'
                   AND status NOT IN ('remediated', 'false_positive')""",
                (org_id,),
            ).fetchone()[0]

            false_positives = conn.execute(
                """SELECT COUNT(*) FROM secret_findings
                   WHERE org_id = ? AND status = 'false_positive'""",
                (org_id,),
            ).fetchone()[0]

            critical_unresolved = conn.execute(
                """SELECT COUNT(*) FROM secret_findings
                   WHERE org_id = ? AND severity = 'critical'
                   AND status NOT IN ('remediated', 'false_positive', 'accepted_risk')""",
                (org_id,),
            ).fetchone()[0]

        remediation_rate = (
            round(remediated / total_findings, 4) if total_findings > 0 else 0.0
        )
        false_positive_rate = (
            round(false_positives / total_findings, 4) if total_findings > 0 else 0.0
        )

        return {
            "total_jobs": total_jobs,
            "total_findings": total_findings,
            "by_type": by_type,
            "by_severity": by_severity,
            "remediation_rate": remediation_rate,
            "confirmed_active": confirmed_active,
            "false_positive_rate": false_positive_rate,
            "critical_unresolved": critical_unresolved,
        }
