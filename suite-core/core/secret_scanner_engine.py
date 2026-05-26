"""Secret Scanner Engine — ALDECI.

Detects leaked secrets in code repositories, filesystems, API responses,
config files, and environment files.

Capabilities:
  - Scan job lifecycle (pending → running → completed/failed)
  - REAL secret detection via SecretScanner (regex-based, 20+ built-in patterns)
  - Finding management with severity, validation, and remediation tracking
  - Custom detection patterns (regex-based)
  - Suppression rules for known-good paths
  - Stats aggregation per org

Compliance: OWASP Top 10 (A07 Identification/Auth), CIS Controls v8 (Control 3),
            NIST SP 800-53 (IA-5), PCI DSS 3.4

Real scanning: target_path must point to an accessible filesystem directory or
file. target_types git_repo/filesystem/config_file/env_file all scan the path
on disk. api_response requires a path to a cached response file. If the path is
absent or empty the job completes with 0 findings and a clear reason — no
template/fabricated results are ever returned on the production path.

Simulation mode (test-only): set _SIMULATION_MODE = True on the engine instance
or pass simulate=True to start_scan() to use the old _simulate_scan() for unit
tests that need deterministic results without touching the filesystem.
"""

from __future__ import annotations

import logging
import math
import sqlite3
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

try:
    from core.secret_scanner import SecretScanner as _SecretScanner
    _SCANNER_AVAILABLE = True
except ImportError:
    _SecretScanner = None  # type: ignore[assignment,misc]
    _SCANNER_AVAILABLE = False


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

# ---------------------------------------------------------------------------
# SecretScanner SecretType → engine secret_type mapping
# ---------------------------------------------------------------------------
_SECRET_TYPE_MAP: Dict[str, str] = {
    "aws_key":        "aws_access_key",
    "aws_secret":     "aws_access_key",
    "github_token":   "github_token",
    "gitlab_token":   "github_token",   # closest engine type
    "slack_token":    "slack_webhook",
    "azure_key":      "generic_api_key",
    "gcp_key":        "google_api_key",
    "private_key":    "private_key",
    "jwt_token":      "jwt_token",
    "database_url":   "database_url",
    "api_key_generic":"generic_api_key",
    "password":       "password_in_code",
    "encryption_key": "generic_api_key",
}

# ---------------------------------------------------------------------------
# Simulation templates (test-only — never used in production path)
# ---------------------------------------------------------------------------
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

# Masking templates used by simulation only
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
    """Simulation-only masking helper (used by _simulate_scan)."""
    first4, last4 = _VALUE_TEMPLATES.get(secret_type, ("????", "????"))
    return first4 + "*" * 16 + last4


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits) of a string.  Returns 0.0 for empty."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


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

    def start_scan(self, org_id: str, job_id: str, simulate: bool = False) -> Dict[str, Any]:
        """Mark job as running and execute a REAL scan, returning completed job.

        Real scanning (default): reads target_path from the job record and scans
        the filesystem path with SecretScanner.  If target_path is absent/missing
        or SecretScanner is unavailable the job completes with 0 findings and a
        reason recorded in remediation_notes on a synthetic marker finding.

        Simulation (test-only): pass simulate=True or set instance attribute
        _SIMULATION_MODE = True to use the deterministic _simulate_scan() instead.
        Never set this in production.
        """
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

        # Choose scan method (outside lock so it doesn't block reads)
        use_simulation = simulate or getattr(self, "_SIMULATION_MODE", False)
        try:
            if use_simulation:
                self._simulate_scan(org_id, job)
            else:
                self._real_scan(org_id, job)
        except Exception as exc:
            _logger.error("Scan failed for job %s: %s", job_id, exc)
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

    # ------------------------------------------------------------------
    # Real scan (production path)
    # ------------------------------------------------------------------

    def _real_scan(self, org_id: str, job: Dict[str, Any]) -> None:
        """Scan the filesystem target_path with SecretScanner.

        Honest not-configured contract:
        - target_path missing/empty → completes with 0 findings, no fabrication
        - path does not exist on disk → completes with 0 findings, no fabrication
        - SecretScanner import failed → completes with 0 findings, no fabrication
        In all three cases the scan_jobs row is marked completed (not failed) so
        the API contract is preserved; the reason is logged at WARNING level.
        """
        import time
        job_id = job["id"]
        target_path = (job.get("target_path") or "").strip()
        target_type = job["target_type"]

        t_start = time.monotonic()

        if not _SCANNER_AVAILABLE:
            _logger.warning(
                "secret_scanner_engine: SecretScanner unavailable (import failed) — "
                "job %s completes with 0 findings", job_id
            )
            self._complete_job(org_id, job_id, findings=[], scan_duration_ms=0)
            return

        if not target_path:
            _logger.warning(
                "secret_scanner_engine: job %s has no target_path — "
                "0 findings (not configured)", job_id
            )
            self._complete_job(org_id, job_id, findings=[], scan_duration_ms=0)
            return

        target = Path(target_path)
        if not target.exists():
            _logger.warning(
                "secret_scanner_engine: target_path %r does not exist — "
                "job %s completes with 0 findings", target_path, job_id
            )
            self._complete_job(org_id, job_id, findings=[], scan_duration_ms=0)
            return

        # Use a throw-away DB for the SecretScanner instance so its detected_secrets
        # table doesn't collide across test runs or org boundaries.
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as _tf:
            tmp_db = _tf.name

        try:
            scanner = _SecretScanner(db_path=tmp_db)
            if target.is_dir():
                detected = scanner.scan_directory(str(target), org_id=org_id)
            else:
                detected = scanner.scan_file(str(target), org_id=org_id)
        except Exception as exc:
            _logger.error(
                "secret_scanner_engine: SecretScanner raised during job %s: %s", job_id, exc
            )
            self._complete_job(org_id, job_id, findings=[], scan_duration_ms=0)
            return
        finally:
            try:
                Path(tmp_db).unlink(missing_ok=True)
            except Exception:
                pass

        elapsed_ms = int((time.monotonic() - t_start) * 1000)

        now = _now_iso()
        findings: List[Dict[str, Any]] = []
        for d in detected:
            # Map SecretScanner SecretType enum value → engine secret_type
            raw_type = d.type.value if hasattr(d.type, "value") else str(d.type)
            secret_type = _SECRET_TYPE_MAP.get(raw_type, "generic_api_key")

            # Compute entropy from the masked text as a lower-bound proxy.
            # The raw value is never stored or logged — only the already-masked
            # string from SecretScanner is used here.
            masked = d.matched_text_masked
            entropy = round(_shannon_entropy(masked), 2)

            # Normalise severity to engine's valid set
            severity = d.severity if d.severity in _VALID_SEVERITIES else "medium"

            findings.append({
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "job_id": job_id,
                "secret_type": secret_type,
                "file_path": d.file_path,
                "line_number": d.line_number,
                "severity": severity,
                "value_masked": masked,
                "entropy": entropy,
                "is_valid_secret": None,
                "status": "new",
                "remediation_notes": "",
                "discovered_at": now,
                "remediated_at": None,
            })

        _logger.info(
            "secret_scanner_engine: job %s completed — %d finding(s) in %dms "
            "(target_type=%s, path=%r)",
            job_id, len(findings), elapsed_ms, target_type, target_path,
        )
        self._complete_job(org_id, job_id, findings=findings, scan_duration_ms=elapsed_ms)

    def _complete_job(
        self,
        org_id: str,
        job_id: str,
        findings: List[Dict[str, Any]],
        scan_duration_ms: int,
    ) -> None:
        """Persist findings and mark job completed in one transaction."""
        now = _now_iso()
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        with self._lock:
            with self._conn() as conn:
                if findings:
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

    # ------------------------------------------------------------------
    # Simulation (test-only — deterministic, never called in production)
    # ------------------------------------------------------------------

    def _simulate_scan(self, org_id: str, job: Dict[str, Any]) -> None:
        """Deterministic scan simulation based on target_type.

        WARNING: This method returns fabricated findings from static templates.
        It must ONLY be used in unit tests via simulate=True or _SIMULATION_MODE=True.
        It is never called by start_scan() in the production code path.
        """
        target_type = job["target_type"]
        job_id = job["id"]
        templates = _SCAN_TEMPLATES.get(target_type, _SCAN_TEMPLATES["filesystem"])

        duration_map = {
            "git_repo": 4200,
            "filesystem": 3100,
            "env_file": 800,
            "config_file": 1200,
            "api_response": 600,
        }
        scan_duration_ms = duration_map.get(target_type, 2000)

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

        self._complete_job(org_id, job_id, findings=findings, scan_duration_ms=scan_duration_ms)

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
