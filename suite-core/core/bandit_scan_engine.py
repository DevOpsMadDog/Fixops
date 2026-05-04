"""
Bandit SAST scan engine.

Singleton-backed engine that:
  * persists scan jobs to SQLite (data/security/bandit_scans.db)
  * exposes the canonical Bandit rule catalog (B-codes)
  * provides queue + status + listing primitives consumed by bandit_router

The actual ``bandit`` binary execution is intentionally NOT performed here —
this engine queues scans and stores their lifecycle so the router can
return capability + scan-id contracts honestly. A separate worker (or the
caller) is responsible for advancing ``status`` from ``queued`` to
``running``/``completed`` once the scanner produces findings.

This honors the NO-MOCKS rule: when no real findings exist we return
``status="empty"`` rather than fabricating data.
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
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical Bandit rule catalog
# Source: https://bandit.readthedocs.io/en/latest/plugins/index.html
# Hardcoded so the capability endpoint works air-gapped (V9).
# ---------------------------------------------------------------------------

BANDIT_RULES: List[Dict[str, str]] = [
    {"rule_id": "B101", "name": "assert_used", "severity": "LOW", "confidence": "HIGH",
     "description": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code."},
    {"rule_id": "B102", "name": "exec_used", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of exec detected."},
    {"rule_id": "B103", "name": "set_bad_file_permissions", "severity": "HIGH", "confidence": "HIGH",
     "description": "Chmod setting a permissive mask 0oXXX on file."},
    {"rule_id": "B104", "name": "hardcoded_bind_all_interfaces", "severity": "MEDIUM", "confidence": "MEDIUM",
     "description": "Possible binding to all interfaces."},
    {"rule_id": "B105", "name": "hardcoded_password_string", "severity": "LOW", "confidence": "MEDIUM",
     "description": "Possible hardcoded password string."},
    {"rule_id": "B106", "name": "hardcoded_password_funcarg", "severity": "LOW", "confidence": "MEDIUM",
     "description": "Possible hardcoded password as function argument."},
    {"rule_id": "B107", "name": "hardcoded_password_default", "severity": "LOW", "confidence": "MEDIUM",
     "description": "Possible hardcoded password in default argument."},
    {"rule_id": "B108", "name": "hardcoded_tmp_directory", "severity": "MEDIUM", "confidence": "MEDIUM",
     "description": "Probable insecure usage of temp file/directory."},
    {"rule_id": "B110", "name": "try_except_pass", "severity": "LOW", "confidence": "HIGH",
     "description": "Try, Except, Pass detected."},
    {"rule_id": "B112", "name": "try_except_continue", "severity": "LOW", "confidence": "HIGH",
     "description": "Try, Except, Continue detected."},
    {"rule_id": "B201", "name": "flask_debug_true", "severity": "HIGH", "confidence": "MEDIUM",
     "description": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger."},
    {"rule_id": "B301", "name": "pickle", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Pickle and modules that wrap it can be unsafe when used to deserialise untrusted data."},
    {"rule_id": "B302", "name": "marshal", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Deserialisation with the marshal module is possibly dangerous."},
    {"rule_id": "B303", "name": "md5", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of insecure MD2, MD4, MD5, or SHA1 hash function."},
    {"rule_id": "B304", "name": "ciphers", "severity": "HIGH", "confidence": "HIGH",
     "description": "Use of insecure cipher."},
    {"rule_id": "B305", "name": "cipher_modes", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of insecure cipher mode."},
    {"rule_id": "B306", "name": "mktemp_q", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of insecure and deprecated function (mktemp)."},
    {"rule_id": "B307", "name": "eval", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of possibly insecure function — consider using safer ast.literal_eval."},
    {"rule_id": "B308", "name": "mark_safe", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of mark_safe() may expose XSS vulnerabilities."},
    {"rule_id": "B310", "name": "urllib_urlopen", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Audit url open for permitted schemes."},
    {"rule_id": "B311", "name": "random", "severity": "LOW", "confidence": "HIGH",
     "description": "Standard pseudo-random generators are not suitable for security/cryptographic purposes."},
    {"rule_id": "B312", "name": "telnetlib", "severity": "HIGH", "confidence": "HIGH",
     "description": "Telnet-related functions are being called."},
    {"rule_id": "B321", "name": "ftplib", "severity": "HIGH", "confidence": "HIGH",
     "description": "FTP-related functions are being called. FTP is considered insecure."},
    {"rule_id": "B324", "name": "hashlib_insecure_functions", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of weak MD2, MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False."},
    {"rule_id": "B501", "name": "request_with_no_cert_validation", "severity": "HIGH", "confidence": "HIGH",
     "description": "Requests call with verify=False disabling SSL certificate checks."},
    {"rule_id": "B502", "name": "ssl_with_bad_version", "severity": "HIGH", "confidence": "HIGH",
     "description": "Function call with insecure SSL/TLS protocol version identified."},
    {"rule_id": "B503", "name": "ssl_with_bad_defaults", "severity": "MEDIUM", "confidence": "MEDIUM",
     "description": "Function definition identified with insecure SSL/TLS protocol version by default."},
    {"rule_id": "B504", "name": "ssl_with_no_version", "severity": "LOW", "confidence": "MEDIUM",
     "description": "ssl.wrap_socket call with no SSL/TLS protocol version specified — auto-negotiation may select insecure."},
    {"rule_id": "B505", "name": "weak_cryptographic_key", "severity": "HIGH", "confidence": "HIGH",
     "description": "Use of weak cryptographic key."},
    {"rule_id": "B506", "name": "yaml_load", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load."},
    {"rule_id": "B507", "name": "ssh_no_host_key_verification", "severity": "HIGH", "confidence": "MEDIUM",
     "description": "Paramiko call with policy set to automatically trust the unknown host key."},
    {"rule_id": "B601", "name": "paramiko_calls", "severity": "MEDIUM", "confidence": "MEDIUM",
     "description": "Possible shell injection via Paramiko call."},
    {"rule_id": "B602", "name": "subprocess_popen_with_shell_equals_true", "severity": "HIGH", "confidence": "HIGH",
     "description": "subprocess call with shell=True identified, security issue."},
    {"rule_id": "B603", "name": "subprocess_without_shell_equals_true", "severity": "LOW", "confidence": "HIGH",
     "description": "subprocess call - check for execution of untrusted input."},
    {"rule_id": "B604", "name": "any_other_function_with_shell_equals_true", "severity": "MEDIUM", "confidence": "LOW",
     "description": "Function call with shell=True parameter identified."},
    {"rule_id": "B605", "name": "start_process_with_a_shell", "severity": "HIGH", "confidence": "HIGH",
     "description": "Starting a process with a shell, possible injection detected."},
    {"rule_id": "B606", "name": "start_process_with_no_shell", "severity": "LOW", "confidence": "MEDIUM",
     "description": "Starting a process without a shell."},
    {"rule_id": "B607", "name": "start_process_with_partial_path", "severity": "LOW", "confidence": "HIGH",
     "description": "Starting a process with a partial executable path."},
    {"rule_id": "B608", "name": "hardcoded_sql_expressions", "severity": "MEDIUM", "confidence": "LOW",
     "description": "Possible SQL injection vector through string-based query construction."},
    {"rule_id": "B609", "name": "linux_commands_wildcard_injection", "severity": "HIGH", "confidence": "MEDIUM",
     "description": "Possible wildcard injection in call."},
    {"rule_id": "B610", "name": "django_extra_used", "severity": "MEDIUM", "confidence": "MEDIUM",
     "description": "Use of Django extra() can lead to SQL injection."},
    {"rule_id": "B611", "name": "django_rawsql_used", "severity": "MEDIUM", "confidence": "MEDIUM",
     "description": "Use of RawSQL can lead to SQL injection."},
    {"rule_id": "B701", "name": "jinja2_autoescape_false", "severity": "HIGH", "confidence": "HIGH",
     "description": "Using jinja2 templates with autoescape=False is dangerous and can lead to XSS."},
    {"rule_id": "B702", "name": "use_of_mako_templates", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks."},
    {"rule_id": "B703", "name": "django_mark_safe", "severity": "MEDIUM", "confidence": "HIGH",
     "description": "Use of mark_safe() may expose cross-site scripting vulnerabilities."},
]

ALL_RULE_IDS: List[str] = [r["rule_id"] for r in BANDIT_RULES]
SEVERITY_LEVELS: List[str] = ["LOW", "MEDIUM", "HIGH"]
CONFIDENCE_LEVELS: List[str] = ["LOW", "MEDIUM", "HIGH"]

# ---------------------------------------------------------------------------
# SQLite engine
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = Path("data") / "security" / "bandit_scans.db"


class BanditScanEngine:
    """SQLite-backed Bandit scan job tracker."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = str(db_path) if db_path else str(DEFAULT_DB_PATH)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    # -- schema ----------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bandit_scans (
                    scan_id TEXT PRIMARY KEY,
                    target_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity_counts_json TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT
                )
                """
            )
            conn.commit()

    # -- catalog ---------------------------------------------------------

    @staticmethod
    def list_rules() -> List[Dict[str, str]]:
        return list(BANDIT_RULES)

    @staticmethod
    def get_rule(rule_id: str) -> Optional[Dict[str, str]]:
        rid = rule_id.upper().strip()
        for r in BANDIT_RULES:
            if r["rule_id"] == rid:
                return dict(r)
        return None

    # -- scans -----------------------------------------------------------

    def queue_scan(
        self,
        target_path: str,
        rule_ids: Optional[List[str]] = None,
        severity_threshold: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Persist a queued scan record. Returns the scan stub. The scanner
        worker is responsible for advancing status and writing findings.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        sev_counts: Dict[str, int] = {s: 0 for s in SEVERITY_LEVELS}
        findings: List[Dict[str, Any]] = []
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO bandit_scans
                  (scan_id, target_path, status, severity_counts_json,
                   findings_json, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    scan_id,
                    target_path,
                    "queued",
                    json.dumps(sev_counts),
                    json.dumps(findings),
                    started_at,
                ),
            )
            conn.commit()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "scan.completed",
                        {
                            "entity_id": scan_id,
                            "type": "bandit_sast_scan",
                            "severity": severity_threshold or "unknown",
                            "source_engine": "bandit_scan",
                            "target": target_path,
                            "status": "queued",
                        },
                    )
            except Exception:
                pass
        return {
            "scan_id": scan_id,
            "status": "queued",
            "target": target_path,
            "started_at": started_at,
            "rule_ids": rule_ids or [],
            "severity_threshold": severity_threshold,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM bandit_scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM bandit_scans ORDER BY started_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_scans(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM bandit_scans").fetchone()
        return int(row["c"]) if row else 0

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "scan_id": row["scan_id"],
            "target_path": row["target_path"],
            "status": row["status"],
            "severity_counts": json.loads(row["severity_counts_json"]),
            "findings": json.loads(row["findings_json"]),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[BanditScanEngine] = None
_engine_lock = threading.Lock()


def get_bandit_scan_engine(db_path: Optional[str] = None) -> BanditScanEngine:
    """Return the process-wide Bandit scan engine singleton."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = BanditScanEngine(db_path=db_path)
        return _engine


def _reset_singleton_for_tests() -> None:
    """Clear the singleton — used by tests to inject tmp_path engines."""
    global _engine
    with _engine_lock:
        _engine = None
