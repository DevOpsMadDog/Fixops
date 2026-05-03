"""Gitleaks Secret-Detection Scan Engine — ALDECI.

Wraps Anchore/Zricethezav Gitleaks for repository / filesystem secret detection
with a SQLite-backed audit trail of scan jobs (``gitleaks_scans``) keyed by
``scan_id``.

Real gitleaks invocation
------------------------
When the ``gitleaks`` binary is on PATH, scans shell out via ``subprocess.run``
using ``detect`` (or ``protect``) sub-command with ``--report-format json``.
Findings are normalized into a uniform ``secrets`` array plus a
``secret_counts.by_rule`` dict.

When gitleaks is unavailable (e.g. CI runner without the binary) the engine
records the job with status ``unavailable`` and an explanatory ``error``
field. NO mock secrets are emitted — that would violate the NO MOCKS rule.

Default rule catalog
--------------------
12 built-in rule IDs covering AWS, GCP, Azure, GitHub, Slack, Stripe, JWT,
NPM, PyPI, and generic private-keys. ``DEFAULT_RULES`` exposes the canonical
list used by the capability summary; ``RULE_CATALOG`` extends each rule with
a description for ``GET /rules``.

DB schema
---------
Table ``gitleaks_scans``::

    scan_id           TEXT PRIMARY KEY
    repo_path         TEXT NOT NULL
    branch            TEXT
    all_history       INTEGER NOT NULL DEFAULT 0
    status            TEXT NOT NULL  -- queued | scanning | complete | failed | unavailable
    secret_counts_json TEXT
    secrets_json      TEXT
    started_at        TEXT
    completed_at      TEXT
    error             TEXT

Compliance alignment
--------------------
- NIST 800-53 IA-5 (Authenticator Management)
- CIS Control 3 (Data Protection)
- OWASP Top 10 2021 — A07 Identification and Authentication Failures
- PCI DSS 3.4 (Render PAN unreadable)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import subprocess  # nosec B404 — gitleaks CLI is the only invocation
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover
    _get_tg_bus = None

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defaults / catalog
# ---------------------------------------------------------------------------

DEFAULT_RULES: List[str] = [
    "aws-access-key",
    "aws-secret-key",
    "github-pat",
    "github-fine-grained-pat",
    "slack-token",
    "stripe-access-token",
    "gcp-service-account",
    "azure-storage-account",
    "jwt",
    "npm-access-token",
    "pypi-token",
    "private-key",
]

RULE_CATALOG: List[Dict[str, str]] = [
    {
        "rule_id": "aws-access-key",
        "description": "AWS Access Key ID (AKIA / ASIA prefix, 16 chars)",
        "severity": "critical",
    },
    {
        "rule_id": "aws-secret-key",
        "description": "AWS Secret Access Key (40 base64 chars)",
        "severity": "critical",
    },
    {
        "rule_id": "github-pat",
        "description": "GitHub Personal Access Token (ghp_ prefix, 40 chars)",
        "severity": "critical",
    },
    {
        "rule_id": "github-fine-grained-pat",
        "description": "GitHub Fine-Grained Personal Access Token (github_pat_ prefix)",
        "severity": "critical",
    },
    {
        "rule_id": "slack-token",
        "description": "Slack Bot/User/Workflow Token (xox[bpoars]- prefix)",
        "severity": "high",
    },
    {
        "rule_id": "stripe-access-token",
        "description": "Stripe Live/Test API Key (sk_live_ / sk_test_ / rk_live_ prefix)",
        "severity": "critical",
    },
    {
        "rule_id": "gcp-service-account",
        "description": "GCP Service Account JSON private_key field",
        "severity": "critical",
    },
    {
        "rule_id": "azure-storage-account",
        "description": "Azure Storage Account Key (88-char base64)",
        "severity": "critical",
    },
    {
        "rule_id": "jwt",
        "description": "JSON Web Token (three base64url segments separated by dots)",
        "severity": "medium",
    },
    {
        "rule_id": "npm-access-token",
        "description": "NPM Access Token (npm_ prefix, 36 chars)",
        "severity": "high",
    },
    {
        "rule_id": "pypi-token",
        "description": "PyPI Upload Token (pypi-AgEIcHlwaS5vcmcC… prefix)",
        "severity": "high",
    },
    {
        "rule_id": "private-key",
        "description": "PEM-encoded private key (RSA / DSA / EC / OPENSSH / PGP)",
        "severity": "critical",
    },
]

SCAN_MODES: List[str] = ["detect", "protect"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_db_path() -> Path:
    base = Path(
        os.environ.get(
            "FIXOPS_DATA_DIR",
            str(Path(__file__).resolve().parents[2] / "data"),
        )
    )
    return base / "security" / "gitleaks_scans.db"


def _redact(s: str, keep: int = 4) -> str:
    if not isinstance(s, str):
        return ""
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GitleaksScanEngine:
    """Singleton-friendly gitleaks scan engine with SQLite audit trail."""

    DEFAULT_TIMEOUT = 600

    def __init__(
        self,
        db_path: Optional[str] = None,
        gitleaks_binary: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._db_path = Path(db_path) if db_path else _default_db_path()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._gitleaks_binary = (
            gitleaks_binary
            or os.environ.get("FIXOPS_GITLEAKS_BINARY")
            or "gitleaks"
        )
        self._timeout = int(timeout)
        self._init_db()

    # ------------------------------------------------------------------ db

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS gitleaks_scans (
                    scan_id            TEXT PRIMARY KEY,
                    repo_path          TEXT NOT NULL,
                    branch             TEXT,
                    all_history        INTEGER NOT NULL DEFAULT 0,
                    status             TEXT NOT NULL,
                    secret_counts_json TEXT,
                    secrets_json       TEXT,
                    started_at         TEXT,
                    completed_at       TEXT,
                    error              TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_gitleaks_status ON gitleaks_scans(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_gitleaks_repo ON gitleaks_scans(repo_path)"
            )
            conn.commit()

    # --------------------------------------------------------------- public

    def is_available(self) -> bool:
        """Return True when the gitleaks binary is on PATH."""
        return shutil.which(self._gitleaks_binary) is not None

    def capability_summary(self) -> Dict[str, Any]:
        """Capability summary used by GET /."""
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM gitleaks_scans").fetchone()
        scan_count = int(row["n"]) if row else 0
        return {
            "service": "Gitleaks",
            "default_rules": list(DEFAULT_RULES),
            "scan_modes": list(SCAN_MODES),
            "binary_available": self.is_available(),
            "scan_count": scan_count,
            "status": "ok" if scan_count > 0 else "empty",
        }

    def list_rules(self) -> List[Dict[str, str]]:
        """Return the documented default rule catalog (12+ rules)."""
        # Return shallow copies so callers cannot mutate the module-level catalog.
        return [dict(r) for r in RULE_CATALOG]

    def queue_scan(
        self,
        *,
        repo_path: str,
        branch: Optional[str] = None,
        all_history: bool = False,
        exclude_paths: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Queue a new scan and return the {scan_id, repo_path, branch, queued_at}
        envelope. Execution runs synchronously when gitleaks is on PATH; otherwise
        the row is recorded with status ``unavailable`` and an error field.
        """
        if not isinstance(repo_path, str) or not repo_path.strip():
            raise ValueError("repo_path must be a non-empty string")
        if branch is not None and not isinstance(branch, str):
            raise ValueError("branch must be a string when provided")
        if exclude_paths is not None and not isinstance(exclude_paths, list):
            raise ValueError("exclude_paths must be a list of strings when provided")

        scan_id = uuid.uuid4().hex
        queued_at = _now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO gitleaks_scans (
                    scan_id, repo_path, branch, all_history, status,
                    secret_counts_json, secrets_json,
                    started_at, completed_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    repo_path,
                    branch,
                    1 if all_history else 0,
                    "queued",
                    json.dumps({"by_rule": {}}),
                    json.dumps([]),
                    queued_at,
                    None,
                    None,
                ),
            )
            conn.commit()

        try:
            self._execute_scan(
                scan_id=scan_id,
                repo_path=repo_path,
                branch=branch,
                all_history=all_history,
                exclude_paths=exclude_paths or [],
            )
        except Exception as exc:  # pragma: no cover - safety net
            _logger.exception("gitleaks scan execution crashed: %s", exc)
            self._mark_failed(scan_id, str(exc))

        return {
            "scan_id": scan_id,
            "repo_path": repo_path,
            "branch": branch,
            "queued_at": queued_at,
        }

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        """Return scan record. Raises ``KeyError`` if scan_id not found."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM gitleaks_scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if row is None:
            raise KeyError(scan_id)
        secret_counts = json.loads(row["secret_counts_json"] or '{"by_rule": {}}')
        if "by_rule" not in secret_counts:
            secret_counts = {"by_rule": secret_counts}
        return {
            "scan_id": row["scan_id"],
            "repo_path": row["repo_path"],
            "branch": row["branch"],
            "all_history": bool(row["all_history"]),
            "status": row["status"],
            "secret_counts": secret_counts,
            "secrets": json.loads(row["secrets_json"] or "[]"),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "error": row["error"],
        }

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT scan_id, repo_path, branch, status, started_at, completed_at"
                "  FROM gitleaks_scans ORDER BY started_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------- internal

    def _mark_failed(self, scan_id: str, error: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE gitleaks_scans SET status=?, completed_at=?, error=? WHERE scan_id=?",
                ("failed", _now(), error[:2000], scan_id),
            )
            conn.commit()

    def _mark_unavailable(self, scan_id: str, error: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE gitleaks_scans SET status=?, completed_at=?, error=? WHERE scan_id=?",
                ("unavailable", _now(), error[:2000], scan_id),
            )
            conn.commit()

    def _execute_scan(
        self,
        *,
        scan_id: str,
        repo_path: str,
        branch: Optional[str],
        all_history: bool,
        exclude_paths: List[str],
    ) -> None:
        # Fast path: gitleaks not installed → record unavailable, no mock data.
        if not self.is_available():
            self._mark_unavailable(
                scan_id,
                "gitleaks binary not found on PATH. "
                "Install via: https://github.com/gitleaks/gitleaks#installing",
            )
            return

        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE gitleaks_scans SET status=?, started_at=? WHERE scan_id=?",
                ("scanning", _now(), scan_id),
            )
            conn.commit()

        # Build CLI args. We always emit JSON to stdout for downstream parsing.
        report_path = self._db_path.parent / f"{scan_id}.report.json"
        cmd: List[str] = [
            self._gitleaks_binary,
            "detect",
            "--source",
            repo_path,
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--exit-code",
            "0",  # never non-zero on findings; we read the report ourselves
            "--no-banner",
        ]
        if not all_history:
            cmd.append("--no-git")
        if branch:
            cmd.extend(["--log-opts", f"{branch}"])
        for excl in exclude_paths:
            if excl:
                cmd.extend(["--config", excl])  # gitleaks uses --config for path filters

        try:
            proc = subprocess.run(  # noqa: S603 — gitleaks binary, validated args
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self._mark_failed(scan_id, f"gitleaks scan timed out after {self._timeout}s: {exc}")
            return
        except FileNotFoundError as exc:
            self._mark_unavailable(scan_id, f"gitleaks binary not executable: {exc}")
            return

        if proc.returncode not in (0, 1):
            stderr = (proc.stderr or proc.stdout or "")[:2000]
            self._mark_failed(scan_id, f"gitleaks exited rc={proc.returncode}: {stderr}")
            return

        # Parse the report file (JSON array). Empty array on no findings.
        try:
            if report_path.exists():
                raw = json.loads(report_path.read_text() or "[]")
            else:
                raw = []
        except json.JSONDecodeError as exc:
            self._mark_failed(scan_id, f"gitleaks report not valid JSON: {exc}")
            return

        secrets, by_rule = self._normalize_findings(raw)
        self._finalize(scan_id, secrets=secrets, by_rule=by_rule)

    @staticmethod
    def _normalize_findings(payload: Any) -> tuple:
        secrets: List[Dict[str, Any]] = []
        by_rule: Dict[str, int] = {}
        if not isinstance(payload, list):
            return secrets, by_rule
        for f in payload:
            if not isinstance(f, dict):
                continue
            rule_id = str(f.get("RuleID") or f.get("ruleID") or f.get("rule") or "unknown")
            file_path = str(f.get("File") or f.get("file") or "")
            line = int(f.get("StartLine") or f.get("startLine") or f.get("line") or 0)
            commit = f.get("Commit") or f.get("commit") or None
            match = str(f.get("Secret") or f.get("Match") or f.get("match") or "")
            secrets.append(
                {
                    "rule_id": rule_id,
                    "file": file_path,
                    "line": line,
                    "commit": commit,
                    "redacted_match": _redact(match),
                }
            )
            by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
        return secrets, by_rule

    def _finalize(
        self,
        scan_id: str,
        *,
        secrets: List[Dict[str, Any]],
        by_rule: Dict[str, int],
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE gitleaks_scans
                   SET status=?, completed_at=?, secret_counts_json=?, secrets_json=?
                 WHERE scan_id=?
                """,
                (
                    "complete",
                    _now(),
                    json.dumps({"by_rule": by_rule}),
                    json.dumps(secrets),
                    scan_id,
                ),
            )
            conn.commit()

        # Best-effort emit to TrustGraph; never block on it.
        if _get_tg_bus is not None:  # pragma: no cover - optional path
            try:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.emit_event(
                        topic="gitleaks_scan_complete",
                        payload={
                            "scan_id": scan_id,
                            "secret_counts": {"by_rule": by_rule},
                            "secret_count": len(secrets),
                        },
                    )
            except Exception:  # noqa: BLE001
                _logger.debug("trustgraph emit failed for gitleaks scan %s", scan_id)


# --------------------------------------------------------------------- singleton

_singleton: Optional[GitleaksScanEngine] = None
_singleton_lock = threading.Lock()


def get_gitleaks_scan_engine(
    db_path: Optional[str] = None,
    gitleaks_binary: Optional[str] = None,
) -> GitleaksScanEngine:
    """Return a process-wide GitleaksScanEngine singleton.

    The first caller's ``db_path`` / ``gitleaks_binary`` win. Tests that need
    an isolated DB should call ``reset_gitleaks_scan_engine`` first.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = GitleaksScanEngine(
                db_path=db_path, gitleaks_binary=gitleaks_binary
            )
        return _singleton


def reset_gitleaks_scan_engine() -> None:
    """Tear down the singleton — used by tests with tmp_path DBs."""
    global _singleton
    with _singleton_lock:
        _singleton = None


__all__ = [
    "GitleaksScanEngine",
    "get_gitleaks_scan_engine",
    "reset_gitleaks_scan_engine",
    "DEFAULT_RULES",
    "RULE_CATALOG",
    "SCAN_MODES",
]
