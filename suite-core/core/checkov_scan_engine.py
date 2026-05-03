"""Checkov IaC Scan Engine — ALDECI.

Wraps Bridgecrew Checkov for Infrastructure-as-Code scanning across 14
frameworks (Terraform, Kubernetes, Helm, CloudFormation, Dockerfile, GitHub
Actions, ARM, Bicep, GitLab CI, CircleCI, Argo Workflows, OpenAPI, SCA Image,
Secrets). Maintains a SQLite audit trail (``checkov_scans``) keyed by
``scan_id``.

Real checkov invocation
-----------------------
When the ``checkov`` binary is on PATH, scans shell out via ``subprocess.run``
with ``-o json`` and the parsed result list is normalized into a uniform
``findings`` array plus ``severity_counts`` and ``framework_counts`` dicts.

When checkov is unavailable (CI runner without the binary, air-gapped node)
the engine records the job with status ``unavailable`` and an explanatory
``error`` field. NO mock findings are emitted — that violates the NO MOCKS
rule. UI consumers should render an EmptyState with the ``error`` text.

DB schema
---------
Table ``checkov_scans``::

    scan_id              TEXT PRIMARY KEY
    target_path          TEXT NOT NULL
    frameworks_json      TEXT
    status               TEXT NOT NULL
    severity_counts_json TEXT
    framework_counts_json TEXT
    findings_json        TEXT
    started_at           TEXT
    completed_at         TEXT
    error                TEXT

Compliance alignment
--------------------
- NIST 800-53 CM-2 (Baseline Configuration), CM-6 (Configuration Settings)
- CIS Control 4 (Secure Configuration of Enterprise Assets and Software)
- ISO 27001 A.8.9 (Configuration Management)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import subprocess
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


# 14 supported Checkov frameworks (canonical names match checkov --framework values).
CHECKOV_FRAMEWORKS: List[Dict[str, str]] = [
    {"framework": "terraform", "description": "HashiCorp Terraform IaC (.tf, .tf.json) — AWS/Azure/GCP/etc."},
    {"framework": "kubernetes", "description": "Kubernetes manifests (.yaml/.yml) — Pods, Deployments, RBAC."},
    {"framework": "helm", "description": "Helm chart templates (Chart.yaml, templates/*.yaml)."},
    {"framework": "cloudformation", "description": "AWS CloudFormation templates (.yaml/.yml/.json)."},
    {"framework": "dockerfile", "description": "Dockerfile container build instructions."},
    {"framework": "github_actions", "description": "GitHub Actions workflow files (.github/workflows/*.yml)."},
    {"framework": "arm", "description": "Azure Resource Manager templates (.json)."},
    {"framework": "bicep", "description": "Azure Bicep templates (.bicep)."},
    {"framework": "gitlab_ci", "description": "GitLab CI pipeline configs (.gitlab-ci.yml)."},
    {"framework": "circleci_pipelines", "description": "CircleCI pipeline configs (.circleci/config.yml)."},
    {"framework": "argo_workflows", "description": "Argo Workflows manifests."},
    {"framework": "openapi", "description": "OpenAPI / Swagger 2/3 specifications."},
    {"framework": "sca_image", "description": "Software Composition Analysis on container images."},
    {"framework": "secrets", "description": "Secret scanning across IaC files (entropy + signature)."},
]

ALL_FRAMEWORKS: List[str] = [f["framework"] for f in CHECKOV_FRAMEWORKS]
SEVERITY_LEVELS: List[str] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_db_path() -> Path:
    base = Path(os.environ.get("FIXOPS_DATA_DIR", str(Path(__file__).resolve().parents[2] / "data")))
    return base / "security" / "checkov_scans.db"


class CheckovScanEngine:
    """Singleton-friendly Checkov scan engine with a SQLite audit trail."""

    def __init__(self, db_path: Optional[str] = None, checkov_binary: Optional[str] = None) -> None:
        self._db_path = Path(db_path) if db_path else _default_db_path()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._checkov_binary = checkov_binary or os.environ.get("FIXOPS_CHECKOV_BINARY") or "checkov"
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
                CREATE TABLE IF NOT EXISTS checkov_scans (
                    scan_id               TEXT PRIMARY KEY,
                    target_path           TEXT NOT NULL,
                    frameworks_json       TEXT,
                    status                TEXT NOT NULL,
                    severity_counts_json  TEXT,
                    framework_counts_json TEXT,
                    findings_json         TEXT,
                    started_at            TEXT,
                    completed_at          TEXT,
                    error                 TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_checkov_scans_status ON checkov_scans(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_checkov_scans_target ON checkov_scans(target_path)"
            )

    # --------------------------------------------------------------- catalog

    @staticmethod
    def list_frameworks() -> List[Dict[str, str]]:
        return [dict(f) for f in CHECKOV_FRAMEWORKS]

    # --------------------------------------------------------------- public

    def is_available(self) -> bool:
        """Return True when the checkov binary is on PATH."""
        return shutil.which(self._checkov_binary) is not None

    def count_scans(self) -> int:
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM checkov_scans").fetchone()
        return int(row["n"]) if row else 0

    def capability(self) -> Dict[str, Any]:
        """Capability summary used by GET /."""
        scan_count = self.count_scans()
        return {
            "service": "Checkov",
            "frameworks": list(ALL_FRAMEWORKS),
            "severity_levels": list(SEVERITY_LEVELS),
            "binary_available": self.is_available(),
            "scan_count": scan_count,
            "framework_count": len(ALL_FRAMEWORKS),
            "status": "ok" if scan_count > 0 else "empty",
        }

    def queue_scan(
        self,
        *,
        target_path: str,
        frameworks: Optional[List[str]] = None,
        check_ids: Optional[List[str]] = None,
        skip_checks: Optional[List[str]] = None,
        soft_fail: bool = False,
    ) -> Dict[str, Any]:
        """Queue a new Checkov scan and return its handle. Execution runs
        synchronously when checkov is on PATH; otherwise the row is recorded
        with status ``unavailable`` and an error field — no mock data."""
        if not target_path or not isinstance(target_path, str):
            raise ValueError("target_path must be a non-empty string")
        if frameworks:
            unknown = [f for f in frameworks if f not in ALL_FRAMEWORKS]
            if unknown:
                raise ValueError(
                    f"Unknown framework(s): {unknown}. Allowed: {ALL_FRAMEWORKS}"
                )

        scan_id = uuid.uuid4().hex
        queued_at = _now()
        sev_counts = {s: 0 for s in SEVERITY_LEVELS}
        fw_counts = {f: 0 for f in (frameworks or [])}

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO checkov_scans (
                    scan_id, target_path, frameworks_json, status,
                    severity_counts_json, framework_counts_json,
                    findings_json, started_at, completed_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target_path,
                    json.dumps(list(frameworks or [])),
                    "queued",
                    json.dumps(sev_counts),
                    json.dumps(fw_counts),
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
                target_path=target_path,
                frameworks=frameworks or [],
                check_ids=check_ids or [],
                skip_checks=skip_checks or [],
                soft_fail=bool(soft_fail),
            )
        except Exception as exc:  # pragma: no cover - safety net
            _logger.exception("checkov scan execution crashed: %s", exc)
            self._mark_failed(scan_id, str(exc))

        return {
            "scan_id": scan_id,
            "target_path": target_path,
            "frameworks": list(frameworks or []),
            "queued_at": queued_at,
        }

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        """Return scan record. Raises ``KeyError`` if scan_id not found."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM checkov_scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if row is None:
            raise KeyError(scan_id)
        sev_counts = json.loads(row["severity_counts_json"] or "{}")
        normalized_sev = {s: int(sev_counts.get(s, 0)) for s in SEVERITY_LEVELS}
        fw_counts = json.loads(row["framework_counts_json"] or "{}")
        return {
            "scan_id": row["scan_id"],
            "target_path": row["target_path"],
            "frameworks": json.loads(row["frameworks_json"] or "[]"),
            "status": row["status"],
            "severity_counts": normalized_sev,
            "framework_counts": fw_counts,
            "findings": json.loads(row["findings_json"] or "[]"),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "error": row["error"],
        }

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT scan_id, target_path, status, started_at, completed_at"
                " FROM checkov_scans ORDER BY started_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------- internal

    def _mark_failed(self, scan_id: str, error: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE checkov_scans SET status=?, completed_at=?, error=? WHERE scan_id=?",
                ("failed", _now(), error[:2000], scan_id),
            )
            conn.commit()

    def _mark_unavailable(self, scan_id: str, error: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE checkov_scans SET status=?, completed_at=?, error=? WHERE scan_id=?",
                ("unavailable", _now(), error[:2000], scan_id),
            )
            conn.commit()

    def _execute_scan(
        self,
        scan_id: str,
        target_path: str,
        frameworks: List[str],
        check_ids: List[str],
        skip_checks: List[str],
        soft_fail: bool,
    ) -> None:
        # Fast path: checkov not installed → record unavailable (no mock data).
        if not self.is_available():
            self._mark_unavailable(
                scan_id,
                "checkov binary not found on PATH. "
                "Install via: pip install checkov  (https://www.checkov.io/)",
            )
            return

        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE checkov_scans SET status=?, started_at=? WHERE scan_id=?",
                ("scanning", _now(), scan_id),
            )
            conn.commit()

        cmd: List[str] = [self._checkov_binary, "-d", target_path, "-o", "json", "--quiet"]
        if frameworks:
            cmd.extend(["--framework", ",".join(frameworks)])
        if check_ids:
            cmd.extend(["--check", ",".join(check_ids)])
        if skip_checks:
            cmd.extend(["--skip-check", ",".join(skip_checks)])
        if soft_fail:
            cmd.append("--soft-fail")

        try:
            proc = subprocess.run(  # noqa: S603 — checkov binary, validated args
                cmd,
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self._mark_failed(scan_id, f"checkov scan timed out after 900s: {exc}")
            return
        except FileNotFoundError as exc:
            self._mark_unavailable(scan_id, f"checkov binary not executable: {exc}")
            return

        # checkov returns rc=0 on no failures, rc=1 when failed checks exist (still valid output).
        if proc.returncode not in (0, 1):
            self._mark_failed(scan_id, (proc.stderr or proc.stdout)[:2000])
            return

        try:
            payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError as exc:
            self._mark_failed(scan_id, f"checkov output not valid JSON: {exc}")
            return

        findings, sev_counts, fw_counts = self._normalize_checkov_payload(payload)
        self._finalize(scan_id, findings, sev_counts, fw_counts)

    @staticmethod
    def _normalize_checkov_payload(payload: Any) -> tuple:
        """Normalize Checkov JSON output into uniform finding rows.

        Checkov may return either a single dict (single framework) or a list
        of dicts (multi-framework). Each dict has ``check_type`` plus
        ``results.failed_checks`` (and passed/skipped, which we drop).
        """
        findings: List[Dict[str, Any]] = []
        sev_counts: Dict[str, int] = {s: 0 for s in SEVERITY_LEVELS}
        fw_counts: Dict[str, int] = {}

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return findings, sev_counts, fw_counts

        for block in payload:
            if not isinstance(block, dict):
                continue
            framework = block.get("check_type", "unknown")
            results = (block.get("results") or {})
            failed = results.get("failed_checks") or []
            for check in failed:
                if not isinstance(check, dict):
                    continue
                severity = (check.get("severity") or "MEDIUM")
                severity = severity.upper() if isinstance(severity, str) else "MEDIUM"
                if severity not in sev_counts:
                    severity = "MEDIUM"
                sev_counts[severity] += 1
                fw_counts[framework] = fw_counts.get(framework, 0) + 1
                findings.append(
                    {
                        "check_id": check.get("check_id", ""),
                        "severity": severity,
                        "framework": framework,
                        "file_path": check.get("file_path", ""),
                        "resource": check.get("resource", ""),
                    }
                )
        return findings, sev_counts, fw_counts

    def _finalize(
        self,
        scan_id: str,
        findings: List[Dict[str, Any]],
        sev_counts: Dict[str, int],
        fw_counts: Dict[str, int],
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE checkov_scans
                   SET status=?, completed_at=?,
                       severity_counts_json=?, framework_counts_json=?,
                       findings_json=?
                 WHERE scan_id=?
                """,
                (
                    "complete",
                    _now(),
                    json.dumps(sev_counts),
                    json.dumps(fw_counts),
                    json.dumps(findings),
                    scan_id,
                ),
            )
            conn.commit()

        if _get_tg_bus is not None:  # pragma: no cover - optional path
            try:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.emit_event(
                        topic="checkov_scan_complete",
                        payload={
                            "scan_id": scan_id,
                            "severity_counts": sev_counts,
                            "framework_counts": fw_counts,
                            "finding_count": len(findings),
                        },
                    )
            except Exception:  # noqa: BLE001
                _logger.debug("trustgraph emit failed for checkov scan %s", scan_id)


# --------------------------------------------------------------------- singleton

_singleton: Optional[CheckovScanEngine] = None
_singleton_lock = threading.Lock()


def get_checkov_scan_engine(
    db_path: Optional[str] = None,
    checkov_binary: Optional[str] = None,
) -> CheckovScanEngine:
    """Return a process-wide CheckovScanEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = CheckovScanEngine(db_path=db_path, checkov_binary=checkov_binary)
        return _singleton


def reset_checkov_scan_engine() -> None:
    """Tear down the singleton — used by tests with tmp_path DBs."""
    global _singleton
    with _singleton_lock:
        _singleton = None


__all__ = [
    "CheckovScanEngine",
    "get_checkov_scan_engine",
    "reset_checkov_scan_engine",
    "CHECKOV_FRAMEWORKS",
    "ALL_FRAMEWORKS",
    "SEVERITY_LEVELS",
]
