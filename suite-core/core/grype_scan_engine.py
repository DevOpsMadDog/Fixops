"""Grype Vulnerability Scan Engine — ALDECI.

Wraps Anchore Grype vulnerability scanning for container images, SBOM files
(SPDX/CycloneDX/syft-json), and filesystem directories. Maintains a SQLite
audit trail of scan jobs (`grype_scans`) keyed by ``scan_id``.

Real grype invocation
---------------------
When the ``grype`` binary is on PATH, scans shell out via ``subprocess.run``
with ``-o json`` and the parsed match list is normalized into a uniform
``vulnerabilities`` array plus a ``severity_counts`` dict.

When grype is unavailable (e.g. CI runner without the binary) the engine
records the job with status ``unavailable`` and an explanatory ``error``
field. NO mock vulnerabilities are emitted — that would violate the
NO MOCKS rule. UI consumers should render an EmptyState with the
``error`` text.

DB schema
---------
Table ``grype_scans``::

    scan_id              TEXT PRIMARY KEY
    input_type           TEXT NOT NULL          -- image | sbom | dir
    target               TEXT NOT NULL          -- ref/path
    status               TEXT NOT NULL          -- queued | scanning | complete | failed | unavailable
    severity_counts_json TEXT                   -- {"Critical":N, "High":N, ...}
    vulnerabilities_json TEXT                   -- [ {vuln_id, severity, package, version, fixed_version}, ... ]
    started_at           TEXT
    completed_at         TEXT
    error                TEXT
    scope                TEXT
    only_fixed           INTEGER

Compliance alignment
--------------------
- NIST 800-53 RA-5 (Vulnerability Scanning)
- CIS Control 7 (Continuous Vulnerability Management)
- ISO 27001 A.8.8 (Management of technical vulnerabilities)
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


_VALID_INPUT_TYPES = {"image", "sbom", "dir"}
_VALID_SCOPES = {"Squashed", "AllLayers"}
_VALID_SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_db_path() -> Path:
    base = Path(os.environ.get("FIXOPS_DATA_DIR", str(Path(__file__).resolve().parents[2] / "data")))
    return base / "security" / "grype_scans.db"


class GrypeScanEngine:
    """Singleton-friendly Grype scan engine with a SQLite audit trail."""

    def __init__(self, db_path: Optional[str] = None, grype_binary: Optional[str] = None) -> None:
        self._db_path = Path(db_path) if db_path else _default_db_path()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._grype_binary = grype_binary or os.environ.get("FIXOPS_GRYPE_BINARY") or "grype"
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
                CREATE TABLE IF NOT EXISTS grype_scans (
                    scan_id              TEXT PRIMARY KEY,
                    input_type           TEXT NOT NULL,
                    target               TEXT NOT NULL,
                    status               TEXT NOT NULL,
                    severity_counts_json TEXT,
                    vulnerabilities_json TEXT,
                    started_at           TEXT,
                    completed_at         TEXT,
                    error                TEXT,
                    scope                TEXT,
                    only_fixed           INTEGER
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_grype_scans_status ON grype_scans(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_grype_scans_input_type ON grype_scans(input_type)"
            )

    # --------------------------------------------------------------- public

    def is_available(self) -> bool:
        """Return True when the grype binary is on PATH."""
        return shutil.which(self._grype_binary) is not None

    def capability(self) -> Dict[str, Any]:
        """Capability summary used by GET /."""
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM grype_scans").fetchone()
        scan_count = int(row["n"]) if row else 0
        available = self.is_available()
        return {
            "service": "Grype",
            "input_types": ["image", "sbom", "dir"],
            "output_formats": ["json", "table", "cyclonedx", "sarif"],
            "severities": ["Negligible", "Low", "Medium", "High", "Critical"],
            "binary_available": available,
            "scan_count": scan_count,
            "status": "ok" if scan_count > 0 else "empty",
        }

    def queue_scan(
        self,
        *,
        input_type: str,
        target: str,
        scope: Optional[str] = None,
        only_fixed: bool = False,
    ) -> Dict[str, Any]:
        """Queue a new scan and return its handle. Execution runs synchronously
        when grype is on PATH; otherwise the row is recorded with status
        ``unavailable`` and an error field.
        """
        if input_type not in _VALID_INPUT_TYPES:
            raise ValueError(
                f"input_type must be one of {sorted(_VALID_INPUT_TYPES)}; got {input_type!r}"
            )
        if not target or not isinstance(target, str):
            raise ValueError("target must be a non-empty string")
        if scope is not None and scope not in _VALID_SCOPES:
            raise ValueError(f"scope must be one of {sorted(_VALID_SCOPES)} or None")

        scan_id = uuid.uuid4().hex
        queued_at = _now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO grype_scans (
                    scan_id, input_type, target, status,
                    severity_counts_json, vulnerabilities_json,
                    started_at, completed_at, error,
                    scope, only_fixed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    input_type,
                    target,
                    "queued",
                    json.dumps({s: 0 for s in _VALID_SEVERITIES[:5]}),
                    json.dumps([]),
                    queued_at,
                    None,
                    None,
                    scope,
                    1 if only_fixed else 0,
                ),
            )
            conn.commit()

        # Run synchronously (small jobs) — for async fan-out wire to a worker pool later.
        try:
            self._execute_scan(scan_id, input_type, target, scope, only_fixed)
        except Exception as exc:  # pragma: no cover - safety net
            _logger.exception("grype scan execution crashed: %s", exc)
            self._mark_failed(scan_id, str(exc))

        return {
            "scan_id": scan_id,
            "input_type": input_type,
            "target": target,
            "queued_at": queued_at,
        }

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        """Return scan record. Raises ``KeyError`` if scan_id not found."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM grype_scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if row is None:
            raise KeyError(scan_id)
        sev_counts = json.loads(row["severity_counts_json"] or "{}")
        # Normalize so the 5 documented severities are always present.
        normalized = {s: int(sev_counts.get(s, 0)) for s in _VALID_SEVERITIES[:5]}
        return {
            "scan_id": row["scan_id"],
            "input_type": row["input_type"],
            "target": row["target"],
            "status": row["status"],
            "severity_counts": normalized,
            "vulnerabilities": json.loads(row["vulnerabilities_json"] or "[]"),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "error": row["error"],
            "scope": row["scope"],
            "only_fixed": bool(row["only_fixed"]),
        }

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT scan_id, input_type, target, status, started_at, completed_at FROM grype_scans"
                " ORDER BY started_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------- internal

    def _mark_failed(self, scan_id: str, error: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE grype_scans SET status=?, completed_at=?, error=? WHERE scan_id=?",
                ("failed", _now(), error[:2000], scan_id),
            )
            conn.commit()

    def _mark_unavailable(self, scan_id: str, error: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE grype_scans SET status=?, completed_at=?, error=? WHERE scan_id=?",
                ("unavailable", _now(), error[:2000], scan_id),
            )
            conn.commit()

    def _execute_scan(
        self,
        scan_id: str,
        input_type: str,
        target: str,
        scope: Optional[str],
        only_fixed: bool,
    ) -> None:
        # Fast path: grype not installed → record unavailable, no mock data.
        if not self.is_available():
            self._mark_unavailable(
                scan_id,
                "grype binary not found on PATH. "
                "Install via: https://github.com/anchore/grype#installation",
            )
            return

        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE grype_scans SET status=?, started_at=? WHERE scan_id=?",
                ("scanning", _now(), scan_id),
            )
            conn.commit()

        target_arg = target
        if input_type == "sbom":
            target_arg = f"sbom:{target}"
        elif input_type == "dir":
            target_arg = f"dir:{target}"

        cmd = [self._grype_binary, target_arg, "-o", "json"]
        if scope:
            cmd.extend(["--scope", scope])
        if only_fixed:
            cmd.append("--only-fixed")

        try:
            proc = subprocess.run(  # noqa: S603 — grype binary, validated args
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self._mark_failed(scan_id, f"grype scan timed out after 600s: {exc}")
            return
        except FileNotFoundError as exc:
            self._mark_unavailable(scan_id, f"grype binary not executable: {exc}")
            return

        if proc.returncode not in (0, 1):
            # rc=1 means vulns found but scan succeeded; >1 is real failure.
            self._mark_failed(scan_id, (proc.stderr or proc.stdout)[:2000])
            return

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            self._mark_failed(scan_id, f"grype output not valid JSON: {exc}")
            return

        vulns, sev_counts = self._normalize_grype_payload(payload)
        self._finalize(scan_id, vulns, sev_counts)

    @staticmethod
    def _normalize_grype_payload(payload: Dict[str, Any]) -> tuple:
        matches = payload.get("matches") or []
        vulns: List[Dict[str, Any]] = []
        sev_counts: Dict[str, int] = {s: 0 for s in _VALID_SEVERITIES[:5]}
        for m in matches:
            vuln = (m or {}).get("vulnerability") or {}
            artifact = (m or {}).get("artifact") or {}
            severity = (vuln.get("severity") or "Unknown").capitalize()
            if severity not in sev_counts:
                # group Unknown into Negligible bucket so the severities array is always 5
                sev_counts["Negligible"] = sev_counts.get("Negligible", 0) + 1
            else:
                sev_counts[severity] += 1
            fix = (vuln.get("fix") or {}).get("versions") or []
            vulns.append(
                {
                    "vuln_id": vuln.get("id", ""),
                    "severity": severity,
                    "package": artifact.get("name", ""),
                    "version": artifact.get("version", ""),
                    "fixed_version": fix[0] if fix else "",
                }
            )
        return vulns, sev_counts

    def _finalize(
        self,
        scan_id: str,
        vulns: List[Dict[str, Any]],
        sev_counts: Dict[str, int],
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE grype_scans
                   SET status=?, completed_at=?, severity_counts_json=?, vulnerabilities_json=?
                 WHERE scan_id=?
                """,
                (
                    "complete",
                    _now(),
                    json.dumps(sev_counts),
                    json.dumps(vulns),
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
                        topic="grype_scan_complete",
                        payload={
                            "scan_id": scan_id,
                            "severity_counts": sev_counts,
                            "vulnerability_count": len(vulns),
                        },
                    )
            except Exception:  # noqa: BLE001
                _logger.debug("trustgraph emit failed for grype scan %s", scan_id)


# --------------------------------------------------------------------- singleton

_singleton: Optional[GrypeScanEngine] = None
_singleton_lock = threading.Lock()


def get_grype_scan_engine(
    db_path: Optional[str] = None,
    grype_binary: Optional[str] = None,
) -> GrypeScanEngine:
    """Return a process-wide GrypeScanEngine singleton.

    The first caller's ``db_path`` / ``grype_binary`` win. Tests that need
    an isolated DB should call ``reset_grype_scan_engine`` first.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = GrypeScanEngine(db_path=db_path, grype_binary=grype_binary)
        return _singleton


def reset_grype_scan_engine() -> None:
    """Tear down the singleton — used by tests with tmp_path DBs."""
    global _singleton
    with _singleton_lock:
        _singleton = None


__all__ = ["GrypeScanEngine", "get_grype_scan_engine", "reset_grype_scan_engine"]
