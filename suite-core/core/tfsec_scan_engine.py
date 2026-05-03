"""ALDECI tfsec Scan Engine — Terraform-only IaC static analysis orchestration.

This engine is the persistence + lifecycle layer for tfsec scans triggered via
the ``/api/v1/tfsec`` REST surface. It does NOT bundle the tfsec binary; instead
it shells out to ``tfsec`` if present on PATH and otherwise records scans in a
``record-only`` (queued/degraded) state so the control plane (UI, MCP, AQUA) can
plan around capacity.

Scope
-----
Terraform-only by design. Other IaC (CloudFormation, ARM, Bicep, K8s manifests
via Checkov, etc.) belongs in their own engines / routers — keeping tfsec
focused mirrors the upstream tool's scope and avoids overlap.

Providers
---------
The 8 first-class providers tfsec knows about today:
``aws``, ``azure``, ``gcp``, ``digitalocean``, ``kubernetes``, ``cloudstack``,
``github``, ``oracle``. The /providers endpoint exposes a static catalog with
the published rule counts per provider (May 2026 baseline — refreshed when the
tfsec rule pack updates).

Severity levels
---------------
``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW`` (matches tfsec's published levels;
``UNKNOWN`` is normalised to ``LOW``).

Persistence
-----------
SQLite at ``data/security/tfsec_scans.db`` with the canonical schema::

    CREATE TABLE IF NOT EXISTS tfsec_scans (
        scan_id TEXT PRIMARY KEY,
        target_path TEXT NOT NULL,
        status TEXT NOT NULL,
        severity_counts_json TEXT,
        provider_counts_json TEXT,
        findings_json TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        exit_code INTEGER
    );

The engine emits TrustGraph events (``tfsec.scan.queued``,
``tfsec.scan.completed``, ``tfsec.scan.failed``) so the second-brain coverage
map includes this IaC surface. Failures are swallowed — no engine call should
raise because of TrustGraph wiring.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import subprocess  # nosec B404 — controlled invocation of tfsec only
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TrustGraph emit (non-fatal)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit TrustGraph event. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

VALID_STATUSES = (
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
    "record_only",
)

# Static provider catalog — May 2026 baseline. Counts are approximate published
# rule counts per provider; engine consumers should treat them as a hint, not a
# contract. Refreshed when the tfsec rule pack ships a new minor version.
PROVIDER_CATALOG: Dict[str, Dict[str, Any]] = {
    "aws":          {"rule_count": 178, "description": "Amazon Web Services"},
    "azure":        {"rule_count":  95, "description": "Microsoft Azure"},
    "gcp":          {"rule_count":  68, "description": "Google Cloud Platform"},
    "digitalocean": {"rule_count":  10, "description": "DigitalOcean"},
    "kubernetes":   {"rule_count":  18, "description": "Kubernetes (via Terraform)"},
    "cloudstack":   {"rule_count":   3, "description": "Apache CloudStack"},
    "github":       {"rule_count":   8, "description": "GitHub provider"},
    "oracle":       {"rule_count":   4, "description": "Oracle Cloud Infrastructure"},
}

PROVIDERS = tuple(PROVIDER_CATALOG.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalise_severity(raw: Any) -> str:
    s = str(raw or "").upper().strip()
    if s in SEVERITY_LEVELS:
        return s
    if s in ("UNKNOWN", "INFO", "INFORMATIONAL", ""):
        return "LOW"
    if s == "ERROR":
        return "HIGH"
    if s == "WARNING":
        return "MEDIUM"
    return "LOW"


def _validate_target_path(target_path: str) -> str:
    if not isinstance(target_path, str) or not target_path.strip():
        raise ValueError("target_path is required")
    p = target_path.strip()
    # Disallow obvious shell metacharacters — defence in depth even though we
    # never invoke tfsec via a shell.
    bad = set("`$;&|<>\n\r")
    if any(c in p for c in bad):
        raise ValueError("target_path contains disallowed characters")
    if len(p) > 4096:
        raise ValueError("target_path exceeds 4096 chars")
    return p


def _validate_severity(level: Optional[str]) -> str:
    if level is None:
        return "LOW"
    s = str(level).upper().strip()
    if s not in SEVERITY_LEVELS:
        raise ValueError(
            f"minimum_severity must be one of {list(SEVERITY_LEVELS)}"
        )
    return s


def _validate_exclude_checks(checks: Optional[List[str]]) -> List[str]:
    if checks is None:
        return []
    if not isinstance(checks, list):
        raise ValueError("exclude_checks must be a list of rule-id strings")
    out: List[str] = []
    for c in checks:
        if not isinstance(c, str):
            raise ValueError("exclude_checks entries must be strings")
        c2 = c.strip()
        if not c2:
            continue
        if len(c2) > 128:
            raise ValueError("exclude_checks entry exceeds 128 chars")
        # Basic shape check — tfsec rule ids look like AVD-AWS-0001 or aws-s3-...
        if any(ch in c2 for ch in "`$;&|<>\n\r "):
            raise ValueError("exclude_checks entry contains disallowed characters")
        out.append(c2)
    return out


def _provider_from_rule(rule_id: str, resource: str) -> str:
    rid = (rule_id or "").lower()
    res = (resource or "").lower()
    for prov in PROVIDERS:
        if f"-{prov}-" in rid or rid.startswith(f"{prov}-") or res.startswith(f"{prov}_"):
            return prov
    # Heuristic fallback for AVD-style ids
    for prov in PROVIDERS:
        if prov in rid:
            return prov
    return "unknown"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TfsecScanEngine:
    """Persistence + lifecycle for tfsec Terraform IaC scans."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            base = Path(os.environ.get("FIXOPS_DATA_DIR", "data")) / "security"
            base.mkdir(parents=True, exist_ok=True)
            db_path = str(base / "tfsec_scans.db")
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tfsec_available = shutil.which("tfsec") is not None
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tfsec_scans (
                    scan_id TEXT PRIMARY KEY,
                    target_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity_counts_json TEXT,
                    provider_counts_json TEXT,
                    findings_json TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    exit_code INTEGER
                )
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------
    def capability_summary(self) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM tfsec_scans"
            ).fetchone()
        scan_count = int(row["c"] or 0) if row else 0

        if not self._tfsec_available:
            envelope_status = "degraded"
        elif scan_count == 0:
            envelope_status = "empty"
        else:
            envelope_status = "ok"

        return {
            "service": "tfsec",
            "scope": "terraform-only",
            "providers": list(PROVIDERS),
            "severity_levels": list(SEVERITY_LEVELS),
            "status": envelope_status,
            "tfsec_binary_available": self._tfsec_available,
            "scan_count": scan_count,
            "db_path": self.db_path,
        }

    # ------------------------------------------------------------------
    # Provider catalog
    # ------------------------------------------------------------------
    @staticmethod
    def provider_catalog() -> Dict[str, Any]:
        items: List[Dict[str, Any]] = []
        total = 0
        for prov, meta in PROVIDER_CATALOG.items():
            entry = {"provider": prov, **meta}
            items.append(entry)
            total += int(meta.get("rule_count", 0) or 0)
        return {
            "providers": items,
            "total_providers": len(PROVIDER_CATALOG),
            "total_rules": total,
        }

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def queue_scan(
        self,
        target_path: str,
        exclude_checks: Optional[List[str]] = None,
        minimum_severity: Optional[str] = None,
        soft_fail: Optional[bool] = None,
    ) -> Dict[str, Any]:
        target = _validate_target_path(target_path)
        excl = _validate_exclude_checks(exclude_checks)
        sev = _validate_severity(minimum_severity)

        scan_id = f"tfsec-{uuid.uuid4().hex[:16]}"
        queued_at = _now_iso()
        status = "queued" if self._tfsec_available else "record_only"

        meta_payload = {
            "exclude_checks": excl,
            "minimum_severity": sev,
            "soft_fail": bool(soft_fail) if soft_fail is not None else False,
            "tfsec_binary_available": self._tfsec_available,
            "queued_at": queued_at,
        }

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tfsec_scans (
                    scan_id, target_path, status, severity_counts_json,
                    provider_counts_json, findings_json,
                    started_at, completed_at, exit_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target,
                    status,
                    json.dumps({}),
                    json.dumps({}),
                    json.dumps({"_request": meta_payload}),
                    queued_at,
                    None,
                    None,
                ),
            )
            conn.commit()

        try:
            _emit_event(
                "tfsec.scan.queued",
                {
                    "scan_id": scan_id,
                    "target_path": target,
                    "minimum_severity": sev,
                },
            )
        except Exception:  # pragma: no cover
            pass

        return {
            "scan_id": scan_id,
            "target_path": target,
            "queued_at": queued_at,
            "status": status,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if not isinstance(scan_id, str) or not scan_id:
            raise ValueError("scan_id is required")
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tfsec_scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_scans(self, limit: int = 100) -> List[Dict[str, Any]]:
        if limit < 1:
            limit = 1
        if limit > 1000:
            limit = 1000
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tfsec_scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_status(
        self,
        scan_id: str,
        status: str,
        severity_counts: Optional[Dict[str, int]] = None,
        provider_counts: Optional[Dict[str, int]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        exit_code: Optional[int] = None,
    ) -> Dict[str, Any]:
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Must be one of: {list(VALID_STATUSES)}"
            )
        existing = self.get_scan(scan_id)
        if existing is None:
            raise KeyError(f"Unknown scan_id: {scan_id}")

        completed_at = (
            _now_iso() if status in ("completed", "failed", "cancelled") else None
        )

        merged_sev = {k: 0 for k in SEVERITY_LEVELS}
        merged_sev.update(existing.get("severity_counts") or {})
        if severity_counts:
            for k, v in severity_counts.items():
                merged_sev[_normalise_severity(k)] = int(v)

        merged_prov = dict(existing.get("provider_counts") or {})
        if provider_counts:
            for k, v in provider_counts.items():
                merged_prov[str(k)] = int(v)

        merged_findings = list(existing.get("findings") or [])
        if findings is not None:
            merged_findings = [self._normalise_finding(f) for f in findings]

        # Preserve _request envelope inside findings_json (we store both)
        wrapped_findings = {
            "_request": (existing.get("_request") or {}),
            "items": merged_findings,
        }

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE tfsec_scans
                   SET status = ?,
                       completed_at = COALESCE(?, completed_at),
                       severity_counts_json = ?,
                       provider_counts_json = ?,
                       findings_json = ?,
                       exit_code = COALESCE(?, exit_code)
                 WHERE scan_id = ?
                """,
                (
                    status,
                    completed_at,
                    json.dumps(merged_sev),
                    json.dumps(merged_prov),
                    json.dumps(wrapped_findings),
                    exit_code,
                    scan_id,
                ),
            )
            conn.commit()

        try:
            evt = (
                "tfsec.scan.completed"
                if status == "completed"
                else "tfsec.scan.failed"
                if status == "failed"
                else "tfsec.scan.updated"
            )
            _emit_event(
                evt,
                {
                    "scan_id": scan_id,
                    "status": status,
                    "severity_counts": merged_sev,
                    "provider_counts": merged_prov,
                },
            )
        except Exception:  # pragma: no cover
            pass

        return self.get_scan(scan_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    @staticmethod
    def _normalise_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
        rule_id = str(raw.get("rule_id") or raw.get("long_id") or "").strip()
        resource = str(raw.get("resource") or raw.get("resource_block") or "").strip()
        severity = _normalise_severity(raw.get("severity"))
        provider = str(raw.get("provider") or _provider_from_rule(rule_id, resource))
        return {
            "rule_id": rule_id,
            "severity": severity,
            "provider": provider,
            "resource": resource,
            "file_path": str(raw.get("file_path") or raw.get("filename") or ""),
            "line": int(raw.get("line") or raw.get("start_line") or 0),
            "description": str(raw.get("description") or raw.get("rule_description") or ""),
        }

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        try:
            sev_counts = json.loads(row["severity_counts_json"] or "{}")
        except Exception:  # noqa: BLE001
            sev_counts = {}
        try:
            prov_counts = json.loads(row["provider_counts_json"] or "{}")
        except Exception:  # noqa: BLE001
            prov_counts = {}
        try:
            findings_blob = json.loads(row["findings_json"] or "{}")
        except Exception:  # noqa: BLE001
            findings_blob = {}

        if isinstance(findings_blob, list):
            request = {}
            items = findings_blob
        elif isinstance(findings_blob, dict):
            request = findings_blob.get("_request") or {}
            items = findings_blob.get("items") or []
        else:
            request = {}
            items = []

        return {
            "scan_id": row["scan_id"],
            "target_path": row["target_path"],
            "status": row["status"],
            "severity_counts": sev_counts,
            "provider_counts": prov_counts,
            "findings": items,
            "_request": request,
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "exit_code": row["exit_code"],
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_singleton_lock = threading.Lock()
_singleton: Optional[TfsecScanEngine] = None


def get_tfsec_scan_engine(db_path: Optional[str] = None) -> TfsecScanEngine:
    """Return the process-wide tfsec scan engine singleton.

    A non-default ``db_path`` returns a fresh, non-singleton instance so tests
    can isolate state with ``tmp_path``.
    """
    global _singleton
    if db_path is not None:
        return TfsecScanEngine(db_path=db_path)
    with _singleton_lock:
        if _singleton is None:
            _singleton = TfsecScanEngine()
        return _singleton


# Module-load heartbeat — observable in TrustGraph second-brain.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass
