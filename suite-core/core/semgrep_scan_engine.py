"""Semgrep SAST Scan Engine — async-queue model with SQLite persistence.

Complementary to the legacy SemgrepScanner in semgrep_integration.py:
- SemgrepScanner = synchronous scan-and-return + in-memory history
- SemgrepScanEngine = async-queued scans + durable SQLite history per scan_id

Endpoints exposed by semgrep_scan_router (prefix /api/v1/semgrep):
  GET  /                  — capability summary (rule packs, severity levels)
  GET  /rule-packs        — catalog of supported rule packs
  POST /scan              — queue a scan, returns {scan_id, target_path,
                            rule_packs, queued_at}
  GET  /scan/{scan_id}    — fetch a scan record (status + severity counts +
                            findings)

Storage: SQLite at data/security/semgrep_scans.db
Schema:  semgrep_scans (scan_id PK, target_path, rule_packs_json, status,
                        severity_counts_json, findings_json, started_at,
                        completed_at)

When the semgrep CLI binary is not present we record the scan with
``status="unavailable"`` rather than fabricating findings — honoring the
NO-MOCKS rule: callers can poll the scan_id, see the unavailable status,
and decide whether to re-run after installing semgrep.

Vision pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import subprocess  # nosec B404 — semgrep CLI is the only invocation
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DB_DIR = _REPO_ROOT / "data" / "security"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "semgrep_scans.db"

SEVERITY_LEVELS: List[str] = ["INFO", "WARNING", "ERROR"]

# Hardcoded so the rule-pack catalog works air-gapped (V9).
RULE_PACKS: List[Dict[str, str]] = [
    {
        "id": "r2c-security-audit",
        "name": "r2c Security Audit",
        "description": "Curated r2c registry security audit pack — broad coverage of common SAST issues across languages.",
    },
    {
        "id": "owasp-top-10",
        "name": "OWASP Top 10",
        "description": "Detect patterns mapped to the OWASP Top 10 application security risks.",
    },
    {
        "id": "ci-rules",
        "name": "CI Rules",
        "description": "Default CI-friendly rule pack — fast, low false-positive set suitable for pre-merge checks.",
    },
    {
        "id": "python",
        "name": "Python",
        "description": "Python-specific SAST rules covering insecure deserialization, SQL injection, weak crypto, and unsafe subprocess use.",
    },
    {
        "id": "javascript",
        "name": "JavaScript",
        "description": "JavaScript SAST rules covering XSS, prototype pollution, injection, and unsafe eval/Function use.",
    },
    {
        "id": "typescript",
        "name": "TypeScript",
        "description": "TypeScript SAST rules — superset of JavaScript checks with type-aware detections.",
    },
]

ALL_RULE_PACK_IDS: List[str] = [pack["id"] for pack in RULE_PACKS]

_SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "semgrep")


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SemgrepScanEngine:
    """Async-queue Semgrep SAST scan engine with SQLite persistence."""

    DEFAULT_TIMEOUT = 600

    def __init__(
        self,
        db_path: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if db_path is None:
            db_path = str(_DEFAULT_DB_PATH)
        self._db_path = db_path
        self._timeout = timeout
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS semgrep_scans (
                    scan_id TEXT PRIMARY KEY,
                    target_path TEXT NOT NULL,
                    rule_packs_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL,
                    severity_counts_json TEXT NOT NULL DEFAULT '{}',
                    findings_json TEXT NOT NULL DEFAULT '[]',
                    started_at TEXT NOT NULL,
                    completed_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_semgrep_scans_status ON semgrep_scans(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_semgrep_scans_target ON semgrep_scans(target_path)"
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------

    @staticmethod
    def list_rule_packs() -> List[Dict[str, str]]:
        return [dict(p) for p in RULE_PACKS]

    @staticmethod
    def get_rule_pack(pack_id: str) -> Optional[Dict[str, str]]:
        pid = (pack_id or "").strip().lower()
        for pack in RULE_PACKS:
            if pack["id"].lower() == pid:
                return dict(pack)
        return None

    # ------------------------------------------------------------------
    # CLI helpers
    # ------------------------------------------------------------------

    def is_semgrep_available(self) -> bool:
        return shutil.which(_SEMGREP_BIN) is not None

    @staticmethod
    def _normalize_rule_packs(rule_packs: Optional[List[str]]) -> List[str]:
        """Filter to known rule pack IDs; default to ['r2c-security-audit']."""
        if not rule_packs:
            return ["r2c-security-audit"]
        normalized: List[str] = []
        seen = set()
        for raw in rule_packs:
            if not isinstance(raw, str):
                continue
            rid = raw.strip()
            if not rid or rid in seen:
                continue
            seen.add(rid)
            normalized.append(rid)
        return normalized or ["r2c-security-audit"]

    @staticmethod
    def _normalize_severity_threshold(value: Optional[str]) -> str:
        if not value:
            return "WARNING"
        v = value.strip().upper()
        if v not in SEVERITY_LEVELS:
            raise ValueError(
                f"invalid severity_threshold {value!r}; allowed: {SEVERITY_LEVELS}"
            )
        return v

    def _build_cli_args(
        self,
        target_path: str,
        rule_packs: List[str],
        severity_threshold: str,
        exclude_dirs: Optional[List[str]],
    ) -> List[str]:
        args: List[str] = [_SEMGREP_BIN, "scan", "--json", "--quiet"]
        for pack in rule_packs:
            # Map known pack IDs to semgrep registry refs (e.g. p/python).
            args += ["--config", f"p/{pack}"]
        if severity_threshold:
            args += ["--severity", severity_threshold]
        for excl in exclude_dirs or []:
            if excl:
                args += ["--exclude", excl]
        args.append(target_path)
        return args

    def _run_semgrep(
        self,
        target_path: str,
        rule_packs: List[str],
        severity_threshold: str,
        exclude_dirs: Optional[List[str]],
    ) -> Dict[str, Any]:
        if not self.is_semgrep_available():
            # Honor NO-MOCKS — surface the absence rather than invent findings.
            raise RuntimeError("semgrep_binary_unavailable")

        cmd = self._build_cli_args(
            target_path, rule_packs, severity_threshold, exclude_dirs
        )
        try:
            proc = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"semgrep scan of {target_path!r} timed out after {self._timeout}s"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError("semgrep_binary_unavailable") from exc

        # semgrep exits 1 when findings are present — treat 0/1 as success.
        if proc.returncode not in (0, 1):
            stderr = proc.stderr.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(
                f"semgrep exited with code {proc.returncode}: {stderr}"
            )

        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            return {}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"semgrep output is not valid JSON: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Severity bucketing
    # ------------------------------------------------------------------

    @staticmethod
    def _bucket_severities(raw: Dict[str, Any]) -> Dict[str, int]:
        counts: Dict[str, int] = {sev: 0 for sev in SEVERITY_LEVELS}
        for finding in raw.get("results", []) or []:
            extra = finding.get("extra", {}) or {}
            sev = (extra.get("severity") or "INFO").upper()
            if sev not in counts:
                sev = "INFO"
            counts[sev] += 1
        return counts

    @staticmethod
    def _flatten_findings(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for finding in raw.get("results", []) or []:
            extra = finding.get("extra", {}) or {}
            start = finding.get("start", {}) or {}
            out.append(
                {
                    "rule_id": finding.get("check_id"),
                    "severity": (extra.get("severity") or "INFO").upper(),
                    "file_path": finding.get("path"),
                    "line": start.get("line"),
                    "message": extra.get("message"),
                }
            )
        return out

    # ------------------------------------------------------------------
    # Public scan API
    # ------------------------------------------------------------------

    def queue_scan(
        self,
        target_path: str,
        rule_packs: Optional[List[str]] = None,
        severity_threshold: Optional[str] = None,
        exclude_dirs: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Queue a scan, run inline (NO-MOCKS — record-only when binary absent)."""
        if not isinstance(target_path, str) or not target_path.strip():
            raise ValueError("target_path must be a non-empty string")

        normalized_packs = self._normalize_rule_packs(rule_packs)
        threshold = self._normalize_severity_threshold(severity_threshold)

        scan_id = str(uuid.uuid4())
        queued_at = datetime.now(timezone.utc).isoformat()

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO semgrep_scans
                    (scan_id, target_path, rule_packs_json, status,
                     severity_counts_json, findings_json,
                     started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target_path,
                    json.dumps(normalized_packs),
                    "queued",
                    json.dumps({sev: 0 for sev in SEVERITY_LEVELS}),
                    json.dumps([]),
                    queued_at,
                    None,
                ),
            )
            conn.commit()

        # Inline execution. When semgrep is missing we record-only — the
        # scan_id remains pollable and reports status=unavailable.
        try:
            raw = self._run_semgrep(
                target_path,
                rule_packs=normalized_packs,
                severity_threshold=threshold,
                exclude_dirs=exclude_dirs,
            )
            severity_counts = self._bucket_severities(raw)
            findings = self._flatten_findings(raw)
            completed_at = datetime.now(timezone.utc).isoformat()
            with self._lock, self._conn() as conn:
                conn.execute(
                    """
                    UPDATE semgrep_scans
                       SET status = ?,
                           severity_counts_json = ?,
                           findings_json = ?,
                           completed_at = ?
                     WHERE scan_id = ?
                    """,
                    (
                        "completed",
                        json.dumps(severity_counts),
                        json.dumps(findings)[:1_000_000],  # cap at ~1MB
                        completed_at,
                        scan_id,
                    ),
                )
                conn.commit()
        except RuntimeError as exc:
            # Record-only fallback when semgrep is not installed; do NOT
            # fabricate findings. Other RuntimeErrors are recorded as failed.
            status = (
                "unavailable" if str(exc) == "semgrep_binary_unavailable" else "failed"
            )
            completed_at = datetime.now(timezone.utc).isoformat()
            with self._lock, self._conn() as conn:
                conn.execute(
                    """
                    UPDATE semgrep_scans
                       SET status = ?,
                           completed_at = ?,
                           findings_json = ?
                     WHERE scan_id = ?
                    """,
                    (
                        status,
                        completed_at,
                        json.dumps([]) if status == "unavailable"
                        else json.dumps({"error": str(exc)}),
                        scan_id,
                    ),
                )
                conn.commit()
        except Exception as exc:  # noqa: BLE001 — we record then surface
            logger.error("semgrep scan failed for %r: %s", target_path, exc)
            with self._lock, self._conn() as conn:
                conn.execute(
                    """
                    UPDATE semgrep_scans
                       SET status = ?,
                           completed_at = ?,
                           findings_json = ?
                     WHERE scan_id = ?
                    """,
                    (
                        "failed",
                        datetime.now(timezone.utc).isoformat(),
                        json.dumps({"error": str(exc)}),
                        scan_id,
                    ),
                )
                conn.commit()

        return {
            "scan_id": scan_id,
            "target_path": target_path,
            "rule_packs": normalized_packs,
            "queued_at": queued_at,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM semgrep_scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None

        severity_counts = json.loads(row["severity_counts_json"] or "{}")
        # Ensure every key in SEVERITY_LEVELS is present
        for sev in SEVERITY_LEVELS:
            severity_counts.setdefault(sev, 0)

        try:
            findings_raw = json.loads(row["findings_json"] or "[]")
        except (TypeError, ValueError):
            findings_raw = []
        # findings_json may have been overwritten with an error envelope on
        # failed scans — only return list-shaped findings to the caller.
        findings = findings_raw if isinstance(findings_raw, list) else []

        try:
            rule_packs = json.loads(row["rule_packs_json"] or "[]")
        except (TypeError, ValueError):
            rule_packs = []

        return {
            "scan_id": row["scan_id"],
            "target_path": row["target_path"],
            "rule_packs": rule_packs,
            "status": row["status"],
            "severity_counts": severity_counts,
            "findings": findings,
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }

    def count_scans(self) -> int:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM semgrep_scans"
            ).fetchone()
        return int(row["c"]) if row else 0

    def capability_summary(self) -> Dict[str, Any]:
        binary_present = self.is_semgrep_available()
        scan_count = self.count_scans()
        if not binary_present:
            status = "unavailable"
        elif scan_count == 0:
            status = "empty"
        else:
            status = "ok"
        return {
            "service": "Semgrep",
            "rule_packs": list(ALL_RULE_PACK_IDS),
            "severity_levels": list(SEVERITY_LEVELS),
            "status": status,
            "binary_present": binary_present,
            "scan_count": scan_count,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_singleton: Optional[SemgrepScanEngine] = None
_singleton_lock = threading.Lock()


def get_semgrep_scan_engine(db_path: Optional[str] = None) -> SemgrepScanEngine:
    """Return the process-wide SemgrepScanEngine.

    Tests may pass an explicit ``db_path`` on first call (or call
    ``reset_semgrep_scan_engine()`` then re-fetch) to point at a tmp DB.
    """
    global _engine_singleton
    with _singleton_lock:
        if _engine_singleton is None:
            _engine_singleton = SemgrepScanEngine(db_path=db_path)
        return _engine_singleton


def reset_semgrep_scan_engine() -> None:
    """Test helper — drop the singleton so the next call rebuilds it."""
    global _engine_singleton
    with _singleton_lock:
        _engine_singleton = None
