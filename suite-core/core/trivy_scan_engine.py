"""Trivy Image Scan Engine — async-queue model with SQLite persistence.

Complementary to the existing TrivyScanner in trivy_integration.py:
- TrivyScanner = synchronous scan-and-return + in-memory history
- TrivyScanEngine = async-queued scans + durable SQLite history per scan_id

Endpoints exposed by trivy_router (prefix /api/v1/trivy):
  GET  /                  — capability summary
  POST /image             — queue an image scan, returns {scan_id, queued_at}
  GET  /image/{scan_id}   — fetch a scan record (status + severity + findings)

Storage: SQLite at data/security/trivy_scans.db
Schema:  trivy_scans (scan_id PK, image, status, severity_counts_json,
                       scan_started_at, scan_completed_at, raw_output_json)

Falls back to a deterministic mock when the trivy CLI binary is not present
so tests / dev installs can exercise the full pipeline.

Vision pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import subprocess  # nosec B404 — trivy CLI is the only invocation
import threading
import time
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
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "trivy_scans.db"

_VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_SUPPORTED_FORMATS = ("json", "table", "sarif", "cyclonedx", "spdx")
_SCANNER_TYPES = ("vuln", "secret", "config", "license")

_TRIVY_BIN = os.environ.get("TRIVY_BIN", "trivy")

# Mock output used when trivy is not installed — keeps the queue+SQLite
# round-trip working in tests / air-gapped dev installs.
_MOCK_TRIVY_OUTPUT: Dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "mock-image:latest",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "mock-image:latest (debian 11.6)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-MOCK-001",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1n",
                    "FixedVersion": "1.1.1w",
                    "Severity": "HIGH",
                    "Title": "Mock OpenSSL CVE — install trivy CLI for real scans",
                },
                {
                    "VulnerabilityID": "CVE-2024-MOCK-002",
                    "PkgName": "curl",
                    "InstalledVersion": "7.74.0",
                    "FixedVersion": "7.88.1",
                    "Severity": "MEDIUM",
                    "Title": "Mock curl CVE — install trivy CLI for real scans",
                },
                {
                    "VulnerabilityID": "CVE-2024-MOCK-003",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.2.11",
                    "FixedVersion": "1.2.13",
                    "Severity": "LOW",
                    "Title": "Mock zlib CVE — install trivy CLI for real scans",
                },
            ],
        }
    ],
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TrivyScanEngine:
    """Async-queue Trivy image scan engine with SQLite persistence."""

    DEFAULT_TIMEOUT = 300

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
                CREATE TABLE IF NOT EXISTS trivy_scans (
                    scan_id TEXT PRIMARY KEY,
                    image TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity_counts_json TEXT NOT NULL DEFAULT '{}',
                    scan_started_at TEXT NOT NULL,
                    scan_completed_at TEXT,
                    raw_output_json TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_trivy_scans_image ON trivy_scans(image)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_trivy_scans_status ON trivy_scans(status)"
            )
            conn.commit()

    # ------------------------------------------------------------------
    # CLI helpers
    # ------------------------------------------------------------------

    def is_trivy_available(self) -> bool:
        return shutil.which(_TRIVY_BIN) is not None

    def _build_cli_args(
        self,
        image: str,
        severities: Optional[List[str]],
        skip_files: Optional[List[str]],
        ignore_unfixed: bool,
    ) -> List[str]:
        args: List[str] = [_TRIVY_BIN, "image", "--format", "json", "--quiet"]
        if severities:
            normalized = [
                s.upper() for s in severities if s.upper() in _VALID_SEVERITIES
            ]
            if normalized:
                args += ["--severity", ",".join(normalized)]
        if skip_files:
            for sf in skip_files:
                if sf:
                    args += ["--skip-files", sf]
        if ignore_unfixed:
            args += ["--ignore-unfixed"]
        args.append(image)
        return args

    def _run_trivy(
        self,
        image: str,
        severities: Optional[List[str]] = None,
        skip_files: Optional[List[str]] = None,
        ignore_unfixed: bool = False,
    ) -> Dict[str, Any]:
        if not self.is_trivy_available():
            logger.warning(
                "trivy CLI not on PATH — returning deterministic mock output"
            )
            return dict(_MOCK_TRIVY_OUTPUT)

        cmd = self._build_cli_args(image, severities, skip_files, ignore_unfixed)
        try:
            proc = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"trivy scan of {image!r} timed out after {self._timeout}s"
            ) from exc
        except FileNotFoundError:
            logger.warning("trivy disappeared mid-run — falling back to mock")
            return dict(_MOCK_TRIVY_OUTPUT)

        # trivy exits 1 when vulns are found — that is not an error.
        if proc.returncode not in (0, 1):
            stderr = proc.stderr.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(
                f"trivy exited with code {proc.returncode}: {stderr}"
            )

        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            return {}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"trivy output is not valid JSON: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Severity bucketing
    # ------------------------------------------------------------------

    @staticmethod
    def _bucket_severities(raw: Dict[str, Any]) -> Dict[str, int]:
        counts: Dict[str, int] = {sev: 0 for sev in _VALID_SEVERITIES}
        for result in raw.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities") or []:
                sev = (vuln.get("Severity") or "UNKNOWN").upper()
                if sev not in counts:
                    sev = "UNKNOWN"
                counts[sev] += 1
        return counts

    @staticmethod
    def _flatten_vulns(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for result in raw.get("Results", []) or []:
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities") or []:
                out.append(
                    {
                        "vulnerability_id": vuln.get("VulnerabilityID"),
                        "pkg_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                        "title": vuln.get("Title"),
                        "target": target,
                    }
                )
        return out

    # ------------------------------------------------------------------
    # Public scan API (sync but cheap — perfect for TestClient)
    # ------------------------------------------------------------------

    def queue_scan(
        self,
        image: str,
        severities: Optional[List[str]] = None,
        skip_files: Optional[List[str]] = None,
        ignore_unfixed: bool = False,
    ) -> Dict[str, Any]:
        """Queue a scan, run it inline (sub-second for mock), persist record.

        Returns the queued envelope: {scan_id, image, queued_at}.
        Status / severity_counts / vulnerabilities are then fetchable via
        get_scan(scan_id).
        """
        if not isinstance(image, str) or not image.strip():
            raise ValueError("image must be a non-empty string")

        scan_id = str(uuid.uuid4())
        queued_at = datetime.now(timezone.utc).isoformat()

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO trivy_scans
                    (scan_id, image, status, severity_counts_json,
                     scan_started_at, scan_completed_at, raw_output_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    image,
                    "queued",
                    "{}",
                    queued_at,
                    None,
                    None,
                ),
            )
            conn.commit()

        # Run the scan inline. For a real production deployment this would be
        # dispatched to a worker queue, but the SQLite envelope still gives
        # callers a {scan_id, status} they can poll.
        try:
            raw = self._run_trivy(
                image,
                severities=severities,
                skip_files=skip_files,
                ignore_unfixed=ignore_unfixed,
            )
            severity_counts = self._bucket_severities(raw)
            completed_at = datetime.now(timezone.utc).isoformat()
            with self._lock, self._conn() as conn:
                conn.execute(
                    """
                    UPDATE trivy_scans
                       SET status = ?,
                           severity_counts_json = ?,
                           scan_completed_at = ?,
                           raw_output_json = ?
                     WHERE scan_id = ?
                    """,
                    (
                        "completed",
                        json.dumps(severity_counts),
                        completed_at,
                        json.dumps(raw)[:1_000_000],  # cap at ~1MB
                        scan_id,
                    ),
                )
                conn.commit()
        except Exception as exc:  # noqa: BLE001 — we record then re-surface
            logger.error("trivy scan failed for %r: %s", image, exc)
            with self._lock, self._conn() as conn:
                conn.execute(
                    """
                    UPDATE trivy_scans
                       SET status = ?,
                           scan_completed_at = ?,
                           raw_output_json = ?
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
            "image": image,
            "queued_at": queued_at,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM trivy_scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None

        sev_counts = json.loads(row["severity_counts_json"] or "{}")
        raw_output = json.loads(row["raw_output_json"] or "{}")
        vulns = self._flatten_vulns(raw_output) if isinstance(raw_output, dict) else []

        return {
            "scan_id": row["scan_id"],
            "image": row["image"],
            "status": row["status"],
            "severity_counts": sev_counts,
            "scan_started_at": row["scan_started_at"],
            "scan_completed_at": row["scan_completed_at"],
            "vulnerabilities": vulns,
        }

    def capability_summary(self) -> Dict[str, Any]:
        binary_present = self.is_trivy_available()
        with self._lock, self._conn() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM trivy_scans"
            ).fetchone()["c"]
        if not binary_present:
            status = "degraded"
        elif count == 0:
            status = "empty"
        else:
            status = "ok"
        return {
            "service": "trivy_scan_engine",
            "scanners": list(_SCANNER_TYPES),
            "supported_formats": list(_SUPPORTED_FORMATS),
            "valid_severities": list(_VALID_SEVERITIES),
            "binary_present": binary_present,
            "scan_count": count,
            "status": status,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_singleton: Optional[TrivyScanEngine] = None
_singleton_lock = threading.Lock()


def get_trivy_scan_engine(db_path: Optional[str] = None) -> TrivyScanEngine:
    """Return the process-wide TrivyScanEngine.

    Tests may pass an explicit ``db_path`` on first call (or call
    ``reset_trivy_scan_engine()`` then re-fetch) to point at a tmp DB.
    """
    global _engine_singleton
    with _singleton_lock:
        if _engine_singleton is None:
            _engine_singleton = TrivyScanEngine(db_path=db_path)
        return _engine_singleton


def reset_trivy_scan_engine() -> None:
    """Test helper — drop the singleton so the next call rebuilds it."""
    global _engine_singleton
    with _singleton_lock:
        _engine_singleton = None
