"""kube-bench CIS Kubernetes Benchmark Scan Engine — async-queue model with SQLite persistence.

Aqua Security's kube-bench (https://github.com/aquasecurity/kube-bench) runs the
CIS Kubernetes Benchmark against a cluster — master, node, etcd, policies,
controlplane, and managedservices roles. This engine wraps the binary in the
same async-queue + SQLite contract as semgrep_scan_engine / gitleaks_router.

Endpoints exposed by kube_bench_router (prefix /api/v1/kube-bench):
  GET  /                        — capability summary (benchmarks, target node
                                  roles, status levels)
  GET  /benchmarks              — catalog with check-count per benchmark
  POST /scan                    — queue a scan; returns {scan_id,
                                  benchmark_version, target_node_role,
                                  queued_at}
  GET  /scan/{scan_id}          — fetch scan record (status_counts, total
                                  checks, findings)

Storage: SQLite at data/security/kube_bench_scans.db
Schema:  kube_bench_scans (scan_id PK, benchmark_version, target_node_role,
                            status, status_counts_json, total_checks,
                            findings_json, started_at, completed_at)

When the kube-bench binary is not present we record the scan with
``status="unavailable"`` rather than fabricating findings — honoring the
NO-MOCKS rule: callers can poll the scan_id, see the unavailable status, and
decide whether to re-run after installing kube-bench (and configuring
KUBECONFIG to point at a reachable cluster).

Vision pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import subprocess  # nosec B404 — kube-bench CLI is the only invocation
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
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "kube_bench_scans.db"

# CIS Kubernetes Benchmark versions supported by upstream kube-bench.
BENCHMARK_VERSIONS: List[str] = [
    "cis-1.6",
    "cis-1.7",
    "cis-1.8",
    "cis-1.9",
    "cis-1.10",
]

# Target node roles understood by `kube-bench --targets <role>`.
TARGET_NODE_ROLES: List[str] = [
    "master",
    "node",
    "etcd",
    "policies",
    "controlplane",
    "managedservices",
]

# kube-bench status vocabulary.
STATUS_LEVELS: List[str] = ["PASS", "FAIL", "WARN", "INFO"]

# Approximate default check counts per benchmark version. Used by GET
# /benchmarks so the catalog is meaningful air-gapped (V9). Real per-scan
# counts always come from the actual kube-bench JSON output.
_BENCHMARK_DEFAULT_CHECK_COUNTS: Dict[str, int] = {
    "cis-1.6": 122,
    "cis-1.7": 124,
    "cis-1.8": 126,
    "cis-1.9": 128,
    "cis-1.10": 130,
}

_KUBE_BENCH_BIN = os.environ.get("KUBE_BENCH_BIN", "kube-bench")


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class KubeBenchScanEngine:
    """Async-queue kube-bench CIS Kubernetes Benchmark scan engine."""

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
                CREATE TABLE IF NOT EXISTS kube_bench_scans (
                    scan_id             TEXT PRIMARY KEY,
                    benchmark_version   TEXT NOT NULL,
                    target_node_role    TEXT NOT NULL,
                    status              TEXT NOT NULL,
                    status_counts_json  TEXT NOT NULL DEFAULT '{}',
                    total_checks        INTEGER NOT NULL DEFAULT 0,
                    findings_json       TEXT NOT NULL DEFAULT '[]',
                    started_at          TEXT NOT NULL,
                    completed_at        TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_kube_bench_scans_status "
                "ON kube_bench_scans(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_kube_bench_scans_benchmark "
                "ON kube_bench_scans(benchmark_version)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_kube_bench_scans_role "
                "ON kube_bench_scans(target_node_role)"
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------

    @staticmethod
    def list_benchmarks() -> List[Dict[str, Any]]:
        return [
            {
                "id": ver,
                "name": f"CIS Kubernetes Benchmark {ver.split('-', 1)[1]}",
                "default_check_count": _BENCHMARK_DEFAULT_CHECK_COUNTS.get(ver, 0),
            }
            for ver in BENCHMARK_VERSIONS
        ]

    # ------------------------------------------------------------------
    # CLI helpers
    # ------------------------------------------------------------------

    def is_kube_bench_available(self) -> bool:
        return shutil.which(_KUBE_BENCH_BIN) is not None

    @staticmethod
    def _normalize_benchmark(value: Optional[str]) -> str:
        v = (value or "").strip().lower()
        if not v:
            return BENCHMARK_VERSIONS[-1]
        if v not in BENCHMARK_VERSIONS:
            raise ValueError(
                f"invalid benchmark_version {value!r}; allowed: {BENCHMARK_VERSIONS}"
            )
        return v

    @staticmethod
    def _normalize_role(value: Optional[str]) -> str:
        v = (value or "").strip().lower()
        if not v:
            return "node"
        if v not in TARGET_NODE_ROLES:
            raise ValueError(
                f"invalid target_node_role {value!r}; allowed: {TARGET_NODE_ROLES}"
            )
        return v

    def _build_cli_args(
        self,
        benchmark_version: str,
        target_node_role: str,
        asff_output: bool,
    ) -> List[str]:
        args: List[str] = [_KUBE_BENCH_BIN, "run"]
        # kube-bench accepts `--benchmark <id>` (e.g. cis-1.10).
        args += ["--benchmark", benchmark_version]
        # `--targets <role>` selects which checks to execute.
        args += ["--targets", target_node_role]
        if asff_output:
            args += ["--asff"]
        else:
            args += ["--json"]
        return args

    def _run_kube_bench(
        self,
        benchmark_version: str,
        target_node_role: str,
        asff_output: bool,
    ) -> Dict[str, Any]:
        if not self.is_kube_bench_available():
            raise RuntimeError("kube_bench_binary_unavailable")

        cmd = self._build_cli_args(benchmark_version, target_node_role, asff_output)
        try:
            proc = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"kube-bench scan timed out after {self._timeout}s"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError("kube_bench_binary_unavailable") from exc

        # kube-bench exits non-zero when WARN/FAIL findings exist; treat 0/1/2
        # as success and only fail hard on >2.
        if proc.returncode > 2:
            stderr = proc.stderr.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(
                f"kube-bench exited with code {proc.returncode}: {stderr}"
            )

        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            return {}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"kube-bench output is not valid JSON: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Output bucketing
    # ------------------------------------------------------------------

    @staticmethod
    def _bucket_statuses(raw: Dict[str, Any]) -> Dict[str, int]:
        counts: Dict[str, int] = {s: 0 for s in STATUS_LEVELS}
        # kube-bench JSON shape:
        #   {"Totals": {"total_pass": N, "total_fail": N, "total_warn": N,
        #               "total_info": N}, "Controls": [...]}
        totals = raw.get("Totals") or {}
        if totals:
            counts["PASS"] = int(totals.get("total_pass", 0) or 0)
            counts["FAIL"] = int(totals.get("total_fail", 0) or 0)
            counts["WARN"] = int(totals.get("total_warn", 0) or 0)
            counts["INFO"] = int(totals.get("total_info", 0) or 0)
            return counts

        # Fall back to walking Controls -> tests -> results.
        for control in raw.get("Controls", []) or []:
            for test in control.get("tests", []) or []:
                for result in test.get("results", []) or []:
                    status = (result.get("status") or "").upper()
                    if status in counts:
                        counts[status] += 1
        return counts

    @staticmethod
    def _flatten_findings(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for control in raw.get("Controls", []) or []:
            for test in control.get("tests", []) or []:
                for result in test.get("results", []) or []:
                    out.append(
                        {
                            "test_number": result.get("test_number"),
                            "test_desc": result.get("test_desc"),
                            "status": (result.get("status") or "").upper(),
                            "remediation": result.get("remediation"),
                            "scored": bool(result.get("scored", False)),
                        }
                    )
        return out

    # ------------------------------------------------------------------
    # Public scan API
    # ------------------------------------------------------------------

    def queue_scan(
        self,
        benchmark_version: Optional[str] = None,
        target_node_role: Optional[str] = None,
        asff_output: bool = False,
    ) -> Dict[str, Any]:
        """Queue a scan, run inline (NO-MOCKS — record-only when binary absent)."""
        normalized_benchmark = self._normalize_benchmark(benchmark_version)
        normalized_role = self._normalize_role(target_node_role)

        scan_id = str(uuid.uuid4())
        queued_at = datetime.now(timezone.utc).isoformat()

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO kube_bench_scans
                    (scan_id, benchmark_version, target_node_role, status,
                     status_counts_json, total_checks, findings_json,
                     started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    normalized_benchmark,
                    normalized_role,
                    "queued",
                    json.dumps({s: 0 for s in STATUS_LEVELS}),
                    0,
                    json.dumps([]),
                    queued_at,
                    None,
                ),
            )
            conn.commit()

        # Inline execution — when kube-bench is missing we record-only.
        try:
            raw = self._run_kube_bench(
                benchmark_version=normalized_benchmark,
                target_node_role=normalized_role,
                asff_output=bool(asff_output),
            )
            status_counts = self._bucket_statuses(raw)
            findings = self._flatten_findings(raw)
            total_checks = sum(status_counts.values())
            completed_at = datetime.now(timezone.utc).isoformat()
            with self._lock, self._conn() as conn:
                conn.execute(
                    """
                    UPDATE kube_bench_scans
                       SET status = ?,
                           status_counts_json = ?,
                           total_checks = ?,
                           findings_json = ?,
                           completed_at = ?
                     WHERE scan_id = ?
                    """,
                    (
                        "completed",
                        json.dumps(status_counts),
                        int(total_checks),
                        json.dumps(findings)[:1_000_000],  # cap at ~1MB
                        completed_at,
                        scan_id,
                    ),
                )
                conn.commit()
        except RuntimeError as exc:
            status = (
                "unavailable"
                if str(exc) == "kube_bench_binary_unavailable"
                else "failed"
            )
            completed_at = datetime.now(timezone.utc).isoformat()
            with self._lock, self._conn() as conn:
                conn.execute(
                    """
                    UPDATE kube_bench_scans
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
        except Exception as exc:  # noqa: BLE001 — record then surface
            logger.error("kube-bench scan failed: %s", exc)
            with self._lock, self._conn() as conn:
                conn.execute(
                    """
                    UPDATE kube_bench_scans
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
            "benchmark_version": normalized_benchmark,
            "target_node_role": normalized_role,
            "queued_at": queued_at,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM kube_bench_scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None

        try:
            status_counts = json.loads(row["status_counts_json"] or "{}")
        except (TypeError, ValueError):
            status_counts = {}
        for s in STATUS_LEVELS:
            status_counts.setdefault(s, 0)

        try:
            findings_raw = json.loads(row["findings_json"] or "[]")
        except (TypeError, ValueError):
            findings_raw = []
        findings = findings_raw if isinstance(findings_raw, list) else []

        return {
            "scan_id": row["scan_id"],
            "benchmark_version": row["benchmark_version"],
            "target_node_role": row["target_node_role"],
            "status": row["status"],
            "status_counts": status_counts,
            "total_checks": int(row["total_checks"] or 0),
            "findings": findings,
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }

    def count_scans(self) -> int:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM kube_bench_scans"
            ).fetchone()
        return int(row["c"]) if row else 0

    def capability_summary(self) -> Dict[str, Any]:
        binary_present = self.is_kube_bench_available()
        scan_count = self.count_scans()
        if not binary_present:
            status = "unavailable"
        elif scan_count == 0:
            status = "empty"
        else:
            status = "ok"
        return {
            "service": "kube-bench",
            "benchmarks": list(BENCHMARK_VERSIONS),
            "target_node_roles": list(TARGET_NODE_ROLES),
            "status_levels": list(STATUS_LEVELS),
            "status": status,
            "binary_present": binary_present,
            "scan_count": scan_count,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_singleton: Optional[KubeBenchScanEngine] = None
_singleton_lock = threading.Lock()


def get_kube_bench_scan_engine(
    db_path: Optional[str] = None,
) -> KubeBenchScanEngine:
    """Return the process-wide KubeBenchScanEngine.

    Tests may pass an explicit ``db_path`` on first call (or call
    ``reset_kube_bench_scan_engine()`` then re-fetch) to point at a tmp DB.
    """
    global _engine_singleton
    with _singleton_lock:
        if _engine_singleton is None:
            _engine_singleton = KubeBenchScanEngine(db_path=db_path)
        return _engine_singleton


def reset_kube_bench_scan_engine() -> None:
    """Test helper — drop the singleton so the next call rebuilds it."""
    global _engine_singleton
    with _singleton_lock:
        _engine_singleton = None
