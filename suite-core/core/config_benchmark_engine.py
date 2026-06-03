"""
Security Configuration Benchmark Engine — ALDECI.

REAL IMPLEMENTATION: run_assessment() executes the real ``checkov`` binary
against a target directory (or file) of IaC/configuration files and persists
actual pass/fail check results.  There are NO seeded-random or hash-derived
results.  Honest degradation:

- checkov not on PATH → ConfigBenchmarkError (router surfaces as HTTP 422)
- target path missing/empty → ConfigBenchmarkError (router surfaces as HTTP 422)
- checkov non-zero exit (checks failed) → normal; results are still parsed
  and persisted.

Supported frameworks: terraform, dockerfile, kubernetes (skips the secrets
runner which has a broken detect-secrets dependency on this installation).

Profile/check CRUD, get_assessment(), list_assessments(), get_failed_checks(),
and get_benchmark_stats() are all production-ready SQLite-backed methods.

Thread-safe via RLock.  Multi-tenant via org_id.
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import subprocess
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
_logger.info(
    "%s loaded — run_assessment() runs real checkov IaC/config benchmarks "
    "(frameworks: terraform, dockerfile, kubernetes). No simulated data.",
    __name__,
)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "config_benchmark.db"
)

_VALID_STANDARDS = {"CIS", "DISA_STIG", "NIST_800_53", "PCI_DSS_HW", "custom"}
_VALID_TARGET_TYPES = {
    "linux_server", "windows_server", "network_device",
    "kubernetes", "docker", "aws", "azure",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_STATUSES = {"pass", "fail", "warning", "not_applicable"}

# Frameworks we scan with — excludes 'secrets' which crashes on this install
# due to a broken detect-secrets/checkov integration (AttributeError: JSON).
_CHECKOV_FRAMEWORKS = "terraform,dockerfile,kubernetes"

# Checkov process timeout in seconds
_CHECKOV_TIMEOUT = 120


class ConfigBenchmarkError(ValueError):
    """Raised when a real checkov assessment cannot be performed.

    Surfaced by the router as HTTP 422 with the error message — never as
    fabricated results.  Common causes:
    - checkov binary not on PATH
    - target path does not exist or contains no scannable files
    """


class ConfigBenchmarkEngine:
    """SQLite WAL-backed security configuration benchmark engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS benchmark_profiles (
                    profile_id  TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    standard    TEXT NOT NULL DEFAULT 'CIS',
                    target_type TEXT NOT NULL DEFAULT 'linux_server',
                    version     TEXT NOT NULL DEFAULT '1.0',
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_profile_org
                    ON benchmark_profiles (org_id, standard);

                CREATE TABLE IF NOT EXISTS benchmark_checks (
                    check_id       TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    profile_id     TEXT NOT NULL,
                    check_ref      TEXT NOT NULL,
                    title          TEXT NOT NULL,
                    description    TEXT NOT NULL DEFAULT '',
                    category       TEXT NOT NULL DEFAULT '',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    expected_value TEXT NOT NULL DEFAULT '',
                    remediation    TEXT NOT NULL DEFAULT '',
                    created_at     DATETIME NOT NULL,
                    FOREIGN KEY (profile_id) REFERENCES benchmark_profiles(profile_id)
                );

                CREATE INDEX IF NOT EXISTS idx_check_org_profile
                    ON benchmark_checks (org_id, profile_id, severity);

                CREATE TABLE IF NOT EXISTS assessment_results (
                    result_id      TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    profile_id     TEXT NOT NULL,
                    target_name    TEXT NOT NULL,
                    assessed_at    DATETIME NOT NULL,
                    passed         INTEGER NOT NULL DEFAULT 0,
                    failed         INTEGER NOT NULL DEFAULT 0,
                    warnings       INTEGER NOT NULL DEFAULT 0,
                    not_applicable INTEGER NOT NULL DEFAULT 0,
                    score          REAL NOT NULL DEFAULT 0.0,
                    status         TEXT NOT NULL DEFAULT 'fail',
                    FOREIGN KEY (profile_id) REFERENCES benchmark_profiles(profile_id)
                );

                CREATE INDEX IF NOT EXISTS idx_result_org
                    ON assessment_results (org_id, profile_id, assessed_at DESC);

                CREATE TABLE IF NOT EXISTS check_results (
                    cr_id        TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    result_id    TEXT NOT NULL,
                    check_id     TEXT NOT NULL,
                    actual_value TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'fail',
                    notes        TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (result_id) REFERENCES assessment_results(result_id),
                    FOREIGN KEY (check_id) REFERENCES benchmark_checks(check_id)
                );

                CREATE INDEX IF NOT EXISTS idx_cr_result
                    ON check_results (org_id, result_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Profiles
    # ------------------------------------------------------------------

    def create_profile(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new benchmark profile."""
        profile_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        standard = str(data.get("standard", "CIS"))
        if standard not in _VALID_STANDARDS:
            standard = "custom"
        target_type = str(data.get("target_type", "linux_server"))
        if target_type not in _VALID_TARGET_TYPES:
            target_type = "linux_server"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO benchmark_profiles
                        (profile_id, org_id, name, standard, target_type, version, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        profile_id,
                        org_id,
                        str(data.get("name", "Unnamed Profile")),
                        standard,
                        target_type,
                        str(data.get("version", "1.0")),
                        now,
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "config_benchmark", "org_id": org_id, "source_engine": "config_benchmark"})
            except Exception:
                pass

        return {
            "profile_id": profile_id,
            "org_id": org_id,
            "name": data.get("name", "Unnamed Profile"),
            "standard": standard,
            "target_type": target_type,
            "version": data.get("version", "1.0"),
            "created_at": now,
        }

    def list_profiles(self, org_id: str, standard: Optional[str] = None) -> List[Dict[str, Any]]:
        """List profiles for an org, optionally filtered by standard."""
        if standard:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM benchmark_profiles WHERE org_id=? AND standard=? ORDER BY created_at DESC",
                    (org_id, standard),
                ).fetchall()
        else:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM benchmark_profiles WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def add_check(self, org_id: str, profile_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a benchmark check to a profile."""
        check_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        severity = str(data.get("severity", "medium")).lower()
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO benchmark_checks
                        (check_id, org_id, profile_id, check_ref, title, description,
                         category, severity, expected_value, remediation, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        check_id,
                        org_id,
                        profile_id,
                        str(data.get("check_ref", f"CHECK-{check_id[:8].upper()}")),
                        str(data.get("title", "Unnamed Check")),
                        str(data.get("description", "")),
                        str(data.get("category", "")),
                        severity,
                        str(data.get("expected_value", "")),
                        str(data.get("remediation", "")),
                        now,
                    ),
                )
        return {
            "check_id": check_id,
            "org_id": org_id,
            "profile_id": profile_id,
            **{k: data.get(k, "") for k in ("check_ref", "title", "description", "category", "expected_value", "remediation")},
            "severity": severity,
            "created_at": now,
        }

    def list_checks(
        self, org_id: str, profile_id: str, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List checks for a profile, optionally filtered by severity."""
        if severity:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM benchmark_checks WHERE org_id=? AND profile_id=? AND severity=? ORDER BY check_ref",
                    (org_id, profile_id, severity),
                ).fetchall()
        else:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM benchmark_checks WHERE org_id=? AND profile_id=? ORDER BY check_ref",
                    (org_id, profile_id),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Assessment — real checkov execution
    # ------------------------------------------------------------------

    @staticmethod
    def _find_checkov() -> str:
        """Return the path to the checkov binary, or raise ConfigBenchmarkError."""
        path = shutil.which("checkov")
        if path is None:
            raise ConfigBenchmarkError(
                "checkov not installed — install it to run real config benchmarks "
                "(pip install checkov or brew install checkov)"
            )
        return path

    @staticmethod
    def _parse_checkov_output(raw_json: str) -> tuple[int, int, list]:
        """Parse checkov JSON output into (passed_count, failed_count, check_rows).

        Handles both single-framework output (dict) and multi-framework output
        (list of dicts).  Each item in check_rows is a dict with keys:
          check_id, check_name, file_path, resource, severity, guideline, status.
        """
        data = json.loads(raw_json)
        items: list = data if isinstance(data, list) else [data]

        passed_count = 0
        failed_count = 0
        check_rows: list = []

        for item in items:
            if not isinstance(item, dict):
                continue
            results = item.get("results", {})
            passed_checks = results.get("passed_checks", [])
            failed_checks = results.get("failed_checks", [])

            passed_count += len(passed_checks)
            failed_count += len(failed_checks)

            for chk in passed_checks:
                check_rows.append({
                    "check_id": chk.get("check_id", ""),
                    "check_name": chk.get("check_name", ""),
                    "file_path": chk.get("file_path", ""),
                    "resource": chk.get("resource", ""),
                    "severity": chk.get("severity") or "unknown",
                    "guideline": chk.get("guideline", ""),
                    "status": "pass",
                })
            for chk in failed_checks:
                check_rows.append({
                    "check_id": chk.get("check_id", ""),
                    "check_name": chk.get("check_name", ""),
                    "file_path": chk.get("file_path", ""),
                    "resource": chk.get("resource", ""),
                    "severity": chk.get("severity") or "unknown",
                    "guideline": chk.get("guideline", ""),
                    "status": "fail",
                })

        return passed_count, failed_count, check_rows

    def _persist_assessment(
        self,
        org_id: str,
        profile_id: str,
        target_name: str,
        target_path: str,
        passed_count: int,
        failed_count: int,
        check_rows: list,
    ) -> Dict[str, Any]:
        """Persist a real checkov assessment result + individual check rows.

        Each check_result row uses a synthetic benchmark_checks entry keyed on
        check_id (since checkov defines its own check catalogue rather than the
        profile's manually-added checks).  If a check already exists for this
        profile it is reused; otherwise it is upserted.

        Returns a summary dict matching the shape callers expect.
        """
        result_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        total = passed_count + failed_count
        score = round((passed_count / total) * 100, 2) if total > 0 else 0.0

        if score >= 80:
            status = "pass"
        elif score >= 50:
            status = "partial"
        else:
            status = "fail"

        with self._lock:
            with self._conn() as conn:
                # Upsert checkov check definitions into benchmark_checks so that
                # the FK constraint on check_results is satisfied and the JOIN in
                # get_failed_checks() returns real check metadata.
                check_id_map: Dict[str, str] = {}
                for row in check_rows:
                    ck_ref = row["check_id"]
                    if ck_ref in check_id_map:
                        continue
                    existing = conn.execute(
                        "SELECT check_id FROM benchmark_checks WHERE org_id=? AND profile_id=? AND check_ref=?",
                        (org_id, profile_id, ck_ref),
                    ).fetchone()
                    if existing:
                        check_id_map[ck_ref] = existing["check_id"]
                    else:
                        new_id = str(uuid.uuid4())
                        # Map checkov severity (may be None/"unknown") to our valid set
                        raw_sev = (row.get("severity") or "medium").lower()
                        severity = raw_sev if raw_sev in _VALID_SEVERITIES else "medium"
                        conn.execute(
                            """
                            INSERT INTO benchmark_checks
                                (check_id, org_id, profile_id, check_ref, title,
                                 description, category, severity, expected_value,
                                 remediation, created_at)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?)
                            """,
                            (
                                new_id, org_id, profile_id, ck_ref,
                                row.get("check_name", ck_ref),
                                row.get("guideline", ""),
                                "checkov",
                                severity,
                                "pass",
                                row.get("guideline", ""),
                                now,
                            ),
                        )
                        check_id_map[ck_ref] = new_id

                # Insert the assessment summary
                conn.execute(
                    """
                    INSERT INTO assessment_results
                        (result_id, org_id, profile_id, target_name, assessed_at,
                         passed, failed, warnings, not_applicable, score, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (result_id, org_id, profile_id, target_name, now,
                     passed_count, failed_count, 0, 0, score, status),
                )

                # Insert individual check results
                for row in check_rows:
                    mapped_check_id = check_id_map.get(row["check_id"])
                    if mapped_check_id is None:
                        continue
                    conn.execute(
                        """
                        INSERT INTO check_results
                            (cr_id, org_id, result_id, check_id, actual_value, status, notes)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            str(uuid.uuid4()),
                            org_id,
                            result_id,
                            mapped_check_id,
                            row.get("resource", ""),
                            row["status"],
                            f"{row['file_path']} | {row['resource']}",
                        ),
                    )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {
                        "entity_type": "config_benchmark",
                        "org_id": org_id,
                        "source_engine": "config_benchmark",
                        "passed": passed_count,
                        "failed": failed_count,
                        "score": score,
                    })
            except Exception:
                pass

        return {
            "result_id": result_id,
            "org_id": org_id,
            "profile_id": profile_id,
            "target_name": target_name,
            "target_path": target_path,
            "assessed_at": now,
            "passed": passed_count,
            "failed": failed_count,
            "warnings": 0,
            "not_applicable": 0,
            "total_checks": total,
            "score": score,
            "status": status,
            "scanner": "checkov",
            "frameworks": _CHECKOV_FRAMEWORKS,
        }

    def run_assessment(
        self,
        org_id: str,
        profile_id: str,
        target_name: str,
        target_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run a real checkov assessment against ``target_path``.

        Parameters
        ----------
        org_id:
            Organisation identifier for multi-tenant isolation.
        profile_id:
            Benchmark profile to associate the results with.
        target_name:
            Human-readable label for the scan target (e.g. ``"infra/prod"``).
        target_path:
            Filesystem path to the directory (or single file) to scan.
            When omitted the router should supply it; raises
            ConfigBenchmarkError if not provided or not found.

        Returns
        -------
        dict
            Assessment summary with ``result_id``, ``passed``, ``failed``,
            ``score``, ``status``, ``total_checks``.

        Raises
        ------
        ConfigBenchmarkError
            If checkov is not installed, or the target path is missing/empty.
        """
        # --- Guard: checkov must be installed
        checkov_bin = self._find_checkov()

        # --- Guard: target_path must exist and have scannable content
        if not target_path:
            raise ConfigBenchmarkError(
                "target_path is required — provide the directory or file to benchmark"
            )
        # SCIF hardening: confine scan target to the storage-root allowlist.
        from core.storage_root_guard import assert_path_allowed
        assert_path_allowed(target_path, "FIXOPS_SCANNER_ALLOWED_ROOTS", label="target_path")
        tp = Path(target_path)
        if not tp.exists():
            raise ConfigBenchmarkError(
                f"target path not found / no scannable files: {target_path}"
            )
        if tp.is_dir():
            # Check directory contains at least one file
            files = list(tp.rglob("*"))
            scannable = [f for f in files if f.is_file()]
            if not scannable:
                raise ConfigBenchmarkError(
                    f"target path not found / no scannable files: {target_path}"
                )

        # --- Build checkov command
        if tp.is_dir():
            scan_flag = ["-d", str(tp)]
        else:
            scan_flag = ["-f", str(tp)]

        cmd = [
            checkov_bin,
            *scan_flag,
            "--framework", _CHECKOV_FRAMEWORKS,
            "-o", "json",
            "--compact",
        ]

        _logger.info(
            "config_benchmark: running checkov on %s (org=%s, profile=%s)",
            target_path, org_id, profile_id,
        )

        # --- Execute checkov (exit code 1 = checks failed; that's normal)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_CHECKOV_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise ConfigBenchmarkError(
                f"checkov timed out after {_CHECKOV_TIMEOUT}s scanning {target_path}"
            )
        except OSError as exc:
            raise ConfigBenchmarkError(f"checkov execution failed: {exc}") from exc

        # checkov exits 0 (all pass), 1 (some fail), 2 (internal error)
        if proc.returncode == 2:
            stderr_snippet = (proc.stderr or "")[:500]
            raise ConfigBenchmarkError(
                f"checkov exited with error (code 2). stderr: {stderr_snippet}"
            )

        raw_output = proc.stdout.strip()
        if not raw_output:
            raise ConfigBenchmarkError(
                f"checkov produced no output for {target_path} — "
                "no scannable IaC/config files found in the target"
            )

        # --- Parse JSON output
        try:
            passed_count, failed_count, check_rows = self._parse_checkov_output(raw_output)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ConfigBenchmarkError(
                f"failed to parse checkov JSON output: {exc}"
            ) from exc

        if passed_count == 0 and failed_count == 0:
            raise ConfigBenchmarkError(
                f"checkov ran but found 0 checks in {target_path} — "
                "no IaC/config files matched the supported frameworks"
            )

        _logger.info(
            "config_benchmark: checkov complete — passed=%d failed=%d (org=%s)",
            passed_count, failed_count, org_id,
        )

        return self._persist_assessment(
            org_id=org_id,
            profile_id=profile_id,
            target_name=target_name,
            target_path=str(tp),
            passed_count=passed_count,
            failed_count=failed_count,
            check_rows=check_rows,
        )

    # ------------------------------------------------------------------
    # Assessment read methods
    # ------------------------------------------------------------------

    def get_assessment(self, org_id: str, result_id: str) -> Dict[str, Any]:
        """Return assessment with embedded check_results."""
        with self._conn() as conn:
            result_row = conn.execute(
                "SELECT * FROM assessment_results WHERE result_id=? AND org_id=?",
                (result_id, org_id),
            ).fetchone()
            if not result_row:
                return {}
            cr_rows = conn.execute(
                "SELECT * FROM check_results WHERE result_id=? AND org_id=? ORDER BY status",
                (result_id, org_id),
            ).fetchall()

        result = self._row_to_dict(result_row)
        result["check_results"] = [self._row_to_dict(r) for r in cr_rows]
        return result

    def list_assessments(self, org_id: str, profile_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List assessments, optionally filtered by profile."""
        if profile_id:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM assessment_results WHERE org_id=? AND profile_id=? ORDER BY assessed_at DESC",
                    (org_id, profile_id),
                ).fetchall()
        else:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM assessment_results WHERE org_id=? ORDER BY assessed_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_failed_checks(self, org_id: str, result_id: str) -> List[Dict[str, Any]]:
        """Return failed check_results with check details joined."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT cr.*, bc.check_ref, bc.title, bc.severity,
                       bc.remediation, bc.category
                FROM check_results cr
                JOIN benchmark_checks bc ON cr.check_id = bc.check_id
                WHERE cr.result_id=? AND cr.org_id=? AND cr.status='fail'
                ORDER BY bc.severity
                """,
                (result_id, org_id),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_benchmark_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate benchmark statistics for an org."""
        with self._conn() as conn:
            profile_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM benchmark_profiles WHERE org_id=?",
                (org_id,),
            ).fetchone()["cnt"]

            assessment_row = conn.execute(
                "SELECT COUNT(*) as cnt, AVG(score) as avg_score FROM assessment_results WHERE org_id=?",
                (org_id,),
            ).fetchone()

            by_standard_rows = conn.execute(
                """
                SELECT bp.standard, COUNT(ar.result_id) as cnt, AVG(ar.score) as avg_score
                FROM benchmark_profiles bp
                LEFT JOIN assessment_results ar ON bp.profile_id = ar.profile_id AND ar.org_id = bp.org_id
                WHERE bp.org_id=?
                GROUP BY bp.standard
                """,
                (org_id,),
            ).fetchall()

            by_target_rows = conn.execute(
                """
                SELECT bp.target_type, COUNT(ar.result_id) as cnt, AVG(ar.score) as avg_score
                FROM benchmark_profiles bp
                LEFT JOIN assessment_results ar ON bp.profile_id = ar.profile_id AND ar.org_id = bp.org_id
                WHERE bp.org_id=?
                GROUP BY bp.target_type
                """,
                (org_id,),
            ).fetchall()

            critical_failures = conn.execute(
                """
                SELECT COUNT(*) as cnt
                FROM check_results cr
                JOIN benchmark_checks bc ON cr.check_id = bc.check_id
                JOIN assessment_results ar ON cr.result_id = ar.result_id
                WHERE ar.org_id=? AND cr.status='fail' AND bc.severity='critical'
                """,
                (org_id,),
            ).fetchone()["cnt"]

            # Total failed checks across all assessments for org
            total_failed_checks = conn.execute(
                """
                SELECT COUNT(*) as cnt
                FROM check_results cr
                JOIN assessment_results ar ON cr.result_id = ar.result_id
                WHERE ar.org_id=? AND cr.status='fail'
                """,
                (org_id,),
            ).fetchone()["cnt"]

            # Most recent result_id for this org (used for check_results alias)
            latest_result_row = conn.execute(
                "SELECT result_id FROM assessment_results WHERE org_id=? ORDER BY assessed_at DESC LIMIT 1",
                (org_id,),
            ).fetchone()

        by_standard = {
            r["standard"]: {"assessments": r["cnt"], "avg_score": round(r["avg_score"] or 0.0, 2)}
            for r in by_standard_rows
        }
        by_target_type = {
            r["target_type"]: {"assessments": r["cnt"], "avg_score": round(r["avg_score"] or 0.0, 2)}
            for r in by_target_rows
        }

        # Failed check rows for most recent assessment (real empty list when no data)
        latest_failed_checks: List[Dict[str, Any]] = []
        if latest_result_row:
            latest_failed_checks = self.get_failed_checks(org_id, latest_result_row["result_id"])

        return {
            "org_id": org_id,
            "total_profiles": profile_count,
            "total_assessments": assessment_row["cnt"] or 0,
            "avg_score": round(assessment_row["avg_score"] or 0.0, 2),
            "by_standard": by_standard,
            "by_target_type": by_target_type,
            "critical_failures_total": critical_failures or 0,
            # UI-alias keys (additive — do not remove above keys)
            "score_by_standard": by_standard,
            "failed_checks": total_failed_checks or 0,
            "check_results": latest_failed_checks,
        }
