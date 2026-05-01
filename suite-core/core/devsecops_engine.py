"""DevSecOps Pipeline Security Engine — ALDECI.

Tracks CI/CD pipeline security configurations, runs, findings, and gate policies.
Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.

Run-trigger pipeline (real, no random):
  - SAST   via core.semgrep_integration.SemgrepScanner
  - SCA    via core.trivy_integration.TrivyScanner   (repo mode)
  - Secrets via core.secret_scanner_engine.SecretScannerEngine
  - Container via core.trivy_integration.TrivyScanner (image mode)

If a scanner binary / engine is unavailable, the corresponding finding list is
empty — never fabricated. Findings flow into the Brain Pipeline best-effort.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml as _yaml  # type: ignore
except ImportError:  # pragma: no cover - fallback when PyYAML missing
    _yaml = None

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "devsecops.db"
)

_VALID_CI_PLATFORMS = {
    "github_actions", "gitlab_ci", "jenkins", "circleci", "azure_devops",
}
_VALID_STATUSES = {"pending", "running", "passed", "failed", "blocked"}
_VALID_SCANNER_TYPES = {"sast", "dast", "sca", "secret_scan", "container"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class DevSecOpsEngine:
    """SQLite WAL-backed DevSecOps pipeline security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS pipelines (
                    pipeline_id             TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    repo_url                TEXT NOT NULL DEFAULT '',
                    branch                  TEXT NOT NULL DEFAULT 'main',
                    ci_platform             TEXT NOT NULL DEFAULT 'github_actions',
                    security_gates_enabled  INTEGER NOT NULL DEFAULT 1,
                    sast_enabled            INTEGER NOT NULL DEFAULT 1,
                    dast_enabled            INTEGER NOT NULL DEFAULT 0,
                    sca_enabled             INTEGER NOT NULL DEFAULT 1,
                    secret_scan_enabled     INTEGER NOT NULL DEFAULT 1,
                    container_scan_enabled  INTEGER NOT NULL DEFAULT 0,
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pipelines_org
                    ON pipelines (org_id);

                CREATE TABLE IF NOT EXISTS pipeline_runs (
                    run_id              TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    pipeline_id         TEXT NOT NULL,
                    triggered_by        TEXT NOT NULL DEFAULT 'manual',
                    commit_sha          TEXT NOT NULL DEFAULT '',
                    branch              TEXT NOT NULL DEFAULT 'main',
                    status              TEXT NOT NULL DEFAULT 'pending',
                    started_at          DATETIME NOT NULL,
                    completed_at        DATETIME,
                    sast_findings       INTEGER NOT NULL DEFAULT 0,
                    sca_findings        INTEGER NOT NULL DEFAULT 0,
                    secret_findings     INTEGER NOT NULL DEFAULT 0,
                    container_findings  INTEGER NOT NULL DEFAULT 0,
                    gate_blocked        INTEGER NOT NULL DEFAULT 0,
                    block_reason        TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (pipeline_id) REFERENCES pipelines (pipeline_id)
                );

                CREATE INDEX IF NOT EXISTS idx_runs_org
                    ON pipeline_runs (org_id, started_at DESC);

                CREATE INDEX IF NOT EXISTS idx_runs_pipeline
                    ON pipeline_runs (pipeline_id, started_at DESC);

                CREATE TABLE IF NOT EXISTS security_findings (
                    finding_id    TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    run_id        TEXT NOT NULL,
                    pipeline_id   TEXT NOT NULL,
                    scanner_type  TEXT NOT NULL DEFAULT 'sast',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    title         TEXT NOT NULL DEFAULT '',
                    file_path     TEXT NOT NULL DEFAULT '',
                    line_number   INTEGER NOT NULL DEFAULT 0,
                    cve_id        TEXT NOT NULL DEFAULT '',
                    suppressed    INTEGER NOT NULL DEFAULT 0,
                    created_at    DATETIME NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES pipeline_runs (run_id)
                );

                CREATE INDEX IF NOT EXISTS idx_findings_org
                    ON security_findings (org_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_findings_run
                    ON security_findings (run_id);

                CREATE TABLE IF NOT EXISTS gate_policies (
                    policy_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    pipeline_id     TEXT NOT NULL DEFAULT '',
                    block_on_critical INTEGER NOT NULL DEFAULT 1,
                    block_on_high   INTEGER NOT NULL DEFAULT 0,
                    max_critical    INTEGER NOT NULL DEFAULT 0,
                    max_high        INTEGER NOT NULL DEFAULT 5,
                    max_medium      INTEGER NOT NULL DEFAULT 20,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_policies_org
                    ON gate_policies (org_id);

                CREATE TABLE IF NOT EXISTS github_app_installations (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    app_id               TEXT NOT NULL,
                    installation_id      TEXT NOT NULL,
                    webhook_secret_hash  TEXT NOT NULL,
                    app_slug             TEXT NOT NULL DEFAULT '',
                    installed_at         DATETIME NOT NULL,
                    UNIQUE (org_id, installation_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ghapp_org
                    ON github_app_installations (org_id);

                CREATE INDEX IF NOT EXISTS idx_ghapp_installation
                    ON github_app_installations (installation_id);

                CREATE TABLE IF NOT EXISTS hook_policies (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    policy_json  TEXT NOT NULL,
                    hash         TEXT NOT NULL,
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_hookpolicy_org
                    ON hook_policies (org_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_hookpolicy_hash
                    ON hook_policies (org_id, hash);
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
    # Pipelines
    # ------------------------------------------------------------------

    def register_pipeline(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new CI/CD pipeline. Returns the created record."""
        name = data.get("name", "")
        if not name:
            raise ValueError("name is required.")

        ci_platform = data.get("ci_platform", "github_actions")
        if ci_platform not in _VALID_CI_PLATFORMS:
            raise ValueError(
                f"Invalid ci_platform: {ci_platform}. Must be one of {_VALID_CI_PLATFORMS}"
            )

        pipeline_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            "pipeline_id": pipeline_id,
            "org_id": org_id,
            "name": name,
            "repo_url": data.get("repo_url", ""),
            "branch": data.get("branch", "main"),
            "ci_platform": ci_platform,
            "security_gates_enabled": int(data.get("security_gates_enabled", 1)),
            "sast_enabled": int(data.get("sast_enabled", 1)),
            "dast_enabled": int(data.get("dast_enabled", 0)),
            "sca_enabled": int(data.get("sca_enabled", 1)),
            "secret_scan_enabled": int(data.get("secret_scan_enabled", 1)),
            "container_scan_enabled": int(data.get("container_scan_enabled", 0)),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pipelines
                        (pipeline_id, org_id, name, repo_url, branch, ci_platform,
                         security_gates_enabled, sast_enabled, dast_enabled,
                         sca_enabled, secret_scan_enabled, container_scan_enabled,
                         created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["pipeline_id"], record["org_id"], record["name"],
                        record["repo_url"], record["branch"], record["ci_platform"],
                        record["security_gates_enabled"], record["sast_enabled"],
                        record["dast_enabled"], record["sca_enabled"],
                        record["secret_scan_enabled"], record["container_scan_enabled"],
                        record["created_at"],
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "devsecops", "org_id": org_id, "source_engine": "devsecops"})
            except Exception:
                pass

        return record

    def list_pipelines(
        self,
        org_id: str,
        ci_platform: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List pipelines for org with optional ci_platform filter."""
        query = "SELECT * FROM pipelines WHERE org_id=?"
        params: list = [org_id]
        if ci_platform:
            query += " AND ci_platform=?"
            params.append(ci_platform)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def _get_pipeline(self, org_id: str, pipeline_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pipelines WHERE org_id=? AND pipeline_id=?",
                (org_id, pipeline_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------

    def trigger_run(
        self, org_id: str, pipeline_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Trigger a new pipeline run with REAL scanners.

        Invokes Semgrep (SAST), Trivy (SCA + container), and the SecretScanner
        engine (secrets) when enabled on the pipeline. Aggregates findings,
        evaluates gate policies, persists everything, and best-effort feeds
        the Brain Pipeline.
        """
        pipeline = self._get_pipeline(org_id, pipeline_id)
        if pipeline is None:
            raise ValueError(f"Pipeline {pipeline_id} not found for org {org_id}.")

        run_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        repo_url = pipeline.get("repo_url", "") or data.get("repo_url", "")

        sast_findings_list: List[Dict[str, Any]] = []
        sca_findings_list: List[Dict[str, Any]] = []
        secret_findings_list: List[Dict[str, Any]] = []
        container_findings_list: List[Dict[str, Any]] = []

        # SAST via Semgrep
        if pipeline["sast_enabled"] and repo_url:
            try:
                from core.semgrep_integration import SemgrepScanner
                scanner = SemgrepScanner()
                if scanner.is_semgrep_available():
                    result = scanner.scan_and_ingest(repo_url, org_id)
                    sast_findings_list = result.get("findings", []) or []
            except Exception as exc:  # noqa: BLE001
                _logger.warning("SAST scan failed: %s", exc)

        # SCA via Trivy (repo mode against the configured repo URL)
        if pipeline["sca_enabled"] and repo_url:
            try:
                from core.trivy_integration import TrivyScanner
                scanner = TrivyScanner()
                if scanner.is_trivy_available():
                    result = scanner.scan_and_ingest(repo_url, org_id, scan_type="repo")
                    sca_findings_list = result.get("findings", []) or []
            except Exception as exc:  # noqa: BLE001
                _logger.warning("SCA scan failed: %s", exc)

        # Secret scanning via SecretScannerEngine (per-org instance)
        if pipeline["secret_scan_enabled"] and repo_url:
            try:
                from core.secret_scanner_engine import SecretScannerEngine
                ss = SecretScannerEngine.for_org(org_id)
                job = ss.create_scan_job(
                    org_id, {"target_type": "git_repo", "target_path": repo_url}
                )
                ss.start_scan(org_id, job["id"])
                detail = ss.get_scan_job(org_id, job["id"]) or {}
                secret_findings_list = detail.get("findings", []) or []
            except Exception as exc:  # noqa: BLE001
                _logger.warning("Secret scan failed: %s", exc)

        # Container scanning via Trivy (image mode)
        if pipeline["container_scan_enabled"]:
            try:
                from core.trivy_integration import TrivyScanner
                scanner = TrivyScanner()
                if scanner.is_trivy_available():
                    image = data.get("container_image", "") or ""
                    if image:
                        result = scanner.scan_and_ingest(image, org_id, scan_type="image")
                        container_findings_list = result.get("findings", []) or []
            except Exception as exc:  # noqa: BLE001
                _logger.warning("Container scan failed: %s", exc)

        all_findings: List[Dict[str, Any]] = (
            sast_findings_list
            + sca_findings_list
            + secret_findings_list
            + container_findings_list
        )

        def _sev(f: Dict[str, Any]) -> str:
            return (f.get("severity") or "").lower()

        n_critical = sum(1 for f in all_findings if _sev(f) == "critical")
        n_high = sum(1 for f in all_findings if _sev(f) == "high")
        n_medium = sum(1 for f in all_findings if _sev(f) == "medium")
        n_low = sum(1 for f in all_findings if _sev(f) == "low")

        # Build persistable rows for security_findings table
        scanner_map = [
            ("sast", sast_findings_list),
            ("sca", sca_findings_list),
            ("secret_scan", secret_findings_list),
            ("container", container_findings_list),
        ]
        rows: List[Dict[str, Any]] = []
        for scanner_type, items in scanner_map:
            for f in items:
                rows.append({
                    "scanner_type": scanner_type,
                    "severity": _sev(f) or "info",
                    "title": f.get("title") or f.get("rule_id") or f.get("source_id") or "",
                    "file_path": f.get("file_path") or "",
                    "line_number": int(f.get("line_number") or 0),
                    "cve_id": f.get("cve_id") or "",
                })

        # Evaluate gate policies
        gate_blocked = False
        block_reason = ""
        if pipeline["security_gates_enabled"]:
            gate_blocked, block_reason = self._evaluate_gates(
                org_id, pipeline_id, n_critical, n_high, n_medium
            )

        status = "blocked" if gate_blocked else "passed"

        run = {
            "run_id": run_id,
            "org_id": org_id,
            "pipeline_id": pipeline_id,
            "triggered_by": data.get("triggered_by", "manual"),
            "commit_sha": data.get("commit_sha", ""),
            "branch": data.get("branch", pipeline["branch"]),
            "status": status,
            "started_at": now,
            "completed_at": now,
            "sast_findings": len(sast_findings_list),
            "sca_findings": len(sca_findings_list),
            "secret_findings": len(secret_findings_list),
            "container_findings": len(container_findings_list),
            "gate_blocked": int(gate_blocked),
            "block_reason": block_reason,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pipeline_runs
                        (run_id, org_id, pipeline_id, triggered_by, commit_sha, branch,
                         status, started_at, completed_at, sast_findings, sca_findings,
                         secret_findings, container_findings, gate_blocked, block_reason)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        run["run_id"], run["org_id"], run["pipeline_id"],
                        run["triggered_by"], run["commit_sha"], run["branch"],
                        run["status"], run["started_at"], run["completed_at"],
                        run["sast_findings"], run["sca_findings"], run["secret_findings"],
                        run["container_findings"], run["gate_blocked"], run["block_reason"],
                    ),
                )
                # Persist real findings
                self._insert_findings(conn, org_id, run_id, pipeline_id, rows)

        run["finding_summary"] = {
            "critical": n_critical,
            "high": n_high,
            "medium": n_medium,
            "low": n_low,
        }

        # Best-effort: feed all_findings into the Brain Pipeline
        if all_findings:
            try:
                from core.brain_pipeline import BrainPipeline, PipelineInput
                BrainPipeline().run(PipelineInput(
                    org_id=org_id,
                    findings=all_findings,
                    run_pentest=False,
                    run_playbooks=True,
                    generate_evidence=False,
                ))
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "BrainPipeline feed from trigger_run failed: %s", exc
                )

        return run

    def _insert_findings(
        self,
        conn: sqlite3.Connection,
        org_id: str,
        run_id: str,
        pipeline_id: str,
        rows: List[Dict[str, Any]],
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        for f in rows:
            conn.execute(
                """
                INSERT INTO security_findings
                    (finding_id, org_id, run_id, pipeline_id, scanner_type, severity,
                     title, file_path, line_number, cve_id, suppressed, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    str(uuid.uuid4()), org_id, run_id, pipeline_id,
                    f["scanner_type"], f["severity"], f["title"],
                    f["file_path"], f["line_number"], f["cve_id"], 0, now,
                ),
            )

    def _evaluate_gates(
        self,
        org_id: str,
        pipeline_id: str,
        n_critical: int,
        n_high: int,
        n_medium: int,
    ) -> tuple[bool, str]:
        """Evaluate gate policies. Returns (blocked, reason)."""
        policies = self.list_gate_policies(org_id, pipeline_id=pipeline_id)
        # Also include org-wide policies (no pipeline_id)
        org_wide = self.list_gate_policies(org_id)
        all_policies = {p["policy_id"]: p for p in policies + org_wide}

        for policy in all_policies.values():
            if not policy["enabled"]:
                continue
            if policy["block_on_critical"] and n_critical > policy["max_critical"]:
                return True, (
                    f"Policy '{policy['name']}': {n_critical} critical findings "
                    f"exceeds max_critical={policy['max_critical']}"
                )
            if policy["block_on_high"] and n_high > policy["max_high"]:
                return True, (
                    f"Policy '{policy['name']}': {n_high} high findings "
                    f"exceeds max_high={policy['max_high']}"
                )
            if n_medium > policy["max_medium"]:
                return True, (
                    f"Policy '{policy['name']}': {n_medium} medium findings "
                    f"exceeds max_medium={policy['max_medium']}"
                )
        return False, ""

    def get_run(self, org_id: str, run_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single run by run_id and org_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pipeline_runs WHERE org_id=? AND run_id=?",
                (org_id, run_id),
            ).fetchone()
        return self._row(row) if row else None

    def list_runs(
        self,
        org_id: str,
        pipeline_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """List runs with optional pipeline_id / status filters."""
        query = "SELECT * FROM pipeline_runs WHERE org_id=?"
        params: list = [org_id]
        if pipeline_id:
            query += " AND pipeline_id=?"
            params.append(pipeline_id)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def list_findings(
        self,
        org_id: str,
        run_id: Optional[str] = None,
        severity: Optional[str] = None,
        suppressed: bool = False,
    ) -> List[Dict[str, Any]]:
        """List security findings with optional filters."""
        query = "SELECT * FROM security_findings WHERE org_id=? AND suppressed=?"
        params: list = [org_id, int(suppressed)]
        if run_id:
            query += " AND run_id=?"
            params.append(run_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def suppress_finding(self, org_id: str, finding_id: str) -> bool:
        """Mark a finding as suppressed. Returns True on success."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE security_findings SET suppressed=1 WHERE org_id=? AND finding_id=?",
                    (org_id, finding_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Gate policies
    # ------------------------------------------------------------------

    def create_gate_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a security gate policy. Returns the created record."""
        name = data.get("name", "")
        if not name:
            raise ValueError("name is required.")

        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": name,
            "pipeline_id": data.get("pipeline_id", ""),
            "block_on_critical": int(data.get("block_on_critical", 1)),
            "block_on_high": int(data.get("block_on_high", 0)),
            "max_critical": int(data.get("max_critical", 0)),
            "max_high": int(data.get("max_high", 5)),
            "max_medium": int(data.get("max_medium", 20)),
            "enabled": int(data.get("enabled", 1)),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO gate_policies
                        (policy_id, org_id, name, pipeline_id, block_on_critical,
                         block_on_high, max_critical, max_high, max_medium, enabled, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["policy_id"], record["org_id"], record["name"],
                        record["pipeline_id"], record["block_on_critical"],
                        record["block_on_high"], record["max_critical"],
                        record["max_high"], record["max_medium"],
                        record["enabled"], record["created_at"],
                    ),
                )
        return record

    def list_gate_policies(
        self,
        org_id: str,
        pipeline_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List gate policies. If pipeline_id given, returns policies for that pipeline."""
        query = "SELECT * FROM gate_policies WHERE org_id=?"
        params: list = [org_id]
        if pipeline_id is not None:
            query += " AND pipeline_id=?"
            params.append(pipeline_id)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_devsecops_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate DevSecOps statistics for an org."""
        with self._conn() as conn:
            total_pipelines = conn.execute(
                "SELECT COUNT(*) FROM pipelines WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_runs = conn.execute(
                "SELECT COUNT(*) FROM pipeline_runs WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            passed_runs = conn.execute(
                "SELECT COUNT(*) FROM pipeline_runs WHERE org_id=? AND status='passed'",
                (org_id,),
            ).fetchone()[0]

            blocked_runs = conn.execute(
                "SELECT COUNT(*) FROM pipeline_runs WHERE org_id=? AND gate_blocked=1",
                (org_id,),
            ).fetchone()[0]

            critical_findings = conn.execute(
                "SELECT COUNT(*) FROM security_findings WHERE org_id=? AND severity='critical' AND suppressed=0",
                (org_id,),
            ).fetchone()[0]

            high_findings = conn.execute(
                "SELECT COUNT(*) FROM security_findings WHERE org_id=? AND severity='high' AND suppressed=0",
                (org_id,),
            ).fetchone()[0]

            secret_findings = conn.execute(
                "SELECT COUNT(*) FROM security_findings WHERE org_id=? AND scanner_type='secret_scan' AND suppressed=0",
                (org_id,),
            ).fetchone()[0]

            # Per-platform breakdown
            platform_rows = conn.execute(
                """
                SELECT p.ci_platform, COUNT(r.run_id) as run_count
                FROM pipelines p
                LEFT JOIN pipeline_runs r ON r.pipeline_id = p.pipeline_id AND r.org_id = p.org_id
                WHERE p.org_id=?
                GROUP BY p.ci_platform
                """,
                (org_id,),
            ).fetchall()

        pass_rate = (passed_runs / total_runs) if total_runs > 0 else 0.0
        by_platform = {row[0]: row[1] for row in platform_rows}

        return {
            "total_pipelines": total_pipelines,
            "total_runs": total_runs,
            "pass_rate": round(pass_rate, 4),
            "blocked_runs": blocked_runs,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "secret_findings": secret_findings,
            "by_platform": by_platform,
        }


    # ------------------------------------------------------------------
    # GAP-015 — GitHub App registration + HMAC webhook verification
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_secret(secret: str) -> str:
        """SHA-256 hex digest of a webhook secret (never store raw secret)."""
        if not isinstance(secret, str):
            raise ValueError("secret must be a string")
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def register_github_app(
        self,
        org_id: str,
        app_id: str,
        installation_id: str,
        webhook_secret_hash: str,
        app_slug: str = "",
    ) -> Dict[str, Any]:
        """Register a GitHub App installation. Idempotent on (org_id, installation_id).

        `webhook_secret_hash` MUST be the SHA-256 hex digest of the raw secret.
        Callers may pass a raw secret (len != 64, non-hex) — it will be hashed here
        as a safety net; but the contract is to pre-hash.
        """
        if not org_id or not app_id or not installation_id:
            raise ValueError("org_id, app_id, installation_id are required")
        if not isinstance(webhook_secret_hash, str) or not webhook_secret_hash:
            raise ValueError("webhook_secret_hash is required")

        # Safety net: if a raw secret was passed, hash it.
        looks_hashed = (
            len(webhook_secret_hash) == 64
            and all(c in "0123456789abcdef" for c in webhook_secret_hash.lower())
        )
        stored_hash = webhook_secret_hash if looks_hashed else self._hash_secret(
            webhook_secret_hash
        )

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    """
                    SELECT * FROM github_app_installations
                    WHERE org_id=? AND installation_id=?
                    """,
                    (org_id, installation_id),
                ).fetchone()
                if existing is not None:
                    # Idempotent — refresh secret hash + app metadata.
                    conn.execute(
                        """
                        UPDATE github_app_installations
                        SET app_id=?, webhook_secret_hash=?, app_slug=?
                        WHERE org_id=? AND installation_id=?
                        """,
                        (
                            app_id,
                            stored_hash,
                            app_slug or existing["app_slug"],
                            org_id,
                            installation_id,
                        ),
                    )
                    row = conn.execute(
                        """
                        SELECT * FROM github_app_installations
                        WHERE org_id=? AND installation_id=?
                        """,
                        (org_id, installation_id),
                    ).fetchone()
                    return self._row(row)

                record_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO github_app_installations
                        (id, org_id, app_id, installation_id, webhook_secret_hash,
                         app_slug, installed_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        record_id,
                        org_id,
                        app_id,
                        installation_id,
                        stored_hash,
                        app_slug,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM github_app_installations WHERE id=?",
                    (record_id,),
                ).fetchone()
        return self._row(row)

    def list_github_app_installations(self, org_id: str) -> List[Dict[str, Any]]:
        """List all GitHub App installations for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM github_app_installations
                WHERE org_id=?
                ORDER BY installed_at DESC
                """,
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def verify_webhook(
        self,
        payload_bytes: bytes,
        signature_header: str,
        installation_id: str,
    ) -> bool:
        """Verify a GitHub webhook HMAC-SHA256 signature.

        GitHub sends the X-Hub-Signature-256 header as `sha256=<hex>`. We stored
        only the SHA-256 hash of the raw secret (never the secret itself), so we
        cannot re-HMAC with the raw secret. Instead, we treat the stored hex
        digest as the HMAC key — registration MUST have stored the HMAC key (i.e.
        the raw webhook secret's hex representation) accordingly. Callers that
        want the classic GitHub HMAC semantics should register the raw secret
        directly (the method hashes it once for at-rest storage); the caller's
        job is to compute the expected digest the same way.
        """
        if not isinstance(payload_bytes, (bytes, bytearray)):
            return False
        if not signature_header or not installation_id:
            return False

        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT webhook_secret_hash FROM github_app_installations
                WHERE installation_id=?
                """,
                (installation_id,),
            ).fetchone()
        if row is None:
            return False
        stored_hash = row["webhook_secret_hash"]

        # Expected signature computed using the stored hash as HMAC key so the
        # raw secret never leaves the provisioning step.
        expected = hmac.new(
            stored_hash.encode("utf-8"),
            bytes(payload_bytes),
            hashlib.sha256,
        ).hexdigest()

        provided = signature_header.strip()
        if provided.lower().startswith("sha256="):
            provided = provided.split("=", 1)[1]

        try:
            return hmac.compare_digest(expected, provided)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # GAP-068 — .fixops/hooks.yaml policy parsing + persistence
    # ------------------------------------------------------------------

    _HOOK_ALLOWED_KEYS = {"pre-commit", "pre_commit", "pr-gate", "pr_gate"}
    _HOOK_PRECOMMIT_KEYS = {"block-on", "block_on", "llm"}
    _HOOK_PRGATE_KEYS = {"block-on", "block_on"}
    _HOOK_BLOCK_VOCAB = {
        "critical", "high", "medium", "low", "info",
        "secrets", "secret_scan", "sast", "dast", "sca", "container",
        "license", "malware",
    }

    @classmethod
    def _normalize_hook_section(
        cls, section: Any, allowed: set, errors: List[str], section_name: str
    ) -> Dict[str, Any]:
        if not isinstance(section, dict):
            errors.append(f"{section_name}: must be a mapping/object")
            return {}
        normalized: Dict[str, Any] = {}
        for raw_key, raw_val in section.items():
            if raw_key not in allowed:
                errors.append(f"{section_name}: unknown key '{raw_key}'")
                continue
            key = raw_key.replace("_", "-")
            if key == "block-on":
                if not isinstance(raw_val, list):
                    errors.append(f"{section_name}.block-on: must be a list")
                    continue
                cleaned: List[str] = []
                for item in raw_val:
                    if not isinstance(item, str):
                        errors.append(
                            f"{section_name}.block-on: non-string entry {item!r}"
                        )
                        continue
                    token = item.strip().lower()
                    if not token:
                        continue
                    if token not in cls._HOOK_BLOCK_VOCAB:
                        errors.append(
                            f"{section_name}.block-on: unsupported value '{item}'"
                        )
                        continue
                    cleaned.append(token)
                normalized["block-on"] = cleaned
            elif key == "llm":
                if not isinstance(raw_val, bool):
                    errors.append(f"{section_name}.llm: must be boolean")
                    continue
                normalized["llm"] = raw_val
        return normalized

    @classmethod
    def parse_hooks_yaml(cls, yaml_text: str) -> Dict[str, Any]:
        """Parse .fixops/hooks.yaml. YAML first, JSON fallback.

        Returns: {valid: bool, policy: {pre-commit: {...}, pr-gate: {...}},
                  errors: [...], source: 'yaml'|'json'}.
        """
        if not isinstance(yaml_text, str):
            return {
                "valid": False,
                "policy": {},
                "errors": ["yaml_text must be a string"],
                "source": "none",
            }
        text = yaml_text.strip()
        if not text:
            return {
                "valid": False,
                "policy": {},
                "errors": ["empty document"],
                "source": "none",
            }

        parsed: Any = None
        source = "none"
        errors: List[str] = []

        if _yaml is not None:
            try:
                parsed = _yaml.safe_load(text)
                source = "yaml"
            except Exception as exc:  # noqa: BLE001 — parser-specific errors vary
                errors.append(f"yaml parse error: {exc}")
                parsed = None

        if parsed is None and not errors:
            # yaml unavailable — try JSON directly
            try:
                parsed = json.loads(text)
                source = "json"
            except json.JSONDecodeError as exc:
                errors.append(f"json parse error: {exc}")
        elif parsed is None and errors:
            # yaml failed — attempt JSON fallback and clear yaml error if JSON succeeds
            try:
                parsed = json.loads(text)
                source = "json"
                errors = []
            except json.JSONDecodeError:
                pass

        if parsed is None:
            return {"valid": False, "policy": {}, "errors": errors or ["unparseable"], "source": source}
        if not isinstance(parsed, dict):
            return {
                "valid": False,
                "policy": {},
                "errors": ["root must be a mapping/object"],
                "source": source,
            }

        # Validate top-level keys
        for key in parsed.keys():
            if key not in cls._HOOK_ALLOWED_KEYS:
                errors.append(f"unknown top-level key '{key}'")

        pre_commit_raw = parsed.get("pre-commit", parsed.get("pre_commit"))
        pr_gate_raw = parsed.get("pr-gate", parsed.get("pr_gate"))

        policy: Dict[str, Any] = {}
        if pre_commit_raw is not None:
            policy["pre-commit"] = cls._normalize_hook_section(
                pre_commit_raw, cls._HOOK_PRECOMMIT_KEYS, errors, "pre-commit"
            )
        if pr_gate_raw is not None:
            policy["pr-gate"] = cls._normalize_hook_section(
                pr_gate_raw, cls._HOOK_PRGATE_KEYS, errors, "pr-gate"
            )

        if not policy:
            errors.append("must define at least one of: pre-commit, pr-gate")

        return {
            "valid": len(errors) == 0,
            "policy": policy,
            "errors": errors,
            "source": source,
        }

    @staticmethod
    def _hash_policy(policy: Dict[str, Any]) -> str:
        canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def apply_hook_policy(
        self, org_id: str, hooks_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Persist a validated hook policy. Idempotent on (org_id, hash)."""
        if not org_id:
            raise ValueError("org_id is required")
        if not isinstance(hooks_dict, dict) or not hooks_dict:
            raise ValueError("hooks_dict must be a non-empty mapping")

        policy_hash = self._hash_policy(hooks_dict)
        policy_json = json.dumps(hooks_dict, sort_keys=True, separators=(",", ":"))
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    """
                    SELECT * FROM hook_policies
                    WHERE org_id=? AND hash=?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (org_id, policy_hash),
                ).fetchone()
                if existing is not None:
                    return {
                        "id": existing["id"],
                        "org_id": existing["org_id"],
                        "hash": existing["hash"],
                        "policy": json.loads(existing["policy_json"]),
                        "created_at": existing["created_at"],
                        "deduplicated": True,
                    }

                record_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO hook_policies
                        (id, org_id, policy_json, hash, created_at)
                    VALUES (?,?,?,?,?)
                    """,
                    (record_id, org_id, policy_json, policy_hash, now),
                )
        return {
            "id": record_id,
            "org_id": org_id,
            "hash": policy_hash,
            "policy": hooks_dict,
            "created_at": now,
            "deduplicated": False,
        }

    def get_active_hook_policy(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Return the most recently applied hook policy for an org, or None."""
        if not org_id:
            return None
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM hook_policies
                WHERE org_id=?
                ORDER BY created_at DESC LIMIT 1
                """,
                (org_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "hash": row["hash"],
            "policy": json.loads(row["policy_json"]),
            "created_at": row["created_at"],
        }

    def delete_hook_policy(
        self,
        org_id: Optional[str] = None,
        hook_id: Optional[str] = None,
        policy_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Delete hook policy records by id, hash, or active-for-org.

        Resolution order (first match wins):
          1. ``hook_id`` — delete that exact record
          2. ``policy_hash`` (+ ``org_id`` if provided) — delete matching content hash
          3. ``org_id`` alone — delete the active (most recent) policy for that org

        Returns: ``{deleted: int, record: Optional[dict]}``.
        """
        if not (hook_id or policy_hash or org_id):
            raise ValueError(
                "at least one of hook_id, policy_hash, or org_id is required"
            )

        with self._lock:
            with self._conn() as conn:
                row = None
                if hook_id:
                    row = conn.execute(
                        "SELECT * FROM hook_policies WHERE id=?",
                        (hook_id,),
                    ).fetchone()
                elif policy_hash and org_id:
                    row = conn.execute(
                        """
                        SELECT * FROM hook_policies
                        WHERE org_id=? AND hash=?
                        ORDER BY created_at DESC LIMIT 1
                        """,
                        (org_id, policy_hash),
                    ).fetchone()
                elif policy_hash:
                    row = conn.execute(
                        """
                        SELECT * FROM hook_policies
                        WHERE hash=?
                        ORDER BY created_at DESC LIMIT 1
                        """,
                        (policy_hash,),
                    ).fetchone()
                else:  # org_id alone — delete active policy
                    row = conn.execute(
                        """
                        SELECT * FROM hook_policies
                        WHERE org_id=?
                        ORDER BY created_at DESC LIMIT 1
                        """,
                        (org_id,),
                    ).fetchone()

                if row is None:
                    return {"deleted": 0, "record": None}

                record = {
                    "id": row["id"],
                    "org_id": row["org_id"],
                    "hash": row["hash"],
                    "policy": json.loads(row["policy_json"]),
                    "created_at": row["created_at"],
                }
                cur = conn.execute(
                    "DELETE FROM hook_policies WHERE id=?", (row["id"],)
                )
                return {"deleted": int(cur.rowcount or 0), "record": record}


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[DevSecOpsEngine] = None
_engine_lock = threading.Lock()


def get_devsecops_engine() -> DevSecOpsEngine:
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = DevSecOpsEngine()
    return _engine_instance
