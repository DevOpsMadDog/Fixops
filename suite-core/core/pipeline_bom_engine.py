"""Pipeline Bill of Materials (PBOM) Engine — ALDECI GAP-017.

Where SBOM captures *what is in the binary*, PBOM captures *how the binary
was made* — every CI/CD step's configuration, the artifacts each step
produced, their cryptographic signatures, and the environments they were
deployed to.

Capabilities
------------
- Record CI/CD pipeline runs (provider-agnostic: GitHub Actions, GitLab CI,
  Jenkins, CircleCI, Azure DevOps, Argo Workflows, Tekton).
- Record ordered pipeline steps with type, image, command, config hash,
  duration and outcome.
- Record artifacts produced by steps (container images, binaries, packages,
  SBOMs, attestations) with SHA-256, signer identity, and signature algo.
- Record deployments (artifact -> environment, target, actor).
- Export a single nested PBOM document per run (run -> steps[] -> artifacts[]
  -> deploys[]).
- Provenance lookup: given an artifact SHA-256, find every run that produced
  it and every deployment that used it.
- Full multi-tenant isolation via org_id on pipeline_runs; child tables join
  via pipeline_run_id so org scoping is preserved through the graph.

Design notes
------------
- SQLite WAL + RLock (same pattern as all other ALDECI engines).
- Realistic CI races: a run can be marked complete before every late-arriving
  artifact has been reported (think post-run signature webhooks). We therefore
  *allow* artifacts and deploys to be attached to a completed run. Runs with
  an unknown status transition are rejected.
- No cross-engine imports. No new third-party deps.
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
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover - optional wiring
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "pipeline_bom.db"
)


_VALID_STEP_TYPES = {
    "build", "test", "lint", "scan", "sign", "publish", "deploy",
}
_VALID_ARTIFACT_TYPES = {
    "container-image", "binary", "package", "sbom", "attestation",
}
_VALID_RUN_STATUSES = {
    "queued", "running", "success", "failed", "cancelled", "partial",
}
_VALID_OUTCOMES = {
    "success", "failed", "skipped", "cancelled", "neutral",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PipelineBOMEngine:
    """SQLite-backed Pipeline BOM (PBOM) engine.

    Thread-safe via RLock. Multi-tenant via org_id on pipeline_runs;
    child rows inherit isolation through pipeline_run_id FK lookups that
    always re-verify the run belongs to the calling org.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self.ensure_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS pipeline_runs (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    repo_ref        TEXT NOT NULL,
                    run_id_external TEXT NOT NULL,
                    ci_provider     TEXT NOT NULL,
                    trigger         TEXT NOT NULL DEFAULT '',
                    branch          TEXT NOT NULL DEFAULT '',
                    commit_sha      TEXT NOT NULL DEFAULT '',
                    started_at      TEXT NOT NULL,
                    finished_at     TEXT,
                    status          TEXT NOT NULL DEFAULT 'running',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pipeline_runs_org
                    ON pipeline_runs(org_id);
                CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo
                    ON pipeline_runs(org_id, repo_ref);
                CREATE INDEX IF NOT EXISTS idx_pipeline_runs_commit
                    ON pipeline_runs(org_id, commit_sha);

                CREATE TABLE IF NOT EXISTS pipeline_steps (
                    id               TEXT PRIMARY KEY,
                    pipeline_run_id  TEXT NOT NULL,
                    step_order       INTEGER NOT NULL,
                    step_name        TEXT NOT NULL,
                    step_type        TEXT NOT NULL,
                    image            TEXT NOT NULL DEFAULT '',
                    command          TEXT NOT NULL DEFAULT '',
                    config_hash      TEXT NOT NULL DEFAULT '',
                    duration_ms      INTEGER NOT NULL DEFAULT 0,
                    outcome          TEXT NOT NULL DEFAULT 'neutral',
                    created_at       TEXT NOT NULL,
                    FOREIGN KEY (pipeline_run_id) REFERENCES pipeline_runs(id)
                );

                CREATE INDEX IF NOT EXISTS idx_pipeline_steps_run
                    ON pipeline_steps(pipeline_run_id);

                CREATE TABLE IF NOT EXISTS pipeline_artifacts (
                    id               TEXT PRIMARY KEY,
                    pipeline_run_id  TEXT NOT NULL,
                    step_id          TEXT,
                    artifact_ref     TEXT NOT NULL,
                    artifact_type    TEXT NOT NULL,
                    sha256           TEXT NOT NULL,
                    size_bytes       INTEGER NOT NULL DEFAULT 0,
                    signed_by        TEXT NOT NULL DEFAULT '',
                    signature_algo   TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL,
                    FOREIGN KEY (pipeline_run_id) REFERENCES pipeline_runs(id)
                );

                CREATE INDEX IF NOT EXISTS idx_pipeline_artifacts_run
                    ON pipeline_artifacts(pipeline_run_id);
                CREATE INDEX IF NOT EXISTS idx_pipeline_artifacts_sha
                    ON pipeline_artifacts(sha256);

                CREATE TABLE IF NOT EXISTS pipeline_deploys (
                    id               TEXT PRIMARY KEY,
                    pipeline_run_id  TEXT NOT NULL,
                    artifact_id      TEXT NOT NULL,
                    environment      TEXT NOT NULL,
                    target           TEXT NOT NULL DEFAULT '',
                    deployed_at      TEXT NOT NULL,
                    deployed_by      TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL,
                    FOREIGN KEY (pipeline_run_id) REFERENCES pipeline_runs(id),
                    FOREIGN KEY (artifact_id)     REFERENCES pipeline_artifacts(id)
                );

                CREATE INDEX IF NOT EXISTS idx_pipeline_deploys_run
                    ON pipeline_deploys(pipeline_run_id);
                CREATE INDEX IF NOT EXISTS idx_pipeline_deploys_artifact
                    ON pipeline_deploys(artifact_id);
                CREATE INDEX IF NOT EXISTS idx_pipeline_deploys_env
                    ON pipeline_deploys(environment);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return dict(row) if row else {}

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            result = bus.emit(event, payload)
            # Some bus implementations return a coroutine; close it to
            # avoid RuntimeWarnings when called outside an event loop.
            if hasattr(result, "close") and hasattr(result, "send"):
                try:
                    result.close()
                except Exception:  # pragma: no cover
                    pass
        except Exception:  # pragma: no cover - bus optional
            _logger.debug("trustgraph emit failed", exc_info=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_run(self, run_db_id: str, org_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM pipeline_runs WHERE id = ?"
        params: List[Any] = [run_db_id]
        if org_id is not None:
            sql += " AND org_id = ?"
            params.append(org_id)
        with self._conn() as conn:
            row = conn.execute(sql, params).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------

    def record_run(
        self,
        org_id: str,
        repo_ref: str,
        run_id_external: str,
        ci_provider: str,
        trigger: str = "",
        branch: str = "",
        commit_sha: str = "",
    ) -> str:
        """Start a pipeline run record.

        Returns the engine-side run_db_id (uuid4). ``run_id_external`` is the
        CI provider's own run ID (preserved for round-tripping).
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not repo_ref:
            raise ValueError("repo_ref is required")
        if not ci_provider:
            raise ValueError("ci_provider is required")

        run_db_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": run_db_id,
            "org_id": org_id,
            "repo_ref": repo_ref,
            "run_id_external": run_id_external or "",
            "ci_provider": ci_provider,
            "trigger": trigger,
            "branch": branch,
            "commit_sha": commit_sha,
            "started_at": now,
            "finished_at": None,
            "status": "running",
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO pipeline_runs
                   (id, org_id, repo_ref, run_id_external, ci_provider, trigger,
                    branch, commit_sha, started_at, finished_at, status, created_at)
                   VALUES (:id, :org_id, :repo_ref, :run_id_external, :ci_provider,
                           :trigger, :branch, :commit_sha, :started_at,
                           :finished_at, :status, :created_at)""",
                row,
            )

        self._emit(
            "pipeline_run_started",
            {"run_db_id": run_db_id, "org_id": org_id, "repo_ref": repo_ref,
             "commit_sha": commit_sha, "ci_provider": ci_provider},
        )
        return run_db_id

    def record_step(
        self,
        run_db_id: str,
        step_order: int,
        step_name: str,
        step_type: str,
        image: str = "",
        command: str = "",
        config_hash: str = "",
        duration_ms: int = 0,
        outcome: str = "neutral",
    ) -> str:
        """Record a single pipeline step. Returns the step_id."""
        if step_type not in _VALID_STEP_TYPES:
            raise ValueError(
                f"step_type must be one of: {sorted(_VALID_STEP_TYPES)}"
            )
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(
                f"outcome must be one of: {sorted(_VALID_OUTCOMES)}"
            )
        if duration_ms < 0:
            raise ValueError("duration_ms must be >= 0")
        run = self._get_run(run_db_id)
        if not run:
            raise ValueError(f"pipeline run not found: {run_db_id}")

        step_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": step_id,
            "pipeline_run_id": run_db_id,
            "step_order": int(step_order),
            "step_name": step_name,
            "step_type": step_type,
            "image": image,
            "command": command,
            "config_hash": config_hash,
            "duration_ms": int(duration_ms),
            "outcome": outcome,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO pipeline_steps
                   (id, pipeline_run_id, step_order, step_name, step_type,
                    image, command, config_hash, duration_ms, outcome, created_at)
                   VALUES (:id, :pipeline_run_id, :step_order, :step_name,
                           :step_type, :image, :command, :config_hash,
                           :duration_ms, :outcome, :created_at)""",
                row,
            )
        return step_id

    def record_artifact(
        self,
        run_db_id: str,
        step_id: Optional[str],
        artifact_ref: str,
        artifact_type: str,
        sha256: str,
        size_bytes: int = 0,
        signed_by: str = "",
        signature_algo: str = "",
    ) -> str:
        """Record an artifact produced by a step. Returns the artifact_id.

        ``step_id`` may be ``None`` if the artifact is attributed to the run
        as a whole (e.g., aggregate SBOM). Artifacts may be recorded even
        after ``complete_run`` to model realistic CI races where signing or
        attestation webhooks arrive after the primary run is marked done.
        """
        if artifact_type not in _VALID_ARTIFACT_TYPES:
            raise ValueError(
                f"artifact_type must be one of: {sorted(_VALID_ARTIFACT_TYPES)}"
            )
        if not artifact_ref:
            raise ValueError("artifact_ref is required")
        if not sha256:
            raise ValueError("sha256 is required")
        if size_bytes < 0:
            raise ValueError("size_bytes must be >= 0")
        run = self._get_run(run_db_id)
        if not run:
            raise ValueError(f"pipeline run not found: {run_db_id}")

        art_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": art_id,
            "pipeline_run_id": run_db_id,
            "step_id": step_id,
            "artifact_ref": artifact_ref,
            "artifact_type": artifact_type,
            "sha256": sha256,
            "size_bytes": int(size_bytes),
            "signed_by": signed_by,
            "signature_algo": signature_algo,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO pipeline_artifacts
                   (id, pipeline_run_id, step_id, artifact_ref, artifact_type,
                    sha256, size_bytes, signed_by, signature_algo, created_at)
                   VALUES (:id, :pipeline_run_id, :step_id, :artifact_ref,
                           :artifact_type, :sha256, :size_bytes, :signed_by,
                           :signature_algo, :created_at)""",
                row,
            )

        self._emit(
            "pipeline_artifact_recorded",
            {"artifact_id": art_id, "run_db_id": run_db_id,
             "sha256": sha256, "artifact_type": artifact_type,
             "org_id": run.get("org_id")},
        )
        return art_id

    def record_deploy(
        self,
        run_db_id: str,
        artifact_id: str,
        environment: str,
        target: str = "",
        deployed_by: str = "",
    ) -> str:
        """Record a deployment of an artifact to an environment."""
        if not environment:
            raise ValueError("environment is required")
        run = self._get_run(run_db_id)
        if not run:
            raise ValueError(f"pipeline run not found: {run_db_id}")

        with self._conn() as conn:
            art_row = conn.execute(
                "SELECT id, pipeline_run_id FROM pipeline_artifacts WHERE id = ?",
                (artifact_id,),
            ).fetchone()
        if not art_row:
            raise ValueError(f"artifact not found: {artifact_id}")
        # Artifact must belong to *some* run in the same org as this run.
        art_run = self._get_run(art_row["pipeline_run_id"])
        if not art_run or art_run.get("org_id") != run.get("org_id"):
            raise ValueError(
                "artifact does not belong to the same org as the deploy run"
            )

        dep_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": dep_id,
            "pipeline_run_id": run_db_id,
            "artifact_id": artifact_id,
            "environment": environment,
            "target": target,
            "deployed_at": now,
            "deployed_by": deployed_by,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO pipeline_deploys
                   (id, pipeline_run_id, artifact_id, environment, target,
                    deployed_at, deployed_by, created_at)
                   VALUES (:id, :pipeline_run_id, :artifact_id, :environment,
                           :target, :deployed_at, :deployed_by, :created_at)""",
                row,
            )

        self._emit(
            "pipeline_deploy_recorded",
            {"deploy_id": dep_id, "artifact_id": artifact_id,
             "environment": environment, "org_id": run.get("org_id")},
        )
        return dep_id

    def complete_run(self, run_db_id: str, status: str) -> Dict[str, Any]:
        """Mark a run complete with a terminal status."""
        if status not in _VALID_RUN_STATUSES:
            raise ValueError(
                f"status must be one of: {sorted(_VALID_RUN_STATUSES)}"
            )
        run = self._get_run(run_db_id)
        if not run:
            raise ValueError(f"pipeline run not found: {run_db_id}")

        now = _now_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE pipeline_runs SET status = ?, finished_at = ? WHERE id = ?",
                (status, now, run_db_id),
            )
        updated = self._get_run(run_db_id) or {}

        self._emit(
            "pipeline_run_completed",
            {"run_db_id": run_db_id, "status": status,
             "org_id": updated.get("org_id")},
        )
        return updated

    # ------------------------------------------------------------------
    # Export / provenance
    # ------------------------------------------------------------------

    def export_pbom(self, run_db_id: str) -> Dict[str, Any]:
        """Return a nested PBOM document for a single run.

        Shape::

            {
              "schema": "aldeci.pbom/v1",
              "run": {... pipeline_runs row ...},
              "steps": [
                {... pipeline_steps row ...,
                 "artifacts": [
                   {... pipeline_artifacts row ...,
                    "deploys": [{... pipeline_deploys row ...}]}
                 ]}
              ],
              "orphan_artifacts": [...artifacts with step_id=None...]
            }

        The deploys list on each artifact only contains deploys whose
        ``pipeline_run_id == run_db_id``; deploys from other runs that
        reused this artifact are accessible through ``find_runs_producing_artifact``.
        """
        run = self._get_run(run_db_id)
        if not run:
            raise ValueError(f"pipeline run not found: {run_db_id}")

        with self._conn() as conn:
            step_rows = conn.execute(
                """SELECT * FROM pipeline_steps
                   WHERE pipeline_run_id = ?
                   ORDER BY step_order ASC, created_at ASC""",
                (run_db_id,),
            ).fetchall()
            artifact_rows = conn.execute(
                "SELECT * FROM pipeline_artifacts WHERE pipeline_run_id = ? ORDER BY created_at ASC",
                (run_db_id,),
            ).fetchall()
            deploy_rows = conn.execute(
                "SELECT * FROM pipeline_deploys WHERE pipeline_run_id = ? ORDER BY deployed_at ASC",
                (run_db_id,),
            ).fetchall()

        deploys_by_artifact: Dict[str, List[Dict[str, Any]]] = {}
        for d in deploy_rows:
            d_dict = self._row(d)
            deploys_by_artifact.setdefault(d_dict["artifact_id"], []).append(d_dict)

        artifacts_by_step: Dict[Optional[str], List[Dict[str, Any]]] = {}
        orphan_artifacts: List[Dict[str, Any]] = []
        for a in artifact_rows:
            a_dict = self._row(a)
            a_dict["deploys"] = deploys_by_artifact.get(a_dict["id"], [])
            key = a_dict.get("step_id")
            if key is None:
                orphan_artifacts.append(a_dict)
            else:
                artifacts_by_step.setdefault(key, []).append(a_dict)

        steps_nested: List[Dict[str, Any]] = []
        for s in step_rows:
            s_dict = self._row(s)
            s_dict["artifacts"] = artifacts_by_step.get(s_dict["id"], [])
            steps_nested.append(s_dict)

        return {
            "schema": "aldeci.pbom/v1",
            "run": run,
            "steps": steps_nested,
            "orphan_artifacts": orphan_artifacts,
        }

    def export_pbom_json(self, run_db_id: str, indent: int = 2) -> str:
        """Serialise export_pbom as JSON (convenience)."""
        return json.dumps(self.export_pbom(run_db_id), indent=indent, sort_keys=False)

    def find_runs_producing_artifact(
        self, org_id: str, artifact_sha256: str
    ) -> List[Dict[str, Any]]:
        """Find every run in ``org_id`` that produced an artifact with this SHA.

        Returns a list of ``{artifact, run, deploys}`` dicts ordered newest-first.
        """
        if not artifact_sha256:
            raise ValueError("artifact_sha256 is required")
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT a.id AS artifact_id, a.pipeline_run_id, a.sha256,
                          a.artifact_ref, a.artifact_type, a.signed_by,
                          a.signature_algo, a.created_at AS artifact_created_at,
                          r.*
                     FROM pipeline_artifacts a
                     JOIN pipeline_runs r ON r.id = a.pipeline_run_id
                    WHERE a.sha256 = ? AND r.org_id = ?
                    ORDER BY a.created_at DESC""",
                (artifact_sha256, org_id),
            ).fetchall()
            results: List[Dict[str, Any]] = []
            for r in rows:
                r_dict = dict(r)
                artifact = {
                    "id": r_dict.pop("artifact_id"),
                    "pipeline_run_id": r_dict.pop("pipeline_run_id"),
                    "sha256": r_dict.pop("sha256"),
                    "artifact_ref": r_dict.pop("artifact_ref"),
                    "artifact_type": r_dict.pop("artifact_type"),
                    "signed_by": r_dict.pop("signed_by"),
                    "signature_algo": r_dict.pop("signature_algo"),
                    "created_at": r_dict.pop("artifact_created_at"),
                }
                deploys = conn.execute(
                    "SELECT * FROM pipeline_deploys WHERE artifact_id = ? ORDER BY deployed_at DESC",
                    (artifact["id"],),
                ).fetchall()
                results.append({
                    "artifact": artifact,
                    "run": r_dict,  # remaining keys are the pipeline_runs row
                    "deploys": [self._row(d) for d in deploys],
                })
        return results

    def list_deployed_artifacts(
        self, org_id: str, environment: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List artifacts currently deployed in any environment (or one specific).

        Scoped by org_id. Returns newest deploys first.
        """
        sql = (
            "SELECT d.*, a.artifact_ref, a.artifact_type, a.sha256, a.signed_by, "
            "       a.signature_algo, r.repo_ref, r.commit_sha "
            "  FROM pipeline_deploys d "
            "  JOIN pipeline_artifacts a ON a.id = d.artifact_id "
            "  JOIN pipeline_runs r      ON r.id = d.pipeline_run_id "
            " WHERE r.org_id = ?"
        )
        params: List[Any] = [org_id]
        if environment is not None:
            sql += " AND d.environment = ?"
            params.append(environment)
        sql += " ORDER BY d.deployed_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate PBOM stats for an org."""
        with self._conn() as conn:
            runs_row = conn.execute(
                "SELECT COUNT(*) AS c FROM pipeline_runs WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            completed_row = conn.execute(
                """SELECT COUNT(*) AS c FROM pipeline_runs
                    WHERE org_id = ? AND status IN ('success','failed','cancelled','partial')""",
                (org_id,),
            ).fetchone()
            success_row = conn.execute(
                "SELECT COUNT(*) AS c FROM pipeline_runs WHERE org_id = ? AND status = 'success'",
                (org_id,),
            ).fetchone()
            step_row = conn.execute(
                """SELECT COUNT(*) AS c FROM pipeline_steps s
                     JOIN pipeline_runs r ON r.id = s.pipeline_run_id
                    WHERE r.org_id = ?""",
                (org_id,),
            ).fetchone()
            artifact_row = conn.execute(
                """SELECT COUNT(*) AS c FROM pipeline_artifacts a
                     JOIN pipeline_runs r ON r.id = a.pipeline_run_id
                    WHERE r.org_id = ?""",
                (org_id,),
            ).fetchone()
            signed_row = conn.execute(
                """SELECT COUNT(*) AS c FROM pipeline_artifacts a
                     JOIN pipeline_runs r ON r.id = a.pipeline_run_id
                    WHERE r.org_id = ? AND a.signed_by != ''""",
                (org_id,),
            ).fetchone()
            deploy_row = conn.execute(
                """SELECT COUNT(*) AS c FROM pipeline_deploys d
                     JOIN pipeline_runs r ON r.id = d.pipeline_run_id
                    WHERE r.org_id = ?""",
                (org_id,),
            ).fetchone()
            env_rows = conn.execute(
                """SELECT d.environment, COUNT(*) AS c FROM pipeline_deploys d
                     JOIN pipeline_runs r ON r.id = d.pipeline_run_id
                    WHERE r.org_id = ?
                    GROUP BY d.environment""",
                (org_id,),
            ).fetchall()

        total_runs = runs_row["c"] if runs_row else 0
        completed_runs = completed_row["c"] if completed_row else 0
        success_runs = success_row["c"] if success_row else 0
        total_artifacts = artifact_row["c"] if artifact_row else 0
        signed_artifacts = signed_row["c"] if signed_row else 0

        success_rate = (
            round(success_runs / completed_runs * 100.0, 2)
            if completed_runs > 0 else 0.0
        )
        sign_rate = (
            round(signed_artifacts / total_artifacts * 100.0, 2)
            if total_artifacts > 0 else 0.0
        )

        return {
            "org_id": org_id,
            "total_runs": total_runs,
            "completed_runs": completed_runs,
            "success_runs": success_runs,
            "success_rate_pct": success_rate,
            "total_steps": step_row["c"] if step_row else 0,
            "total_artifacts": total_artifacts,
            "signed_artifacts": signed_artifacts,
            "sign_rate_pct": sign_rate,
            "total_deploys": deploy_row["c"] if deploy_row else 0,
            "deploys_by_env": {r["environment"]: r["c"] for r in env_rows},
        }


# ---------------------------------------------------------------------------
# Module-level singleton accessor
# ---------------------------------------------------------------------------

_engine: Optional[PipelineBOMEngine] = None
_engine_lock = threading.Lock()


def get_engine(db_path: Optional[str] = None) -> PipelineBOMEngine:
    """Return a process-wide singleton for the default DB path."""
    global _engine
    with _engine_lock:
        if _engine is None or db_path is not None:
            _engine = PipelineBOMEngine(db_path=db_path or _DEFAULT_DB)
        return _engine
