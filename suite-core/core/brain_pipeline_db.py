"""
Brain Pipeline → DatabaseManager integration shim.

Responsibility (Sprint 2 scope only):
  After a ``BrainPipeline.run()`` completes, persist the ``PipelineResult``
  as a ``PipelineRun`` row via the enterprise ``DatabaseManager``.

What this module does NOT do:
  - It does NOT change any existing sqlite3 behaviour in brain_pipeline.py.
  - It does NOT block the pipeline result from being returned — the DB write
    is fire-and-await in async context or fire-and-background in sync context.
  - All failures are caught and logged; they never propagate to the caller.

Usage:
    # Async context (FastAPI handler, test):
    result = await pipeline.run_async(inp)
    await persist_pipeline_run(result, org_id="acme")

    # Sync context (CLI, background thread):
    result = pipeline.run(inp)
    persist_pipeline_run_sync(result, org_id="acme")

The sync wrapper uses ``asyncio.run()`` when no event loop is running, and
schedules a background task when one is already active (the brain pipeline
itself is CPU-bound and runs in a thread pool via run_async, so the sync
path should only be reached from the CLI).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

import structlog

if TYPE_CHECKING:
    # Avoid circular import; BrainPipeline imports nothing from this module.
    from core.brain_pipeline import PipelineResult  # noqa: F401

logger = structlog.get_logger(__name__)
_fallback_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_pipeline_run_row(result: "PipelineResult", org_id: str) -> Dict[str, Any]:
    """Convert a PipelineResult into a dict suitable for the PipelineRun model."""
    # Parse ISO timestamps back to datetime objects for SQLAlchemy
    def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None

    # Build condensed result summary (exclude full steps list to save space)
    result_dict = result.to_dict()
    summary = result_dict.get("summary", {})
    result_summary: Dict[str, Any] = {
        "run_id": result.run_id,
        "status": result_dict.get("status"),
        "total_duration_ms": result_dict.get("total_duration_ms"),
        "progress_percent": result_dict.get("progress_percent"),
        "error": result_dict.get("error"),
        **summary,
    }

    # Build input summary from available data
    input_summary: Dict[str, Any] = {
        "findings_ingested": result.findings_ingested,
    }

    return {
        "id": result.run_id,
        "org_id": org_id,
        "status": result.status.value if hasattr(result.status, "value") else str(result.status),
        "started_at": _parse_ts(result.started_at),
        "finished_at": _parse_ts(result.finished_at),
        "total_duration_ms": result.total_duration_ms,
        "findings_ingested": result.findings_ingested,
        "clusters_created": result.clusters_created,
        "exposure_cases_created": result.exposure_cases_created,
        "critical_cases": result.critical_cases,
        "avg_risk_score": result.avg_risk_score,
        "steps_json": [s.to_dict() for s in result.steps],
        "result_summary": result_summary,
        "input_summary": input_summary,
    }


# ---------------------------------------------------------------------------
# Async persist function
# ---------------------------------------------------------------------------

async def persist_pipeline_run(
    result: "PipelineResult",
    org_id: str = "default",
) -> bool:
    """
    Persist a completed PipelineResult to the enterprise database.

    Returns True on success, False on any error.  Never raises.

    Args:
        result:  The PipelineResult returned by BrainPipeline.run() or run_async().
        org_id:  Organisation identifier for multi-tenant isolation.
                 Defaults to "default" for single-tenant / dev environments.
    """
    try:
        from sqlalchemy import select

        from core.db.enterprise.session import DatabaseManager
        from core.db.models import PipelineRun

        row_data = _build_pipeline_run_row(result, org_id)

        async with DatabaseManager.get_session_context() as session:
            # Check for duplicate run_id (idempotent — re-submit is safe)
            existing = await session.execute(
                select(PipelineRun).where(PipelineRun.id == row_data["id"])
            )
            if existing.scalar_one_or_none() is not None:
                logger.debug(
                    "pipeline_run already persisted, skipping",
                    run_id=row_data["id"],
                )
                return True

            run = PipelineRun(**row_data)
            session.add(run)
            # session.commit() is called by get_session_context on exit

        logger.info(
            "pipeline_run persisted",
            run_id=result.run_id,
            org_id=org_id,
            status=row_data["status"],
            duration_ms=result.total_duration_ms,
        )
        return True

    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        # Never block the pipeline result on a DB write failure
        logger.warning(
            "pipeline_run persist failed — continuing without DB write",
            run_id=getattr(result, "run_id", "unknown"),
            error=f"{type(exc).__name__}: pipeline db write failed",
        )
        return False


# ---------------------------------------------------------------------------
# Sync wrapper (CLI / background thread path)
# ---------------------------------------------------------------------------

def persist_pipeline_run_sync(
    result: "PipelineResult",
    org_id: str = "default",
) -> bool:
    """
    Synchronous wrapper around ``persist_pipeline_run``.

    Uses asyncio.run() when no event loop is active (CLI context).
    When an event loop is already running (e.g. called from a thread pool
    task inside FastAPI), schedules a background task and returns True
    immediately without waiting for the write to complete.

    Returns True if the write was submitted successfully, False on error.
    Never raises.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        # No event loop — safe to call asyncio.run()
        try:
            return asyncio.run(persist_pipeline_run(result, org_id))
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            _fallback_logger.warning(
                "persist_pipeline_run_sync: asyncio.run failed: %s: pipeline db write failed",
                type(exc).__name__,
            )
            return False
    else:
        # Event loop is running — schedule as a fire-and-forget background task
        try:
            loop.create_task(persist_pipeline_run(result, org_id))
            return True
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            _fallback_logger.warning(
                "persist_pipeline_run_sync: create_task failed: %s: pipeline db write failed",
                type(exc).__name__,
            )
            return False


# ---------------------------------------------------------------------------
# Database health check helper
# ---------------------------------------------------------------------------

async def check_database_health() -> Dict[str, Any]:
    """
    Check enterprise database health.

    Returns a health dict compatible with the /api/v1/health/deep endpoint.
    Distinguishes between SQLite (local dev) and PostgreSQL (production).

    Never raises — all errors are caught and returned as an "unhealthy" status.
    """
    try:
        from config.enterprise.settings import get_settings

        from core.db.enterprise.session import DatabaseManager

        settings = get_settings()
        db_url = settings.DATABASE_URL
        is_postgres = "postgresql" in db_url

        # Ensure engine is initialised
        await DatabaseManager.initialize()

        is_healthy = await DatabaseManager.health_check()

        if not is_healthy:
            return {
                "status": "unhealthy",
                "backend": "postgresql" if is_postgres else "sqlite",
                "message": "SELECT 1 query failed",
            }

        result: Dict[str, Any] = {
            "status": "healthy",
            "backend": "postgresql" if is_postgres else "sqlite",
        }

        if is_postgres:
            # Expose pool stats for PostgreSQL
            try:
                engine = DatabaseManager._engine
                if engine is not None:
                    pool = engine.pool
                    result["pool"] = {
                        "size": getattr(pool, "size", lambda: None)(),
                        "checked_in": getattr(pool, "checkedin", lambda: None)(),
                        "checked_out": getattr(pool, "checkedout", lambda: None)(),
                        "overflow": getattr(pool, "overflow", lambda: None)(),
                    }
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass  # Pool stats are informational; don't fail health check
        else:
            # For SQLite: report file path and approximate size
            import os
            # Strip scheme prefix: sqlite+aiosqlite:///data/fixops.db → data/fixops.db
            db_path = db_url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")
            result["path"] = db_path
            if os.path.exists(db_path):
                size_bytes = os.path.getsize(db_path)
                result["size_bytes"] = size_bytes
                result["size_kb"] = round(size_bytes / 1024, 1)
                # Check WAL mode
                try:
                    import sqlite3 as _sqlite3
                    conn = _sqlite3.connect(db_path, timeout=3)
                    mode = conn.execute("PRAGMA journal_mode").fetchone()
                    conn.close()
                    result["journal_mode"] = mode[0] if mode else "unknown"
                except ImportError:
                    pass
            else:
                result["note"] = "database file not yet created"

        return result

    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        return {
            "status": "unhealthy",
            "error": f"{type(exc).__name__}: database health check failed",
        }


__all__ = [
    "persist_pipeline_run",
    "persist_pipeline_run_sync",
    "check_database_health",
]
