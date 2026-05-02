"""Celery task queue for async pipeline execution.

Wraps BrainPipeline, AutoFix, and MPTE as Celery tasks.
Falls back to synchronous execution if Redis is unavailable (air-gap mode).

Design:
  - All tasks are registered with max_retries=2 and default_retry_delay=30s.
  - is_celery_available() pings Redis before dispatching — if it fails, execution
    drops through to synchronous mode transparently.
  - The Celery app is created lazily on first import to avoid import-time
    side-effects when Redis is absent (e.g. CI, air-gap deployments).

Environment variables:
  FIXOPS_REDIS_URL  — default: redis://localhost:6379/0
  FIXOPS_REDIS_PASSWORD — optional password
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDIS_URL: str = os.getenv("FIXOPS_REDIS_URL", "redis://localhost:6379/0")
REDIS_PASSWORD: str = os.getenv("FIXOPS_REDIS_PASSWORD", "")

TASK_MAX_RETRIES: int = 2
TASK_RETRY_DELAY: int = 30  # seconds


# ---------------------------------------------------------------------------
# TaskResult — returned by execute_async
# ---------------------------------------------------------------------------


class TaskStatus(str, Enum):
    PENDING = "pending"
    STARTED = "started"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRY = "retry"


@dataclass
class TaskResult:
    """Thin wrapper around a Celery AsyncResult or synchronous result."""

    task_id: str
    status: TaskStatus
    result: Any = None          # populated when status == SUCCESS
    error: Optional[str] = None  # populated when status == FAILURE
    queued_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    celery_backed: bool = False  # True if dispatched to Celery, False = sync ran inline

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "queued_at": self.queued_at,
            "celery_backed": self.celery_backed,
        }


# ---------------------------------------------------------------------------
# In-memory result store (used in synchronous / no-Redis mode)
# ---------------------------------------------------------------------------

_sync_results: Dict[str, TaskResult] = {}
_sync_results_lock = threading.Lock()


def _store_sync_result(task_result: TaskResult) -> None:
    with _sync_results_lock:
        _sync_results[task_result.task_id] = task_result


# ---------------------------------------------------------------------------
# Redis availability check
# ---------------------------------------------------------------------------

# Cache the availability check result for 30 seconds to avoid hammering Redis
_celery_available_cache: Optional[bool] = None
_celery_available_checked_at: float = 0.0
_CACHE_TTL: float = 30.0

# Module-level Celery app — initialised lazily via _get_celery_app()
_celery_app: Any = None
_celery_app_lock = threading.Lock()


def _get_celery_app() -> Any:
    """Return the Celery app — RETIRED 2026-05-03.

    # celery — RETIRED 2026-05-03 per
    # docs/suite_core_install_retire_decisions_2026-05-03.md
    # Project explicitly uses in-process queues (CLAUDE.md). The Celery branch
    # is dead. Always returns ``None`` so downstream callers route through the
    # synchronous fallback paths (``_run_sync_*``) that ship today.
    """
    return None


def is_celery_available() -> bool:
    """Ping Redis to check if the Celery broker is reachable.

    Result is cached for 30 seconds to avoid connection overhead on every call.
    Returns False immediately if Celery is not installed.
    """
    global _celery_available_cache, _celery_available_checked_at

    now = time.monotonic()
    if _celery_available_cache is not None and (now - _celery_available_checked_at) < _CACHE_TTL:
        return _celery_available_cache

    app = _get_celery_app()
    if app is None:
        _celery_available_cache = False
        _celery_available_checked_at = now
        return False

    try:
        conn = app.connection_for_write()
        conn.connect()
        conn.release()
        _celery_available_cache = True
        logger.debug("Celery broker reachable: %s", REDIS_URL)
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        _celery_available_cache = False
        logger.debug("Celery broker unreachable (%s) — will run synchronously", exc)

    _celery_available_checked_at = now
    return bool(_celery_available_cache)


# ---------------------------------------------------------------------------
# Celery task definitions
# ---------------------------------------------------------------------------


def _register_tasks(app: Any) -> None:
    """Register all Celery tasks on the given app instance.

    Called once when the app is first used. We register lazily so the module
    can be imported without Redis being available (air-gap safety).
    """

    @app.task(
        name="fixops.brain_run_pipeline",
        bind=True,
        max_retries=TASK_MAX_RETRIES,
        default_retry_delay=TASK_RETRY_DELAY,
        serializer="json",
    )
    def brain_run_pipeline(self, input_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Run the BrainPipeline on a serialised PipelineInput dict.

        Args:
            input_dict: Serialised PipelineInput (org_id, findings, assets, …)

        Returns:
            Serialised PipelineResult as dict.
        """
        try:
            from core.brain_pipeline import BrainPipeline, PipelineInput

            inp = PipelineInput(**{
                k: v for k, v in input_dict.items()
                if k in PipelineInput.__dataclass_fields__
            })
            pipeline = BrainPipeline()
            result = pipeline.run(inp)
            return result.__dict__ if hasattr(result, "__dict__") else {"status": "completed"}
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("brain_run_pipeline task failed: %s", exc)
            raise self.retry(exc=exc)

    @app.task(
        name="fixops.autofix_generate",
        bind=True,
        max_retries=TASK_MAX_RETRIES,
        default_retry_delay=TASK_RETRY_DELAY,
        serializer="json",
    )
    def autofix_generate(self, finding_id: str, org_id: str) -> Dict[str, Any]:
        """Generate an AutoFix for a single finding.

        Args:
            finding_id: The finding ID to fix.
            org_id:     The organisation ID.

        Returns:
            AutoFix result dict.
        """
        try:
            from core.autofix_engine import AutoFixEngine

            engine = AutoFixEngine()
            result = engine.generate_fix(finding_id=finding_id, org_id=org_id)
            return result if isinstance(result, dict) else {"result": str(result)}
        except ImportError as exc:
            logger.exception("autofix_generate task failed (finding=%s): %s", finding_id, exc)
            raise self.retry(exc=exc)

    @app.task(
        name="fixops.mpte_scan",
        bind=True,
        max_retries=TASK_MAX_RETRIES,
        default_retry_delay=TASK_RETRY_DELAY,
        serializer="json",
    )
    def mpte_scan(self, target_url: str, org_id: str) -> Dict[str, Any]:
        """Run a micro-pentest against a target URL.

        Args:
            target_url: The URL / endpoint to test.
            org_id:     The organisation ID.

        Returns:
            MicroPenTest result dict.
        """
        # REMOVED — ``core.micro_pentest.MicroPentestEngine`` no longer exists
        # (2026-05-03 silenced-imports audit). The module exposes
        # ``MicroPentestConfig``/``Result``/``Status`` + functional helpers,
        # not an Engine class. Celery branch raises ImportError so callers
        # receive an honest error instead of the broad-Exception silent miss.
        exc = ImportError(
            "core.micro_pentest.MicroPentestEngine no longer exists "
            "(2026-05-03 audit). Wire to MPTE router or reintroduce engine class."
        )
        logger.exception("mpte_scan task failed (target=%s): %s", target_url, exc)
        raise self.retry(exc=exc)

    # Expose on app so callers can access via _get_celery_app().tasks[name]
    app.brain_run_pipeline = brain_run_pipeline
    app.autofix_generate = autofix_generate
    app.mpte_scan = mpte_scan


_tasks_registered = False
_tasks_lock = threading.Lock()


def _ensure_tasks_registered() -> Any:
    """Return the Celery app with tasks registered, or None."""
    global _tasks_registered
    app = _get_celery_app()
    if app is None:
        return None
    if not _tasks_registered:
        with _tasks_lock:
            if not _tasks_registered:
                _register_tasks(app)
                _tasks_registered = True
    return app


# ---------------------------------------------------------------------------
# Public task dispatch functions
# ---------------------------------------------------------------------------


def dispatch_brain_pipeline(input_dict: Dict[str, Any]) -> TaskResult:
    """Dispatch a BrainPipeline run.

    If Celery is available, queues asynchronously.
    Otherwise runs synchronously and returns a completed TaskResult.
    """
    task_id = str(uuid.uuid4())
    if is_celery_available():
        app = _ensure_tasks_registered()
        if app is not None:
            try:
                async_res = app.send_task(
                    "fixops.brain_run_pipeline",
                    kwargs={"input_dict": input_dict},
                    task_id=task_id,
                )
                tr = TaskResult(
                    task_id=async_res.id,
                    status=TaskStatus.PENDING,
                    celery_backed=True,
                )
                logger.info("brain_run_pipeline queued: task_id=%s", tr.task_id)
                return tr
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                logger.warning("Celery dispatch failed, falling back to sync: %s", exc)

    # Synchronous fallback
    return _run_sync_brain_pipeline(task_id, input_dict)


def dispatch_autofix_generate(finding_id: str, org_id: str) -> TaskResult:
    """Dispatch an AutoFix generation task."""
    task_id = str(uuid.uuid4())
    if is_celery_available():
        app = _ensure_tasks_registered()
        if app is not None:
            try:
                async_res = app.send_task(
                    "fixops.autofix_generate",
                    kwargs={"finding_id": finding_id, "org_id": org_id},
                    task_id=task_id,
                )
                tr = TaskResult(
                    task_id=async_res.id,
                    status=TaskStatus.PENDING,
                    celery_backed=True,
                )
                logger.info("autofix_generate queued: task_id=%s finding=%s", tr.task_id, finding_id)
                return tr
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                logger.warning("Celery dispatch failed, falling back to sync: %s", exc)

    return _run_sync_autofix_generate(task_id, finding_id, org_id)


def dispatch_mpte_scan(target_url: str, org_id: str) -> TaskResult:
    """Dispatch an MPTE scan task."""
    task_id = str(uuid.uuid4())
    if is_celery_available():
        app = _ensure_tasks_registered()
        if app is not None:
            try:
                async_res = app.send_task(
                    "fixops.mpte_scan",
                    kwargs={"target_url": target_url, "org_id": org_id},
                    task_id=task_id,
                )
                tr = TaskResult(
                    task_id=async_res.id,
                    status=TaskStatus.PENDING,
                    celery_backed=True,
                )
                logger.info("mpte_scan queued: task_id=%s target=%s", tr.task_id, target_url)
                return tr
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                logger.warning("Celery dispatch failed, falling back to sync: %s", exc)

    return _run_sync_mpte_scan(task_id, target_url, org_id)


# ---------------------------------------------------------------------------
# Synchronous fallback implementations
# ---------------------------------------------------------------------------


def _run_sync_brain_pipeline(task_id: str, input_dict: Dict[str, Any]) -> TaskResult:
    logger.info("brain_run_pipeline running synchronously: task_id=%s", task_id)
    tr = TaskResult(task_id=task_id, status=TaskStatus.STARTED, celery_backed=False)
    _store_sync_result(tr)
    try:
        from core.brain_pipeline import BrainPipeline, PipelineInput

        inp = PipelineInput(**{
            k: v for k, v in input_dict.items()
            if k in PipelineInput.__dataclass_fields__
        })
        pipeline = BrainPipeline()
        result = pipeline.run(inp)
        tr.result = result.__dict__ if hasattr(result, "__dict__") else {"status": "completed"}
        tr.status = TaskStatus.SUCCESS
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Sync brain_run_pipeline failed: %s", exc)
        tr.status = TaskStatus.FAILURE
        tr.error = str(exc)
    _store_sync_result(tr)
    return tr


def _run_sync_autofix_generate(task_id: str, finding_id: str, org_id: str) -> TaskResult:
    logger.info("autofix_generate running synchronously: task_id=%s finding=%s", task_id, finding_id)
    tr = TaskResult(task_id=task_id, status=TaskStatus.STARTED, celery_backed=False)
    _store_sync_result(tr)
    try:
        from core.autofix_engine import AutoFixEngine

        engine = AutoFixEngine()
        result = engine.generate_fix(finding_id=finding_id, org_id=org_id)
        tr.result = result if isinstance(result, dict) else {"result": str(result)}
        tr.status = TaskStatus.SUCCESS
    except ImportError as exc:
        logger.exception("Sync autofix_generate failed (finding=%s): %s", finding_id, exc)
        tr.status = TaskStatus.FAILURE
        tr.error = str(exc)
    _store_sync_result(tr)
    return tr


def _run_sync_mpte_scan(task_id: str, target_url: str, org_id: str) -> TaskResult:
    logger.info("mpte_scan running synchronously: task_id=%s target=%s", task_id, target_url)
    tr = TaskResult(task_id=task_id, status=TaskStatus.STARTED, celery_backed=False)
    _store_sync_result(tr)
    # REMOVED — ``core.micro_pentest.MicroPentestEngine`` no longer exists
    # (2026-05-03 silenced-imports audit). Sync path now reports a structured
    # FAILURE with the canonical reason instead of pretending an Engine
    # import will succeed.
    exc = ImportError(
        "core.micro_pentest.MicroPentestEngine no longer exists (2026-05-03 audit)"
    )
    logger.exception("Sync mpte_scan failed (target=%s): %s", target_url, exc)
    tr.status = TaskStatus.FAILURE
    tr.error = str(exc)
    _ = org_id  # signature preserved for downstream callers
    _store_sync_result(tr)
    return tr


# ---------------------------------------------------------------------------
# get_task_status — checks Celery backend OR in-memory sync store
# ---------------------------------------------------------------------------


def get_task_status(task_id: str) -> TaskResult:
    """Return the current status of a task.

    Checks:
      1. In-memory synchronous result store (populated for sync runs)
      2. Celery result backend (if Celery is available)
    """
    # Check sync store first
    with _sync_results_lock:
        if task_id in _sync_results:
            return _sync_results[task_id]

    # Check Celery backend
    if is_celery_available():
        app = _ensure_tasks_registered()
        if app is not None:
            try:
                from celery.result import AsyncResult  # type: ignore[import]

                ar = AsyncResult(task_id, app=app)
                celery_state = ar.state

                STATUS_MAP = {
                    "PENDING": TaskStatus.PENDING,
                    "STARTED": TaskStatus.STARTED,
                    "SUCCESS": TaskStatus.SUCCESS,
                    "FAILURE": TaskStatus.FAILURE,
                    "RETRY": TaskStatus.RETRY,
                    "REVOKED": TaskStatus.FAILURE,
                }
                status = STATUS_MAP.get(celery_state, TaskStatus.PENDING)
                result_val = None
                error_val = None

                if celery_state == "SUCCESS":
                    result_val = ar.result
                elif celery_state == "FAILURE":
                    error_val = str(ar.result)

                return TaskResult(
                    task_id=task_id,
                    status=status,
                    result=result_val,
                    error=error_val,
                    celery_backed=True,
                )
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                logger.debug("Celery status check failed for task %s: %s", task_id, exc)

    # Unknown
    return TaskResult(
        task_id=task_id,
        status=TaskStatus.PENDING,
        error="Task not found — may have expired or never been created",
    )


# ---------------------------------------------------------------------------
# Expose a ready-to-use celery_app at module level (may be None)
# ---------------------------------------------------------------------------

celery_app = _get_celery_app()
