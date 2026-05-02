"""Async task executor — unified dispatch interface.

Abstracts over Celery async execution and synchronous fallback.
Callers use ``execute_async()`` without caring whether Redis is available.

Usage:
    from core.async_executor import execute_async, get_task_status

    # Queue a brain pipeline run
    task = execute_async("brain_pipeline", org_id="acme", findings=[...])
    print(task.task_id)  # e.g. "b34f..."
    print(task.status)   # TaskStatus.PENDING (Celery) or SUCCESS (sync)

    # Poll status
    status = get_task_status(task.task_id)

Supported task names (first argument to execute_async):
    "brain_pipeline"  — runs BrainPipeline().run()
    "autofix"         — runs AutoFixEngine().generate_fix()
    "mpte"            — runs MicroPentestEngine().scan()

For unknown task names, raises ValueError immediately.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from core.task_queue import (
    TaskResult,
    dispatch_autofix_generate,
    dispatch_brain_pipeline,
    dispatch_mpte_scan,
    is_celery_available,
)
from core.task_queue import (
    get_task_status as _get_task_status,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def execute_async(task_name: str, **kwargs: Any) -> TaskResult:
    """Dispatch a named task, using Celery if available or sync otherwise.

    Args:
        task_name: One of "brain_pipeline", "autofix", "mpte".
        **kwargs:  Task-specific keyword arguments (see dispatch functions).

    Returns:
        TaskResult — immediately.  For Celery-backed tasks the result will
        be populated asynchronously; poll with get_task_status(task_id).

    Raises:
        ValueError: If task_name is unrecognised.
    """
    if task_name == "brain_pipeline":
        input_dict = kwargs.get("input_dict") or {
            k: v for k, v in kwargs.items() if k != "task_name"
        }
        return dispatch_brain_pipeline(input_dict)

    if task_name == "autofix":
        finding_id = kwargs.get("finding_id", "")
        org_id = kwargs.get("org_id", "")
        if not finding_id:
            raise ValueError("autofix task requires 'finding_id' kwarg")
        return dispatch_autofix_generate(finding_id=finding_id, org_id=org_id)

    if task_name == "mpte":
        target_url = kwargs.get("target_url", "")
        org_id = kwargs.get("org_id", "")
        if not target_url:
            raise ValueError("mpte task requires 'target_url' kwarg")
        return dispatch_mpte_scan(target_url=target_url, org_id=org_id)

    raise ValueError(
        f"Unknown task name: {task_name!r}. "
        "Valid names: 'brain_pipeline', 'autofix', 'mpte'"
    )


def get_task_status(task_id: str) -> TaskResult:
    """Return the current status of any dispatched task.

    Delegates to task_queue.get_task_status — checks in-memory sync store
    first, then Celery backend if available.

    Args:
        task_id: The task ID returned by execute_async().

    Returns:
        TaskResult with current status and result/error if complete.
    """
    return _get_task_status(task_id)


def celery_status() -> Dict[str, Any]:
    """Return a dict describing the current Celery / Redis availability."""
    available = is_celery_available()
    return {
        "celery_available": available,
        "mode": "async" if available else "sync",
        "note": (
            "Tasks are dispatched to Celery workers via Redis."
            if available
            else "Redis unavailable — tasks run synchronously (air-gap mode)."
        ),
    }
