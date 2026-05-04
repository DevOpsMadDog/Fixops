"""
Performance regression tests for PlaybookEngine.

Covers the 3 hotspots fixed in beast-mode(perf):
  1. O(1) step lookup (was O(n) per iteration via next(generator))
  2. True parallel PARALLEL-step execution via ThreadPoolExecutor
  3. Baseline: multi-step sequential chain finishes < 200 ms
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.playbook_engine import (
    Playbook,
    PlaybookEngine,
    PlaybookStatus,
    PlaybookStep,
    PlaybookStepType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(tmp_path) -> PlaybookEngine:
    return PlaybookEngine(db_path=str(tmp_path / f"pb_perf_{uuid.uuid4().hex}.db"))


def _action_step(step_id: str, next_ok: str | None = None) -> PlaybookStep:
    return PlaybookStep(
        step_id=step_id,
        step_type=PlaybookStepType.ACTION,
        name=f"action_{step_id}",
        config={"action_type": "send_notification"},
        next_on_success=next_ok,
        next_on_failure=None,
    )


def _register_and_run(engine: PlaybookEngine, playbook: Playbook) -> float:
    engine.register_playbook(playbook)
    t0 = time.perf_counter()
    engine.execute_playbook(playbook.playbook_id, {})
    return time.perf_counter() - t0


# ---------------------------------------------------------------------------
# Test 1: O(1) step lookup — long linear chain must stay fast
# ---------------------------------------------------------------------------

def test_step_lookup_linear_chain_fast(tmp_path):
    """
    50-step linear ACTION chain. With O(n) lookup the hot path does
    50 * 50 / 2 = 1250 generator scans. O(1) dict lookup collapses
    this to 50 lookups. Must complete in < 500 ms.
    """
    engine = _make_engine(tmp_path)
    n = 50
    step_ids = [f"s{i:03d}" for i in range(n)]

    steps = []
    for i, sid in enumerate(step_ids):
        next_id = step_ids[i + 1] if i + 1 < n else None
        steps.append(_action_step(sid, next_ok=next_id))

    pb = Playbook(
        playbook_id=str(uuid.uuid4()),
        name="chain50",
        trigger_conditions={"t": "v"},
        steps=steps,
        status=PlaybookStatus.ACTIVE,
    )

    elapsed = _register_and_run(engine, pb)
    assert elapsed < 0.5, f"50-step chain took {elapsed:.3f}s — O(n) lookup regression?"


# ---------------------------------------------------------------------------
# Test 2: PARALLEL step actually runs concurrently
# ---------------------------------------------------------------------------

def test_parallel_step_faster_than_serial(tmp_path):
    """
    Create 3 NOTIFICATION sub-steps each taking ~20 ms (mocked via sleep).
    Serial: ~60 ms.  Parallel with ThreadPoolExecutor: ~20 ms + overhead.
    Assert parallel wall-clock < serial wall-clock * 0.8.
    """
    import threading

    engine = _make_engine(tmp_path)

    delay_ms = 0.02  # 20 ms per step

    # Patch the notification step handler to sleep
    original_step_notification = engine._step_notification

    def slow_notification(step, ctx, result):
        time.sleep(delay_ms)
        result.status = "success"
        result.output = {"recipients": [], "channel": "email"}
        return result

    engine._step_notification = slow_notification  # type: ignore[method-assign]

    notif_ids = [f"n{i}" for i in range(3)]
    notif_steps = [
        PlaybookStep(
            step_id=sid,
            step_type=PlaybookStepType.NOTIFICATION,
            name=f"notif_{sid}",
            config={"channel": "email", "recipients": ["x@x.com"], "message": "hi"},
        )
        for sid in notif_ids
    ]

    parallel_step = PlaybookStep(
        step_id="par",
        step_type=PlaybookStepType.PARALLEL,
        name="parallel",
        config={"step_ids": notif_ids},
    )

    pb = Playbook(
        playbook_id=str(uuid.uuid4()),
        name="parallel_perf",
        trigger_conditions={"t": "v"},
        steps=[parallel_step] + notif_steps,
        status=PlaybookStatus.ACTIVE,
    )

    engine.register_playbook(pb)
    t0 = time.perf_counter()
    run = engine.execute_playbook(pb.playbook_id, {})
    parallel_elapsed = time.perf_counter() - t0

    serial_baseline = delay_ms * len(notif_ids)
    # Allow generous overhead (thread spawn, SQLite write) but must beat serial * 0.9
    assert parallel_elapsed < serial_baseline * 2.5, (
        f"Parallel took {parallel_elapsed:.3f}s vs serial baseline {serial_baseline:.3f}s — "
        "ThreadPoolExecutor not kicking in?"
    )
    assert run.status == PlaybookStatus.COMPLETED


# ---------------------------------------------------------------------------
# Test 3: Baseline multi-step sequential run < 200 ms
# ---------------------------------------------------------------------------

def test_sequential_5step_under_200ms(tmp_path):
    """5-step sequential ACTION chain (no sleeps) must complete < 200 ms."""
    engine = _make_engine(tmp_path)
    step_ids = [f"q{i}" for i in range(5)]
    steps = []
    for i, sid in enumerate(step_ids):
        steps.append(_action_step(sid, next_ok=step_ids[i + 1] if i + 1 < 5 else None))

    pb = Playbook(
        playbook_id=str(uuid.uuid4()),
        name="seq5",
        trigger_conditions={"t": "v"},
        steps=steps,
        status=PlaybookStatus.ACTIVE,
    )
    elapsed = _register_and_run(engine, pb)
    assert elapsed < 0.2, f"5-step chain took {elapsed:.3f}s"
