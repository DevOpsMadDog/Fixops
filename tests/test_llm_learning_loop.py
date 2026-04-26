"""Tests for the LLM Learning Loop — Phase 1 closed-loop subscriber.

Covers:
1. opt-out when FIXOPS_LLM_LEARNING_LOOP env var unset (default-off behaviour)
2. subscribe-fires-callback   — emit on EventBus reaches the loop's handler
3. council-runs-on-event       — pipeline produces a verdict (deterministic
                                  fallback when no API keys present)
4. DPO-pair-persisted          — low-confidence verdicts insert a feedback_pair
5. decision-event-republished  — loop emits decision.made on the EventBus
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

# sitecustomize.py prepends suite paths; explicit fallback for CI safety.
ROOT = Path(__file__).resolve().parent.parent
for sub in ("suite-core", "suite-api"):
    candidate = ROOT / sub
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_dbs(tmp_path):
    """Per-test private TG + signals DBs and a fresh EventBus singleton."""
    tg_db = tmp_path / "phase1_trustgraph.db"
    signals_db = tmp_path / "learning_signals.db"

    # Reset the cross-suite event bus singleton between tests so subscriptions
    # don't leak across cases.
    from core.event_bus import EventBus

    EventBus.reset_instance()

    # Reset the loop module-level singleton too.
    from core import llm_learning_loop

    llm_learning_loop.stop_llm_learning_loop()

    yield {"tg_db": str(tg_db), "signals_db": str(signals_db)}

    llm_learning_loop.stop_llm_learning_loop()
    EventBus.reset_instance()


def _seed_finding_event(org_id: str = "test-org") -> object:
    """Build a realistic Event for finding.created."""
    from core.event_bus import Event, EventType

    return Event(
        event_type=EventType.FINDING_CREATED,
        source="test-suite",
        data={
            "finding_id": "VULN-TEST-001",
            "title": "SQL Injection in admin/user.update_view",
            "severity": "high",
            "cve_id": "CVE-2024-99999",
            "service_name": "django",
            "asset_criticality": "high",
        },
        org_id=org_id,
    )


# ---------------------------------------------------------------------------
# 1. Opt-out behaviour
# ---------------------------------------------------------------------------


def test_opt_out_when_env_unset(fresh_dbs, monkeypatch):
    """Without FIXOPS_LLM_LEARNING_LOOP=1, start returns None and no singleton."""
    monkeypatch.delenv("FIXOPS_LLM_LEARNING_LOOP", raising=False)
    from core.llm_learning_loop import (
        get_llm_learning_loop,
        start_llm_learning_loop,
    )

    handle = start_llm_learning_loop()
    assert handle is None
    assert get_llm_learning_loop() is None


# ---------------------------------------------------------------------------
# 2. Subscription wiring fires the callback
# ---------------------------------------------------------------------------


def test_subscribe_fires_callback(fresh_dbs, monkeypatch):
    """Emitting finding.created on the EventBus reaches the loop's handler."""
    monkeypatch.setenv("FIXOPS_LLM_LEARNING_LOOP", "1")
    monkeypatch.setenv("FIXOPS_LLM_LOOP_TG_DB", fresh_dbs["tg_db"])
    monkeypatch.setenv("FIXOPS_LLM_LOOP_SIGNALS_DB", fresh_dbs["signals_db"])

    from core.event_bus import get_event_bus
    from core.llm_learning_loop import start_llm_learning_loop

    loop = start_llm_learning_loop(force=True)
    assert loop is not None
    assert loop.status()["running"] is True

    bus = get_event_bus()
    # The loop subscribed under the EventType for finding.created
    from core.event_bus import EventType

    handlers = bus._subscribers.get(EventType.FINDING_CREATED.value, [])
    assert any(h.__qualname__.startswith("LLMLearningLoop._on_event") for h in handlers), (
        f"loop did not register for FINDING_CREATED — handlers={[h.__qualname__ for h in handlers]}"
    )


# ---------------------------------------------------------------------------
# 3. Council runs on event (deterministic fallback OK)
# ---------------------------------------------------------------------------


def test_council_runs_on_event(fresh_dbs, monkeypatch):
    """Emit one event; verify the loop processed it and incremented counters."""
    monkeypatch.setenv("FIXOPS_LLM_LEARNING_LOOP", "1")
    monkeypatch.setenv("FIXOPS_LLM_LOOP_TG_DB", fresh_dbs["tg_db"])
    monkeypatch.setenv("FIXOPS_LLM_LOOP_SIGNALS_DB", fresh_dbs["signals_db"])

    from core.event_bus import get_event_bus
    from core.llm_learning_loop import start_llm_learning_loop

    loop = start_llm_learning_loop(force=True)
    assert loop is not None

    before = loop.signals_summary()["verdicts"]

    bus = get_event_bus()

    async def _drive():
        await bus.emit(_seed_finding_event())

    asyncio.run(_drive())

    assert loop.status()["processed_events"] >= 1, loop.status()
    after = loop.signals_summary()["verdicts"]
    assert after == before + 1, (
        f"expected verdict count to increase by 1, before={before} after={after}"
    )


# ---------------------------------------------------------------------------
# 4. DPO pair persisted for low-confidence (deterministic fallback yields 0.0)
# ---------------------------------------------------------------------------


def test_dpo_pair_persisted(fresh_dbs, monkeypatch):
    """Deterministic council returns confidence < 0.75 → DPO pair must be inserted."""
    monkeypatch.setenv("FIXOPS_LLM_LEARNING_LOOP", "1")
    monkeypatch.setenv("FIXOPS_LLM_LOOP_TG_DB", fresh_dbs["tg_db"])
    monkeypatch.setenv("FIXOPS_LLM_LOOP_SIGNALS_DB", fresh_dbs["signals_db"])

    from core.event_bus import get_event_bus
    from core.llm_learning_loop import start_llm_learning_loop

    loop = start_llm_learning_loop(force=True)
    assert loop is not None

    pairs_before = loop.signals_summary()["pairs"]

    bus = get_event_bus()

    async def _drive():
        await bus.emit(_seed_finding_event(org_id="dpo-test"))

    asyncio.run(_drive())

    pairs_after = loop.signals_summary()["pairs"]
    assert pairs_after == pairs_before + 1, (
        f"expected DPO pair count to increase by 1, before={pairs_before} after={pairs_after}"
    )

    # Confirm the pair links back to a real verdict and uses the loop's source tag.
    conn = sqlite3.connect(fresh_dbs["signals_db"])
    try:
        row = conn.execute(
            """SELECT pair_source, chosen_action, rejected_action
               FROM feedback_pairs ORDER BY created_at DESC LIMIT 1"""
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    pair_source, chosen, rejected = row
    assert pair_source == "llm_learning_loop_low_confidence"
    assert chosen != rejected
    assert chosen and rejected


# ---------------------------------------------------------------------------
# 5. Decision event republished on the EventBus
# ---------------------------------------------------------------------------


def test_decision_event_republished(fresh_dbs, monkeypatch):
    """After the loop processes an event it must emit decision.made."""
    monkeypatch.setenv("FIXOPS_LLM_LEARNING_LOOP", "1")
    monkeypatch.setenv("FIXOPS_LLM_LOOP_TG_DB", fresh_dbs["tg_db"])
    monkeypatch.setenv("FIXOPS_LLM_LOOP_SIGNALS_DB", fresh_dbs["signals_db"])

    from core.event_bus import Event, EventType, get_event_bus
    from core.llm_learning_loop import start_llm_learning_loop

    loop = start_llm_learning_loop(force=True)
    assert loop is not None

    bus = get_event_bus()

    captured: list[Event] = []

    async def _capture(ev: Event) -> None:
        captured.append(ev)

    bus.subscribe(EventType.DECISION_MADE, _capture)

    async def _drive():
        await bus.emit(_seed_finding_event(org_id="republish-test"))
        # Give the dispatched republish a tick to land — emit() awaits handlers
        # in-line, but the capture is itself a handler that runs in the same
        # loop, so this is just defensive.
        await asyncio.sleep(0)

    asyncio.run(_drive())

    assert any(
        ev.source == "llm_learning_loop"
        and ev.data.get("finding_id") == "VULN-TEST-001"
        for ev in captured
    ), f"decision.made not republished. captured={[(e.source, e.data) for e in captured]}"
