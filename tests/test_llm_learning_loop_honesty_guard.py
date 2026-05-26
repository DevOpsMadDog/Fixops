"""US-003: the learning loop must NEVER persist a non-real (cost_usd<=0) verdict.

This is the structural guard that prevents the failure that produced 5,196
fabricated "$0 / confidence 0.5" placeholder rows. Only verdicts from a genuine
LLM call (cost_usd > 0) may become a learning signal.
"""
from __future__ import annotations

import sqlite3
import types

import pytest

from core.llm_learning_loop import LLMLearningLoop


def _count_verdicts(db_path: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM council_verdicts").fetchone()[0]
    finally:
        conn.close()


def _make_loop(tmp_path, cost_usd: float):
    loop = LLMLearningLoop(signals_db_path=str(tmp_path / "signals.db"))
    loop._running = True

    # Controlled verdict — vary only cost_usd
    def _fake_pipeline(finding, org_id):
        return {
            "rag_block": "[PRIOR DECISIONS]",
            "raw_verdict": {
                "action": "remediate_critical",
                "confidence": 0.9,
                "reasoning": "real-looking reasoning",
                "cost_usd": cost_usd,
            },
        }

    loop._run_pipeline_blocking = _fake_pipeline  # type: ignore[assignment]

    async def _noop_republish(*a, **k):
        return None

    loop._republish_decision = _noop_republish  # type: ignore[assignment]
    return loop


def _event():
    return types.SimpleNamespace(
        event_type="finding.created",
        data={"finding_id": "f-test-1", "title": "SQLi", "severity": "critical", "org_id": "org-x"},
        org_id="org-x",
    )


@pytest.mark.asyncio
async def test_zero_cost_verdict_is_not_persisted(tmp_path):
    """A $0 verdict (deterministic/placeholder fallback) must NOT enter the learning signal."""
    loop = _make_loop(tmp_path, cost_usd=0.0)
    await loop._on_event(_event())
    assert _count_verdicts(loop.signals_db_path) == 0


@pytest.mark.asyncio
async def test_real_cost_verdict_is_persisted(tmp_path):
    """A real verdict (cost_usd > 0) IS persisted as a learning signal."""
    loop = _make_loop(tmp_path, cost_usd=0.0019)
    await loop._on_event(_event())
    assert _count_verdicts(loop.signals_db_path) == 1
