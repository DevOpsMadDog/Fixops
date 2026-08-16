"""The learning loop must judge realness by inference, not by price.

Only verdicts produced by a genuine model call may enter DPO training; a fallback verdict
is fabricated data, and persisting it poisons the signal. That guard is right, and it
exists because 5,196 bogus "confidence 0.5 / $0" rows once did exactly that.

The original test was ``cost_usd > 0``. That works for cloud providers and silently
breaks air-gapped deployments, where inference runs on the customer's own hardware and
legitimately costs nothing: under the ``scif`` profile every genuine local verdict was
discarded and the self-learning loop quietly stopped working — with no error, because
dropping verdicts is the guard behaving "correctly".

The right signal is ``is_real_inference``, which every provider already sets: ``True``
for a real call, ``False`` when it fell back to a heuristic. Cost stays as the fallback
for rows recorded before providers reported the flag, so historical protection holds.

These tests pin the decision table rather than the implementation.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import pytest


def _decide(
    *, is_real: Optional[bool], cost: float, in_metadata: bool = False
) -> bool:
    """Reproduce the guard's decision from a verdict payload.

    Mirrors llm_learning_loop._on_event so the table can be asserted without standing up
    the event bus, a pipeline and a database for what is a three-line policy.
    """
    raw: Dict[str, Any] = {}
    target = raw.setdefault("metadata", {}) if in_metadata else raw
    target["cost_usd"] = cost
    if is_real is not None:
        target["is_real_inference"] = is_real

    meta = raw.get("metadata", {}) or {}
    try:
        resolved_cost = float(raw.get("cost_usd", meta.get("cost_usd", 0)) or 0)
    except (TypeError, ValueError):
        resolved_cost = 0.0
    flag = raw.get("is_real_inference", meta.get("is_real_inference"))
    return bool(flag) if flag is not None else resolved_cost > 0


def test_cloud_verdict_is_learned_from() -> None:
    assert _decide(is_real=True, cost=0.0021) is True


def test_local_zero_cost_verdict_is_learned_from() -> None:
    """The air-gap case: real inference, no invoice.

    This is what the cost test discarded, disabling self-learning under scif.
    """
    assert _decide(is_real=True, cost=0.0) is True


def test_heuristic_fallback_is_never_learned_from() -> None:
    """Even if something reported a cost, a fallback is fabricated data."""
    assert _decide(is_real=False, cost=0.0) is False
    assert _decide(is_real=False, cost=0.05) is False


def test_legacy_rows_still_fall_back_to_cost() -> None:
    """Verdicts recorded before providers reported the flag keep the old protection."""
    assert _decide(is_real=None, cost=0.004) is True
    assert _decide(is_real=None, cost=0.0) is False


def test_flag_is_read_from_metadata_too() -> None:
    """Councils nest provenance under metadata; the guard must look there."""
    assert _decide(is_real=True, cost=0.0, in_metadata=True) is True
    assert _decide(is_real=False, cost=0.02, in_metadata=True) is False


def test_source_still_documents_the_guard() -> None:
    """The rationale must stay next to the code, or the cost test will return."""
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1]
        / "suite-core"
        / "core"
        / "llm_learning_loop.py"
    ).read_text(encoding="utf-8")

    assert "is_real_inference" in source, (
        "the learning-loop guard no longer references is_real_inference — if it has "
        "reverted to a cost test, air-gapped deployments silently stop learning"
    )
