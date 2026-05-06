"""Tests for composite_risk_router GET / (risk_index) fix — Multica #4030.

Verifies that GET /api/v1/risk/ no longer calls the undefined _get_engine()
(NameError) and returns a valid envelope.
"""
from __future__ import annotations

import pytest


def test_risk_index_no_name_error():
    """risk_index must not raise NameError from _get_engine() call.

    Before the fix, the function called _get_engine() which didn't exist in
    composite_risk_router.py, causing a NameError at runtime. Now it calls
    _get_scorer() via the _HAS_SCORER guard.
    """
    import inspect
    from apps.api.composite_risk_router import risk_index
    src = inspect.getsource(risk_index)
    assert "_get_engine" not in src, (
        "risk_index still references _get_engine() which is undefined — fix not applied"
    )
    assert "_get_scorer" in src or "_HAS_SCORER" in src, (
        "risk_index must use _get_scorer() / _HAS_SCORER after the fix"
    )


def test_risk_index_returns_valid_envelope():
    """risk_index coroutine returns a dict with required keys when scorer unavailable."""
    import asyncio
    from unittest.mock import patch

    from apps.api import composite_risk_router as crm

    async def _run():
        # Patch _HAS_SCORER=False so we get the fast path (no DB needed)
        with patch.object(crm, "_HAS_SCORER", False), \
             patch.object(crm, "_get_scorer", None):
            # get_org_id normally comes from a Request header; pass "default" directly
            result = await crm.risk_index(org_id="default")
        return result

    result = asyncio.get_event_loop().run_until_complete(_run())
    assert isinstance(result, dict)
    assert result.get("router") == "risk"
    assert "items" in result
    assert "count" in result
    assert result["count"] == len(result["items"])
