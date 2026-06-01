"""AC-007-01 — TenantContext asyncio isolation test.

Proves that two interleaved asyncio Tasks each keep their own org_id
and never see the other task's value.  This test would FAIL if
TenantContext used threading.local (the old bug) because both coroutines
run on the same OS thread.  With ContextVar each Task inherits an
independent copy of the context snapshot.

Run:
    PYTHONPATH=.:suite-api:suite-core:suite-attack:suite-feeds:suite-integrations:suite-evidence-risk:archive/legacy:archive/enterprise_legacy \
    python -m pytest tests/test_tenant_context_asyncio.py -v
"""
from __future__ import annotations

import asyncio
import sys
import os

import pytest

# Ensure suite-core is on path when run directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.tenant_isolation import TenantContext, _tenant_org_id_var


# ---------------------------------------------------------------------------
# Core correctness: two concurrent tasks must never see each other's org
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_interleaved_tasks_keep_separate_org_ids():
    """Two tasks that overlap in time each read back their OWN org_id."""
    results: dict[str, str | None] = {}

    async def task_a() -> None:
        TenantContext.set("org-alpha")
        await asyncio.sleep(0)          # yield — task_b runs here
        results["a"] = TenantContext.get()

    async def task_b() -> None:
        TenantContext.set("org-beta")
        await asyncio.sleep(0)          # yield — task_a may resume
        results["b"] = TenantContext.get()

    await asyncio.gather(
        asyncio.ensure_future(task_a()),
        asyncio.ensure_future(task_b()),
    )

    assert results["a"] == "org-alpha", (
        f"Task-A saw wrong org: {results['a']!r} — threading.local bleed?"
    )
    assert results["b"] == "org-beta", (
        f"Task-B saw wrong org: {results['b']!r} — threading.local bleed?"
    )


@pytest.mark.asyncio
async def test_set_in_one_task_does_not_affect_parent_context():
    """A child task's set() must not mutate the parent task's context."""
    TenantContext.set("parent-org")

    async def child() -> None:
        TenantContext.set("child-org")
        await asyncio.sleep(0)

    await asyncio.ensure_future(child())

    # Parent still sees its own org (ContextVar copy-on-write semantics)
    assert TenantContext.get() == "parent-org", (
        f"Parent context was mutated by child task: {TenantContext.get()!r}"
    )


@pytest.mark.asyncio
async def test_clear_only_affects_current_task():
    """clear() in one task must not clear another task's org_id."""
    done_event = asyncio.Event()
    cleared_event = asyncio.Event()
    results: dict[str, str | None] = {}

    async def task_holds() -> None:
        TenantContext.set("holder-org")
        cleared_event.set()             # signal: we've set our org
        await done_event.wait()         # wait for the other task to clear
        results["holder"] = TenantContext.get()

    async def task_clears() -> None:
        await cleared_event.wait()      # wait until holder has set its org
        TenantContext.set("clearer-org")
        TenantContext.clear()           # clear THIS task's org
        done_event.set()

    await asyncio.gather(
        asyncio.ensure_future(task_holds()),
        asyncio.ensure_future(task_clears()),
    )

    assert results["holder"] == "holder-org", (
        f"holder-org was cleared by another task: {results['holder']!r}"
    )


@pytest.mark.asyncio
async def test_token_reset_restores_previous_value():
    """set() returns a Token; reset(token) restores the previous value."""
    TenantContext.set("before")
    token = TenantContext.set("during")
    assert TenantContext.get() == "during"

    _tenant_org_id_var.reset(token)
    assert TenantContext.get() == "before", (
        f"reset(token) did not restore previous org: {TenantContext.get()!r}"
    )


@pytest.mark.asyncio
async def test_many_concurrent_tasks_no_cross_bleed():
    """20 concurrent tasks, each with a unique org — no bleed."""
    n = 20
    results: dict[int, str | None] = {}

    async def worker(idx: int) -> None:
        org = f"tenant-{idx:03d}"
        TenantContext.set(org)
        # Multiple yields to maximise interleaving
        for _ in range(3):
            await asyncio.sleep(0)
        results[idx] = TenantContext.get()

    await asyncio.gather(*[asyncio.ensure_future(worker(i)) for i in range(n)])

    for i in range(n):
        expected = f"tenant-{i:03d}"
        assert results[i] == expected, (
            f"Task {i} saw {results[i]!r} instead of {expected!r} — cross-bleed detected"
        )


# ---------------------------------------------------------------------------
# Regression: synchronous usage still works (callers that do not use asyncio)
# ---------------------------------------------------------------------------

def test_sync_set_get_clear():
    """Synchronous set/get/clear still works correctly (backward compat)."""
    TenantContext.set("sync-org")
    assert TenantContext.get() == "sync-org"
    TenantContext.clear()
    assert TenantContext.get() is None


def test_get_returns_none_when_not_set():
    """get() returns None (not 'default') when no org has been set in this context."""
    TenantContext.clear()
    val = TenantContext.get()
    assert val is None, f"Expected None, got {val!r}"
