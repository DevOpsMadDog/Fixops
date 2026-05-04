"""tests/test_memory_caps.py — Memory-cap regression tests.

Verifies that module-level caches in sse_router remain bounded under
high cardinality org_id load (prevents OOM in long-running processes).

We import sse_router directly (sitecustomize.py puts suite-api on sys.path).
Each test resets the three module-level dicts to a clean OrderedDict so
tests are independent even when run in the same process.
"""
from __future__ import annotations

from collections import OrderedDict

import apps.api.sse_router as sse


def _reset_sse_state() -> None:
    """Reset the three module-level caches to empty OrderedDicts."""
    sse._event_store.clear()
    sse._event_counter.clear()
    sse._org_conditions.clear()


class TestSSERouterOrgCaps:
    """_event_store, _event_counter, _org_conditions must not exceed _MAX_ORGS."""

    def test_event_store_capped(self):
        _reset_sse_state()
        cap = sse._MAX_ORGS

        for i in range(cap + 50):
            sse.publish_event(f"org-{i}", "alert", {"x": i})

        assert len(sse._event_store) <= cap, (
            f"_event_store grew to {len(sse._event_store)}, expected <= {cap}"
        )

    def test_event_counter_capped(self):
        _reset_sse_state()
        cap = sse._MAX_ORGS

        for i in range(cap + 50):
            sse.publish_event(f"org-{i}", "alert", {"x": i})

        assert len(sse._event_counter) <= cap, (
            f"_event_counter grew to {len(sse._event_counter)}, expected <= {cap}"
        )

    def test_org_conditions_capped(self):
        _reset_sse_state()
        cap = sse._MAX_ORGS

        for i in range(cap + 50):
            sse._get_condition(f"org-{i}")

        assert len(sse._org_conditions) <= cap, (
            f"_org_conditions grew to {len(sse._org_conditions)}, expected <= {cap}"
        )

    def test_per_org_event_list_still_ring_buffered(self):
        """Per-org event list must never exceed _MAX_EVENTS regardless of cap logic."""
        _reset_sse_state()
        max_ev = sse._MAX_EVENTS

        for i in range(max_ev + 200):
            sse.publish_event("org-single", "alert", {"seq": i})

        store = sse._event_store.get("org-single", [])
        assert len(store) <= max_ev, (
            f"per-org event list grew to {len(store)}, expected <= {max_ev}"
        )

    def test_lru_eviction_order(self):
        """Most-recently-used org survives eviction; oldest must be gone."""
        _reset_sse_state()
        cap = sse._MAX_ORGS

        # Fill to exactly cap
        for i in range(cap):
            sse.publish_event(f"org-{i}", "alert", {"x": i})

        # Adding one more org should evict org-0 (the LRU)
        sse.publish_event("org-newest", "alert", {"x": 999})

        assert "org-newest" in sse._event_store, "Newest org must be present"
        assert "org-0" not in sse._event_store, "Oldest org must have been evicted"
