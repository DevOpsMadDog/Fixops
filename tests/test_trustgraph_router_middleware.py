"""
Smoke tests for the broadened ResponseInterceptorMiddleware ID-extraction.

These tests synthesize representative POST/PUT/PATCH responses from
wave A/B/C/D-style routers (policies, connectors/mapping, findings,
risk/quantify-fair, easm/seed-domain) and assert that the middleware
extracts the correct entity IDs even when wrapped in nested envelopes
like {"data": {...}}, {"result": {...}}, {"items": [...]}.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_capturing_bus() -> Tuple[Any, List[Tuple[str, Dict[str, Any]]]]:
    """Build a fresh EventBus that captures every emit into a list.

    Returns (bus, captured) where ``captured`` is a list populated by
    every handler invocation as (event_type, payload) tuples.
    """
    import core.trustgraph_event_bus as eb_mod

    eb_mod._bus_instance = None  # reset singleton to avoid cross-test bleed
    from core.trustgraph_event_bus import (
        ALL_EVENT_TYPES,
        EventBus,
    )

    bus = EventBus(enabled=True)
    captured: List[Tuple[str, Dict[str, Any]]] = []

    # Register a capture handler for every known event type so any
    # extracted ID lands in `captured`.
    for evt in ALL_EVENT_TYPES:
        async def _capture(payload: Dict[str, Any], _evt: str = evt) -> bool:
            captured.append((_evt, payload))
            return True

        bus.on(evt, _capture)

    return bus, captured


def _build_app(bus: Any) -> FastAPI:
    """Stand up a small FastAPI app emulating wave A/B/C/D endpoint shapes."""
    from core.trustgraph_event_bus import ResponseInterceptorMiddleware

    app = FastAPI()
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)

    # 1) Wave A — code intel/policies (flat shape, "policy_id" at root).
    @app.post("/api/v1/policies")
    async def create_policy() -> Dict[str, Any]:
        return {"policy_id": "pol-001", "name": "blocker-on-critical"}

    # 2) Wave B — connectors/mapping (nested under "data").
    @app.post("/api/v1/connectors/mapping")
    async def create_mapping() -> Dict[str, Any]:
        return {"data": {"mapping_id": "map-77", "source": "jira"}}

    # 3) Findings batch (list under "items").
    @app.post("/api/v1/findings/batch")
    async def create_findings() -> Dict[str, Any]:
        return {
            "items": [
                {"finding_id": "f-001", "engine": "sast"},
                {"finding_id": "f-002", "engine": "sast"},
            ]
        }

    # 4) Wave C — risk/quantify-fair (custom q_id key).
    @app.post("/api/v1/risk/quantify-fair")
    async def quantify_fair() -> Dict[str, Any]:
        return {"result": {"q_id": "q-42", "ale": 1234567.89}}

    # 5) Wave D — easm/seed-domain (custom domain key).
    @app.post("/api/v1/easm/seed-domain")
    async def seed_domain() -> Dict[str, Any]:
        return {"data": {"seed_id": "s-9", "domain": "example.com"}}

    # 6) Wave A — wrapped scan response (scan_id under payload).
    @app.post("/api/v1/scans")
    async def create_scan() -> Dict[str, Any]:
        return {"payload": {"scan_id": "scan-2024-01"}}

    # 7) Tenant onboarding (correlation_id at root).
    @app.post("/api/v1/orgs")
    async def create_org() -> Dict[str, Any]:
        return {"correlation_id": "corr-abc", "tenant_id": "t-123"}

    # 8) PUT update (update event for an existing finding under wrapper).
    @app.put("/api/v1/findings/{fid}")
    async def update_finding(fid: str) -> Dict[str, Any]:
        return {"data": {"finding_id": fid, "status": "triaged"}}

    # 9) PATCH on a control (control_id at root).
    @app.patch("/api/v1/controls/{cid}")
    async def patch_control(cid: str) -> Dict[str, Any]:
        return {"control_id": cid, "status": "passing"}

    # 10) Evidence collection (digest deeply nested).
    @app.post("/api/v1/evidence")
    async def create_evidence() -> Dict[str, Any]:
        return {"data": {"items": [{"digest": "sha256:abc", "evidence_id": "e-1"}]}}

    return app


def _wait_for_emits(captured: List, expected: int, timeout_s: float = 1.0) -> None:
    """Poll until at least ``expected`` events captured or timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline and len(captured) < expected:
        time.sleep(0.01)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_middleware_emits_for_flat_policy_response():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    resp = client.post("/api/v1/policies")
    assert resp.status_code == 200

    _wait_for_emits(captured, 1)
    types = [evt for evt, _ in captured]
    assert "policy.updated" in types
    payloads = [p for _, p in captured if "policy_id" in p]
    assert any(p["policy_id"] == "pol-001" for p in payloads)


def test_middleware_unwraps_data_envelope_for_mapping():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.post("/api/v1/connectors/mapping")
    _wait_for_emits(captured, 1)

    payloads = [p for _, p in captured if "mapping_id" in p]
    assert payloads, f"mapping_id not extracted from data envelope: {captured}"
    assert payloads[0]["mapping_id"] == "map-77"


def test_middleware_unwraps_items_list_for_findings():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.post("/api/v1/findings/batch")
    _wait_for_emits(captured, 1)

    finding_payloads = [p for _, p in captured if "finding_id" in p]
    assert finding_payloads, f"no finding_id extracted from list: {captured}"
    finding_ids = {p["finding_id"] for p in finding_payloads}
    # At least one of the items is extracted (middleware emits per matched type).
    assert finding_ids & {"f-001", "f-002"}


def test_middleware_extracts_q_id_from_result_envelope():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.post("/api/v1/risk/quantify-fair")
    _wait_for_emits(captured, 1)

    payloads = [p for _, p in captured if "q_id" in p]
    assert payloads, f"q_id not extracted from result envelope: {captured}"


def test_middleware_extracts_seed_id_and_domain():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.post("/api/v1/easm/seed-domain")
    _wait_for_emits(captured, 1)

    # Both seed_id and domain map to asset.discovered — only one event will fire
    # per event-type per response, but the payload should carry both fields.
    asset_payloads = [p for evt, p in captured if evt == "asset.discovered"]
    assert asset_payloads, f"no asset.discovered emitted: {captured}"
    payload = asset_payloads[0]
    assert payload.get("seed_id") == "s-9"
    assert payload.get("domain") == "example.com"


def test_middleware_extracts_scan_id_under_payload_wrapper():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.post("/api/v1/scans")
    _wait_for_emits(captured, 1)

    payloads = [p for evt, p in captured if evt == "scan.completed"]
    assert payloads, f"scan.completed not emitted: {captured}"
    assert payloads[0].get("scan_id") == "scan-2024-01"


def test_middleware_extracts_correlation_and_tenant():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.post("/api/v1/orgs")
    _wait_for_emits(captured, 1)

    types = {evt for evt, _ in captured}
    # Either correlation -> event.created OR tenant_id -> asset.discovered must fire.
    assert types & {"event.created", "asset.discovered"}


def test_middleware_emits_finding_updated_on_put():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.put("/api/v1/findings/f-999")
    _wait_for_emits(captured, 1)

    types = {evt for evt, _ in captured}
    assert "finding.updated" in types, f"PUT did not emit finding.updated: {types}"


def test_middleware_emits_on_patch_control():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.patch("/api/v1/controls/ctrl-7")
    _wait_for_emits(captured, 1)

    types = {evt for evt, _ in captured}
    assert "control.assessed" in types


def test_middleware_walks_deeply_nested_evidence():
    bus, captured = _make_capturing_bus()
    client = TestClient(_build_app(bus))

    client.post("/api/v1/evidence")
    _wait_for_emits(captured, 1)

    # data -> items[0] is two levels deep — well within max_depth=3.
    payloads = [p for evt, p in captured if evt == "evidence.collected"]
    assert payloads, f"evidence.collected not emitted from nested shape: {captured}"


# ---------------------------------------------------------------------------
# Resolver-only tests (don't need TestClient — exercise _collect_id_candidates)
# ---------------------------------------------------------------------------


def test_collect_id_candidates_unwraps_data_wrapper():
    from core.trustgraph_event_bus import _collect_id_candidates

    body = {"data": {"finding_id": "f1"}}
    candidates = _collect_id_candidates(body)
    # Both the outer envelope and the inner dict must appear.
    assert any("finding_id" in c for c in candidates)


def test_collect_id_candidates_walks_lists():
    from core.trustgraph_event_bus import _collect_id_candidates

    body = {"items": [{"asset_id": "a1"}, {"asset_id": "a2"}]}
    candidates = _collect_id_candidates(body)
    asset_ids = {c.get("asset_id") for c in candidates if "asset_id" in c}
    assert {"a1", "a2"} <= asset_ids


def test_collect_id_candidates_respects_max_depth():
    from core.trustgraph_event_bus import _collect_id_candidates

    # Build an envelope nested 5 layers deep — depth limit is 3.
    body = {
        "data": {
            "items": [
                {"data": {"items": [{"data": {"finding_id": "too-deep"}}]}}
            ]
        }
    }
    candidates = _collect_id_candidates(body, max_depth=3)
    deeply_nested = [c for c in candidates if c.get("finding_id") == "too-deep"]
    assert not deeply_nested, "depth limit was not respected"


def test_collect_id_candidates_handles_non_dict():
    from core.trustgraph_event_bus import _collect_id_candidates

    assert _collect_id_candidates(None) == []
    assert _collect_id_candidates(42) == []
    assert _collect_id_candidates("string") == []


def test_collect_id_candidates_handles_cycle():
    from core.trustgraph_event_bus import _collect_id_candidates

    # Self-referencing dict — should not infinite-loop.
    body: Dict[str, Any] = {"finding_id": "f-cycle"}
    body["data"] = body
    candidates = _collect_id_candidates(body)
    assert any(c.get("finding_id") == "f-cycle" for c in candidates)
