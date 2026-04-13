"""Tests for AlertBroadcaster — subscribe, unsubscribe, broadcast, tenant filtering.

All tests are pure asyncio — no external dependencies, no network, no DB.
Run with: pytest tests/test_alert_broadcaster.py --timeout=10 -q
"""

from __future__ import annotations

import asyncio
import os
import pytest
from typing import Any, Dict, Optional
from unittest.mock import patch

# Ensure test mode so event buses don't init SQLite
os.environ.setdefault("FIXOPS_TEST_MODE", "1")
os.environ.setdefault("FIXOPS_MODE", "dev")

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

from core.alert_broadcaster import (
    ALERT_TYPES,
    SEVERITY_LEVELS,
    AlertBroadcaster,
    build_alert,
    get_alert_broadcaster,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    alert_type: str = "finding_created",
    severity: str = "high",
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    return build_alert(
        alert_type=alert_type,
        severity=severity,
        title="Test Alert",
        message="Test message",
        tenant_id=tenant_id,
        metadata={"test": True},
    )


async def _drain(q: asyncio.Queue, timeout: float = 0.1) -> list:
    """Drain all items currently in the queue within timeout."""
    items = []
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            item = q.get_nowait()
            items.append(item)
        except asyncio.QueueEmpty:
            await asyncio.sleep(0.01)
    return items


# ---------------------------------------------------------------------------
# build_alert tests
# ---------------------------------------------------------------------------


def test_build_alert_valid():
    """build_alert returns a well-formed dict with all required fields."""
    alert = build_alert(
        alert_type="finding_created",
        severity="critical",
        title="CVE Found",
        message="Critical CVE in openssl",
    )
    assert alert["type"] == "finding_created"
    assert alert["severity"] == "critical"
    assert alert["title"] == "CVE Found"
    assert alert["message"] == "Critical CVE in openssl"
    assert "id" in alert
    assert "timestamp" in alert
    assert alert["tenant_id"] is None
    assert isinstance(alert["metadata"], dict)


def test_build_alert_invalid_type():
    """build_alert raises ValueError for unknown alert type."""
    with pytest.raises(ValueError, match="Invalid alert type"):
        build_alert(alert_type="not_a_type", severity="high", title="x", message="x")


def test_build_alert_invalid_severity():
    """build_alert raises ValueError for unknown severity."""
    with pytest.raises(ValueError, match="Invalid severity"):
        build_alert(alert_type="finding_created", severity="urgent", title="x", message="x")


def test_build_alert_all_types():
    """build_alert accepts every defined alert type."""
    for at in ALERT_TYPES:
        alert = build_alert(alert_type=at, severity="info", title="t", message="m")
        assert alert["type"] == at


def test_build_alert_all_severities():
    """build_alert accepts every defined severity level."""
    for sev in SEVERITY_LEVELS:
        alert = build_alert(alert_type="new_cve", severity=sev, title="t", message="m")
        assert alert["severity"] == sev


def test_build_alert_custom_id():
    """build_alert respects an explicit alert_id override."""
    alert = build_alert(
        alert_type="sla_breach", severity="high", title="t", message="m", alert_id="fixed-id"
    )
    assert alert["id"] == "fixed-id"


def test_build_alert_tenant_id():
    """build_alert stores tenant_id in the alert dict."""
    alert = build_alert(
        alert_type="incident_opened", severity="critical", title="t", message="m", tenant_id="acme"
    )
    assert alert["tenant_id"] == "acme"


def test_build_alert_metadata():
    """build_alert stores arbitrary metadata."""
    alert = build_alert(
        alert_type="threat_detected",
        severity="medium",
        title="t",
        message="m",
        metadata={"cve": "CVE-2024-1234", "score": 9.8},
    )
    assert alert["metadata"]["cve"] == "CVE-2024-1234"
    assert alert["metadata"]["score"] == 9.8


# ---------------------------------------------------------------------------
# Subscribe / Unsubscribe tests
# ---------------------------------------------------------------------------


def test_subscribe_returns_queue():
    """subscribe() returns an asyncio.Queue."""
    b = AlertBroadcaster()
    q = b.subscribe("conn-1")
    assert isinstance(q, asyncio.Queue)
    assert b.subscriber_count == 1


def test_unsubscribe_removes_subscriber():
    """unsubscribe() removes the connection from the broadcaster."""
    b = AlertBroadcaster()
    b.subscribe("conn-1")
    b.subscribe("conn-2")
    assert b.subscriber_count == 2
    b.unsubscribe("conn-1")
    assert b.subscriber_count == 1


def test_unsubscribe_unknown_id_is_safe():
    """unsubscribe() with unknown connection_id does not raise."""
    b = AlertBroadcaster()
    b.unsubscribe("does-not-exist")  # must not raise
    assert b.subscriber_count == 0


def test_subscribe_tenant_stored():
    """subscribe() records the tenant_id for each connection."""
    b = AlertBroadcaster()
    b.subscribe("conn-1", tenant_id="tenant-a")
    assert b._tenants.get("conn-1") == "tenant-a"


# ---------------------------------------------------------------------------
# Broadcast tests (async)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_reaches_all_subscribers():
    """broadcast() delivers to every subscriber."""
    b = AlertBroadcaster()
    q1 = b.subscribe("c1")
    q2 = b.subscribe("c2")
    alert = _make_alert()
    delivered = await b.broadcast(alert)
    assert delivered == 2
    assert q1.qsize() == 1
    assert q2.qsize() == 1


@pytest.mark.asyncio
async def test_broadcast_alert_content_correct():
    """broadcast() places the exact alert dict into each queue."""
    b = AlertBroadcaster()
    q = b.subscribe("c1")
    alert = _make_alert(alert_type="sla_breach", severity="critical")
    await b.broadcast(alert)
    received = q.get_nowait()
    assert received["type"] == "sla_breach"
    assert received["severity"] == "critical"


@pytest.mark.asyncio
async def test_broadcast_no_subscribers_returns_zero():
    """broadcast() with no subscribers returns 0."""
    b = AlertBroadcaster()
    delivered = await b.broadcast(_make_alert())
    assert delivered == 0


@pytest.mark.asyncio
async def test_broadcast_multiple_alerts_ordered():
    """Multiple broadcasts arrive in order."""
    b = AlertBroadcaster()
    q = b.subscribe("c1")
    alerts = [_make_alert(alert_type=t) for t in ["finding_created", "sla_breach", "new_cve"]]
    for a in alerts:
        await b.broadcast(a)
    received = [q.get_nowait() for _ in range(3)]
    assert [r["type"] for r in received] == ["finding_created", "sla_breach", "new_cve"]


@pytest.mark.asyncio
async def test_broadcast_queue_full_drops_oldest():
    """When queue is full, oldest alert is evicted so newest fits."""
    b = AlertBroadcaster(queue_max=2)
    q = b.subscribe("c1")
    a1 = _make_alert(alert_type="finding_created")
    a2 = _make_alert(alert_type="sla_breach")
    a3 = _make_alert(alert_type="new_cve")
    await b.broadcast(a1)
    await b.broadcast(a2)
    # Queue is full; broadcasting a3 must drop a1
    await b.broadcast(a3)
    assert q.qsize() == 2
    first = q.get_nowait()
    second = q.get_nowait()
    # a1 should have been evicted; a2 and a3 remain
    assert first["type"] == "sla_breach"
    assert second["type"] == "new_cve"


# ---------------------------------------------------------------------------
# Tenant-filtered broadcast tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_to_tenant_filters_correctly():
    """broadcast_to_tenant() only delivers to matching or unscoped subscribers."""
    b = AlertBroadcaster()
    q_a = b.subscribe("c1", tenant_id="tenant-a")
    q_b = b.subscribe("c2", tenant_id="tenant-b")
    q_all = b.subscribe("c3", tenant_id=None)  # receives all

    alert = _make_alert(tenant_id="tenant-a")
    delivered = await b.broadcast_to_tenant("tenant-a", alert)

    assert delivered == 2  # tenant-a + unscoped
    assert q_a.qsize() == 1
    assert q_b.qsize() == 0
    assert q_all.qsize() == 1


@pytest.mark.asyncio
async def test_broadcast_to_tenant_no_match_returns_zero():
    """broadcast_to_tenant() returns 0 when no subscriber matches."""
    b = AlertBroadcaster()
    b.subscribe("c1", tenant_id="tenant-x")
    delivered = await b.broadcast_to_tenant("tenant-y", _make_alert())
    assert delivered == 0


@pytest.mark.asyncio
async def test_broadcast_to_tenant_none_subscriber_always_receives():
    """A subscriber with tenant_id=None receives all tenant broadcasts."""
    b = AlertBroadcaster()
    q = b.subscribe("c1", tenant_id=None)
    await b.broadcast_to_tenant("any-tenant", _make_alert())
    assert q.qsize() == 1


# ---------------------------------------------------------------------------
# Singleton test
# ---------------------------------------------------------------------------


def test_get_alert_broadcaster_singleton():
    """get_alert_broadcaster() always returns the same instance."""
    b1 = get_alert_broadcaster()
    b2 = get_alert_broadcaster()
    assert b1 is b2
