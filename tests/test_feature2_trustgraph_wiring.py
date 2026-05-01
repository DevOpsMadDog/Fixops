"""FEATURE-2 — TrustGraph wiring across RASP / CTEM / SAST / CloudConnectors.

Founder spec (2026-05-02 pivot):
    rasp_engine.py: _index_in_trustgraph + trustgraph_query_attacker were
    documented stubs — wire them to the real TrustGraph event bus
    (trustgraph_event_bus.py). Same canonical pattern needed in:
      - ctem_engine.py (already partially wired — complete it)
      - sast_engine.py (already partially wired — complete it)
      - cloud_connectors.py (add event emission on sync)

These tests assert that:
1. Every emit-site uses the canonical bus surface (`emit` or `publish`).
2. Payloads carry the agreed-upon keys for downstream correlation.
3. Failures inside the bus NEVER propagate up (best-effort try/except).
4. Stub language ("trustgraph-stub", "TrustGraph integration pending")
   is gone from rasp_engine — the methods are real now.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Import targets (sitecustomize.py prepends suite paths automatically when
# pytest runs from the repo root — same as the rest of the Beast Mode suite)
# ---------------------------------------------------------------------------

from core.rasp_engine import (
    RaspEngine,
    ThreatEvent,
    ThreatCategory,
    ThreatSeverity,
)
from core.ctem_engine import CTEMEngine, Exposure, CTEMStage, ExposureStatus
from core.sast_engine import SASTEngine
from core.cloud_connectors import (
    CloudConnectorEngine,
    CloudProviderType,
)


# ---------------------------------------------------------------------------
# Helper: fake bus that records every emit() call
# ---------------------------------------------------------------------------


class _RecordingBus:
    """Stand-in for TrustGraphEventBus — records emits for assertions."""

    enabled = True

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def emit(self, event_type: str, data: Dict[str, Any]) -> None:
        self.calls.append((event_type, dict(data)))

    def event_types(self) -> List[str]:
        return [c[0] for c in self.calls]


class _RaisingBus:
    """Bus that raises on emit — used to verify best-effort try/except."""

    enabled = True

    def emit(self, event_type: str, data: Dict[str, Any]) -> None:
        raise RuntimeError("simulated bus outage")


# ---------------------------------------------------------------------------
# Test 1: RASP — _index_in_trustgraph emits rasp.attack_detected
# ---------------------------------------------------------------------------


def test_rasp_index_in_trustgraph_emits_attack_detected(tmp_path):
    """The previously-stubbed _index_in_trustgraph now emits the canonical
    event with full payload."""
    bus = _RecordingBus()
    db = tmp_path / "rasp.db"
    engine = RaspEngine(db_path=str(db))

    event = ThreatEvent(
        event_id="evt-test-1",
        rule_id="sqli-001",
        category=ThreatCategory.SQLI,
        severity=ThreatSeverity.HIGH,
        confidence=0.92,
        client_ip="198.51.100.42",
        method="POST",
        path="/api/v1/login",
        matched_value="' OR 1=1--",
        matched_field="body.password",
        action_taken="block",
        org_id="acme-corp",
        timestamp=datetime.now(timezone.utc),
    )

    with patch("core.rasp_engine._get_tg_bus", return_value=bus):
        engine._index_in_trustgraph(event)

    assert "rasp.attack_detected" in bus.event_types(), (
        f"expected rasp.attack_detected, got {bus.event_types()}"
    )
    payload = next(p for et, p in bus.calls if et == "rasp.attack_detected")
    # Payload must carry the keys downstream correlators rely on
    for required_key in (
        "event_id", "rule_id", "category", "severity",
        "attacker_ip", "request_path", "org_id", "timestamp",
        "source_engine", "entity_type",
    ):
        assert required_key in payload, f"missing key {required_key}"
    assert payload["attacker_ip"] == "198.51.100.42"
    assert payload["org_id"] == "acme-corp"
    assert payload["source_engine"] == "rasp_engine"


def test_rasp_index_swallows_bus_exceptions(tmp_path):
    """RASP is hot-path — a busted bus must never raise."""
    db = tmp_path / "rasp.db"
    engine = RaspEngine(db_path=str(db))
    event = ThreatEvent(
        event_id="evt-raise-1",
        rule_id="xss-002",
        category=ThreatCategory.XSS,
        severity=ThreatSeverity.MEDIUM,
        confidence=0.7,
        client_ip="203.0.113.10",
        method="GET",
        path="/search",
        matched_value="<script>",
        matched_field="query.q",
        action_taken="block",
        org_id="default",
        timestamp=datetime.now(timezone.utc),
    )

    with patch("core.rasp_engine._get_tg_bus", return_value=_RaisingBus()):
        # Must not raise
        engine._index_in_trustgraph(event)


def test_rasp_query_attacker_returns_real_envelope(tmp_path):
    """trustgraph_query_attacker is no longer a stub — returns a real envelope
    with `source` field and emits rasp.attacker_query."""
    bus = _RecordingBus()
    db = tmp_path / "rasp.db"
    engine = RaspEngine(db_path=str(db))

    with patch("core.rasp_engine._get_tg_bus", return_value=bus):
        result = engine.trustgraph_query_attacker("198.51.100.99")

    # Old stub returned `note: "TrustGraph integration pending"` — must be gone
    assert "note" not in result or "pending" not in str(result.get("note", ""))
    # New envelope has source + local_sightings
    assert "source" in result
    assert "local_sightings" in result
    assert "correlated_entities" in result
    # And the query itself was emitted
    assert "rasp.attacker_query" in bus.event_types()


def test_rasp_correlate_campaign_detects_multi_ip(tmp_path):
    """Campaign correlation: 3+ unique IPs hitting the same rule = campaign."""
    bus = _RecordingBus()
    db = tmp_path / "rasp.db"
    engine = RaspEngine(db_path=str(db))

    base_kwargs = dict(
        rule_id="sqli-001",
        category=ThreatCategory.SQLI,
        severity=ThreatSeverity.HIGH,
        confidence=0.9,
        method="POST",
        path="/api/v1/login",
        matched_value="' OR 1=1--",
        matched_field="body.password",
        action_taken="block",
        org_id="default",
        timestamp=datetime.now(timezone.utc),
    )
    events = [
        ThreatEvent(event_id=f"evt-{i}", client_ip=ip, **base_kwargs)
        for i, ip in enumerate(["198.51.100.1", "198.51.100.2", "198.51.100.3"])
    ]

    with patch("core.rasp_engine._get_tg_bus", return_value=bus):
        result = engine.trustgraph_correlate_campaign(events)

    assert result["campaign_detected"] is True
    assert result["event_count"] == 3
    assert len(result["ips"]) == 3
    assert "rasp.campaign_correlated" in bus.event_types()


# ---------------------------------------------------------------------------
# Test 2: CTEM — exposure CRUD now emits canonical events
# ---------------------------------------------------------------------------


def test_ctem_add_exposure_emits_canonical_event(tmp_path):
    """add_exposure must emit ctem.exposure.added with org/stage/risk fields."""
    bus = _RecordingBus()
    db = tmp_path / "ctem.db"
    engine = CTEMEngine(db_path=str(db))
    engine.start_cycle("Q2-cycle", org_id="acme")
    bus.calls.clear()  # discard the cycle.started emit

    exp = Exposure(
        title="Public S3 bucket",
        org_id="acme",
        risk_score=78.0,
        assets=["s3://acme-data"],
    )

    with patch("core.ctem_engine._get_tg_bus", return_value=bus):
        engine.add_exposure(exp)

    assert "ctem.exposure.added" in bus.event_types()
    payload = next(p for et, p in bus.calls if et == "ctem.exposure.added")
    assert payload["exposure_id"] == exp.id
    assert payload["org_id"] == "acme"
    assert payload["risk_score"] == 78.0
    assert payload["asset_count"] == 1


def test_ctem_prioritize_emits_event(tmp_path):
    """prioritize_exposures must emit ctem.exposures.prioritized with max risk."""
    bus = _RecordingBus()
    db = tmp_path / "ctem.db"
    engine = CTEMEngine(db_path=str(db))
    cycle = engine.start_cycle("Q3-cycle", org_id="acme")
    engine.add_exposure(Exposure(title="X", org_id="acme", risk_score=40.0,
                                 assets=["a"], findings=["f1"]))
    engine.scope_assets(cycle.id, ["a"])
    bus.calls.clear()

    with patch("core.ctem_engine._get_tg_bus", return_value=bus):
        engine.prioritize_exposures(cycle.id)

    assert "ctem.exposures.prioritized" in bus.event_types()
    payload = next(p for et, p in bus.calls if et == "ctem.exposures.prioritized")
    assert payload["cycle_id"] == cycle.id
    assert payload["org_id"] == "acme"
    assert payload["stage"] == CTEMStage.PRIORITIZATION.value


# ---------------------------------------------------------------------------
# Test 3: SAST — get_summary no-scan path emits sast.summary.requested
#                (NOT the bogus FINDING_CREATED event it used to emit)
# ---------------------------------------------------------------------------


def test_sast_summary_no_scan_emits_correct_event():
    """Previous code wrongly emitted FINDING_CREATED on cache miss.
    New code emits sast.summary.requested with status=no_scan."""
    bus = _RecordingBus()
    engine = SASTEngine()

    with patch("core.sast_engine._get_tg_bus", return_value=bus):
        result = engine.get_summary()

    assert result["status"] == "no_scan"
    # Must NOT emit the bogus event
    assert "FINDING_CREATED" not in bus.event_types(), (
        "FINDING_CREATED must not be emitted from get_summary cache-miss path"
    )
    # Must emit the canonical replacement
    assert "sast.summary.requested" in bus.event_types()


# ---------------------------------------------------------------------------
# Test 4: CloudConnectors — sync_account emits connector.sync_completed
# ---------------------------------------------------------------------------


def test_cloud_connectors_sync_emits_completed(tmp_path):
    """sync_account on a successful sync must emit connector.sync_completed
    with provider/account/findings_count payload."""
    bus = _RecordingBus()
    persist = tmp_path / "cloud.db"
    engine = CloudConnectorEngine(persist_path=str(persist))

    # Stub the provider to avoid real AWS calls
    fake_provider = MagicMock()
    fake_provider.list_resources.return_value = [{"id": "r1"}, {"id": "r2"}]
    fake_provider.list_findings.return_value = [{"id": "f1"}]

    with patch.object(engine, "_get_provider", return_value=fake_provider), \
         patch("core.cloud_connectors._get_tg_bus", return_value=bus):
        result = engine.sync_account(CloudProviderType.AWS, "111111111111")

    assert result.status == "completed"
    assert "connector.sync_completed" in bus.event_types()
    payload = next(p for et, p in bus.calls if et == "connector.sync_completed")
    assert payload["provider"] == "aws"
    assert payload["account_id"] == "111111111111"
    assert payload["resources_count"] == 2
    assert payload["findings_count"] == 1
    assert payload["source_engine"] == "cloud_connectors"


def test_cloud_connectors_sync_emits_failed_on_error(tmp_path):
    """Failed sync emits connector.sync_failed with error payload."""
    bus = _RecordingBus()
    persist = tmp_path / "cloud.db"
    engine = CloudConnectorEngine(persist_path=str(persist))

    with patch.object(engine, "_get_provider",
                      side_effect=RuntimeError("creds expired")), \
         patch("core.cloud_connectors._get_tg_bus", return_value=bus):
        result = engine.sync_account(CloudProviderType.AZURE, "subscription-x")

    assert result.status == "failed"
    assert "connector.sync_failed" in bus.event_types()
    payload = next(p for et, p in bus.calls if et == "connector.sync_failed")
    assert "creds expired" in payload["error"]
    assert payload["provider"] == "azure"
