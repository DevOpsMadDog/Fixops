"""Wave 2D — BrainPipeline integration tests for VulnIntelFusion + Correlator + auto-collect.

Verifies that brain_pipeline now actually CALLS:
  - VulnIntelFusionEngine in step 6 (_step_enrich_threats / _fuse_vuln_intel)
  - FindingCorrelator in step 4 (_step_deduplicate / _correlate_and_emit)
  - ConnectorIngestionScheduler in step 1 (_step_connect) when findings empty
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.brain_pipeline import BrainPipeline, PipelineInput


@pytest.fixture
def pipeline():
    return BrainPipeline()


@pytest.fixture
def basic_input():
    return PipelineInput(org_id="test-org-wave2d", source="pytest")


# ---------------------------------------------------------------------------
# Integration 1 — VulnIntelFusionEngine
# ---------------------------------------------------------------------------


def test_enrich_threats_calls_fusion(pipeline):
    """When findings have CVE ids, fusion.ingest_source_feed must fire per CVE."""
    findings = [
        {"id": "F-1", "cve_id": "CVE-2024-1001", "severity": "high", "engine": "snyk",
         "cvss_score": 7.5, "epss_score": 0.1},
        {"id": "F-2", "cve_id": "CVE-2024-1002", "severity": "critical", "engine": "trivy",
         "cvss_score": 9.0, "epss_score": 0.5, "in_kev": True},
    ]
    ctx = {"org_id": "test-org", "findings": findings}

    fake_fusion = MagicMock()
    fake_fusion.get_priority_queue.return_value = [
        {"cve_id": "CVE-2024-1001", "fusion_score": 0.85,
         "consensus_severity": "high", "consensus_priority": 2,
         "epss_score": 0.12, "kev_listed": 0},
        {"cve_id": "CVE-2024-1002", "fusion_score": 0.97,
         "consensus_severity": "critical", "consensus_priority": 1,
         "epss_score": 0.55, "kev_listed": 1},
    ]

    with patch("core.vuln_intel_fusion_engine.VulnIntelFusionEngine",
               return_value=fake_fusion):
        pipeline._fuse_vuln_intel(ctx)

    # ingest_source_feed called once per CVE finding
    assert fake_fusion.ingest_source_feed.call_count == 2
    # Findings enriched with fusion fields
    assert findings[0]["fusion_score"] == 0.85
    assert findings[0]["consensus_severity"] == "high"
    assert findings[0]["consensus_priority"] == 2
    assert findings[1]["fusion_score"] == 0.97
    assert findings[1]["kev_listed"] is True
    # ctx now has fused_vulns
    assert "fused_vulns" in ctx
    assert len(ctx["fused_vulns"]) == 2


def test_enrich_threats_skips_findings_without_cve(pipeline):
    """Findings without cve_id must NOT trigger ingest_source_feed."""
    findings = [
        {"id": "F-1", "severity": "high"},  # no cve_id
        {"id": "F-2", "severity": "low", "rule_id": "CWE-79"},  # no cve_id
    ]
    ctx = {"org_id": "test-org", "findings": findings}

    fake_fusion = MagicMock()
    fake_fusion.get_priority_queue.return_value = []

    with patch("core.vuln_intel_fusion_engine.VulnIntelFusionEngine",
               return_value=fake_fusion):
        pipeline._fuse_vuln_intel(ctx)

    assert fake_fusion.ingest_source_feed.call_count == 0
    # No fusion_score injected on either finding
    assert "fusion_score" not in findings[0]
    assert "fusion_score" not in findings[1]


# ---------------------------------------------------------------------------
# Integration 2 — FindingCorrelator
# ---------------------------------------------------------------------------


def test_deduplicate_calls_correlator(pipeline):
    """_correlate_and_emit must call build_exposure_cases and store results."""
    findings = [
        {"id": "F-1", "cve_id": "CVE-2024-1001", "severity": "high",
         "asset_name": "web-1"},
        {"id": "F-2", "cve_id": "CVE-2024-1001", "severity": "high",
         "asset_name": "web-1"},
    ]
    ctx = {"org_id": "test-org", "findings": findings}

    fake_correlator = MagicMock()
    fake_case = MagicMock()
    fake_case.model_dump.return_value = {
        "id": "ec-001",
        "title": "Cluster of CVE-2024-1001",
        "severity": "high",
        "risk_score": 7.5,
        "findings": findings,
    }
    fake_correlator.build_exposure_cases.return_value = [fake_case]

    with patch("core.finding_correlator.FindingCorrelator",
               return_value=fake_correlator), \
         patch("core.trustgraph_event_bus.get_event_bus") as mock_get_bus:
        mock_bus = MagicMock()

        async def _async_emit(*a, **kw):
            return None

        mock_bus.emit = MagicMock(side_effect=_async_emit)
        mock_get_bus.return_value = mock_bus

        pipeline._correlate_and_emit(ctx)

    fake_correlator.build_exposure_cases.assert_called_once()
    args, kwargs = fake_correlator.build_exposure_cases.call_args
    assert kwargs.get("org_id") == "test-org" or (len(args) >= 1 and args[0] == findings)
    assert "correlator_exposure_cases" in ctx
    assert len(ctx["correlator_exposure_cases"]) == 1
    assert ctx["correlator_exposure_cases"][0]["title"] == "Cluster of CVE-2024-1001"


def test_deduplicate_emits_correlator_events(pipeline):
    """Each exposure case must trigger bus.emit('finding.created', ...) with engine='correlator'."""
    findings = [
        {"id": "F-1", "cve_id": "CVE-2024-9000", "severity": "critical"},
    ]
    ctx = {"org_id": "test-org", "findings": findings}

    fake_correlator = MagicMock()
    case_a = MagicMock()
    case_a.model_dump.return_value = {
        "id": "ec-A", "title": "Case A", "severity": "critical",
        "risk_score": 9.5, "findings": findings,
    }
    case_b = MagicMock()
    case_b.model_dump.return_value = {
        "id": "ec-B", "title": "Case B", "severity": "high",
        "risk_score": 7.0, "findings": [],
    }
    fake_correlator.build_exposure_cases.return_value = [case_a, case_b]

    emit_calls = []

    class FakeBus:
        async def emit(self, event_type, data):
            emit_calls.append((event_type, data))

    with patch("core.finding_correlator.FindingCorrelator",
               return_value=fake_correlator), \
         patch("core.trustgraph_event_bus.get_event_bus", return_value=FakeBus()):
        pipeline._correlate_and_emit(ctx)

    # Two emit calls (one per case) with engine='correlator'
    assert len(emit_calls) == 2
    for event_type, payload in emit_calls:
        assert event_type == "finding.created"
        assert payload["engine"] == "correlator"
        assert payload["entity_type"] == "exposure_case"
        assert payload["org_id"] == "test-org"


# ---------------------------------------------------------------------------
# Integration 3 — _step_connect auto-collect
# ---------------------------------------------------------------------------


def test_step_connect_auto_collects_when_empty(pipeline, basic_input):
    """When PipelineInput has zero findings, the scheduler must be invoked."""
    ctx = {
        "org_id": basic_input.org_id,
        "findings": [],
        "assets": [],
        "clusters": [],
        "exposure_cases": [],
    }

    fake_scheduler_class = MagicMock()
    fake_scheduler = MagicMock()
    fake_scheduler.collect_all_findings.return_value = [
        {"id": "AUTO-1", "severity": "medium", "source": "auto"},
        {"id": "AUTO-2", "severity": "high", "source": "auto"},
    ]
    fake_scheduler_class.return_value = fake_scheduler

    # Use a fake module so the import succeeds even though scheduler doesn't exist yet
    import sys
    import types
    fake_mod = types.ModuleType("core.connector_ingestion_scheduler")
    fake_mod.ConnectorIngestionScheduler = fake_scheduler_class
    sys.modules["core.connector_ingestion_scheduler"] = fake_mod
    try:
        pipeline._step_connect(ctx, basic_input)
    finally:
        sys.modules.pop("core.connector_ingestion_scheduler", None)

    fake_scheduler_class.assert_called_once_with(basic_input.org_id)
    fake_scheduler.collect_all_findings.assert_called_once()
    # ctx findings extended
    assert len(ctx["findings"]) >= 2
    assert any(f.get("id") == "AUTO-1" for f in ctx["findings"])


def test_step_connect_skips_when_findings_present(pipeline, basic_input):
    """When ctx already has findings, the scheduler must NOT be instantiated."""
    seed = [{"id": "EXISTING-1", "severity": "high"}]
    ctx = {
        "org_id": basic_input.org_id,
        "findings": list(seed),
        "assets": [],
        "clusters": [],
        "exposure_cases": [],
    }

    fake_scheduler_class = MagicMock()
    import sys
    import types
    fake_mod = types.ModuleType("core.connector_ingestion_scheduler")
    fake_mod.ConnectorIngestionScheduler = fake_scheduler_class
    sys.modules["core.connector_ingestion_scheduler"] = fake_mod
    try:
        pipeline._step_connect(ctx, basic_input)
    finally:
        sys.modules.pop("core.connector_ingestion_scheduler", None)

    # Scheduler class must NEVER be called
    fake_scheduler_class.assert_not_called()
    # Existing finding still present
    assert any(f.get("id") == "EXISTING-1" for f in ctx["findings"])
