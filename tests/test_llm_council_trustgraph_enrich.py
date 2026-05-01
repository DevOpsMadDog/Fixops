"""Tests for LLMCouncilEngine._enrich_with_trustgraph (Wave 2e).

Validates that the council pulls TrustGraph blast-radius and CVE
correlation context onto the finding before stage-1 reasoning, and
that all failure paths are swallowed so the council never crashes.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.llm_council import (
    CouncilMember,
    CouncilVerdict,
    LLMCouncilEngine,
    MemberAnalysis,
)
from core.llm_providers import BaseLLMProvider


def _make_council() -> LLMCouncilEngine:
    provider = BaseLLMProvider(name="stub-provider")
    member = CouncilMember(
        provider=provider,
        expertise="vulnerability_assessment",
        weight=1.0,
    )
    return LLMCouncilEngine(members=[member], chairman=provider)


def _impact(blast_radius: int = 7) -> SimpleNamespace:
    return SimpleNamespace(
        blast_radius=blast_radius,
        upstream_dependencies=[{"id": "dep-a"}, {"id": "dep-b"}],
        compliance_impact=[{"framework": "PCI-DSS"}, {"framework": "SOC2"}],
        risk_weight=4.2,
    )


def _correlation(dollars: float = 1234567.0) -> SimpleNamespace:
    return SimpleNamespace(
        containers=[{"id": "c1"}, {"id": "c2"}, {"id": "c3"}],
        namespaces=[{"id": "ns1"}],
        dollar_risk_estimate=dollars,
        compliance_controls=[{"control_id": "AC-3"}, {"control_id": "AC-6"}],
    )


def test_enrich_calls_impact_analyzer():
    council = _make_council()
    finding = {"asset_id": "asset-42", "title": "Test SAST"}

    fake_analyzer_cls = MagicMock()
    fake_analyzer_cls.return_value.blast_radius.return_value = _impact(blast_radius=11)
    fake_correlator_cls = MagicMock()  # Should NOT be called — no cve_id.

    with patch.dict(
        "sys.modules",
        {"core.trustgraph_integrations": SimpleNamespace(
            ImpactAnalyzer=fake_analyzer_cls,
            CrossDomainCorrelator=fake_correlator_cls,
        )},
    ):
        enriched = council._enrich_with_trustgraph(dict(finding), {}, "tenant-1")

    fake_analyzer_cls.assert_called_once_with(org_id="tenant-1")
    fake_analyzer_cls.return_value.blast_radius.assert_called_once_with("asset-42")
    fake_correlator_cls.assert_not_called()

    assert enriched["blast_radius"] == 11
    assert enriched["upstream_dependencies"] == ["dep-a", "dep-b"]
    assert enriched["compliance_impact"] == ["PCI-DSS", "SOC2"]
    assert enriched["risk_weight"] == pytest.approx(4.2)
    # Original payload is preserved.
    assert enriched["title"] == "Test SAST"
    assert enriched["asset_id"] == "asset-42"


def test_enrich_calls_cross_domain_correlator():
    council = _make_council()
    finding = {"cve_id": "CVE-2024-9999", "severity": "critical"}

    fake_analyzer_cls = MagicMock()
    fake_correlator_cls = MagicMock()
    fake_correlator_cls.return_value.correlate_cve.return_value = _correlation(dollars=987654.0)

    with patch.dict(
        "sys.modules",
        {"core.trustgraph_integrations": SimpleNamespace(
            ImpactAnalyzer=fake_analyzer_cls,
            CrossDomainCorrelator=fake_correlator_cls,
        )},
    ):
        enriched = council._enrich_with_trustgraph(dict(finding), {}, "tenant-2")

    fake_correlator_cls.assert_called_once_with(org_id="tenant-2")
    fake_correlator_cls.return_value.correlate_cve.assert_called_once_with("CVE-2024-9999")
    fake_analyzer_cls.assert_not_called()

    assert enriched["dollar_risk_estimate"] == pytest.approx(987654.0)
    assert enriched["affected_containers"] == 3
    assert enriched["affected_namespaces"] == 1
    assert enriched["compliance_controls_violated"] == ["AC-3", "AC-6"]
    assert enriched["severity"] == "critical"


def test_enrich_swallows_exceptions():
    council = _make_council()
    finding = {"asset_id": "asset-99", "cve_id": "CVE-2024-1", "title": "boom"}

    fake_analyzer_cls = MagicMock()
    fake_analyzer_cls.return_value.blast_radius.side_effect = RuntimeError("graph offline")
    fake_correlator_cls = MagicMock()
    fake_correlator_cls.return_value.correlate_cve.side_effect = RuntimeError("offline too")

    with patch.dict(
        "sys.modules",
        {"core.trustgraph_integrations": SimpleNamespace(
            ImpactAnalyzer=fake_analyzer_cls,
            CrossDomainCorrelator=fake_correlator_cls,
        )},
    ):
        enriched = council._enrich_with_trustgraph(dict(finding), {}, "tenant-x")

    # Did NOT raise. Original payload is preserved untouched.
    assert enriched["title"] == "boom"
    assert enriched["asset_id"] == "asset-99"
    assert enriched["cve_id"] == "CVE-2024-1"
    # Enrichment fields are absent because the analyzer raised before they could be set.
    assert "blast_radius" not in enriched
    assert "dollar_risk_estimate" not in enriched


def test_convene_uses_enriched_finding():
    council = _make_council()
    finding = {"asset_id": "asset-7", "title": "input"}

    enriched_marker = {"asset_id": "asset-7", "title": "input", "blast_radius": 99}

    captured: dict = {}

    def _fake_stage1(passed_finding, passed_context):
        captured["stage1"] = passed_finding
        return [
            MemberAnalysis(
                member_name="stub-provider",
                expertise="vulnerability_assessment",
                stage="1_independent",
                position="accept_risk",
                confidence=0.8,
                reasoning="ok",
            )
        ]

    def _fake_stage2(_a, passed_finding, _ctx):
        captured["stage2"] = passed_finding
        return _a

    def _fake_stage3(_a, _b, passed_finding, _ctx):
        captured["stage3"] = passed_finding
        return CouncilVerdict(action="accept_risk", confidence=0.8, reasoning="t")

    with patch.object(council, "_enrich_with_trustgraph", return_value=dict(enriched_marker)) as enrich, \
         patch.object(council, "_stage_independent_analysis", side_effect=_fake_stage1), \
         patch.object(council, "_stage_peer_review", side_effect=_fake_stage2), \
         patch.object(council, "_stage_chairman_synthesis", side_effect=_fake_stage3), \
         patch.object(council, "should_escalate", return_value=False), \
         patch.object(council, "_persist_verdict_to_agentdb"):
        council.convene(finding, {}, org_id="tenant-9")

    enrich.assert_called_once()
    enrich_call = enrich.call_args
    # First positional is the finding dict copy, third is org_id.
    assert enrich_call.args[0] == finding
    assert enrich_call.args[2] == "tenant-9"

    # Every stage receives the enriched dict, not the raw finding.
    for stage_key in ("stage1", "stage2", "stage3"):
        assert captured[stage_key] == enriched_marker
        assert captured[stage_key]["blast_radius"] == 99
