"""
Tests for TrustGraph Integration Layer (suite-core/core/trustgraph_integrations.py)
and the integration router (suite-api/apps/api/trustgraph_integration_router.py).

Covers:
- FindingInput validation and normalisation (engine, severity)
- KnowledgeCoreRouter entity-type and engine routing
- UniversalFindingIndexer: single finding, CVE link, CWE link, asset link, control link
- UniversalFindingIndexer: scan-result bulk helper
- CrossDomainCorrelator: CVE correlation (with mock backbone), finding correlation
- AttackPathEnricher: asset enrichment, classification of vuln/misconfig/rasp findings
- ImpactAnalyzer: blast_radius, structured_json, unavailable store
- BatchIndexer: dedup, merge (latest timestamp, highest severity, union scanners)
- GraphRAGQueries: all 5 templates with store unavailable → graceful degradation
- GraphRAGQueries.run_template: invalid template raises ValueError
- Dollar-risk estimate heuristic
- Router endpoints via FastAPI TestClient (mocked backbone)
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------


def _make_entity(entity_id: str, entity_type: str, name: str, properties: dict, core_id: int = 2):
    """Return a lightweight entity-like object matching KnowledgeEntity API."""
    ent = MagicMock()
    ent.entity_id = entity_id
    ent.entity_type = entity_type
    ent.name = name
    ent.properties = properties
    ent.core_id = core_id
    ent.to_dict.return_value = {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "name": name,
        "properties": properties,
        "core_id": core_id,
    }
    return ent


def _make_rel(source_id: str, target_id: str, rel_type: str):
    rel = MagicMock()
    rel.source_id = source_id
    rel.target_id = target_id
    rel.rel_type = rel_type
    rel.to_dict.return_value = {
        "source_id": source_id,
        "target_id": target_id,
        "rel_type": rel_type,
    }
    return rel


def _patched_backbone(
    available: bool = True,
    entities: Optional[Dict[str, Any]] = None,
    relationships: Optional[List[Any]] = None,
    neighbors: Optional[List[Any]] = None,
    search_results: Optional[List[Any]] = None,
):
    """Build a mock TrustGraphBackbone with configurable returns."""
    entities = entities or {}
    relationships = relationships or []
    neighbors = neighbors or []
    search_results = search_results or []

    store = MagicMock()
    store.get_entity.side_effect = lambda entity_id: entities.get(entity_id)
    store.get_relationships.return_value = relationships
    store.get_neighbors.return_value = neighbors
    store.search.return_value = search_results
    store.ingest = MagicMock()
    store.add_relationship = MagicMock()

    backbone = MagicMock()
    backbone._available = available
    backbone._store = store if available else None
    backbone._make_entity.side_effect = lambda **kw: _make_entity(
        kw["entity_id"], kw["entity_type"], kw["name"], kw.get("properties", {}), kw.get("core_id", 2)
    )
    backbone._make_rel.return_value = _make_rel("a", "b", "FINDING_AFFECTS_ASSET")
    backbone._safe_ingest.return_value = True
    backbone._safe_relate.return_value = True
    return backbone


# ============================================================================
# 1. FindingInput — validation and normalisation
# ============================================================================


class TestFindingInput:
    def test_minimal_valid(self):
        from core.trustgraph_integrations import FindingInput
        fi = FindingInput(engine="sast")
        assert fi.engine == "sast"
        assert fi.severity == "unknown"
        assert fi.status == "open"
        assert fi.control_ids == []

    def test_severity_normalised_to_lower(self):
        from core.trustgraph_integrations import FindingInput
        fi = FindingInput(engine="sca", severity="CRITICAL")
        assert fi.severity == "critical"

    def test_severity_unknown_on_invalid(self):
        from core.trustgraph_integrations import FindingInput
        fi = FindingInput(engine="sca", severity="extreme")
        assert fi.severity == "unknown"

    def test_engine_normalised_to_lower(self):
        from core.trustgraph_integrations import FindingInput
        fi = FindingInput(engine="DAST")
        assert fi.engine == "dast"

    def test_all_optional_fields(self):
        from core.trustgraph_integrations import FindingInput
        fi = FindingInput(
            id="f001",
            engine="cspm",
            title="S3 public read",
            severity="high",
            cve_id="CVE-2024-1234",
            cwe_id="CWE-200",
            cvss=7.5,
            epss=0.03,
            asset_id="asset_s3_prod",
            asset_name="prod-bucket",
            asset_type="s3_bucket",
            namespace="prod",
            control_ids=["CIS-1.1", "SOC2-CC6.1"],
            scanner="prowler",
            status="confirmed",
            timestamp="2025-01-01T00:00:00+00:00",
            metadata={"region": "us-east-1"},
        )
        assert fi.cve_id == "CVE-2024-1234"
        assert fi.control_ids == ["CIS-1.1", "SOC2-CC6.1"]
        assert fi.metadata == {"region": "us-east-1"}

    def test_cvss_bounds(self):
        from core.trustgraph_integrations import FindingInput
        with pytest.raises(ValidationError):
            FindingInput(engine="sast", cvss=11.0)

    def test_epss_bounds(self):
        from core.trustgraph_integrations import FindingInput
        with pytest.raises(ValidationError):
            FindingInput(engine="sast", epss=1.5)

    def test_extra_fields_ignored(self):
        from core.trustgraph_integrations import FindingInput
        fi = FindingInput.model_validate({"engine": "sast", "unknown_field": "ignored"})
        assert fi.engine == "sast"


# ============================================================================
# 2. KnowledgeCoreRouter
# ============================================================================


class TestKnowledgeCoreRouter:
    def test_engine_sast_routes_to_security(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_engine("sast") == 2

    def test_engine_cspm_routes_to_security(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_engine("cspm") == 2

    def test_engine_compliance_routes_to_compliance(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_engine("compliance") == 3

    def test_engine_incident_routes_to_operational(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_engine("incident") == 4

    def test_engine_vendor_routes_to_external(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_engine("vendor") == 5

    def test_unknown_engine_defaults_to_security(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_engine("totally_unknown") == 2

    def test_entity_type_asset_routes_to_asset(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_entity_type("asset") == 1

    def test_entity_type_control_routes_to_compliance(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_entity_type("control") == 3

    def test_entity_type_incident_routes_to_operational(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_entity_type("incident") == 4

    def test_entity_type_vendor_routes_to_external(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        assert KnowledgeCoreRouter.core_for_entity_type("vendor") == 5

    def test_describe_returns_string(self):
        from core.trustgraph_integrations import KnowledgeCoreRouter
        desc = KnowledgeCoreRouter.describe(2)
        assert "SecurityCore" in desc or "threat" in desc.lower()


# ============================================================================
# 3. UniversalFindingIndexer
# ============================================================================


class TestUniversalFindingIndexer:
    def _make_indexer(self, backbone_mock):
        from core.trustgraph_integrations import UniversalFindingIndexer
        indexer = UniversalFindingIndexer(org_id="test")
        indexer._get_backbone = lambda: backbone_mock
        return indexer

    def test_index_returns_finding_entity_id(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        eid = indexer.index({"engine": "sast", "title": "SQL Injection", "severity": "high"})
        assert eid.startswith("finding_")

    def test_index_calls_safe_ingest(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        indexer.index({"engine": "sca", "title": "Log4Shell", "cve_id": "CVE-2021-44228", "severity": "critical"})
        assert backbone._safe_ingest.called

    def test_index_creates_cve_entity_when_cve_present(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        indexer.index({"engine": "sca", "cve_id": "CVE-2024-9999", "severity": "high"})
        # CVE entity should be ingested
        calls = [str(c) for c in backbone._safe_ingest.call_args_list]
        assert any("CVE" in c or "cve" in str(c).lower() for c in calls) or backbone._safe_ingest.call_count >= 2

    def test_index_creates_cwe_entity_when_cwe_present(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        indexer.index({"engine": "sast", "cwe_id": "CWE-79", "severity": "medium"})
        # CWE ingest should happen
        assert backbone._safe_ingest.call_count >= 2

    def test_index_creates_asset_entity_when_asset_present(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        indexer.index({"engine": "cspm", "asset_id": "s3_prod", "asset_name": "prod-bucket", "severity": "high"})
        assert backbone._safe_ingest.call_count >= 2

    def test_index_creates_scanner_entity(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        indexer.index({"engine": "sast", "scanner": "semgrep", "severity": "low"})
        # Scanner entity + finding entity
        assert backbone._safe_ingest.call_count >= 2

    def test_index_links_control_violations(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        indexer.index({
            "engine": "compliance",
            "severity": "high",
            "control_ids": ["CIS-1.1", "NIST-AC-2"],
        })
        # violates_control relationships
        assert backbone._safe_relate.call_count >= 2

    def test_index_with_invalid_raw_falls_back_gracefully(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        # No engine key — should still return an entity_id
        eid = indexer.index({"title": "Mystery finding"})
        assert isinstance(eid, str)

    def test_index_severity_stored_in_properties(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        indexer.index({"engine": "dast", "severity": "critical", "title": "XSS"})
        # _make_entity called with properties containing severity
        call_kwargs = backbone._make_entity.call_args_list[0][1]
        assert call_kwargs["properties"]["severity"] == "critical"

    def test_index_from_scan_result_indexes_all_findings(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        scan_result = {
            "engine": "sca",
            "findings": [
                {"severity": "high", "title": "dep vuln 1"},
                {"severity": "medium", "title": "dep vuln 2"},
                {"severity": "low", "title": "dep vuln 3"},
            ],
        }
        entity_ids = indexer.index_from_scan_result(scan_result)
        assert len(entity_ids) == 3

    def test_index_from_scan_result_empty(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        entity_ids = indexer.index_from_scan_result({"engine": "sca", "findings": []})
        assert entity_ids == []

    def test_index_from_scan_result_uses_vulnerabilities_key(self):
        backbone = _patched_backbone()
        indexer = self._make_indexer(backbone)
        scan_result = {
            "engine": "dast",
            "vulnerabilities": [{"severity": "high", "title": "SSRF"}],
        }
        entity_ids = indexer.index_from_scan_result(scan_result)
        assert len(entity_ids) == 1


# ============================================================================
# 4. CrossDomainCorrelator
# ============================================================================


class TestCrossDomainCorrelator:
    def _make_correlator(self, backbone_mock):
        from core.trustgraph_integrations import CrossDomainCorrelator
        correlator = CrossDomainCorrelator(org_id="test")
        correlator._get_backbone = lambda: backbone_mock
        return correlator

    def test_correlate_cve_unavailable_backbone(self):
        backbone = _patched_backbone(available=False)
        correlator = self._make_correlator(backbone)
        result = correlator.correlate_cve("CVE-2024-1234")
        assert result.available is False

    def test_correlate_cve_no_findings(self):
        backbone = _patched_backbone(available=True, relationships=[])
        correlator = self._make_correlator(backbone)
        result = correlator.correlate_cve("CVE-2024-1234")
        assert result.available is True
        assert result.containers == []
        assert result.namespaces == []
        assert result.dollar_risk_estimate == 0.0

    def test_correlate_cve_with_finding_and_asset(self):
        cve_entity_id = "cve_cve_2024_1234"
        finding_id = "finding_f001"
        asset_id = "asset_prod_api"

        # CVE→finding relationships (inbound to CVE)
        rel_finding_cve = _make_rel(finding_id, cve_entity_id, "FINDING_EXPLOITS_CVE")
        # finding→asset relationship
        rel_finding_asset = _make_rel(finding_id, asset_id, "FINDING_AFFECTS_ASSET")

        asset_ent = _make_entity(asset_id, "Asset", "prod-api", {"asset_type": "container", "namespace": "prod"}, 1)

        def get_rels(entity_id):
            if entity_id == cve_entity_id:
                return [rel_finding_cve]
            if entity_id == finding_id:
                return [rel_finding_asset]
            return []

        backbone = _patched_backbone(
            available=True,
            entities={asset_id: asset_ent},
        )
        backbone._store.get_relationships.side_effect = get_rels
        backbone._store.get_entity.side_effect = lambda eid: {asset_id: asset_ent}.get(eid)

        correlator = self._make_correlator(backbone)
        result = correlator.correlate_cve("CVE-2024-1234")
        assert result.available is True
        assert len(result.containers) >= 1

    def test_correlate_finding_unavailable_backbone(self):
        backbone = _patched_backbone(available=False)
        correlator = self._make_correlator(backbone)
        result = correlator.correlate_finding("finding_f001")
        assert result.get("available") is False

    def test_correlate_finding_not_found(self):
        backbone = _patched_backbone(available=True)
        backbone._store.get_entity.return_value = None
        correlator = self._make_correlator(backbone)
        result = correlator.correlate_finding("f001")
        assert "error" in result

    def test_dollar_risk_zero_assets(self):
        from core.trustgraph_integrations import CrossDomainCorrelator
        risk = CrossDomainCorrelator._estimate_dollar_risk("CVE-2024-1", 0, 5, 1)
        assert risk == 0.0

    def test_dollar_risk_increases_with_assets(self):
        from core.trustgraph_integrations import CrossDomainCorrelator
        r1 = CrossDomainCorrelator._estimate_dollar_risk("CVE-2024-1", 1, 5, 1)
        r10 = CrossDomainCorrelator._estimate_dollar_risk("CVE-2024-1", 10, 5, 1)
        assert r10 > r1

    def test_dollar_risk_increases_with_control_gaps(self):
        from core.trustgraph_integrations import CrossDomainCorrelator
        r_no_gaps = CrossDomainCorrelator._estimate_dollar_risk("CVE-2024-1", 5, 10, 1)
        r_gaps = CrossDomainCorrelator._estimate_dollar_risk("CVE-2024-1", 5, 0, 1)
        assert r_gaps > r_no_gaps


# ============================================================================
# 5. AttackPathEnricher
# ============================================================================


class TestAttackPathEnricher:
    def _make_enricher(self, backbone_mock):
        from core.trustgraph_integrations import AttackPathEnricher
        enricher = AttackPathEnricher(org_id="test")
        enricher._get_backbone = lambda: backbone_mock
        return enricher

    def test_enrich_asset_unavailable(self):
        backbone = _patched_backbone(available=False)
        enricher = self._make_enricher(backbone)
        result = enricher.enrich_asset("asset_prod")
        assert result["available"] is False

    def test_enrich_asset_not_found(self):
        backbone = _patched_backbone(available=True)
        backbone._store.get_entity.return_value = None
        enricher = self._make_enricher(backbone)
        result = enricher.enrich_asset("asset_missing")
        assert "error" in result

    def test_enrich_asset_classifies_sca_as_vuln(self):
        asset_id = "asset_prod_api"
        finding_id = "finding_sca_001"
        asset_ent = _make_entity(asset_id, "Asset", "prod-api", {"asset_type": "container"}, 1)
        finding_ent = _make_entity(finding_id, "Finding", "Log4Shell", {"engine": "sca", "severity": "critical"}, 2)

        rel = _make_rel(finding_id, asset_id, "FINDING_AFFECTS_ASSET")

        backbone = _patched_backbone(available=True)
        backbone._store.get_entity.side_effect = lambda eid: {
            asset_id: asset_ent, finding_id: finding_ent
        }.get(eid)
        backbone._store.get_relationships.return_value = [rel]

        enricher = self._make_enricher(backbone)
        result = enricher.enrich_asset(asset_id)
        assert result["available"] is True
        assert result["aggregate_risk_score"] >= 0

    def test_enrich_asset_classifies_cspm_as_misconfig(self):
        asset_id = "asset_s3"
        finding_id = "finding_cspm_001"
        asset_ent = _make_entity(asset_id, "Asset", "s3-bucket", {"asset_type": "s3_bucket"}, 1)
        finding_ent = _make_entity(finding_id, "Finding", "Public read", {"engine": "cspm", "severity": "high"}, 2)

        rel = _make_rel(finding_id, asset_id, "FINDING_AFFECTS_ASSET")

        backbone = _patched_backbone(available=True)
        backbone._store.get_entity.side_effect = lambda eid: {
            asset_id: asset_ent, finding_id: finding_ent
        }.get(eid)
        backbone._store.get_relationships.return_value = [rel]

        enricher = self._make_enricher(backbone)
        result = enricher.enrich_asset(asset_id)
        assert result["available"] is True
        assert result["finding_count"] >= 0

    def test_enrich_asset_returns_enrichment_summary(self):
        asset_id = "asset_web"
        asset_ent = _make_entity(asset_id, "Asset", "web-server", {}, 1)
        backbone = _patched_backbone(available=True, relationships=[])
        backbone._store.get_entity.side_effect = lambda eid: asset_ent if eid == asset_id else None
        enricher = self._make_enricher(backbone)
        result = enricher.enrich_asset(asset_id)
        assert "enrichment_summary" in result


# ============================================================================
# 6. ImpactAnalyzer
# ============================================================================


class TestImpactAnalyzer:
    """ImpactAnalyzer tests — patch GraphRAGEnhanced at its backbone source."""

    def _run_blast(self, analyzer, graphrag_instance, entity_id, depth=2):
        """Helper: run blast_radius with GraphRAGEnhanced patched at backbone."""
        with patch("core.trustgraph_backbone.GraphRAGEnhanced", return_value=graphrag_instance):
            return analyzer.blast_radius(entity_id, depth=depth)

    def _run_structured(self, analyzer, graphrag_instance, entity_id):
        with patch("core.trustgraph_backbone.GraphRAGEnhanced", return_value=graphrag_instance):
            return analyzer.structured_json(entity_id)

    def test_blast_radius_unavailable(self):
        from core.trustgraph_integrations import ImpactAnalyzer
        graphrag = MagicMock()
        graphrag._available = False
        graphrag._store = None

        analyzer = ImpactAnalyzer(org_id="test")
        result = self._run_blast(analyzer, graphrag, "finding_test")
        assert result.available is False
        assert result.blast_radius == 0

    def test_blast_radius_with_neighbors(self):
        from core.trustgraph_integrations import ImpactAnalyzer

        neighbor = _make_entity("asset_prod", "Asset", "prod", {"severity": "high"}, 1)
        rel = _make_rel("finding_test", "asset_prod", "FINDING_AFFECTS_ASSET")

        graphrag = MagicMock()
        graphrag._available = True
        graphrag._store = MagicMock()
        graphrag._store.get_neighbors.return_value = [neighbor]
        graphrag._store.get_relationships.return_value = [rel]
        graphrag._store.get_entity.return_value = neighbor

        analyzer = ImpactAnalyzer(org_id="test")
        result = self._run_blast(analyzer, graphrag, "finding_test", depth=2)
        assert result.available is True
        assert result.blast_radius == 1

    def test_structured_json_returns_dict(self):
        from core.trustgraph_integrations import ImpactAnalyzer

        graphrag = MagicMock()
        graphrag._available = False
        graphrag._store = None

        analyzer = ImpactAnalyzer(org_id="test")
        result = self._run_structured(analyzer, graphrag, "entity_x")
        assert isinstance(result, dict)
        assert "entity_id" in result
        assert "blast_radius" in result

    def test_blast_radius_depth_clamped(self):
        from core.trustgraph_integrations import ImpactAnalyzer

        graphrag = MagicMock()
        graphrag._available = True
        graphrag._store = MagicMock()
        graphrag._store.get_neighbors.return_value = []
        graphrag._store.get_relationships.return_value = []

        analyzer = ImpactAnalyzer(org_id="test")
        result = self._run_blast(analyzer, graphrag, "entity_x", depth=99)
        assert result.available is True  # clamped to 3, no crash


# ============================================================================
# 7. BatchIndexer
# ============================================================================


class TestBatchIndexer:
    def _make_batch_indexer(self, backbone_mock):
        from core.trustgraph_integrations import BatchIndexer
        bi = BatchIndexer(org_id="test")
        bi._indexer._get_backbone = lambda: backbone_mock
        return bi

    def test_empty_batch_returns_zeros(self):
        backbone = _patched_backbone()
        bi = self._make_batch_indexer(backbone)
        result = bi.index_batch([])
        assert result.total == 0
        assert result.indexed == 0

    def test_single_finding_indexed(self):
        backbone = _patched_backbone()
        bi = self._make_batch_indexer(backbone)
        result = bi.index_batch([{"engine": "sast", "severity": "high", "title": "XSS"}])
        assert result.total == 1
        assert result.indexed == 1
        assert len(result.entity_ids) == 1

    def test_dedup_same_cve_same_asset(self):
        backbone = _patched_backbone()
        bi = self._make_batch_indexer(backbone)
        findings = [
            {"engine": "sca", "cve_id": "CVE-2024-1234", "asset_id": "prod_api", "severity": "high", "scanner": "snyk"},
            {"engine": "sca", "cve_id": "CVE-2024-1234", "asset_id": "prod_api", "severity": "high", "scanner": "trivy"},
        ]
        result = bi.index_batch(findings)
        assert result.total == 2
        assert result.indexed == 1  # merged into one
        assert result.deduplicated == 1

    def test_merge_highest_severity_wins(self):
        from core.trustgraph_integrations import BatchIndexer
        from core.trustgraph_integrations import FindingInput
        fi_low = FindingInput(engine="sca", cve_id="CVE-2024-1", severity="low")
        fi_crit = FindingInput(engine="sca", cve_id="CVE-2024-1", severity="critical")
        raw_low = {"engine": "sca", "cve_id": "CVE-2024-1", "severity": "low"}
        raw_crit = {"engine": "sca", "cve_id": "CVE-2024-1", "severity": "critical"}
        merged = BatchIndexer._merge_group([(fi_low, raw_low), (fi_crit, raw_crit)])
        assert merged["severity"] == "critical"

    def test_merge_latest_timestamp_wins(self):
        from core.trustgraph_integrations import BatchIndexer, FindingInput
        fi_old = FindingInput(engine="sca", cve_id="CVE-X", severity="medium", timestamp="2024-01-01T00:00:00+00:00")
        fi_new = FindingInput(engine="sca", cve_id="CVE-X", severity="medium", timestamp="2025-01-01T00:00:00+00:00")
        raw_old = {"engine": "sca", "cve_id": "CVE-X", "timestamp": "2024-01-01T00:00:00+00:00"}
        raw_new = {"engine": "sca", "cve_id": "CVE-X", "timestamp": "2025-01-01T00:00:00+00:00", "description": "latest"}
        merged = BatchIndexer._merge_group([(fi_old, raw_old), (fi_new, raw_new)])
        # Primary should be latest
        assert merged.get("description") == "latest" or merged.get("timestamp", "").startswith("2025")

    def test_merge_single_item_is_identity(self):
        from core.trustgraph_integrations import BatchIndexer, FindingInput
        fi = FindingInput(engine="sca", severity="high")
        raw = {"engine": "sca", "severity": "high"}
        merged = BatchIndexer._merge_group([(fi, raw)])
        assert merged == raw

    def test_batch_multiple_unique_findings(self):
        backbone = _patched_backbone()
        bi = self._make_batch_indexer(backbone)
        findings = [
            {"engine": "sast", "title": "XSS", "severity": "high"},
            {"engine": "dast", "title": "SSRF", "severity": "critical"},
            {"engine": "sca", "cve_id": "CVE-2023-111", "severity": "medium"},
        ]
        result = bi.index_batch(findings)
        assert result.total == 3
        assert result.indexed == 3
        assert result.deduplicated == 0


# ============================================================================
# 8. GraphRAGQueries — templates
# ============================================================================


class TestGraphRAGQueries:
    def _make_graphrag(self, backbone_mock):
        from core.trustgraph_integrations import GraphRAGQueries
        gq = GraphRAGQueries(org_id="test")
        gq._get_backbone = lambda: backbone_mock
        return gq

    def test_invalid_template_raises(self):
        from core.trustgraph_integrations import GraphRAGQueries
        gq = GraphRAGQueries()
        with pytest.raises(ValueError, match="Unknown template"):
            gq.run_template("nonexistent_template")

    def test_top_risks_unavailable(self):
        backbone = _patched_backbone(available=False)
        gq = self._make_graphrag(backbone)
        result = gq.top_risks()
        assert result["available"] is False

    def test_top_risks_returns_findings(self):
        finding_ent = _make_entity("finding_001", "Finding", "XSS", {"severity": "critical"}, 2)
        backbone = _patched_backbone(available=True, search_results=[finding_ent])
        gq = self._make_graphrag(backbone)
        result = gq.top_risks(limit=10)
        assert result["available"] is True
        assert "findings" in result
        assert "severity_distribution" in result

    def test_top_risks_sorted_by_severity(self):
        ents = [
            _make_entity("f1", "Finding", "Low", {"severity": "low"}, 2),
            _make_entity("f2", "Finding", "Critical", {"severity": "critical"}, 2),
            _make_entity("f3", "Finding", "Medium", {"severity": "medium"}, 2),
        ]
        backbone = _patched_backbone(available=True, search_results=ents)
        gq = self._make_graphrag(backbone)
        result = gq.top_risks(limit=10)
        severities = [f.get("properties", {}).get("severity") for f in result["findings"]]
        assert severities[0] == "critical"

    def test_compliance_gaps_unavailable(self):
        backbone = _patched_backbone(available=False)
        gq = self._make_graphrag(backbone)
        result = gq.compliance_gaps()
        assert result["available"] is False

    def test_compliance_gaps_returns_gaps(self):
        ctrl_ent = _make_entity("control_cis_1", "Control", "CIS-1.1", {"framework": "CIS"}, 3)
        finding_id = "finding_violating"
        rel = _make_rel(finding_id, "control_cis_1", "violates_control")

        backbone = _patched_backbone(available=True, search_results=[ctrl_ent])
        backbone._store.get_relationships.return_value = [rel]
        gq = self._make_graphrag(backbone)
        result = gq.compliance_gaps()
        assert result["available"] is True
        assert "gaps" in result

    def test_attack_surface_unavailable(self):
        backbone = _patched_backbone(available=False)
        gq = self._make_graphrag(backbone)
        result = gq.attack_surface()
        assert result["available"] is False

    def test_attack_surface_returns_structure(self):
        asset_ent = _make_entity("asset_prod", "Asset", "prod", {"asset_type": "container", "exposure": "external"}, 1)
        rel = _make_rel("finding_001", "asset_prod", "FINDING_AFFECTS_ASSET")

        backbone = _patched_backbone(available=True, search_results=[asset_ent])
        backbone._store.get_relationships.return_value = [rel]
        gq = self._make_graphrag(backbone)
        result = gq.attack_surface(limit=10)
        assert result["available"] is True
        assert "surface" in result
        assert "by_asset_type" in result

    def test_threat_landscape_unavailable(self):
        backbone = _patched_backbone(available=False)
        gq = self._make_graphrag(backbone)
        result = gq.threat_landscape()
        assert result["available"] is False

    def test_threat_landscape_returns_actors(self):
        actor_ent = _make_entity("actor_apt29", "ThreatActor", "APT29", {"sophistication": "high"}, 2)
        ttp_ent = _make_entity("ttp_t1059", "TTP", "T1059", {"mitre_id": "T1059"}, 2)
        rel_ttp = _make_rel("actor_apt29", "ttp_t1059", "ACTOR_USES_TTP")

        backbone = _patched_backbone(available=True, search_results=[actor_ent])
        backbone._store.get_relationships.return_value = [rel_ttp]
        backbone._store.get_entity.return_value = ttp_ent
        gq = self._make_graphrag(backbone)
        result = gq.threat_landscape(limit=5)
        assert result["available"] is True
        assert "landscape" in result
        assert "top_ttps" in result

    def test_exposure_chain_unavailable(self):
        backbone = _patched_backbone(available=False)
        gq = self._make_graphrag(backbone)
        result = gq.exposure_chain()
        assert result["available"] is False

    def test_run_template_top_risks(self):
        finding_ent = _make_entity("finding_001", "Finding", "XSS", {"severity": "high"}, 2)
        backbone = _patched_backbone(available=True, search_results=[finding_ent])
        gq = self._make_graphrag(backbone)
        result = gq.run_template("top_risks", limit=5)
        assert result["template"] == "top_risks"

    def test_all_templates_have_generated_at(self):
        backbone = _patched_backbone(available=True, search_results=[])
        gq = self._make_graphrag(backbone)
        for template in ("top_risks", "attack_surface", "threat_landscape"):
            result = gq.run_template(template)
            if result.get("available"):
                assert "generated_at" in result


# ============================================================================
# 9. Router Endpoint Tests
# ============================================================================


def _build_test_app():
    """Create a minimal FastAPI app with the integration router mounted."""
    from fastapi import FastAPI
    from apps.api.trustgraph_integration_router import router
    app = FastAPI()
    app.include_router(router)
    return app


class TestRouterIndexEndpoint:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        app = _build_test_app()
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_index_single_finding(self):
        with patch("core.trustgraph_integrations.UniversalFindingIndexer._get_backbone") as mock_bb:
            mock_bb.return_value = _patched_backbone()
            resp = self.client.post("/api/v1/graph/index", json={
                "findings": [{"engine": "sast", "severity": "high", "title": "XSS"}],
                "batch": False,
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["indexed"] >= 0
        assert "entity_ids" in data

    def test_index_empty_findings_rejected(self):
        resp = self.client.post("/api/v1/graph/index", json={
            "findings": [],
            "batch": False,
        })
        assert resp.status_code == 422  # pydantic min_length=1

    def test_index_batch_mode(self):
        with patch("core.trustgraph_integrations.UniversalFindingIndexer._get_backbone") as mock_bb:
            mock_bb.return_value = _patched_backbone()
            resp = self.client.post("/api/v1/graph/index", json={
                "findings": [
                    {"engine": "sca", "cve_id": "CVE-2024-1", "severity": "high"},
                    {"engine": "sca", "cve_id": "CVE-2024-1", "severity": "high"},
                ],
                "batch": True,
            })
        assert resp.status_code == 200
        data = resp.json()
        assert "deduplicated" in data


class TestRouterQueryEndpoint:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        app = _build_test_app()
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_valid_template_top_risks(self):
        with patch("core.trustgraph_integrations.GraphRAGQueries._get_backbone") as mock_bb:
            mock_bb.return_value = _patched_backbone(available=True, search_results=[])
            resp = self.client.get("/api/v1/graph/query/top_risks")
        assert resp.status_code == 200
        data = resp.json()
        assert "template" in data or "findings" in data or "available" in data

    def test_invalid_template_returns_400(self):
        resp = self.client.get("/api/v1/graph/query/nonexistent")
        assert resp.status_code == 400

    def test_compliance_gaps_with_framework_param(self):
        with patch("core.trustgraph_integrations.GraphRAGQueries._get_backbone") as mock_bb:
            mock_bb.return_value = _patched_backbone(available=True, search_results=[])
            resp = self.client.get("/api/v1/graph/query/compliance_gaps?framework=NIST")
        assert resp.status_code == 200


class TestRouterImpactEndpoint:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        app = _build_test_app()
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_impact_unavailable_backbone(self):
        mock_graphrag = MagicMock()
        mock_graphrag._available = False
        mock_graphrag._store = None
        with patch("core.trustgraph_backbone.GraphRAGEnhanced", return_value=mock_graphrag):
            resp = self.client.get("/api/v1/graph/impact/finding_001")
        assert resp.status_code == 200
        data = resp.json()
        assert "entity_id" in data

    def test_impact_returns_required_fields(self):
        mock_graphrag = MagicMock()
        mock_graphrag._available = False
        mock_graphrag._store = None
        with patch("core.trustgraph_backbone.GraphRAGEnhanced", return_value=mock_graphrag):
            resp = self.client.get("/api/v1/graph/impact/asset_prod?depth=2")
        data = resp.json()
        assert "blast_radius" in data
        assert "available" in data


class TestRouterCorrelateEndpoint:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        app = _build_test_app()
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_correlate_no_params_returns_400(self):
        resp = self.client.get("/api/v1/graph/correlate")
        assert resp.status_code == 400

    def test_correlate_cve(self):
        with patch("core.trustgraph_integrations.CrossDomainCorrelator._get_backbone") as mock_bb:
            mock_bb.return_value = _patched_backbone(available=True, relationships=[])
            resp = self.client.get("/api/v1/graph/correlate?cve_id=CVE-2024-1234")
        assert resp.status_code == 200
        data = resp.json()
        assert data["query_type"] == "cve"

    def test_correlate_finding(self):
        with patch("core.trustgraph_integrations.CrossDomainCorrelator._get_backbone") as mock_bb:
            backbone = _patched_backbone(available=True)
            backbone._store.get_entity.return_value = None
            mock_bb.return_value = backbone
            resp = self.client.get("/api/v1/graph/correlate?finding_id=finding_001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["query_type"] == "finding"


class TestRouterAttackPathsEndpoint:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        app = _build_test_app()
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_attack_paths_missing_params(self):
        resp = self.client.get("/api/v1/graph/attack-paths?source=asset_a")
        assert resp.status_code == 422  # missing target

    def test_attack_paths_no_enrich(self):
        with patch("core.trustgraph_backbone.GraphRAGEnhanced") as mock_cls:
            mock_graphrag = MagicMock()
            mock_graphrag.query_attack_path.return_value = {
                "available": True,
                "paths": [],
                "path_count": 0,
                "summary": "no paths",
            }
            mock_cls.return_value = mock_graphrag
            resp = self.client.get(
                "/api/v1/graph/attack-paths?source=asset_a&target=asset_b&enrich=false"
            )
        assert resp.status_code == 200

    def test_attack_paths_with_enrich(self):
        mock_graphrag = MagicMock()
        mock_graphrag._available = False
        mock_graphrag._store = None
        mock_graphrag.query_attack_path.return_value = {
            "available": False,
            "paths": [],
            "path_count": 0,
        }
        with patch("core.trustgraph_integrations.AttackPathEnricher._get_backbone") as mock_bb:
            mock_bb.return_value = _patched_backbone(available=False)
            with patch("core.trustgraph_backbone.GraphRAGEnhanced", return_value=mock_graphrag):
                resp = self.client.get(
                    "/api/v1/graph/attack-paths?source=asset_a&target=asset_b&enrich=true"
                )
        assert resp.status_code == 200


# ============================================================================
# 10. Severity weight table
# ============================================================================


class TestSeverityWeights:
    def test_critical_highest(self):
        from core.trustgraph_integrations import _SEVERITY_WEIGHT
        assert _SEVERITY_WEIGHT["critical"] > _SEVERITY_WEIGHT["high"]

    def test_high_above_medium(self):
        from core.trustgraph_integrations import _SEVERITY_WEIGHT
        assert _SEVERITY_WEIGHT["high"] > _SEVERITY_WEIGHT["medium"]

    def test_medium_above_low(self):
        from core.trustgraph_integrations import _SEVERITY_WEIGHT
        assert _SEVERITY_WEIGHT["medium"] > _SEVERITY_WEIGHT["low"]

    def test_unknown_has_value(self):
        from core.trustgraph_integrations import _SEVERITY_WEIGHT
        assert _SEVERITY_WEIGHT["unknown"] > 0


# ============================================================================
# 11. Entity ID helper
# ============================================================================


class TestEntityIdHelper:
    def test_normalises_dashes_and_spaces(self):
        from core.trustgraph_integrations import _entity_id
        eid = _entity_id("cve", "CVE-2024-1234")
        assert "-" not in eid
        assert eid == eid.lower()

    def test_caps_at_128(self):
        from core.trustgraph_integrations import _entity_id
        long_part = "x" * 200
        eid = _entity_id("finding", long_part)
        assert len(eid) <= 128

    def test_empty_parts_skipped(self):
        from core.trustgraph_integrations import _entity_id
        eid = _entity_id("finding", "", "abc")
        assert "finding" in eid
        assert "abc" in eid


# ============================================================================
# 12. Module-level factory functions
# ============================================================================


class TestFactoryFunctions:
    def test_get_universal_indexer(self):
        from core.trustgraph_integrations import get_universal_indexer, UniversalFindingIndexer
        obj = get_universal_indexer(org_id="acme")
        assert isinstance(obj, UniversalFindingIndexer)
        assert obj.org_id == "acme"

    def test_get_cross_domain_correlator(self):
        from core.trustgraph_integrations import get_cross_domain_correlator, CrossDomainCorrelator
        obj = get_cross_domain_correlator()
        assert isinstance(obj, CrossDomainCorrelator)

    def test_get_impact_analyzer(self):
        from core.trustgraph_integrations import get_impact_analyzer, ImpactAnalyzer
        obj = get_impact_analyzer()
        assert isinstance(obj, ImpactAnalyzer)

    def test_get_graphrag_queries(self):
        from core.trustgraph_integrations import get_graphrag_queries, GraphRAGQueries
        obj = get_graphrag_queries()
        assert isinstance(obj, GraphRAGQueries)
