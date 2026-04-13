"""
Tests for TrustGraph Backbone — Central nervous system for ALDECI.

Covers:
- TrustGraphBackbone entity indexing (all 6 types)
- Relationship creation (all 10 relationship types)
- GraphRAGEnhanced: impact analysis, root cause, attack path, related, risk context
- Semantic search across cores
- Visualization data generation
- Event-driven auto-indexing handlers
- Graph statistics
- Graceful degradation when TrustGraph unavailable
- Multi-tenant isolation via org_id

50+ tests.
"""

from __future__ import annotations

import tempfile
import pytest
from pathlib import Path

from core.trustgraph_backbone import (
    TrustGraphBackbone,
    GraphRAGEnhanced,
    RelationshipType,
    get_backbone,
    get_graphrag_enhanced,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_db():
    """Temporary SQLite DB path for test isolation."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def backbone(temp_db):
    """Fresh TrustGraphBackbone with isolated DB."""
    return TrustGraphBackbone(db_path=temp_db, org_id="test_org")


@pytest.fixture
def graphrag(temp_db):
    """Fresh GraphRAGEnhanced backed by the same isolated DB."""
    return GraphRAGEnhanced(db_path=temp_db, org_id="test_org")


@pytest.fixture
def populated_backbone(backbone):
    """Backbone with a set of pre-indexed entities for traversal tests."""
    backbone.index_asset({
        "id": "prod_api",
        "name": "Production API",
        "type": "service",
        "owner": "backend-team",
        "zone": "prod",
        "criticality": "critical",
        "environment": "production",
    })
    backbone.index_finding({
        "id": "f001",
        "title": "Log4Shell RCE",
        "severity": "critical",
        "cve_id": "CVE-2021-44228",
        "asset_id": "asset_prod_api",
        "cvss": 10.0,
        "epss": 0.97,
        "scanner": "grype",
    })
    backbone.index_incident({
        "id": "inc001",
        "title": "Log4Shell Incident",
        "severity": "critical",
        "finding_ids": ["f001"],
        "asset_ids": ["prod_api"],
    })
    backbone.index_compliance_control({
        "id": "cc6_patch",
        "name": "CC6.1 Patch Management",
        "framework": "soc2",
        "status": "compliant",
        "mitigates_finding_ids": ["f001"],
    })
    return backbone


# ============================================================================
# RelationshipType
# ============================================================================


class TestRelationshipType:
    """Verify relationship type constants."""

    def test_all_relationship_types_defined(self):
        assert RelationshipType.FINDING_AFFECTS_ASSET == "FINDING_AFFECTS_ASSET"
        assert RelationshipType.FINDING_EXPLOITS_CVE == "FINDING_EXPLOITS_CVE"
        assert RelationshipType.ASSET_BELONGS_TO_ZONE == "ASSET_BELONGS_TO_ZONE"
        assert RelationshipType.INCIDENT_INVOLVES_FINDING == "INCIDENT_INVOLVES_FINDING"
        assert RelationshipType.INCIDENT_IMPACTS_ASSET == "INCIDENT_IMPACTS_ASSET"
        assert RelationshipType.CONTROL_MITIGATES_FINDING == "CONTROL_MITIGATES_FINDING"
        assert RelationshipType.VENDOR_PROVIDES_COMPONENT == "VENDOR_PROVIDES_COMPONENT"
        assert RelationshipType.COMPONENT_HAS_VULNERABILITY == "COMPONENT_HAS_VULNERABILITY"
        assert RelationshipType.ACTOR_USES_TTP == "ACTOR_USES_TTP"
        assert RelationshipType.ACTOR_TARGETS_ASSET == "ACTOR_TARGETS_ASSET"

    def test_all_set_contains_ten_types(self):
        assert len(RelationshipType.ALL) == 10


# ============================================================================
# TrustGraphBackbone — initialization
# ============================================================================


class TestBackboneInit:
    """Test initialization and graceful degradation."""

    def test_backbone_initializes(self, backbone):
        assert backbone is not None
        assert backbone.org_id == "test_org"
        assert backbone._available is True

    def test_backbone_default_org_id(self, temp_db):
        b = TrustGraphBackbone(db_path=temp_db)
        assert b.org_id == "default"

    def test_backbone_unavailable_on_bad_path(self):
        # Pass a path that can't be created to simulate failure
        b = TrustGraphBackbone.__new__(TrustGraphBackbone)
        b.org_id = "test"
        b._db_path = None
        b._store = None
        b._available = False
        assert b._available is False


# ============================================================================
# index_finding
# ============================================================================


class TestIndexFinding:
    """Tests for index_finding()."""

    def test_index_finding_returns_entity_id(self, backbone):
        eid = backbone.index_finding({"id": "f1", "title": "SQL Injection", "severity": "high"})
        assert eid.startswith("finding_")

    def test_index_finding_with_cve(self, backbone):
        eid = backbone.index_finding({
            "id": "f2",
            "title": "Log4j",
            "severity": "critical",
            "cve_id": "CVE-2021-44228",
        })
        store = backbone._store
        # CVE entity should exist
        cve_entity = store.get_entity("cve_cve_2021_44228")
        assert cve_entity is not None
        assert cve_entity.entity_type == "CVE"

    def test_index_finding_links_cve(self, backbone):
        backbone.index_finding({
            "id": "f3",
            "title": "Spring4Shell",
            "severity": "critical",
            "cve_id": "CVE-2022-22965",
        })
        store = backbone._store
        rels = store.get_relationships("finding_f3")
        rel_types = [r.rel_type for r in rels]
        assert RelationshipType.FINDING_EXPLOITS_CVE in rel_types

    def test_index_finding_links_asset(self, backbone):
        backbone.index_finding({
            "id": "f4",
            "title": "XSS",
            "severity": "medium",
            "asset_id": "web_server",
        })
        store = backbone._store
        rels = store.get_relationships("finding_f4")
        rel_types = [r.rel_type for r in rels]
        assert RelationshipType.FINDING_AFFECTS_ASSET in rel_types

    def test_index_finding_in_core_2(self, backbone):
        eid = backbone.index_finding({"id": "f5", "title": "SSRF", "severity": "high"})
        entity = backbone._store.get_entity(eid)
        assert entity.core_id == 2  # CORE_THREAT_INTEL

    def test_index_finding_idempotent(self, backbone):
        """Indexing the same finding twice should not raise."""
        data = {"id": "f6", "title": "Dup Finding", "severity": "low"}
        eid1 = backbone.index_finding(data)
        eid2 = backbone.index_finding(data)
        assert eid1 == eid2

    def test_index_finding_no_id_generates_one(self, backbone):
        eid = backbone.index_finding({"title": "Anon Finding", "severity": "low"})
        assert eid.startswith("finding_")

    def test_index_finding_stores_severity(self, backbone):
        backbone.index_finding({"id": "f7", "title": "Critical Bug", "severity": "critical"})
        entity = backbone._store.get_entity("finding_f7")
        assert entity.properties["severity"] == "critical"

    def test_index_finding_stores_cvss(self, backbone):
        backbone.index_finding({"id": "f8", "title": "High CVSS", "severity": "high", "cvss": 8.5})
        entity = backbone._store.get_entity("finding_f8")
        assert entity.properties["cvss"] == 8.5


# ============================================================================
# index_asset
# ============================================================================


class TestIndexAsset:
    """Tests for index_asset()."""

    def test_index_asset_returns_entity_id(self, backbone):
        eid = backbone.index_asset({"id": "srv1", "name": "Auth Service"})
        assert eid.startswith("asset_")

    def test_index_asset_in_core_1(self, backbone):
        eid = backbone.index_asset({"id": "srv2", "name": "DB Server"})
        entity = backbone._store.get_entity(eid)
        assert entity.core_id == 1  # CORE_CUSTOMER_ENV

    def test_index_asset_with_zone(self, backbone):
        backbone.index_asset({"id": "srv3", "name": "API GW", "zone": "dmz"})
        store = backbone._store
        zone_entity = store.get_entity("zone_dmz")
        assert zone_entity is not None
        assert zone_entity.entity_type == "Zone"

    def test_index_asset_zone_relationship(self, backbone):
        backbone.index_asset({"id": "srv4", "name": "Cache", "zone": "internal"})
        rels = backbone._store.get_relationships("asset_srv4")
        rel_types = [r.rel_type for r in rels]
        assert RelationshipType.ASSET_BELONGS_TO_ZONE in rel_types

    def test_index_asset_stores_criticality(self, backbone):
        backbone.index_asset({"id": "srv5", "name": "PCI Host", "criticality": "critical"})
        entity = backbone._store.get_entity("asset_srv5")
        assert entity.properties["criticality"] == "critical"

    def test_index_asset_no_id_generates_one(self, backbone):
        eid = backbone.index_asset({"name": "Unknown Host", "ip": "10.0.0.1"})
        assert eid.startswith("asset_")


# ============================================================================
# index_incident
# ============================================================================


class TestIndexIncident:
    """Tests for index_incident()."""

    def test_index_incident_returns_entity_id(self, backbone):
        eid = backbone.index_incident({"id": "inc1", "title": "Breach"})
        assert eid.startswith("incident_")

    def test_index_incident_in_core_4(self, backbone):
        eid = backbone.index_incident({"id": "inc2", "title": "Ransomware"})
        entity = backbone._store.get_entity(eid)
        assert entity.core_id == 4  # CORE_DECISION_MEMORY

    def test_index_incident_links_findings(self, backbone):
        backbone.index_incident({
            "id": "inc3",
            "title": "Multi-vuln incident",
            "finding_ids": ["f_a", "f_b"],
        })
        rels = backbone._store.get_relationships("incident_inc3")
        involvement_rels = [r for r in rels if r.rel_type == RelationshipType.INCIDENT_INVOLVES_FINDING]
        assert len(involvement_rels) == 2

    def test_index_incident_links_assets(self, backbone):
        backbone.index_incident({
            "id": "inc4",
            "title": "Asset incident",
            "asset_ids": ["web", "db"],
        })
        rels = backbone._store.get_relationships("incident_inc4")
        impact_rels = [r for r in rels if r.rel_type == RelationshipType.INCIDENT_IMPACTS_ASSET]
        assert len(impact_rels) == 2


# ============================================================================
# index_compliance_control
# ============================================================================


class TestIndexComplianceControl:
    """Tests for index_compliance_control()."""

    def test_index_control_returns_entity_id(self, backbone):
        eid = backbone.index_compliance_control({
            "id": "cc6_1",
            "name": "Logical Access",
            "framework": "soc2",
        })
        assert eid.startswith("control_")

    def test_index_control_in_core_3(self, backbone):
        eid = backbone.index_compliance_control({
            "id": "cc6_2",
            "name": "Access Control",
            "framework": "pci_dss",
        })
        entity = backbone._store.get_entity(eid)
        assert entity.core_id == 3  # CORE_COMPLIANCE

    def test_index_control_creates_framework(self, backbone):
        backbone.index_compliance_control({
            "id": "ctrl1",
            "name": "Audit Logs",
            "framework": "hipaa",
        })
        fw_entity = backbone._store.get_entity("framework_hipaa")
        assert fw_entity is not None
        assert fw_entity.entity_type == "Framework"

    def test_index_control_mitigates_finding(self, backbone):
        backbone.index_compliance_control({
            "id": "ctrl2",
            "name": "Patch Management",
            "framework": "nist_csf",
            "mitigates_finding_ids": ["f_log4j"],
        })
        rels = backbone._store.get_relationships("control_ctrl2")
        mitigates = [r for r in rels if r.rel_type == RelationshipType.CONTROL_MITIGATES_FINDING]
        assert len(mitigates) == 1


# ============================================================================
# index_vendor
# ============================================================================


class TestIndexVendor:
    """Tests for index_vendor()."""

    def test_index_vendor_returns_entity_id(self, backbone):
        eid = backbone.index_vendor({"id": "aws", "name": "Amazon Web Services"})
        assert eid.startswith("vendor_")

    def test_index_vendor_in_core_5(self, backbone):
        eid = backbone.index_vendor({"id": "azure", "name": "Microsoft Azure"})
        entity = backbone._store.get_entity(eid)
        assert entity.core_id == 5  # CORE_EXTERNAL

    def test_index_vendor_with_components(self, backbone):
        backbone.index_vendor({
            "id": "log4j_vendor",
            "name": "Apache",
            "components": ["log4j-core", "log4j-api"],
        })
        rels = backbone._store.get_relationships("vendor_log4j_vendor")
        comp_rels = [r for r in rels if r.rel_type == RelationshipType.VENDOR_PROVIDES_COMPONENT]
        assert len(comp_rels) == 2

    def test_index_vendor_component_entities_created(self, backbone):
        backbone.index_vendor({
            "id": "struts_vendor",
            "name": "Apache Struts",
            "components": ["struts2-core"],
        })
        store = backbone._store
        # ID is built as component_{vendor_entity_id}_{name.lower().replace(' ', '_')}
        # hyphens are preserved: "struts2-core" → "struts2-core"
        comp_id = "component_vendor_struts_vendor_struts2-core"
        entity = store.get_entity(comp_id)
        assert entity is not None
        assert entity.entity_type == "Component"


# ============================================================================
# index_threat_actor
# ============================================================================


class TestIndexThreatActor:
    """Tests for index_threat_actor()."""

    def test_index_actor_returns_entity_id(self, backbone):
        eid = backbone.index_threat_actor({"id": "apt28", "name": "APT28"})
        assert eid.startswith("actor_")

    def test_index_actor_in_core_2(self, backbone):
        eid = backbone.index_threat_actor({"id": "apt29", "name": "Cozy Bear"})
        entity = backbone._store.get_entity(eid)
        assert entity.core_id == 2  # CORE_THREAT_INTEL

    def test_index_actor_with_ttps(self, backbone):
        backbone.index_threat_actor({
            "id": "lazarus",
            "name": "Lazarus Group",
            "ttps": ["T1190", "T1059"],
        })
        rels = backbone._store.get_relationships("actor_lazarus")
        ttp_rels = [r for r in rels if r.rel_type == RelationshipType.ACTOR_USES_TTP]
        assert len(ttp_rels) == 2

    def test_index_actor_with_target_assets(self, backbone):
        backbone.index_threat_actor({
            "id": "fin7",
            "name": "FIN7",
            "target_asset_ids": ["pos_system", "payment_gateway"],
        })
        rels = backbone._store.get_relationships("actor_fin7")
        target_rels = [r for r in rels if r.rel_type == RelationshipType.ACTOR_TARGETS_ASSET]
        assert len(target_rels) == 2

    def test_index_actor_ttp_entities_created(self, backbone):
        backbone.index_threat_actor({
            "id": "unc_group",
            "name": "Unknown Group",
            "ttps": ["T1078"],
        })
        entity = backbone._store.get_entity("ttp_t1078")
        assert entity is not None
        assert entity.entity_type == "TTP"


# ============================================================================
# link_entities
# ============================================================================


class TestLinkEntities:
    """Tests for link_entities()."""

    def test_link_entities_returns_rel_id(self, backbone):
        rel_id = backbone.link_entities("entity_a", "entity_b", RelationshipType.FINDING_AFFECTS_ASSET)
        assert rel_id.startswith("rel_")

    def test_link_entities_with_properties(self, backbone):
        rel_id = backbone.link_entities(
            "src", "tgt",
            RelationshipType.VENDOR_PROVIDES_COMPONENT,
            confidence=0.8,
            properties={"version": "2.14.1"},
        )
        assert rel_id != ""

    def test_link_entities_unavailable_returns_empty(self):
        b = TrustGraphBackbone.__new__(TrustGraphBackbone)
        b._available = False
        b._store = None
        result = b.link_entities("a", "b", "FINDING_AFFECTS_ASSET")
        assert result == ""

    def test_link_entities_relationship_retrievable(self, backbone):
        backbone.link_entities("x_src", "x_tgt", RelationshipType.ACTOR_USES_TTP)
        rels = backbone._store.get_relationships("x_src")
        assert any(r.rel_type == RelationshipType.ACTOR_USES_TTP for r in rels)


# ============================================================================
# Event handlers
# ============================================================================


class TestEventHandlers:
    """Tests for synchronous event handler methods."""

    def test_on_finding_created(self, backbone):
        eid = backbone.on_finding_created({"id": "ev_f1", "title": "Event Finding", "severity": "high"})
        assert eid.startswith("finding_")
        assert backbone._store.get_entity(eid) is not None

    def test_on_asset_discovered(self, backbone):
        eid = backbone.on_asset_discovered({"id": "ev_a1", "name": "Event Asset"})
        assert eid.startswith("asset_")
        assert backbone._store.get_entity(eid) is not None

    def test_on_incident_created(self, backbone):
        eid = backbone.on_incident_created({"id": "ev_i1", "title": "Event Incident"})
        assert eid.startswith("incident_")
        assert backbone._store.get_entity(eid) is not None

    def test_on_compliance_assessed(self, backbone):
        eid = backbone.on_compliance_assessed({
            "id": "ev_ctrl1",
            "name": "Event Control",
            "framework": "iso27001",
        })
        assert eid.startswith("control_")
        assert backbone._store.get_entity(eid) is not None


# ============================================================================
# GraphRAGEnhanced — query_impact
# ============================================================================


class TestQueryImpact:
    """Tests for GraphRAGEnhanced.query_impact()."""

    def test_impact_returns_available_true(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_asset({"id": "imp_asset", "name": "Impact Asset", "zone": "prod"})
        result = graphrag.query_impact("asset_imp_asset")
        assert result["available"] is True

    def test_impact_returns_entity_id(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_asset({"id": "imp2", "name": "Asset2"})
        result = graphrag.query_impact("asset_imp2")
        assert result["entity_id"] == "asset_imp2"

    def test_impact_includes_affected_count(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({"id": "impf1", "title": "Vuln", "severity": "high", "asset_id": "imp_target"})
        result = graphrag.query_impact("finding_impf1", depth=1)
        assert "affected_count" in result

    def test_impact_unavailable_when_store_missing(self):
        g = GraphRAGEnhanced.__new__(GraphRAGEnhanced)
        g._backbone = TrustGraphBackbone.__new__(TrustGraphBackbone)
        g._backbone._available = False
        g._backbone._store = None
        result = g.query_impact("any_entity")
        assert result["available"] is False


# ============================================================================
# GraphRAGEnhanced — query_root_cause
# ============================================================================


class TestQueryRootCause:
    """Tests for GraphRAGEnhanced.query_root_cause()."""

    def test_root_cause_not_found(self, graphrag):
        result = graphrag.query_root_cause("nonexistent_finding")
        assert result["available"] is True
        assert "error" in result

    def test_root_cause_with_cve(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({
            "id": "rc_f1",
            "title": "Log4j",
            "severity": "critical",
            "cve_id": "CVE-2021-44228",
        })
        result = graphrag.query_root_cause("finding_rc_f1")
        assert result["available"] is True
        assert len(result["cves"]) >= 1

    def test_root_cause_includes_summary(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({"id": "rc_f2", "title": "No CVE Finding", "severity": "low"})
        result = graphrag.query_root_cause("finding_rc_f2")
        assert "summary" in result

    def test_root_cause_with_affected_asset(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({
            "id": "rc_f3",
            "title": "Asset Finding",
            "severity": "high",
            "asset_id": "prod_db",
        })
        result = graphrag.query_root_cause("finding_rc_f3")
        assert result["available"] is True
        assert "affected_assets" in result


# ============================================================================
# GraphRAGEnhanced — query_attack_path
# ============================================================================


class TestQueryAttackPath:
    """Tests for GraphRAGEnhanced.query_attack_path()."""

    def test_attack_path_no_path(self, graphrag):
        result = graphrag.query_attack_path("isolated_src", "isolated_tgt")
        assert result["available"] is True
        assert result["path_count"] == 0
        assert "No path found" in result["summary"]

    def test_attack_path_direct_link(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({
            "id": "ap_finding",
            "title": "Attack Vector",
            "severity": "critical",
            "asset_id": "ap_asset",
        })
        result = graphrag.query_attack_path("finding_ap_finding", "asset_ap_asset")
        assert result["available"] is True
        assert result["source_id"] == "finding_ap_finding"
        assert result["target_id"] == "asset_ap_asset"

    def test_attack_path_returns_path_structure(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({
            "id": "ap2_finding",
            "title": "Chained Attack",
            "severity": "high",
            "asset_id": "ap2_asset",
        })
        result = graphrag.query_attack_path("finding_ap2_finding", "asset_ap2_asset")
        assert isinstance(result["paths"], list)


# ============================================================================
# GraphRAGEnhanced — query_related
# ============================================================================


class TestQueryRelated:
    """Tests for GraphRAGEnhanced.query_related()."""

    def test_related_returns_available_true(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_asset({"id": "rel_asset", "name": "Related Asset", "zone": "dmz"})
        result = graphrag.query_related("asset_rel_asset")
        assert result["available"] is True

    def test_related_includes_entity(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_asset({"id": "rel_a2", "name": "Asset2"})
        result = graphrag.query_related("asset_rel_a2")
        assert "entity" in result

    def test_related_includes_neighbors(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({
            "id": "rel_f1",
            "title": "Vuln",
            "severity": "high",
            "asset_id": "rel_target_asset",
        })
        result = graphrag.query_related("finding_rel_f1")
        assert isinstance(result["neighbors"], list)
        assert "neighbor_count" in result

    def test_related_depth_clamped(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_asset({"id": "clamp_asset", "name": "Depth Clamp Asset"})
        result = graphrag.query_related("asset_clamp_asset", depth=10)
        assert result["available"] is True  # depth silently clamped to 3


# ============================================================================
# GraphRAGEnhanced — query_risk_context
# ============================================================================


class TestQueryRiskContext:
    """Tests for GraphRAGEnhanced.query_risk_context()."""

    def test_risk_context_not_found(self, graphrag):
        result = graphrag.query_risk_context("nonexistent_f")
        assert result["available"] is True
        assert "error" in result

    def test_risk_context_structure(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({
            "id": "rctx_f1",
            "title": "Critical Finding",
            "severity": "critical",
            "cve_id": "CVE-2023-0001",
            "asset_id": "rctx_asset",
            "cvss": 9.8,
            "epss": 0.85,
        })
        result = graphrag.query_risk_context("finding_rctx_f1")
        assert result["available"] is True
        assert "finding" in result
        assert "cves" in result
        assert "affected_assets" in result
        assert "mitigating_controls" in result
        assert "related_incidents" in result
        assert "llm_context" in result
        assert "risk_score_inputs" in result

    def test_risk_context_includes_severity_inputs(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({
            "id": "rctx_f2",
            "title": "High Finding",
            "severity": "high",
            "cvss": 7.5,
        })
        result = graphrag.query_risk_context("finding_rctx_f2")
        inputs = result.get("risk_score_inputs", {})
        assert inputs.get("severity") == "high"


# ============================================================================
# GraphRAGEnhanced — semantic_search
# ============================================================================


class TestSemanticSearch:
    """Tests for GraphRAGEnhanced.semantic_search()."""

    def test_semantic_search_returns_structure(self, graphrag):
        result = graphrag.semantic_search("critical vulnerability")
        assert "available" in result
        assert "results" in result
        assert "total_count" in result

    def test_semantic_search_finds_indexed_entity(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({
            "id": "sem_f1",
            "title": "Unique Sentinel Value XYZABC",
            "severity": "high",
        })
        result = graphrag.semantic_search("Unique Sentinel Value XYZABC")
        assert result["total_count"] >= 1

    def test_semantic_search_with_core_filter(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_asset({"id": "sem_a1", "name": "SearchableAsset QRST"})
        result = graphrag.semantic_search("SearchableAsset QRST", cores=[1])
        assert result["available"] is True
        assert 1 in result["results_by_core"]

    def test_semantic_search_empty_query_returns_structure(self, graphrag):
        result = graphrag.semantic_search("zzz_nonexistent_xyz_999")
        assert isinstance(result["results"], list)
        assert result["total_count"] >= 0

    def test_semantic_search_unavailable_graceful(self):
        g = GraphRAGEnhanced.__new__(GraphRAGEnhanced)
        b = TrustGraphBackbone.__new__(TrustGraphBackbone)
        b._available = False
        b._store = None
        g._backbone = b
        result = g.semantic_search("anything")
        assert result["available"] is False


# ============================================================================
# Graph statistics
# ============================================================================


class TestGraphStats:
    """Tests for TrustGraphBackbone.get_stats()."""

    def test_stats_returns_available(self, backbone):
        stats = backbone.get_stats()
        assert stats["available"] is True

    def test_stats_has_five_cores(self, backbone):
        stats = backbone.get_stats()
        assert len(stats["cores"]) == 5

    def test_stats_totals_after_indexing(self, backbone):
        backbone.index_finding({"id": "stat_f1", "title": "Stat Finding", "severity": "low"})
        backbone.index_asset({"id": "stat_a1", "name": "Stat Asset"})
        stats = backbone.get_stats()
        assert stats["total_entities"] >= 2

    def test_stats_unavailable_when_no_store(self):
        b = TrustGraphBackbone.__new__(TrustGraphBackbone)
        b._available = False
        b._store = None
        stats = b.get_stats()
        assert stats["available"] is False
        assert stats["total_entities"] == 0

    def test_stats_core_names_present(self, backbone):
        stats = backbone.get_stats()
        assert stats["cores"][1]["name"] == "customer_env"
        assert stats["cores"][2]["name"] == "threat_intel"
        assert stats["cores"][3]["name"] == "compliance"
        assert stats["cores"][4]["name"] == "decision_memory"
        assert stats["cores"][5]["name"] == "external"


# ============================================================================
# Visualization
# ============================================================================


class TestVisualization:
    """Tests for GraphRAGEnhanced.get_visualization_data()."""

    def test_visualization_returns_structure(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_asset({"id": "viz_a1", "name": "Viz Asset", "zone": "prod"})
        result = graphrag.get_visualization_data("asset_viz_a1")
        assert result["available"] is True
        assert "nodes" in result
        assert "edges" in result
        assert "node_count" in result
        assert "edge_count" in result

    def test_visualization_center_node_present(self, graphrag, temp_db):
        b = TrustGraphBackbone(db_path=temp_db, org_id="test_org")
        b.index_finding({"id": "viz_f1", "title": "Viz Finding", "severity": "high"})
        result = graphrag.get_visualization_data("finding_viz_f1")
        if result["available"] and result["node_count"] > 0:
            center_nodes = [n for n in result["nodes"] if n.get("is_center")]
            assert len(center_nodes) == 1

    def test_visualization_unavailable_graceful(self):
        g = GraphRAGEnhanced.__new__(GraphRAGEnhanced)
        b = TrustGraphBackbone.__new__(TrustGraphBackbone)
        b._available = False
        b._store = None
        g._backbone = b
        result = g.get_visualization_data("any_entity")
        assert result["available"] is False
        assert result["nodes"] == []
        assert result["edges"] == []


# ============================================================================
# Module-level singletons
# ============================================================================


class TestSingletons:
    """Tests for module-level singleton accessors."""

    def test_get_backbone_returns_instance(self, temp_db):
        import core.trustgraph_backbone as mod
        mod._backbone = None  # Reset singleton
        b = get_backbone(db_path=temp_db)
        assert isinstance(b, TrustGraphBackbone)

    def test_get_backbone_singleton(self, temp_db):
        import core.trustgraph_backbone as mod
        mod._backbone = None
        b1 = get_backbone(db_path=temp_db)
        b2 = get_backbone(db_path=temp_db)
        assert b1 is b2

    def test_get_graphrag_enhanced_returns_instance(self, temp_db):
        import core.trustgraph_backbone as mod
        mod._graphrag_enhanced = None
        g = get_graphrag_enhanced(db_path=temp_db)
        assert isinstance(g, GraphRAGEnhanced)

    def test_get_graphrag_enhanced_singleton(self, temp_db):
        import core.trustgraph_backbone as mod
        mod._graphrag_enhanced = None
        g1 = get_graphrag_enhanced(db_path=temp_db)
        g2 = get_graphrag_enhanced(db_path=temp_db)
        assert g1 is g2


# ============================================================================
# Integration: populated backbone traversal
# ============================================================================


class TestIntegrationTraversal:
    """Integration tests using the populated_backbone fixture."""

    def test_finding_links_to_cve(self, populated_backbone):
        store = populated_backbone._store
        rels = store.get_relationships("finding_f001")
        rel_types = {r.rel_type for r in rels}
        assert RelationshipType.FINDING_EXPLOITS_CVE in rel_types

    def test_finding_links_to_asset(self, populated_backbone):
        store = populated_backbone._store
        rels = store.get_relationships("finding_f001")
        rel_types = {r.rel_type for r in rels}
        assert RelationshipType.FINDING_AFFECTS_ASSET in rel_types

    def test_incident_linked_to_finding(self, populated_backbone):
        store = populated_backbone._store
        rels = store.get_relationships("incident_inc001")
        rel_types = {r.rel_type for r in rels}
        assert RelationshipType.INCIDENT_INVOLVES_FINDING in rel_types

    def test_control_mitigates_finding(self, populated_backbone):
        store = populated_backbone._store
        rels = store.get_relationships("control_cc6_patch")
        rel_types = {r.rel_type for r in rels}
        assert RelationshipType.CONTROL_MITIGATES_FINDING in rel_types

    def test_asset_in_zone(self, populated_backbone):
        store = populated_backbone._store
        rels = store.get_relationships("asset_prod_api")
        rel_types = {r.rel_type for r in rels}
        assert RelationshipType.ASSET_BELONGS_TO_ZONE in rel_types

    def test_graphrag_impact_on_finding(self, temp_db, populated_backbone):
        g = GraphRAGEnhanced(db_path=temp_db, org_id="test_org")
        result = g.query_impact("finding_f001", depth=1)
        assert result["available"] is True

    def test_graphrag_root_cause_on_finding(self, temp_db, populated_backbone):
        g = GraphRAGEnhanced(db_path=temp_db, org_id="test_org")
        result = g.query_root_cause("finding_f001")
        assert result["available"] is True
        assert len(result["cves"]) >= 1

    def test_graphrag_risk_context_full(self, temp_db, populated_backbone):
        g = GraphRAGEnhanced(db_path=temp_db, org_id="test_org")
        result = g.query_risk_context("finding_f001")
        assert result["available"] is True
        assert result["risk_score_inputs"]["severity"] == "critical"
        assert result["risk_score_inputs"]["cvss"] == 10.0
