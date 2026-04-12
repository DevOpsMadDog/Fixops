"""Tests for TrustGraph Indexer — Populates 5 Knowledge Cores.

Validates that the indexer correctly creates entities and relationships
across all 5 cores from existing codebase data.
"""

import pytest
from core.trustgraph_indexer import TrustGraphIndexer, run_indexer


@pytest.fixture
def indexer():
    """Create a fresh indexer with test org."""
    return TrustGraphIndexer(org_id="test_org")


@pytest.fixture
def indexed_data(indexer):
    """Run full indexer and return stats."""
    return indexer.index_all()


class TestIndexerSetup:
    """Test indexer initialization and basic flow."""

    def test_indexer_creation(self):
        idx = TrustGraphIndexer(org_id="test")
        assert idx.org_id == "test"
        assert idx._store is None  # Lazy init

    def test_indexer_default_org(self):
        idx = TrustGraphIndexer()
        assert idx.org_id == "default"

    def test_run_indexer_convenience(self):
        stats = run_indexer(org_id="test_run")
        assert "total" in stats
        assert stats["total"] > 0
        assert "core_stats" in stats


class TestCore1CustomerEnvironment:
    """Test Core 1: Connectors and Scanner indexing."""

    def test_connectors_indexed(self, indexer):
        count = indexer.index_connectors()
        assert count > 0

    def test_bidirectional_connectors(self, indexer):
        indexer.index_connectors()
        store = indexer._get_store()
        # Should have Jira connector
        entity = store.get_entity("connector_jira")
        assert entity is not None
        assert entity.core_id == 1
        assert entity.entity_type == "Service"
        assert "bidirectional" in entity.properties.get("type", "")

    def test_security_connectors(self, indexer):
        indexer.index_connectors()
        store = indexer._get_store()
        entity = store.get_entity("connector_snyk")
        assert entity is not None
        assert entity.core_id == 1
        assert "pull" in entity.properties.get("type", "")

    def test_scanner_normalizers_indexed(self, indexer):
        indexer.index_connectors()
        store = indexer._get_store()
        # Check for a scanner entity
        entity = store.get_entity("scanner_zap")
        assert entity is not None
        assert entity.properties.get("has_normalizer") is True

    def test_core1_stats(self, indexed_data):
        stats = indexed_data["core_stats"][1]
        assert stats["entity_count"] >= 18  # At least bidirectional + security connectors


class TestCore2ThreatIntelligence:
    """Test Core 2: Threat feeds and MITRE ATT&CK indexing."""

    def test_threat_feeds_indexed(self, indexer):
        count = indexer.index_threat_feeds()
        assert count >= 28  # 28 feeds + TTPs

    def test_nvd_feed_entity(self, indexer):
        indexer.index_threat_feeds()
        store = indexer._get_store()
        entity = store.get_entity("feed_nvd")
        assert entity is not None
        assert entity.core_id == 2
        assert entity.entity_type == "Threat"
        assert entity.properties.get("category") == "government"

    def test_mitre_ttps(self, indexer):
        indexer.index_threat_feeds()
        store = indexer._get_store()
        entity = store.get_entity("ttp_T1190")
        assert entity is not None
        assert entity.entity_type == "TTP"
        assert entity.properties.get("tactic") == "Initial Access"

    def test_feed_categories(self, indexer):
        indexer.index_threat_feeds()
        store = indexer._get_store()
        cat = store.get_entity("feed_category_government")
        assert cat is not None
        assert cat.entity_type == "Campaign"

    def test_core2_stats(self, indexed_data):
        stats = indexed_data["core_stats"][2]
        assert stats["entity_count"] >= 28


class TestCore3Compliance:
    """Test Core 3: Compliance frameworks and controls."""

    def test_compliance_indexed(self, indexer):
        count = indexer.index_compliance_frameworks()
        assert count >= 7  # At least 7 frameworks

    def test_soc2_framework(self, indexer):
        indexer.index_compliance_frameworks()
        store = indexer._get_store()
        entity = store.get_entity("framework_soc2")
        assert entity is not None
        assert entity.core_id == 3
        assert entity.entity_type == "Framework"
        assert entity.properties.get("control_count") > 0

    def test_soc2_controls(self, indexer):
        indexer.index_compliance_frameworks()
        store = indexer._get_store()
        entity = store.get_entity("control_soc2_CC6")
        assert entity is not None
        assert entity.entity_type == "Control"
        assert entity.properties.get("framework") == "soc2"

    def test_all_seven_frameworks(self, indexer):
        indexer.index_compliance_frameworks()
        store = indexer._get_store()
        frameworks = ["soc2", "hipaa", "pci_dss", "iso27001", "nist_csf", "gdpr", "fedramp"]
        for fw in frameworks:
            entity = store.get_entity(f"framework_{fw}")
            assert entity is not None, f"Framework {fw} not indexed"

    def test_core3_stats(self, indexed_data):
        stats = indexed_data["core_stats"][3]
        assert stats["entity_count"] >= 7
        assert "Control" in stats.get("entity_types", {})
        assert "Framework" in stats.get("entity_types", {})


class TestCore4DecisionMemory:
    """Test Core 4: Decision patterns seeding."""

    def test_decision_patterns_indexed(self, indexer):
        count = indexer.index_decision_patterns()
        assert count == 8

    def test_critical_rce_pattern(self, indexer):
        indexer.index_decision_patterns()
        store = indexer._get_store()
        entity = store.get_entity("pattern_critical_rce")
        assert entity is not None
        assert entity.core_id == 4
        assert entity.entity_type == "Decision"
        assert entity.properties.get("action") == "block"

    def test_all_patterns_have_actions(self, indexer):
        indexer.index_decision_patterns()
        store = indexer._get_store()
        pattern_ids = [
            "pattern_critical_rce", "pattern_kev_active", "pattern_low_epss",
            "pattern_supply_chain", "pattern_false_positive", "pattern_config_drift",
            "pattern_secret_leak", "pattern_container_vuln",
        ]
        for pid in pattern_ids:
            entity = store.get_entity(pid)
            assert entity is not None, f"Pattern {pid} not indexed"
            assert "action" in entity.properties


class TestCore5CompetitiveIntel:
    """Test Core 5: Competitor and capability indexing."""

    def test_competitive_indexed(self, indexer):
        count = indexer.index_competitive_intel()
        assert count >= 10  # 9 competitors + ALDECI

    def test_competitor_entity(self, indexer):
        indexer.index_competitive_intel()
        store = indexer._get_store()
        entity = store.get_entity("competitor_wiz")
        assert entity is not None
        assert entity.core_id == 5
        assert entity.entity_type == "Competitor"
        assert "CNAPP" in entity.properties.get("category", "")

    def test_aldeci_product_entity(self, indexer):
        indexer.index_competitive_intel()
        store = indexer._get_store()
        entity = store.get_entity("competitor_aldeci")
        assert entity is not None
        assert entity.entity_type == "Product"
        assert "TrustGraph" in str(entity.properties.get("differentiators", []))

    def test_capability_entities(self, indexer):
        indexer.index_competitive_intel()
        store = indexer._get_store()
        entity = store.get_entity("capability_sca")
        assert entity is not None
        assert entity.entity_type == "Capability"


class TestCrossCoreRelationships:
    """Test cross-core relationship creation."""

    def test_cross_core_relationships(self, indexer):
        # First index all cores
        indexer.index_connectors()
        indexer.index_threat_feeds()
        indexer.index_compliance_frameworks()
        count = indexer.index_cross_core_relationships()
        assert count >= 5

    def test_connector_feed_relationship(self, indexer):
        indexer.index_connectors()
        indexer.index_threat_feeds()
        indexer.index_cross_core_relationships()
        store = indexer._get_store()
        rels = store.get_relationships("connector_snyk")
        assert len(rels) > 0
        rel_types = [r.rel_type for r in rels]
        assert "consumes" in rel_types


class TestFullIndexing:
    """Test complete indexing pipeline."""

    def test_full_index_all(self, indexed_data):
        assert indexed_data["total"] > 100
        assert indexed_data["core_1_connectors"] > 0
        assert indexed_data["core_2_threat_intel"] > 0
        assert indexed_data["core_3_compliance"] > 0
        assert indexed_data["core_4_decisions"] > 0
        assert indexed_data["core_5_competitive"] > 0
        assert indexed_data["cross_core_relationships"] > 0

    def test_all_cores_have_entities(self, indexed_data):
        for core_id in range(1, 6):
            assert indexed_data["core_stats"][core_id]["entity_count"] > 0

    def test_idempotent_indexing(self, indexer):
        """Running indexer twice should not duplicate entities."""
        stats1 = indexer.index_all()
        stats2 = indexer.index_all()
        # Entity counts should be identical (upsert, not insert)
        for core_id in range(1, 6):
            assert stats1["core_stats"][core_id]["entity_count"] == stats2["core_stats"][core_id]["entity_count"]
