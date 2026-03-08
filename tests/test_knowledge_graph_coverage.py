"""Tests for enterprise knowledge graph — entities, relations, entity extraction.

networkx may fail on Python 3.14 — we mock it to test the module.
"""
import sys
import types
from unittest.mock import MagicMock

import pytest


def _make_kg_importable():
    """Ensure knowledge_graph can be imported even if networkx fails."""
    try:
        import core.services.enterprise.knowledge_graph as kg
        return kg
    except (ImportError, AttributeError):
        pass

    # Mock networkx
    mock_nx = types.ModuleType("networkx")
    mock_nx.DiGraph = MagicMock
    mock_nx.Graph = MagicMock
    mock_nx.NetworkXNoPath = type("NetworkXNoPath", (Exception,), {})
    mock_nx.shortest_path = MagicMock(return_value=[])

    saved = sys.modules.get("networkx")
    sys.modules["networkx"] = mock_nx
    try:
        import importlib
        if "core.services.enterprise.knowledge_graph" in sys.modules:
            importlib.reload(sys.modules["core.services.enterprise.knowledge_graph"])
        else:
            pass
        return sys.modules["core.services.enterprise.knowledge_graph"]
    except Exception:
        pytest.skip("Cannot import knowledge_graph even with mocks", allow_module_level=True)
    finally:
        if saved is None:
            sys.modules.pop("networkx", None)
        else:
            sys.modules["networkx"] = saved


kg = _make_kg_importable()
SecurityEntity = kg.SecurityEntity
SecurityRelation = kg.SecurityRelation
CTINexusEntityExtractor = kg.CTINexusEntityExtractor


class TestSecurityEntity:
    def test_create_vulnerability(self):
        entity = SecurityEntity(
            entity_id="vuln-001", entity_type="vulnerability",
            name="CVE-2024-1234",
            properties={"cvss": 9.8, "cwe": "CWE-89"},
            confidence=0.95,
        )
        assert entity.entity_id == "vuln-001"
        assert entity.entity_type == "vulnerability"
        assert entity.properties["cvss"] == 9.8

    def test_create_component(self):
        entity = SecurityEntity(
            entity_id="comp-001", entity_type="component",
            name="spring-boot-3.2.0",
            properties={"version": "3.2.0"}, confidence=1.0,
        )
        assert entity.entity_type == "component"

    def test_create_threat_actor(self):
        entity = SecurityEntity(
            entity_id="ta-001", entity_type="threat_actor",
            name="APT29", properties={"country": "RU"}, confidence=0.8,
        )
        assert entity.entity_type == "threat_actor"

    def test_create_service(self):
        entity = SecurityEntity(
            entity_id="svc-001", entity_type="service",
            name="auth-service", properties={"port": 8443}, confidence=1.0,
        )
        assert entity.entity_type == "service"

    def test_create_technique(self):
        entity = SecurityEntity(
            entity_id="tech-001", entity_type="technique",
            name="T1059.001", properties={"tactic": "execution"}, confidence=0.9,
        )
        assert entity.entity_type == "technique"

    def test_empty_properties(self):
        entity = SecurityEntity(
            entity_id="empty-001", entity_type="vulnerability",
            name="Unknown", properties={}, confidence=0.0,
        )
        assert entity.properties == {}


class TestSecurityRelation:
    def test_exploits(self):
        rel = SecurityRelation(
            source_id="ta-001", target_id="vuln-001",
            relation_type="exploits",
            properties={"first_seen": "2024-01-01"}, confidence=0.9,
        )
        assert rel.relation_type == "exploits"

    def test_depends_on(self):
        rel = SecurityRelation(
            source_id="comp-001", target_id="comp-002",
            relation_type="depends_on",
            properties={"scope": "runtime"}, confidence=1.0,
        )
        assert rel.relation_type == "depends_on"

    def test_mitigates(self):
        rel = SecurityRelation(
            source_id="fix-001", target_id="vuln-001",
            relation_type="mitigates",
            properties={"effectiveness": 0.95}, confidence=0.85,
        )
        assert rel.relation_type == "mitigates"

    def test_affects(self):
        rel = SecurityRelation(
            source_id="vuln-001", target_id="svc-001",
            relation_type="affects",
            properties={"impact": "high"}, confidence=0.75,
        )
        assert rel.relation_type == "affects"


class TestCTINexusEntityExtractor:
    def test_init_without_api_key(self):
        extractor = CTINexusEntityExtractor()
        assert extractor is not None
        assert extractor.llm_client is None

    def test_cybersecurity_ontology_loaded(self):
        extractor = CTINexusEntityExtractor()
        ontology = extractor.cybersecurity_ontology
        assert isinstance(ontology, dict)
        assert "vulnerability" in ontology
        assert "threat_actor" in ontology

    def test_demonstration_examples_loaded(self):
        extractor = CTINexusEntityExtractor()
        examples = extractor.demonstration_examples
        assert isinstance(examples, (list, dict))

    def test_vulnerability_keywords(self):
        extractor = CTINexusEntityExtractor()
        vuln_keywords = extractor.cybersecurity_ontology.get("vulnerability", [])
        assert "CVE" in vuln_keywords

    def test_threat_actor_keywords(self):
        extractor = CTINexusEntityExtractor()
        ta_keywords = extractor.cybersecurity_ontology.get("threat_actor", [])
        assert "APT" in ta_keywords
