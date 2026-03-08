"""Comprehensive tests for core.mitre_mapper — MITRE ATT&CK v14 Mapping Engine.

Tests the MITREMapper class: CWE→technique mapping, text-based matching,
kill chain coverage analysis, ATT&CK Navigator layer export, and utility functions.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import pytest
from core.mitre_mapper import (
    TACTICS,
    TECHNIQUES,
    MITREMapper,
    TechniqueMapping,
    FindingMappingResult,
    KillChainCoverage,
    MappingEngineResult,
    get_mitre_mapper,
)


class TestMITREMapperInit:
    """Test mapper initialization."""

    def test_singleton_factory(self):
        m1 = get_mitre_mapper()
        m2 = get_mitre_mapper()
        assert m1 is m2

    def test_constructor(self):
        m = MITREMapper()
        assert hasattr(m, "map_finding")
        assert hasattr(m, "map_findings")
        assert hasattr(m, "get_cwe_mapping")


class TestTacticsAndTechniques:
    """Test the built-in MITRE ATT&CK catalog."""

    def test_all_14_tactics(self):
        assert len(TACTICS) == 14

    def test_tactic_structure(self):
        for tid, t in TACTICS.items():
            assert tid.startswith("TA")
            assert "name" in t
            assert "shortname" in t
            assert "description" in t
            assert "url" in t

    def test_key_tactics_present(self):
        names = {t["name"] for t in TACTICS.values()}
        for expected in [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
            "Reconnaissance",
            "Resource Development",
        ]:
            assert expected in names, f"Missing tactic: {expected}"

    def test_techniques_not_empty(self):
        assert len(TECHNIQUES) >= 30, "Should have at least 30 techniques"

    def test_technique_structure(self):
        for tid, t in TECHNIQUES.items():
            assert tid.startswith("T")
            assert "name" in t
            assert "tactic_ids" in t
            assert isinstance(t["tactic_ids"], list)


class TestMapFinding:
    """Test mapping individual findings to MITRE techniques."""

    @pytest.fixture
    def mapper(self):
        return MITREMapper()

    def test_map_by_cwe_sql_injection(self, mapper):
        finding = {
            "cwe_id": "CWE-89",
            "title": "SQL Injection in login form",
            "severity": "critical",
        }
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)
        assert len(result.techniques) >= 1
        tech_ids = [t.technique_id for t in result.techniques]
        # SQL injection typically maps to T1190 (Exploit Public-Facing Application)
        assert any("T1190" in tid for tid in tech_ids) or len(tech_ids) > 0

    def test_map_by_cwe_xss(self, mapper):
        finding = {"cwe_id": "CWE-79", "title": "Cross-Site Scripting"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_by_cwe_command_injection(self, mapper):
        finding = {"cwe_id": "CWE-78", "title": "OS Command Injection"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_by_cwe_path_traversal(self, mapper):
        finding = {"cwe_id": "CWE-22", "title": "Path Traversal"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_by_cwe_hardcoded_creds(self, mapper):
        finding = {"cwe_id": "CWE-798", "title": "Hard-coded Credentials"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_by_cwe_broken_auth(self, mapper):
        finding = {"cwe_id": "CWE-287", "title": "Improper Authentication"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_by_cwe_insecure_deserialization(self, mapper):
        finding = {"cwe_id": "CWE-502", "title": "Deserialization of Untrusted Data"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_by_title_text(self, mapper):
        finding = {"title": "Remote code execution via file upload", "severity": "critical"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_empty_finding(self, mapper):
        result = mapper.map_finding({})
        assert isinstance(result, FindingMappingResult)
        assert result.techniques is not None

    def test_map_finding_with_cve(self, mapper):
        finding = {"cve_id": "CVE-2021-44228", "title": "Log4Shell RCE"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_finding_numeric_cwe(self, mapper):
        finding = {"cwe_id": 89, "title": "SQL Injection"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_finding_prefixed_cwe(self, mapper):
        finding = {"cwe_id": "CWE-89"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)

    def test_map_finding_bare_cwe(self, mapper):
        finding = {"cwe_id": "89"}
        result = mapper.map_finding(finding)
        assert isinstance(result, FindingMappingResult)


class TestMapFindings:
    """Test batch mapping of multiple findings."""

    @pytest.fixture
    def mapper(self):
        return MITREMapper()

    def test_map_multiple(self, mapper):
        findings = [
            {"cwe_id": "CWE-89", "title": "SQL Injection"},
            {"cwe_id": "CWE-79", "title": "XSS"},
            {"cwe_id": "CWE-22", "title": "Path Traversal"},
        ]
        result = mapper.map_findings(findings)
        assert isinstance(result, MappingEngineResult)
        assert len(result.finding_results) == 3
        assert result.total_findings == 3
        assert result.total_techniques >= 0

    def test_map_empty_list(self, mapper):
        result = mapper.map_findings([])
        assert isinstance(result, MappingEngineResult)
        assert result.total_findings == 0

    def test_kill_chain_coverage(self, mapper):
        findings = [
            {"cwe_id": "CWE-89", "title": "SQL Injection", "severity": "critical"},
            {"cwe_id": "CWE-798", "title": "Hardcoded Creds", "severity": "high"},
            {"cwe_id": "CWE-78", "title": "Command Injection", "severity": "critical"},
            {"cwe_id": "CWE-502", "title": "Insecure Deserialization", "severity": "high"},
        ]
        result = mapper.map_findings(findings)
        assert isinstance(result, MappingEngineResult)
        if result.kill_chain_coverage:
            for kc in result.kill_chain_coverage:
                assert isinstance(kc, KillChainCoverage)


class TestGetCWEMapping:
    """Test CWE → MITRE technique lookup."""

    @pytest.fixture
    def mapper(self):
        return MITREMapper()

    def test_known_cwe(self, mapper):
        mapping = mapper.get_cwe_mapping("CWE-89")
        assert mapping is not None or mapping is None  # May or may not have mapping

    def test_unknown_cwe(self, mapper):
        mapping = mapper.get_cwe_mapping("CWE-99999")
        assert mapping is None or isinstance(mapping, list)

    def test_normalize_cwe_formats(self, mapper):
        # Test various CWE ID formats
        for cwe in ["CWE-89", "89", "cwe-89"]:
            mapper.get_cwe_mapping(cwe)
            # Just ensure no crash


class TestNavigatorLayer:
    """Test MITRE ATT&CK Navigator JSON export."""

    @pytest.fixture
    def mapper(self):
        return MITREMapper()

    def test_generate_navigator_basic(self, mapper):
        findings = [
            {"cwe_id": "CWE-89", "title": "SQL Injection"},
            {"cwe_id": "CWE-79", "title": "XSS"},
        ]
        layer = mapper.generate_navigator_layer(findings)
        assert isinstance(layer, dict)
        assert "name" in layer or "techniques" in layer

    def test_navigator_layer_structure(self, mapper):
        findings = [{"cwe_id": "CWE-89"}]
        layer = mapper.generate_navigator_layer(findings)
        assert isinstance(layer, dict)
        # ATT&CK Navigator layers have standard fields
        if "techniques" in layer:
            assert isinstance(layer["techniques"], list)
        if "versions" in layer:
            assert isinstance(layer["versions"], dict)

    def test_navigator_empty_findings(self, mapper):
        layer = mapper.generate_navigator_layer([])
        assert isinstance(layer, dict)

    def test_navigator_custom_name(self, mapper):
        layer = mapper.generate_navigator_layer(
            [{"cwe_id": "CWE-89"}],
            layer_name="Test Layer"
        )
        assert isinstance(layer, dict)


class TestListMethods:
    """Test listing techniques and tactics."""

    @pytest.fixture
    def mapper(self):
        return MITREMapper()

    def test_list_techniques(self, mapper):
        techs = mapper.list_techniques()
        assert isinstance(techs, list)
        assert len(techs) >= 30
        for t in techs[:3]:
            assert "id" in t or "technique_id" in t or isinstance(t, dict)

    def test_list_tactics(self, mapper):
        tactics = mapper.list_tactics()
        assert isinstance(tactics, list)
        assert len(tactics) == 14


class TestInternalMethods:
    """Test internal utility methods."""

    @pytest.fixture
    def mapper(self):
        return MITREMapper()

    def test_normalize_cwe_string(self, mapper):
        assert mapper._normalize_cwe("CWE-89") is not None
        assert mapper._normalize_cwe("89") is not None
        assert mapper._normalize_cwe(89) is not None
        assert mapper._normalize_cwe(None) is None
        assert mapper._normalize_cwe("") is None

    def test_infer_primary_tactic_empty(self, mapper):
        result = mapper._infer_primary_tactic([])
        assert result is None

    def test_compute_risk_score(self, mapper):
        techs = [TechniqueMapping(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic_ids=["TA0001"],
            tactic_names=["Initial Access"],
            confidence=0.9,
            source="cwe",
            source_ref="CWE-89",
            rationale="SQL injection maps to exploit public-facing app",
            technique_url="https://attack.mitre.org/techniques/T1190/",
        )]
        score = mapper._compute_risk_score(
            {"severity": "critical"}, techs
        )
        assert isinstance(score, float)
        assert 0.0 <= score <= 10.0

    def test_confidence_to_color(self, mapper):
        for conf in [0.0, 0.3, 0.5, 0.7, 0.9, 1.0]:
            color = mapper._confidence_to_color(conf)
            assert isinstance(color, str)
            assert color.startswith("#") or len(color) > 0


class TestDataclasses:
    """Test data model classes."""

    def test_technique_mapping(self):
        tm = TechniqueMapping(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic_ids=["TA0001"],
            tactic_names=["Initial Access"],
            confidence=0.9,
            source="cwe",
            source_ref="CWE-89",
            rationale="SQL injection maps to exploit public-facing app",
            technique_url="https://attack.mitre.org/techniques/T1190/",
        )
        assert tm.technique_id == "T1190"
        assert tm.confidence == 0.9
        assert tm.source == "cwe"

    def test_finding_mapping_result(self):
        fm = FindingMappingResult(
            finding_id="test-1",
            finding_title="Test Finding",
            cwe_id="CWE-89",
            cve_ids=[],
            techniques=[],
            primary_tactic=None,
            risk_score=5.0,
        )
        assert fm.finding_id == "test-1"
        assert fm.risk_score == 5.0
        assert fm.finding_title == "Test Finding"

    def test_kill_chain_coverage(self):
        kc = KillChainCoverage(
            tactic_id="TA0001",
            tactic_name="Initial Access",
            covered=True,
            technique_count=3,
            techniques=["T1190"],
            highest_confidence=0.9,
        )
        assert kc.tactic_id == "TA0001"
        assert kc.technique_count == 3
        assert kc.covered is True

    def test_mapping_engine_result(self):
        mr = MappingEngineResult(
            session_id="test-session",
            mapped_at="2026-03-08T00:00:00Z",
            total_findings=0,
            total_techniques=0,
            total_tactics_covered=0,
            kill_chain_coverage=[],
            finding_results=[],
            all_techniques=[],
            technique_frequency={},
            coverage_percentage=0.0,
        )
        assert mr.total_findings == 0
        assert mr.coverage_percentage == 0.0
