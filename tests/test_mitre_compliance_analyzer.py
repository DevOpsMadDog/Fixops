"""Comprehensive tests for MITRE ATT&CK compliance analyzer."""

from __future__ import annotations

from core.services.enterprise.mitre_compliance_analyzer import MITREComplianceAnalyzer


def test_mitre_analyzer_initialization():
    """Test that MITRE analyzer initializes correctly."""
    analyzer = MITREComplianceAnalyzer()
    assert analyzer is not None


def test_mitre_technique_mapping():
    """Test MITRE technique mapping from findings."""
    analyzer = MITREComplianceAnalyzer()
    findings = [
        {
            "rule_id": "SQL-001",
            "message": "SQL injection vulnerability detected",
            "severity": "high",
        }
    ]

    result = analyzer.analyze(findings)
    assert "mitre_techniques" in result
    assert isinstance(result["mitre_techniques"], list)


def test_mitre_coverage_calculation():
    """Test MITRE ATT&CK coverage calculation."""
    analyzer = MITREComplianceAnalyzer()
    findings = [{"rule_id": "TEST-001", "message": "Test finding", "severity": "low"}]

    result = analyzer.analyze(findings)
    assert "coverage" in result
    assert isinstance(result["coverage"], dict)


def test_attack_chain_analysis():
    """Test attack chain severity calculation."""
    analyzer = MITREComplianceAnalyzer()
    findings = [
        {
            "rule_id": "INIT-001",
            "message": "Initial access vulnerability",
            "severity": "high",
        },
        {
            "rule_id": "EXEC-001",
            "message": "Code execution vulnerability",
            "severity": "critical",
        },
    ]

    result = analyzer.analyze(findings)
    assert "attack_chain_severity" in result


def test_compliance_framework_analysis():
    """Test compliance framework validation."""
    analyzer = MITREComplianceAnalyzer()
    findings = [
        {"rule_id": "AUTH-001", "message": "Authentication issue", "severity": "high"}
    ]

    result = analyzer.analyze(findings, frameworks=["PCI-DSS", "SOX", "HIPAA"])
    assert "compliance_analysis" in result


def test_business_risk_amplification():
    """Test business risk amplification calculation."""
    analyzer = MITREComplianceAnalyzer()
    findings = [
        {
            "rule_id": "DATA-001",
            "message": "Data exposure vulnerability",
            "severity": "critical",
        }
    ]

    result = analyzer.analyze(findings, business_context={"data_classification": "pii"})
    assert "business_risk_multiplier" in result


def test_empty_findings_list():
    """Test analysis with empty findings list."""
    analyzer = MITREComplianceAnalyzer()
    result = analyzer.analyze([])

    assert result["mitre_techniques"] == []
    assert result["coverage"]["total_techniques"] == 0


def test_mitre_technique_count():
    """Test that analyzer supports 35 MITRE techniques."""
    analyzer = MITREComplianceAnalyzer()

    assert len(analyzer.supported_techniques) == 35


def test_mitre_tactic_coverage():
    """Test that analyzer covers all 14 MITRE tactics."""
    analyzer = MITREComplianceAnalyzer()

    tactics = {t["tactic"] for t in analyzer.supported_techniques}
    assert len(tactics) == 14


def test_technique_metadata():
    """Test that each technique has required metadata."""
    analyzer = MITREComplianceAnalyzer()

    for technique in analyzer.supported_techniques:
        assert "id" in technique
        assert "name" in technique
        assert "tactic" in technique
        assert "description" in technique
