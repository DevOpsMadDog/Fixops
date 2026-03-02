"""Unit tests for suite-evidence-risk/compliance/templates/

Tests the compliance template framework: base classes, OWASP Top 10,
HIPAA, PCI DSS, SOC2, and NIST templates.

Pillar: V10 (CTEM + Crypto Evidence)
"""


from compliance.templates.base import ComplianceCheck, ComplianceRule, ComplianceTemplate
from compliance.templates.hipaa import HIPAATemplate
from compliance.templates.nist import NISTTemplate
from compliance.templates.owasp import OWASPRule, OWASPTemplate
from compliance.templates.pci_dss import PCIDSSTemplate
from compliance.templates.soc2 import SOC2Template


# --- ComplianceRule dataclass ---


class TestComplianceRule:
    """Tests for ComplianceRule dataclass."""

    def test_create_rule_required_fields(self):
        """ComplianceRule requires id, name, description, severity."""
        rule = ComplianceRule(
            id="TEST-001",
            name="Test Rule",
            description="A test rule",
            severity="high",
        )
        assert rule.id == "TEST-001"
        assert rule.name == "Test Rule"
        assert rule.severity == "high"

    def test_create_rule_defaults(self):
        """ComplianceRule has default checks and remediation."""
        rule = ComplianceRule(
            id="TEST-002",
            name="Defaults",
            description="Test defaults",
            severity="low",
        )
        assert rule.checks == []
        assert rule.remediation is None

    def test_create_rule_with_checks(self):
        """ComplianceRule accepts checks list."""
        rule = ComplianceRule(
            id="TEST-003",
            name="With Checks",
            description="Rule with checks",
            severity="medium",
            checks=["Check 1", "Check 2", "Check 3"],
        )
        assert len(rule.checks) == 3
        assert "Check 1" in rule.checks

    def test_create_rule_with_remediation(self):
        """ComplianceRule accepts remediation text."""
        rule = ComplianceRule(
            id="TEST-004",
            name="With Fix",
            description="Rule with remediation",
            severity="critical",
            remediation="Apply patch XYZ",
        )
        assert rule.remediation == "Apply patch XYZ"


# --- ComplianceCheck dataclass ---


class TestComplianceCheck:
    """Tests for ComplianceCheck dataclass."""

    def test_create_check_passed(self):
        """ComplianceCheck with passed=True."""
        check = ComplianceCheck(
            rule_id="TEST-001",
            passed=True,
            message="All checks passed",
        )
        assert check.passed is True
        assert check.rule_id == "TEST-001"

    def test_create_check_failed(self):
        """ComplianceCheck with passed=False."""
        check = ComplianceCheck(
            rule_id="TEST-002",
            passed=False,
            message="Check failed: missing encryption",
        )
        assert check.passed is False

    def test_create_check_with_evidence(self):
        """ComplianceCheck with evidence list."""
        check = ComplianceCheck(
            rule_id="TEST-003",
            passed=True,
            message="Passed",
            evidence=["scan-report.json", "config-audit.yaml"],
        )
        assert len(check.evidence) == 2

    def test_create_check_default_evidence(self):
        """ComplianceCheck defaults to empty evidence list."""
        check = ComplianceCheck(
            rule_id="TEST-004",
            passed=True,
            message="OK",
        )
        assert check.evidence == []


# --- OWASPRule ---


class TestOWASPRule:
    """Tests for OWASPRule dataclass."""

    def test_create_owasp_rule(self):
        """OWASPRule extends ComplianceRule with owasp_category."""
        rule = OWASPRule(
            id="OWASP-A01",
            name="Broken Access Control",
            description="Test",
            severity="high",
            owasp_category="A01",
            cwe_ids=["CWE-284"],
        )
        assert rule.owasp_category == "A01"
        assert "CWE-284" in rule.cwe_ids

    def test_owasp_rule_default_cwe_ids(self):
        """OWASPRule defaults cwe_ids to None."""
        rule = OWASPRule(
            id="TEST",
            name="Test",
            description="Test",
            severity="low",
            owasp_category="A01",
        )
        assert rule.cwe_ids is None


# --- OWASPTemplate ---


class TestOWASPTemplate:
    """Tests for OWASPTemplate class."""

    def test_init(self):
        """OWASPTemplate initializes with correct framework name."""
        tmpl = OWASPTemplate()
        assert tmpl.framework_name == "OWASP Top 10"
        assert tmpl.version == "2021"

    def test_has_10_rules(self):
        """OWASPTemplate has exactly 10 rules (A01-A10)."""
        tmpl = OWASPTemplate()
        assert len(tmpl.rules) == 10

    def test_rules_are_owasp_rules(self):
        """All rules are OWASPRule instances."""
        tmpl = OWASPTemplate()
        for rule in tmpl.rules:
            assert isinstance(rule, OWASPRule)

    def test_categories_a01_through_a10(self):
        """Rules cover categories A01 through A10."""
        tmpl = OWASPTemplate()
        categories = {r.owasp_category for r in tmpl.rules}
        expected = {f"A{i:02d}" for i in range(1, 11)}
        assert categories == expected

    def test_all_rules_have_cwe_ids(self):
        """All OWASP rules have at least one CWE ID."""
        tmpl = OWASPTemplate()
        for rule in tmpl.rules:
            assert rule.cwe_ids is not None
            assert len(rule.cwe_ids) > 0

    def test_all_rules_have_checks(self):
        """All OWASP rules have at least one check."""
        tmpl = OWASPTemplate()
        for rule in tmpl.rules:
            assert len(rule.checks) > 0

    def test_injection_is_critical(self):
        """A03 (Injection) has critical severity."""
        tmpl = OWASPTemplate()
        injection = [r for r in tmpl.rules if r.owasp_category == "A03"][0]
        assert injection.severity == "critical"

    def test_logging_is_medium(self):
        """A09 (Security Logging) has medium severity."""
        tmpl = OWASPTemplate()
        logging_rule = [r for r in tmpl.rules if r.owasp_category == "A09"][0]
        assert logging_rule.severity == "medium"

    def test_get_rules_by_category(self):
        """get_rules_by_category returns correct rules."""
        tmpl = OWASPTemplate()
        a01_rules = tmpl.get_rules_by_category("A01")
        assert len(a01_rules) == 1
        assert a01_rules[0].name == "Broken Access Control"

    def test_get_rules_by_nonexistent_category(self):
        """get_rules_by_category returns empty for non-existent category."""
        tmpl = OWASPTemplate()
        result = tmpl.get_rules_by_category("A99")
        assert result == []

    def test_get_rules_inherited_method(self):
        """get_rules() inherited method works."""
        tmpl = OWASPTemplate()
        rules = tmpl.get_rules()
        assert len(rules) == 10

    def test_get_rule_by_id(self):
        """get_rule() inherited method finds rule by ID."""
        tmpl = OWASPTemplate()
        rule = tmpl.get_rule("OWASP-A03")
        assert rule is not None
        assert rule.name == "Injection"

    def test_get_rule_nonexistent_returns_none(self):
        """get_rule() returns None for non-existent ID."""
        tmpl = OWASPTemplate()
        assert tmpl.get_rule("NONEXISTENT") is None


# --- OWASPTemplate.assess_compliance ---


class TestOWASPAssessCompliance:
    """Tests for OWASPTemplate.assess_compliance method."""

    def test_no_findings_full_compliance(self):
        """No findings means 100% compliance."""
        tmpl = OWASPTemplate()
        result = tmpl.assess_compliance([])
        assert result["compliance_score"] == 100.0
        assert result["compliant_categories"] == 10
        assert result["total_categories"] == 10
        assert result["framework"] == "OWASP Top 10"
        assert result["version"] == "2021"

    def test_all_categories_have_findings(self):
        """All categories with matching findings have compliant=False."""
        tmpl = OWASPTemplate()
        # Create findings for every CWE across all categories
        all_cwes = set()
        for rule in tmpl.rules:
            all_cwes.update(rule.cwe_ids)

        findings = [{"cwe_ids": [cwe]} for cwe in all_cwes]
        result = tmpl.assess_compliance(findings)
        assert result["compliance_score"] == 0.0
        assert result["compliant_categories"] == 0

    def test_single_category_finding(self):
        """Finding matching one category reduces compliance."""
        tmpl = OWASPTemplate()
        findings = [{"cwe_ids": ["CWE-89"]}]  # SQL injection → A03
        result = tmpl.assess_compliance(findings)
        assert result["compliant_categories"] == 9
        assert result["compliance_score"] == 90.0
        assert result["by_category"]["A03"]["compliant"] is False
        assert result["by_category"]["A03"]["findings_count"] == 1

    def test_multiple_findings_same_category(self):
        """Multiple findings for same category counted correctly."""
        tmpl = OWASPTemplate()
        findings = [
            {"cwe_ids": ["CWE-89"]},  # SQL injection
            {"cwe_ids": ["CWE-78"]},  # Command injection
            {"cwe_ids": ["CWE-79"]},  # XSS
        ]
        result = tmpl.assess_compliance(findings)
        assert result["by_category"]["A03"]["findings_count"] == 3
        assert result["by_category"]["A03"]["compliant"] is False

    def test_findings_without_cwe_ids_ignored(self):
        """Findings without cwe_ids key don't match any category."""
        tmpl = OWASPTemplate()
        findings = [{"severity": "high", "title": "Mystery finding"}]
        result = tmpl.assess_compliance(findings)
        assert result["compliance_score"] == 100.0

    def test_findings_with_empty_cwe_ids(self):
        """Findings with empty cwe_ids list don't match."""
        tmpl = OWASPTemplate()
        findings = [{"cwe_ids": []}]
        result = tmpl.assess_compliance(findings)
        assert result["compliance_score"] == 100.0

    def test_findings_with_unknown_cwe(self):
        """Findings with CWEs not in OWASP don't match."""
        tmpl = OWASPTemplate()
        findings = [{"cwe_ids": ["CWE-999999"]}]
        result = tmpl.assess_compliance(findings)
        assert result["compliance_score"] == 100.0

    def test_by_category_structure(self):
        """by_category has correct structure for each entry."""
        tmpl = OWASPTemplate()
        result = tmpl.assess_compliance([])
        for category, data in result["by_category"].items():
            assert "name" in data
            assert "compliant" in data
            assert "findings_count" in data
            assert "severity" in data

    def test_partial_compliance(self):
        """Partial compliance with 3 categories violated."""
        tmpl = OWASPTemplate()
        findings = [
            {"cwe_ids": ["CWE-284"]},  # A01
            {"cwe_ids": ["CWE-327"]},  # A02
            {"cwe_ids": ["CWE-89"]},   # A03
        ]
        result = tmpl.assess_compliance(findings)
        assert result["compliant_categories"] == 7
        assert result["compliance_score"] == 70.0


# --- HIPAATemplate ---


class TestHIPAATemplate:
    """Tests for HIPAATemplate class."""

    def test_init(self):
        """HIPAATemplate initializes correctly."""
        tmpl = HIPAATemplate()
        assert tmpl.framework_name == "HIPAA"
        assert tmpl.version == "2023"

    def test_has_rules(self):
        """HIPAATemplate has rules defined."""
        tmpl = HIPAATemplate()
        assert len(tmpl.rules) == 3

    def test_rule_ids(self):
        """HIPAA rules have expected IDs."""
        tmpl = HIPAATemplate()
        ids = {r.id for r in tmpl.rules}
        assert "HIPAA-164.308" in ids
        assert "HIPAA-164.312" in ids
        assert "HIPAA-164.314" in ids

    def test_all_rules_high_severity(self):
        """All HIPAA rules are high severity."""
        tmpl = HIPAATemplate()
        for rule in tmpl.rules:
            assert rule.severity == "high"

    def test_assess_compliance_returns_dict(self):
        """assess_compliance returns proper structure."""
        tmpl = HIPAATemplate()
        result = tmpl.assess_compliance([])
        assert result["framework"] == "HIPAA"
        assert result["version"] == "2023"
        assert "compliance_score" in result

    def test_get_rules_inherited(self):
        """get_rules() works for HIPAATemplate."""
        tmpl = HIPAATemplate()
        assert len(tmpl.get_rules()) == 3

    def test_get_rule_by_id(self):
        """get_rule() finds HIPAA rules by ID."""
        tmpl = HIPAATemplate()
        rule = tmpl.get_rule("HIPAA-164.308")
        assert rule is not None
        assert rule.name == "Administrative Safeguards"


# --- PCIDSSTemplate ---


class TestPCIDSSTemplate:
    """Tests for PCIDSSTemplate class."""

    def test_init(self):
        """PCIDSSTemplate initializes correctly."""
        tmpl = PCIDSSTemplate()
        assert tmpl.framework_name == "PCI DSS"
        assert tmpl.version == "4.0"

    def test_has_rules(self):
        """PCIDSSTemplate has rules defined."""
        tmpl = PCIDSSTemplate()
        assert len(tmpl.rules) == 4

    def test_rule_ids(self):
        """PCI DSS rules have expected IDs."""
        tmpl = PCIDSSTemplate()
        ids = {r.id for r in tmpl.rules}
        assert "PCI-1" in ids
        assert "PCI-2" in ids
        assert "PCI-3" in ids
        assert "PCI-4" in ids

    def test_all_rules_critical(self):
        """All PCI DSS rules are critical severity."""
        tmpl = PCIDSSTemplate()
        for rule in tmpl.rules:
            assert rule.severity == "critical"

    def test_assess_compliance_returns_dict(self):
        """assess_compliance returns proper structure."""
        tmpl = PCIDSSTemplate()
        result = tmpl.assess_compliance([])
        assert result["framework"] == "PCI DSS"
        assert result["version"] == "4.0"
        assert "compliance_score" in result

    def test_get_rules_inherited(self):
        """get_rules() works for PCIDSSTemplate."""
        tmpl = PCIDSSTemplate()
        assert len(tmpl.get_rules()) == 4

    def test_get_rule_by_id(self):
        """get_rule() finds PCI DSS rules by ID."""
        tmpl = PCIDSSTemplate()
        rule = tmpl.get_rule("PCI-3")
        assert rule is not None
        assert "cardholder" in rule.name.lower()

    def test_get_nonexistent_rule(self):
        """get_rule() returns None for non-existent ID."""
        tmpl = PCIDSSTemplate()
        assert tmpl.get_rule("PCI-999") is None


# --- NISTTemplate ---


class TestNISTTemplate:
    """Tests for NISTTemplate class."""

    def test_init(self):
        """NISTTemplate initializes correctly."""
        tmpl = NISTTemplate()
        assert tmpl.framework_name == "NIST SSDF"
        assert tmpl.version == "1.1"

    def test_has_rules(self):
        """NISTTemplate has 4 practice rules."""
        tmpl = NISTTemplate()
        assert len(tmpl.rules) == 4

    def test_rule_ids(self):
        """NIST rules have expected IDs."""
        tmpl = NISTTemplate()
        ids = {r.id for r in tmpl.rules}
        assert "NIST-PO.1" in ids
        assert "NIST-PS.1" in ids
        assert "NIST-PW.1" in ids
        assert "NIST-RV.1" in ids

    def test_all_rules_high_severity(self):
        """All NIST rules are high severity."""
        tmpl = NISTTemplate()
        for rule in tmpl.rules:
            assert rule.severity == "high"

    def test_all_rules_have_checks(self):
        """All NIST rules have at least one check."""
        tmpl = NISTTemplate()
        for rule in tmpl.rules:
            assert len(rule.checks) >= 3

    def test_assess_compliance_returns_dict(self):
        """assess_compliance returns proper structure."""
        tmpl = NISTTemplate()
        result = tmpl.assess_compliance([])
        assert result["framework"] == "NIST SSDF"
        assert result["version"] == "1.1"
        assert "compliance_score" in result

    def test_assess_compliance_has_practices(self):
        """assess_compliance returns practice-level scores."""
        tmpl = NISTTemplate()
        result = tmpl.assess_compliance([])
        assert "practices" in result
        for practice in ["PO", "PS", "PW", "RV"]:
            assert practice in result["practices"]

    def test_get_rules_inherited(self):
        """get_rules() works for NISTTemplate."""
        tmpl = NISTTemplate()
        assert len(tmpl.get_rules()) == 4

    def test_get_rule_by_id(self):
        """get_rule() finds NIST rules by ID."""
        tmpl = NISTTemplate()
        rule = tmpl.get_rule("NIST-PO.1")
        assert rule is not None
        assert "Prepare" in rule.name


# --- SOC2Template ---


class TestSOC2Template:
    """Tests for SOC2Template class."""

    def test_init(self):
        """SOC2Template initializes correctly."""
        tmpl = SOC2Template()
        assert tmpl.framework_name == "SOC 2"
        assert tmpl.version == "Type II"

    def test_has_rules(self):
        """SOC2Template has 5 trust service criteria."""
        tmpl = SOC2Template()
        assert len(tmpl.rules) == 5

    def test_rule_ids(self):
        """SOC 2 rules have expected IDs."""
        tmpl = SOC2Template()
        ids = {r.id for r in tmpl.rules}
        assert "SOC2-Security" in ids
        assert "SOC2-Availability" in ids
        assert "SOC2-ProcessingIntegrity" in ids
        assert "SOC2-Confidentiality" in ids
        assert "SOC2-Privacy" in ids

    def test_all_rules_high_severity(self):
        """All SOC 2 rules are high severity."""
        tmpl = SOC2Template()
        for rule in tmpl.rules:
            assert rule.severity == "high"

    def test_assess_compliance_returns_dict(self):
        """assess_compliance returns proper structure."""
        tmpl = SOC2Template()
        result = tmpl.assess_compliance([])
        assert result["framework"] == "SOC 2"
        assert result["version"] == "Type II"
        assert "compliance_score" in result

    def test_get_rules_inherited(self):
        """get_rules() works for SOC2Template."""
        tmpl = SOC2Template()
        assert len(tmpl.get_rules()) == 5

    def test_get_rule_by_id(self):
        """get_rule() finds SOC 2 rules by ID."""
        tmpl = SOC2Template()
        rule = tmpl.get_rule("SOC2-Security")
        assert rule is not None
        assert rule.name == "Security"


# --- Cross-template tests ---


class TestCrossTemplate:
    """Tests that verify consistency across templates."""

    def _all_templates(self):
        return [OWASPTemplate(), HIPAATemplate(), PCIDSSTemplate(), NISTTemplate(), SOC2Template()]

    def test_all_templates_have_framework_name(self):
        """All templates set framework_name."""
        for tmpl in self._all_templates():
            assert tmpl.framework_name
            assert len(tmpl.framework_name) > 0

    def test_all_templates_have_version(self):
        """All templates set version."""
        for tmpl in self._all_templates():
            assert tmpl.version
            assert len(tmpl.version) > 0

    def test_all_templates_have_rules(self):
        """All templates define at least one rule."""
        for tmpl in self._all_templates():
            assert len(tmpl.rules) > 0

    def test_all_templates_implement_assess_compliance(self):
        """All templates implement assess_compliance."""
        for tmpl in self._all_templates():
            result = tmpl.assess_compliance([])
            assert isinstance(result, dict)
            assert "framework" in result

    def test_rule_ids_unique_within_template(self):
        """Rule IDs are unique within each template."""
        for tmpl in self._all_templates():
            ids = [r.id for r in tmpl.rules]
            assert len(ids) == len(set(ids)), f"Duplicate IDs in {tmpl.framework_name}"

    def test_all_rules_have_valid_severity(self):
        """All rules across all templates have valid severity."""
        valid_severities = {"critical", "high", "medium", "low"}
        for tmpl in self._all_templates():
            for rule in tmpl.rules:
                assert rule.severity in valid_severities, (
                    f"{tmpl.framework_name}/{rule.id} has invalid severity: {rule.severity}"
                )

    def test_total_rules_across_all_frameworks(self):
        """Verify total rule count across all frameworks."""
        total = sum(len(tmpl.rules) for tmpl in self._all_templates())
        assert total == 26  # 10 + 3 + 4 + 4 + 5

    def test_all_templates_are_compliance_template(self):
        """All templates inherit from ComplianceTemplate."""
        for tmpl in self._all_templates():
            assert isinstance(tmpl, ComplianceTemplate)
