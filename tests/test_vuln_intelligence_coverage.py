"""Tests for core.vuln_intelligence — vulnerability intelligence database."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.vuln_intelligence import VULN_TYPE_INTEL


class TestVulnTypeIntel:
    def test_has_entries(self):
        assert len(VULN_TYPE_INTEL) >= 10  # At least 10 vuln types

    def test_sql_injection_present(self):
        assert "sql_injection" in VULN_TYPE_INTEL
        sqli = VULN_TYPE_INTEL["sql_injection"]
        assert sqli["owasp_top10"] == "A03:2021 – Injection"
        assert sqli["cwe"] == "CWE-89"
        assert sqli["attack_complexity"] == "LOW"
        assert sqli["remediation_priority"] == "CRITICAL"
        assert len(sqli["business_impact"]) >= 3
        assert len(sqli["real_world_examples"]) >= 2

    def test_xss_present(self):
        assert "xss" in VULN_TYPE_INTEL
        xss = VULN_TYPE_INTEL["xss"]
        assert xss["cwe"] == "CWE-79"
        assert "Injection" in xss["owasp_top10"]

    def test_security_headers_present(self):
        assert "security_headers" in VULN_TYPE_INTEL

    def test_all_entries_have_required_fields(self):
        required = [
            "source_file",
            "source_function",
            "detection_logic",
            "threat_scenario",
            "cwe",
            "owasp_top10",
            "attack_complexity",
            "remediation_priority",
        ]
        for vuln_type, data in VULN_TYPE_INTEL.items():
            for field in required:
                assert field in data, f"{vuln_type} missing '{field}'"

    def test_attack_complexity_valid(self):
        valid_prefixes = {"LOW", "MEDIUM", "HIGH"}
        for vuln_type, data in VULN_TYPE_INTEL.items():
            ac = data["attack_complexity"]
            # Some entries use ranges like "LOW to MEDIUM"
            first_word = ac.split()[0]
            assert first_word in valid_prefixes, (
                f"{vuln_type} has invalid attack_complexity: {ac}"
            )

    def test_remediation_priority_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for vuln_type, data in VULN_TYPE_INTEL.items():
            assert data["remediation_priority"] in valid, (
                f"{vuln_type} has invalid remediation_priority: {data['remediation_priority']}"
            )

    def test_cwe_format(self):
        for vuln_type, data in VULN_TYPE_INTEL.items():
            cwe = data["cwe"]
            assert cwe.startswith("CWE-"), f"{vuln_type} has invalid CWE: {cwe}"

    def test_source_file_consistent(self):
        for vuln_type, data in VULN_TYPE_INTEL.items():
            assert data["source_file"].endswith(".py"), (
                f"{vuln_type} source_file doesn't end with .py"
            )

    def test_business_impact_is_list(self):
        for vuln_type, data in VULN_TYPE_INTEL.items():
            assert isinstance(data["business_impact"], list), (
                f"{vuln_type} business_impact is not a list"
            )
            assert len(data["business_impact"]) >= 1

    def test_real_world_examples_is_list(self):
        for vuln_type, data in VULN_TYPE_INTEL.items():
            assert isinstance(data["real_world_examples"], list), (
                f"{vuln_type} real_world_examples is not a list"
            )

    def test_stride_present(self):
        for vuln_type, data in VULN_TYPE_INTEL.items():
            assert "stride" in data, f"{vuln_type} missing stride"
            assert len(data["stride"]) > 0
