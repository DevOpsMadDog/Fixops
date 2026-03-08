"""Tests for Identity Resolution — CWE/control normalization and correlation keys."""

from core.services.identity import (
    CWE_RULE_MAPPINGS,
    CONTROL_ID_MAPPINGS,
)


class TestCWERuleMappings:
    def test_sql_injection_mappings(self):
        assert CWE_RULE_MAPPINGS["sql-injection"] == "CWE-89"
        assert CWE_RULE_MAPPINGS["sqli"] == "CWE-89"
        assert CWE_RULE_MAPPINGS["sql_injection"] == "CWE-89"

    def test_xss_mappings(self):
        assert CWE_RULE_MAPPINGS["xss"] == "CWE-79"
        assert CWE_RULE_MAPPINGS["cross-site-scripting"] == "CWE-79"
        assert CWE_RULE_MAPPINGS["reflected-xss"] == "CWE-79"
        assert CWE_RULE_MAPPINGS["stored-xss"] == "CWE-79"
        assert CWE_RULE_MAPPINGS["dom-xss"] == "CWE-79"

    def test_command_injection(self):
        assert CWE_RULE_MAPPINGS["command-injection"] == "CWE-78"
        assert CWE_RULE_MAPPINGS["shell-injection"] == "CWE-78"

    def test_path_traversal(self):
        assert CWE_RULE_MAPPINGS["path-traversal"] == "CWE-22"
        assert CWE_RULE_MAPPINGS["lfi"] == "CWE-22"

    def test_ssrf(self):
        assert CWE_RULE_MAPPINGS["ssrf"] == "CWE-918"

    def test_deserialization(self):
        assert CWE_RULE_MAPPINGS["insecure-deserialization"] == "CWE-502"

    def test_hardcoded_secrets(self):
        assert CWE_RULE_MAPPINGS["hardcoded-secret"] == "CWE-798"
        assert CWE_RULE_MAPPINGS["hardcoded-password"] == "CWE-798"

    def test_weak_crypto(self):
        assert CWE_RULE_MAPPINGS["weak-crypto"] == "CWE-327"

    def test_xxe(self):
        assert CWE_RULE_MAPPINGS["xxe"] == "CWE-611"

    def test_open_redirect(self):
        assert CWE_RULE_MAPPINGS["open-redirect"] == "CWE-601"

    def test_csrf(self):
        assert CWE_RULE_MAPPINGS["csrf"] == "CWE-352"

    def test_nosql_injection(self):
        assert CWE_RULE_MAPPINGS["nosql-injection"] == "CWE-943"

    def test_ldap_injection(self):
        assert CWE_RULE_MAPPINGS["ldap-injection"] == "CWE-90"


class TestControlIDMappings:
    def test_s3_bucket_mappings(self):
        assert "s3-bucket-public-read" in CONTROL_ID_MAPPINGS
        assert CONTROL_ID_MAPPINGS["s3-bucket-public-read"] == "CIS-AWS-2.1.5"

    def test_has_entries(self):
        assert len(CONTROL_ID_MAPPINGS) > 0

    def test_all_values_are_strings(self):
        for k, v in CONTROL_ID_MAPPINGS.items():
            assert isinstance(k, str)
            assert isinstance(v, str)


class TestCWEMappingCompleteness:
    """Verify the CWE mapping covers OWASP Top 10 vulnerability types."""

    def test_owasp_a03_injection_covered(self):
        """A03:2021 — Injection should be covered."""
        injection_cwes = {"CWE-89", "CWE-78", "CWE-90", "CWE-943"}
        mapped_cwes = set(CWE_RULE_MAPPINGS.values())
        assert injection_cwes.issubset(mapped_cwes)

    def test_owasp_a07_xss_covered(self):
        """A07:2017 — Cross-Site Scripting should be covered."""
        assert "CWE-79" in CWE_RULE_MAPPINGS.values()

    def test_owasp_a10_ssrf_covered(self):
        """A10:2021 — Server-Side Request Forgery covered."""
        assert "CWE-918" in CWE_RULE_MAPPINGS.values()
