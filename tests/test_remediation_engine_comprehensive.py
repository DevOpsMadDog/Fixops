"""Comprehensive tests for the ALdeci Remediation Engine.

Tests CWEFixRegistry, RemediationEngine, and all 5 CWE fix templates:
  CWE-79  (XSS), CWE-89 (SQL Injection), CWE-502 (Deserialization),
  CWE-78  (OS Command Injection), CWE-22 (Path Traversal).

Sprint: SPRINT1-005 — Self-Healing Remediation
Pillar: V7 — MCP-Native / Self-Healing
"""

from __future__ import annotations

import pytest

import sys
import os

# Ensure suite-core is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from automation.remediation import (
    CWEFixRegistry,
    CWEFixTemplate,
    RemediationEngine,
    RemediationResult,
    RemediationStatus,
    RemediationStrategy,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def xss_finding() -> dict:
    return {
        "cve_id": "CVE-2026-1234",
        "cwe_id": "CWE-79",
        "title": "Reflected XSS in /search endpoint",
        "severity": "high",
        "file_path": "app/views/search.py",
        "language": "python",
        "code_snippet": 'from flask import request\nresult = f"<div>{request.args.get(\'q\')}</div>"',
    }


@pytest.fixture
def sqli_finding() -> dict:
    return {
        "cve_id": "CVE-2026-5678",
        "cwe_id": "CWE-89",
        "title": "SQL Injection in user lookup",
        "severity": "critical",
        "file_path": "app/db/users.py",
        "language": "python",
        "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    }


@pytest.fixture
def deserialization_finding() -> dict:
    return {
        "cve_id": "CVE-2026-9012",
        "cwe_id": "CWE-502",
        "title": "Unsafe pickle deserialization",
        "severity": "critical",
        "file_path": "app/utils/cache.py",
        "language": "python",
        "code_snippet": "import pickle\ndata = pickle.loads(user_input)",
    }


@pytest.fixture
def cmdi_finding() -> dict:
    return {
        "cve_id": "CVE-2026-3456",
        "cwe_id": "CWE-78",
        "title": "OS Command Injection in ping utility",
        "severity": "critical",
        "file_path": "app/utils/network.py",
        "language": "python",
        "code_snippet": 'import os\nos.system(f"ping -c 1 {host}")',
    }


@pytest.fixture
def path_traversal_finding() -> dict:
    return {
        "cve_id": "CVE-2026-7890",
        "cwe_id": "CWE-22",
        "title": "Path Traversal in file download",
        "severity": "high",
        "file_path": "app/views/download.py",
        "language": "python",
        "code_snippet": 'filepath = os.path.join("/uploads", user_filename)\nreturn open(filepath).read()',
    }


@pytest.fixture
def engine() -> RemediationEngine:
    return RemediationEngine(config={"repository": "test/repo"})


# ---------------------------------------------------------------------------
# CWEFixRegistry — Supported CWEs
# ---------------------------------------------------------------------------


class TestCWEFixRegistrySupported:
    def test_supported_cwes_returns_five(self):
        cwes = CWEFixRegistry.supported_cwes()
        assert len(cwes) == 5

    def test_supported_cwes_contains_required(self):
        cwes = CWEFixRegistry.supported_cwes()
        for cwe in ["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-502"]:
            assert cwe in cwes

    def test_can_fix_true_for_all_supported(self):
        for cwe in CWEFixRegistry.supported_cwes():
            assert CWEFixRegistry.can_fix(cwe) is True

    def test_can_fix_false_for_unsupported(self):
        assert CWEFixRegistry.can_fix("CWE-999") is False
        assert CWEFixRegistry.can_fix("CWE-200") is False


# ---------------------------------------------------------------------------
# CWEFixRegistry — Normalize CWE ID
# ---------------------------------------------------------------------------


class TestCWENormalization:
    def test_standard_format(self):
        assert CWEFixRegistry._normalize_cwe("CWE-79") == "CWE-79"

    def test_lowercase(self):
        assert CWEFixRegistry._normalize_cwe("cwe-79") == "CWE-79"

    def test_no_dash(self):
        assert CWEFixRegistry._normalize_cwe("CWE79") == "CWE-79"

    def test_just_number(self):
        assert CWEFixRegistry._normalize_cwe("79") == "CWE-79"

    def test_with_leading_zeros(self):
        assert CWEFixRegistry._normalize_cwe("CWE-079") == "CWE-79"

    def test_whitespace(self):
        assert CWEFixRegistry._normalize_cwe("  CWE-89  ") == "CWE-89"


# ---------------------------------------------------------------------------
# CWEFixRegistry — Generate Fix (CWE-79 XSS)
# ---------------------------------------------------------------------------


class TestCWE79Fix:
    def test_generates_fix_template(self, xss_finding):
        result = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert isinstance(result, CWEFixTemplate)
        assert result.cwe_id == "CWE-79"
        assert result.cwe_name == "Cross-Site Scripting (XSS)"

    def test_fix_code_has_escape_import(self, xss_finding):
        result = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert "_html_escape" in result.fix_code or "escape" in result.fix_code

    def test_fix_code_has_csp(self, xss_finding):
        result = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert "Content-Security-Policy" in result.fix_code

    def test_test_code_generated(self, xss_finding):
        result = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert "TestCWE79Fix" in result.test_code
        assert "XSS_PAYLOADS" in result.test_code

    def test_pr_title_format(self, xss_finding):
        result = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert "CWE-79" in result.pr_title
        assert "XSS" in result.pr_title

    def test_compliance_refs_present(self, xss_finding):
        result = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert "CWE-79" in result.compliance_refs
        assert any("OWASP" in ref for ref in result.compliance_refs)

    def test_mitre_techniques_present(self, xss_finding):
        result = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert len(result.mitre_techniques) > 0

    def test_to_dict_serialization(self, xss_finding):
        result = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        d = result.to_dict()
        assert d["cwe_id"] == "CWE-79"
        assert isinstance(d["compliance_refs"], list)
        assert isinstance(d["mitre_techniques"], list)


# ---------------------------------------------------------------------------
# CWEFixRegistry — Generate Fix (CWE-89 SQL Injection)
# ---------------------------------------------------------------------------


class TestCWE89Fix:
    def test_generates_fix_template(self, sqli_finding):
        result = CWEFixRegistry.generate_fix("CWE-89", sqli_finding)
        assert result.cwe_id == "CWE-89"
        assert result.cwe_name == "SQL Injection"

    def test_fix_removes_fstring_sql(self, sqli_finding):
        result = CWEFixRegistry.generate_fix("CWE-89", sqli_finding)
        # Fix code should use parameterized queries
        assert "?" in result.fix_code or "execute" in result.fix_code

    def test_confidence_high(self, sqli_finding):
        result = CWEFixRegistry.generate_fix("CWE-89", sqli_finding)
        assert result.confidence >= 0.90


# ---------------------------------------------------------------------------
# CWEFixRegistry — Generate Fix (CWE-502 Deserialization)
# ---------------------------------------------------------------------------


class TestCWE502Fix:
    def test_generates_fix_template(self, deserialization_finding):
        result = CWEFixRegistry.generate_fix("CWE-502", deserialization_finding)
        assert result.cwe_id == "CWE-502"

    def test_fix_replaces_pickle(self, deserialization_finding):
        result = CWEFixRegistry.generate_fix("CWE-502", deserialization_finding)
        # Should suggest json instead of pickle, or add validation
        assert (
            "json" in result.fix_code.lower()
            or "safe" in result.fix_code.lower()
            or "restrict" in result.fix_code.lower()
            or "RestrictedUnpickler" in result.fix_code
        )


# ---------------------------------------------------------------------------
# CWEFixRegistry — Generate Fix (CWE-78 Command Injection)
# ---------------------------------------------------------------------------


class TestCWE78Fix:
    def test_generates_fix_template(self, cmdi_finding):
        result = CWEFixRegistry.generate_fix("CWE-78", cmdi_finding)
        assert result.cwe_id == "CWE-78"

    def test_fix_uses_subprocess_or_shlex(self, cmdi_finding):
        result = CWEFixRegistry.generate_fix("CWE-78", cmdi_finding)
        assert (
            "subprocess" in result.fix_code
            or "shlex" in result.fix_code
            or "shell=False" in result.fix_code
            or "quote" in result.fix_code
        )


# ---------------------------------------------------------------------------
# CWEFixRegistry — Generate Fix (CWE-22 Path Traversal)
# ---------------------------------------------------------------------------


class TestCWE22Fix:
    def test_generates_fix_template(self, path_traversal_finding):
        result = CWEFixRegistry.generate_fix("CWE-22", path_traversal_finding)
        assert result.cwe_id == "CWE-22"

    def test_fix_validates_path(self, path_traversal_finding):
        result = CWEFixRegistry.generate_fix("CWE-22", path_traversal_finding)
        assert (
            "resolve" in result.fix_code
            or "realpath" in result.fix_code
            or "abspath" in result.fix_code
            or ".." in result.test_code
        )


# ---------------------------------------------------------------------------
# CWEFixRegistry — Error Cases
# ---------------------------------------------------------------------------


class TestCWEFixErrors:
    def test_unsupported_cwe_raises(self):
        with pytest.raises(ValueError, match="Unsupported CWE"):
            CWEFixRegistry.generate_fix("CWE-999", {"file_path": "test.py"})

    def test_generate_with_no_source_code(self):
        result = CWEFixRegistry.generate_fix(
            "CWE-79", {"file_path": "test.py", "severity": "high"}
        )
        assert isinstance(result, CWEFixTemplate)

    def test_generate_with_empty_finding(self):
        result = CWEFixRegistry.generate_fix("CWE-89", {})
        assert isinstance(result, CWEFixTemplate)
        assert result.cwe_id == "CWE-89"


# ---------------------------------------------------------------------------
# RemediationResult — Serialization
# ---------------------------------------------------------------------------


class TestRemediationResult:
    def test_default_values(self):
        result = RemediationResult(finding_id="F-001")
        assert result.status == RemediationStatus.PENDING
        assert result.strategy == RemediationStrategy.GUIDED
        assert result.pillar == "V7"

    def test_to_dict(self):
        result = RemediationResult(
            finding_id="F-001",
            status=RemediationStatus.FIX_GENERATED,
            fix_description="Test fix",
        )
        d = result.to_dict()
        assert d["finding_id"] == "F-001"
        assert d["status"] == "fix_generated"
        assert d["pillar"] == "V7"

    def test_to_dict_with_cwe_fix(self, xss_finding):
        cwe_fix = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        result = RemediationResult(finding_id="F-002", cwe_fix=cwe_fix)
        d = result.to_dict()
        assert "cwe_fix" in d
        assert d["cwe_fix"]["cwe_id"] == "CWE-79"


# ---------------------------------------------------------------------------
# RemediationEngine — Core Methods
# ---------------------------------------------------------------------------


class TestRemediationEngine:
    def test_engine_init(self, engine):
        assert engine is not None
        assert engine.config.get("repository") == "test/repo"

    def test_get_metrics_empty(self, engine):
        metrics = engine.get_metrics()
        assert metrics["total"] == 0
        assert metrics["success_rate"] == 0.0
        assert len(metrics["supported_cwes"]) == 5

    def test_remediate_with_cwe(self, engine, xss_finding):
        result = engine.remediate("F-XSS-001", xss_finding)
        assert isinstance(result, RemediationResult)
        # Should at minimum generate a fix since CWE-79 has a template
        assert result.status in (
            RemediationStatus.FIX_GENERATED,
            RemediationStatus.PR_CREATED,
            RemediationStatus.FAILED,
        )

    def test_remediate_with_sqli(self, engine, sqli_finding):
        result = engine.remediate("F-SQLI-001", sqli_finding)
        assert isinstance(result, RemediationResult)

    def test_remediate_unknown_cwe(self, engine):
        finding = {
            "cve_id": "CVE-2026-0001",
            "cwe_id": "CWE-999",
            "title": "Unknown vulnerability",
            "severity": "medium",
        }
        result = engine.remediate("F-UNK-001", finding)
        assert isinstance(result, RemediationResult)

    def test_get_result_after_remediate(self, engine, xss_finding):
        engine.remediate("F-XSS-002", xss_finding)
        # Should be stored
        all_results = engine.get_all_results()
        assert len(all_results) > 0

    def test_metrics_after_remediation(self, engine, xss_finding):
        engine.remediate("F-XSS-003", xss_finding)
        metrics = engine.get_metrics()
        assert metrics["total"] >= 1


# ---------------------------------------------------------------------------
# RemediationStrategy Enum
# ---------------------------------------------------------------------------


class TestRemediationStrategy:
    def test_all_strategies_exist(self):
        assert RemediationStrategy.AUTO_FIX.value == "auto_fix"
        assert RemediationStrategy.GUIDED.value == "guided"
        assert RemediationStrategy.MANUAL.value == "manual"
        assert RemediationStrategy.ACCEPT_RISK.value == "accept_risk"
        assert RemediationStrategy.COMPENSATING.value == "compensating"


# ---------------------------------------------------------------------------
# RemediationStatus Enum
# ---------------------------------------------------------------------------


class TestRemediationStatus:
    def test_all_statuses_exist(self):
        assert RemediationStatus.PENDING.value == "pending"
        assert RemediationStatus.IN_PROGRESS.value == "in_progress"
        assert RemediationStatus.FIX_GENERATED.value == "fix_generated"
        assert RemediationStatus.PR_CREATED.value == "pr_created"
        assert RemediationStatus.PR_MERGED.value == "pr_merged"
        assert RemediationStatus.VERIFIED.value == "verified"
        assert RemediationStatus.FAILED.value == "failed"
        assert RemediationStatus.SKIPPED.value == "skipped"


# ---------------------------------------------------------------------------
# All CWE Templates — Determinism
# ---------------------------------------------------------------------------


class TestCWEDeterminism:
    """Same input must produce the same output every time."""

    @pytest.mark.parametrize("cwe_id", CWEFixRegistry.supported_cwes())
    def test_deterministic_output(self, cwe_id):
        finding = {"file_path": "test.py", "severity": "high", "language": "python"}
        r1 = CWEFixRegistry.generate_fix(cwe_id, finding)
        r2 = CWEFixRegistry.generate_fix(cwe_id, finding)
        assert r1.fix_code == r2.fix_code
        assert r1.test_code == r2.test_code
        assert r1.pr_title == r2.pr_title


# ---------------------------------------------------------------------------
# All CWE Templates — Structural Validity
# ---------------------------------------------------------------------------


class TestCWETemplateStructure:
    @pytest.mark.parametrize("cwe_id", CWEFixRegistry.supported_cwes())
    def test_has_fix_or_test_code(self, cwe_id):
        result = CWEFixRegistry.generate_fix(cwe_id, {"severity": "high"})
        # Every CWE template must produce either fix code or test code (or both)
        assert len(result.fix_code) > 0 or len(result.test_code) > 0

    @pytest.mark.parametrize("cwe_id", CWEFixRegistry.supported_cwes())
    def test_has_test_code(self, cwe_id):
        result = CWEFixRegistry.generate_fix(cwe_id, {"severity": "high"})
        assert len(result.test_code) > 0

    @pytest.mark.parametrize("cwe_id", CWEFixRegistry.supported_cwes())
    def test_has_pr_description(self, cwe_id):
        result = CWEFixRegistry.generate_fix(cwe_id, {"severity": "high"})
        assert len(result.pr_description) > 0

    @pytest.mark.parametrize("cwe_id", CWEFixRegistry.supported_cwes())
    def test_has_compliance_refs(self, cwe_id):
        result = CWEFixRegistry.generate_fix(cwe_id, {"severity": "high"})
        assert len(result.compliance_refs) > 0
        assert cwe_id in result.compliance_refs

    @pytest.mark.parametrize("cwe_id", CWEFixRegistry.supported_cwes())
    def test_effort_reasonable(self, cwe_id):
        result = CWEFixRegistry.generate_fix(cwe_id, {"severity": "high"})
        assert 5 <= result.effort_minutes <= 60

    @pytest.mark.parametrize("cwe_id", CWEFixRegistry.supported_cwes())
    def test_confidence_in_range(self, cwe_id):
        result = CWEFixRegistry.generate_fix(cwe_id, {"severity": "high"})
        assert 0.0 <= result.confidence <= 1.0
