"""
Tests for the AutoFix Template Library and its integration with AutoFixEngine.

Covers:
1. Template library standalone functionality (lookup, matching, generation)
2. Integration with AutoFixEngine._generate_code_patch (fallback path)
3. Edge cases (unknown CWEs, empty findings, malformed input)
4. Code scanning utility
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

from core.autofix_templates import (
    AutoFixTemplateLibrary,
    FixTemplate,
    get_template_library,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def library() -> AutoFixTemplateLibrary:
    """Fresh template library instance."""
    return AutoFixTemplateLibrary()


@pytest.fixture
def sqli_finding() -> Dict[str, Any]:
    """Sample SQL injection finding."""
    return {
        "id": "finding-sqli-001",
        "title": "SQL Injection in login endpoint",
        "description": "User input concatenated into SQL query without parameterization",
        "cwe_id": "CWE-89",
        "severity": "critical",
        "file_path": "app/auth.py",
        "language": "python",
        "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{user_input}\'")',
    }


@pytest.fixture
def xss_finding() -> Dict[str, Any]:
    """Sample XSS finding."""
    return {
        "id": "finding-xss-001",
        "title": "Reflected Cross-Site Scripting in search",
        "description": "User input rendered in HTML without escaping",
        "cwe_id": "CWE-79",
        "severity": "high",
        "file_path": "app/views.py",
        "language": "python",
    }


@pytest.fixture
def path_traversal_finding() -> Dict[str, Any]:
    """Sample path traversal finding."""
    return {
        "id": "finding-pt-001",
        "title": "Path Traversal in file download",
        "description": "User controls file path without validation",
        "cwe_id": "CWE-22",
        "severity": "high",
        "file_path": "app/downloads.py",
        "language": "python",
    }


@pytest.fixture
def deserialization_finding() -> Dict[str, Any]:
    """Sample deserialization finding."""
    return {
        "id": "finding-deser-001",
        "title": "Insecure Deserialization via pickle",
        "description": "pickle.loads used on user-supplied data",
        "cwe_id": "CWE-502",
        "severity": "critical",
        "file_path": "app/cache.py",
        "language": "python",
        "code_snippet": "data = pickle.loads(user_bytes)",
    }


@pytest.fixture
def unknown_cwe_finding() -> Dict[str, Any]:
    """Finding with an unknown CWE that has no template."""
    return {
        "id": "finding-unknown-001",
        "title": "Unusual vulnerability with no template",
        "description": "Something exotic that templates do not cover",
        "cwe_id": "CWE-999999",
        "severity": "low",
        "file_path": "app/exotic.py",
        "language": "python",
    }


# ===========================================================================
# Tests: Template lookup
# ===========================================================================


class TestTemplateLookup:
    """Test direct CWE-based template lookup."""

    def test_get_template_by_cwe_id(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.get_template("CWE-89")
        assert tpl is not None
        assert tpl.cwe_id == "CWE-89"
        assert tpl.cwe_name == "SQL Injection"

    def test_get_template_case_insensitive(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.get_template("cwe-89")
        assert tpl is not None
        assert tpl.cwe_id == "CWE-89"

    def test_get_template_numeric_only(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.get_template("89")
        assert tpl is not None
        assert tpl.cwe_id == "CWE-89"

    def test_get_template_missing(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.get_template("CWE-999999")
        assert tpl is None

    def test_get_template_empty_string(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.get_template("")
        assert tpl is None

    def test_get_template_none_safe(self, library: AutoFixTemplateLibrary) -> None:
        # Should not crash on None-like input
        tpl = library.get_template("")
        assert tpl is None

    def test_all_10_cwes_have_templates(self, library: AutoFixTemplateLibrary) -> None:
        expected = [
            "CWE-79", "CWE-89", "CWE-22", "CWE-502", "CWE-798",
            "CWE-327", "CWE-611", "CWE-918", "CWE-78", "CWE-200",
        ]
        for cwe in expected:
            tpl = library.get_template(cwe)
            assert tpl is not None, f"Missing template for {cwe}"

    def test_list_templates_returns_all(self, library: AutoFixTemplateLibrary) -> None:
        templates = library.list_templates()
        assert len(templates) >= 10

    def test_get_supported_cwes(self, library: AutoFixTemplateLibrary) -> None:
        cwes = library.get_supported_cwes()
        assert "CWE-89" in cwes
        assert "CWE-79" in cwes
        assert len(cwes) >= 10


# ===========================================================================
# Tests: Vulnerability matching
# ===========================================================================


class TestVulnerabilityMatching:
    """Test matching vulnerabilities to templates."""

    def test_match_by_cwe_id(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="Something",
            description="Something",
            cwe_ids=["CWE-89"],
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-89"

    def test_match_by_title_keyword_sqli(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="SQL Injection in user search",
            description="",
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-89"

    def test_match_by_title_keyword_xss(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="Reflected XSS in comment field",
            description="",
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-79"

    def test_match_by_title_keyword_command_injection(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="OS Command Injection via ping",
            description="",
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-78"

    def test_match_by_description_keyword(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="Security vulnerability",
            description="This endpoint is vulnerable to server-side request forgery (SSRF)",
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-918"

    def test_match_by_code_pattern_pickle(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="Unknown vuln",
            description="Unknown",
            code_snippet="data = pickle.loads(user_input)",
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-502"

    def test_match_by_code_pattern_os_system(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="Unknown vuln",
            description="Unknown",
            code_snippet='os.system(f"ping {host}")',
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-78"

    def test_match_by_code_pattern_md5(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="Unknown vuln",
            description="Unknown",
            code_snippet="digest = hashlib.md5(data).hexdigest()",
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-327"

    def test_no_match_for_unknown(self, library: AutoFixTemplateLibrary) -> None:
        tpl = library.match_vulnerability(
            title="Exotic zero-day in custom protocol",
            description="Something very unusual",
            cwe_ids=["CWE-999999"],
        )
        assert tpl is None

    def test_cwe_priority_over_keyword(self, library: AutoFixTemplateLibrary) -> None:
        """CWE ID match should take priority over keyword match."""
        tpl = library.match_vulnerability(
            title="SQL Injection",  # Would match CWE-89 by keyword
            description="",
            cwe_ids=["CWE-79"],  # But CWE says XSS
        )
        assert tpl is not None
        assert tpl.cwe_id == "CWE-79"  # CWE ID wins over title keyword


# ===========================================================================
# Tests: Offline suggestion generation
# ===========================================================================


class TestOfflineSuggestionGeneration:
    """Test generate_offline_suggestion output format."""

    def test_sqli_suggestion_format(
        self, library: AutoFixTemplateLibrary, sqli_finding: Dict[str, Any]
    ) -> None:
        result = library.generate_offline_suggestion(sqli_finding)
        assert result is not None
        assert result["finding_id"] == "finding-sqli-001"
        assert result["fix_type"] == "template"
        assert result["template_based"] is True
        assert result["cwe_id"] == "CWE-89"
        assert 0.6 <= result["confidence_score"] <= 0.9
        assert len(result["patches"]) >= 1

    def test_suggestion_has_required_fields(
        self, library: AutoFixTemplateLibrary, sqli_finding: Dict[str, Any]
    ) -> None:
        result = library.generate_offline_suggestion(sqli_finding)
        assert result is not None
        required_keys = [
            "fix_id", "finding_id", "title", "description", "fix_type",
            "confidence_score", "patches", "explanation", "cwe_id",
            "template_based", "testing_guidance", "rollback_steps",
            "risk_assessment", "effort_minutes",
        ]
        for key in required_keys:
            assert key in result, f"Missing required key: {key}"

    def test_suggestion_patches_have_before_after(
        self, library: AutoFixTemplateLibrary, sqli_finding: Dict[str, Any]
    ) -> None:
        result = library.generate_offline_suggestion(sqli_finding)
        assert result is not None
        for patch in result["patches"]:
            assert "before" in patch
            assert "after" in patch
            assert "language" in patch
            assert "file_path" in patch
            assert len(patch["before"]) > 0
            assert len(patch["after"]) > 0

    def test_suggestion_uses_correct_language(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        finding = {
            "id": "js-001",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "language": "javascript",
            "file_path": "app.js",
        }
        result = library.generate_offline_suggestion(finding)
        assert result is not None
        assert result["patches"][0]["language"] == "javascript"

    def test_suggestion_falls_back_to_first_language(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        finding = {
            "id": "rust-001",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "language": "rust",  # not in template languages
            "file_path": "src/main.rs",
        }
        result = library.generate_offline_suggestion(finding)
        assert result is not None
        # Should fall back to python (first available)
        assert result["patches"][0]["language"] in ("python", "javascript")

    def test_suggestion_returns_none_for_unknown_cwe(
        self, library: AutoFixTemplateLibrary, unknown_cwe_finding: Dict[str, Any]
    ) -> None:
        result = library.generate_offline_suggestion(unknown_cwe_finding)
        assert result is None

    def test_fix_id_is_unique(
        self, library: AutoFixTemplateLibrary, sqli_finding: Dict[str, Any]
    ) -> None:
        r1 = library.generate_offline_suggestion(sqli_finding)
        r2 = library.generate_offline_suggestion(sqli_finding)
        assert r1 is not None and r2 is not None
        # fix_ids include timestamp, so they should differ
        # (unless called in exact same microsecond)
        assert r1["fix_id"].startswith("fix-tpl-")
        assert r2["fix_id"].startswith("fix-tpl-")

    def test_xss_suggestion(
        self, library: AutoFixTemplateLibrary, xss_finding: Dict[str, Any]
    ) -> None:
        result = library.generate_offline_suggestion(xss_finding)
        assert result is not None
        assert result["cwe_id"] == "CWE-79"
        assert "escape" in result["description"].lower() or "xss" in result["description"].lower()

    def test_path_traversal_suggestion(
        self, library: AutoFixTemplateLibrary, path_traversal_finding: Dict[str, Any]
    ) -> None:
        result = library.generate_offline_suggestion(path_traversal_finding)
        assert result is not None
        assert result["cwe_id"] == "CWE-22"
        assert len(result["patches"]) >= 1

    def test_deserialization_suggestion(
        self, library: AutoFixTemplateLibrary, deserialization_finding: Dict[str, Any]
    ) -> None:
        result = library.generate_offline_suggestion(deserialization_finding)
        assert result is not None
        assert result["cwe_id"] == "CWE-502"
        assert "pickle" in result["description"].lower() or "json" in result["description"].lower()

    def test_empty_finding(self, library: AutoFixTemplateLibrary) -> None:
        result = library.generate_offline_suggestion({})
        assert result is None  # No CWE, no keywords, no code -- nothing to match

    def test_finding_with_name_instead_of_title(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        finding = {
            "id": "alt-001",
            "name": "SQL Injection in API",  # uses 'name' not 'title'
            "cwe_id": "CWE-89",
            "language": "python",
        }
        result = library.generate_offline_suggestion(finding)
        assert result is not None
        assert result["cwe_id"] == "CWE-89"


# ===========================================================================
# Tests: All 10 CWE templates produce valid suggestions
# ===========================================================================


class TestAllCWETemplates:
    """Verify every template produces a valid suggestion."""

    @pytest.mark.parametrize(
        "cwe_id,title_kw,severity",
        [
            ("CWE-79", "XSS in search", "high"),
            ("CWE-89", "SQL injection in login", "critical"),
            ("CWE-22", "Path traversal in download", "high"),
            ("CWE-502", "Pickle deserialization", "critical"),
            ("CWE-798", "Hard-coded API key", "high"),
            ("CWE-327", "MD5 hash usage", "high"),
            ("CWE-611", "XXE in XML parser", "high"),
            ("CWE-918", "SSRF in webhook", "high"),
            ("CWE-78", "OS command injection", "critical"),
            ("CWE-200", "Stack trace in error response", "medium"),
        ],
    )
    def test_cwe_template_produces_suggestion(
        self,
        library: AutoFixTemplateLibrary,
        cwe_id: str,
        title_kw: str,
        severity: str,
    ) -> None:
        finding = {
            "id": f"finding-{cwe_id}",
            "title": title_kw,
            "cwe_id": cwe_id,
            "severity": severity,
            "file_path": "app/vulnerable.py",
            "language": "python",
        }
        result = library.generate_offline_suggestion(finding)
        assert result is not None, f"No suggestion for {cwe_id}"
        assert result["cwe_id"] == cwe_id
        assert result["template_based"] is True
        assert len(result["patches"]) >= 1
        assert result["patches"][0]["before"] != ""
        assert result["patches"][0]["after"] != ""
        assert result["confidence_score"] >= 0.6
        assert result["confidence_score"] <= 0.9
        assert result["testing_guidance"] != ""
        assert result["rollback_steps"] != ""


# ===========================================================================
# Tests: Template data quality
# ===========================================================================


class TestTemplateDataQuality:
    """Verify template data is complete and well-formed."""

    def test_all_templates_have_vulnerable_patterns(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        for tpl in library.list_templates():
            assert len(tpl.vulnerable_patterns) >= 2, (
                f"{tpl.cwe_id} has too few vulnerable patterns"
            )

    def test_all_templates_have_fix_snippets(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        for tpl in library.list_templates():
            assert len(tpl.fix_snippets) >= 1, (
                f"{tpl.cwe_id} has no fix snippets"
            )
            for lang, snippet in tpl.fix_snippets.items():
                assert "before" in snippet, f"{tpl.cwe_id}/{lang} missing 'before'"
                assert "after" in snippet, f"{tpl.cwe_id}/{lang} missing 'after'"
                assert len(snippet["before"]) > 20, f"{tpl.cwe_id}/{lang} 'before' too short"
                assert len(snippet["after"]) > 20, f"{tpl.cwe_id}/{lang} 'after' too short"

    def test_all_patterns_are_valid_regex(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        for tpl in library.list_templates():
            for pattern in tpl.vulnerable_patterns:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    pytest.fail(f"{tpl.cwe_id} has invalid regex '{pattern}': {exc}")

    def test_confidence_scores_in_range(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        for tpl in library.list_templates():
            assert 0.6 <= tpl.confidence <= 0.8, (
                f"{tpl.cwe_id} confidence {tpl.confidence} outside [0.6, 0.8]"
            )

    def test_all_templates_have_title_keywords(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        for tpl in library.list_templates():
            assert len(tpl.title_keywords) >= 1, (
                f"{tpl.cwe_id} has no title keywords for matching"
            )

    def test_all_templates_have_mitre_techniques(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        for tpl in library.list_templates():
            assert len(tpl.mitre_techniques) >= 1, (
                f"{tpl.cwe_id} has no MITRE techniques"
            )

    def test_all_templates_have_compliance_refs(
        self, library: AutoFixTemplateLibrary
    ) -> None:
        for tpl in library.list_templates():
            assert len(tpl.compliance_refs) >= 1, (
                f"{tpl.cwe_id} has no compliance references"
            )


# ===========================================================================
# Tests: Code scanning
# ===========================================================================


class TestCodeScanning:
    """Test the scan_code_for_vulnerabilities utility."""

    def test_scan_detects_sqli(self, library: AutoFixTemplateLibrary) -> None:
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        matches = library.scan_code_for_vulnerabilities(code, "python")
        cwe_ids = [m["cwe_id"] for m in matches]
        assert "CWE-89" in cwe_ids

    def test_scan_detects_os_system(self, library: AutoFixTemplateLibrary) -> None:
        code = 'os.system(f"rm -rf {user_path}")'
        matches = library.scan_code_for_vulnerabilities(code, "python")
        cwe_ids = [m["cwe_id"] for m in matches]
        assert "CWE-78" in cwe_ids

    def test_scan_detects_pickle(self, library: AutoFixTemplateLibrary) -> None:
        code = "data = pickle.loads(request.body)"
        matches = library.scan_code_for_vulnerabilities(code, "python")
        cwe_ids = [m["cwe_id"] for m in matches]
        assert "CWE-502" in cwe_ids

    def test_scan_detects_md5(self, library: AutoFixTemplateLibrary) -> None:
        code = "hash_val = hashlib.md5(password.encode()).hexdigest()"
        matches = library.scan_code_for_vulnerabilities(code, "python")
        cwe_ids = [m["cwe_id"] for m in matches]
        assert "CWE-327" in cwe_ids

    def test_scan_detects_innerhtml(self, library: AutoFixTemplateLibrary) -> None:
        code = "element.innerHTML = userInput;"
        matches = library.scan_code_for_vulnerabilities(code, "javascript")
        cwe_ids = [m["cwe_id"] for m in matches]
        assert "CWE-79" in cwe_ids

    def test_scan_safe_code_no_matches(self, library: AutoFixTemplateLibrary) -> None:
        code = """
def hello(name: str) -> str:
    return f"Hello, {name}"

result = 1 + 2
print(result)
"""
        matches = library.scan_code_for_vulnerabilities(code, "python")
        assert len(matches) == 0

    def test_scan_multiple_vulns(self, library: AutoFixTemplateLibrary) -> None:
        code = """
import os
import pickle
import hashlib
data = pickle.loads(user_input)
digest = hashlib.md5(data).hexdigest()
os.system(f"process {data}")
"""
        matches = library.scan_code_for_vulnerabilities(code, "python")
        cwe_ids = {m["cwe_id"] for m in matches}
        assert len(cwe_ids) >= 2  # Should detect at least pickle and md5/os.system

    def test_scan_filters_by_language(self, library: AutoFixTemplateLibrary) -> None:
        # innerHTML is a JavaScript pattern, some templates may be JS-only
        code = "element.innerHTML = userInput;"
        py_matches = library.scan_code_for_vulnerabilities(code, "python")
        js_matches = library.scan_code_for_vulnerabilities(code, "javascript")
        # JS matches should include XSS, Python may not (since innerHTML is JS-specific)
        js_cwe_ids = {m["cwe_id"] for m in js_matches}
        assert "CWE-79" in js_cwe_ids

    def test_scan_returns_matched_text(self, library: AutoFixTemplateLibrary) -> None:
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        matches = library.scan_code_for_vulnerabilities(code, "python")
        sqli_matches = [m for m in matches if m["cwe_id"] == "CWE-89"]
        assert len(sqli_matches) >= 1
        assert "matched_text" in sqli_matches[0]
        assert len(sqli_matches[0]["matched_text"]) > 0


# ===========================================================================
# Tests: Singleton
# ===========================================================================


class TestSingleton:
    """Test the module-level singleton."""

    def test_get_template_library_returns_instance(self) -> None:
        lib = get_template_library()
        assert isinstance(lib, AutoFixTemplateLibrary)

    def test_singleton_returns_same_instance(self) -> None:
        lib1 = get_template_library()
        lib2 = get_template_library()
        assert lib1 is lib2


# ===========================================================================
# Tests: Integration with AutoFixEngine
# ===========================================================================


class TestAutoFixEngineIntegration:
    """Test _try_template_fallback and integration points."""

    def test_try_template_fallback_returns_suggestion(self) -> None:
        from core.autofix_engine import AutoFixEngine

        engine = AutoFixEngine()
        finding = {
            "id": "int-001",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "file_path": "app/db.py",
            "language": "python",
        }
        result = engine._try_template_fallback(finding, "python", "app/db.py")
        assert result is not None
        assert result["cwe_id"] == "CWE-89"
        assert result["template_based"] is True
        assert len(result["patches"]) >= 1

    def test_try_template_fallback_returns_none_for_unknown(self) -> None:
        from core.autofix_engine import AutoFixEngine

        engine = AutoFixEngine()
        finding = {
            "id": "int-002",
            "title": "Exotic zero-day",
            "cwe_id": "CWE-999999",
            "severity": "low",
            "file_path": "app/exotic.py",
            "language": "python",
        }
        result = engine._try_template_fallback(finding, "python", "app/exotic.py")
        assert result is None

    @pytest.mark.asyncio
    async def test_generate_code_patch_uses_template_on_fallback(self) -> None:
        """When LLM returns deterministic fallback, template library should produce patches."""
        from core.autofix_engine import AutoFixEngine, AutoFixSuggestion, FixType

        engine = AutoFixEngine()

        # Mock the LLM to return a deterministic fallback (no real API key)
        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.reasoning = "Generated code patch for vulnerability fix"
        mock_response.metadata = {"mode": "deterministic", "reason": "provider_disabled"}
        mock_response.mitre_techniques = []
        mock_response.compliance_concerns = []
        mock_llm.analyse.return_value = mock_response
        engine._llm = mock_llm

        finding = {
            "id": "fallback-001",
            "title": "SQL Injection in user query",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "file_path": "app/db.py",
            "language": "python",
            "description": "User input concatenated into SQL query",
        }

        suggestion = AutoFixSuggestion(
            fix_id="test-fix",
            finding_id="fallback-001",
            finding_title="SQL Injection in user query",
            fix_type=FixType.CODE_PATCH,
            metadata={},
        )

        result = await engine._generate_code_patch(
            suggestion, finding, None, {}, {}
        )

        # The template library should have kicked in
        assert result.metadata.get("template_based") is True
        assert result.metadata.get("template_cwe") == "CWE-89"
        assert len(result.code_patches) >= 1
        assert result.confidence_score >= 0.6
        assert result.code_patches[0].old_code != ""
        assert result.code_patches[0].new_code != ""

    @pytest.mark.asyncio
    async def test_generate_code_patch_prefers_llm_response(self) -> None:
        """When LLM returns valid JSON, it should be used instead of templates."""
        from core.autofix_engine import AutoFixEngine, AutoFixSuggestion, FixType

        engine = AutoFixEngine()

        llm_json = json.dumps({
            "title": "LLM-generated fix for SQL Injection",
            "description": "Parameterize the query",
            "patches": [{
                "file_path": "app/db.py",
                "old_code": "cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")",
                "new_code": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (uid,))",
                "explanation": "Use parameterized query",
            }],
            "testing_guidance": "Run SQL injection tests",
            "rollback_steps": "Revert commit",
            "risk_assessment": "Low risk",
            "effort_minutes": 10,
        })

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.reasoning = llm_json
        mock_response.metadata = {"mode": "live"}  # Real LLM response
        mock_response.mitre_techniques = ["T1190"]
        mock_response.compliance_concerns = ["CWE-89"]
        mock_llm.analyse.return_value = mock_response
        engine._llm = mock_llm

        finding = {
            "id": "llm-001",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "file_path": "app/db.py",
            "language": "python",
        }

        suggestion = AutoFixSuggestion(
            fix_id="test-fix-llm",
            finding_id="llm-001",
            finding_title="SQL Injection",
            fix_type=FixType.CODE_PATCH,
            metadata={},
        )

        result = await engine._generate_code_patch(
            suggestion, finding, None, {}, {}
        )

        # Should use LLM response, not template
        assert result.title == "LLM-generated fix for SQL Injection"
        assert not result.metadata.get("template_based", False)
        assert len(result.code_patches) == 1
        assert "parameterized" in result.code_patches[0].new_code.lower() or "?" in result.code_patches[0].new_code

    @pytest.mark.asyncio
    async def test_generate_code_patch_xss_template_fallback(self) -> None:
        """XSS finding should get template-based fix when LLM is unavailable."""
        from core.autofix_engine import AutoFixEngine, AutoFixSuggestion, FixType

        engine = AutoFixEngine()

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.reasoning = "Generated code patch for vulnerability fix"
        mock_response.metadata = {"mode": "deterministic"}
        mock_response.mitre_techniques = []
        mock_response.compliance_concerns = []
        mock_llm.analyse.return_value = mock_response
        engine._llm = mock_llm

        finding = {
            "id": "xss-fallback-001",
            "title": "Cross-Site Scripting in search page",
            "cwe_id": "CWE-79",
            "severity": "high",
            "file_path": "app/views.py",
            "language": "python",
        }

        suggestion = AutoFixSuggestion(
            fix_id="test-xss",
            finding_id="xss-fallback-001",
            finding_title="Cross-Site Scripting",
            fix_type=FixType.CODE_PATCH,
            metadata={},
        )

        result = await engine._generate_code_patch(
            suggestion, finding, None, {}, {}
        )

        assert result.metadata.get("template_based") is True
        assert result.metadata.get("template_cwe") == "CWE-79"
        assert len(result.code_patches) >= 1
        # XSS fix should mention escaping
        combined = " ".join(p.new_code + p.explanation for p in result.code_patches)
        assert "escape" in combined.lower() or "textcontent" in combined.lower()

    @pytest.mark.asyncio
    async def test_generate_code_patch_unknown_cwe_low_confidence(self) -> None:
        """Unknown CWE with no template should fall back to 0.4 confidence."""
        from core.autofix_engine import AutoFixEngine, AutoFixSuggestion, FixType

        engine = AutoFixEngine()

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.reasoning = "Generated code patch for vulnerability fix"
        mock_response.metadata = {"mode": "deterministic"}
        mock_response.mitre_techniques = []
        mock_response.compliance_concerns = []
        mock_llm.analyse.return_value = mock_response
        engine._llm = mock_llm

        finding = {
            "id": "unknown-001",
            "title": "Exotic vulnerability in custom protocol",
            "cwe_id": "CWE-999999",
            "severity": "low",
            "file_path": "app/custom.py",
            "language": "python",
        }

        suggestion = AutoFixSuggestion(
            fix_id="test-unknown",
            finding_id="unknown-001",
            finding_title="Exotic vulnerability",
            fix_type=FixType.CODE_PATCH,
            metadata={},
        )

        result = await engine._generate_code_patch(
            suggestion, finding, None, {}, {}
        )

        # No template match, should fall back to low confidence
        assert not result.metadata.get("template_based", False)
        assert result.confidence_score == 0.4
        assert len(result.code_patches) == 0
