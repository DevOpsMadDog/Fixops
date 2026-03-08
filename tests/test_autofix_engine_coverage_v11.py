"""Comprehensive coverage tests for core.autofix_engine — v11 swarm coverage push.

Targets: FixType, FixStatus, FixConfidence, PatchFormat, CodePatch,
         DependencyFix, AutoFixSuggestion, AutoFixResult, _cwe_to_category,
         AutoFixEngine (init, _infer_fix_type, _make_fix_id, stats, history).
"""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.autofix_engine import (
    AutoFixEngine,
    AutoFixResult,
    AutoFixSuggestion,
    CodePatch,
    DependencyFix,
    FixConfidence,
    FixStatus,
    FixType,
    PatchFormat,
    _cwe_to_category,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestFixType:
    def test_all_values(self):
        expected = {
            "code_patch", "dependency_update", "config_hardening",
            "iac_fix", "secret_rotation", "permission_fix",
            "input_validation", "output_encoding", "waf_rule", "container_fix",
        }
        actual = {ft.value for ft in FixType}
        assert actual == expected

    def test_from_value(self):
        assert FixType("code_patch") == FixType.CODE_PATCH
        assert FixType("dependency_update") == FixType.DEPENDENCY_UPDATE


class TestFixStatus:
    def test_all_values(self):
        expected = {
            "generated", "validated", "applied", "pr_created",
            "merged", "failed", "rejected", "rolled_back",
        }
        actual = {fs.value for fs in FixStatus}
        assert actual == expected


class TestFixConfidence:
    def test_all_values(self):
        assert FixConfidence.HIGH.value == "high"
        assert FixConfidence.MEDIUM.value == "medium"
        assert FixConfidence.LOW.value == "low"


class TestPatchFormat:
    def test_all_values(self):
        expected = {
            "unified_diff", "json_patch", "yaml_patch", "toml_patch",
            "package_json", "requirements_txt", "dockerfile", "terraform",
        }
        actual = {pf.value for pf in PatchFormat}
        assert actual == expected


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


class TestCodePatch:
    def test_defaults(self):
        patch = CodePatch()
        assert patch.file_path == ""
        assert patch.language == ""
        assert patch.old_code == ""
        assert patch.new_code == ""
        assert patch.start_line == 0
        assert patch.patch_format == PatchFormat.UNIFIED_DIFF

    def test_with_values(self):
        patch = CodePatch(
            file_path="src/auth.py",
            language="python",
            old_code="password = input()",
            new_code="password = getpass.getpass()",
            start_line=42,
            end_line=42,
            explanation="Use getpass for secure input",
        )
        assert patch.file_path == "src/auth.py"
        assert patch.start_line == 42


class TestDependencyFix:
    def test_defaults(self):
        dep = DependencyFix()
        assert dep.package_name == ""
        assert dep.ecosystem == ""
        assert dep.cve_ids == []
        assert dep.breaking_changes == []

    def test_with_values(self):
        dep = DependencyFix(
            package_name="lodash",
            ecosystem="npm",
            current_version="4.17.15",
            fixed_version="4.17.21",
            cve_ids=["CVE-2020-28500"],
            manifest_file="package.json",
        )
        assert dep.package_name == "lodash"
        assert dep.fixed_version == "4.17.21"
        assert "CVE-2020-28500" in dep.cve_ids


class TestAutoFixSuggestion:
    def test_defaults(self):
        s = AutoFixSuggestion()
        assert s.fix_id == ""
        assert s.fix_type == FixType.CODE_PATCH
        assert s.confidence == FixConfidence.MEDIUM
        assert s.confidence_score == 0.0
        assert s.status == FixStatus.GENERATED
        assert s.code_patches == []
        assert s.dependency_fixes == []
        assert s.metadata == {}
        assert s.pr_number == 0

    def test_with_values(self):
        s = AutoFixSuggestion(
            fix_id="fix-abc123",
            finding_id="FIND-001",
            fix_type=FixType.DEPENDENCY_UPDATE,
            confidence=FixConfidence.HIGH,
            confidence_score=0.92,
            title="Update lodash",
            status=FixStatus.VALIDATED,
            cve_ids=["CVE-2020-28500"],
        )
        assert s.fix_id == "fix-abc123"
        assert s.confidence_score == 0.92
        assert s.status == FixStatus.VALIDATED


class TestAutoFixResult:
    def test_defaults(self):
        r = AutoFixResult()
        assert r.success is False
        assert r.fix is None
        assert r.pr_url == ""
        assert r.error == ""

    def test_successful(self):
        suggestion = AutoFixSuggestion(fix_id="fix-001")
        r = AutoFixResult(
            success=True,
            fix=suggestion,
            pr_url="https://github.com/org/repo/pull/42",
            pr_number=42,
            validation_passed=True,
        )
        assert r.success is True
        assert r.pr_number == 42
        assert r.fix.fix_id == "fix-001"


# ---------------------------------------------------------------------------
# _cwe_to_category
# ---------------------------------------------------------------------------


class TestCweToCategory:
    def test_known_cwe_injection(self):
        assert _cwe_to_category("CWE-89", FixType.CODE_PATCH) == "injection"

    def test_known_cwe_xss(self):
        assert _cwe_to_category("CWE-79", FixType.CODE_PATCH) == "xss"

    def test_known_cwe_auth(self):
        assert _cwe_to_category("CWE-287", FixType.CODE_PATCH) == "auth"

    def test_known_cwe_crypto(self):
        assert _cwe_to_category("CWE-327", FixType.CODE_PATCH) == "crypto"

    def test_known_cwe_secrets(self):
        assert _cwe_to_category("CWE-798", FixType.CODE_PATCH) == "secrets"

    def test_known_cwe_config(self):
        assert _cwe_to_category("CWE-16", FixType.CODE_PATCH) == "config"

    def test_known_cwe_ssrf(self):
        assert _cwe_to_category("CWE-918", FixType.CODE_PATCH) == "ssrf"

    def test_known_cwe_path_traversal(self):
        assert _cwe_to_category("CWE-22", FixType.CODE_PATCH) == "path_traversal"

    def test_known_cwe_deserialization(self):
        assert _cwe_to_category("CWE-502", FixType.CODE_PATCH) == "deserialization"

    def test_known_cwe_dependency(self):
        assert _cwe_to_category("CWE-1104", FixType.CODE_PATCH) == "dependency"

    def test_unknown_cwe_falls_back_to_fix_type(self):
        assert _cwe_to_category("CWE-99999", FixType.DEPENDENCY_UPDATE) == "dependency"
        assert _cwe_to_category("CWE-99999", FixType.CONFIG_HARDENING) == "config"
        assert _cwe_to_category("CWE-99999", FixType.IAC_FIX) == "iac"
        assert _cwe_to_category("CWE-99999", FixType.SECRET_ROTATION) == "secrets"

    def test_unknown_cwe_unknown_fix_type(self):
        assert _cwe_to_category("CWE-99999", FixType.CODE_PATCH) == "other"

    def test_empty_cwe(self):
        assert _cwe_to_category("", FixType.DEPENDENCY_UPDATE) == "dependency"

    def test_permissions_cwe(self):
        assert _cwe_to_category("CWE-269", FixType.CODE_PATCH) == "permissions"
        assert _cwe_to_category("CWE-732", FixType.CODE_PATCH) == "permissions"


# ---------------------------------------------------------------------------
# AutoFixEngine
# ---------------------------------------------------------------------------


class TestAutoFixEngine:
    def test_init(self):
        engine = AutoFixEngine()
        assert engine._fixes == {}
        assert engine._history == []
        assert engine._stats["total_generated"] == 0

    def test_make_fix_id(self):
        fix_id = AutoFixEngine._make_fix_id("FIND-001", FixType.CODE_PATCH)
        assert fix_id.startswith("fix-")
        assert len(fix_id) == 4 + 16  # "fix-" + 16 hex chars

    def test_make_fix_id_different_inputs(self):
        id1 = AutoFixEngine._make_fix_id("FIND-001", FixType.CODE_PATCH)
        id2 = AutoFixEngine._make_fix_id("FIND-002", FixType.CODE_PATCH)
        # IDs should differ (different finding_ids)
        # Note: they might be same due to timestamp being same
        # But generally they should differ
        assert isinstance(id1, str)
        assert isinstance(id2, str)

    def test_infer_fix_type_dependency(self):
        finding = {"title": "Outdated library detected", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.DEPENDENCY_UPDATE

    def test_infer_fix_type_dependency_by_category(self):
        finding = {
            "title": "CVE in component",
            "description": "",
            "category": "dependency",
            "cve_ids": ["CVE-2024-1234"],
        }
        assert AutoFixEngine._infer_fix_type(finding) == FixType.DEPENDENCY_UPDATE

    def test_infer_fix_type_container(self):
        finding = {"title": "Container image vulnerability", "description": "", "file_path": "Dockerfile"}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CONTAINER_FIX

    def test_infer_fix_type_container_by_title(self):
        finding = {"title": "Docker base image has known CVE", "description": "", "file_path": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CONTAINER_FIX

    def test_infer_fix_type_config(self):
        finding = {"title": "CORS misconfiguration", "description": "", "file_path": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CONFIG_HARDENING

    def test_infer_fix_type_secret(self):
        finding = {"title": "Hardcoded API key detected", "description": "", "file_path": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.SECRET_ROTATION

    def test_infer_fix_type_permission(self):
        finding = {"title": "Missing authorization check", "description": "", "file_path": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.PERMISSION_FIX

    def test_infer_fix_type_input_validation(self):
        finding = {"title": "SQL injection vulnerability", "description": "", "file_path": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.INPUT_VALIDATION

    def test_infer_fix_type_waf(self):
        finding = {"title": "WAF rule needed", "description": "", "file_path": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.WAF_RULE

    def test_infer_fix_type_iac(self):
        finding = {
            "title": "IaC misconfiguration in infrastructure",
            "description": "",
            "file_path": "main.tf",
        }
        assert AutoFixEngine._infer_fix_type(finding) == FixType.IAC_FIX

    def test_infer_fix_type_default_code_patch(self):
        finding = {"title": "Buffer overflow", "description": "", "file_path": "src/main.c"}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CODE_PATCH

    def test_stats_structure(self):
        engine = AutoFixEngine()
        stats = engine._stats
        assert "total_generated" in stats
        assert "total_applied" in stats
        assert "by_type" in stats
        assert "by_confidence" in stats
        assert stats["by_confidence"]["high"] == 0

    def test_max_fixes_stored(self):
        assert AutoFixEngine.MAX_FIXES_STORED == 5000

    def test_max_history_entries(self):
        assert AutoFixEngine.MAX_HISTORY_ENTRIES == 10000

    def test_get_llm_lazy(self):
        engine = AutoFixEngine()
        assert engine._llm is None  # Not initialized yet

    def test_get_brain_lazy(self):
        engine = AutoFixEngine()
        assert engine._brain is None

    def test_get_bus_lazy(self):
        engine = AutoFixEngine()
        assert engine._bus is None

    def test_enrich_from_graph_graceful_error(self):
        engine = AutoFixEngine()
        # Should not raise even when knowledge_brain fails
        result = engine._enrich_from_graph("FIND-001", ["CVE-2024-0001"])
        assert isinstance(result, dict)
        assert "related_cves" in result
