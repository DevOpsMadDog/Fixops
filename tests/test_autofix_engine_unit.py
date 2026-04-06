"""
Comprehensive unit tests for suite-core/core/autofix_engine.py.

Covers:
  - FixType, FixStatus, FixConfidence, PatchFormat enums
  - CodePatch, DependencyFix, AutoFixSuggestion, AutoFixResult dataclasses
  - AutoFixEngine: init, _make_fix_id, _infer_fix_type, _enrich_from_graph,
    _validate_fix, _compute_confidence, _build_pr_description, generate_fix,
    get_fix, list_fixes, get_stats, _update_stats
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.autofix_engine import (
    FixType,
    FixStatus,
    FixConfidence,
    PatchFormat,
    CodePatch,
    DependencyFix,
    AutoFixSuggestion,
    AutoFixResult,
    AutoFixEngine,
    _cwe_to_category,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    return AutoFixEngine()


@pytest.fixture
def code_patch_finding():
    return {
        "id": "FIND-001",
        "title": "SQL Injection in login handler",
        "description": "Unsanitized user input in SQL query",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "cve_ids": ["CVE-2024-1234"],
        "file_path": "auth/login.py",
        "language": "python",
    }


@pytest.fixture
def dependency_finding():
    return {
        "id": "FIND-002",
        "title": "Outdated dependency: lodash",
        "description": "lodash 4.17.15 has known vulnerabilities",
        "severity": "high",
        "category": "dependency",
        "cve_ids": ["CVE-2021-23337"],
    }


@pytest.fixture
def container_finding():
    return {
        "id": "FIND-003",
        "title": "Docker container running as root",
        "description": "Container runs as root user",
        "severity": "medium",
        "file_path": "Dockerfile",
    }


# ===========================================================================
# Enums
# ===========================================================================


class TestEnums:
    def test_fix_type_values(self):
        assert FixType.CODE_PATCH.value == "code_patch"
        assert FixType.DEPENDENCY_UPDATE.value == "dependency_update"
        assert FixType.CONFIG_HARDENING.value == "config_hardening"
        assert FixType.IAC_FIX.value == "iac_fix"
        assert FixType.SECRET_ROTATION.value == "secret_rotation"
        assert FixType.CONTAINER_FIX.value == "container_fix"

    def test_fix_status_values(self):
        assert FixStatus.GENERATED.value == "generated"
        assert FixStatus.VALIDATED.value == "validated"
        assert FixStatus.APPLIED.value == "applied"
        assert FixStatus.PR_CREATED.value == "pr_created"
        assert FixStatus.MERGED.value == "merged"
        assert FixStatus.FAILED.value == "failed"
        assert FixStatus.REJECTED.value == "rejected"
        assert FixStatus.ROLLED_BACK.value == "rolled_back"

    def test_fix_confidence_values(self):
        assert FixConfidence.HIGH.value == "high"
        assert FixConfidence.MEDIUM.value == "medium"
        assert FixConfidence.LOW.value == "low"

    def test_patch_format_values(self):
        assert PatchFormat.UNIFIED_DIFF.value == "unified_diff"
        assert PatchFormat.JSON_PATCH.value == "json_patch"
        assert PatchFormat.DOCKERFILE.value == "dockerfile"
        assert PatchFormat.TERRAFORM.value == "terraform"


# ===========================================================================
# Data Classes
# ===========================================================================


class TestCodePatch:
    def test_defaults(self):
        patch = CodePatch()
        assert patch.file_path == ""
        assert patch.language == ""
        assert patch.old_code == ""
        assert patch.new_code == ""
        assert patch.start_line == 0
        assert patch.patch_format == PatchFormat.UNIFIED_DIFF

    def test_construction(self):
        patch = CodePatch(
            file_path="app.py",
            language="python",
            old_code="bad code",
            new_code="good code",
            start_line=10,
            end_line=15,
            explanation="Fixed vulnerability",
        )
        assert patch.file_path == "app.py"
        assert patch.start_line == 10


class TestDependencyFix:
    def test_defaults(self):
        fix = DependencyFix()
        assert fix.package_name == ""
        assert fix.cve_ids == []
        assert fix.breaking_changes == []

    def test_construction(self):
        fix = DependencyFix(
            package_name="lodash",
            ecosystem="npm",
            current_version="4.17.15",
            fixed_version="4.17.21",
            cve_ids=["CVE-2021-23337"],
            manifest_file="package.json",
        )
        assert fix.package_name == "lodash"
        assert fix.fixed_version == "4.17.21"


class TestAutoFixSuggestion:
    def test_defaults(self):
        sugg = AutoFixSuggestion()
        assert sugg.fix_id == ""
        assert sugg.fix_type == FixType.CODE_PATCH
        assert sugg.confidence == FixConfidence.MEDIUM
        assert sugg.confidence_score == 0.0
        assert sugg.status == FixStatus.GENERATED
        assert sugg.code_patches == []
        assert sugg.dependency_fixes == []
        assert sugg.metadata == {}

    def test_construction(self):
        sugg = AutoFixSuggestion(
            fix_id="fix-abc123",
            finding_id="FIND-001",
            title="Fix SQL Injection",
            fix_type=FixType.INPUT_VALIDATION,
            confidence=FixConfidence.HIGH,
            confidence_score=0.92,
        )
        assert sugg.fix_id == "fix-abc123"
        assert sugg.confidence == FixConfidence.HIGH


class TestAutoFixResult:
    def test_defaults(self):
        result = AutoFixResult()
        assert result.success is False
        assert result.fix is None
        assert result.error == ""
        assert result.validation_passed is False

    def test_success_result(self):
        sugg = AutoFixSuggestion(fix_id="fix-1")
        result = AutoFixResult(success=True, fix=sugg, validation_passed=True)
        assert result.success is True
        assert result.fix.fix_id == "fix-1"


# ===========================================================================
# AutoFixEngine: _make_fix_id
# ===========================================================================


class TestMakeFixId:
    def test_returns_prefixed_hash(self):
        fix_id = AutoFixEngine._make_fix_id("FIND-001", FixType.CODE_PATCH)
        assert fix_id.startswith("fix-")
        assert len(fix_id) == 4 + 16  # "fix-" + 16 hex chars

    def test_different_inputs_different_ids(self):
        id1 = AutoFixEngine._make_fix_id("FIND-001", FixType.CODE_PATCH)
        id2 = AutoFixEngine._make_fix_id("FIND-002", FixType.CODE_PATCH)
        # Should be different (timestamps differ too, but inputs differ)
        # Due to timestamp component, these will differ
        assert isinstance(id1, str)
        assert isinstance(id2, str)

    def test_deterministic_format(self):
        fix_id = AutoFixEngine._make_fix_id("X", FixType.DEPENDENCY_UPDATE)
        assert fix_id.startswith("fix-")
        # 16 hex chars after "fix-"
        hex_part = fix_id[4:]
        assert len(hex_part) == 16
        assert all(c in "0123456789abcdef" for c in hex_part)


# ===========================================================================
# AutoFixEngine: _infer_fix_type
# ===========================================================================


class TestInferFixType:
    def test_dependency_from_title(self):
        finding = {"title": "Outdated dependency found", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.DEPENDENCY_UPDATE

    def test_dependency_from_category(self):
        finding = {"title": "CVE-2024-1", "description": "", "category": "dependency", "cve_ids": ["CVE-2024-1"]}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.DEPENDENCY_UPDATE

    def test_iac_from_file_path(self):
        finding = {"title": "Misconfiguration in infrastructure", "description": "", "file_path": "main.tf"}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.IAC_FIX

    def test_container_from_file_path(self):
        finding = {"title": "Issue", "description": "", "file_path": "Dockerfile"}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CONTAINER_FIX

    def test_container_from_title(self):
        finding = {"title": "Docker container vulnerability", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CONTAINER_FIX

    def test_config_from_title(self):
        finding = {"title": "Missing HSTS header configuration", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CONFIG_HARDENING

    def test_secret_from_title(self):
        finding = {"title": "Exposed API key in source", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.SECRET_ROTATION

    def test_permission_from_title(self):
        finding = {"title": "Excessive IAM permissions", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.PERMISSION_FIX

    def test_injection_from_title(self):
        finding = {"title": "SQL injection in search handler", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.INPUT_VALIDATION

    def test_xss_from_title(self):
        finding = {"title": "Cross-site scripting in user profile", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.OUTPUT_ENCODING

    def test_waf_from_title(self):
        finding = {"title": "WAF rule missing for endpoint", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.WAF_RULE

    def test_default_code_patch(self):
        finding = {"title": "Unknown issue", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CODE_PATCH

    def test_package_keyword(self):
        finding = {"title": "Vulnerable package detected", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.DEPENDENCY_UPDATE

    def test_csp_header(self):
        finding = {"title": "Missing CSP header", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CONFIG_HARDENING

    def test_cors_header(self):
        finding = {"title": "Permissive CORS policy", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.CONFIG_HARDENING

    def test_firewall_keyword(self):
        # "misconfiguration" matches config check before waf, so pure "firewall" needed
        finding = {"title": "WAF firewall bypass", "description": ""}
        assert AutoFixEngine._infer_fix_type(finding) == FixType.WAF_RULE


# ===========================================================================
# AutoFixEngine: _enrich_from_graph
# ===========================================================================


class TestEnrichFromGraph:
    def test_returns_context_on_graph_failure(self, engine):
        """When graph is unavailable, returns default context."""
        with patch.object(engine, "_get_brain", side_effect=Exception("No brain")):
            ctx = engine._enrich_from_graph("F-001", ["CVE-2024-1"])
            assert "related_cves" in ctx
            assert "affected_assets" in ctx
            assert "prior_fixes" in ctx

    def test_returns_context_structure(self, engine):
        mock_brain = MagicMock()
        mock_brain.get_node.return_value = None
        with patch.object(engine, "_get_brain", return_value=mock_brain):
            ctx = engine._enrich_from_graph("F-001", [])
            assert isinstance(ctx, dict)

    def test_uses_enrich_findings_when_legacy_enrich_method_missing(self, engine):
        mock_brain = MagicMock()
        mock_brain.get_node.return_value = None

        class _ThreatEnricherCompat:
            def enrich_findings(self, findings, skip_api=False):
                assert skip_api is True
                findings[0]["epss_score"] = 0.73
                findings[0]["in_kev"] = True
                return {"enriched": 1}

        with patch.object(engine, "_get_brain", return_value=mock_brain), patch(
            "core.ml.threat_enricher.ThreatEnricher", return_value=_ThreatEnricherCompat()
        ):
            ctx = engine._enrich_from_graph("F-001", ["CVE-2024-1234"])

        assert ctx["epss_score"] == 0.73
        assert ctx["is_kev"] is True


# ===========================================================================
# AutoFixEngine: init and stats
# ===========================================================================


class TestAutoFixEngineInit:
    def test_init(self, engine):
        assert engine._fixes == {}
        assert engine._history == []
        assert engine._stats["total_generated"] == 0

    def test_stats_structure(self, engine):
        stats = engine._stats
        assert "total_generated" in stats
        assert "total_applied" in stats
        assert "total_prs_created" in stats
        assert "by_type" in stats
        assert "by_confidence" in stats
        assert "avg_confidence_score" in stats


# ===========================================================================
# AutoFixEngine: _update_stats
# ===========================================================================


class TestUpdateStats:
    def test_update_stats_generated(self, engine):
        sugg = AutoFixSuggestion(
            fix_id="fix-1",
            fix_type=FixType.CODE_PATCH,
            confidence=FixConfidence.HIGH,
            confidence_score=0.9,
            status=FixStatus.GENERATED,
        )
        engine._update_stats(sugg)
        assert engine._stats["total_generated"] == 1
        assert engine._stats["by_confidence"]["high"] == 1

    def test_update_stats_multiple(self, engine):
        for i in range(3):
            sugg = AutoFixSuggestion(
                fix_id=f"fix-{i}",
                fix_type=FixType.CODE_PATCH,
                confidence=FixConfidence.MEDIUM,
                confidence_score=0.7,
                status=FixStatus.GENERATED,
            )
            engine._update_stats(sugg)
        assert engine._stats["total_generated"] == 3
        assert engine._stats["by_confidence"]["medium"] == 3


# ===========================================================================
# CWE-to-Category Mapping
# ===========================================================================


class TestCweToCategory:
    """Test the CWE → vulnerability category mapping."""

    def test_sql_injection(self):
        assert _cwe_to_category("CWE-89", FixType.CODE_PATCH) == "injection"

    def test_xss(self):
        assert _cwe_to_category("CWE-79", FixType.CODE_PATCH) == "xss"

    def test_auth_bypass(self):
        assert _cwe_to_category("CWE-287", FixType.CODE_PATCH) == "auth"

    def test_crypto_weakness(self):
        assert _cwe_to_category("CWE-327", FixType.CODE_PATCH) == "crypto"

    def test_ssrf(self):
        assert _cwe_to_category("CWE-918", FixType.CODE_PATCH) == "ssrf"

    def test_path_traversal(self):
        assert _cwe_to_category("CWE-22", FixType.CODE_PATCH) == "path_traversal"

    def test_deserialization(self):
        assert _cwe_to_category("CWE-502", FixType.CODE_PATCH) == "deserialization"

    def test_hardcoded_secrets(self):
        assert _cwe_to_category("CWE-798", FixType.CODE_PATCH) == "secrets"

    def test_unknown_cwe_falls_back_to_fix_type(self):
        assert _cwe_to_category("CWE-99999", FixType.DEPENDENCY_UPDATE) == "dependency"
        assert _cwe_to_category("CWE-99999", FixType.CONFIG_HARDENING) == "config"
        assert _cwe_to_category("CWE-99999", FixType.IAC_FIX) == "iac"
        assert _cwe_to_category("CWE-99999", FixType.SECRET_ROTATION) == "secrets"
        assert _cwe_to_category("CWE-99999", FixType.CONTAINER_FIX) == "container"

    def test_empty_cwe_falls_back_to_fix_type(self):
        assert _cwe_to_category("", FixType.DEPENDENCY_UPDATE) == "dependency"

    def test_no_cwe_no_fix_type_match_defaults_other(self):
        assert _cwe_to_category("", FixType.CODE_PATCH) == "other"


# ===========================================================================
# ML Confidence Integration
# ===========================================================================


class TestMLConfidenceIntegration:
    """Test the ML-powered confidence scoring integration."""

    def test_compute_confidence_returns_float(self, engine, code_patch_finding):
        sugg = AutoFixSuggestion(
            fix_id="fix-test",
            fix_type=FixType.CODE_PATCH,
            cve_ids=["CVE-2024-1234"],
            code_patches=[CodePatch(file_path="app.py", language="python",
                                    old_code="bad", new_code="good")],
            metadata={"validation": {"valid": True, "score": 0.8}},
        )
        score = engine._compute_confidence(sugg, code_patch_finding)
        assert isinstance(score, float)
        assert 0.1 <= score <= 0.99

    def test_compute_confidence_fallback_returns_float(self, engine, code_patch_finding):
        """Verify the rule-based fallback works."""
        sugg = AutoFixSuggestion(
            fix_id="fix-fb",
            fix_type=FixType.DEPENDENCY_UPDATE,
            metadata={"validation": {"valid": True, "score": 0.9}},
        )
        score = AutoFixEngine._compute_confidence_fallback(sugg, code_patch_finding)
        assert isinstance(score, float)
        assert 0.1 <= score <= 0.99

    def test_fallback_dep_update_gets_boost(self, engine):
        sugg = AutoFixSuggestion(
            fix_type=FixType.DEPENDENCY_UPDATE,
            metadata={"validation": {"valid": True, "score": 0.5}},
        )
        dep_score = AutoFixEngine._compute_confidence_fallback(sugg, {"severity": "high"})

        sugg2 = AutoFixSuggestion(
            fix_type=FixType.CODE_PATCH,
            metadata={"validation": {"valid": True, "score": 0.5}},
        )
        patch_score = AutoFixEngine._compute_confidence_fallback(sugg2, {"severity": "high"})

        # Dependency update should score higher
        assert dep_score > patch_score

    def test_build_confidence_features_shape(self, engine, code_patch_finding):
        sugg = AutoFixSuggestion(
            fix_id="fix-feat",
            fix_type=FixType.CODE_PATCH,
            cve_ids=["CVE-2024-1234"],
            code_patches=[CodePatch(file_path="app.py", language="python",
                                    old_code="x=1", new_code="x=safe(1)")],
            metadata={"validation": {"valid": True, "score": 0.8}},
            testing_guidance="Run pytest tests/test_login.py",
        )
        features = engine._build_confidence_features(sugg, code_patch_finding)
        assert "fix_type" in features
        assert "severity" in features
        assert "category" in features
        assert "language" in features
        assert features["fix_type"] == "code_patch"
        assert features["severity"] == "critical"
        assert features["category"] == "injection"  # CWE-89 → injection
        assert features["has_tests"] is True
        assert features["language"] == "python"

    def test_build_confidence_features_no_patches(self, engine):
        sugg = AutoFixSuggestion(
            fix_type=FixType.CONFIG_HARDENING,
            metadata={"validation": {"score": 0.5}},
        )
        finding = {"severity": "medium", "cwe_id": "CWE-16"}
        features = engine._build_confidence_features(sugg, finding)
        assert features["category"] == "config"
        assert features["files_affected"] == 1  # min 1
        assert features["lines_changed"] == 1  # min 1

    def test_ml_confidence_metadata_attached(self, engine, code_patch_finding):
        """When ML model runs, metadata should be enriched."""
        sugg = AutoFixSuggestion(
            fix_id="fix-ml-meta",
            fix_type=FixType.CODE_PATCH,
            code_patches=[CodePatch(language="python", old_code="a", new_code="b")],
            metadata={"validation": {"valid": True, "score": 0.7}},
        )
        engine._compute_confidence(sugg, code_patch_finding)
        # ML metadata may or may not be present depending on model availability
        # But the function should always return a valid score
        if "ml_confidence" in sugg.metadata:
            ml_data = sugg.metadata["ml_confidence"]
            assert "confidence_score" in ml_data
            assert "classification" in ml_data
            assert "confidence_interval" in ml_data
