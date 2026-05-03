"""
Tests for suite-core/core/license_compliance.py and
suite-api/apps/api/license_compliance_router.py.

Covers:
- License database (lookup, list, normalize)
- Compatibility matrix (compatible, incompatible, conditional, fallback)
- Policy engine (block, warn, require-approval, OSI rule, copyleft %)
- SBOM audit (violations, obligations, risk scores, dual licenses)
- Obligation tracking + NOTICE file generation
- Risk scoring (per-component + project aggregate)
- Dual-license detection + recommendation
- Router endpoints (7 endpoints, happy path + error cases)

Usage:
    pytest tests/test_license_compliance.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure suite-core is on the path
suite_core = str(Path(__file__).parent.parent / "suite-core")
suite_api = str(Path(__file__).parent.parent / "suite-api")
for p in (suite_core, suite_api):
    if p not in sys.path:
        sys.path.insert(0, p)

from core.license_compliance import (
    CompatibilityResult,
    LicenseCategory,
    LicensePolicy,
    ObligationType,
    PolicyAction,
    PolicyRule,
    SBOMComponent,
    ViolationSeverity,
    audit_sbom,
    check_compatibility,
    compute_project_risk_score,
    detect_dual_licenses,
    extract_obligations,
    generate_notice_file,
    get_engine,
    get_license,
    list_licenses,
    normalize_license_id,
    score_dependency_license,
)


# ===========================================================================
# Helpers / fixtures
# ===========================================================================


def _comp(name: str, license_expr: str = "", declared: list[str] | None = None, version: str = "1.0.0") -> SBOMComponent:
    return SBOMComponent(
        name=name,
        version=version,
        license_expression=license_expr or None,
        declared_licenses=declared or [],
    )


@pytest.fixture
def engine():
    """Fresh engine instance for tests that modify policies."""
    from core.license_compliance import LicenseComplianceEngine
    return LicenseComplianceEngine()


@pytest.fixture
def commercial_policy():
    return LicensePolicy(
        policy_id="test-commercial",
        name="Test Commercial Policy",
        rules=[
            PolicyRule(
                rule_id="block-gpl",
                description="Block GPL",
                action=PolicyAction.BLOCK,
                categories=[LicenseCategory.STRONG_COPYLEFT],
                license_ids=["GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"],
            ),
            PolicyRule(
                rule_id="warn-lgpl",
                description="Warn on LGPL",
                action=PolicyAction.WARN,
                categories=[LicenseCategory.WEAK_COPYLEFT],
                license_ids=["LGPL-2.1-only", "LGPL-3.0-only"],
            ),
            PolicyRule(
                rule_id="block-nc",
                description="Block non-commercial",
                action=PolicyAction.BLOCK,
                categories=[LicenseCategory.NON_COMMERCIAL],
            ),
            PolicyRule(
                rule_id="approve-unknown",
                description="Require approval for unknown",
                action=PolicyAction.REQUIRE_APPROVAL,
                categories=[LicenseCategory.UNKNOWN],
            ),
        ],
        max_copyleft_percentage=30.0,
        project_license="Apache-2.0",
    )


# ===========================================================================
# 1. LICENSE DATABASE TESTS
# ===========================================================================


class TestLicenseDatabase:
    def test_lookup_mit(self):
        info = get_license("MIT")
        assert info is not None
        assert info.spdx_id == "MIT"
        assert info.category == LicenseCategory.PERMISSIVE
        assert info.osi_approved is True
        assert ObligationType.ATTRIBUTION in info.obligations

    def test_lookup_apache(self):
        info = get_license("Apache-2.0")
        assert info is not None
        assert info.category == LicenseCategory.PERMISSIVE
        assert info.patent_grant is True
        assert ObligationType.PATENT_GRANT in info.obligations

    def test_lookup_gpl2(self):
        info = get_license("GPL-2.0-only")
        assert info is not None
        assert info.category == LicenseCategory.STRONG_COPYLEFT
        assert ObligationType.SOURCE_DISCLOSURE in info.obligations
        assert ObligationType.COPYLEFT_SHARE in info.obligations

    def test_lookup_agpl(self):
        info = get_license("AGPL-3.0-only")
        assert info is not None
        assert info.network_disclosure is True
        assert ObligationType.NETWORK_DISCLOSURE in info.obligations

    def test_lookup_lgpl(self):
        info = get_license("LGPL-2.1-only")
        assert info is not None
        assert info.category == LicenseCategory.WEAK_COPYLEFT

    def test_lookup_mpl(self):
        info = get_license("MPL-2.0")
        assert info is not None
        assert info.category == LicenseCategory.WEAK_COPYLEFT
        assert info.patent_grant is True

    def test_lookup_cc_nc(self):
        info = get_license("CC-BY-NC-4.0")
        assert info is not None
        assert info.category == LicenseCategory.NON_COMMERCIAL
        assert info.commercial_use_allowed is False

    def test_lookup_unknown_returns_none(self):
        info = get_license("NONEXISTENT-LICENSE-XYZ")
        assert info is None

    def test_lookup_by_alias_case_insensitive(self):
        # "MIT License" is an alias
        info = get_license("mit license")
        assert info is not None
        assert info.spdx_id == "MIT"

    def test_lookup_isc(self):
        info = get_license("ISC")
        assert info is not None
        assert info.category == LicenseCategory.PERMISSIVE
        assert info.risk_score < 1.0

    def test_lookup_sspl(self):
        info = get_license("SSPL-1.0")
        assert info is not None
        assert info.commercial_use_allowed is False
        assert info.risk_score >= 9.0

    def test_list_all_licenses(self):
        all_licenses = list_licenses()
        assert len(all_licenses) >= 50

    def test_list_permissive_only(self):
        permissive = list_licenses(LicenseCategory.PERMISSIVE)
        assert all(l.category == LicenseCategory.PERMISSIVE for l in permissive)
        assert len(permissive) >= 8

    def test_list_strong_copyleft(self):
        strong = list_licenses(LicenseCategory.STRONG_COPYLEFT)
        assert len(strong) >= 5
        spdx_ids = [l.spdx_id for l in strong]
        assert "GPL-2.0-only" in spdx_ids
        assert "AGPL-3.0-only" in spdx_ids

    def test_list_weak_copyleft(self):
        weak = list_licenses(LicenseCategory.WEAK_COPYLEFT)
        assert len(weak) >= 5

    def test_risk_scores_ordered(self):
        """Permissive licenses should have lower risk than copyleft."""
        mit = get_license("MIT")
        gpl = get_license("GPL-3.0-only")
        agpl = get_license("AGPL-3.0-only")
        assert mit.risk_score < gpl.risk_score
        assert gpl.risk_score < agpl.risk_score


# ===========================================================================
# 2. LICENSE NORMALIZATION TESTS
# ===========================================================================


class TestNormalizeLicense:
    def test_normalize_exact_spdx(self):
        assert normalize_license_id("MIT") == "MIT"

    def test_normalize_gpl_shorthand(self):
        assert normalize_license_id("gplv2") == "GPL-2.0-only"

    def test_normalize_apache_shorthand(self):
        assert normalize_license_id("apache2") == "Apache-2.0"

    def test_normalize_unknown(self):
        assert normalize_license_id("some weird license") == "UNKNOWN"

    def test_normalize_proprietary(self):
        assert normalize_license_id("proprietary") == "Proprietary"

    def test_normalize_all_rights_reserved(self):
        assert normalize_license_id("all rights reserved") == "Proprietary"

    def test_normalize_cc0(self):
        assert normalize_license_id("cc0") == "CC0-1.0"

    def test_normalize_agpl(self):
        result = normalize_license_id("agplv3")
        assert result == "AGPL-3.0-only"


# ===========================================================================
# 3. COMPATIBILITY MATRIX TESTS
# ===========================================================================


class TestCompatibilityMatrix:
    def test_mit_apache_compatible(self):
        result, notes = check_compatibility("MIT", "Apache-2.0")
        assert result == CompatibilityResult.COMPATIBLE

    def test_mit_gpl_incompatible(self):
        result, _ = check_compatibility("MIT", "GPL-2.0-only")
        assert result == CompatibilityResult.INCOMPATIBLE

    def test_mit_agpl_incompatible(self):
        result, _ = check_compatibility("MIT", "AGPL-3.0-only")
        assert result == CompatibilityResult.INCOMPATIBLE

    def test_apache_gpl3_compatible(self):
        result, _ = check_compatibility("Apache-2.0", "GPL-3.0-only")
        assert result == CompatibilityResult.COMPATIBLE

    def test_apache_gpl2_incompatible(self):
        # Patent clause conflict
        result, _ = check_compatibility("Apache-2.0", "GPL-2.0-only")
        assert result == CompatibilityResult.INCOMPATIBLE

    def test_mit_lgpl_conditional(self):
        result, notes = check_compatibility("MIT", "LGPL-2.1-only")
        assert result == CompatibilityResult.CONDITIONAL
        assert notes != ""

    def test_proprietary_mit_compatible(self):
        result, _ = check_compatibility("Proprietary", "MIT")
        assert result == CompatibilityResult.COMPATIBLE

    def test_proprietary_gpl_incompatible(self):
        result, _ = check_compatibility("Proprietary", "GPL-3.0-only")
        assert result == CompatibilityResult.INCOMPATIBLE

    def test_gpl3_mit_compatible(self):
        result, _ = check_compatibility("GPL-3.0-only", "MIT")
        assert result == CompatibilityResult.COMPATIBLE

    def test_gpl3_agpl_incompatible(self):
        result, _ = check_compatibility("GPL-3.0-only", "AGPL-3.0-only")
        assert result == CompatibilityResult.INCOMPATIBLE

    def test_proprietary_agpl_incompatible(self):
        result, _ = check_compatibility("Proprietary", "AGPL-3.0-only")
        assert result == CompatibilityResult.INCOMPATIBLE

    def test_unknown_dependency_returns_unknown(self):
        result, notes = check_compatibility("MIT", "UNKNOWN")
        assert result == CompatibilityResult.UNKNOWN
        assert "manual review" in notes.lower()

    def test_strong_copyleft_dep_with_permissive_project_fallback(self):
        # Not in matrix but category fallback applies
        result, _ = check_compatibility("BSD-2-Clause", "AGPL-3.0-only")
        assert result == CompatibilityResult.INCOMPATIBLE

    def test_non_commercial_dep_incompatible_apache(self):
        result, _ = check_compatibility("Apache-2.0", "CC-BY-NC-4.0")
        assert result == CompatibilityResult.INCOMPATIBLE


# ===========================================================================
# 4. POLICY ENGINE TESTS
# ===========================================================================


class TestPolicyEngine:
    def test_default_policy_blocks_agpl(self):
        from core.license_compliance import evaluate_license_policy, _DEFAULT_COMMERCIAL_POLICY
        action, rule = evaluate_license_policy("AGPL-3.0-only", _DEFAULT_COMMERCIAL_POLICY)
        assert action == PolicyAction.BLOCK

    def test_default_policy_blocks_gpl(self):
        from core.license_compliance import evaluate_license_policy, _DEFAULT_COMMERCIAL_POLICY
        action, rule = evaluate_license_policy("GPL-3.0-only", _DEFAULT_COMMERCIAL_POLICY)
        assert action == PolicyAction.BLOCK

    def test_default_policy_warns_lgpl(self):
        from core.license_compliance import evaluate_license_policy, _DEFAULT_COMMERCIAL_POLICY
        action, rule = evaluate_license_policy("LGPL-2.1-only", _DEFAULT_COMMERCIAL_POLICY)
        assert action == PolicyAction.WARN

    def test_default_policy_allows_mit(self):
        from core.license_compliance import evaluate_license_policy, _DEFAULT_COMMERCIAL_POLICY
        action, rule = evaluate_license_policy("MIT", _DEFAULT_COMMERCIAL_POLICY)
        assert action == PolicyAction.ALLOW

    def test_default_policy_requires_approval_unknown(self):
        from core.license_compliance import evaluate_license_policy, _DEFAULT_COMMERCIAL_POLICY
        action, rule = evaluate_license_policy("UNKNOWN", _DEFAULT_COMMERCIAL_POLICY)
        assert action == PolicyAction.REQUIRE_APPROVAL

    def test_disabled_rule_skipped(self):
        from core.license_compliance import evaluate_license_policy
        policy = LicensePolicy(
            policy_id="test",
            name="Test",
            rules=[
                PolicyRule(
                    rule_id="disabled-block",
                    description="Disabled",
                    action=PolicyAction.BLOCK,
                    categories=[LicenseCategory.PERMISSIVE],
                    enabled=False,
                )
            ],
        )
        action, rule = evaluate_license_policy("MIT", policy)
        assert action == PolicyAction.ALLOW
        assert rule is None

    def test_osi_required_policy_warns_non_osi(self):
        from core.license_compliance import evaluate_license_policy
        policy = LicensePolicy(
            policy_id="osi-only",
            name="OSI Only",
            rules=[],
            require_osi_approved=True,
        )
        action, _ = evaluate_license_policy("CC0-1.0", policy)
        # CC0-1.0 is not OSI-approved, so should warn
        assert action == PolicyAction.WARN

    def test_block_takes_priority_over_warn(self):
        from core.license_compliance import evaluate_license_policy
        policy = LicensePolicy(
            policy_id="priority-test",
            name="Priority Test",
            rules=[
                PolicyRule(
                    rule_id="warn-copyleft",
                    description="Warn copyleft",
                    action=PolicyAction.WARN,
                    categories=[LicenseCategory.STRONG_COPYLEFT],
                ),
                PolicyRule(
                    rule_id="block-agpl",
                    description="Block AGPL",
                    action=PolicyAction.BLOCK,
                    license_ids=["AGPL-3.0-only"],
                ),
            ],
        )
        action, rule = evaluate_license_policy("AGPL-3.0-only", policy)
        assert action == PolicyAction.BLOCK


# ===========================================================================
# 5. SBOM AUDIT TESTS
# ===========================================================================


class TestSBOMAudit:
    def test_all_permissive_no_violations(self, commercial_policy):
        components = [
            _comp("requests", "MIT"),
            _comp("flask", "BSD-3-Clause"),
            _comp("click", "BSD-3-Clause"),
        ]
        report = audit_sbom(components, commercial_policy)
        block_violations = [v for v in report.violations if v.action == PolicyAction.BLOCK]
        assert len(block_violations) == 0
        assert report.total_components == 3

    def test_gpl_dep_creates_violation(self, commercial_policy):
        components = [_comp("some-gpl-lib", "GPL-3.0-only")]
        report = audit_sbom(components, commercial_policy)
        assert report.violation_count > 0
        assert any(v.action == PolicyAction.BLOCK for v in report.violations)

    def test_agpl_dep_critical_violation(self, commercial_policy):
        components = [_comp("some-agpl-lib", "AGPL-3.0-only")]
        report = audit_sbom(components, commercial_policy)
        assert any(v.severity == ViolationSeverity.CRITICAL for v in report.violations)

    def test_unknown_license_requires_approval(self, commercial_policy):
        components = [_comp("mystery-lib", "UNKNOWN")]
        report = audit_sbom(components, commercial_policy)
        assert any(v.action == PolicyAction.REQUIRE_APPROVAL for v in report.violations)

    def test_report_has_risk_scores(self, commercial_policy):
        components = [_comp("requests", "MIT"), _comp("flask", "Apache-2.0")]
        report = audit_sbom(components, commercial_policy)
        assert len(report.dependency_scores) == 2

    def test_report_has_obligations(self, commercial_policy):
        components = [_comp("requests", "MIT")]
        report = audit_sbom(components, commercial_policy)
        assert len(report.obligations) > 0

    def test_report_has_notice_file(self, commercial_policy):
        components = [_comp("requests", "MIT")]
        report = audit_sbom(components, commercial_policy)
        assert "NOTICE" in report.notice_file_content
        assert "requests" in report.notice_file_content

    def test_report_has_summary(self, commercial_policy):
        components = [_comp("a", "MIT")]
        report = audit_sbom(components, commercial_policy)
        assert "total_components" in report.summary
        assert "violation_count" in report.summary

    def test_copyleft_percentage_violation(self):
        policy = LicensePolicy(
            policy_id="strict",
            name="Strict",
            rules=[],
            max_copyleft_percentage=10.0,
        )
        components = [
            _comp("a", "MIT"),
            _comp("b", "GPL-3.0-only"),
            _comp("c", "LGPL-3.0-only"),
            _comp("d", "AGPL-3.0-only"),
        ]
        report = audit_sbom(components, policy)
        # 3/4 = 75% copyleft > 10% limit
        pct_violations = [v for v in report.violations if v.policy_rule_id == "max-copyleft-percentage"]
        assert len(pct_violations) > 0

    def test_dual_license_uses_recommended(self, commercial_policy):
        # Package with MIT OR GPL-3.0-only — should use MIT
        comp = SBOMComponent(
            name="dual-lib",
            version="1.0.0",
            license_expression="MIT OR GPL-3.0-only",
            declared_licenses=["MIT", "GPL-3.0-only"],
        )
        report = audit_sbom([comp], commercial_policy)
        # MIT is recommended, should have no block violations for this component
        block_violations = [v for v in report.violations if v.component_name == "dual-lib" and v.action == PolicyAction.BLOCK]
        assert len(block_violations) == 0

    def test_report_ids(self):
        components = [_comp("a", "MIT")]
        report = audit_sbom(components, report_id="test-123")
        assert report.report_id == "test-123"

    def test_auto_report_id_generated(self):
        components = [_comp("a", "MIT")]
        report = audit_sbom(components)
        assert report.report_id != ""

    def test_compatibility_check_in_audit(self):
        """Audit should flag incompatible licenses even if policy allows them."""
        policy = LicensePolicy(
            policy_id="compat-test",
            name="Compat Test",
            rules=[],
            project_license="Apache-2.0",
        )
        components = [_comp("gpl-lib", "GPL-2.0-only")]
        report = audit_sbom(components, policy)
        # Apache-2.0 incompatible with GPL-2.0-only
        assert report.violation_count > 0


# ===========================================================================
# 6. OBLIGATION TRACKING TESTS
# ===========================================================================


class TestObligations:
    def test_mit_attribution_obligation(self):
        components = [_comp("requests", "MIT")]
        obligations = extract_obligations(components)
        types = [o.obligation_type for o in obligations]
        assert ObligationType.ATTRIBUTION in types

    def test_gpl_source_disclosure_obligation(self):
        components = [_comp("gpl-lib", "GPL-3.0-only")]
        obligations = extract_obligations(components)
        types = [o.obligation_type for o in obligations]
        assert ObligationType.SOURCE_DISCLOSURE in types
        assert ObligationType.COPYLEFT_SHARE in types

    def test_agpl_network_disclosure_obligation(self):
        components = [_comp("agpl-lib", "AGPL-3.0-only")]
        obligations = extract_obligations(components)
        types = [o.obligation_type for o in obligations]
        assert ObligationType.NETWORK_DISCLOSURE in types

    def test_apache_patent_grant_obligation(self):
        components = [_comp("lib", "Apache-2.0")]
        obligations = extract_obligations(components)
        types = [o.obligation_type for o in obligations]
        assert ObligationType.PATENT_GRANT in types

    def test_notice_file_contains_component(self):
        components = [_comp("mylib", "MIT")]
        obligations = extract_obligations(components)
        notice = generate_notice_file(obligations, components)
        assert "mylib" in notice
        assert "MIT" in notice

    def test_notice_file_has_header(self):
        components = [_comp("a", "MIT")]
        obligations = extract_obligations(components)
        notice = generate_notice_file(obligations, components)
        assert notice.startswith("NOTICE")

    def test_notice_file_has_generated_timestamp(self):
        components = [_comp("a", "MIT")]
        obligations = extract_obligations(components)
        notice = generate_notice_file(obligations, components)
        assert "Generated" in notice

    def test_multiple_components_in_notice(self):
        components = [_comp("libA", "MIT"), _comp("libB", "Apache-2.0")]
        obligations = extract_obligations(components)
        notice = generate_notice_file(obligations, components)
        assert "libA" in notice
        assert "libB" in notice


# ===========================================================================
# 7. RISK SCORING TESTS
# ===========================================================================


class TestRiskScoring:
    def test_mit_low_risk(self):
        comp = _comp("requests", "MIT")
        score = score_dependency_license(comp)
        assert score.risk_label in ("low", "medium")
        assert score.copyleft_risk == 0.0

    def test_agpl_critical_risk(self):
        comp = _comp("agpl-lib", "AGPL-3.0-only")
        score = score_dependency_license(comp)
        assert score.risk_label == "critical"
        assert score.copyleft_risk > 5.0

    def test_gpl_high_risk(self):
        comp = _comp("gpl-lib", "GPL-3.0-only")
        score = score_dependency_license(comp)
        assert score.aggregate_risk > 3.0

    def test_unknown_high_risk(self):
        comp = _comp("mystery", "UNKNOWN")
        score = score_dependency_license(comp)
        assert score.risk_label in ("high", "critical")

    def test_project_score_aggregation(self):
        scores = [
            score_dependency_license(_comp("a", "MIT")),
            score_dependency_license(_comp("b", "AGPL-3.0-only")),
        ]
        project_score, label = compute_project_risk_score(scores)
        assert project_score > 0.0
        assert label in ("low", "medium", "high", "critical")

    def test_project_score_empty_returns_zero(self):
        score, label = compute_project_risk_score([])
        assert score == 0.0
        assert label == "none"

    def test_all_permissive_low_project_score(self):
        scores = [
            score_dependency_license(_comp("a", "MIT")),
            score_dependency_license(_comp("b", "Apache-2.0")),
            score_dependency_license(_comp("c", "BSD-3-Clause")),
        ]
        project_score, label = compute_project_risk_score(scores)
        assert label in ("low",)
        assert project_score < 3.0

    def test_nc_license_commercial_restriction_risk(self):
        comp = _comp("nc-lib", "CC-BY-NC-4.0")
        score = score_dependency_license(comp)
        assert score.commercial_restriction_risk > 0.0


# ===========================================================================
# 8. DUAL LICENSE DETECTION TESTS
# ===========================================================================


class TestDualLicenseDetection:
    def test_no_dual_license_single(self):
        components = [_comp("lib", "MIT")]
        result = detect_dual_licenses(components)
        assert len(result) == 0

    def test_dual_license_or_expression(self):
        comp = SBOMComponent(
            name="dual-lib",
            version="1.0",
            license_expression="MIT OR GPL-3.0-only",
            declared_licenses=[],
        )
        result = detect_dual_licenses([comp])
        assert len(result) == 1
        assert result[0].recommended_license == "MIT"

    def test_dual_license_declared_list(self):
        comp = SBOMComponent(
            name="dual-lib2",
            version="2.0",
            license_expression=None,
            declared_licenses=["Apache-2.0", "GPL-2.0-only"],
        )
        result = detect_dual_licenses([comp])
        assert len(result) == 1
        # Apache-2.0 lower risk than GPL-2.0-only
        assert result[0].recommended_license == "Apache-2.0"

    def test_dual_license_recommendation_reason(self):
        comp = SBOMComponent(
            name="lib",
            version="1.0",
            license_expression=None,
            declared_licenses=["MIT", "AGPL-3.0-only"],
        )
        result = detect_dual_licenses([comp])
        assert len(result) == 1
        assert "MIT" in result[0].reason

    def test_multiple_dual_licensed_components(self):
        components = [
            SBOMComponent(
                name="lib-a",
                version="1.0",
                license_expression=None,
                declared_licenses=["MIT", "GPL-2.0-only"],
            ),
            SBOMComponent(
                name="lib-b",
                version="1.0",
                license_expression=None,
                declared_licenses=["Apache-2.0", "LGPL-2.1-only"],
            ),
        ]
        result = detect_dual_licenses(components)
        assert len(result) == 2


# ===========================================================================
# 9. ENGINE SINGLETON TESTS
# ===========================================================================


class TestEngineAPI:
    def test_get_engine_returns_singleton(self):
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2

    def test_engine_has_default_policy(self, engine):
        policies = engine.list_policies()
        assert any(p.policy_id == "default-commercial" for p in policies)

    def test_engine_add_and_get_policy(self, engine):
        policy = LicensePolicy(
            policy_id="new-policy",
            name="New Policy",
            rules=[],
        )
        engine.add_policy(policy)
        retrieved = engine.get_policy("new-policy")
        assert retrieved is not None
        assert retrieved.name == "New Policy"

    def test_engine_delete_policy(self, engine):
        policy = LicensePolicy(
            policy_id="del-policy",
            name="Delete Me",
            rules=[],
        )
        engine.add_policy(policy)
        assert engine.delete_policy("del-policy") is True
        assert engine.get_policy("del-policy") is None

    def test_engine_delete_nonexistent_returns_false(self, engine):
        assert engine.delete_policy("does-not-exist") is False

    def test_engine_audit(self, engine):
        components = [_comp("requests", "MIT")]
        report = engine.audit(components, "default-commercial")
        assert report.total_components == 1

    def test_engine_generate_notice(self, engine):
        components = [_comp("requests", "MIT")]
        notice = engine.generate_notice(components)
        assert "requests" in notice

    def test_engine_detect_dual_licenses(self, engine):
        comp = SBOMComponent(
            name="dual",
            version="1.0",
            license_expression=None,
            declared_licenses=["MIT", "GPL-3.0-only"],
        )
        result = engine.detect_dual_licenses([comp])
        assert len(result) == 1


# ===========================================================================
# 10. ROUTER ENDPOINT TESTS
# ===========================================================================


@pytest.fixture
def client():
    """FastAPI test client for license compliance router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.license_compliance_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestRouterEndpoints:
    def test_lookup_known_license(self, client):
        resp = client.get("/api/v1/licenses/lookup?spdx_id=MIT")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["license"]["spdx_id"] == "MIT"

    def test_lookup_unknown_license_404(self, client):
        resp = client.get("/api/v1/licenses/lookup?spdx_id=NONEXISTENT-XYZ-999")
        assert resp.status_code == 404

    def test_list_all_licenses(self, client):
        resp = client.get("/api/v1/licenses/list")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 50

    def test_list_licenses_by_category(self, client):
        resp = client.get("/api/v1/licenses/list?category=permissive")
        assert resp.status_code == 200
        data = resp.json()
        assert all(l["category"] == "permissive" for l in data["licenses"])

    def test_list_licenses_invalid_category(self, client):
        resp = client.get("/api/v1/licenses/list?category=bogus")
        assert resp.status_code == 400

    def test_compatibility_compatible(self, client):
        resp = client.post(
            "/api/v1/licenses/compatibility",
            json={"project_license": "MIT", "dependency_license": "Apache-2.0"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["result"] == "compatible"

    def test_compatibility_incompatible(self, client):
        resp = client.post(
            "/api/v1/licenses/compatibility",
            json={"project_license": "MIT", "dependency_license": "GPL-2.0-only"},
        )
        assert resp.status_code == 200
        assert resp.json()["result"] == "incompatible"

    def test_list_policies(self, client):
        resp = client.get("/api/v1/licenses/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        ids = [p["policy_id"] for p in data["policies"]]
        assert "default-commercial" in ids

    def test_create_policy(self, client):
        policy_data = {
            "policy": {
                "policy_id": "test-router-policy",
                "name": "Test Router Policy",
                "rules": [],
                "max_copyleft_percentage": 50.0,
                "require_osi_approved": False,
            }
        }
        resp = client.post("/api/v1/licenses/policies", json=policy_data)
        assert resp.status_code == 201
        assert resp.json()["policy_id"] == "test-router-policy"

    def test_delete_default_policy_blocked(self, client):
        resp = client.delete("/api/v1/licenses/policies/default-commercial")
        assert resp.status_code == 400

    def test_delete_nonexistent_policy_404(self, client):
        resp = client.delete("/api/v1/licenses/policies/nonexistent-policy-xyz")
        assert resp.status_code == 404

    def test_audit_endpoint_happy_path(self, client):
        payload = {
            "components": [
                {"name": "requests", "version": "2.28.0", "license_expression": "Apache-2.0", "declared_licenses": []},
                {"name": "flask", "version": "2.0.0", "license_expression": "BSD-3-Clause", "declared_licenses": []},
            ],
            "policy_id": "default-commercial",
        }
        resp = client.post("/api/v1/licenses/audit", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "report" in data
        assert data["report"]["total_components"] == 2

    def test_audit_empty_components_400(self, client):
        resp = client.post(
            "/api/v1/licenses/audit",
            json={"components": [], "policy_id": "default-commercial"},
        )
        assert resp.status_code == 400

    def test_audit_unknown_policy_404(self, client):
        payload = {
            "components": [{"name": "a", "version": "1.0", "license_expression": "MIT", "declared_licenses": []}],
            "policy_id": "nonexistent-policy",
        }
        resp = client.post("/api/v1/licenses/audit", json=payload)
        assert resp.status_code == 404

    def test_obligations_endpoint(self, client):
        payload = {
            "components": [
                {"name": "requests", "version": "2.0", "license_expression": "MIT", "declared_licenses": []}
            ]
        }
        resp = client.post("/api/v1/licenses/obligations", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "obligations" in data
        assert "notice_file" in data
        assert data["total_obligations"] > 0

    def test_risk_scores_endpoint(self, client):
        payload = {
            "components": [
                {"name": "requests", "version": "2.0", "license_expression": "MIT", "declared_licenses": []},
                {"name": "evil-lib", "version": "1.0", "license_expression": "AGPL-3.0-only", "declared_licenses": []},
            ]
        }
        resp = client.post("/api/v1/licenses/risk-scores", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "project_risk_score" in data
        assert "scores" in data
        assert len(data["scores"]) == 2

    def test_dual_license_endpoint(self, client):
        payload = {
            "components": [
                {
                    "name": "dual-lib",
                    "version": "1.0",
                    "license_expression": None,
                    "declared_licenses": ["MIT", "GPL-3.0-only"],
                }
            ]
        }
        resp = client.post("/api/v1/licenses/dual-license", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["dual_license_count"] == 1
        assert data["detections"][0]["recommended_license"] == "MIT"

    def test_dual_license_no_duals(self, client):
        payload = {
            "components": [
                {"name": "plain", "version": "1.0", "license_expression": "MIT", "declared_licenses": []}
            ]
        }
        resp = client.post("/api/v1/licenses/dual-license", json=payload)
        assert resp.status_code == 200
        assert resp.json()["dual_license_count"] == 0

    # -----------------------------------------------------------------------
    # Root endpoint + copyleft listing (new)
    # -----------------------------------------------------------------------

    def test_root_returns_ok(self, client):
        resp = client.get("/api/v1/licenses/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "license-compliance"
        assert data["license_count"] >= 50

    def test_root_has_category_breakdown(self, client):
        resp = client.get("/api/v1/licenses/")
        data = resp.json()
        cats = data["categories"]
        assert "permissive" in cats
        assert "strong_copyleft" in cats
        assert "weak_copyleft" in cats

    def test_copyleft_all_returns_both_strengths(self, client):
        resp = client.get("/api/v1/licenses/copyleft")
        assert resp.status_code == 200
        data = resp.json()
        assert data["strength_filter"] == "all"
        categories = {lic["category"] for lic in data["licenses"]}
        assert "weak_copyleft" in categories
        assert "strong_copyleft" in categories

    def test_copyleft_strong_only(self, client):
        resp = client.get("/api/v1/licenses/copyleft?strength=strong")
        assert resp.status_code == 200
        data = resp.json()
        assert data["strength_filter"] == "strong"
        assert all(lic["category"] == "strong_copyleft" for lic in data["licenses"])
        spdx_ids = [lic["spdx_id"] for lic in data["licenses"]]
        assert "GPL-2.0-only" in spdx_ids or "GPL-3.0-only" in spdx_ids

    def test_copyleft_sorted_by_risk_descending(self, client):
        resp = client.get("/api/v1/licenses/copyleft")
        data = resp.json()
        scores = [lic["risk_score"] for lic in data["licenses"]]
        assert scores == sorted(scores, reverse=True)

    def test_copyleft_invalid_strength_400(self, client):
        resp = client.get("/api/v1/licenses/copyleft?strength=ultra")
        assert resp.status_code == 400
