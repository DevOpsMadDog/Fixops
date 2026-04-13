"""Tests for WAF Rule Generator Engine and REST API.

Covers:
- Core engine: template catalog, rule generation, virtual patching
- Lifecycle management: status transitions, rollback, versioning
- Rule testing/simulation: FP rate, accuracy
- Export formats: AWS WAF, Cloudflare, ModSecurity, NGINX, Apache, OWASP CRS, Terraform
- REST API endpoints: /generate, /virtual-patch, /rules, /rules/{id}, /status, /test, /export, /templates
"""

import os
import sys

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-value-longer-than-32-chars")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

import pytest
from unittest.mock import patch, MagicMock

# Ensure suite-core is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.waf_generator import (
    WAFRuleGenerator,
    WAFProvider,
    RuleType,
    RuleStatus,
    VulnType,
    ExportFormat,
    WAFRule,
    WAFCondition,
    VulnFinding,
    TestRequest as WafTestRequest,
    RuleSet,
    get_waf_generator,
    _export_aws_waf,
    _export_cloudflare,
    _export_modsecurity,
    _export_nginx,
    _export_apache,
    _export_owasp_crs,
    _export_terraform,
    _rule_matches_request,
    _TEMPLATES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def gen():
    """Fresh generator instance for each test."""
    return WAFRuleGenerator()


@pytest.fixture
def sqli_finding():
    return VulnFinding(
        title="SQL Injection on /api/users",
        vuln_type=VulnType.SQLI,
        severity="critical",
        endpoint="/api/users",
        parameter="id",
        description="Unsanitised id parameter allows UNION-based SQLi",
        attack_payload="' UNION SELECT 1,2,3--",
    )


@pytest.fixture
def xss_finding():
    return VulnFinding(
        title="Reflected XSS in search parameter",
        vuln_type=VulnType.XSS,
        severity="high",
        endpoint="/search",
        parameter="q",
        attack_payload="<script>alert(1)</script>",
    )


@pytest.fixture
def generic_finding():
    return VulnFinding(
        title="Generic vulnerability",
        vuln_type=VulnType.GENERIC,
        severity="medium",
    )


@pytest.fixture
def sample_rule(gen, sqli_finding):
    rules = gen.generate_from_finding(sqli_finding)
    return rules[0]


# ---------------------------------------------------------------------------
# 1. Template catalog tests
# ---------------------------------------------------------------------------

class TestTemplateCatalog:
    def test_template_count_at_least_50(self):
        assert len(_TEMPLATES) >= 50

    def test_templates_have_required_fields(self):
        for tid, tmpl in _TEMPLATES.items():
            assert tmpl.template_id == tid
            assert tmpl.name
            assert tmpl.vuln_type in VulnType.__members__.values()
            assert tmpl.rule_type in RuleType.__members__.values()
            assert len(tmpl.conditions) >= 1

    def test_list_templates_all(self, gen):
        templates = gen.list_templates()
        assert len(templates) >= 50

    def test_list_templates_filter_sqli(self, gen):
        templates = gen.list_templates(vuln_type=VulnType.SQLI)
        assert len(templates) >= 3
        for t in templates:
            assert t.vuln_type == VulnType.SQLI

    def test_list_templates_filter_xss(self, gen):
        templates = gen.list_templates(vuln_type=VulnType.XSS)
        assert len(templates) >= 2
        for t in templates:
            assert t.vuln_type == VulnType.XSS

    def test_list_templates_filter_path_traversal(self, gen):
        templates = gen.list_templates(vuln_type=VulnType.PATH_TRAVERSAL)
        assert len(templates) >= 2

    def test_get_template_exists(self, gen):
        tmpl = gen.get_template("SQLI-001")
        assert tmpl is not None
        assert tmpl.template_id == "SQLI-001"

    def test_get_template_missing(self, gen):
        tmpl = gen.get_template("DOES-NOT-EXIST")
        assert tmpl is None

    def test_template_instantiate_basic(self, gen):
        tmpl = gen.get_template("SQLI-001")
        rule = tmpl.instantiate()
        assert isinstance(rule, WAFRule)
        assert rule.status == RuleStatus.DRAFT

    def test_template_instantiate_with_endpoint(self, gen):
        tmpl = gen.get_template("SQLI-001")
        rule = tmpl.instantiate(endpoint="/api/users")
        # First condition should be the endpoint constraint
        assert any(c.field == "URI" and c.value == "/api/users" for c in rule.conditions)

    def test_sqli_templates_have_cwe_89(self, gen):
        templates = gen.list_templates(vuln_type=VulnType.SQLI)
        for t in templates:
            assert "CWE-89" in (t.cwe_id or ""), f"Template {t.template_id} missing CWE-89"


# ---------------------------------------------------------------------------
# 2. Rule generation from finding tests
# ---------------------------------------------------------------------------

class TestGenerateFromFinding:
    def test_generate_returns_multiple_rules(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        assert len(rules) >= 3

    def test_generate_includes_block_rule(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        block_rules = [r for r in rules if r.rule_type == RuleType.BLOCK]
        assert len(block_rules) >= 1

    def test_generate_includes_log_rule(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        log_rules = [r for r in rules if r.rule_type == RuleType.LOG]
        assert len(log_rules) >= 1

    def test_generate_includes_rate_limit_rule(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        rate_rules = [r for r in rules if r.rule_type == RuleType.RATE_LIMIT]
        assert len(rate_rules) >= 1

    def test_generated_rules_stored(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        for rule in rules:
            stored = gen.get_rule(rule.rule_id)
            assert stored is not None

    def test_generated_rules_draft_status(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        for rule in rules:
            assert rule.status == RuleStatus.DRAFT

    def test_generated_rules_have_endpoint(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        for rule in rules:
            # block rules targeting endpoint should have it set or in conditions
            if rule.rule_type == RuleType.BLOCK:
                assert rule.endpoint == "/api/users" or any(
                    c.value == "/api/users" for c in rule.conditions
                )

    def test_generate_xss_rules(self, gen, xss_finding):
        rules = gen.generate_from_finding(xss_finding)
        assert any(r.vuln_type == VulnType.XSS for r in rules)

    def test_generate_generic_finding(self, gen, generic_finding):
        rules = gen.generate_from_finding(generic_finding)
        assert len(rules) >= 1

    def test_generate_path_traversal(self, gen):
        finding = VulnFinding(
            title="Path Traversal in file param",
            vuln_type=VulnType.PATH_TRAVERSAL,
            endpoint="/download",
            parameter="file",
        )
        rules = gen.generate_from_finding(finding)
        assert len(rules) >= 2
        vuln_types = {r.vuln_type for r in rules}
        assert VulnType.PATH_TRAVERSAL in vuln_types

    def test_generate_ssrf_rules(self, gen):
        finding = VulnFinding(
            title="SSRF via url param",
            vuln_type=VulnType.SSRF,
            endpoint="/api/fetch",
            parameter="url",
        )
        rules = gen.generate_from_finding(finding)
        assert any(r.vuln_type == VulnType.SSRF for r in rules)

    def test_generated_rule_ids_unique(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# 3. Virtual patching tests
# ---------------------------------------------------------------------------

class TestVirtualPatch:
    def test_virtual_patch_returns_rule(self, gen):
        rule = gen.generate_virtual_patch(
            cve_id="CVE-2024-1234",
            endpoint="/api/login",
            attack_vector="sql injection via username parameter",
            description="Critical SQLi in login endpoint",
        )
        assert isinstance(rule, WAFRule)
        assert rule.cve_id == "CVE-2024-1234"

    def test_virtual_patch_high_priority(self, gen):
        rule = gen.generate_virtual_patch(
            cve_id="CVE-2024-9999",
            endpoint="/api/exec",
            attack_vector="rce via command injection",
            description="RCE vulnerability",
        )
        assert rule.priority == 1

    def test_virtual_patch_is_block_type(self, gen):
        rule = gen.generate_virtual_patch(
            cve_id="CVE-2024-5555",
            endpoint="/api/files",
            attack_vector="path traversal attack",
            description="LFI",
        )
        assert rule.rule_type == RuleType.BLOCK

    def test_virtual_patch_stored(self, gen):
        rule = gen.generate_virtual_patch(
            cve_id="CVE-2024-0001",
            endpoint="/api/data",
            attack_vector="xss in output",
            description="XSS",
        )
        stored = gen.get_rule(rule.rule_id)
        assert stored is not None
        assert stored.cve_id == "CVE-2024-0001"

    def test_virtual_patch_has_tag(self, gen):
        rule = gen.generate_virtual_patch(
            cve_id="CVE-2024-7777",
            endpoint="/api/upload",
            attack_vector="file upload bypass",
            description="Unrestricted upload",
        )
        assert "virtual-patch" in rule.tags

    def test_virtual_patch_sqli_vector(self, gen):
        rule = gen.generate_virtual_patch(
            cve_id="CVE-2024-2222",
            endpoint="/api/query",
            attack_vector="sql injection",
            description="SQLi",
        )
        has_sqli_cond = any(
            "select" in c.value.lower() or "union" in c.value.lower()
            for c in rule.conditions
        )
        assert has_sqli_cond

    def test_virtual_patch_draft_status(self, gen):
        rule = gen.generate_virtual_patch(
            cve_id="CVE-2024-3333",
            endpoint="/api/v1/data",
            attack_vector="generic attack",
            description="Some CVE",
        )
        assert rule.status == RuleStatus.DRAFT


# ---------------------------------------------------------------------------
# 4. Rule lifecycle tests
# ---------------------------------------------------------------------------

class TestRuleLifecycle:
    def test_status_transition_draft_to_testing(self, gen, sample_rule):
        rule = gen.update_rule_status(sample_rule.rule_id, RuleStatus.TESTING)
        assert rule.status == RuleStatus.TESTING

    def test_status_transition_testing_to_active(self, gen, sample_rule):
        gen.update_rule_status(sample_rule.rule_id, RuleStatus.TESTING)
        rule = gen.update_rule_status(sample_rule.rule_id, RuleStatus.ACTIVE)
        assert rule.status == RuleStatus.ACTIVE

    def test_status_transition_active_to_deprecated(self, gen, sample_rule):
        gen.update_rule_status(sample_rule.rule_id, RuleStatus.ACTIVE)
        rule = gen.update_rule_status(sample_rule.rule_id, RuleStatus.DEPRECATED)
        assert rule.status == RuleStatus.DEPRECATED

    def test_status_change_increments_version(self, gen, sample_rule):
        initial_version = sample_rule.version
        gen.update_rule_status(sample_rule.rule_id, RuleStatus.TESTING)
        rule = gen.get_rule(sample_rule.rule_id)
        assert rule.version == initial_version + 1

    def test_status_change_recorded_in_history(self, gen, sample_rule):
        gen.update_rule_status(sample_rule.rule_id, RuleStatus.TESTING)
        rule = gen.get_rule(sample_rule.rule_id)
        assert len(rule.history) >= 1
        assert rule.history[-1]["event"] == "status_change"

    def test_rollback_restores_previous_status(self, gen, sample_rule):
        gen.update_rule_status(sample_rule.rule_id, RuleStatus.TESTING)
        gen.rollback_rule(sample_rule.rule_id)
        rule = gen.get_rule(sample_rule.rule_id)
        assert rule.status == RuleStatus.DRAFT

    def test_rollback_no_history_returns_rule(self, gen, sample_rule):
        # No transitions yet
        result = gen.rollback_rule(sample_rule.rule_id)
        # With no history, rollback is a no-op but doesn't crash
        assert result is None or result.rule_id == sample_rule.rule_id

    def test_update_missing_rule_returns_none(self, gen):
        result = gen.update_rule_status("nonexistent-id", RuleStatus.ACTIVE)
        assert result is None

    def test_delete_rule(self, gen, sample_rule):
        deleted = gen.delete_rule(sample_rule.rule_id)
        assert deleted is True
        assert gen.get_rule(sample_rule.rule_id) is None

    def test_delete_nonexistent_rule(self, gen):
        deleted = gen.delete_rule("nonexistent-id")
        assert deleted is False

    def test_list_rules_filter_by_status(self, gen, sqli_finding, xss_finding):
        gen.generate_from_finding(sqli_finding)
        gen.generate_from_finding(xss_finding)
        draft_rules = gen.list_rules(status=RuleStatus.DRAFT)
        assert len(draft_rules) >= 1
        for r in draft_rules:
            assert r.status == RuleStatus.DRAFT

    def test_list_rules_filter_by_vuln_type(self, gen, sqli_finding, xss_finding):
        gen.generate_from_finding(sqli_finding)
        gen.generate_from_finding(xss_finding)
        xss_rules = gen.list_rules(vuln_type=VulnType.XSS)
        for r in xss_rules:
            assert r.vuln_type == VulnType.XSS


# ---------------------------------------------------------------------------
# 5. Rule testing / simulation tests
# ---------------------------------------------------------------------------

class TestRuleSimulation:
    def test_sqli_rule_blocks_malicious(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        block_rule = next(r for r in rules if r.rule_type == RuleType.BLOCK)
        malicious = WafTestRequest(
            uri="/api/users",
            query_string="id=1%20UNION%20SELECT%201%2C2%2C3--",
            is_malicious=True,
        )
        results = gen.test_rule(block_rule, [malicious])
        assert results[0].matched is True

    def test_rule_allows_clean_request(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        block_rule = next(r for r in rules if r.rule_type == RuleType.BLOCK
                          and any("select" in c.value.lower() or "union" in c.value.lower() for c in r.conditions))
        clean = WafTestRequest(
            uri="/api/users",
            query_string="id=42",
            is_malicious=False,
        )
        results = gen.test_rule(block_rule, [clean])
        assert results[0].correct is True

    def test_test_returns_correct_count(self, gen, sample_rule):
        reqs = [
            WafTestRequest(uri="/api/users", query_string="id=1", is_malicious=False),
            WafTestRequest(uri="/api/users", query_string="id=2", is_malicious=False),
        ]
        results = gen.test_rule(sample_rule, reqs)
        assert len(results) == 2

    def test_fp_rate_stored_on_rule(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        block_rule = next(r for r in rules if r.rule_type == RuleType.BLOCK)
        reqs = [
            WafTestRequest(uri="/api/users", query_string="id=1", is_malicious=False),
            WafTestRequest(uri="/api/users", query_string="id=1 UNION SELECT 1--", is_malicious=True),
        ]
        gen.test_rule(block_rule, reqs)
        stored = gen.get_rule(block_rule.rule_id)
        assert stored.false_positive_rate is not None
        assert 0.0 <= stored.false_positive_rate <= 1.0

    def test_result_latency_recorded(self, gen, sample_rule):
        reqs = [WafTestRequest(uri="/test", is_malicious=False)]
        results = gen.test_rule(sample_rule, reqs)
        assert results[0].latency_us >= 0

    def test_xss_rule_blocks_xss_payload(self, gen, xss_finding):
        rules = gen.generate_from_finding(xss_finding)
        block_rules = [r for r in rules if r.rule_type == RuleType.BLOCK
                       and any("script" in c.value.lower() or "xss" in c.value.lower() or "javascript" in c.value.lower() for c in r.conditions)]
        if not block_rules:
            pytest.skip("No XSS block rule with script pattern found")
        xss_req = WafTestRequest(
            uri="/search",
            query_string="q=<script>alert(1)</script>",
            is_malicious=True,
        )
        results = gen.test_rule(block_rules[0], [xss_req])
        assert results[0].matched is True

    def test_empty_request_list(self, gen, sample_rule):
        results = gen.test_rule(sample_rule, [])
        assert results == []


# ---------------------------------------------------------------------------
# 6. Export format tests
# ---------------------------------------------------------------------------

class TestExportFormats:
    def _make_rule(self):
        return WAFRule(
            name="Test Block SQLi",
            description="Test rule",
            rule_type=RuleType.BLOCK,
            vuln_type=VulnType.SQLI,
            conditions=[
                WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r"(?i)(\bunion\b)", transform="URL_DECODE")
            ],
            endpoint="/api/users",
        )

    def test_export_aws_waf_structure(self):
        rule = self._make_rule()
        out = _export_aws_waf(rule)
        assert "Name" in out
        assert "Statement" in out
        assert "Action" in out
        assert "Block" in out["Action"]

    def test_export_aws_waf_log_rule(self):
        rule = WAFRule(
            name="Log XSS",
            description="Log",
            rule_type=RuleType.LOG,
            vuln_type=VulnType.XSS,
            conditions=[WAFCondition(field="QUERY_STRING", operator="CONTAINS", value="<script>")],
        )
        out = _export_aws_waf(rule)
        assert "Count" in out["Action"]

    def test_export_cloudflare_structure(self):
        rule = self._make_rule()
        out = _export_cloudflare(rule)
        assert "expression" in out
        assert "action" in out
        assert out["action"] == "block"

    def test_export_cloudflare_log_rule(self):
        rule = WAFRule(
            name="Log",
            description="Log",
            rule_type=RuleType.LOG,
            vuln_type=VulnType.SQLI,
            conditions=[WAFCondition(field="QUERY_STRING", operator="CONTAINS", value="union")],
        )
        out = _export_cloudflare(rule)
        assert out["action"] == "log"

    def test_export_modsecurity_contains_secrule(self):
        rule = self._make_rule()
        out = _export_modsecurity(rule)
        assert "SecRule" in out
        assert "deny" in out or "block" in out.lower()

    def test_export_modsecurity_log_rule(self):
        rule = WAFRule(
            name="Log SQLi",
            description="Log",
            rule_type=RuleType.LOG,
            vuln_type=VulnType.SQLI,
            conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value="select")],
        )
        out = _export_modsecurity(rule)
        assert "pass" in out

    def test_export_nginx_structure(self):
        rule = self._make_rule()
        out = _export_nginx(rule)
        assert "if" in out
        assert "return 403" in out

    def test_export_apache_structure(self):
        rule = self._make_rule()
        out = _export_apache(rule)
        assert "RewriteEngine" in out
        assert "RewriteRule" in out

    def test_export_owasp_crs_structure(self):
        rule = self._make_rule()
        out = _export_owasp_crs(rule)
        assert "id" in out
        assert "phase" in out
        assert "conditions" in out
        assert out["ver"].startswith("OWASP_CRS")

    def test_export_terraform_aws(self):
        rule = self._make_rule()
        out = _export_terraform(rule, WAFProvider.AWS_WAF)
        assert "resource" in out
        assert "aws_wafv2_rule_group" in out

    def test_export_terraform_cloudflare(self):
        rule = self._make_rule()
        out = _export_terraform(rule, WAFProvider.CLOUDFLARE)
        assert "resource" in out
        assert "cloudflare_ruleset" in out

    def test_export_ruleset_aws(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        exported = gen.export_ruleset(rules, WAFProvider.AWS_WAF)
        assert isinstance(exported, list)
        assert len(exported) == len(rules)

    def test_export_ruleset_modsecurity_text(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        exported = gen.export_ruleset(rules, WAFProvider.MODSECURITY)
        assert isinstance(exported, str)
        assert "SecRule" in exported or "# WAF Rule" in exported

    def test_export_ruleset_owasp_crs(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        exported = gen.export_ruleset(rules, WAFProvider.AWS_WAF, fmt=ExportFormat.OWASP_CRS)
        assert isinstance(exported, list)

    def test_engine_export_rule_aws(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        rule = rules[0]
        out = gen.export_rule(rule, WAFProvider.AWS_WAF)
        assert "Name" in out

    def test_engine_export_rule_terraform(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        rule = rules[0]
        out = gen.export_rule(rule, WAFProvider.AWS_WAF, ExportFormat.TERRAFORM)
        assert isinstance(out, str)
        assert "resource" in out


# ---------------------------------------------------------------------------
# 7. RuleSet management tests
# ---------------------------------------------------------------------------

class TestRuleSetManagement:
    def test_create_ruleset(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        rs = gen.create_ruleset("My SQLi Rules", WAFProvider.AWS_WAF, rules, "Test ruleset")
        assert rs.ruleset_id
        assert rs.name == "My SQLi Rules"
        assert len(rs.rules) == len(rules)

    def test_get_ruleset(self, gen, sqli_finding):
        rules = gen.generate_from_finding(sqli_finding)
        rs = gen.create_ruleset("Test RS", WAFProvider.CLOUDFLARE, rules)
        stored = gen.get_ruleset(rs.ruleset_id)
        assert stored is not None
        assert stored.ruleset_id == rs.ruleset_id

    def test_list_rulesets(self, gen, sqli_finding, xss_finding):
        rules1 = gen.generate_from_finding(sqli_finding)
        rules2 = gen.generate_from_finding(xss_finding)
        gen.create_ruleset("RS1", WAFProvider.AWS_WAF, rules1)
        gen.create_ruleset("RS2", WAFProvider.NGINX, rules2)
        rulesets = gen.list_rulesets()
        assert len(rulesets) >= 2

    def test_get_nonexistent_ruleset(self, gen):
        rs = gen.get_ruleset("nonexistent-id")
        assert rs is None


# ---------------------------------------------------------------------------
# 8. Singleton tests
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_waf_generator_returns_same_instance(self):
        g1 = get_waf_generator()
        g2 = get_waf_generator()
        assert g1 is g2

    def test_generator_has_templates(self):
        gen = get_waf_generator()
        assert len(gen.list_templates()) >= 50


# ---------------------------------------------------------------------------
# 9. REST API endpoint tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def api_client():
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient

    # Build a minimal app with auth dependency overridden
    app = FastAPI()

    # Import router — auth is applied via Depends(api_key_auth) in router definition
    from apps.api.waf_router import router
    from apps.api import auth_deps

    # Override the auth dependency so all requests pass
    async def _no_auth():
        return None

    app.dependency_overrides[auth_deps.api_key_auth] = _no_auth
    app.include_router(router)

    return TestClient(app)


@pytest.fixture(scope="module")
def api_gen():
    """Ensure the module-level singleton is fresh-ish for API tests."""
    return get_waf_generator()


class TestAPIEndpoints:
    def test_generate_endpoint_returns_rules(self, api_client):
        resp = api_client.post("/api/v1/waf/generate", json={
            "title": "SQLi in /api/users",
            "vuln_type": "sqli",
            "severity": "critical",
            "endpoint": "/api/users",
            "parameter": "id",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "generated" in data
        assert data["generated"] >= 1
        assert "rules" in data

    def test_generate_endpoint_invalid_vuln_type(self, api_client):
        resp = api_client.post("/api/v1/waf/generate", json={
            "title": "Test",
            "vuln_type": "invalid_type",
        })
        assert resp.status_code == 400

    def test_virtual_patch_endpoint(self, api_client):
        resp = api_client.post("/api/v1/waf/virtual-patch", json={
            "cve_id": "CVE-2024-12345",
            "endpoint": "/api/login",
            "attack_vector": "sql injection",
            "description": "Critical CVE",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-12345"
        assert "rule" in data

    def test_list_rules_endpoint(self, api_client):
        resp = api_client.get("/api/v1/waf/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "rules" in data

    def test_list_rules_filter_by_status(self, api_client):
        resp = api_client.get("/api/v1/waf/rules?status=draft")
        assert resp.status_code == 200
        data = resp.json()
        for rule in data["rules"]:
            assert rule["status"] == "draft"

    def test_list_rules_invalid_status(self, api_client):
        resp = api_client.get("/api/v1/waf/rules?status=bogus")
        assert resp.status_code == 400

    def test_get_rule_endpoint(self, api_client):
        # Generate a rule first
        gen_resp = api_client.post("/api/v1/waf/generate", json={
            "title": "XSS in search",
            "vuln_type": "xss",
            "endpoint": "/search",
        })
        assert gen_resp.status_code == 200
        rule_id = gen_resp.json()["rules"][0]["rule_id"]

        resp = api_client.get(f"/api/v1/waf/rules/{rule_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == rule_id
        assert "conditions" in data
        assert "history" in data

    def test_get_rule_not_found(self, api_client):
        resp = api_client.get("/api/v1/waf/rules/nonexistent-rule-id")
        assert resp.status_code == 404

    def test_update_status_endpoint(self, api_client):
        gen_resp = api_client.post("/api/v1/waf/generate", json={
            "title": "Path traversal",
            "vuln_type": "path_traversal",
            "endpoint": "/files",
        })
        rule_id = gen_resp.json()["rules"][0]["rule_id"]

        resp = api_client.patch(f"/api/v1/waf/rules/{rule_id}/status", json={"status": "testing"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "testing"
        assert data["version"] >= 2

    def test_update_status_invalid(self, api_client):
        gen_resp = api_client.post("/api/v1/waf/generate", json={
            "title": "RCE test",
            "vuln_type": "rce",
        })
        rule_id = gen_resp.json()["rules"][0]["rule_id"]
        resp = api_client.patch(f"/api/v1/waf/rules/{rule_id}/status", json={"status": "invalid_status"})
        assert resp.status_code == 400

    def test_test_rule_endpoint(self, api_client):
        gen_resp = api_client.post("/api/v1/waf/generate", json={
            "title": "SQLi test rule",
            "vuln_type": "sqli",
            "endpoint": "/api/data",
        })
        rule_id = gen_resp.json()["rules"][0]["rule_id"]

        resp = api_client.post(f"/api/v1/waf/rules/{rule_id}/test", json={
            "requests": [
                {"uri": "/api/data", "query_string": "id=1", "is_malicious": False},
                {"uri": "/api/data", "query_string": "id=1 UNION SELECT 1--", "is_malicious": True},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 2
        assert "accuracy" in data
        assert "false_positive_rate" in data
        assert len(data["results"]) == 2

    def test_test_rule_not_found(self, api_client):
        resp = api_client.post("/api/v1/waf/rules/bad-id/test", json={"requests": []})
        assert resp.status_code == 404

    def test_export_endpoint_aws(self, api_client):
        # Generate some rules first
        api_client.post("/api/v1/waf/generate", json={
            "title": "Export test SQLi",
            "vuln_type": "sqli",
            "endpoint": "/api/export-test",
        })
        resp = api_client.post("/api/v1/waf/export", json={
            "provider": "aws_waf",
            "format": "provider_native",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "aws_waf"
        assert data["rule_count"] >= 1

    def test_export_endpoint_specific_rules(self, api_client):
        gen_resp = api_client.post("/api/v1/waf/generate", json={
            "title": "Specific export test",
            "vuln_type": "xss",
            "endpoint": "/api/specific",
        })
        rule_ids = [r["rule_id"] for r in gen_resp.json()["rules"]]

        resp = api_client.post("/api/v1/waf/export", json={
            "rule_ids": rule_ids[:2],
            "provider": "cloudflare",
            "format": "provider_native",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "cloudflare"
        assert data["rule_count"] == len(rule_ids[:2])

    def test_export_invalid_provider(self, api_client):
        resp = api_client.post("/api/v1/waf/export", json={
            "provider": "bad_provider",
        })
        assert resp.status_code == 400

    def test_templates_endpoint(self, api_client):
        resp = api_client.get("/api/v1/waf/templates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 50
        assert "templates" in data
        tmpl = data["templates"][0]
        assert "template_id" in tmpl
        assert "vuln_type" in tmpl
        assert "conditions_count" in tmpl

    def test_templates_endpoint_filter(self, api_client):
        resp = api_client.get("/api/v1/waf/templates?vuln_type=sqli")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 3
        for t in data["templates"]:
            assert t["vuln_type"] == "sqli"
