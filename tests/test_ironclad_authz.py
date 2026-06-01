"""
Iron-Clad Authorization Hardening 2 — regression tests.

Covers the 40 routers fixed in the iron-clad hardening wave:
  * No-API-key → 401 or 403 on every sensitive endpoint
  * Monte Carlo router (suite-core) — no-key → 401/403
  * Webhook router — okta/verify stays public; events/generic/list need auth
  * SCIM router — needs auth (api_key_auth at router level)
  * Stream router — needs auth
  * TrustGraph maintenance/quality — need auth
  * Security KPI, report scheduler, SOC automation — need auth
  * Attack path, bulk, breach sim, graphql, admin wizard — need auth
  * Ansible Tower, Jenkins, Splunk, SumoLogic, Snowflake, Workday — need auth
  * AWS ECR/EKS/S3, Azure KeyVault/Sentinel, BitBucket, CircleCI — need auth
  * GAR, GitHub API, GitLab pipeline, Harbor, Kong, Lacework — need auth
  * Jira Cloud, Mattermost, Noname, Purview DLP, WIZ, ZAP — need auth
  * Syft, TFSec, Threat Intel Sharing, Threat Modeling — need auth
  * Security Maturity, Threat Correlation — need auth (moved before router def)

Assertions:
  A. No API key → 401 or 403 (never 200/404/500/422).
  B. Stripe webhook stays public (uses Stripe HMAC — must NOT be 401/403).
  C. Okta /verify endpoint stays public (Okta verification challenge).
  D. System /health stays public (checked via separate read-only assertion).
"""
from __future__ import annotations

import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in [".", "suite-api", "suite-core", "suite-attack", "suite-feeds",
           "suite-integrations", "suite-evidence-risk"]:
    _full = os.path.join(_REPO, _p)
    if _full not in sys.path:
        sys.path.insert(0, _full)

# ---------------------------------------------------------------------------
# Auth environment
# ---------------------------------------------------------------------------
_TOKEN = "test-ironclad-hardening-2"
os.environ.setdefault("FIXOPS_API_TOKEN", _TOKEN)
os.environ.setdefault("FIXOPS_MODE", "production")

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="module")
def client():
    os.environ["FIXOPS_API_TOKEN"] = _TOKEN
    os.environ["FIXOPS_MODE"] = "production"
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _no_key() -> dict:
    return {}


def _with_key() -> dict:
    return {"X-API-Key": _TOKEN}


def _assert_auth_required(resp, endpoint: str) -> None:
    """Assert 401 or 403 — never a successful data response."""
    assert resp.status_code in (401, 403), (
        f"{endpoint}: expected 401/403 without API key, "
        f"got {resp.status_code}: {resp.text[:200]}"
    )


def _assert_authenticated_ok(resp, endpoint: str) -> None:
    """Assert authenticated request does NOT get 401/403."""
    assert resp.status_code not in (401, 403), (
        f"{endpoint}: authenticated request rejected with "
        f"{resp.status_code}: {resp.text[:200]}"
    )


# ============================================================================
# Wave-4 regressions (must still pass)
# ============================================================================

class TestWave4Regression:
    """Verify prior wave-4 fixes still hold."""

    def test_cases_no_key(self, client):
        _assert_auth_required(client.get("/api/v1/cases", headers=_no_key()), "/api/v1/cases")

    def test_ciem_no_key(self, client):
        _assert_auth_required(client.get("/api/v1/ciem/risks", headers=_no_key()), "/api/v1/ciem/risks")

    def test_cspm_engine_no_key(self, client):
        _assert_auth_required(client.get("/api/v1/cspm-engine/resources", headers=_no_key()), "/api/v1/cspm-engine/resources")


# ============================================================================
# Monte Carlo (suite-core router) — compute-heavy, must be auth-gated
# ============================================================================

class TestMonteCarloNoAuth:
    def test_fair_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/risk/simulate/fair", json={}, headers=_no_key()),
            "/api/v1/risk/simulate/fair",
        )

    def test_cvss_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/risk/simulate/cvss", json={"cvss_score": 9.8}, headers=_no_key()),
            "/api/v1/risk/simulate/cvss",
        )

    def test_cve_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/risk/simulate/cve",
                        json={"cve_id": "CVE-2024-1234", "cvss_score": 7.5},
                        headers=_no_key()),
            "/api/v1/risk/simulate/cve",
        )

    def test_portfolio_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/risk/simulate/portfolio", json={"cves": []}, headers=_no_key()),
            "/api/v1/risk/simulate/portfolio",
        )

    def test_fair_authenticated_not_rejected(self, client):
        resp = client.post(
            "/api/v1/risk/simulate/fair",
            json={"tef_min": 0.1, "tef_max": 10.0, "tef_mode": 2.0,
                  "vuln_min": 0.1, "vuln_max": 0.9, "vuln_mode": 0.5,
                  "primary_loss_min": 10000, "primary_loss_max": 1000000,
                  "primary_loss_mode": 100000,
                  "secondary_loss_min": 50000, "secondary_loss_max": 5000000,
                  "secondary_loss_mode": 500000,
                  "slef_probability": 0.3, "asset_value": 1000000, "iterations": 100},
            headers=_with_key(),
        )
        _assert_authenticated_ok(resp, "/api/v1/risk/simulate/fair")


# ============================================================================
# Admin wizard — onboarding state, sensitive
# ============================================================================

class TestAdminWizardNoAuth:
    def test_wizard_state_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/admin/wizard-state", headers=_no_key()),
            "/api/v1/admin/wizard-state",
        )

    def test_wizard_state_post_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/admin/wizard-state", json={}, headers=_no_key()),
            "/api/v1/admin/wizard-state POST",
        )


# ============================================================================
# Webhook router — okta/verify PUBLIC, everything else auth-gated
# ============================================================================

class TestWebhookAuth:
    def test_okta_verify_is_public(self, client):
        """Okta verification challenge must NOT require auth."""
        resp = client.get(
            "/api/v1/webhooks/okta/verify",
            headers={**_no_key(), "x-okta-verification-challenge": "test-challenge"},
        )
        # 200 (challenge echoed) or 400 (missing header on stripped call) — never 401/403
        assert resp.status_code not in (401, 403), (
            f"okta/verify should be public, got {resp.status_code}"
        )

    def test_okta_events_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/webhooks/okta/events", json={}, headers=_no_key()),
            "/api/v1/webhooks/okta/events",
        )

    def test_generic_webhook_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/webhooks/generic/github", json={}, headers=_no_key()),
            "/api/v1/webhooks/generic/github",
        )

    def test_list_events_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/webhooks/events", headers=_no_key()),
            "/api/v1/webhooks/events",
        )

    def test_webhooks_index_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/webhooks/", headers=_no_key()),
            "/api/v1/webhooks/",
        )


# ============================================================================
# Stripe webhook — must remain PUBLIC (Stripe HMAC auth, not our API key)
# ============================================================================

class TestStripeWebhookRemainsPublic:
    def test_stripe_webhook_not_401(self, client):
        """Stripe sends without our API key — must NOT return 401/403."""
        resp = client.post(
            "/api/v1/billing/stripe-webhook",
            json={"type": "customer.created", "id": "evt_test", "data": {}},
            headers={"stripe-signature": "t=123,v1=invalid"},
        )
        # 400 (invalid sig), 200/202 (accepted), 422 (validation) — all fine
        # 401/403 would break Stripe integration
        assert resp.status_code not in (401, 403), (
            f"Stripe webhook must not require our API key, got {resp.status_code}"
        )


# ============================================================================
# SCIM router — needs auth
# ============================================================================

class TestSCIMNoAuth:
    def test_scim_service_provider_config_no_key(self, client):
        _assert_auth_required(
            client.get("/scim/v2/ServiceProviderConfig", headers=_no_key()),
            "/scim/v2/ServiceProviderConfig",
        )

    def test_scim_users_no_key(self, client):
        _assert_auth_required(
            client.get("/scim/v2/Users", headers=_no_key()),
            "/scim/v2/Users",
        )

    def test_scim_create_user_no_key(self, client):
        _assert_auth_required(
            client.post("/scim/v2/Users", json={}, headers=_no_key()),
            "/scim/v2/Users POST",
        )


# ============================================================================
# Stream router
# ============================================================================

class TestStreamNoAuth:
    def test_stream_publish_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/stream/publish", json={"channel": "test", "event": {}},
                        headers=_no_key()),
            "/api/v1/stream/publish",
        )

    def test_stream_stats_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/stream/stats", headers=_no_key()),
            "/api/v1/stream/stats",
        )


# ============================================================================
# TrustGraph maintenance / quality
# ============================================================================

class TestTrustGraphAdminNoAuth:
    def test_maintenance_sweep_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/trustgraph/maintenance/sweep", json={}, headers=_no_key()),
            "/api/v1/trustgraph/maintenance/sweep",
        )

    def test_quality_coverage_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/trustgraph/quality/coverage", headers=_no_key()),
            "/api/v1/trustgraph/quality/coverage",
        )


# ============================================================================
# Security KPI, report scheduler, SOC automation
# ============================================================================

class TestOperationalRoutersNoAuth:
    def test_kpi_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/kpis/record", json={}, headers=_no_key()),
            "/api/v1/kpis/record",
        )

    def test_report_scheduler_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/reports/schedules", headers=_no_key()),
            "/api/v1/reports/schedules",
        )

    def test_soc_automation_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/soc-automation/rules", headers=_no_key()),
            "/api/v1/soc-automation/rules",
        )


# ============================================================================
# Attack / pentest routers
# ============================================================================

class TestAttackRoutersNoAuth:
    def test_attack_path_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/attack-paths/nodes", json={}, headers=_no_key()),
            "/api/v1/attack-paths/nodes",
        )

    def test_breach_sim_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/breach-sim/run", json={}, headers=_no_key()),
            "/api/v1/breach-sim/run",
        )


# ============================================================================
# Bulk operations
# ============================================================================

class TestBulkNoAuth:
    def test_bulk_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/bulk/clusters/status", json={}, headers=_no_key()),
            "/api/v1/bulk/clusters/status",
        )


# ============================================================================
# GraphQL
# ============================================================================

class TestGraphQLNoAuth:
    def test_graphql_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/graphql", json={"query": "{ __typename }"}, headers=_no_key()),
            "/api/v1/graphql",
        )


# ============================================================================
# Cloud integration connectors — all need auth
# ============================================================================

class TestCloudConnectorNoAuth:
    ENDPOINTS = [
        ("GET",  "/api/v1/aws-ecr/"),
        ("GET",  "/api/v1/aws-eks/"),
        ("GET",  "/api/v1/aws-s3/"),
        ("GET",  "/api/v1/azure-keyvault/"),
        ("GET",  "/api/v1/azure-sentinel/"),
        ("GET",  "/api/v1/bitbucket/"),
        ("GET",  "/api/v1/circleci/"),
        ("GET",  "/api/v1/gar/"),
        ("GET",  "/api/v1/github-api/"),
        ("GET",  "/api/v1/gitlab-pipeline/"),
        ("GET",  "/api/v1/harbor/"),
        ("GET",  "/api/v1/jenkins/"),
        ("GET",  "/api/v1/jira-cloud/"),
        ("GET",  "/api/v1/kong/"),
        ("GET",  "/api/v1/lacework/"),
        ("GET",  "/api/v1/mattermost/"),
        ("GET",  "/api/v1/noname/"),
        ("GET",  "/api/v1/microsoft-purview/"),
        ("GET",  "/api/v1/snowflake/"),
        ("GET",  "/api/v1/splunk/"),
        ("GET",  "/api/v1/splunk-soar-rest/rest/playbook"),
        ("GET",  "/api/v1/sumologic/"),
        ("GET",  "/api/v1/wiz/"),
        ("GET",  "/api/v1/workday/"),
        ("GET",  "/api/v1/zap/"),
    ]

    @pytest.mark.parametrize("method,endpoint", ENDPOINTS)
    def test_connector_no_key(self, client, method, endpoint):
        if method == "GET":
            resp = client.get(endpoint, headers=_no_key())
        else:
            resp = client.post(endpoint, json={}, headers=_no_key())
        _assert_auth_required(resp, endpoint)


# ============================================================================
# Security scanning tools
# ============================================================================

class TestScanningToolsNoAuth:
    def test_syft_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/syft/sbom", json={}, headers=_no_key()),
            "/api/v1/syft/sbom",
        )

    def test_tfsec_no_key(self, client):
        _assert_auth_required(
            client.post("/api/v1/tfsec/scan", json={}, headers=_no_key()),
            "/api/v1/tfsec/scan",
        )


# ============================================================================
# Policy, compliance, security posture
# ============================================================================

class TestPolicySecurityNoAuth:
    def test_policy_generator_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/policy-generator/policies", headers=_no_key()),
            "/api/v1/policy-generator/policies",
        )

    def test_fedramp_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/fedramp/controls", headers=_no_key()),
            "/api/v1/fedramp/controls",
        )

    def test_license_compliance_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/licenses/", headers=_no_key()),
            "/api/v1/licenses/",
        )

    def test_pyrit_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/pyrit/", headers=_no_key()),
            "/api/v1/pyrit/",
        )

    def test_red_team_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/red-team/engagements", headers=_no_key()),
            "/api/v1/red-team/engagements",
        )


# ============================================================================
# Threat intelligence
# ============================================================================

class TestThreatIntelNoAuth:
    def test_threat_intel_sharing_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/threat-sharing/indicators", headers=_no_key()),
            "/api/v1/threat-sharing/indicators",
        )

    def test_threat_modeling_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/threat-modeling-pipeline/", headers=_no_key()),
            "/api/v1/threat-modeling-pipeline/",
        )


# ============================================================================
# Collaboration / observability
# ============================================================================

class TestInternalToolingNoAuth:
    def test_observability_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/observability/metrics", headers=_no_key()),
            "/api/v1/observability/metrics",
        )

    def test_event_bus_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/event-bus/status", headers=_no_key()),
            "/api/v1/event-bus/status",
        )

    def test_llm_loop_metrics_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/llm-loop/metrics", headers=_no_key()),
            "/api/v1/llm-loop/metrics",
        )

    def test_mcp_gateway_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/mcp-gateway/tools", headers=_no_key()),
            "/api/v1/mcp-gateway/tools",
        )


# ============================================================================
# Security maturity + threat correlation (moved auth before router def)
# ============================================================================

class TestSecurityMaturityNoAuth:
    def test_maturity_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/security-maturity/assessments", headers=_no_key()),
            "/api/v1/security-maturity/assessments",
        )

    def test_maturity_authenticated_ok(self, client):
        resp = client.get("/api/v1/security-maturity/assessments", headers=_with_key())
        _assert_authenticated_ok(resp, "/api/v1/security-maturity/assessments")


class TestThreatCorrelationNoAuth:
    def test_correlation_no_key(self, client):
        _assert_auth_required(
            client.get("/api/v1/threat-correlation/signals", headers=_no_key()),
            "/api/v1/threat-correlation/signals",
        )

    def test_correlation_authenticated_ok(self, client):
        resp = client.get("/api/v1/threat-correlation/signals", headers=_with_key())
        _assert_authenticated_ok(resp, "/api/v1/threat-correlation/signals")


# ============================================================================
# System health remains public (spot-check)
# ============================================================================

class TestPublicEndpointsRemainPublic:
    def test_api_health_public(self, client):
        """Top-level /api/v1/health must remain public (health_v1_router)."""
        resp = client.get("/api/v1/health", headers=_no_key())
        assert resp.status_code not in (401, 403), (
            f"/api/v1/health must be public, got {resp.status_code}: {resp.text[:200]}"
        )

    def test_bare_health_public(self, client):
        """Bare /health endpoint must remain public (k8s liveness probe)."""
        resp = client.get("/health", headers=_no_key())
        assert resp.status_code not in (401, 403), (
            f"/health must be public, got {resp.status_code}"
        )

    def test_version_public(self, client):
        """Version endpoint must remain public."""
        resp = client.get("/api/v1/version", headers=_no_key())
        assert resp.status_code not in (401, 403), (
            f"/api/v1/version must be public, got {resp.status_code}"
        )
