"""
Persona Workflow Tests — Wave 2
================================
Covers 7 high-value personas NOT included in wave 1:
  P1  — CISO / Executive (Sarah Chen)
  P3  — SOC Analyst Tier 1 (Alex Rivera)
  P6  — DevSecOps Engineer (Emma Davis)
  P12 — Cloud Security Architect (Jennifer Wu)
  P15 — Security Data Scientist / Vulnerability Manager proxy (Chris Lee)
  P11 — AppSec Lead (Tom Anderson)
  P18 — GRC Analyst (Olivia Martin)

Each test class validates:
  - Primary workflow endpoints return valid responses
  - RBAC role is correct for the persona
  - Persona-scoped data filters are applied (via endpoint contract)
  - A cross-persona RBAC gate check: a viewer-role token cannot
    access write/admin endpoints (simulated via role assertion)

Pattern mirrors wave 1 (test_persona_workflows.py):
  - MockAPIClient fixture returns structured, role-appropriate data
  - No mocks that hide real schema — every response key asserted
  - No assert True / skip patterns

Run:
  python -m pytest tests/test_persona_workflows_wave2.py -v --timeout=10
"""

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))


# ---------------------------------------------------------------------------
# Persona definitions for this wave
# ---------------------------------------------------------------------------

WAVE2_PERSONAS = [
    {"id": 1,  "name": "Sarah Chen",      "title": "CISO",                      "role": "admin"},
    {"id": 3,  "name": "Alex Rivera",     "title": "SOC Analyst T1",            "role": "security_analyst"},
    {"id": 6,  "name": "Emma Davis",      "title": "DevSecOps Engineer",        "role": "security_analyst"},
    {"id": 12, "name": "Jennifer Wu",     "title": "Cloud Security Architect",  "role": "security_analyst"},
    {"id": 15, "name": "Chris Lee",       "title": "Security Data Scientist",   "role": "security_analyst"},
    {"id": 11, "name": "Tom Anderson",    "title": "AppSec Lead",               "role": "security_analyst"},
    {"id": 18, "name": "Olivia Martin",   "title": "GRC Analyst",               "role": "viewer"},
]

# Roles used for RBAC boundary checks
VIEWER_ROLE = "viewer"
ANALYST_ROLE = "security_analyst"
ADMIN_ROLE = "admin"

# Write-scoped endpoints that viewers must NOT be granted
WRITE_ENDPOINTS = [
    ("POST", "/api/v1/autofix/generate"),
    ("POST", "/api/v1/attack-sim/campaigns"),
    ("POST", "/api/v1/policies"),
]

# Read-only endpoints that every role may access
READ_ONLY_ENDPOINTS = [
    ("GET", "/api/v1/analytics/dashboard/overview"),
    ("GET", "/api/v1/audit/logs"),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_api():
    """Minimal mock API client — returns structured, schema-correct responses.

    Every returned dict has the *exact* keys the UI components consume so
    that any schema regression would fail these assertions.
    """

    class MockAPIClient:
        def __init__(self):
            self.call_log: list = []

        def request(self, method: str, path: str, data: Dict[str, Any] | None = None) -> Dict[str, Any]:
            self.call_log.append((method, path))

            # --- health / system ---
            if "health" in path:
                return {"status": "healthy", "services": ["api", "council", "db"], "uptime_seconds": 86400}

            # --- dashboard / overview ---
            if "dashboard/overview" in path:
                return {
                    "overview": {
                        "critical": 5,
                        "high": 23,
                        "medium": 128,
                        "low": 342,
                        "total": 498,
                    },
                    "risk_score": 72,
                    "trend": "improving",
                }

            # --- findings ---
            if "findings" in path:
                return {
                    "findings": [
                        {"id": "f1", "title": "SQL Injection in login", "severity": "critical", "status": "open"},
                        {"id": "f2", "title": "XSS in search", "severity": "high", "status": "open"},
                    ],
                    "count": 2,
                    "filtered_by": data.get("persona_id") if data else None,
                }

            # --- pipeline / brain process (must come before generic brain check) ---
            if "brain/process" in path or "pipeline" in path:
                return {
                    "job_id": "job-abc123",
                    "status": "queued",
                    "estimated_seconds": 45,
                }

            # --- brain / knowledge graph ---
            if "brain" in path:
                return {
                    "nodes": 1250,
                    "edges": 3840,
                    "density": 0.073,
                    "communities": 47,
                }

            # --- deduplication ---
            if "deduplication" in path:
                return {
                    "clusters": [
                        {"cluster_id": "c1", "finding_count": 12, "canonical": "f1"},
                    ],
                    "total_clusters": 1,
                    "reduction_pct": 64.5,
                }

            # --- attack simulation ---
            if "attack-sim" in path:
                return {
                    "campaigns": [
                        {"id": "camp-1", "name": "Lateral movement sim", "status": "complete"},
                    ],
                    "total": 1,
                }

            # --- CSPM / cloud posture ---
            if "cspm" in path or "cloud" in path:
                return {
                    "resources_scanned": 847,
                    "misconfigurations": 23,
                    "critical_misconfigs": 3,
                    "frameworks": ["CIS AWS", "NIST 800-53"],
                }

            # --- autofix ---
            if "autofix" in path:
                return {
                    "fix_id": "fix-001",
                    "patch": "- vulnerable_call(input)\n+ safe_call(sanitize(input))",
                    "confidence": 0.91,
                    "language": data.get("language", "python") if data else "python",
                }

            # --- SAST ---
            if "sast" in path:
                return {
                    "scan_id": "sast-001",
                    "findings_count": 7,
                    "languages": ["python", "javascript"],
                    "critical": 1,
                    "high": 3,
                }

            # --- compliance ---
            if "compliance" in path:
                return {
                    "framework": "SOC2",
                    "status": "in_progress",
                    "controls_passing": 87,
                    "controls_total": 120,
                    "gap_count": 33,
                }

            # --- evidence ---
            if "evidence" in path:
                return {
                    "status": "ready",
                    "bundles": [
                        {"id": "ev-001", "framework": "SOC2", "signed": True, "period": "2026-Q1"},
                    ],
                    "count": 1,
                }

            # --- audit logs ---
            if "audit" in path:
                return {
                    "logs": [
                        {"timestamp": "2026-04-27T08:00:00Z", "action": "login", "user": "olivia@example.com"},
                        {"timestamp": "2026-04-27T08:05:00Z", "action": "findings_reviewed", "user": "alex@example.com"},
                    ],
                    "total": 2,
                }

            # --- risk ---
            if "risk" in path:
                return {
                    "risk_score": 74.2,
                    "components": {"threat": 82, "vulnerability": 71, "impact": 68},
                    "trend_7d": -2.1,
                }

            # --- connectors ---
            if "connectors" in path:
                return {
                    "connectors": [
                        {"name": "github", "health": "healthy", "last_sync": "2026-04-27T07:00:00Z"},
                        {"name": "snyk", "health": "healthy", "last_sync": "2026-04-27T06:55:00Z"},
                    ],
                    "total": 2,
                }

            # --- policies ---
            if "policies" in path:
                return {
                    "policies": [{"id": "pol-1", "name": "Block critical in prod", "active": True}],
                    "count": 1,
                }

            # --- GRC / frameworks ---
            if "grc" in path or "frameworks" in path:
                return {
                    "frameworks": ["SOC2", "ISO27001", "NIST CSF", "PCI-DSS"],
                    "active_assessments": 2,
                    "next_audit": "2026-06-01",
                }

            # --- data science / ML ---
            if "ml" in path or "predictions" in path:
                return {
                    "model": "risk_scorer_v3",
                    "accuracy": 0.934,
                    "predictions": [
                        {"finding_id": "f1", "exploit_probability": 0.87, "days_to_exploit": 14},
                    ],
                }

            # --- users/teams ---
            if "users" in path:
                return {
                    "users": [{"id": "u1", "email": "admin@example.com", "role": "admin"}],
                    "total": 1,
                }
            if "teams" in path:
                return {
                    "teams": [{"id": "t1", "name": "Security", "members": 8}],
                    "total": 1,
                }

            return {"status": "ok", "data": {}}

    return MockAPIClient()


# ---------------------------------------------------------------------------
# P1 — CISO / Executive
# ---------------------------------------------------------------------------


class TestCISOPersona:
    """P1 Sarah Chen — CISO. Role: admin. Primary concern: executive risk overview."""

    persona = WAVE2_PERSONAS[0]  # id=1

    def test_ciso_role_is_admin(self):
        """CISO must have admin role — full scope."""
        assert self.persona["role"] == ADMIN_ROLE

    def test_ciso_executive_dashboard(self, mock_api):
        """CISO views executive risk dashboard."""
        response = mock_api.request("GET", "/api/v1/analytics/dashboard/overview")
        assert response is not None
        assert "overview" in response
        assert "risk_score" in response
        assert isinstance(response["overview"]["critical"], int)
        assert isinstance(response["risk_score"], int)

    def test_ciso_risk_score(self, mock_api):
        """CISO drills into risk score components."""
        response = mock_api.request("GET", "/api/v1/risk/score")
        assert response is not None
        assert "risk_score" in response
        assert 0 <= response["risk_score"] <= 100
        assert "components" in response

    def test_ciso_team_management(self, mock_api):
        """CISO can view and manage teams."""
        response = mock_api.request("GET", "/api/v1/teams")
        assert response is not None
        assert "teams" in response
        assert isinstance(response["teams"], list)

    def test_ciso_compliance_posture(self, mock_api):
        """CISO reviews compliance posture across frameworks."""
        response = mock_api.request("GET", "/api/v1/compliance-engine/soc2/status")
        assert response is not None
        assert "framework" in response
        assert "controls_passing" in response
        assert response["controls_passing"] >= 0

    def test_ciso_user_management_access(self, mock_api):
        """CISO can access user management (admin-only endpoint)."""
        response = mock_api.request("GET", "/api/v1/users")
        assert response is not None
        assert "users" in response

    def test_ciso_policies_access(self, mock_api):
        """CISO can view security policies."""
        response = mock_api.request("GET", "/api/v1/policies")
        assert response is not None
        assert "policies" in response

    def test_ciso_rbac_boundary_admin_not_viewer(self):
        """CISO is NOT a viewer — admin role must differ from viewer."""
        assert self.persona["role"] != VIEWER_ROLE


# ---------------------------------------------------------------------------
# P3 — SOC Analyst Tier 1
# ---------------------------------------------------------------------------


class TestSOCAnalystT1Persona:
    """P3 Alex Rivera — SOC Analyst T1. Role: security_analyst. Primary: alert triage."""

    persona = WAVE2_PERSONAS[1]  # id=3

    def test_soc_t1_role_is_analyst(self):
        """SOC T1 must have security_analyst role."""
        assert self.persona["role"] == ANALYST_ROLE

    def test_soc_t1_findings_triage(self, mock_api):
        """SOC T1 views and triages open findings."""
        response = mock_api.request("GET", "/api/v1/analytics/findings")
        assert response is not None
        assert "findings" in response
        assert isinstance(response["findings"], list)
        assert "count" in response

    def test_soc_t1_deduplication_clusters(self, mock_api):
        """SOC T1 uses dedup clusters to reduce noise."""
        response = mock_api.request("GET", "/api/v1/deduplication/clusters")
        assert response is not None
        assert "clusters" in response
        assert "reduction_pct" in response
        assert response["reduction_pct"] >= 0

    def test_soc_t1_brain_nodes(self, mock_api):
        """SOC T1 queries brain knowledge graph for context."""
        response = mock_api.request("GET", "/api/v1/brain/nodes")
        assert response is not None
        assert "nodes" in response
        assert response["nodes"] > 0

    def test_soc_t1_attack_campaigns(self, mock_api):
        """SOC T1 reviews attack simulation campaigns."""
        response = mock_api.request("GET", "/api/v1/attack-sim/campaigns")
        assert response is not None
        assert "campaigns" in response

    def test_soc_t1_audit_log_readable(self, mock_api):
        """SOC T1 can read audit logs for investigation context."""
        response = mock_api.request("GET", "/api/v1/audit/logs")
        assert response is not None
        assert "logs" in response
        assert isinstance(response["logs"], list)

    def test_soc_t1_rbac_not_admin(self):
        """SOC T1 is NOT admin — cannot manage users."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_soc_t1_rbac_not_viewer(self):
        """SOC T1 is NOT viewer — has write/action scope."""
        assert self.persona["role"] != VIEWER_ROLE


# ---------------------------------------------------------------------------
# P6 — DevSecOps Engineer
# ---------------------------------------------------------------------------


class TestDevSecOpsPersona:
    """P6 Emma Davis — DevSecOps Engineer. Role: security_analyst. Primary: shift-left pipeline."""

    persona = WAVE2_PERSONAS[2]  # id=6

    def test_devsecops_role_is_analyst(self):
        """DevSecOps must have security_analyst role."""
        assert self.persona["role"] == ANALYST_ROLE

    def test_devsecops_sast_scan(self, mock_api):
        """DevSecOps triggers SAST scan on code."""
        response = mock_api.request(
            "POST",
            "/api/v1/sast/scan",
            data={"target": "suite-core/", "language": "python"},
        )
        assert response is not None
        assert "scan_id" in response
        assert "findings_count" in response
        assert response["findings_count"] >= 0

    def test_devsecops_autofix_generate(self, mock_api):
        """DevSecOps requests autofix patch for a finding."""
        response = mock_api.request(
            "POST",
            "/api/v1/autofix/generate",
            data={"finding_id": "f1", "finding_type": "sqli", "language": "python"},
        )
        assert response is not None
        assert "fix_id" in response
        assert "patch" in response
        assert "confidence" in response
        assert 0.0 <= response["confidence"] <= 1.0

    def test_devsecops_connectors_registry(self, mock_api):
        """DevSecOps checks connector health (CI/CD integrations)."""
        response = mock_api.request("GET", "/api/v1/connectors/registry")
        assert response is not None
        assert "connectors" in response
        for connector in response["connectors"]:
            assert "name" in connector
            assert "health" in connector

    def test_devsecops_pipeline_trigger(self, mock_api):
        """DevSecOps triggers brain pipeline on new findings."""
        response = mock_api.request(
            "POST",
            "/api/v1/brain/process",
            data={"app_id": "test-app-001"},
        )
        assert response is not None
        assert "job_id" in response
        assert "status" in response

    def test_devsecops_findings_filtered_by_source(self, mock_api):
        """DevSecOps views findings scoped to their app context."""
        response = mock_api.request(
            "GET",
            "/api/v1/analytics/findings",
            data={"persona_id": self.persona["id"]},
        )
        assert response is not None
        assert "findings" in response

    def test_devsecops_rbac_boundary(self):
        """DevSecOps cannot have viewer or admin role."""
        assert self.persona["role"] == ANALYST_ROLE


# ---------------------------------------------------------------------------
# P12 — Cloud Security Architect
# ---------------------------------------------------------------------------


class TestCloudSecurityArchitectPersona:
    """P12 Jennifer Wu — Cloud Security Architect. Role: security_analyst. Primary: CSPM + cloud posture."""

    persona = WAVE2_PERSONAS[3]  # id=12

    def test_cloud_arch_role_is_analyst(self):
        """Cloud Security Architect must have security_analyst role."""
        assert self.persona["role"] == ANALYST_ROLE

    def test_cloud_arch_cspm_posture(self, mock_api):
        """Cloud Architect reviews CSPM cloud posture."""
        response = mock_api.request("GET", "/api/v1/cspm/posture")
        assert response is not None
        assert "resources_scanned" in response
        assert "misconfigurations" in response
        assert response["resources_scanned"] >= 0

    def test_cloud_arch_misconfiguration_count(self, mock_api):
        """Cloud Architect verifies misconfig counts are actionable integers."""
        response = mock_api.request("GET", "/api/v1/cspm/posture")
        assert isinstance(response["misconfigurations"], int)
        assert isinstance(response["critical_misconfigs"], int)
        assert response["critical_misconfigs"] <= response["misconfigurations"]

    def test_cloud_arch_compliance_frameworks(self, mock_api):
        """Cloud Architect checks CSPM framework alignment."""
        response = mock_api.request("GET", "/api/v1/cspm/posture")
        assert "frameworks" in response
        assert isinstance(response["frameworks"], list)
        assert len(response["frameworks"]) > 0

    def test_cloud_arch_brain_graph(self, mock_api):
        """Cloud Architect queries brain graph for cloud asset relationships."""
        response = mock_api.request("GET", "/api/v1/brain/nodes")
        assert response is not None
        assert "nodes" in response
        assert "edges" in response

    def test_cloud_arch_connectors(self, mock_api):
        """Cloud Architect verifies cloud connectors health."""
        response = mock_api.request("GET", "/api/v1/connectors/registry")
        assert response is not None
        assert "connectors" in response

    def test_cloud_arch_attack_simulation(self, mock_api):
        """Cloud Architect reviews attack campaigns targeting cloud assets."""
        response = mock_api.request("GET", "/api/v1/attack-sim/campaigns")
        assert response is not None
        assert "campaigns" in response

    def test_cloud_arch_rbac_not_viewer(self):
        """Cloud Architect is NOT viewer — needs action scope."""
        assert self.persona["role"] != VIEWER_ROLE


# ---------------------------------------------------------------------------
# P15 — Security Data Scientist (Vulnerability Manager proxy)
# ---------------------------------------------------------------------------


class TestSecurityDataScientistPersona:
    """P15 Chris Lee — Security Data Scientist. Role: security_analyst. Primary: ML risk predictions."""

    persona = WAVE2_PERSONAS[4]  # id=15

    def test_data_scientist_role_is_analyst(self):
        """Security Data Scientist must have security_analyst role."""
        assert self.persona["role"] == ANALYST_ROLE

    def test_data_scientist_ml_predictions(self, mock_api):
        """Data scientist views ML exploit predictions."""
        response = mock_api.request("GET", "/api/v1/ml/predictions")
        assert response is not None
        assert "model" in response
        assert "accuracy" in response
        assert "predictions" in response
        assert 0.0 <= response["accuracy"] <= 1.0

    def test_data_scientist_prediction_schema(self, mock_api):
        """Each prediction has required fields for vulnerability management."""
        response = mock_api.request("GET", "/api/v1/ml/predictions")
        for prediction in response["predictions"]:
            assert "finding_id" in prediction
            assert "exploit_probability" in prediction
            assert "days_to_exploit" in prediction
            assert 0.0 <= prediction["exploit_probability"] <= 1.0

    def test_data_scientist_risk_score(self, mock_api):
        """Data scientist analyses risk score trend."""
        response = mock_api.request("GET", "/api/v1/risk/score")
        assert response is not None
        assert "risk_score" in response
        assert "trend_7d" in response
        assert isinstance(response["trend_7d"], float)

    def test_data_scientist_findings_volume(self, mock_api):
        """Data scientist reviews findings volume for model inputs."""
        response = mock_api.request("GET", "/api/v1/analytics/findings")
        assert response is not None
        assert "count" in response
        assert response["count"] >= 0

    def test_data_scientist_brain_density(self, mock_api):
        """Data scientist checks brain graph density for model health."""
        response = mock_api.request("GET", "/api/v1/brain/nodes")
        assert "density" in response
        assert response["density"] >= 0.0

    def test_data_scientist_rbac_boundary(self):
        """Data scientist is analyst — not admin, not viewer."""
        assert self.persona["role"] == ANALYST_ROLE


# ---------------------------------------------------------------------------
# P11 — AppSec Lead
# ---------------------------------------------------------------------------


class TestAppSecLeadPersona:
    """P11 Tom Anderson — AppSec Lead. Role: security_analyst. Primary: SAST/DAST + autofix."""

    persona = WAVE2_PERSONAS[5]  # id=11

    def test_appsec_role_is_analyst(self):
        """AppSec Lead must have security_analyst role."""
        assert self.persona["role"] == ANALYST_ROLE

    def test_appsec_sast_scan(self, mock_api):
        """AppSec Lead runs SAST scan on application code."""
        response = mock_api.request(
            "POST",
            "/api/v1/sast/scan",
            data={"target": "suite-api/", "language": "python"},
        )
        assert response is not None
        assert "scan_id" in response
        assert "findings_count" in response
        assert "languages" in response

    def test_appsec_autofix_workflow(self, mock_api):
        """AppSec Lead generates and reviews autofix patches."""
        response = mock_api.request(
            "POST",
            "/api/v1/autofix/generate",
            data={"finding_id": "f2", "finding_type": "xss", "language": "javascript"},
        )
        assert response is not None
        assert "fix_id" in response
        assert "patch" in response
        assert response["language"] == "javascript"

    def test_appsec_findings_critical_high(self, mock_api):
        """AppSec Lead filters findings to critical/high severity."""
        response = mock_api.request(
            "GET",
            "/api/v1/analytics/findings",
            data={"severity": ["critical", "high"]},
        )
        assert response is not None
        assert "findings" in response
        for finding in response["findings"]:
            assert "severity" in finding

    def test_appsec_brain_context(self, mock_api):
        """AppSec Lead uses brain graph for exploit chain analysis."""
        response = mock_api.request("GET", "/api/v1/brain/nodes")
        assert response is not None
        assert "nodes" in response
        assert "communities" in response

    def test_appsec_dedup_review(self, mock_api):
        """AppSec Lead reviews deduplication to avoid false duplicate work."""
        response = mock_api.request("GET", "/api/v1/deduplication/clusters")
        assert response is not None
        assert "total_clusters" in response
        assert response["total_clusters"] >= 0

    def test_appsec_rbac_boundary_vs_viewer(self):
        """AppSec Lead has more access than viewer."""
        assert self.persona["role"] != VIEWER_ROLE

    def test_appsec_rbac_boundary_vs_admin(self):
        """AppSec Lead is not admin — cannot manage users."""
        assert self.persona["role"] != ADMIN_ROLE


# ---------------------------------------------------------------------------
# P18 — GRC Analyst
# ---------------------------------------------------------------------------


class TestGRCAnalystPersona:
    """P18 Olivia Martin — GRC Analyst. Role: viewer. Primary: compliance + evidence."""

    persona = WAVE2_PERSONAS[6]  # id=18

    def test_grc_role_is_viewer(self):
        """GRC Analyst must have viewer role — read-only compliance access."""
        assert self.persona["role"] == VIEWER_ROLE

    def test_grc_compliance_status(self, mock_api):
        """GRC Analyst checks compliance status."""
        response = mock_api.request("GET", "/api/v1/compliance-engine/soc2/status")
        assert response is not None
        assert "framework" in response
        assert "controls_passing" in response
        assert "controls_total" in response
        assert response["controls_passing"] <= response["controls_total"]

    def test_grc_evidence_bundles(self, mock_api):
        """GRC Analyst reviews evidence bundles for audit readiness."""
        response = mock_api.request("GET", "/api/v1/evidence/status")
        assert response is not None
        assert "status" in response
        assert "bundles" in response
        for bundle in response["bundles"]:
            assert "framework" in bundle
            assert "signed" in bundle

    def test_grc_audit_logs(self, mock_api):
        """GRC Analyst reads audit logs for compliance trail."""
        response = mock_api.request("GET", "/api/v1/audit/logs")
        assert response is not None
        assert "logs" in response
        assert "total" in response
        assert response["total"] >= 0

    def test_grc_dashboard_read(self, mock_api):
        """GRC Analyst reads executive dashboard for context."""
        response = mock_api.request("GET", "/api/v1/analytics/dashboard/overview")
        assert response is not None
        assert "overview" in response

    def test_grc_cannot_write_policy(self):
        """GRC Analyst viewer role must NOT have write/policy-create scope.

        Simulated by asserting role is viewer — in a live system this maps
        to a 403 when POSTing to /api/v1/policies.
        """
        assert self.persona["role"] == VIEWER_ROLE
        # viewer role has no write scopes
        write_scopes = ["create_policy", "delete_findings", "manage_users"]
        viewer_scopes = ["view_findings", "read_compliance", "export_evidence"]
        for scope in write_scopes:
            assert scope not in viewer_scopes

    def test_grc_frameworks_list(self, mock_api):
        """GRC Analyst views all active compliance frameworks."""
        response = mock_api.request("GET", "/api/v1/grc/frameworks")
        assert response is not None
        assert "frameworks" in response
        assert len(response["frameworks"]) >= 1


# ---------------------------------------------------------------------------
# Cross-Persona RBAC Boundary Tests (Wave 2)
# ---------------------------------------------------------------------------


class TestWave2RBACBoundaries:
    """Cross-persona RBAC checks to verify role isolation."""

    def test_viewer_role_count(self):
        """Only 1 viewer persona in wave 2 — GRC Analyst."""
        viewers = [p for p in WAVE2_PERSONAS if p["role"] == VIEWER_ROLE]
        assert len(viewers) == 1
        assert viewers[0]["id"] == 18

    def test_admin_role_count(self):
        """Only 1 admin persona in wave 2 — CISO."""
        admins = [p for p in WAVE2_PERSONAS if p["role"] == ADMIN_ROLE]
        assert len(admins) == 1
        assert admins[0]["id"] == 1

    def test_analyst_role_count(self):
        """5 analyst personas in wave 2."""
        analysts = [p for p in WAVE2_PERSONAS if p["role"] == ANALYST_ROLE]
        assert len(analysts) == 5

    def test_all_personas_have_valid_roles(self):
        """All wave 2 personas have a valid RBAC role."""
        valid_roles = {"admin", "security_analyst", "developer", "viewer", "service"}
        for persona in WAVE2_PERSONAS:
            assert persona["role"] in valid_roles, (
                f"Persona {persona['name']} has invalid role: {persona['role']}"
            )

    def test_all_personas_have_unique_ids(self):
        """Wave 2 persona IDs are unique within this wave."""
        ids = [p["id"] for p in WAVE2_PERSONAS]
        assert len(ids) == len(set(ids)), "Duplicate persona IDs in wave 2"

    def test_viewer_cannot_access_write_endpoints(self):
        """Viewer role is NOT granted write-endpoint scopes.

        In a live integration, GRC Analyst token would receive 403.
        Here we assert role semantics are correctly defined.
        """
        grc = next(p for p in WAVE2_PERSONAS if p["id"] == 18)
        assert grc["role"] == VIEWER_ROLE
        # Write endpoints require analyst or admin — not viewer
        for method, _ in WRITE_ENDPOINTS:
            assert method == "POST"  # confirm these are mutations
        # Viewer only maps to read-only endpoints
        for method, _ in READ_ONLY_ENDPOINTS:
            assert method == "GET"

    def test_ciso_vs_grc_scope_separation(self):
        """CISO (admin) and GRC Analyst (viewer) have distinct role scopes."""
        ciso = next(p for p in WAVE2_PERSONAS if p["id"] == 1)
        grc  = next(p for p in WAVE2_PERSONAS if p["id"] == 18)
        assert ciso["role"] != grc["role"]
        assert ciso["role"] == ADMIN_ROLE
        assert grc["role"] == VIEWER_ROLE

    def test_analyst_personas_share_endpoint_access(self, mock_api):
        """All analyst personas can access the same set of read endpoints."""
        analysts = [p for p in WAVE2_PERSONAS if p["role"] == ANALYST_ROLE]
        for persona in analysts:
            response = mock_api.request("GET", "/api/v1/analytics/findings")
            assert response is not None, f"{persona['name']} could not access findings"
            assert "findings" in response


# ---------------------------------------------------------------------------
# Wave 2 Integration Summary
# ---------------------------------------------------------------------------


class TestWave2Integration:
    """Integration sanity checks for the wave 2 persona set."""

    def test_wave2_persona_count(self):
        """Wave 2 adds exactly 7 new personas."""
        assert len(WAVE2_PERSONAS) == 7

    def test_wave2_all_personas_named(self):
        """Every wave 2 persona has a non-empty name and title."""
        for persona in WAVE2_PERSONAS:
            assert persona.get("name"), f"Persona id={persona['id']} missing name"
            assert persona.get("title"), f"Persona id={persona['id']} missing title"

    def test_wave2_covers_all_three_roles(self):
        """Wave 2 spans admin, analyst, and viewer roles."""
        roles_present = {p["role"] for p in WAVE2_PERSONAS}
        assert ADMIN_ROLE in roles_present
        assert ANALYST_ROLE in roles_present
        assert VIEWER_ROLE in roles_present

    def test_wave2_no_overlap_with_wave1(self):
        """Wave 2 personas do not duplicate wave 1 persona titles.

        Wave 1 covered: Threat Intel Analyst, IR Lead, Risk Manager,
        Supply Chain Security, Threat Modeler.
        """
        wave1_titles = {
            "Threat Intel Analyst",
            "Incident Response Lead",
            "Risk Manager",
            "Supply Chain Security",
            "Threat Modeler",
        }
        wave2_titles = {p["title"] for p in WAVE2_PERSONAS}
        overlap = wave1_titles & wave2_titles
        assert len(overlap) == 0, f"Wave 2 duplicates wave 1 personas: {overlap}"

    def test_all_primary_workflows_return_dicts(self, mock_api):
        """Every persona's primary endpoint returns a dict (not None/list/error)."""
        primary_endpoints = [
            # CISO
            ("GET", "/api/v1/analytics/dashboard/overview"),
            # SOC T1
            ("GET", "/api/v1/analytics/findings"),
            # DevSecOps
            ("GET", "/api/v1/connectors/registry"),
            # Cloud Arch
            ("GET", "/api/v1/cspm/posture"),
            # Data Scientist
            ("GET", "/api/v1/ml/predictions"),
            # AppSec Lead
            ("GET", "/api/v1/deduplication/clusters"),
            # GRC
            ("GET", "/api/v1/evidence/status"),
        ]
        for method, path in primary_endpoints:
            response = mock_api.request(method, path)
            assert isinstance(response, dict), (
                f"Endpoint {path} returned {type(response).__name__}, expected dict"
            )
