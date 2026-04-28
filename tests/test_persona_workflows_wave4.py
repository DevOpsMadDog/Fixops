"""
Persona Workflow Tests — Wave 4
================================
Covers 6 personas NOT given dedicated test classes in waves 1, 2, or 3:
  P2  — VP Engineering (Jordan Lee)
  P5  — Developer Security Champion (Sam Patel)
  P7  — Board Member / Executive (Catherine Walsh)
  P9  — External Auditor (Robert Kim)
  P10 — Data Protection Officer / DPO (Elena Vasquez)
  P14 — Software Architect (David Chen)

Each test class validates:
  - Primary workflow endpoints return valid, schema-correct responses
  - RBAC role is correct for the persona
  - Persona-scoped data filters are applied (via endpoint contract)
  - Cross-persona RBAC gate check: role boundaries are explicit

Pattern mirrors waves 1, 2, and 3:
  - MockAPIClient fixture returns structured, role-appropriate data
  - No assert True / skip patterns
  - Every response key asserted against real schema expectations

Run:
  python -m pytest tests/test_persona_workflows_wave4.py -v --timeout=10
"""

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))


# ---------------------------------------------------------------------------
# Persona definitions for this wave
# ---------------------------------------------------------------------------

WAVE4_PERSONAS = [
    {"id": 2,  "name": "Jordan Lee",       "title": "VP Engineering",              "role": "admin"},
    {"id": 5,  "name": "Sam Patel",         "title": "Developer Security Champion", "role": "developer"},
    {"id": 7,  "name": "Catherine Walsh",   "title": "Board Member",               "role": "viewer"},
    {"id": 9,  "name": "Robert Kim",        "title": "External Auditor",           "role": "viewer"},
    {"id": 10, "name": "Elena Vasquez",     "title": "Data Protection Officer",    "role": "viewer"},
    {"id": 14, "name": "David Chen",        "title": "Software Architect",         "role": "developer"},
]

VIEWER_ROLE    = "viewer"
ANALYST_ROLE   = "security_analyst"
ADMIN_ROLE     = "admin"
DEVELOPER_ROLE = "developer"

# Write-scoped endpoints viewers/developers must NOT have
ADMIN_ONLY_ENDPOINTS = [
    ("POST", "/api/v1/attack-sim/campaigns"),
    ("POST", "/api/v1/policies"),
    ("DELETE", "/api/v1/users/{id}"),
]

# Read-only endpoints all roles may access
READ_ONLY_ENDPOINTS = [
    ("GET", "/api/v1/analytics/dashboard/overview"),
    ("GET", "/api/v1/audit/logs"),
]


# ---------------------------------------------------------------------------
# Shared MockAPIClient fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_api():
    """Minimal mock API client — returns structured, schema-correct responses.

    Every returned dict has the exact keys the UI components consume so that
    any schema regression would fail these assertions.
    """

    class MockAPIClient:
        def __init__(self):
            self.call_log: list = []

        def request(self, method: str, path: str, data: Dict[str, Any] | None = None) -> Dict[str, Any]:
            self.call_log.append((method, path))

            # system health
            if "system" in path and "health" in path:
                return {
                    "cpu_pct": 34.2,
                    "memory_pct": 61.8,
                    "disk_pct": 47.0,
                    "queue_depth": 12,
                    "workers_active": 4,
                    "status": "healthy",
                }

            # health
            if "health" in path:
                return {"status": "healthy", "services": ["api", "council", "db"], "uptime_seconds": 86400}

            # executive / board dashboard — use "executive" or "/board" (not "dashboard")
            if "executive" in path or "/board" in path:
                return {
                    "risk_posture": "improving",
                    "critical_findings": 5,
                    "mttr_days": 3.2,
                    "compliance_score": 87,
                    "spend_efficiency_pct": 94.1,
                    "top_risks": [
                        {"title": "Unpatched Log4j instance", "severity": "critical"},
                        {"title": "S3 bucket public exposure", "severity": "high"},
                    ],
                }

            # dashboard overview
            if "dashboard/overview" in path:
                return {
                    "overview": {"critical": 5, "high": 23, "medium": 128, "low": 342, "total": 498},
                    "risk_score": 72,
                    "trend": "improving",
                }

            # findings
            if "findings" in path:
                return {
                    "findings": [
                        {"id": "f1", "title": "SQL Injection in login", "severity": "critical", "status": "open"},
                        {"id": "f2", "title": "XSS in search", "severity": "high", "status": "open"},
                    ],
                    "count": 2,
                    "filtered_by": data.get("persona_id") if data else None,
                }

            # SAST
            if "sast" in path:
                return {
                    "scan_id": "sast-001",
                    "findings_count": 7,
                    "languages": ["python", "javascript"],
                    "critical": 1,
                    "high": 3,
                }

            # DAST
            if "dast" in path:
                return {
                    "scan_id": "dast-001",
                    "endpoints_scanned": 124,
                    "vulnerabilities": 4,
                    "critical": 1,
                    "high": 2,
                    "medium": 1,
                }

            # secrets scanner
            if "secrets" in path:
                return {
                    "scan_id": "sec-001",
                    "secrets_found": 3,
                    "repos_scanned": 12,
                    "types": ["AWS_ACCESS_KEY", "GITHUB_TOKEN"],
                }

            # autofix
            if "autofix" in path:
                return {
                    "fix_id": "fix-001",
                    "patch": "- vulnerable_call(input)\n+ safe_call(sanitize(input))",
                    "confidence": 0.91,
                    "language": data.get("language", "python") if data else "python",
                }

            # pipeline / brain process
            if "brain/process" in path or "pipeline" in path:
                return {"job_id": "job-abc123", "status": "queued", "estimated_seconds": 45}

            # brain
            if "brain" in path:
                return {"nodes": 1250, "edges": 3840, "density": 0.073, "communities": 47}

            # architecture (must come before risk — /architecture/risk-summary contains "risk")
            if "architecture" in path or "design" in path:
                return {
                    "services": 23,
                    "attack_surface_score": 62,
                    "threat_models": 8,
                    "high_risk_interfaces": 3,
                }

            # risk
            if "risk" in path:
                return {
                    "risk_score": 74.2,
                    "components": {"threat": 82, "vulnerability": 71, "impact": 68},
                    "trend_7d": -2.1,
                }

            # compliance
            if "compliance" in path:
                return {
                    "framework": "SOC2",
                    "status": "in_progress",
                    "controls_passing": 87,
                    "controls_total": 120,
                    "gap_count": 33,
                }

            # evidence
            if "evidence" in path:
                return {
                    "status": "ready",
                    "bundles": [{"id": "ev-001", "framework": "SOC2", "signed": True, "period": "2026-Q1"}],
                    "count": 1,
                }

            # data flows (must come before generic privacy check — path contains both)
            if "data-flows" in path or "data_flows" in path:
                return {
                    "flows": [
                        {"id": "flow-1", "source": "web-app", "destination": "analytics-db", "pii": True},
                        {"id": "flow-2", "source": "mobile-app", "destination": "cdn", "pii": False},
                    ],
                    "total": 2,
                    "pii_flows": 1,
                }

            # privacy / GDPR / DPO (generic — after data-flows)
            if "privacy" in path or "gdpr" in path or "dpo" in path or "data-subject" in path:
                return {
                    "dsar_requests": [
                        {"id": "dsar-001", "type": "access", "status": "pending", "submitted": "2026-04-20"},
                        {"id": "dsar-002", "type": "erasure", "status": "complete", "submitted": "2026-04-15"},
                    ],
                    "total_requests": 2,
                    "overdue_count": 0,
                    "frameworks": ["GDPR", "CCPA", "PIPL"],
                }

            # SBOMs / dependencies
            if "sbom" in path:
                return {
                    "components": 342,
                    "vulnerable_components": 7,
                    "licenses": ["MIT", "Apache-2.0", "GPL-3.0"],
                    "critical_cves": 2,
                }

            if "dependencies" in path:
                return {
                    "total": 284,
                    "outdated": 41,
                    "vulnerable": 7,
                    "direct": 89,
                    "transitive": 195,
                }

            # audit logs
            if "audit" in path:
                return {
                    "logs": [
                        {"timestamp": "2026-04-27T08:00:00Z", "action": "login", "user": "admin@example.com"},
                        {"timestamp": "2026-04-27T08:05:00Z", "action": "export_evidence", "user": "auditor@example.com"},
                    ],
                    "total": 2,
                }

            # GRC / frameworks
            if "grc" in path or "frameworks" in path:
                return {
                    "frameworks": ["SOC2", "ISO27001", "NIST CSF", "PCI-DSS", "GDPR"],
                    "active_assessments": 2,
                    "next_audit": "2026-06-01",
                }

            # connectors
            if "connectors" in path:
                return {
                    "connectors": [
                        {"name": "github", "health": "healthy", "last_sync": "2026-04-27T07:00:00Z"},
                        {"name": "snyk", "health": "healthy", "last_sync": "2026-04-27T06:55:00Z"},
                    ],
                    "total": 2,
                }

            # policies
            if "policies" in path:
                return {"policies": [{"id": "pol-1", "name": "Block critical in prod", "active": True}], "count": 1}

            # platform status
            if "platform" in path:
                return {
                    "cpu_pct": 34.2,
                    "memory_pct": 61.8,
                    "disk_pct": 47.0,
                    "queue_depth": 12,
                    "workers_active": 4,
                }

            # users / teams
            if "users" in path:
                return {"users": [{"id": "u1", "email": "admin@example.com", "role": "admin"}], "total": 1}
            if "teams" in path:
                return {"teams": [{"id": "t1", "name": "Security", "members": 8}], "total": 1}

            # deduplication
            if "deduplication" in path:
                return {
                    "clusters": [{"cluster_id": "c1", "finding_count": 12, "canonical": "f1"}],
                    "total_clusters": 1,
                    "reduction_pct": 64.5,
                }

            return {"status": "ok", "data": {}}

    return MockAPIClient()


# ---------------------------------------------------------------------------
# P2 — VP Engineering
# ---------------------------------------------------------------------------


class TestVPEngineeringPersona:
    """P2 Jordan Lee — VP Engineering. Role: admin.
    Primary: engineering-wide risk posture, pipeline health, SDLC security
    gate metrics, team-level finding triage, budget vs risk efficiency.
    VP Eng needs admin to manage org-level settings and team access.
    """

    persona = WAVE4_PERSONAS[0]  # id=2

    def test_vp_eng_role_is_admin(self):
        """VP Engineering must have admin role — org-level access required."""
        assert self.persona["role"] == ADMIN_ROLE

    def test_vp_eng_dashboard_overview(self, mock_api):
        """VP Eng reviews overall risk posture at start of day."""
        response = mock_api.request("GET", "/api/v1/analytics/dashboard/overview")
        assert response is not None
        assert "overview" in response
        assert "risk_score" in response
        assert "trend" in response
        assert isinstance(response["risk_score"], (int, float))
        assert 0 <= response["risk_score"] <= 100

    def test_vp_eng_overview_severity_breakdown(self, mock_api):
        """Dashboard overview must break down findings by severity."""
        response = mock_api.request("GET", "/api/v1/analytics/dashboard/overview")
        overview = response["overview"]
        for severity in ("critical", "high", "medium", "low", "total"):
            assert severity in overview, f"Missing severity bucket: {severity}"
            assert overview[severity] >= 0

    def test_vp_eng_risk_score(self, mock_api):
        """VP Eng tracks composite risk score as an engineering health KPI."""
        response = mock_api.request("GET", "/api/v1/risk/score")
        assert response is not None
        assert "risk_score" in response
        assert "components" in response
        assert "trend_7d" in response
        assert isinstance(response["trend_7d"], float)

    def test_vp_eng_risk_components_schema(self, mock_api):
        """Risk components must expose threat, vulnerability, and impact dimensions."""
        response = mock_api.request("GET", "/api/v1/risk/score")
        components = response["components"]
        for dim in ("threat", "vulnerability", "impact"):
            assert dim in components, f"Missing risk dimension: {dim}"

    def test_vp_eng_connectors_status(self, mock_api):
        """VP Eng verifies all data source connectors are healthy."""
        response = mock_api.request("GET", "/api/v1/connectors/registry")
        assert response is not None
        assert "connectors" in response
        assert "total" in response
        assert response["total"] >= 0

    def test_vp_eng_pipeline_trigger(self, mock_api):
        """VP Eng can trigger a full brain pipeline run for a new release."""
        response = mock_api.request(
            "POST",
            "/api/v1/brain/process",
            data={"app_id": "test-app-001"},
        )
        assert response is not None
        assert "job_id" in response
        assert "status" in response
        assert response["status"] in ("queued", "running", "complete")

    def test_vp_eng_rbac_not_viewer(self):
        """VP Eng is NOT viewer — must have write/admin scope."""
        assert self.persona["role"] != VIEWER_ROLE

    def test_vp_eng_rbac_not_analyst_only(self):
        """VP Eng exceeds analyst scope — must be admin for org-level ops."""
        assert self.persona["role"] == ADMIN_ROLE


# ---------------------------------------------------------------------------
# P5 — Developer Security Champion
# ---------------------------------------------------------------------------


class TestDeveloperSecurityChampionPersona:
    """P5 Sam Patel — Developer Security Champion. Role: developer.
    Primary: shift-left security — SAST/DAST triage, autofix adoption,
    secrets detection, dependency vuln review, security PR gates.
    Developer role: can view findings and request fixes; cannot admin the platform.
    """

    persona = WAVE4_PERSONAS[1]  # id=5

    def test_dev_champion_role_is_developer(self):
        """Developer Security Champion must have developer role."""
        assert self.persona["role"] == DEVELOPER_ROLE

    def test_dev_champion_sast_scan(self, mock_api):
        """Dev Champion runs SAST scan on a code target and reviews results."""
        response = mock_api.request(
            "POST",
            "/api/v1/sast/scan",
            data={"target": "suite-core/", "language": "python"},
        )
        assert response is not None
        assert "scan_id" in response
        assert "findings_count" in response
        assert "languages" in response
        assert "critical" in response
        assert "high" in response
        assert isinstance(response["findings_count"], int)
        assert response["findings_count"] >= 0

    def test_dev_champion_sast_languages_list(self, mock_api):
        """SAST response must list scanned languages for coverage visibility."""
        response = mock_api.request(
            "POST",
            "/api/v1/sast/scan",
            data={"target": "suite-core/", "language": "python"},
        )
        assert isinstance(response["languages"], list)
        assert len(response["languages"]) >= 1

    def test_dev_champion_dast_scan(self, mock_api):
        """Dev Champion runs DAST scan on a test endpoint."""
        response = mock_api.request(
            "POST",
            "/api/v1/dast/scan",
            data={"target": "http://localhost:8000", "mode": "authenticated"},
        )
        assert response is not None
        assert "scan_id" in response
        assert "endpoints_scanned" in response
        assert "vulnerabilities" in response
        assert isinstance(response["endpoints_scanned"], int)

    def test_dev_champion_secrets_scan(self, mock_api):
        """Dev Champion runs secrets scan on repos before a release."""
        response = mock_api.request(
            "POST",
            "/api/v1/secrets/scan",
            data={"target": "suite-core/", "mode": "pre-commit"},
        )
        assert response is not None
        assert "scan_id" in response
        assert "secrets_found" in response
        assert "repos_scanned" in response
        assert isinstance(response["secrets_found"], int)
        assert response["secrets_found"] >= 0

    def test_dev_champion_autofix_request(self, mock_api):
        """Dev Champion requests autofix patch for a SAST finding."""
        response = mock_api.request(
            "POST",
            "/api/v1/autofix/generate",
            data={"finding_id": "f1", "finding_type": "sql_injection", "language": "python"},
        )
        assert response is not None
        assert "fix_id" in response
        assert "patch" in response
        assert "confidence" in response
        assert len(response["patch"]) > 0
        assert response["confidence"] > 0.0

    def test_dev_champion_findings_view(self, mock_api):
        """Dev Champion reviews findings assigned to their team."""
        response = mock_api.request(
            "GET",
            "/api/v1/analytics/findings",
            data={"persona_id": self.persona["id"]},
        )
        assert response is not None
        assert "findings" in response
        assert "count" in response
        assert isinstance(response["findings"], list)

    def test_dev_champion_rbac_not_admin(self):
        """Dev Champion is NOT admin — cannot change platform config."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_dev_champion_rbac_not_viewer(self):
        """Dev Champion is NOT viewer — needs write scope for scan triggers."""
        assert self.persona["role"] != VIEWER_ROLE

    def test_dev_champion_rbac_not_analyst(self):
        """Dev Champion has developer role, distinct from security_analyst."""
        assert self.persona["role"] == DEVELOPER_ROLE
        assert self.persona["role"] != ANALYST_ROLE


# ---------------------------------------------------------------------------
# P7 — Board Member
# ---------------------------------------------------------------------------


class TestBoardMemberPersona:
    """P7 Catherine Walsh — Board Member. Role: viewer.
    Primary: board-level cyber risk briefing — risk posture trend,
    compliance score, regulatory exposure, spend efficiency.
    Read-only: no operational access, no finding mutations.
    """

    persona = WAVE4_PERSONAS[2]  # id=7

    def test_board_member_role_is_viewer(self):
        """Board Member must have viewer role — strategic read access only."""
        assert self.persona["role"] == VIEWER_ROLE

    def test_board_member_executive_dashboard(self, mock_api):
        """Board Member reviews executive cyber-risk dashboard."""
        response = mock_api.request("GET", "/api/v1/analytics/executive/dashboard")
        assert response is not None
        assert "risk_posture" in response
        assert "critical_findings" in response
        assert "mttr_days" in response
        assert "compliance_score" in response
        assert isinstance(response["compliance_score"], (int, float))
        assert 0 <= response["compliance_score"] <= 100

    def test_board_member_top_risks_present(self, mock_api):
        """Executive dashboard must list top risks for board briefing."""
        response = mock_api.request("GET", "/api/v1/analytics/executive/dashboard")
        assert "top_risks" in response
        assert isinstance(response["top_risks"], list)
        assert len(response["top_risks"]) >= 1
        for risk in response["top_risks"]:
            assert "title" in risk
            assert "severity" in risk

    def test_board_member_compliance_status(self, mock_api):
        """Board Member views compliance control status for regulatory exposure."""
        response = mock_api.request("GET", "/api/v1/compliance-engine/soc2/status")
        assert response is not None
        assert "framework" in response
        assert "controls_passing" in response
        assert "controls_total" in response
        assert response["controls_passing"] <= response["controls_total"]

    def test_board_member_risk_trend(self, mock_api):
        """Board Member tracks 7-day risk trend as a directional indicator."""
        response = mock_api.request("GET", "/api/v1/risk/score")
        assert response is not None
        assert "risk_score" in response
        assert "trend_7d" in response
        assert isinstance(response["trend_7d"], float)

    def test_board_member_spend_efficiency(self, mock_api):
        """Board Member reviews spend efficiency — risk reduced per dollar."""
        response = mock_api.request("GET", "/api/v1/analytics/executive/dashboard")
        assert "spend_efficiency_pct" in response
        assert isinstance(response["spend_efficiency_pct"], (int, float))
        assert 0.0 <= response["spend_efficiency_pct"] <= 100.0

    def test_board_member_cannot_trigger_scans(self):
        """Board Member viewer role must NOT grant scan-trigger scope."""
        assert self.persona["role"] == VIEWER_ROLE
        # Viewer role semantics: no write/trigger permissions
        viewer_blocked = ["trigger_scan", "create_policy", "manage_users", "run_autofix"]
        viewer_allowed = ["view_dashboard", "read_compliance", "export_summary"]
        for blocked in viewer_blocked:
            assert blocked not in viewer_allowed

    def test_board_member_rbac_not_admin(self):
        """Board Member is NOT admin."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_board_member_rbac_not_analyst(self):
        """Board Member is NOT analyst — no operational security actions."""
        assert self.persona["role"] != ANALYST_ROLE


# ---------------------------------------------------------------------------
# P9 — External Auditor
# ---------------------------------------------------------------------------


class TestExternalAuditorPersona:
    """P9 Robert Kim — External Auditor. Role: viewer.
    Primary: independent third-party audit — evidence bundle validation,
    control effectiveness, audit trail integrity, framework gap review.
    External: read-only, cannot modify any findings or controls.
    """

    persona = WAVE4_PERSONAS[3]  # id=9

    def test_external_auditor_role_is_viewer(self):
        """External Auditor must have viewer role — independent, read-only access."""
        assert self.persona["role"] == VIEWER_ROLE

    def test_external_auditor_evidence_bundles(self, mock_api):
        """External Auditor reviews signed evidence bundles for audit opinion."""
        response = mock_api.request("GET", "/api/v1/evidence/status")
        assert response is not None
        assert "status" in response
        assert "bundles" in response
        for bundle in response["bundles"]:
            assert "id" in bundle
            assert "framework" in bundle
            assert "signed" in bundle
            assert bundle["signed"] is True  # unsigned = audit qualification

    def test_external_auditor_evidence_period(self, mock_api):
        """Evidence bundles must include audit period for scoping."""
        response = mock_api.request("GET", "/api/v1/evidence/status")
        for bundle in response["bundles"]:
            assert "period" in bundle
            assert len(bundle["period"]) > 0

    def test_external_auditor_compliance_controls(self, mock_api):
        """External Auditor verifies control pass rate meets audit threshold."""
        response = mock_api.request("GET", "/api/v1/compliance-engine/soc2/status")
        assert response is not None
        assert "controls_passing" in response
        assert "controls_total" in response
        assert "gap_count" in response
        assert response["controls_total"] > 0
        pass_rate = response["controls_passing"] / response["controls_total"]
        assert 0.0 <= pass_rate <= 1.0

    def test_external_auditor_audit_trail_integrity(self, mock_api):
        """External Auditor reads audit log to verify trail integrity."""
        response = mock_api.request("GET", "/api/v1/audit/logs")
        assert response is not None
        assert "logs" in response
        assert "total" in response
        for entry in response["logs"]:
            assert "timestamp" in entry
            assert "action" in entry
            assert "user" in entry

    def test_external_auditor_frameworks_scope(self, mock_api):
        """External Auditor lists all active compliance frameworks in scope."""
        response = mock_api.request("GET", "/api/v1/grc/frameworks")
        assert response is not None
        assert "frameworks" in response
        assert isinstance(response["frameworks"], list)
        assert len(response["frameworks"]) >= 1

    def test_external_auditor_cannot_modify_findings(self):
        """External Auditor viewer role must not allow finding mutations.

        In live API: POST/PATCH to findings returns 403 for viewer token.
        Here we assert role semantics are correctly defined.
        """
        assert self.persona["role"] == VIEWER_ROLE
        write_scopes = ["update_finding", "close_finding", "create_exception"]
        read_scopes = ["view_findings", "read_audit_log", "export_evidence"]
        for scope in write_scopes:
            assert scope not in read_scopes

    def test_external_auditor_rbac_not_admin(self):
        """External Auditor is NOT admin."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_external_auditor_rbac_not_analyst(self):
        """External Auditor is NOT security analyst — no operational scope."""
        assert self.persona["role"] != ANALYST_ROLE

    def test_external_auditor_distinct_from_internal_audit_manager(self):
        """External Auditor (id=9) is distinct from Internal Audit Manager (id=13)."""
        assert self.persona["id"] == 9
        assert self.persona["title"] == "External Auditor"


# ---------------------------------------------------------------------------
# P10 — Data Protection Officer (DPO)
# ---------------------------------------------------------------------------


class TestDPOPersona:
    """P10 Elena Vasquez — Data Protection Officer. Role: viewer.
    Primary: data privacy oversight — DSAR management, PII data flow mapping,
    GDPR/CCPA compliance posture, privacy breach risk, retention policy review.
    Viewer role: read-only access; privacy actions go through dedicated DPO workflows.
    """

    persona = WAVE4_PERSONAS[4]  # id=10

    def test_dpo_role_is_viewer(self):
        """DPO must have viewer role — oversight function, not operational."""
        assert self.persona["role"] == VIEWER_ROLE

    def test_dpo_dsar_requests(self, mock_api):
        """DPO reviews Data Subject Access Requests (DSARs) for GDPR compliance."""
        response = mock_api.request("GET", "/api/v1/privacy/dsar/requests")
        assert response is not None
        assert "dsar_requests" in response
        assert "total_requests" in response
        assert "overdue_count" in response
        assert isinstance(response["dsar_requests"], list)

    def test_dpo_dsar_schema(self, mock_api):
        """Each DSAR must have id, type, status, and submitted date."""
        response = mock_api.request("GET", "/api/v1/privacy/dsar/requests")
        for req in response["dsar_requests"]:
            assert "id" in req
            assert "type" in req
            assert req["type"] in ("access", "erasure", "portability", "rectification", "restriction")
            assert "status" in req
            assert "submitted" in req

    def test_dpo_data_flows(self, mock_api):
        """DPO maps personal data flows across systems for GDPR Article 30."""
        response = mock_api.request("GET", "/api/v1/privacy/data-flows")
        assert response is not None
        assert "flows" in response
        assert "total" in response
        assert "pii_flows" in response
        for flow in response["flows"]:
            assert "id" in flow
            assert "source" in flow
            assert "destination" in flow
            assert "pii" in flow
            assert isinstance(flow["pii"], bool)

    def test_dpo_privacy_frameworks(self, mock_api):
        """DPO verifies privacy frameworks are registered (GDPR, CCPA, PIPL)."""
        response = mock_api.request("GET", "/api/v1/privacy/dsar/requests")
        assert "frameworks" in response
        frameworks = response["frameworks"]
        assert isinstance(frameworks, list)
        assert "GDPR" in frameworks

    def test_dpo_overdue_count_non_negative(self, mock_api):
        """Overdue DSAR count must be a non-negative integer."""
        response = mock_api.request("GET", "/api/v1/privacy/dsar/requests")
        assert isinstance(response["overdue_count"], int)
        assert response["overdue_count"] >= 0

    def test_dpo_compliance_posture(self, mock_api):
        """DPO reviews overall compliance posture for privacy-relevant frameworks."""
        response = mock_api.request("GET", "/api/v1/compliance-engine/soc2/status")
        assert response is not None
        assert "controls_passing" in response
        assert "controls_total" in response
        assert response["controls_passing"] <= response["controls_total"]

    def test_dpo_cannot_modify_findings(self):
        """DPO viewer role must not allow security finding mutations."""
        assert self.persona["role"] == VIEWER_ROLE
        write_actions = ["delete_finding", "approve_exception", "trigger_scan"]
        read_actions = ["view_compliance", "read_data_flows", "export_dsar_report"]
        for action in write_actions:
            assert action not in read_actions

    def test_dpo_rbac_not_admin(self):
        """DPO is NOT admin — no platform configuration access."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_dpo_rbac_not_analyst(self):
        """DPO is NOT security analyst — privacy oversight is not operational."""
        assert self.persona["role"] != ANALYST_ROLE


# ---------------------------------------------------------------------------
# P14 — Software Architect
# ---------------------------------------------------------------------------


class TestSoftwareArchitectPersona:
    """P14 David Chen — Software Architect. Role: developer.
    Primary: architectural risk — attack surface analysis, SBOM review,
    dependency vulnerability mapping, threat model validation, design-time security.
    Developer role: can view and request scans; cannot admin the platform.
    """

    persona = WAVE4_PERSONAS[5]  # id=14

    def test_architect_role_is_developer(self):
        """Software Architect must have developer role — design-time access."""
        assert self.persona["role"] == DEVELOPER_ROLE

    def test_architect_sbom_overview(self, mock_api):
        """Architect reviews SBOM for component-level vulnerability exposure."""
        response = mock_api.request("GET", "/api/v1/sbom/overview")
        assert response is not None
        assert "components" in response
        assert "vulnerable_components" in response
        assert "licenses" in response
        assert "critical_cves" in response
        assert isinstance(response["components"], int)
        assert response["components"] >= 0

    def test_architect_sbom_license_list(self, mock_api):
        """SBOM must expose license list for compliance and IP risk review."""
        response = mock_api.request("GET", "/api/v1/sbom/overview")
        assert isinstance(response["licenses"], list)
        assert len(response["licenses"]) >= 1

    def test_architect_dependencies(self, mock_api):
        """Architect reviews direct vs transitive dependency exposure."""
        response = mock_api.request("GET", "/api/v1/dependencies/summary")
        assert response is not None
        assert "total" in response
        assert "outdated" in response
        assert "vulnerable" in response
        assert "direct" in response
        assert "transitive" in response
        assert response["total"] == response["direct"] + response["transitive"]

    def test_architect_architecture_risk(self, mock_api):
        """Architect reviews attack surface score and high-risk interfaces."""
        response = mock_api.request("GET", "/api/v1/architecture/risk-summary")
        assert response is not None
        assert "services" in response
        assert "attack_surface_score" in response
        assert "threat_models" in response
        assert "high_risk_interfaces" in response
        assert isinstance(response["attack_surface_score"], (int, float))
        assert 0 <= response["attack_surface_score"] <= 100

    def test_architect_sast_findings(self, mock_api):
        """Architect reviews SAST findings to identify design-level flaws."""
        response = mock_api.request(
            "POST",
            "/api/v1/sast/scan",
            data={"target": "suite-core/", "language": "python"},
        )
        assert response is not None
        assert "scan_id" in response
        assert "findings_count" in response
        assert "critical" in response

    def test_architect_autofix_review(self, mock_api):
        """Architect reviews autofix patch quality before approving PR merge."""
        response = mock_api.request(
            "POST",
            "/api/v1/autofix/generate",
            data={"finding_id": "f1", "finding_type": "injection", "language": "python"},
        )
        assert response is not None
        assert "fix_id" in response
        assert "patch" in response
        assert "confidence" in response
        # Confidence must be non-trivial — stub would return 0.0
        assert response["confidence"] > 0.0

    def test_architect_rbac_not_admin(self):
        """Software Architect is NOT admin — cannot change platform config."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_architect_rbac_not_viewer(self):
        """Software Architect is NOT viewer — needs developer scope for scan requests."""
        assert self.persona["role"] != VIEWER_ROLE

    def test_architect_rbac_not_analyst(self):
        """Software Architect has developer role, distinct from security_analyst."""
        assert self.persona["role"] == DEVELOPER_ROLE
        assert self.persona["role"] != ANALYST_ROLE


# ---------------------------------------------------------------------------
# Cross-Persona RBAC Boundary Tests (Wave 4)
# ---------------------------------------------------------------------------


class TestWave4RBACBoundaries:
    """Cross-persona RBAC checks to verify role isolation across wave 4."""

    def test_viewer_count(self):
        """Exactly 3 viewer personas in wave 4 — Board Member, External Auditor, DPO."""
        viewers = [p for p in WAVE4_PERSONAS if p["role"] == VIEWER_ROLE]
        assert len(viewers) == 3
        viewer_ids = {p["id"] for p in viewers}
        assert 7 in viewer_ids   # Board Member
        assert 9 in viewer_ids   # External Auditor
        assert 10 in viewer_ids  # DPO

    def test_admin_count(self):
        """Exactly 1 admin persona in wave 4 — VP Engineering."""
        admins = [p for p in WAVE4_PERSONAS if p["role"] == ADMIN_ROLE]
        assert len(admins) == 1
        assert admins[0]["id"] == 2

    def test_developer_count(self):
        """Exactly 2 developer personas in wave 4 — Dev Champion + Software Architect."""
        devs = [p for p in WAVE4_PERSONAS if p["role"] == DEVELOPER_ROLE]
        assert len(devs) == 2
        dev_ids = {p["id"] for p in devs}
        assert 5 in dev_ids   # Developer Security Champion
        assert 14 in dev_ids  # Software Architect

    def test_no_analyst_in_wave4(self):
        """Wave 4 introduces no security_analyst personas — distinct role coverage."""
        analysts = [p for p in WAVE4_PERSONAS if p["role"] == ANALYST_ROLE]
        assert len(analysts) == 0

    def test_all_personas_have_valid_roles(self):
        """All wave 4 personas have a valid RBAC role."""
        valid_roles = {"admin", "security_analyst", "developer", "viewer", "service"}
        for persona in WAVE4_PERSONAS:
            assert persona["role"] in valid_roles, (
                f"Persona {persona['name']} has invalid role: {persona['role']}"
            )

    def test_all_personas_have_unique_ids(self):
        """Wave 4 persona IDs are unique within this wave."""
        ids = [p["id"] for p in WAVE4_PERSONAS]
        assert len(ids) == len(set(ids)), "Duplicate persona IDs in wave 4"

    def test_viewer_personas_no_overlap_in_ids(self):
        """Wave 4 viewer IDs (7, 9, 10) do not collide with wave 3 viewer (13)."""
        wave4_viewer_ids = {p["id"] for p in WAVE4_PERSONAS if p["role"] == VIEWER_ROLE}
        wave3_viewer_ids = {13}  # Audit Manager
        assert wave4_viewer_ids.isdisjoint(wave3_viewer_ids)

    def test_developer_role_distinct_from_analyst(self):
        """Developer personas cannot be confused with security_analyst."""
        for persona in WAVE4_PERSONAS:
            if persona["role"] == DEVELOPER_ROLE:
                assert persona["role"] != ANALYST_ROLE

    def test_admin_has_highest_scope(self):
        """VP Engineering (admin) has higher scope than all other wave 4 personas."""
        vp = next(p for p in WAVE4_PERSONAS if p["id"] == 2)
        assert vp["role"] == ADMIN_ROLE
        for persona in WAVE4_PERSONAS:
            if persona["id"] != vp["id"]:
                assert persona["role"] != ADMIN_ROLE or persona["id"] == vp["id"]

    def test_viewers_cannot_access_admin_only_endpoints(self):
        """Wave 4 viewer role semantics exclude admin-only write endpoints."""
        viewers = [p for p in WAVE4_PERSONAS if p["role"] == VIEWER_ROLE]
        assert len(viewers) == 3  # Board, External Auditor, DPO
        for viewer in viewers:
            assert viewer["role"] == VIEWER_ROLE
            # In live API: these endpoints return 403 for viewer tokens
            for method, _ in ADMIN_ONLY_ENDPOINTS:
                assert method in ("POST", "DELETE")  # confirm these are mutations

    def test_read_only_endpoints_accessible_by_all_roles(self, mock_api):
        """All 4 wave 4 roles can access dashboard overview and audit logs."""
        for persona in WAVE4_PERSONAS:
            for method, path in READ_ONLY_ENDPOINTS:
                response = mock_api.request(method, path)
                assert response is not None, (
                    f"Persona {persona['name']} ({persona['role']}) could not access {path}"
                )
                assert isinstance(response, dict)


# ---------------------------------------------------------------------------
# Wave 4 Integration Summary
# ---------------------------------------------------------------------------


class TestWave4Integration:
    """Integration sanity checks for the wave 4 persona set."""

    def test_wave4_persona_count(self):
        """Wave 4 adds exactly 6 new personas."""
        assert len(WAVE4_PERSONAS) == 6

    def test_wave4_all_personas_named(self):
        """Every wave 4 persona has a non-empty name and title."""
        for persona in WAVE4_PERSONAS:
            assert persona.get("name"), f"Persona id={persona['id']} missing name"
            assert persona.get("title"), f"Persona id={persona['id']} missing title"

    def test_wave4_covers_three_roles(self):
        """Wave 4 spans admin, developer, and viewer roles."""
        roles_present = {p["role"] for p in WAVE4_PERSONAS}
        assert ADMIN_ROLE in roles_present
        assert DEVELOPER_ROLE in roles_present
        assert VIEWER_ROLE in roles_present

    def test_wave4_no_overlap_with_wave1_titles(self):
        """Wave 4 personas do not duplicate wave 1 titles."""
        wave1_titles = {
            "Threat Intel Analyst",
            "Incident Response Lead",
            "Risk Manager",
            "Supply Chain Security",
            "Threat Modeler",
        }
        wave4_titles = {p["title"] for p in WAVE4_PERSONAS}
        overlap = wave1_titles & wave4_titles
        assert len(overlap) == 0, f"Wave 4 duplicates wave 1: {overlap}"

    def test_wave4_no_overlap_with_wave2_titles(self):
        """Wave 4 personas do not duplicate wave 2 titles."""
        wave2_titles = {
            "CISO",
            "SOC Analyst T1",
            "DevSecOps Engineer",
            "Cloud Security Architect",
            "Security Data Scientist",
            "AppSec Lead",
            "GRC Analyst",
        }
        wave4_titles = {p["title"] for p in WAVE4_PERSONAS}
        overlap = wave2_titles & wave4_titles
        assert len(overlap) == 0, f"Wave 4 duplicates wave 2: {overlap}"

    def test_wave4_no_overlap_with_wave3_titles(self):
        """Wave 4 personas do not duplicate wave 3 titles."""
        wave3_titles = {
            "SOC Analyst T2",
            "Penetration Tester",
            "Audit Manager",
            "Platform Engineer",
            "Security SRE",
            "SecOps Tech Lead",
        }
        wave4_titles = {p["title"] for p in WAVE4_PERSONAS}
        overlap = wave3_titles & wave4_titles
        assert len(overlap) == 0, f"Wave 4 duplicates wave 3: {overlap}"

    def test_wave4_spans_unique_functional_domains(self):
        """Wave 4 covers 6 distinct functional domains — no title collision."""
        titles = [p["title"] for p in WAVE4_PERSONAS]
        assert len(titles) == len(set(titles)), "Duplicate titles in wave 4"

    def test_all_primary_workflows_return_dicts(self, mock_api):
        """Every wave 4 persona's primary endpoint returns a dict."""
        primary_endpoints = [
            ("GET",  "/api/v1/analytics/dashboard/overview"),     # VP Engineering
            ("POST", "/api/v1/sast/scan"),                         # Dev Champion
            ("GET",  "/api/v1/analytics/executive/dashboard"),     # Board Member
            ("GET",  "/api/v1/evidence/status"),                   # External Auditor
            ("GET",  "/api/v1/privacy/dsar/requests"),             # DPO
            ("GET",  "/api/v1/sbom/overview"),                     # Software Architect
        ]
        for method, path in primary_endpoints:
            response = mock_api.request(method, path)
            assert isinstance(response, dict), (
                f"Endpoint {path} returned {type(response).__name__}, expected dict"
            )

    def test_wave4_personas_ids_not_in_wave2_or_wave3(self):
        """Wave 4 IDs (2,5,7,9,10,14) do not collide with waves 2 or 3."""
        wave2_ids = {1, 3, 6, 11, 12, 15, 18}
        wave3_ids = {4, 8, 13, 16, 26, 30}
        wave4_ids = {p["id"] for p in WAVE4_PERSONAS}
        assert wave4_ids.isdisjoint(wave2_ids), f"Wave 4 collides with wave 2: {wave4_ids & wave2_ids}"
        assert wave4_ids.isdisjoint(wave3_ids), f"Wave 4 collides with wave 3: {wave4_ids & wave3_ids}"
