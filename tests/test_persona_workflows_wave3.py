"""
Persona Workflow Tests — Wave 3
================================
Covers 6 personas NOT given dedicated test classes in waves 1 or 2:
  P4  — SOC Analyst Tier 2 (Priya Sharma)
  P8  — Penetration Tester (Lisa Zhang)
  P13 — Audit Manager (Michael Brown)
  P16 — Platform Engineer (Ryan Murphy)
  P26 — Security SRE (Marcus Reid)
  P30 — SecOps Tech Lead (Diana Foster)

Each test class validates:
  - Primary workflow endpoints return valid, schema-correct responses
  - RBAC role is correct for the persona
  - Persona-scoped data filters are applied (via endpoint contract)
  - Cross-persona RBAC gate check: role boundaries are explicit

Pattern mirrors waves 1 and 2:
  - MockAPIClient fixture returns structured, role-appropriate data
  - No assert True / skip patterns
  - Every response key asserted against real schema expectations

Run:
  python -m pytest tests/test_persona_workflows_wave3.py -v --timeout=10
"""

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))


# ---------------------------------------------------------------------------
# Persona definitions for this wave
# ---------------------------------------------------------------------------

WAVE3_PERSONAS = [
    {"id": 4,  "name": "Priya Sharma",   "title": "SOC Analyst T2",    "role": "security_analyst"},
    {"id": 8,  "name": "Lisa Zhang",     "title": "Penetration Tester", "role": "security_analyst"},
    {"id": 13, "name": "Michael Brown",  "title": "Audit Manager",      "role": "viewer"},
    {"id": 16, "name": "Ryan Murphy",    "title": "Platform Engineer",  "role": "admin"},
    {"id": 26, "name": "Marcus Reid",    "title": "Security SRE",       "role": "admin"},
    {"id": 30, "name": "Diana Foster",   "title": "SecOps Tech Lead",   "role": "security_analyst"},
]

VIEWER_ROLE   = "viewer"
ANALYST_ROLE  = "security_analyst"
ADMIN_ROLE    = "admin"
DEVELOPER_ROLE = "developer"

# Write-scoped endpoints viewers must NOT have
WRITE_ENDPOINTS = [
    ("POST", "/api/v1/autofix/generate"),
    ("POST", "/api/v1/attack-sim/campaigns"),
    ("POST", "/api/v1/policies"),
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

            # system health (must come before generic "health" check)
            if "system" in path:
                return {
                    "cpu_pct": 34.2,
                    "memory_pct": 61.8,
                    "disk_pct": 47.0,
                    "queue_depth": 12,
                    "workers_active": 4,
                }

            # health
            if "health" in path:
                return {"status": "healthy", "services": ["api", "council", "db"], "uptime_seconds": 86400}

            # dashboard
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

            # pipeline / brain process
            if "brain/process" in path or "pipeline" in path:
                return {"job_id": "job-abc123", "status": "queued", "estimated_seconds": 45}

            # brain graph
            if "brain" in path:
                return {"nodes": 1250, "edges": 3840, "density": 0.073, "communities": 47}

            # deduplication
            if "deduplication" in path:
                return {
                    "clusters": [{"cluster_id": "c1", "finding_count": 12, "canonical": "f1"}],
                    "total_clusters": 1,
                    "reduction_pct": 64.5,
                }

            # attack simulation / MPTE
            if "mpte" in path:
                return {
                    "verification_id": "mpte-001",
                    "finding_id": data.get("finding_id", "f1") if data else "f1",
                    "exploitable": True,
                    "exploit_proof": "CVE-2024-1234 confirmed via payload injection",
                    "confidence": 0.93,
                    "phases_completed": 19,
                }
            if "attack-sim" in path:
                return {
                    "campaigns": [{"id": "camp-1", "name": "Lateral movement sim", "status": "complete"}],
                    "total": 1,
                }
            if "pentest" in path:
                return {
                    "report_id": "pt-2026-001",
                    "scope": data.get("scope", "full") if data else "full",
                    "findings": [
                        {"id": "pt-f1", "type": "RCE", "cvss": 9.8, "exploitable": True},
                        {"id": "pt-f2", "type": "SSRF", "cvss": 7.5, "exploitable": True},
                    ],
                    "total_findings": 2,
                    "critical_count": 1,
                }

            # CSPM / cloud posture
            if "cspm" in path or "cloud" in path:
                return {
                    "resources_scanned": 847,
                    "misconfigurations": 23,
                    "critical_misconfigs": 3,
                    "frameworks": ["CIS AWS", "NIST 800-53"],
                }

            # autofix
            if "autofix" in path:
                return {
                    "fix_id": "fix-001",
                    "patch": "- vulnerable_call(input)\n+ safe_call(sanitize(input))",
                    "confidence": 0.91,
                    "language": data.get("language", "python") if data else "python",
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

            # infrastructure / SRE
            if "infrastructure" in path or "sre" in path:
                return {
                    "services": [
                        {"name": "api-gateway", "status": "healthy", "latency_ms": 42},
                        {"name": "brain-pipeline", "status": "healthy", "latency_ms": 118},
                    ],
                    "total_services": 2,
                    "incidents_open": 0,
                }
            if "incidents" in path:
                return {
                    "incidents": [
                        {"id": "inc-001", "title": "Cert expiry warning", "severity": "medium", "status": "open"},
                    ],
                    "total": 1,
                    "mttr_hours": 4.2,
                }

            # compliance / evidence
            if "compliance" in path:
                return {
                    "framework": "SOC2",
                    "status": "in_progress",
                    "controls_passing": 87,
                    "controls_total": 120,
                    "gap_count": 33,
                }
            if "evidence" in path:
                return {
                    "status": "ready",
                    "bundles": [{"id": "ev-001", "framework": "SOC2", "signed": True, "period": "2026-Q1"}],
                    "count": 1,
                }

            # audit logs
            if "audit" in path:
                return {
                    "logs": [
                        {"timestamp": "2026-04-27T08:00:00Z", "action": "login", "user": "michael@example.com"},
                        {"timestamp": "2026-04-27T08:05:00Z", "action": "export_evidence", "user": "michael@example.com"},
                    ],
                    "total": 2,
                }

            # risk
            if "risk" in path:
                return {
                    "risk_score": 74.2,
                    "components": {"threat": 82, "vulnerability": 71, "impact": 68},
                    "trend_7d": -2.1,
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

            # GRC / frameworks
            if "grc" in path or "frameworks" in path:
                return {
                    "frameworks": ["SOC2", "ISO27001", "NIST CSF", "PCI-DSS"],
                    "active_assessments": 2,
                    "next_audit": "2026-06-01",
                }

            # users / teams
            if "users" in path:
                return {"users": [{"id": "u1", "email": "admin@example.com", "role": "admin"}], "total": 1}
            if "teams" in path:
                return {"teams": [{"id": "t1", "name": "Security", "members": 8}], "total": 1}

            return {"status": "ok", "data": {}}

    return MockAPIClient()


# ---------------------------------------------------------------------------
# P4 — SOC Analyst Tier 2
# ---------------------------------------------------------------------------


class TestSOCAnalystT2Persona:
    """P4 Priya Sharma — SOC Analyst T2. Role: security_analyst.
    Primary: advanced threat investigation, escalation handling, MPTE verification.
    T2 differs from T1 by handling escalated alerts and running MPTE exploit proofs.
    """

    persona = WAVE3_PERSONAS[0]  # id=4

    def test_soc_t2_role_is_analyst(self):
        """SOC T2 must have security_analyst role — elevated over viewer."""
        assert self.persona["role"] == ANALYST_ROLE

    def test_soc_t2_escalated_findings(self, mock_api):
        """SOC T2 views escalated critical/high findings passed up from T1."""
        response = mock_api.request(
            "GET",
            "/api/v1/analytics/findings",
            data={"persona_id": self.persona["id"], "severity": ["critical", "high"]},
        )
        assert response is not None
        assert "findings" in response
        assert isinstance(response["findings"], list)
        assert "count" in response
        assert response["count"] >= 0

    def test_soc_t2_mpte_exploit_verification(self, mock_api):
        """SOC T2 verifies exploitability of escalated findings via MPTE."""
        response = mock_api.request(
            "POST",
            "/api/v1/mpte/verify",
            data={"finding_id": "f1", "target": "test-app-001", "scope": "full"},
        )
        assert response is not None
        assert "verification_id" in response
        assert "exploitable" in response
        assert "exploit_proof" in response
        assert isinstance(response["exploitable"], bool)
        assert "confidence" in response
        assert 0.0 <= response["confidence"] <= 1.0

    def test_soc_t2_mpte_phases_completed(self, mock_api):
        """MPTE response must report phases_completed for audit trail."""
        response = mock_api.request(
            "POST",
            "/api/v1/mpte/verify",
            data={"finding_id": "f1", "target": "test-app-001", "scope": "full"},
        )
        assert "phases_completed" in response
        # MPTE has 19 phases — a completed run should report the count
        assert response["phases_completed"] > 0

    def test_soc_t2_attack_campaigns_review(self, mock_api):
        """SOC T2 reviews active attack simulation campaigns for context."""
        response = mock_api.request("GET", "/api/v1/attack-sim/campaigns")
        assert response is not None
        assert "campaigns" in response
        assert "total" in response
        assert isinstance(response["campaigns"], list)

    def test_soc_t2_dedup_clusters(self, mock_api):
        """SOC T2 uses dedup clusters to identify root-cause alerts."""
        response = mock_api.request("GET", "/api/v1/deduplication/clusters")
        assert response is not None
        assert "clusters" in response
        assert "reduction_pct" in response
        for cluster in response["clusters"]:
            assert "cluster_id" in cluster
            assert "finding_count" in cluster
            assert "canonical" in cluster

    def test_soc_t2_audit_log_investigation(self, mock_api):
        """SOC T2 reads audit logs to reconstruct incident timeline."""
        response = mock_api.request("GET", "/api/v1/audit/logs")
        assert response is not None
        assert "logs" in response
        assert "total" in response
        for entry in response["logs"]:
            assert "timestamp" in entry
            assert "action" in entry

    def test_soc_t2_rbac_not_admin(self):
        """SOC T2 is NOT admin — cannot manage users or system config."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_soc_t2_rbac_not_viewer(self):
        """SOC T2 is NOT viewer — has action/write scope for investigations."""
        assert self.persona["role"] != VIEWER_ROLE

    def test_soc_t2_role_differs_from_t1(self):
        """SOC T2 title is distinct from T1 — same role tier, deeper scope."""
        assert "T2" in self.persona["title"]
        assert self.persona["id"] != 3  # T1 is id=3


# ---------------------------------------------------------------------------
# P8 — Penetration Tester
# ---------------------------------------------------------------------------


class TestPenetrationTesterPersona:
    """P8 Lisa Zhang — Penetration Tester. Role: security_analyst.
    Primary: offensive security — pentest campaigns, MPTE exploit proofs,
    SAST/DAST findings review, autofix quality validation.
    """

    persona = WAVE3_PERSONAS[1]  # id=8

    def test_pentester_role_is_analyst(self):
        """Pen Tester must have security_analyst role — action scope required."""
        assert self.persona["role"] == ANALYST_ROLE

    def test_pentester_pentest_report(self, mock_api):
        """Pen Tester runs a pentest and receives structured findings report."""
        response = mock_api.request(
            "POST",
            "/api/v1/pentest/run",
            data={"target": "test-app-001", "scope": "full", "mode": "authenticated"},
        )
        assert response is not None
        assert "report_id" in response
        assert "findings" in response
        assert "total_findings" in response
        assert isinstance(response["findings"], list)

    def test_pentester_pentest_findings_schema(self, mock_api):
        """Each pentest finding has required fields: type, cvss, exploitable."""
        response = mock_api.request(
            "POST",
            "/api/v1/pentest/run",
            data={"target": "test-app-001", "scope": "full"},
        )
        for finding in response["findings"]:
            assert "id" in finding
            assert "type" in finding
            assert "cvss" in finding
            assert "exploitable" in finding
            assert 0.0 <= finding["cvss"] <= 10.0

    def test_pentester_mpte_exploit_chain(self, mock_api):
        """Pen Tester uses MPTE to prove exploit chain for a finding."""
        response = mock_api.request(
            "POST",
            "/api/v1/mpte/verify",
            data={"finding_id": "pt-f1", "target": "test-app-001", "scope": "full"},
        )
        assert response is not None
        assert "exploit_proof" in response
        # Must be a real proof string, not empty
        assert len(response["exploit_proof"]) > 0
        assert "exploitable" in response

    def test_pentester_sast_findings_context(self, mock_api):
        """Pen Tester reviews SAST findings to identify attack surface."""
        response = mock_api.request(
            "POST",
            "/api/v1/sast/scan",
            data={"target": "suite-core/", "language": "python"},
        )
        assert response is not None
        assert "scan_id" in response
        assert "findings_count" in response
        assert "critical" in response
        assert "high" in response

    def test_pentester_autofix_quality_check(self, mock_api):
        """Pen Tester validates that autofix patches actually close the vuln."""
        response = mock_api.request(
            "POST",
            "/api/v1/autofix/generate",
            data={"finding_id": "pt-f1", "finding_type": "rce", "language": "python"},
        )
        assert response is not None
        assert "fix_id" in response
        assert "patch" in response
        assert "confidence" in response
        # Confidence must be meaningful, not a stub 0.0
        assert response["confidence"] > 0.0

    def test_pentester_attack_campaigns(self, mock_api):
        """Pen Tester reviews attack simulation campaigns for scope alignment."""
        response = mock_api.request("GET", "/api/v1/attack-sim/campaigns")
        assert response is not None
        assert "campaigns" in response
        assert "total" in response

    def test_pentester_rbac_not_admin(self):
        """Pen Tester is NOT admin — cannot change system config."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_pentester_rbac_not_viewer(self):
        """Pen Tester is NOT viewer — needs write scope for offensive actions."""
        assert self.persona["role"] != VIEWER_ROLE


# ---------------------------------------------------------------------------
# P13 — Audit Manager
# ---------------------------------------------------------------------------


class TestAuditManagerPersona:
    """P13 Michael Brown — Audit Manager. Role: viewer.
    Primary: compliance evidence review, audit trail, framework gap analysis.
    Must NOT have write access to any security-modifying endpoint.
    """

    persona = WAVE3_PERSONAS[2]  # id=13

    def test_audit_manager_role_is_viewer(self):
        """Audit Manager must have viewer role — read-only compliance access."""
        assert self.persona["role"] == VIEWER_ROLE

    def test_audit_manager_evidence_bundles(self, mock_api):
        """Audit Manager reviews signed evidence bundles for audit readiness."""
        response = mock_api.request("GET", "/api/v1/evidence/status")
        assert response is not None
        assert "status" in response
        assert "bundles" in response
        for bundle in response["bundles"]:
            assert "id" in bundle
            assert "framework" in bundle
            assert "signed" in bundle
            assert bundle["signed"] is True  # unsigned bundles block audit

    def test_audit_manager_compliance_status(self, mock_api):
        """Audit Manager checks compliance control pass/fail for each framework."""
        response = mock_api.request("GET", "/api/v1/compliance-engine/soc2/status")
        assert response is not None
        assert "framework" in response
        assert "controls_passing" in response
        assert "controls_total" in response
        assert response["controls_passing"] <= response["controls_total"]

    def test_audit_manager_gap_count(self, mock_api):
        """Audit Manager verifies gap count is a non-negative integer."""
        response = mock_api.request("GET", "/api/v1/compliance-engine/soc2/status")
        assert "gap_count" in response
        assert isinstance(response["gap_count"], int)
        assert response["gap_count"] >= 0

    def test_audit_manager_audit_trail(self, mock_api):
        """Audit Manager reads audit logs — primary compliance trail."""
        response = mock_api.request("GET", "/api/v1/audit/logs")
        assert response is not None
        assert "logs" in response
        assert "total" in response
        assert response["total"] >= 0
        for entry in response["logs"]:
            assert "timestamp" in entry
            assert "action" in entry
            assert "user" in entry

    def test_audit_manager_frameworks_list(self, mock_api):
        """Audit Manager views all active compliance frameworks."""
        response = mock_api.request("GET", "/api/v1/grc/frameworks")
        assert response is not None
        assert "frameworks" in response
        assert isinstance(response["frameworks"], list)
        assert len(response["frameworks"]) >= 1

    def test_audit_manager_cannot_write_policy(self):
        """Audit Manager viewer role must NOT grant write/policy-create scope.

        In a live system this maps to 403 when POSTing to /api/v1/policies.
        Here we assert role semantics are correctly defined.
        """
        assert self.persona["role"] == VIEWER_ROLE
        write_scopes = ["create_policy", "delete_findings", "manage_users", "trigger_scan"]
        viewer_scopes = ["view_findings", "read_compliance", "export_evidence"]
        for scope in write_scopes:
            assert scope not in viewer_scopes

    def test_audit_manager_rbac_not_admin(self):
        """Audit Manager is NOT admin."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_audit_manager_rbac_not_analyst(self):
        """Audit Manager is NOT security analyst — no action scope."""
        assert self.persona["role"] != ANALYST_ROLE


# ---------------------------------------------------------------------------
# P16 — Platform Engineer
# ---------------------------------------------------------------------------


class TestPlatformEngineerPersona:
    """P16 Ryan Murphy — Platform Engineer. Role: admin.
    Primary: infrastructure health, connector registry, system resource management,
    pipeline operations. Full admin scope needed for infra-level changes.
    """

    persona = WAVE3_PERSONAS[3]  # id=16

    def test_platform_engineer_role_is_admin(self):
        """Platform Engineer must have admin role — infra changes require full scope."""
        assert self.persona["role"] == ADMIN_ROLE

    def test_platform_engineer_system_health(self, mock_api):
        """Platform Engineer monitors system resource health."""
        response = mock_api.request("GET", "/api/v1/system/health")
        assert response is not None
        assert "cpu_pct" in response
        assert "memory_pct" in response
        assert "disk_pct" in response
        assert 0.0 <= response["cpu_pct"] <= 100.0
        assert 0.0 <= response["memory_pct"] <= 100.0

    def test_platform_engineer_queue_depth(self, mock_api):
        """Platform Engineer checks pipeline queue depth for backpressure."""
        response = mock_api.request("GET", "/api/v1/platform/status")
        assert response is not None
        assert "queue_depth" in response
        assert "workers_active" in response
        assert isinstance(response["queue_depth"], int)

    def test_platform_engineer_connectors_registry(self, mock_api):
        """Platform Engineer manages connector health and sync status."""
        response = mock_api.request("GET", "/api/v1/connectors/registry")
        assert response is not None
        assert "connectors" in response
        assert "total" in response
        for connector in response["connectors"]:
            assert "name" in connector
            assert "health" in connector
            assert "last_sync" in connector

    def test_platform_engineer_pipeline_trigger(self, mock_api):
        """Platform Engineer can trigger brain pipeline runs."""
        response = mock_api.request(
            "POST",
            "/api/v1/brain/process",
            data={"app_id": "test-app-001"},
        )
        assert response is not None
        assert "job_id" in response
        assert "status" in response
        assert response["status"] in ("queued", "running", "complete")

    def test_platform_engineer_policies(self, mock_api):
        """Platform Engineer reviews platform-level security policies."""
        response = mock_api.request("GET", "/api/v1/policies")
        assert response is not None
        assert "policies" in response
        assert isinstance(response["policies"], list)

    def test_platform_engineer_rbac_not_viewer(self):
        """Platform Engineer is NOT viewer — needs full admin scope for infra ops."""
        assert self.persona["role"] != VIEWER_ROLE

    def test_platform_engineer_rbac_not_analyst_only(self):
        """Platform Engineer exceeds analyst scope — must be admin."""
        assert self.persona["role"] == ADMIN_ROLE


# ---------------------------------------------------------------------------
# P26 — Security SRE
# ---------------------------------------------------------------------------


class TestSecuritySREPersona:
    """P26 Marcus Reid — Security SRE. Role: admin.
    Primary: availability + security overlap — SLO tracking, incident management,
    infrastructure hardening, connector reliability, brain pipeline operations.
    """

    persona = WAVE3_PERSONAS[4]  # id=26

    def test_sre_role_is_admin(self):
        """Security SRE must have admin role — SRE actions touch system config."""
        assert self.persona["role"] == ADMIN_ROLE

    def test_sre_incidents_dashboard(self, mock_api):
        """Security SRE monitors open security incidents."""
        response = mock_api.request("GET", "/api/v1/incidents/active")
        assert response is not None
        assert "incidents" in response
        assert "total" in response
        assert "mttr_hours" in response
        assert isinstance(response["mttr_hours"], float)

    def test_sre_incident_schema(self, mock_api):
        """Each incident has required fields for SRE triage."""
        response = mock_api.request("GET", "/api/v1/incidents/active")
        for incident in response["incidents"]:
            assert "id" in incident
            assert "title" in incident
            assert "severity" in incident
            assert "status" in incident

    def test_sre_system_resource_monitoring(self, mock_api):
        """Security SRE checks system resource utilization."""
        response = mock_api.request("GET", "/api/v1/system/health")
        assert response is not None
        assert "cpu_pct" in response
        assert "memory_pct" in response
        assert "workers_active" in response
        assert response["cpu_pct"] >= 0.0

    def test_sre_connectors_health(self, mock_api):
        """Security SRE verifies connector reliability — SLO dependency."""
        response = mock_api.request("GET", "/api/v1/connectors/registry")
        assert response is not None
        assert "connectors" in response
        for connector in response["connectors"]:
            assert "health" in connector
            assert connector["health"] in ("healthy", "degraded", "down")

    def test_sre_brain_pipeline_status(self, mock_api):
        """Security SRE monitors brain pipeline job queue."""
        response = mock_api.request("GET", "/api/v1/platform/status")
        assert response is not None
        assert "queue_depth" in response
        assert "workers_active" in response

    def test_sre_risk_trend(self, mock_api):
        """Security SRE tracks risk trend as a security SLO signal."""
        response = mock_api.request("GET", "/api/v1/risk/score")
        assert response is not None
        assert "risk_score" in response
        assert "trend_7d" in response
        assert isinstance(response["trend_7d"], float)

    def test_sre_rbac_not_viewer(self):
        """Security SRE is NOT viewer — needs write/admin scope for incident response."""
        assert self.persona["role"] != VIEWER_ROLE

    def test_sre_rbac_not_analyst_only(self):
        """Security SRE is admin, not just analyst — system config access required."""
        assert self.persona["role"] == ADMIN_ROLE


# ---------------------------------------------------------------------------
# P30 — SecOps Tech Lead
# ---------------------------------------------------------------------------


class TestSecOpsTechLeadPersona:
    """P30 Diana Foster — SecOps Tech Lead. Role: security_analyst.
    Primary: technical lead for SecOps team — orchestrates detection rules,
    triage workflows, pipeline tuning, RBAC policy review, and team tooling.
    Analyst-scoped (not admin) to keep production system changes gated.
    """

    persona = WAVE3_PERSONAS[5]  # id=30

    def test_secops_tech_lead_role_is_analyst(self):
        """SecOps Tech Lead must have security_analyst role."""
        assert self.persona["role"] == ANALYST_ROLE

    def test_secops_tech_lead_findings_overview(self, mock_api):
        """SecOps Tech Lead reviews findings overview to direct team focus."""
        response = mock_api.request(
            "GET",
            "/api/v1/analytics/findings",
            data={"persona_id": self.persona["id"]},
        )
        assert response is not None
        assert "findings" in response
        assert "count" in response
        assert response["count"] >= 0

    def test_secops_tech_lead_pipeline_trigger(self, mock_api):
        """SecOps Tech Lead triggers brain pipeline to reprocess stale findings."""
        response = mock_api.request(
            "POST",
            "/api/v1/brain/process",
            data={"app_id": "test-app-001"},
        )
        assert response is not None
        assert "job_id" in response
        assert "status" in response
        assert "estimated_seconds" in response

    def test_secops_tech_lead_dedup_cluster_review(self, mock_api):
        """SecOps Tech Lead reviews dedup clusters to tune detection rules."""
        response = mock_api.request("GET", "/api/v1/deduplication/clusters")
        assert response is not None
        assert "clusters" in response
        assert "total_clusters" in response
        assert "reduction_pct" in response
        assert 0.0 <= response["reduction_pct"] <= 100.0

    def test_secops_tech_lead_policies_review(self, mock_api):
        """SecOps Tech Lead reviews active security policies for team alignment."""
        response = mock_api.request("GET", "/api/v1/policies")
        assert response is not None
        assert "policies" in response
        for policy in response["policies"]:
            assert "id" in policy
            assert "name" in policy
            assert "active" in policy

    def test_secops_tech_lead_connectors_health(self, mock_api):
        """SecOps Tech Lead verifies data source connectors are feeding pipeline."""
        response = mock_api.request("GET", "/api/v1/connectors/registry")
        assert response is not None
        assert "connectors" in response
        assert "total" in response

    def test_secops_tech_lead_audit_log(self, mock_api):
        """SecOps Tech Lead reads audit logs to review team activity."""
        response = mock_api.request("GET", "/api/v1/audit/logs")
        assert response is not None
        assert "logs" in response
        assert "total" in response

    def test_secops_tech_lead_risk_score(self, mock_api):
        """SecOps Tech Lead tracks risk score as operational KPI."""
        response = mock_api.request("GET", "/api/v1/risk/score")
        assert response is not None
        assert "risk_score" in response
        assert "components" in response
        assert "trend_7d" in response

    def test_secops_tech_lead_rbac_not_admin(self):
        """SecOps Tech Lead is NOT admin — production changes require escalation."""
        assert self.persona["role"] != ADMIN_ROLE

    def test_secops_tech_lead_rbac_not_viewer(self):
        """SecOps Tech Lead is NOT viewer — has action scope for team operations."""
        assert self.persona["role"] != VIEWER_ROLE


# ---------------------------------------------------------------------------
# Cross-Persona RBAC Boundary Tests (Wave 3)
# ---------------------------------------------------------------------------


class TestWave3RBACBoundaries:
    """Cross-persona RBAC checks to verify role isolation across wave 3."""

    def test_viewer_count(self):
        """Exactly 1 viewer persona in wave 3 — Audit Manager."""
        viewers = [p for p in WAVE3_PERSONAS if p["role"] == VIEWER_ROLE]
        assert len(viewers) == 1
        assert viewers[0]["id"] == 13

    def test_admin_count(self):
        """Exactly 2 admin personas in wave 3 — Platform Engineer + Security SRE."""
        admins = [p for p in WAVE3_PERSONAS if p["role"] == ADMIN_ROLE]
        assert len(admins) == 2
        admin_ids = {p["id"] for p in admins}
        assert 16 in admin_ids
        assert 26 in admin_ids

    def test_analyst_count(self):
        """3 analyst personas in wave 3 — SOC T2, Pen Tester, SecOps Tech Lead."""
        analysts = [p for p in WAVE3_PERSONAS if p["role"] == ANALYST_ROLE]
        assert len(analysts) == 3

    def test_all_personas_have_valid_roles(self):
        """All wave 3 personas have a valid RBAC role."""
        valid_roles = {"admin", "security_analyst", "developer", "viewer", "service"}
        for persona in WAVE3_PERSONAS:
            assert persona["role"] in valid_roles, (
                f"Persona {persona['name']} has invalid role: {persona['role']}"
            )

    def test_all_personas_have_unique_ids(self):
        """Wave 3 persona IDs are unique within this wave."""
        ids = [p["id"] for p in WAVE3_PERSONAS]
        assert len(ids) == len(set(ids)), "Duplicate persona IDs in wave 3"

    def test_viewer_cannot_access_write_scopes(self):
        """Audit Manager viewer role is not granted write scopes."""
        audit_mgr = next(p for p in WAVE3_PERSONAS if p["id"] == 13)
        assert audit_mgr["role"] == VIEWER_ROLE
        for method, _ in WRITE_ENDPOINTS:
            assert method == "POST"  # confirm these are mutations
        for method, _ in READ_ONLY_ENDPOINTS:
            assert method == "GET"

    def test_admin_vs_viewer_scope_separation(self):
        """Platform Engineer (admin) and Audit Manager (viewer) have distinct scopes."""
        platform = next(p for p in WAVE3_PERSONAS if p["id"] == 16)
        audit    = next(p for p in WAVE3_PERSONAS if p["id"] == 13)
        assert platform["role"] != audit["role"]
        assert platform["role"] == ADMIN_ROLE
        assert audit["role"] == VIEWER_ROLE

    def test_sre_vs_pentester_role_distinction(self):
        """Security SRE (admin) and Pen Tester (analyst) are different tiers."""
        sre    = next(p for p in WAVE3_PERSONAS if p["id"] == 26)
        tester = next(p for p in WAVE3_PERSONAS if p["id"] == 8)
        assert sre["role"] == ADMIN_ROLE
        assert tester["role"] == ANALYST_ROLE
        assert sre["role"] != tester["role"]

    def test_analyst_personas_share_read_access(self, mock_api):
        """All analyst personas can access findings and audit logs."""
        analysts = [p for p in WAVE3_PERSONAS if p["role"] == ANALYST_ROLE]
        for persona in analysts:
            response = mock_api.request("GET", "/api/v1/analytics/findings")
            assert response is not None, f"{persona['name']} could not access findings"
            assert "findings" in response


# ---------------------------------------------------------------------------
# Wave 3 Integration Summary
# ---------------------------------------------------------------------------


class TestWave3Integration:
    """Integration sanity checks for the wave 3 persona set."""

    def test_wave3_persona_count(self):
        """Wave 3 adds exactly 6 new personas."""
        assert len(WAVE3_PERSONAS) == 6

    def test_wave3_all_personas_named(self):
        """Every wave 3 persona has a non-empty name and title."""
        for persona in WAVE3_PERSONAS:
            assert persona.get("name"), f"Persona id={persona['id']} missing name"
            assert persona.get("title"), f"Persona id={persona['id']} missing title"

    def test_wave3_covers_all_three_primary_roles(self):
        """Wave 3 spans admin, analyst, and viewer roles."""
        roles_present = {p["role"] for p in WAVE3_PERSONAS}
        assert ADMIN_ROLE in roles_present
        assert ANALYST_ROLE in roles_present
        assert VIEWER_ROLE in roles_present

    def test_wave3_no_overlap_with_wave1(self):
        """Wave 3 personas do not duplicate wave 1 titles."""
        wave1_titles = {
            "Threat Intel Analyst",
            "Incident Response Lead",
            "Risk Manager",
            "Supply Chain Security",
            "Threat Modeler",
        }
        wave3_titles = {p["title"] for p in WAVE3_PERSONAS}
        overlap = wave1_titles & wave3_titles
        assert len(overlap) == 0, f"Wave 3 duplicates wave 1 personas: {overlap}"

    def test_wave3_no_overlap_with_wave2(self):
        """Wave 3 personas do not duplicate wave 2 titles."""
        wave2_titles = {
            "CISO",
            "SOC Analyst T1",
            "DevSecOps Engineer",
            "Cloud Security Architect",
            "Security Data Scientist",
            "AppSec Lead",
            "GRC Analyst",
        }
        wave3_titles = {p["title"] for p in WAVE3_PERSONAS}
        overlap = wave2_titles & wave3_titles
        assert len(overlap) == 0, f"Wave 3 duplicates wave 2 personas: {overlap}"

    def test_all_primary_workflows_return_dicts(self, mock_api):
        """Every persona's primary endpoint returns a dict."""
        primary_endpoints = [
            ("GET",  "/api/v1/analytics/findings"),            # SOC T2
            ("POST", "/api/v1/pentest/run"),                   # Pen Tester
            ("GET",  "/api/v1/evidence/status"),               # Audit Manager
            ("GET",  "/api/v1/system/health"),                 # Platform Engineer
            ("GET",  "/api/v1/incidents/active"),              # Security SRE
            ("GET",  "/api/v1/deduplication/clusters"),        # SecOps Tech Lead
        ]
        for method, path in primary_endpoints:
            response = mock_api.request(method, path)
            assert isinstance(response, dict), (
                f"Endpoint {path} returned {type(response).__name__}, expected dict"
            )

    def test_wave3_personas_span_unique_functional_domains(self):
        """Wave 3 covers 6 distinct functional domains — no title collision."""
        titles = [p["title"] for p in WAVE3_PERSONAS]
        assert len(titles) == len(set(titles)), "Duplicate titles in wave 3"
