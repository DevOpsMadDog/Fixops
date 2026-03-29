"""
Phase 6 — Comply & Evidence
Owner: GRC + Compliance Manager

Validates:
- Compliance framework assessment (SOC2, PCI-DSS, HIPAA)
- Evidence bundle generation
- Audit trail integrity
- Signed evidence chain verification
"""
import pytest


class TestComplianceFrameworks:
    """Compliance Officer: Verify framework assessments."""

    def test_list_frameworks(self, api):
        r = api.get("/api/v1/compliance-engine/frameworks")
        assert r.status_code == 200

    def test_soc2_status(self, api):
        r = api.get("/api/v1/compliance-engine/soc2/status")
        assert r.status_code == 200

    def test_pci_dss_status(self, api):
        r = api.get("/api/v1/compliance-engine/pci-dss/status")
        assert r.status_code == 200

    def test_hipaa_status(self, api):
        r = api.get("/api/v1/compliance-engine/hipaa/status")
        assert r.status_code == 200

    def test_assess_soc2(self, api):
        r = api.post("/api/v1/compliance-engine/assess", json={"framework": "SOC2"})
        assert r.status_code == 200

    def test_compliance_gaps(self, api):
        r = api.get("/api/v1/compliance-engine/gaps")
        assert r.status_code == 200


class TestEvidencePipeline:
    """GRC Analyst: Verify evidence bundle generation."""

    def test_evidence_status(self, api):
        r = api.get("/api/v1/evidence/status")
        assert r.status_code == 200

    def test_risk_status(self, api):
        r = api.get("/api/v1/risk/status")
        assert r.status_code == 200


class TestAuditTrail:
    """Audit Manager: Verify immutable audit logging."""

    def test_audit_logs(self, api):
        r = api.get("/api/v1/audit/logs")
        assert r.status_code == 200

    def test_audit_frameworks(self, api):
        r = api.get("/api/v1/audit/compliance/frameworks")
        assert r.status_code == 200

    def test_decision_trail(self, api):
        r = api.get("/api/v1/audit/decision-trail")
        assert r.status_code == 200

    def test_policy_changes(self, api):
        r = api.get("/api/v1/audit/policy-changes")
        assert r.status_code == 200

    def test_user_activity(self, api):
        r = api.get("/api/v1/audit/user-activity")
        assert r.status_code == 200

    def test_compliance_controls(self, api):
        r = api.get("/api/v1/audit/compliance/controls")
        assert r.status_code == 200


class TestEvidenceChain:
    """External Auditor: Verify cryptographic evidence chain."""

    def test_chain_verify(self, api):
        r = api.get("/api/v1/audit/chain/verify")
        assert r.status_code == 200

    def test_retention_policy(self, api):
        r = api.get("/api/v1/audit/retention")
        assert r.status_code == 200

