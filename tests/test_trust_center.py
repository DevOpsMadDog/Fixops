"""
Tests for Trust Center module (suite-core/core/trust_center.py)
and Trust Center API router (suite-api/apps/api/trust_center_router.py).

Covers:
- TrustCenterManager CRUD for config, badges, controls, subprocessors
- get_public_page aggregation
- generate_security_report
- get_trust_stats + trust score
- Multi-tenant isolation
- FastAPI endpoints (public + admin)
- 404 error paths
- Delete operations
- Singleton pattern
"""
from __future__ import annotations

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from fastapi import FastAPI

from core.trust_center import (
    ComplianceBadge,
    SecurityControl,
    SubprocessorEntry,
    TrustCenterData,
    TrustCenterManager,
    TrustPageConfig,
    _compute_trust_score,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mgr():
    """Fresh in-memory TrustCenterManager for each test."""
    return TrustCenterManager(db_path=":memory:")


@pytest.fixture
def configured_mgr(mgr):
    """Manager with org 'acme' pre-configured."""
    mgr.configure(
        TrustPageConfig(
            org_id="acme",
            org_name="Acme Corp",
            contact_email="security@acme.com",
            brand_color="#FF6600",
        )
    )
    return mgr


@pytest.fixture
def app(configured_mgr):
    """FastAPI test app with trust_center_router mounted, auth bypassed."""
    from apps.api import trust_center_router as tcr

    # Patch the module-level manager and auth
    app = FastAPI()

    # Override dependency to return our test manager
    from apps.api.trust_center_router import router, _get_manager
    from apps.api.auth_deps import api_key_auth

    app.include_router(router)
    app.dependency_overrides[_get_manager] = lambda: configured_mgr
    app.dependency_overrides[api_key_auth] = lambda: None  # bypass auth
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def sample_badge():
    return ComplianceBadge(
        framework="SOC2",
        status="certified",
        certified_date="2024-01-15",
        auditor="Big Four Auditors",
        report_url="https://reports.example.com/soc2.pdf",
    )


@pytest.fixture
def sample_control():
    return SecurityControl(
        category="Access Control",
        title="Multi-Factor Authentication",
        description="MFA is required for all privileged accounts.",
        status="implemented",
    )


@pytest.fixture
def sample_subprocessor():
    return SubprocessorEntry(
        name="AWS",
        purpose="Cloud infrastructure",
        location="United States",
        data_types=["infrastructure", "logs"],
    )


# ============================================================================
# TrustCenterManager — Config
# ============================================================================


def test_configure_creates_config(mgr):
    config = TrustPageConfig(org_id="org1", org_name="Org One")
    result = mgr.configure(config)
    assert result.org_id == "org1"
    assert result.org_name == "Org One"


def test_get_config_returns_none_for_unknown_org(mgr):
    assert mgr.get_config("nonexistent") is None


def test_get_config_returns_configured(mgr):
    mgr.configure(TrustPageConfig(org_id="x", org_name="X Corp", brand_color="#123456"))
    cfg = mgr.get_config("x")
    assert cfg is not None
    assert cfg.org_name == "X Corp"
    assert cfg.brand_color == "#123456"


def test_configure_upserts(mgr):
    mgr.configure(TrustPageConfig(org_id="org1", org_name="Old Name"))
    mgr.configure(TrustPageConfig(org_id="org1", org_name="New Name"))
    cfg = mgr.get_config("org1")
    assert cfg.org_name == "New Name"


def test_config_enabled_sections_roundtrip(mgr):
    mgr.configure(
        TrustPageConfig(
            org_id="o1",
            org_name="O1",
            enabled_sections=["compliance", "subprocessors"],
        )
    )
    cfg = mgr.get_config("o1")
    assert cfg.enabled_sections == ["compliance", "subprocessors"]


def test_config_contact_email(mgr):
    mgr.configure(
        TrustPageConfig(org_id="o2", org_name="O2", contact_email="cto@o2.com")
    )
    cfg = mgr.get_config("o2")
    assert cfg.contact_email == "cto@o2.com"


# ============================================================================
# TrustCenterManager — Badges
# ============================================================================


def test_add_badge(configured_mgr, sample_badge):
    b = configured_mgr.add_badge(sample_badge, "acme")
    assert b.org_id == "acme"
    assert b.framework == "SOC2"
    assert b.status == "certified"


def test_list_badges_empty(configured_mgr):
    assert configured_mgr.list_badges("acme") == []


def test_list_badges_returns_added(configured_mgr, sample_badge):
    configured_mgr.add_badge(sample_badge, "acme")
    badges = configured_mgr.list_badges("acme")
    assert len(badges) == 1
    assert badges[0].framework == "SOC2"


def test_list_badges_multiple(configured_mgr):
    configured_mgr.add_badge(ComplianceBadge(framework="SOC2", status="certified"), "acme")
    configured_mgr.add_badge(ComplianceBadge(framework="ISO27001", status="in_progress"), "acme")
    badges = configured_mgr.list_badges("acme")
    assert len(badges) == 2
    frameworks = {b.framework for b in badges}
    assert frameworks == {"SOC2", "ISO27001"}


def test_delete_badge(configured_mgr, sample_badge):
    b = configured_mgr.add_badge(sample_badge, "acme")
    deleted = configured_mgr.delete_badge(b.id, "acme")
    assert deleted is True
    assert configured_mgr.list_badges("acme") == []


def test_delete_badge_nonexistent(configured_mgr):
    deleted = configured_mgr.delete_badge("fake-id", "acme")
    assert deleted is False


def test_badge_upsert_on_same_id(configured_mgr, sample_badge):
    b = configured_mgr.add_badge(sample_badge, "acme")
    updated = b.model_copy(update={"status": "in_progress"})
    configured_mgr.add_badge(updated, "acme")
    badges = configured_mgr.list_badges("acme")
    assert len(badges) == 1
    assert badges[0].status == "in_progress"


# ============================================================================
# TrustCenterManager — Controls
# ============================================================================


def test_add_control(configured_mgr, sample_control):
    c = configured_mgr.add_control(sample_control, "acme")
    assert c.org_id == "acme"
    assert c.title == "Multi-Factor Authentication"


def test_list_controls_empty(configured_mgr):
    assert configured_mgr.list_controls("acme") == []


def test_list_controls_multiple(configured_mgr):
    configured_mgr.add_control(
        SecurityControl(category="A", title="T1", description="D1", status="implemented"), "acme"
    )
    configured_mgr.add_control(
        SecurityControl(category="B", title="T2", description="D2", status="planned"), "acme"
    )
    controls = configured_mgr.list_controls("acme")
    assert len(controls) == 2


def test_delete_control(configured_mgr, sample_control):
    c = configured_mgr.add_control(sample_control, "acme")
    deleted = configured_mgr.delete_control(c.id, "acme")
    assert deleted is True
    assert configured_mgr.list_controls("acme") == []


def test_delete_control_nonexistent(configured_mgr):
    assert configured_mgr.delete_control("nope", "acme") is False


# ============================================================================
# TrustCenterManager — Subprocessors
# ============================================================================


def test_add_subprocessor(configured_mgr, sample_subprocessor):
    s = configured_mgr.add_subprocessor(sample_subprocessor, "acme")
    assert s.org_id == "acme"
    assert s.name == "AWS"
    assert s.data_types == ["infrastructure", "logs"]


def test_list_subprocessors_empty(configured_mgr):
    assert configured_mgr.list_subprocessors("acme") == []


def test_list_subprocessors_data_types_roundtrip(configured_mgr):
    entry = SubprocessorEntry(
        name="Stripe",
        purpose="Payments",
        location="United States",
        data_types=["payment_info", "email"],
    )
    configured_mgr.add_subprocessor(entry, "acme")
    subs = configured_mgr.list_subprocessors("acme")
    assert subs[0].data_types == ["payment_info", "email"]


def test_delete_subprocessor(configured_mgr, sample_subprocessor):
    s = configured_mgr.add_subprocessor(sample_subprocessor, "acme")
    deleted = configured_mgr.delete_subprocessor(s.id, "acme")
    assert deleted is True
    assert configured_mgr.list_subprocessors("acme") == []


def test_delete_subprocessor_nonexistent(configured_mgr):
    assert configured_mgr.delete_subprocessor("fake", "acme") is False


# ============================================================================
# Multi-tenant isolation
# ============================================================================


def test_multi_tenant_badges_isolated(mgr):
    mgr.configure(TrustPageConfig(org_id="org_a", org_name="Org A"))
    mgr.configure(TrustPageConfig(org_id="org_b", org_name="Org B"))
    mgr.add_badge(ComplianceBadge(framework="SOC2", status="certified"), "org_a")
    mgr.add_badge(ComplianceBadge(framework="GDPR", status="planned"), "org_b")
    assert len(mgr.list_badges("org_a")) == 1
    assert mgr.list_badges("org_a")[0].framework == "SOC2"
    assert len(mgr.list_badges("org_b")) == 1
    assert mgr.list_badges("org_b")[0].framework == "GDPR"


def test_multi_tenant_controls_isolated(mgr):
    mgr.configure(TrustPageConfig(org_id="org_a", org_name="A"))
    mgr.configure(TrustPageConfig(org_id="org_b", org_name="B"))
    mgr.add_control(
        SecurityControl(category="X", title="T1", description="D", status="implemented"), "org_a"
    )
    assert mgr.list_controls("org_b") == []


# ============================================================================
# Public page aggregation
# ============================================================================


def test_get_public_page_none_for_unknown_org(mgr):
    assert mgr.get_public_page("ghost") is None


def test_get_public_page_returns_data(configured_mgr, sample_badge, sample_control, sample_subprocessor):
    configured_mgr.add_badge(sample_badge, "acme")
    configured_mgr.add_control(sample_control, "acme")
    configured_mgr.add_subprocessor(sample_subprocessor, "acme")

    page = configured_mgr.get_public_page("acme")
    assert page is not None
    assert isinstance(page, TrustCenterData)
    assert page.config.org_name == "Acme Corp"
    assert len(page.badges) == 1
    assert len(page.controls) == 1
    assert len(page.subprocessors) == 1
    assert page.last_updated is not None


# ============================================================================
# Security report
# ============================================================================


def test_generate_security_report_structure(configured_mgr, sample_badge, sample_control):
    configured_mgr.add_badge(sample_badge, "acme")
    configured_mgr.add_control(sample_control, "acme")

    report = configured_mgr.generate_security_report("acme")
    assert report["org_id"] == "acme"
    assert report["organization"] == "Acme Corp"
    assert "compliance_summary" in report
    assert "security_controls" in report
    assert "subprocessors" in report
    assert report["compliance_summary"]["certified"] == 1
    assert report["security_controls"]["implemented"] == 1
    assert report["security_controls"]["implementation_rate"] == 100.0


def test_generate_security_report_empty(configured_mgr):
    report = configured_mgr.generate_security_report("acme")
    assert report["compliance_summary"]["total_frameworks"] == 0
    assert report["security_controls"]["total"] == 0
    assert report["security_controls"]["implementation_rate"] == 0.0


# ============================================================================
# Trust stats and score
# ============================================================================


def test_get_trust_stats(configured_mgr, sample_badge, sample_control):
    configured_mgr.add_badge(sample_badge, "acme")
    configured_mgr.add_control(sample_control, "acme")

    stats = configured_mgr.get_trust_stats("acme")
    assert stats["org_id"] == "acme"
    assert stats["badges"]["total"] == 1
    assert stats["badges"]["certified"] == 1
    assert stats["controls"]["total"] == 1
    assert stats["controls"]["implemented"] == 1
    assert stats["controls"]["implementation_rate"] == 100.0
    assert "trust_score" in stats


def test_compute_trust_score_all_certified_implemented():
    badges = [ComplianceBadge(framework="SOC2", status="certified", org_id="x")]
    controls = [
        SecurityControl(category="A", title="T", description="D", status="implemented", org_id="x")
    ]
    score = _compute_trust_score(badges, controls)
    assert score == 100.0


def test_compute_trust_score_no_data():
    assert _compute_trust_score([], []) == 0.0


def test_compute_trust_score_partial():
    badges = [
        ComplianceBadge(framework="SOC2", status="certified", org_id="x"),
        ComplianceBadge(framework="ISO27001", status="planned", org_id="x"),
    ]
    controls = [
        SecurityControl(category="A", title="T1", description="D", status="implemented", org_id="x"),
        SecurityControl(category="A", title="T2", description="D", status="planned", org_id="x"),
    ]
    score = _compute_trust_score(badges, controls)
    # 50% cert * 50 + 50% controls * 50 = 25 + 25 = 50.0
    assert score == 50.0


# ============================================================================
# Singleton pattern
# ============================================================================


def test_singleton_pattern():
    TrustCenterManager.reset_instance()
    mgr1 = TrustCenterManager.get_instance()
    mgr2 = TrustCenterManager.get_instance()
    assert mgr1 is mgr2
    TrustCenterManager.reset_instance()


# ============================================================================
# File-backed persistence
# ============================================================================


def test_file_backed_persistence(tmp_path):
    db_file = tmp_path / "trust.db"
    mgr1 = TrustCenterManager(db_path=db_file)
    mgr1.configure(TrustPageConfig(org_id="persist_org", org_name="Persist Corp"))
    mgr1.add_badge(ComplianceBadge(framework="HIPAA", status="in_progress"), "persist_org")

    mgr2 = TrustCenterManager(db_path=db_file)
    cfg = mgr2.get_config("persist_org")
    assert cfg is not None
    assert cfg.org_name == "Persist Corp"
    badges = mgr2.list_badges("persist_org")
    assert len(badges) == 1
    assert badges[0].framework == "HIPAA"


# ============================================================================
# FastAPI endpoints
# ============================================================================


def test_public_page_endpoint(client, configured_mgr, sample_badge):
    configured_mgr.add_badge(sample_badge, "acme")
    resp = client.get("/api/v1/trust/acme/public")
    assert resp.status_code == 200
    data = resp.json()
    assert data["config"]["org_name"] == "Acme Corp"
    assert len(data["badges"]) == 1


def test_public_page_404(client):
    resp = client.get("/api/v1/trust/nonexistent_org/public")
    assert resp.status_code == 404


def test_report_endpoint(client):
    resp = client.get("/api/v1/trust/acme/report")
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == "acme"
    assert "compliance_summary" in data


def test_report_404(client):
    resp = client.get("/api/v1/trust/ghost_org/report")
    assert resp.status_code == 404


def test_configure_endpoint(client):
    resp = client.post(
        "/api/v1/trust/configure",
        params={"org_id": "new_org"},
        json={"org_name": "New Org", "contact_email": "hi@new.org"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == "new_org"
    assert data["org_name"] == "New Org"


def test_get_config_endpoint(client):
    resp = client.get("/api/v1/trust/acme/config")
    assert resp.status_code == 200
    assert resp.json()["org_name"] == "Acme Corp"


def test_get_config_404(client):
    resp = client.get("/api/v1/trust/ghost_org/config")
    assert resp.status_code == 404


def test_stats_endpoint(client):
    resp = client.get("/api/v1/trust/acme/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "badges" in data
    assert "controls" in data
    assert "trust_score" in data


def test_stats_404(client):
    resp = client.get("/api/v1/trust/ghost_org/stats")
    assert resp.status_code == 404


def test_add_badge_endpoint(client):
    resp = client.post(
        "/api/v1/trust/acme/badges",
        json={"framework": "GDPR", "status": "in_progress"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "GDPR"
    assert data["org_id"] == "acme"


def test_list_badges_endpoint(client, configured_mgr, sample_badge):
    configured_mgr.add_badge(sample_badge, "acme")
    resp = client.get("/api/v1/trust/acme/badges")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_delete_badge_endpoint(client, configured_mgr, sample_badge):
    b = configured_mgr.add_badge(sample_badge, "acme")
    resp = client.delete(f"/api/v1/trust/acme/badges/{b.id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True


def test_delete_badge_404(client):
    resp = client.delete("/api/v1/trust/acme/badges/fake-id")
    assert resp.status_code == 404


def test_add_control_endpoint(client):
    resp = client.post(
        "/api/v1/trust/acme/controls",
        json={
            "category": "Encryption",
            "title": "TLS 1.3",
            "description": "All traffic uses TLS 1.3",
            "status": "implemented",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "TLS 1.3"


def test_list_controls_endpoint(client):
    resp = client.get("/api/v1/trust/acme/controls")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_delete_control_endpoint(client, configured_mgr, sample_control):
    c = configured_mgr.add_control(sample_control, "acme")
    resp = client.delete(f"/api/v1/trust/acme/controls/{c.id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True


def test_delete_control_404(client):
    resp = client.delete("/api/v1/trust/acme/controls/fake-id")
    assert resp.status_code == 404


def test_add_subprocessor_endpoint(client):
    resp = client.post(
        "/api/v1/trust/acme/subprocessors",
        json={
            "name": "Twilio",
            "purpose": "SMS notifications",
            "location": "United States",
            "data_types": ["phone_numbers"],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Twilio"
    assert data["data_types"] == ["phone_numbers"]


def test_list_subprocessors_endpoint(client, configured_mgr, sample_subprocessor):
    configured_mgr.add_subprocessor(sample_subprocessor, "acme")
    resp = client.get("/api/v1/trust/acme/subprocessors")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_delete_subprocessor_endpoint(client, configured_mgr, sample_subprocessor):
    s = configured_mgr.add_subprocessor(sample_subprocessor, "acme")
    resp = client.delete(f"/api/v1/trust/acme/subprocessors/{s.id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True


def test_delete_subprocessor_404(client):
    resp = client.delete("/api/v1/trust/acme/subprocessors/fake-id")
    assert resp.status_code == 404


def test_badges_endpoint_requires_configured_org(client):
    """Adding a badge to unconfigured org returns 404."""
    resp = client.post(
        "/api/v1/trust/unconfigured_org/badges",
        json={"framework": "SOC2", "status": "planned"},
    )
    assert resp.status_code == 404


# ============================================================================
# ExtendedTrustCenterManager — fixtures
# ============================================================================

import pytest
from core.trust_center import (
    ExtendedTrustCenterManager,
    SecurityPractice,
    TrustDocument,
    FAQItem,
    DocumentRequest,
    SignedAgreement,
    _DEFAULT_SECURITY_PRACTICES,
    _DEFAULT_TRUST_DOCUMENTS,
    _DEFAULT_FAQ_ITEMS,
)


@pytest.fixture
def emgr():
    """Fresh in-memory ExtendedTrustCenterManager for each test."""
    return ExtendedTrustCenterManager(db_path=":memory:")


@pytest.fixture
def ext_app(emgr):
    """FastAPI test app using ExtendedTrustCenterManager, auth bypassed."""
    from fastapi import FastAPI
    from apps.api.trust_center_router import router, _get_manager
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_get_manager] = lambda: emgr
    app.dependency_overrides[api_key_auth] = lambda: None
    return app


@pytest.fixture
def ext_client(ext_app):
    from fastapi.testclient import TestClient
    return TestClient(ext_app)


# ============================================================================
# ExtendedTrustCenterManager — Security Practices
# ============================================================================


def test_get_security_practices_returns_list(emgr):
    practices = emgr.get_security_practices()
    assert isinstance(practices, list)
    assert len(practices) > 0
    assert all(isinstance(p, SecurityPractice) for p in practices)


def test_security_practices_have_expected_areas(emgr):
    practices = emgr.get_security_practices()
    areas = {p.area for p in practices}
    assert "Encryption" in areas
    assert "Access Control" in areas
    assert "Incident Response" in areas
    assert "Vulnerability Management" in areas
    assert "Business Continuity" in areas


def test_get_practices_by_area_found(emgr):
    p = emgr.get_practices_by_area("Encryption")
    assert p is not None
    assert p.area == "Encryption"
    assert "AES-256" in p.details.get("at_rest", "")


def test_get_practices_by_area_case_insensitive(emgr):
    p = emgr.get_practices_by_area("access control")
    assert p is not None
    assert p.area == "Access Control"


def test_get_practices_by_area_not_found(emgr):
    assert emgr.get_practices_by_area("Nonexistent Area") is None


def test_get_practices_summary_structure(emgr):
    summary = emgr.get_practices_summary()
    assert "areas" in summary
    assert "highlights" in summary
    assert summary["highlights"]["mfa_required"] is True
    assert summary["highlights"]["annual_pentest"] is True


# ============================================================================
# ExtendedTrustCenterManager — Document Repository
# ============================================================================


def test_list_documents_seeded_on_init(emgr):
    docs = emgr.list_documents(public_only=False)
    assert len(docs) > 0
    assert all(isinstance(d, TrustDocument) for d in docs)


def test_list_documents_public_only_excludes_auth_gated(emgr):
    public = emgr.list_documents(public_only=True)
    assert all(not d.requires_auth for d in public)


def test_list_documents_all_includes_restricted(emgr):
    all_docs = emgr.list_documents(public_only=False)
    restricted = [d for d in all_docs if d.requires_auth]
    assert len(restricted) > 0


def test_add_document_custom(emgr):
    doc = TrustDocument(
        doc_type="security_whitepaper",
        title="Custom Whitepaper",
        description="A custom security whitepaper.",
        version="1.0",
    )
    saved = emgr.add_document(doc)
    assert saved.id == doc.id
    retrieved = emgr.get_document(doc.id)
    assert retrieved is not None
    assert retrieved.title == "Custom Whitepaper"


def test_get_document_not_found(emgr):
    assert emgr.get_document("nonexistent-id") is None


def test_add_document_upserts(emgr):
    doc = TrustDocument(doc_type="privacy_policy", title="Old Title", description="D")
    emgr.add_document(doc)
    updated = doc.model_copy(update={"title": "New Title"})
    emgr.add_document(updated)
    retrieved = emgr.get_document(doc.id)
    assert retrieved.title == "New Title"


# ============================================================================
# ExtendedTrustCenterManager — NDA/DPA Generation
# ============================================================================


def test_generate_nda_returns_agreement_id(emgr):
    result = emgr.generate_nda("Jane Doe", "jane@acme.com", "Acme Corp")
    assert "agreement_id" in result
    assert result["agreement_type"] == "NDA"
    assert "document_text" in result
    assert "Acme Corp" in result["document_text"]
    assert "Jane Doe" in result["document_text"]


def test_generate_dpa_returns_agreement_id(emgr):
    result = emgr.generate_dpa("John Smith", "john@corp.com", "Corp Ltd")
    assert result["agreement_type"] == "DPA"
    assert "Corp Ltd" in result["document_text"]
    assert result["agreement_id"] is not None


def test_list_agreements_tracks_generated(emgr):
    emgr.generate_nda("A", "a@a.com", "A Corp")
    emgr.generate_dpa("B", "b@b.com", "B Corp")
    agreements = emgr.list_agreements()
    assert len(agreements) == 2
    types = {a.agreement_type for a in agreements}
    assert "NDA" in types
    assert "DPA" in types


def test_check_agreement_status_found(emgr):
    emgr.generate_nda("Jane", "jane@test.com", "TestCo")
    found = emgr.check_agreement_status("jane@test.com", "NDA")
    assert found is not None
    assert found.prospect_company == "TestCo"


def test_check_agreement_status_not_found(emgr):
    assert emgr.check_agreement_status("nobody@test.com", "NDA") is None


def test_check_agreement_status_case_insensitive(emgr):
    emgr.generate_nda("Test", "Test@CORP.com", "Corp")
    found = emgr.check_agreement_status("test@corp.com", "NDA")
    assert found is not None


def test_record_signature_marks_signed(emgr):
    result = emgr.generate_nda("Signer", "signer@co.com", "Co Ltd")
    aid = result["agreement_id"]
    signed = emgr.record_signature(aid, ip_address="1.2.3.4")
    assert signed is not None
    assert signed.signed_at is not None
    assert signed.ip_address == "1.2.3.4"


def test_record_signature_unknown_id_returns_none(emgr):
    assert emgr.record_signature("nonexistent-id") is None


# ============================================================================
# ExtendedTrustCenterManager — FAQ Management
# ============================================================================


def test_faq_seeded_on_init(emgr):
    items = emgr.get_faq(public_only=True)
    assert len(items) > 0
    assert all(isinstance(i, FAQItem) for i in items)


def test_faq_category_filter(emgr):
    items = emgr.get_faq(category="compliance", public_only=True)
    assert len(items) > 0
    assert all(i.category == "compliance" for i in items)


def test_faq_by_category_groups_correctly(emgr):
    grouped = emgr.get_faq_by_category()
    assert "compliance" in grouped
    assert "data_handling" in grouped
    assert all(i.category == cat for cat, items in grouped.items() for i in items)


def test_add_faq_item_custom(emgr):
    item = FAQItem(
        category="infrastructure",
        question="Do you use Kubernetes?",
        answer="Yes, EKS on AWS.",
        order=99,
    )
    saved = emgr.add_faq_item(item)
    assert saved.id == item.id
    all_items = emgr.get_faq(category="infrastructure", public_only=True)
    ids = [i.id for i in all_items]
    assert item.id in ids


def test_add_faq_item_upserts(emgr):
    item = FAQItem(category="encryption", question="Q?", answer="Old answer.")
    emgr.add_faq_item(item)
    updated = item.model_copy(update={"answer": "New answer."})
    emgr.add_faq_item(updated)
    items = emgr.get_faq(category="encryption")
    matching = [i for i in items if i.id == item.id]
    assert matching[0].answer == "New answer."


# ============================================================================
# ExtendedTrustCenterManager — Request Portal
# ============================================================================


def test_submit_request(emgr):
    req = DocumentRequest(
        request_type="security_questionnaire",
        requester_name="Alice",
        requester_email="alice@bigco.com",
        requester_company="BigCo",
    )
    saved = emgr.submit_request(req)
    assert saved.request_id == req.request_id
    assert saved.status == "pending"


def test_list_requests_returns_submitted(emgr):
    req = DocumentRequest(
        request_type="additional_docs",
        requester_name="Bob",
        requester_email="bob@co.com",
        requester_company="Co",
    )
    emgr.submit_request(req)
    reqs = emgr.list_requests()
    assert len(reqs) == 1
    assert reqs[0].request_id == req.request_id


def test_list_requests_status_filter(emgr):
    emgr.submit_request(DocumentRequest(
        request_type="additional_docs", requester_name="A",
        requester_email="a@a.com", requester_company="A",
    ))
    emgr.submit_request(DocumentRequest(
        request_type="custom_dpa", requester_name="B",
        requester_email="b@b.com", requester_company="B",
        status="fulfilled",
    ))
    pending = emgr.list_requests(status="pending")
    assert all(r.status == "pending" for r in pending)


def test_update_request_status_to_fulfilled(emgr):
    req = DocumentRequest(
        request_type="architecture_diagram",
        requester_name="C", requester_email="c@c.com", requester_company="C",
    )
    emgr.submit_request(req)
    updated = emgr.update_request_status(
        req.request_id, status="fulfilled",
        fulfilled_by="security@aldeci.io", notes="Sent via email"
    )
    assert updated is not None
    assert updated.status == "fulfilled"
    assert updated.fulfilled_by == "security@aldeci.io"
    assert updated.fulfilled_at is not None


def test_update_request_status_not_found(emgr):
    assert emgr.update_request_status("bad-id", status="fulfilled") is None


# ============================================================================
# New API endpoints — /public, /compliance, /sub-processors, /practices,
#                     /documents, POST /request, /faq, /nda, /dpa
# ============================================================================


def test_public_endpoint(ext_client):
    resp = ext_client.get("/api/v1/trust/public")
    assert resp.status_code == 200
    data = resp.json()
    assert "org_name" in data
    assert "certifications" in data
    assert "contact_email" in data


def test_compliance_endpoint(ext_client):
    resp = ext_client.get("/api/v1/trust/compliance")
    assert resp.status_code == 200
    data = resp.json()
    assert "frameworks" in data
    frameworks = [f["framework"] for f in data["frameworks"]]
    assert "SOC 2 Type II" in frameworks
    assert "ISO 27001:2022" in frameworks
    assert "GDPR" in frameworks


def test_sub_processors_endpoint(ext_client):
    resp = ext_client.get("/api/v1/trust/sub-processors")
    assert resp.status_code == 200
    data = resp.json()
    assert "sub_processors" in data
    assert data["total"] > 0
    names = [sp["name"] for sp in data["sub_processors"]]
    assert any("AWS" in n or "Amazon" in n for n in names)


def test_practices_endpoint_all(ext_client):
    resp = ext_client.get("/api/v1/trust/practices")
    assert resp.status_code == 200
    data = resp.json()
    assert "practices" in data
    assert data["total"] > 0
    areas = [p["area"] for p in data["practices"]]
    assert "Encryption" in areas


def test_practices_endpoint_area_filter(ext_client):
    resp = ext_client.get("/api/v1/trust/practices?area=Encryption")
    assert resp.status_code == 200
    data = resp.json()
    assert "practice" in data
    assert data["practice"]["area"] == "Encryption"


def test_practices_endpoint_area_not_found(ext_client):
    resp = ext_client.get("/api/v1/trust/practices?area=Nonexistent")
    assert resp.status_code == 404


def test_documents_endpoint_public(ext_client):
    resp = ext_client.get("/api/v1/trust/documents")
    assert resp.status_code == 200
    data = resp.json()
    assert "documents" in data
    assert data["total"] > 0
    assert all(not d.get("requires_auth", True) for d in data["documents"])


def test_documents_endpoint_all(ext_client):
    resp = ext_client.get("/api/v1/trust/documents?public_only=false")
    assert resp.status_code == 200
    data = resp.json()
    # All docs including NDA-gated ones
    assert data["total"] >= ext_client.get("/api/v1/trust/documents").json()["total"]


def test_request_endpoint_valid(ext_client):
    resp = ext_client.post("/api/v1/trust/request", json={
        "request_type": "security_questionnaire",
        "requester_name": "Test User",
        "requester_email": "test@example.com",
        "requester_company": "Example Corp",
        "message": "We need your CAIQ.",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "request_id" in data
    assert data["status"] == "pending"


def test_request_endpoint_invalid_type(ext_client):
    resp = ext_client.post("/api/v1/trust/request", json={
        "request_type": "invalid_type",
        "requester_name": "X",
        "requester_email": "x@x.com",
        "requester_company": "X",
    })
    assert resp.status_code == 422


def test_faq_endpoint_all(ext_client):
    resp = ext_client.get("/api/v1/trust/faq")
    assert resp.status_code == 200
    data = resp.json()
    assert "faq" in data
    assert data["total"] > 0


def test_faq_endpoint_category_filter(ext_client):
    resp = ext_client.get("/api/v1/trust/faq?category=compliance")
    assert resp.status_code == 200
    data = resp.json()
    assert all(item["category"] == "compliance" for item in data["faq"])


def test_faq_endpoint_grouped(ext_client):
    resp = ext_client.get("/api/v1/trust/faq?grouped=true")
    assert resp.status_code == 200
    data = resp.json()
    assert "faq" in data
    assert isinstance(data["faq"], dict)
    assert "categories" in data


def test_faq_endpoint_invalid_category(ext_client):
    resp = ext_client.get("/api/v1/trust/faq?category=invalid_cat")
    assert resp.status_code == 422


def test_nda_endpoint(ext_client):
    resp = ext_client.post("/api/v1/trust/nda", json={
        "prospect_name": "Alice Smith",
        "prospect_email": "alice@prospects.com",
        "prospect_company": "Prospect Inc",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["agreement_type"] == "NDA"
    assert "agreement_id" in data
    assert "Prospect Inc" in data["document_text"]


def test_dpa_endpoint(ext_client):
    resp = ext_client.post("/api/v1/trust/dpa", json={
        "prospect_name": "Bob Jones",
        "prospect_email": "bob@eu-corp.com",
        "prospect_company": "EU Corp GmbH",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["agreement_type"] == "DPA"
    assert "EU Corp GmbH" in data["document_text"]


def test_extended_singleton_pattern():
    ExtendedTrustCenterManager.reset_extended_instance()
    m1 = ExtendedTrustCenterManager.get_extended_instance()
    m2 = ExtendedTrustCenterManager.get_extended_instance()
    assert m1 is m2
    ExtendedTrustCenterManager.reset_extended_instance()
