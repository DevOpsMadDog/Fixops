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
