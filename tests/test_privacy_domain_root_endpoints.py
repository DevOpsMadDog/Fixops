"""Tests for GET / root summary endpoints on the 4 privacy-domain routers.

Covers:
  GET /api/v1/data-privacy/      — data_privacy_router
  GET /api/v1/dlp/               — dlp_router
  GET /api/v1/gdpr/              — gdpr_compliance_router
  GET /api/v1/privacy/           — privacy_gdpr_router

Each router is tested directly (no app-level auth needed in tests because
we pass a mock api_key_auth dependency override).
"""

from __future__ import annotations

import sys
import pytest

# Ensure suite-core is on path
sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")


# ---------------------------------------------------------------------------
# Shared auth-bypass override
# ---------------------------------------------------------------------------

def _noop_auth():
    return "test-key"


# ===========================================================================
# 1. data_privacy_router  —  GET /api/v1/data-privacy/
# ===========================================================================

@pytest.fixture()
def data_privacy_client(tmp_path):
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.auth_deps import api_key_auth

    # Point engine at a temp DB
    import apps.api.data_privacy_router as dp_mod
    import core.data_privacy_engine as eng_mod
    dp_mod._engine = eng_mod.DataPrivacyEngine(db_path=str(tmp_path / "dp.db"))

    from apps.api.data_privacy_router import router
    app = FastAPI()
    app.dependency_overrides[api_key_auth] = _noop_auth
    app.include_router(router)
    return TestClient(app)


def test_data_privacy_root_empty_state(data_privacy_client):
    resp = data_privacy_client.get("/api/v1/data-privacy/?org_id=test-org")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "empty"
    assert body["domain"] == "data-privacy"
    assert "hint" in body


def test_data_privacy_root_healthy_after_asset(data_privacy_client):
    from core.data_privacy_engine import DataAssetCreate
    import apps.api.data_privacy_router as dp_mod
    eng = dp_mod._engine
    eng.register_data_asset("org-h", DataAssetCreate(name="CRM DB", data_category="pii"))

    resp = data_privacy_client.get("/api/v1/data-privacy/?org_id=org-h")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert "stats" in body


def test_data_privacy_root_has_org_id(data_privacy_client):
    resp = data_privacy_client.get("/api/v1/data-privacy/?org_id=myorg")
    assert resp.json()["org_id"] == "myorg"


def test_data_privacy_root_stats_present_in_healthy(data_privacy_client):
    from core.data_privacy_engine import DataAssetCreate
    import apps.api.data_privacy_router as dp_mod
    dp_mod._engine.register_data_asset("org-s", DataAssetCreate(name="DB", data_category="pii"))
    resp = data_privacy_client.get("/api/v1/data-privacy/?org_id=org-s")
    body = resp.json()
    assert "stats" in body
    assert "total_assets" in body["stats"]


# ===========================================================================
# 2. dlp_router  —  GET /api/v1/dlp/
# ===========================================================================

@pytest.fixture()
def dlp_client(tmp_path):
    from fastapi.testclient import TestClient
    from fastapi import FastAPI

    import apps.api.dlp_router as dlp_mod
    import core.dlp_engine as eng_mod
    dlp_mod._engine = eng_mod.DLPEngine(db_path=str(tmp_path / "dlp.db"))

    from apps.api.dlp_router import router
    app = FastAPI()
    # Override the router-level auth dependency (imported as _api_key_auth)
    try:
        from apps.api.auth_deps import api_key_auth as _api_key_auth
        app.dependency_overrides[_api_key_auth] = _noop_auth
    except ImportError:
        pass
    app.include_router(router)
    return TestClient(app)


def test_dlp_root_empty_state(dlp_client):
    resp = dlp_client.get("/api/v1/dlp/?org_id=test-org")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "empty"
    assert body["domain"] == "dlp"
    assert "hint" in body


def test_dlp_root_healthy_after_scan(dlp_client):
    import apps.api.dlp_router as dlp_mod
    dlp_mod._engine.scan_text("My SSN is 123-45-6789", org_id="org-dlp")
    resp = dlp_client.get("/api/v1/dlp/?org_id=org-dlp")
    assert resp.status_code == 200
    body = resp.json()
    # at least not empty after a scan
    assert body["status"] in ("healthy", "degraded")


def test_dlp_root_returns_scan_stats(dlp_client):
    resp = dlp_client.get("/api/v1/dlp/?org_id=stats-org")
    body = resp.json()
    assert "scan_stats" in body
    assert "policy_stats" in body


def test_dlp_root_org_id_echoed(dlp_client):
    resp = dlp_client.get("/api/v1/dlp/?org_id=echo-org")
    assert resp.json()["org_id"] == "echo-org"


# ===========================================================================
# 3. gdpr_compliance_router  —  GET /api/v1/gdpr/
# ===========================================================================

@pytest.fixture()
def gdpr_client(tmp_path):
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.auth_deps import api_key_auth

    import apps.api.gdpr_compliance_router as gdpr_mod
    import core.gdpr_compliance_engine as eng_mod
    gdpr_mod._engine = eng_mod.GDPRComplianceEngine(db_path=str(tmp_path / "gdpr.db"))

    from apps.api.gdpr_compliance_router import router
    app = FastAPI()
    app.dependency_overrides[api_key_auth] = _noop_auth
    app.include_router(router)
    return TestClient(app)


def test_gdpr_root_empty_state(gdpr_client):
    resp = gdpr_client.get("/api/v1/gdpr/?org_id=fresh-org")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "empty"
    assert body["domain"] == "gdpr"
    assert "hint" in body


def test_gdpr_root_healthy_after_activity(gdpr_client):
    from core.gdpr_compliance_engine import ProcessingActivityCreate
    import apps.api.gdpr_compliance_router as gdpr_mod
    gdpr_mod._engine.record_processing_activity(
        "org-g",
        ProcessingActivityCreate(
            name="Marketing emails",
            purpose="direct marketing",
            lawful_basis="consent",
        ),
    )
    resp = gdpr_client.get("/api/v1/gdpr/?org_id=org-g")
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["total_processing_activities"] == 1


def test_gdpr_root_shows_consent_counts(gdpr_client):
    resp = gdpr_client.get("/api/v1/gdpr/?org_id=cnt-org")
    body = resp.json()
    assert "total_consents" in body
    assert "active_consents" in body


def test_gdpr_root_org_id_echoed(gdpr_client):
    resp = gdpr_client.get("/api/v1/gdpr/?org_id=my-org")
    assert resp.json()["org_id"] == "my-org"


# ===========================================================================
# 4. privacy_gdpr_router  —  GET /api/v1/privacy/
# ===========================================================================

@pytest.fixture()
def privacy_client(tmp_path):
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.auth_deps import api_key_auth

    import apps.api.privacy_gdpr_router as priv_mod
    import core.privacy_gdpr_engine as eng_mod
    priv_mod._engine = eng_mod.PrivacyGDPREngine(db_dir=str(tmp_path))

    from apps.api.privacy_gdpr_router import router
    app = FastAPI()
    app.dependency_overrides[api_key_auth] = _noop_auth
    app.include_router(router)
    return TestClient(app)


def test_privacy_root_empty_state(privacy_client):
    resp = privacy_client.get("/api/v1/privacy/?org_id=new-org")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "empty"
    assert body["domain"] == "privacy-gdpr"
    assert "hint" in body


def test_privacy_root_healthy_after_dsr(privacy_client):
    import apps.api.privacy_gdpr_router as priv_mod
    priv_mod._engine.create_dsr(
        "org-p",
        {
            "request_type": "access",
            "subject_email": "user@example.com",
            "subject_name": "Test User",
            "identity_verified": True,
            "regulation": "gdpr",
            "notes": "",
        },
    )
    resp = privacy_client.get("/api/v1/privacy/?org_id=org-p")
    body = resp.json()
    assert body["status"] in ("healthy", "degraded")
    assert "stats" in body


def test_privacy_root_stats_keys(privacy_client):
    resp = privacy_client.get("/api/v1/privacy/?org_id=stats-org")
    body = resp.json()
    assert "stats" in body
    stats = body["stats"]
    assert "total_dsrs" in stats


def test_privacy_root_org_id_echoed(privacy_client):
    resp = privacy_client.get("/api/v1/privacy/?org_id=echo-me")
    assert resp.json()["org_id"] == "echo-me"
