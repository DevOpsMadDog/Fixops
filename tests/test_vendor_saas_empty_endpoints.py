"""Tests for vendor/SaaS/TPRM 5-state root GET / endpoints.

Covers:
  GET /api/v1/tprm-exchange/
  GET /api/v1/sspm/
  GET /api/v1/vendor-compliance/
  GET /api/v1/third-party-vendor/

Each endpoint must return a valid 5-state envelope with status in
{healthy, degraded, empty, error, unknown} and the correct domain field.
"""
from __future__ import annotations

import os
import sys

import pytest

# Set auth env before any app import so auth_deps picks it up
os.environ.setdefault("FIXOPS_API_TOKEN", "test-api-key-for-pytest")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from fastapi.testclient import TestClient  # noqa: E402

VALID_STATES = {"healthy", "degraded", "empty", "error", "unknown"}
HEADERS = {"X-API-Key": "test-api-key-for-pytest"}


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# TPRM Exchange
# ---------------------------------------------------------------------------

class TestTPRMRootSummary:
    def test_returns_200(self, client):
        r = client.get("/api/v1/tprm-exchange/", headers=HEADERS)
        assert r.status_code == 200

    def test_envelope_has_status(self, client):
        r = client.get("/api/v1/tprm-exchange/", headers=HEADERS)
        body = r.json()
        assert "status" in body
        assert body["status"] in VALID_STATES

    def test_envelope_has_domain(self, client):
        r = client.get("/api/v1/tprm-exchange/", headers=HEADERS)
        assert r.json()["domain"] == "tprm-exchange"

    def test_envelope_has_org_id(self, client):
        r = client.get("/api/v1/tprm-exchange/?org_id=acme", headers=HEADERS)
        assert r.json()["org_id"] == "acme"

    def test_empty_state_has_hint(self, client):
        r = client.get("/api/v1/tprm-exchange/?org_id=__nonexistent_org_tprm__", headers=HEADERS)
        body = r.json()
        if body.get("status") == "empty":
            assert "hint" in body

    def test_summary_or_error_key_present(self, client):
        r = client.get("/api/v1/tprm-exchange/", headers=HEADERS)
        body = r.json()
        assert "summary" in body or "error" in body


# ---------------------------------------------------------------------------
# SSPM (SaaS Security Posture)
# ---------------------------------------------------------------------------

class TestSSPMRootSummary:
    def test_returns_200(self, client):
        r = client.get("/api/v1/sspm/", headers=HEADERS)
        assert r.status_code == 200

    def test_envelope_has_status(self, client):
        r = client.get("/api/v1/sspm/", headers=HEADERS)
        body = r.json()
        assert "status" in body
        assert body["status"] in VALID_STATES

    def test_envelope_has_domain(self, client):
        r = client.get("/api/v1/sspm/", headers=HEADERS)
        assert r.json()["domain"] == "sspm"

    def test_envelope_has_org_id(self, client):
        r = client.get("/api/v1/sspm/?org_id=tenant1", headers=HEADERS)
        assert r.json()["org_id"] == "tenant1"

    def test_empty_state_has_hint(self, client):
        r = client.get("/api/v1/sspm/?org_id=__nonexistent_org_sspm__", headers=HEADERS)
        body = r.json()
        if body.get("status") == "empty":
            assert "hint" in body

    def test_stats_or_error_key_present(self, client):
        r = client.get("/api/v1/sspm/", headers=HEADERS)
        body = r.json()
        assert "stats" in body or "error" in body


# ---------------------------------------------------------------------------
# Vendor Compliance
# ---------------------------------------------------------------------------

class TestVendorComplianceRootSummary:
    def test_returns_200(self, client):
        r = client.get("/api/v1/vendor-compliance/", headers=HEADERS)
        assert r.status_code == 200

    def test_envelope_has_status(self, client):
        r = client.get("/api/v1/vendor-compliance/", headers=HEADERS)
        body = r.json()
        assert "status" in body
        assert body["status"] in VALID_STATES

    def test_envelope_has_domain(self, client):
        r = client.get("/api/v1/vendor-compliance/", headers=HEADERS)
        assert r.json()["domain"] == "vendor-compliance"

    def test_envelope_has_org_id(self, client):
        r = client.get("/api/v1/vendor-compliance/?org_id=org42", headers=HEADERS)
        assert r.json()["org_id"] == "org42"

    def test_empty_state_has_hint(self, client):
        r = client.get("/api/v1/vendor-compliance/?org_id=__nonexistent_org_vc__", headers=HEADERS)
        body = r.json()
        if body.get("status") == "empty":
            assert "hint" in body

    def test_stats_or_error_key_present(self, client):
        r = client.get("/api/v1/vendor-compliance/", headers=HEADERS)
        body = r.json()
        assert "stats" in body or "error" in body


# ---------------------------------------------------------------------------
# Third-Party Vendor
# ---------------------------------------------------------------------------

class TestThirdPartyVendorRootSummary:
    def test_returns_200(self, client):
        r = client.get("/api/v1/third-party-vendor/", headers=HEADERS)
        assert r.status_code == 200

    def test_envelope_has_status(self, client):
        r = client.get("/api/v1/third-party-vendor/", headers=HEADERS)
        body = r.json()
        assert "status" in body
        assert body["status"] in VALID_STATES

    def test_envelope_has_domain(self, client):
        r = client.get("/api/v1/third-party-vendor/", headers=HEADERS)
        assert r.json()["domain"] == "third-party-vendor"

    def test_envelope_has_org_id(self, client):
        r = client.get("/api/v1/third-party-vendor/?org_id=corp99", headers=HEADERS)
        assert r.json()["org_id"] == "corp99"

    def test_empty_state_has_hint(self, client):
        r = client.get("/api/v1/third-party-vendor/?org_id=__nonexistent_org_tpv__", headers=HEADERS)
        body = r.json()
        if body.get("status") == "empty":
            assert "hint" in body

    def test_stats_or_error_key_present(self, client):
        r = client.get("/api/v1/third-party-vendor/", headers=HEADERS)
        body = r.json()
        assert "stats" in body or "error" in body
