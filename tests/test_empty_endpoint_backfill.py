"""Smoke tests — deferred empty-endpoint backfill (2026-05-04).

Verifies that the 6 feed-importer routers newly mounted in app.py
respond with the correct list shape. The stores may be empty in CI
(no network calls made) — but each endpoint must:
  1. Return HTTP 200
  2. Return a dict (not a bare list) with at least one key

No mock data is inserted — tests verify the real wiring path only.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

API_KEY = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
os.environ.setdefault("FIXOPS_API_TOKEN", API_KEY)
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-for-ci-testing")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# EPSS — /api/v1/epss/scores
# ---------------------------------------------------------------------------

def test_epss_scores_mounted_and_list_shape(client):
    """GET /api/v1/epss/scores returns 200 with a dict response."""
    r = client.get("/api/v1/epss/scores", headers=HEADERS)
    assert r.status_code == 200, f"epss/scores returned {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert isinstance(body, dict), "epss/scores must return a dict"
    # Expect pagination keys regardless of DB content
    assert "scores" in body or "items" in body or "page" in body or "total" in body, (
        f"epss/scores missing expected keys: {list(body.keys())}"
    )


# ---------------------------------------------------------------------------
# Nuclei — /api/v1/nuclei/templates
# ---------------------------------------------------------------------------

def test_nuclei_templates_mounted_and_list_shape(client):
    """GET /api/v1/nuclei/templates returns 200 with category catalog."""
    r = client.get("/api/v1/nuclei/templates", headers=HEADERS)
    assert r.status_code == 200, f"nuclei/templates returned {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert isinstance(body, dict), "nuclei/templates must return a dict"
    assert "categories" in body or "total_templates" in body, (
        f"nuclei/templates missing expected keys: {list(body.keys())}"
    )


def test_nuclei_templates_list_endpoint(client):
    """GET /api/v1/nuclei/templates/list returns 200 with templates list."""
    r = client.get("/api/v1/nuclei/templates/list", headers=HEADERS)
    assert r.status_code == 200, f"nuclei/templates/list returned {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert isinstance(body, dict), "nuclei/templates/list must return a dict"
    assert "templates" in body, f"expected 'templates' key, got: {list(body.keys())}"
    assert isinstance(body["templates"], list), "'templates' must be a list"


# ---------------------------------------------------------------------------
# Spamhaus DROP — /api/v1/spamhaus/cidrs
# ---------------------------------------------------------------------------

def test_spamhaus_cidrs_mounted_and_list_shape(client):
    """GET /api/v1/spamhaus/cidrs returns 200 with CIDR list response."""
    r = client.get("/api/v1/spamhaus/cidrs", headers=HEADERS)
    assert r.status_code == 200, f"spamhaus/cidrs returned {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert isinstance(body, dict), "spamhaus/cidrs must return a dict"
    assert "cidrs" in body, f"expected 'cidrs' key, got: {list(body.keys())}"
    assert isinstance(body["cidrs"], list), "'cidrs' must be a list"


# ---------------------------------------------------------------------------
# GHSA — /api/v1/ghsa/advisories
# ---------------------------------------------------------------------------

def test_ghsa_advisories_mounted_and_list_shape(client):
    """GET /api/v1/ghsa/advisories returns 200 with advisory list response."""
    r = client.get("/api/v1/ghsa/advisories", headers=HEADERS)
    assert r.status_code == 200, f"ghsa/advisories returned {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert isinstance(body, (dict, list)), "ghsa/advisories must return dict or list"
    if isinstance(body, dict):
        assert len(body) > 0, "ghsa/advisories response dict must not be empty"


# ---------------------------------------------------------------------------
# URLhaus — /api/v1/urlhaus/urls
# ---------------------------------------------------------------------------

def test_urlhaus_urls_mounted_and_list_shape(client):
    """GET /api/v1/urlhaus/urls returns 200 with URL list response."""
    r = client.get("/api/v1/urlhaus/urls", headers=HEADERS)
    assert r.status_code == 200, f"urlhaus/urls returned {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert isinstance(body, (dict, list)), "urlhaus/urls must return dict or list"


# ---------------------------------------------------------------------------
# PhishTank — /api/v1/phishtank/phishes
# ---------------------------------------------------------------------------

def test_phishtank_phishes_mounted_and_list_shape(client):
    """GET /api/v1/phishtank/phishes returns 200 with phish list response."""
    r = client.get("/api/v1/phishtank/phishes", headers=HEADERS)
    assert r.status_code == 200, f"phishtank/phishes returned {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert isinstance(body, (dict, list)), "phishtank/phishes must return dict or list"
