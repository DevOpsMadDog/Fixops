"""Tests for SBOM Export Router — ALDECI.

Covers:
  - GET /api/v1/sbom-export/formats                          list supported formats
  - GET /api/v1/sbom-export/cyclonedx                        generate CycloneDX 1.4 (GET)
  - GET /api/v1/sbom-export/spdx                             generate SPDX 2.3 (GET)
  - POST /api/v1/sbom-export/components                      register component
  - POST /api/v1/sbom-export/components/{id}/vulns           add vulnerability
  - POST /api/v1/sbom-export/generate/cyclonedx              generate CycloneDX (POST)
  - POST /api/v1/sbom-export/generate/spdx                   generate SPDX (POST)
  - GET /api/v1/sbom-export/projects                         list projects
  - GET /api/v1/sbom-export/projects/{name}/summary          project summary
  - GET /api/v1/sbom-export/projects/{name}/history          export history
  - GET /api/v1/sbom-export/search                           search components
  - Auth enforcement (missing key → 401/403)
  - Org isolation
"""

from __future__ import annotations

import os
import sys

# Set env vars BEFORE any imports so auth_deps reads them at module import time
os.environ["FIXOPS_API_TOKEN"] = "test-sbom-export-router-xyz"
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-32-chars-padding!!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

API_TOKEN = os.environ["FIXOPS_API_TOKEN"]
BASE = "/api/v1/sbom-export"
AUTH = {"X-API-Key": API_TOKEN}
NO_AUTH: dict = {}


# ---------------------------------------------------------------------------
# Build a minimal app — only mount the SBOM export router.
# This avoids loading the full app.py which triggers unrelated SyntaxErrors.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    from core.sbom_export_engine import SBOMExportEngine
    import apps.api.sbom_export_router as _mod

    # Isolated DB for this test run
    tmp = tmp_path_factory.mktemp("sbom_export_router")
    _mod._engine = SBOMExportEngine(db_path=str(tmp / "sbom_export.db"))

    from apps.api.sbom_export_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _register(client, org_id="org-rt", project="rt-proj",
               name="requests", version="2.28.0"):
    resp = client.post(
        f"{BASE}/components",
        json={
            "org_id": org_id,
            "project_name": project,
            "component_name": name,
            "component_version": version,
            "component_type": "library",
            "ecosystem": "pypi",
            "license": "Apache-2.0",
            "purl": f"pkg:pypi/{name}@{version}",
            "supplier": "PSF",
        },
        headers=AUTH,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# GET /formats
# ---------------------------------------------------------------------------

def test_formats_returns_two_entries(client):
    resp = client.get(f"{BASE}/formats", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert "formats" in data
    assert len(data["formats"]) == 2


def test_formats_contains_cyclonedx(client):
    resp = client.get(f"{BASE}/formats", headers=AUTH)
    ids = {f["id"] for f in resp.json()["formats"]}
    assert "cyclonedx" in ids


def test_formats_contains_spdx(client):
    resp = client.get(f"{BASE}/formats", headers=AUTH)
    ids = {f["id"] for f in resp.json()["formats"]}
    assert "spdx" in ids


def test_formats_has_default_cyclonedx(client):
    resp = client.get(f"{BASE}/formats", headers=AUTH)
    assert resp.json()["default"] == "cyclonedx"


def test_formats_requires_auth(client):
    resp = client.get(f"{BASE}/formats", headers=NO_AUTH)
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# POST /components
# ---------------------------------------------------------------------------

def test_register_component_201(client):
    resp = client.post(
        f"{BASE}/components",
        json={
            "org_id": "org-post",
            "project_name": "proj-post",
            "component_name": "flask",
            "component_version": "3.0.0",
            "component_type": "framework",
            "ecosystem": "pypi",
            "license": "MIT",
        },
        headers=AUTH,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["component_name"] == "flask"
    assert body["id"]


def test_register_component_invalid_type_422(client):
    resp = client.post(
        f"{BASE}/components",
        json={
            "org_id": "org1",
            "project_name": "proj1",
            "component_name": "bad",
            "component_version": "1.0",
            "component_type": "INVALID_TYPE",
            "ecosystem": "npm",
            "license": "MIT",
        },
        headers=AUTH,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /cyclonedx (new GET endpoint)
# ---------------------------------------------------------------------------

def test_get_cyclonedx_structure(client):
    _register(client, org_id="org-cdx", project="cdx-proj")
    resp = client.get(
        f"{BASE}/cyclonedx",
        params={"org_id": "org-cdx", "project_name": "cdx-proj"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["bomFormat"] == "CycloneDX"
    assert body["specVersion"] == "1.6"
    assert "components" in body
    assert "metadata" in body


def test_get_cyclonedx_has_registered_component(client):
    _register(client, org_id="org-cdx2", project="cdx2-proj", name="numpy", version="1.26.0")
    resp = client.get(
        f"{BASE}/cyclonedx",
        params={"org_id": "org-cdx2", "project_name": "cdx2-proj"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    comp_names = [c["name"] for c in resp.json()["components"]]
    assert "numpy" in comp_names


def test_get_cyclonedx_records_export_id(client):
    _register(client, org_id="org-cdx3", project="cdx3-proj")
    resp = client.get(
        f"{BASE}/cyclonedx",
        params={"org_id": "org-cdx3", "project_name": "cdx3-proj"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert "_export_id" in resp.json()


def test_get_cyclonedx_requires_auth(client):
    resp = client.get(
        f"{BASE}/cyclonedx",
        params={"org_id": "org1", "project_name": "proj1"},
        headers=NO_AUTH,
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /spdx (new GET endpoint)
# ---------------------------------------------------------------------------

def test_get_spdx_structure(client):
    _register(client, org_id="org-spdx", project="spdx-proj")
    resp = client.get(
        f"{BASE}/spdx",
        params={"org_id": "org-spdx", "project_name": "spdx-proj"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["spdxVersion"] == "SPDX-2.3"
    assert body["dataLicense"] == "CC0-1.0"
    assert "packages" in body
    assert "documentNamespace" in body


def test_get_spdx_has_packages(client):
    _register(client, org_id="org-spdx2", project="spdx2-proj", name="boto3", version="1.28.0")
    resp = client.get(
        f"{BASE}/spdx",
        params={"org_id": "org-spdx2", "project_name": "spdx2-proj"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    pkg_names = [p["name"] for p in resp.json()["packages"]]
    assert "boto3" in pkg_names


def test_get_spdx_records_export_id(client):
    _register(client, org_id="org-spdx3", project="spdx3-proj")
    resp = client.get(
        f"{BASE}/spdx",
        params={"org_id": "org-spdx3", "project_name": "spdx3-proj"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert "_export_id" in resp.json()


def test_get_spdx_requires_auth(client):
    resp = client.get(
        f"{BASE}/spdx",
        params={"org_id": "org1", "project_name": "proj1"},
        headers=NO_AUTH,
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# POST /generate/cyclonedx and /generate/spdx
# ---------------------------------------------------------------------------

def test_post_generate_cyclonedx(client):
    _register(client, org_id="org-pgcdx", project="pgcdx-proj")
    resp = client.post(
        f"{BASE}/generate/cyclonedx",
        json={"org_id": "org-pgcdx", "project_name": "pgcdx-proj", "version_tag": "2.0"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["bomFormat"] == "CycloneDX"
    assert body["specVersion"] == "1.6"


def test_post_generate_spdx(client):
    _register(client, org_id="org-pgspdx", project="pgspdx-proj")
    resp = client.post(
        f"{BASE}/generate/spdx",
        json={"org_id": "org-pgspdx", "project_name": "pgspdx-proj"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["spdxVersion"] == "SPDX-2.3"


# ---------------------------------------------------------------------------
# GET /projects, summary, history
# ---------------------------------------------------------------------------

def test_list_projects(client):
    _register(client, org_id="org-proj-list", project="listed-proj")
    resp = client.get(
        f"{BASE}/projects",
        params={"org_id": "org-proj-list"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    names = [p["project_name"] for p in resp.json()]
    assert "listed-proj" in names


def test_project_summary(client):
    _register(client, org_id="org-summary", project="summary-proj")
    resp = client.get(
        f"{BASE}/projects/summary-proj/summary",
        params={"org_id": "org-summary"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["project_name"] == "summary-proj"
    assert body["component_count"] >= 1


def test_export_history_after_generate(client):
    org_id, project = "org-hist", "hist-proj"
    _register(client, org_id=org_id, project=project)
    client.get(
        f"{BASE}/cyclonedx",
        params={"org_id": org_id, "project_name": project},
        headers=AUTH,
    )
    resp = client.get(
        f"{BASE}/projects/{project}/history",
        params={"org_id": org_id},
        headers=AUTH,
    )
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) >= 1
    assert history[0]["format"] in ("cyclonedx", "spdx")


# ---------------------------------------------------------------------------
# GET /search
# ---------------------------------------------------------------------------

def test_search_by_name(client):
    _register(client, org_id="org-search", project="search-proj", name="pendulum")
    resp = client.get(
        f"{BASE}/search",
        params={"org_id": "org-search", "q": "pendulum"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    results = resp.json()
    assert any(r["component_name"] == "pendulum" for r in results)


# ---------------------------------------------------------------------------
# Vuln tracking
# ---------------------------------------------------------------------------

def test_vuln_appears_in_cyclonedx(client):
    org_id, project = "org-vuln", "vuln-proj"
    comp = _register(client, org_id=org_id, project=project, name="openssl", version="3.0.0")
    comp_id = comp["id"]

    resp = client.post(
        f"{BASE}/components/{comp_id}/vulns",
        json={
            "org_id": org_id,
            "cve_id": "CVE-2023-1234",
            "severity": "critical",
            "cvss_score": 9.8,
            "affects_version": "3.0.0",
        },
        headers=AUTH,
    )
    assert resp.status_code == 201

    resp = client.get(
        f"{BASE}/cyclonedx",
        params={"org_id": org_id, "project_name": project},
        headers=AUTH,
    )
    assert resp.status_code == 200
    vuln_ids = [v["id"] for v in resp.json().get("vulnerabilities", [])]
    assert "CVE-2023-1234" in vuln_ids


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_cyclonedx(client):
    """org-A components must not appear in org-B CycloneDX export."""
    _register(client, org_id="org-iso-A", project="shared-proj", name="secret-lib")
    resp = client.get(
        f"{BASE}/cyclonedx",
        params={"org_id": "org-iso-B", "project_name": "shared-proj"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    comp_names = [c["name"] for c in resp.json().get("components", [])]
    assert "secret-lib" not in comp_names
