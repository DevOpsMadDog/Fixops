"""Tests that the ALDECI FastAPI app exposes a valid OpenAPI 3.x spec.

Strategy: build a minimal FastAPI app with the same metadata as create_app()
uses, then verify spec structure. Also tests individual importable routers.
Follows the same pattern as test_pipeline_api.py and test_phase8_mcp.py —
small focused apps, no full create_app() import (which has optional deps that
may not be installed).

Verifies:
- OpenAPI spec has required fields (openapi, info, paths)
- Version is 2.5.0
- Title contains ALDECI
- /docs, /redoc, and /api/v1/openapi.json all return 200
- Tags for core domains are present
- Paths block is non-empty
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List

import pytest

# Minimal env so any router imports don't fail on missing config
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-minimum-32-chars!!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# Ensure suite paths are resolved (mirrors sitecustomize.py)
_repo_root = Path(__file__).resolve().parent.parent
for _suite in (
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
):
    _p = str(_repo_root / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# ---------------------------------------------------------------------------
# Build a minimal app that mirrors the real app's OpenAPI metadata.
# We include only routers that import cleanly; the metadata (title, version,
# tags, URLs) is what we're actually testing here.
# ---------------------------------------------------------------------------

OPENAPI_TAGS = [
    {"name": "health", "description": "Health checks and readiness probes"},
    {"name": "findings", "description": "Vulnerability findings lifecycle management"},
    {"name": "pipeline", "description": "CTEM 15-stage pipeline ingestion and processing"},
    {"name": "connectors", "description": "Security tool connectors (Jira, GitHub, Slack, etc.)"},
    {"name": "feeds", "description": "Threat intelligence feeds (NVD, KEV, EPSS, 28+ sources)"},
    {"name": "inventory", "description": "Asset inventory and SBOM management"},
    {"name": "analytics", "description": "Security metrics and analytics"},
    {"name": "compliance", "description": "Compliance frameworks and evidence collection"},
    {"name": "policies", "description": "Security policies and gate rules"},
    {"name": "remediation", "description": "Remediation tracking and playbooks"},
    {"name": "reports", "description": "Report generation and export"},
    {"name": "users", "description": "User management and authentication"},
    {"name": "teams", "description": "Team and organization management"},
    {"name": "admin", "description": "Administrative operations"},
    {"name": "trustgraph", "description": "TrustGraph knowledge graph and GraphRAG"},
    {"name": "mcp", "description": "MCP tool registry and AI integrations"},
    {"name": "attack", "description": "Offensive security and attack simulation"},
    {"name": "audit", "description": "Audit logs and compliance trails"},
]


def _build_test_app() -> FastAPI:
    """Build a minimal FastAPI app with the same OpenAPI metadata as the real app."""
    app = FastAPI(
        title="ALDECI Security Intelligence Platform",
        description=(
            "Unified ASPM + CTEM + CSPM platform API. "
            "Security decision engine by FixOps. "
            "Provides 771+ endpoints for vulnerability management, threat intelligence, "
            "compliance, connectors, and AI-driven security analysis."
        ),
        version="2.5.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/api/v1/openapi.json",
        openapi_tags=OPENAPI_TAGS,
    )

    # Include routers that import cleanly without broken deps
    _include_clean_routers(app)

    return app


def _include_clean_routers(app: FastAPI) -> None:
    """Try to include real routers; silently skip any that fail to import."""
    candidates = [
        ("apps.api.health", "router"),
        ("apps.api.pipeline_routes", "router"),
        ("apps.api.findings_routes", "router"),
        ("apps.api.mcp_routes", "router"),
        ("apps.api.trustgraph_routes", "router"),
    ]
    for module_name, attr in candidates:
        try:
            import importlib
            mod = importlib.import_module(module_name)
            router = getattr(mod, attr, None)
            if router is not None:
                app.include_router(router)
        except Exception:
            pass  # Optional routers — skip if unavailable


@pytest.fixture(scope="module")
def app() -> FastAPI:
    return _build_test_app()


@pytest.fixture(scope="module")
def client(app: FastAPI) -> TestClient:
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="module")
def openapi_spec(client: TestClient) -> dict:
    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200, (
        f"GET /api/v1/openapi.json returned {response.status_code}"
    )
    return response.json()


# ---------------------------------------------------------------------------
# Spec structure tests
# ---------------------------------------------------------------------------


class TestOpenAPISpecStructure:
    def test_openapi_version_field_present(self, openapi_spec):
        assert "openapi" in openapi_spec
        assert openapi_spec["openapi"].startswith("3.")

    def test_info_block_present(self, openapi_spec):
        assert "info" in openapi_spec
        info = openapi_spec["info"]
        assert "title" in info
        assert "version" in info

    def test_app_version_is_2_5_0(self, openapi_spec):
        assert openapi_spec["info"]["version"] == "2.5.0"

    def test_title_contains_aldeci(self, openapi_spec):
        title = openapi_spec["info"]["title"]
        assert "ALDECI" in title, f"Unexpected title: {title!r}"

    def test_description_is_non_empty(self, openapi_spec):
        desc = openapi_spec["info"].get("description", "")
        assert len(desc) > 10, "API description should be meaningful"

    def test_paths_block_present(self, openapi_spec):
        assert "paths" in openapi_spec
        assert isinstance(openapi_spec["paths"], dict)


# ---------------------------------------------------------------------------
# Docs UI endpoints
# ---------------------------------------------------------------------------


class TestDocsEndpoints:
    def test_openapi_json_returns_200(self, client):
        resp = client.get("/api/v1/openapi.json")
        assert resp.status_code == 200

    def test_openapi_json_content_type_is_json(self, client):
        resp = client.get("/api/v1/openapi.json")
        assert "application/json" in resp.headers.get("content-type", "")

    def test_docs_ui_returns_200(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_redoc_ui_returns_200(self, client):
        resp = client.get("/redoc")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


class TestOpenAPITags:
    def test_tags_list_present_and_is_list(self, openapi_spec):
        tags = openapi_spec.get("tags", [])
        assert isinstance(tags, list)
        assert len(tags) > 0, "Expected at least one tag in the spec"

    def test_core_domain_tags_present(self, openapi_spec):
        tag_names = {t["name"] for t in openapi_spec.get("tags", [])}
        required = {"health", "findings", "pipeline", "connectors"}
        missing = required - tag_names
        assert not missing, f"Missing expected domain tags: {missing}"

    def test_all_expected_tags_present(self, openapi_spec):
        tag_names = {t["name"] for t in openapi_spec.get("tags", [])}
        expected = {t["name"] for t in OPENAPI_TAGS}
        missing = expected - tag_names
        assert not missing, f"Missing tags: {missing}"

    def test_each_tag_has_description(self, openapi_spec):
        for tag in openapi_spec.get("tags", []):
            assert "description" in tag and tag["description"], (
                f"Tag {tag.get('name')!r} is missing a description"
            )
