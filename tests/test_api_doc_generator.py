"""Tests for the ALDECI API Documentation Generator.

Tests cover:
- Static router file parsing / endpoint scanning
- OpenAPI spec structure (info, paths, components, security)
- Postman Collection v2.1 format
- Endpoint stats calculation
- Markdown summary content
- Security domain grouping
- Filtering in list_endpoints
- Edge cases (empty router dirs, missing tags)
"""

from __future__ import annotations

import json
import os
import tempfile
import textwrap
from pathlib import Path
from typing import List

import pytest

# Minimal env setup — must happen before any ALDECI imports
os.environ.setdefault("FIXOPS_MODE", "demo")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-32-chars-minimum-ok!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.api_doc_generator import APIDocGenerator, EndpointDoc


# ===========================================================================
# Helpers
# ===========================================================================


def _make_router_file(tmp_dir: Path, name: str, content: str) -> Path:
    """Write a fake router file into tmp_dir and return its path."""
    p = tmp_dir / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


SAMPLE_ROUTER_CONTENT = """\
    from fastapi import APIRouter
    router = APIRouter(prefix="/api/v1/sample", tags=["sample"])

    @router.get("/items", summary="List items", description="Returns all items.")
    async def list_items():
        pass

    @router.post("/items", summary="Create item", description="Create a new item.")
    async def create_item():
        pass

    @router.get("/items/{id}", summary="Get item", description="Fetch single item.")
    async def get_item(id: str):
        pass

    @router.delete("/items/{id}", summary="Delete item")
    async def delete_item(id: str):
        pass
"""

MINIMAL_ROUTER_CONTENT = """\
    from fastapi import APIRouter
    router = APIRouter(prefix="/api/v1/minimal", tags=["minimal"])

    @router.get("/health")
    async def health():
        return {"status": "ok"}
"""


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def tmp_routers(tmp_path: Path) -> Path:
    """Create a temp directory with a few fake router files."""
    _make_router_file(tmp_path, "sample_router.py", SAMPLE_ROUTER_CONTENT)
    _make_router_file(tmp_path, "minimal_router.py", MINIMAL_ROUTER_CONTENT)
    return tmp_path


@pytest.fixture
def generator(tmp_routers: Path) -> APIDocGenerator:
    """APIDocGenerator pointed at the temp router directory."""
    return APIDocGenerator(routers_dir=tmp_routers)


# ===========================================================================
# 1. Endpoint scanning
# ===========================================================================


def test_scan_routers_returns_list(generator: APIDocGenerator) -> None:
    """scan_routers() should return a non-empty list of EndpointDoc objects."""
    endpoints = generator.scan_routers()
    assert isinstance(endpoints, list)
    assert len(endpoints) > 0


def test_scan_routers_finds_all_methods(generator: APIDocGenerator) -> None:
    """All HTTP methods declared in sample_router.py should be found."""
    endpoints = generator.scan_routers()
    methods = {ep.method.lower() for ep in endpoints}
    assert "get" in methods
    assert "post" in methods
    assert "delete" in methods


def test_scan_routers_builds_full_path(generator: APIDocGenerator) -> None:
    """Endpoint paths should be prefixed correctly."""
    endpoints = generator.scan_routers()
    paths = {ep.path for ep in endpoints}
    assert "/api/v1/sample/items" in paths
    assert "/api/v1/minimal/health" in paths


def test_scan_routers_extracts_summary(generator: APIDocGenerator) -> None:
    """Summary attribute should be populated from the decorator argument."""
    endpoints = generator.scan_routers()
    summaries = {ep.summary for ep in endpoints if ep.summary}
    assert "List items" in summaries
    assert "Create item" in summaries


def test_scan_routers_extracts_tags(generator: APIDocGenerator) -> None:
    """Tags should be extracted from the APIRouter declaration."""
    endpoints = generator.scan_routers()
    for ep in endpoints:
        if "sample" in ep.path:
            assert "sample" in ep.tags
            break
    else:
        pytest.fail("No sample endpoint found")


def test_scan_routers_caches_results(generator: APIDocGenerator) -> None:
    """Calling scan_routers() twice should return the same object (cached)."""
    first = generator.scan_routers()
    second = generator.scan_routers()
    assert first is second


def test_scan_routers_skips_non_router_files(tmp_path: Path) -> None:
    """Files not matching *_router.py / *_routes.py should be ignored."""
    (tmp_path / "helpers.py").write_text("x = 1")
    (tmp_path / "models.py").write_text("class Foo: pass")
    gen = APIDocGenerator(routers_dir=tmp_path)
    assert gen.scan_routers() == []


# ===========================================================================
# 2. OpenAPI spec structure
# ===========================================================================


def test_openapi_spec_has_required_keys(generator: APIDocGenerator) -> None:
    """The spec should contain openapi, info, paths, and components."""
    spec = generator.generate_openapi_spec(include_examples=False)
    for key in ("openapi", "info", "paths", "components"):
        assert key in spec, f"Missing key: {key}"


def test_openapi_spec_version_is_3_1(generator: APIDocGenerator) -> None:
    """Spec must declare OpenAPI 3.1.x."""
    spec = generator.generate_openapi_spec()
    assert spec["openapi"].startswith("3.1")


def test_openapi_spec_has_security_schemes(generator: APIDocGenerator) -> None:
    """Security schemes (ApiKeyAuth, BearerAuth) must be present."""
    spec = generator.generate_openapi_spec()
    schemes = spec.get("components", {}).get("securitySchemes", {})
    assert "ApiKeyAuth" in schemes
    assert "BearerAuth" in schemes


def test_openapi_spec_paths_populated(generator: APIDocGenerator) -> None:
    """paths dict should not be empty."""
    spec = generator.generate_openapi_spec()
    assert len(spec["paths"]) > 0


def test_openapi_spec_info_block(generator: APIDocGenerator) -> None:
    """Info block should have title and version."""
    spec = generator.generate_openapi_spec()
    info = spec["info"]
    assert "title" in info
    assert "version" in info


def test_openapi_spec_includes_examples_flag(generator: APIDocGenerator) -> None:
    """include_examples=False should still produce a valid spec."""
    spec = generator.generate_openapi_spec(include_examples=False)
    assert spec["openapi"].startswith("3")


# ===========================================================================
# 3. Postman Collection
# ===========================================================================


def test_postman_collection_has_info(generator: APIDocGenerator) -> None:
    """Postman collection must have an info block with name and schema."""
    collection = generator.generate_postman_collection()
    assert "info" in collection
    assert "name" in collection["info"]
    assert "schema" in collection["info"]


def test_postman_collection_schema_version(generator: APIDocGenerator) -> None:
    """Postman schema URL must reference v2.1."""
    collection = generator.generate_postman_collection()
    assert "v2.1" in collection["info"]["schema"]


def test_postman_collection_has_items(generator: APIDocGenerator) -> None:
    """Postman collection must have at least one folder/item."""
    collection = generator.generate_postman_collection()
    assert len(collection.get("item", [])) > 0


def test_postman_collection_has_variables(generator: APIDocGenerator) -> None:
    """Postman collection should define BASE_URL and ALDECI_API_KEY variables."""
    collection = generator.generate_postman_collection()
    var_keys = {v["key"] for v in collection.get("variable", [])}
    assert "BASE_URL" in var_keys
    assert "ALDECI_API_KEY" in var_keys


def test_postman_collection_serialisable(generator: APIDocGenerator) -> None:
    """Postman collection must be JSON-serialisable."""
    collection = generator.generate_postman_collection()
    serialised = json.dumps(collection)
    assert len(serialised) > 10


# ===========================================================================
# 4. Stats calculation
# ===========================================================================


def test_count_endpoints_by_tag_returns_dict(generator: APIDocGenerator) -> None:
    """count_endpoints_by_tag() should return a non-empty dict."""
    counts = generator.count_endpoints_by_tag()
    assert isinstance(counts, dict)
    assert len(counts) > 0


def test_count_endpoints_by_tag_values_are_positive(generator: APIDocGenerator) -> None:
    """All tag counts should be positive integers."""
    counts = generator.count_endpoints_by_tag()
    for tag, count in counts.items():
        assert count > 0, f"Tag {tag!r} has zero count"


def test_count_endpoints_total_matches_scan(generator: APIDocGenerator) -> None:
    """Sum of all tag counts should be >= total endpoints (endpoints can have multiple tags)."""
    endpoints = generator.scan_routers()
    counts = generator.count_endpoints_by_tag()
    total_from_tags = sum(counts.values())
    # An endpoint with N tags is counted N times
    assert total_from_tags >= len(endpoints)


def test_get_endpoints_by_security_domain_returns_dict(generator: APIDocGenerator) -> None:
    """get_endpoints_by_security_domain() should return a dict of lists."""
    domains = generator.get_endpoints_by_security_domain()
    assert isinstance(domains, dict)
    for domain, eps in domains.items():
        assert isinstance(eps, list)


# ===========================================================================
# 5. Markdown summary
# ===========================================================================


def test_markdown_summary_has_title(generator: APIDocGenerator) -> None:
    """Markdown output should start with the API title as an H1 heading."""
    md = generator.export_markdown_summary()
    assert md.startswith("# ")


def test_markdown_summary_has_authentication_section(generator: APIDocGenerator) -> None:
    """Markdown should contain an Authentication section."""
    md = generator.export_markdown_summary()
    assert "## Authentication" in md


def test_markdown_summary_has_overview_section(generator: APIDocGenerator) -> None:
    """Markdown should contain an Overview section with endpoint count."""
    md = generator.export_markdown_summary()
    assert "## Overview" in md
    assert "Total endpoints" in md


def test_markdown_summary_has_rate_limiting_section(generator: APIDocGenerator) -> None:
    """Markdown should describe rate limiting."""
    md = generator.export_markdown_summary()
    assert "Rate Limit" in md or "rate limit" in md.lower()


def test_markdown_summary_has_endpoints_section(generator: APIDocGenerator) -> None:
    """Markdown should have an Endpoints by Security Domain section."""
    md = generator.export_markdown_summary()
    assert "Endpoints by Security Domain" in md or "Security Domain" in md


# ===========================================================================
# 6. EndpointDoc dataclass
# ===========================================================================


def test_endpoint_doc_to_dict() -> None:
    """EndpointDoc.to_dict() should contain all expected keys."""
    ep = EndpointDoc(
        path="/api/v1/test",
        method="get",
        tags=["test"],
        summary="Test endpoint",
        description="A test.",
        auth_required=True,
        rate_limited=True,
    )
    d = ep.to_dict()
    for key in ("path", "method", "tags", "summary", "description", "auth_required", "rate_limited"):
        assert key in d, f"Missing key in to_dict(): {key}"


def test_endpoint_doc_method_uppercase_in_dict() -> None:
    """to_dict() should return method in uppercase."""
    ep = EndpointDoc(path="/x", method="post")
    assert ep.to_dict()["method"] == "POST"


# ===========================================================================
# 7. Edge cases
# ===========================================================================


def test_empty_routers_dir_returns_empty_list(tmp_path: Path) -> None:
    """An empty router directory should yield no endpoints."""
    gen = APIDocGenerator(routers_dir=tmp_path)
    assert gen.scan_routers() == []


def test_openapi_spec_from_empty_dir(tmp_path: Path) -> None:
    """generate_openapi_spec() on empty dir should still return a valid shell spec."""
    gen = APIDocGenerator(routers_dir=tmp_path)
    spec = gen.generate_openapi_spec()
    assert "openapi" in spec
    assert "paths" in spec


def test_postman_collection_from_empty_dir(tmp_path: Path) -> None:
    """generate_postman_collection() on empty dir should return valid (empty) collection."""
    gen = APIDocGenerator(routers_dir=tmp_path)
    collection = gen.generate_postman_collection()
    assert "info" in collection
    assert collection["item"] == []


def test_markdown_summary_no_crash_on_empty(tmp_path: Path) -> None:
    """export_markdown_summary() should not raise even with no endpoints."""
    gen = APIDocGenerator(routers_dir=tmp_path)
    md = gen.export_markdown_summary()
    assert isinstance(md, str)
    assert len(md) > 0


def test_real_routers_dir_has_many_endpoints() -> None:
    """Scanning the real suite-api router directory should find many endpoints."""
    gen = APIDocGenerator()  # uses default _ROUTERS_DIR
    endpoints = gen.scan_routers()
    # Codebase has 64+ router files; we expect at least 50 endpoints parsed
    assert len(endpoints) >= 50, f"Expected >=50, got {len(endpoints)}"
