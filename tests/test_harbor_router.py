"""Router-level HTTP tests for Harbor v2.0 pass-through API.

Covers /api/v1/harbor/* via FastAPI TestClient with a stub httpx.Client
so no real Harbor call is made.

Tests:
1.  GET /                                              — capability summary (unavailable when env unset)
2.  GET /                                              — capability summary (ok when env set)
3.  GET /api/v2.0/health                               — overall + components
4.  GET /api/v2.0/projects                             — list projects with filter params
5.  GET /api/v2.0/projects/{name}/repositories         — list repos
6.  GET .../artifacts                                  — list artifacts with scan_overview + tags
7.  GET .../artifacts/{digest}/additions/vulnerabilities — vuln report (mime-keyed)
8.  POST .../artifacts/{digest}/scan                   — triggers scan, returns 202
9.  DELETE .../artifacts/{digest}                      — returns deleted=true
10. GET /api/v2.0/scanners                             — list scanners
11. POST /api/v2.0/projects/{name}/scanner             — bind scanner
12. unavailable env returns 503 on lookup endpoint
13. upstream 404 surfaces as 404 with payload echo
14. repository name with "/" gets URL-encoded to %2F
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite paths are importable regardless of cwd
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import apps.api.harbor_router as _router_mod
from apps.api.harbor_router import router
from core.harbor_registry_engine import (
    HarborRegistryEngine,
    reset_harbor_registry_engine,
)


# ---------------------------------------------------------------------------
# Stub httpx.Client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(
        self,
        status_code: int,
        json_payload: Any = None,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        self.headers = headers or {}
        if json_payload is not None:
            self.content = b"{}"
        elif text:
            self.content = text.encode("utf-8") if isinstance(text, str) else text
        else:
            self.content = b""

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class StubHTTPXClient:
    """Captures requests and returns scripted responses keyed by (method, path-suffix)."""

    BASE = "https://harbor.example.com/"

    def __init__(self, routes: Optional[Dict[str, _StubResponse]] = None) -> None:
        self.routes: Dict[str, _StubResponse] = routes or {}
        self.calls: List[Dict[str, Any]] = []

    def set(self, method: str, suffix: str, response: _StubResponse) -> None:
        self.routes[f"{method.upper()} {suffix}"] = response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,  # noqa: A002 - mirror httpx signature
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Any = None,
    ) -> _StubResponse:
        suffix = url[len(self.BASE):] if url.startswith(self.BASE) else url
        key = f"{method.upper()} {suffix}"
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "suffix": suffix,
                "json": json,
                "params": params,
                "headers": headers,
                "auth": auth,
            }
        )
        if key in self.routes:
            return self.routes[key]
        return _StubResponse(200, {})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test gets a fresh engine singleton."""
    reset_harbor_registry_engine()
    yield
    reset_harbor_registry_engine()


def _build_app(engine: HarborRegistryEngine) -> TestClient:
    """Mount the router with engine injection."""
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> HarborRegistryEngine:
    return HarborRegistryEngine(
        harbor_url="https://harbor.example.com",
        harbor_username="robot$ci",
        harbor_password="tok-12345",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> HarborRegistryEngine:
    return HarborRegistryEngine(
        harbor_url="",
        harbor_username="",
        harbor_password="",
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: HarborRegistryEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/harbor/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Harbor"
    assert body["harbor_url_present"] is False
    assert body["harbor_username_present"] is False
    assert body["harbor_password_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/api/v2.0/projects",
        "/api/v2.0/projects/{name}/repositories",
        "/api/v2.0/projects/{name}/repositories/{repo}/artifacts",
        "/api/v2.0/scanners",
        "/api/v2.0/health",
    ):
        assert ep in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: HarborRegistryEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/harbor/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["harbor_url_present"] is True
    assert body["harbor_username_present"] is True
    assert body["harbor_password_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. Health
# ---------------------------------------------------------------------------


def test_health(configured_engine: HarborRegistryEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/v2.0/health",
        _StubResponse(
            200,
            {
                "status": "healthy",
                "components": [
                    {"name": "core", "status": "healthy"},
                    {"name": "database", "status": "healthy"},
                    {"name": "registry", "status": "healthy"},
                    {"name": "trivy", "status": "unhealthy", "error": "scanner offline"},
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/harbor/api/v2.0/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert len(body["components"]) == 4
    trivy = next(c for c in body["components"] if c["name"] == "trivy")
    assert trivy["status"] == "unhealthy"
    assert trivy["error"] == "scanner offline"
    # BasicAuth header was attached
    assert stub.calls[0]["auth"] is not None


# ---------------------------------------------------------------------------
# 4. List projects (with filter params)
# ---------------------------------------------------------------------------


def test_list_projects_with_filters(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2.0/projects",
        _StubResponse(
            200,
            [
                {
                    "project_id": 1,
                    "name": "library",
                    "owner_name": "admin",
                    "owner_id": 1,
                    "creation_time": "2024-01-01T00:00:00Z",
                    "update_time": "2024-06-01T00:00:00Z",
                    "deleted": False,
                    "current_user_role_id": 1,
                    "current_user_role_ids": [1],
                    "repo_count": 12,
                    "chart_count": 0,
                    "metadata": {
                        "public": "true",
                        "enable_content_trust": "false",
                        "prevent_vul": "true",
                        "severity": "high",
                        "auto_scan": "true",
                    },
                    "cve_allowlist": {
                        "id": 1,
                        "project_id": 1,
                        "expires_at": 0,
                        "items": [{"cve_id": "CVE-2024-1234"}],
                        "creation_time": "2024-01-01T00:00:00Z",
                        "update_time": "2024-01-01T00:00:00Z",
                    },
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/harbor/api/v2.0/projects?page=2&page_size=20&name=lib&owner=admin&public=true"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    p = body[0]
    assert p["project_id"] == 1
    assert p["name"] == "library"
    assert p["repo_count"] == 12
    assert p["metadata"]["auto_scan"] == "true"
    assert p["cve_allowlist"]["items"][0]["cve_id"] == "CVE-2024-1234"
    # Verify upstream params forwarded correctly
    params = stub.calls[0]["params"]
    assert params["page"] == 2
    assert params["page_size"] == 20
    assert params["name"] == "lib"
    assert params["owner"] == "admin"
    assert params["public"] == "true"


# ---------------------------------------------------------------------------
# 5. List repositories
# ---------------------------------------------------------------------------


def test_list_repositories(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2.0/projects/library/repositories",
        _StubResponse(
            200,
            [
                {
                    "id": 11,
                    "project_id": 1,
                    "name": "library/nginx",
                    "description": "nginx web server",
                    "artifact_count": 4,
                    "pull_count": 850,
                    "creation_time": "2024-02-01T00:00:00Z",
                    "update_time": "2024-08-01T00:00:00Z",
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/harbor/api/v2.0/projects/library/repositories?page=1&page_size=50&q=nginx&sort=-update_time"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["name"] == "library/nginx"
    assert body[0]["artifact_count"] == 4
    assert body[0]["pull_count"] == 850
    params = stub.calls[0]["params"]
    assert params["q"] == "nginx"
    assert params["sort"] == "-update_time"


# ---------------------------------------------------------------------------
# 6. List artifacts with scan_overview + tags
# ---------------------------------------------------------------------------


def test_list_artifacts_with_scan_overview(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2.0/projects/library/repositories/nginx/artifacts",
        _StubResponse(
            200,
            [
                {
                    "id": 101,
                    "type": "IMAGE",
                    "media_type": "application/vnd.docker.container.image.v1+json",
                    "manifest_media_type": "application/vnd.docker.distribution.manifest.v2+json",
                    "project_id": 1,
                    "repository_id": 11,
                    "digest": "sha256:abc123",
                    "size": 132456789,
                    "push_time": "2024-08-01T10:00:00Z",
                    "pull_time": "2024-08-02T05:00:00Z",
                    "extra_attrs": {
                        "architecture": "amd64",
                        "os": "linux",
                        "created": "2024-08-01T09:00:00Z",
                        "config": {"Cmd": ["nginx", "-g", "daemon off;"]},
                    },
                    "annotations": {"org.opencontainers.image.source": "https://github.com/nginx/nginx"},
                    "references": [],
                    "tags": [
                        {
                            "id": 201,
                            "repository_id": 11,
                            "artifact_id": 101,
                            "name": "1.25.3",
                            "push_time": "2024-08-01T10:00:00Z",
                            "pull_time": "2024-08-02T05:00:00Z",
                            "immutable": False,
                            "signed": True,
                        }
                    ],
                    "addition_links": {
                        "vulnerabilities": {"href": "/api/v2.0/...vulnerabilities", "absolute": False}
                    },
                    "scan_overview": {
                        "application/vnd.security.vulnerability.report; version=1.1": {
                            "report": {
                                "vulnerabilities": [
                                    {
                                        "id": "CVE-2024-9999",
                                        "package": "openssl",
                                        "version": "1.1.1k",
                                        "fix_version": "1.1.1l",
                                        "severity": "High",
                                        "description": "stack overflow in TLS handshake",
                                        "links": ["https://nvd.nist.gov/vuln/detail/CVE-2024-9999"],
                                    }
                                ],
                                "severity": "High",
                                "scan_status": "Success",
                                "vulnerability_summary": {
                                    "total": 12,
                                    "fixable": 9,
                                    "summary": {
                                        "Critical": 0,
                                        "High": 1,
                                        "Medium": 4,
                                        "Low": 7,
                                        "Negligible": 0,
                                        "None": 0,
                                        "Unknown": 0,
                                    },
                                },
                            },
                            "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "0.45.0"},
                            "status": "Success",
                        }
                    },
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/harbor/api/v2.0/projects/library/repositories/nginx/artifacts"
        "?page=1&page_size=10&with_tag=true&with_scan_overview=true&with_signature=true"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    a = body[0]
    assert a["digest"] == "sha256:abc123"
    assert a["type"] == "IMAGE"
    assert a["extra_attrs"]["architecture"] == "amd64"
    assert a["tags"][0]["name"] == "1.25.3"
    assert a["tags"][0]["signed"] is True
    so_keys = list(a["scan_overview"].keys())
    assert len(so_keys) == 1
    so = a["scan_overview"][so_keys[0]]
    assert so["status"] == "Success"
    assert so["report"]["severity"] == "High"
    assert so["report"]["vulnerability_summary"]["total"] == 12
    assert so["report"]["vulnerabilities"][0]["id"] == "CVE-2024-9999"
    # Confirm upstream toggles forwarded
    params = stub.calls[0]["params"]
    assert params["with_tag"] == "true"
    assert params["with_scan_overview"] == "true"
    assert params["with_signature"] == "true"


# ---------------------------------------------------------------------------
# 7. Vulnerability-only payload (mime-keyed → unwrapped)
# ---------------------------------------------------------------------------


def test_get_artifact_vulnerabilities_mime_keyed(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2.0/projects/library/repositories/nginx/artifacts/sha256:abc123/additions/vulnerabilities",
        _StubResponse(
            200,
            {
                "application/vnd.security.vulnerability.report; version=1.1": {
                    "report": {
                        "vulnerabilities": [
                            {
                                "id": "CVE-2024-1111",
                                "package": "libcurl",
                                "version": "7.81.0",
                                "fix_version": "7.88.0",
                                "severity": "Critical",
                                "description": "use-after-free in HTTP/2 frame handling",
                                "links": ["https://curl.se/docs/CVE-2024-1111.html"],
                            }
                        ],
                        "severity": "Critical",
                        "scan_status": "Success",
                        "vulnerability_summary": {
                            "total": 1,
                            "fixable": 1,
                            "summary": {
                                "Critical": 1,
                                "High": 0,
                                "Medium": 0,
                                "Low": 0,
                                "Negligible": 0,
                                "None": 0,
                                "Unknown": 0,
                            },
                        },
                    },
                    "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "0.45.0"},
                    "severity": "Critical",
                    "scan_status": "Success",
                    "vulnerability_summary": {
                        "total": 1,
                        "fixable": 1,
                        "summary": {
                            "Critical": 1,
                            "High": 0,
                            "Medium": 0,
                            "Low": 0,
                            "Negligible": 0,
                            "None": 0,
                            "Unknown": 0,
                        },
                    },
                }
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/harbor/api/v2.0/projects/library/repositories/nginx/artifacts/"
        "sha256:abc123/additions/vulnerabilities"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["severity"] == "Critical"
    assert body["scan_status"] == "Success"
    assert body["report"]["vulnerabilities"][0]["id"] == "CVE-2024-1111"
    assert body["scanner"]["vendor"] == "Aqua Security"
    assert body["vulnerability_summary"]["total"] == 1


# ---------------------------------------------------------------------------
# 8. Trigger scan returns 202
# ---------------------------------------------------------------------------


def test_scan_artifact_returns_202(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "api/v2.0/projects/library/repositories/nginx/artifacts/sha256:abc123/scan",
        _StubResponse(202, None, text=""),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/harbor/api/v2.0/projects/library/repositories/nginx/artifacts/sha256:abc123/scan"
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] is True
    assert body["status_code"] == 202


# ---------------------------------------------------------------------------
# 9. Delete artifact
# ---------------------------------------------------------------------------


def test_delete_artifact(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "DELETE",
        "api/v2.0/projects/library/repositories/nginx/artifacts/sha256:abc123",
        _StubResponse(200, None, text=""),
    )
    client = _build_app(configured_engine)
    resp = client.delete(
        "/api/v1/harbor/api/v2.0/projects/library/repositories/nginx/artifacts/sha256:abc123"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["deleted"] is True


# ---------------------------------------------------------------------------
# 10. List scanners
# ---------------------------------------------------------------------------


def test_list_scanners(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2.0/scanners",
        _StubResponse(
            200,
            [
                {
                    "uuid": "abc-uuid-1",
                    "name": "Trivy",
                    "description": "Open-source vulnerability scanner",
                    "url": "http://trivy-adapter:8080",
                    "auth": "Bearer",
                    "access_credential": "redacted",
                    "skip_certVerify": False,
                    "use_internal_addr": True,
                    "disabled": False,
                    "is_default": True,
                    "health": "healthy",
                    "vendor": "Aqua Security",
                    "version": "0.45.0",
                    "adapter": "Trivy",
                    "capabilities": {
                        "consumes_mime_types": [
                            "application/vnd.oci.image.manifest.v1+json",
                            "application/vnd.docker.distribution.manifest.v2+json",
                        ],
                        "produces_mime_types": [
                            "application/vnd.security.vulnerability.report; version=1.1"
                        ],
                    },
                    "properties": {"max_severity": "Critical"},
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/harbor/api/v2.0/scanners?page=1&page_size=10")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    s = body[0]
    assert s["uuid"] == "abc-uuid-1"
    assert s["name"] == "Trivy"
    assert s["is_default"] is True
    assert s["vendor"] == "Aqua Security"
    assert "application/vnd.security.vulnerability.report; version=1.1" in s["capabilities"]["produces_mime_types"]
    assert s["properties"]["max_severity"] == "Critical"


# ---------------------------------------------------------------------------
# 11. Bind scanner to project
# ---------------------------------------------------------------------------


def test_set_project_scanner(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "api/v2.0/projects/library/scanner",
        _StubResponse(200, None, text=""),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/harbor/api/v2.0/projects/library/scanner",
        json={"scanner_id": "abc-uuid-1"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["updated"] is True
    assert body["scanner_id"] == "abc-uuid-1"
    # Verify body forwarded
    assert stub.calls[0]["json"] == {"scanner_id": "abc-uuid-1"}


# ---------------------------------------------------------------------------
# 12. Lookup endpoint returns 503 when env unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(
    unavailable_engine: HarborRegistryEngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/harbor/api/v2.0/projects")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "harbor_registry_unavailable"


# ---------------------------------------------------------------------------
# 13. Upstream 404 surfaces with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2.0/projects/missing/repositories",
        _StubResponse(
            404,
            {"errors": [{"code": "NOT_FOUND", "message": "project missing not found"}]},
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/harbor/api/v2.0/projects/missing/repositories")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "harbor_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["errors"][0]["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# 14. Repository name with "/" gets URL-encoded
# ---------------------------------------------------------------------------


def test_repository_slash_url_encoded(
    configured_engine: HarborRegistryEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2.0/projects/library/repositories/team%2Fbackend/artifacts",
        _StubResponse(200, [{"id": 9, "digest": "sha256:def456", "type": "IMAGE"}]),
    )
    client = _build_app(configured_engine)
    # Call via direct engine helper to ensure quote(safe='') applies
    artifacts = configured_engine.list_artifacts(
        "library", "team/backend", page=1, page_size=10
    )
    assert len(artifacts) == 1
    assert artifacts[0]["digest"] == "sha256:def456"
    assert stub.calls[0]["suffix"].startswith(
        "api/v2.0/projects/library/repositories/team%2Fbackend/artifacts"
    )
