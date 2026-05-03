"""Router-level HTTP tests for Google Artifact Registry (GAR) v1 pass-through API.

Covers /api/v1/gar/* via FastAPI TestClient with a stub httpx.Client so no real
GAR call is made and no actual JWT signing is performed (the stubbed token-uri
exchange feeds a synthetic access_token straight to the request path).

Tests:
1.  GET /                                                                  — capability summary unavailable
2.  GET /                                                                  — capability summary ok
3.  GET .../locations                                                      — list locations
4.  GET .../repositories                                                   — list repositories with paging
5.  GET .../packages                                                       — list packages with filter + orderBy
6.  GET .../versions                                                       — list versions with view + paging
7.  GET .../dockerImages                                                   — list docker images with filter
8.  GET .../files                                                          — list files
9.  GET .../:getIamPolicy                                                  — IAM policy bindings
10. lookup endpoint returns 503 when env unset
11. upstream 404 surfaces as 404 with payload echo
12. token reuse — second call does not re-exchange (cached)
"""

from __future__ import annotations

import sys
import time
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

import apps.api.gar_router as _router_mod
from apps.api.gar_router import router
from core.gar_engine import GAREngine, reset_gar_engine


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
    """Captures requests and returns scripted responses keyed by (method, path-suffix).

    Special-cases the OAuth2 token endpoint: any POST to oauth2.googleapis.com/token
    returns a synthetic access_token unless overridden in routes.
    """

    BASE = "https://artifactregistry.googleapis.com/"
    TOKEN_URI = "https://oauth2.googleapis.com/token"

    def __init__(self, routes: Optional[Dict[str, _StubResponse]] = None) -> None:
        self.routes: Dict[str, _StubResponse] = routes or {}
        self.calls: List[Dict[str, Any]] = []
        self.token_calls: int = 0

    def set(self, method: str, suffix: str, response: _StubResponse) -> None:
        self.routes[f"{method.upper()} {suffix}"] = response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,  # noqa: A002
        data: Any = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Any = None,
    ) -> _StubResponse:
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "json": json,
                "data": data,
                "params": params,
                "headers": headers,
                "auth": auth,
            }
        )
        # Token exchange
        if url == self.TOKEN_URI:
            self.token_calls += 1
            override = self.routes.get(f"POST {self.TOKEN_URI}")
            if override is not None:
                return override
            return _StubResponse(
                200,
                {
                    "access_token": "ya29.stub-access-token",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        # GAR API
        suffix = url[len(self.BASE):] if url.startswith(self.BASE) else url
        self.calls[-1]["suffix"] = suffix
        key = f"{method.upper()} {suffix}"
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
    reset_gar_engine()
    yield
    reset_gar_engine()


def _build_app(engine: GAREngine) -> TestClient:
    """Mount the router with engine injection."""
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> GAREngine:
    """Engine configured via direct cred injection (bypasses keyfile read).

    The cred dict carries enough for token-exchange path to run, but the stub
    short-circuits the actual JWT sign + exchange — we override _sign_jwt to a
    no-op string so tests never depend on `cryptography` being installed.
    """
    engine = GAREngine(
        credentials_path="/non-existent-but-bypassed.json",
        client=stub,  # type: ignore[arg-type]
    )
    # Pre-load creds to bypass keyfile read
    engine._creds = {  # type: ignore[attr-defined]
        "type": "service_account",
        "client_email": "ci@aldeci-test.iam.gserviceaccount.com",
        "private_key": "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n",
        "token_uri": StubHTTPXClient.TOKEN_URI,
    }
    engine._creds_load_attempted = True  # type: ignore[attr-defined]
    # Skip RS256 signing — return dummy assertion; stub accepts any
    engine._sign_jwt = lambda: "stub.jwt.assertion"  # type: ignore[assignment,method-assign]
    return engine


@pytest.fixture
def unavailable_engine() -> GAREngine:
    return GAREngine(
        credentials_path="",
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: GAREngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/gar/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Google Artifact Registry"
    assert body["google_app_creds_present"] is False
    assert body["status"] == "unavailable"
    expected_endpoints = {
        "/v1/projects/{p}/locations",
        "/v1/projects/{p}/locations/{loc}/repositories",
        "/v1/projects/{p}/locations/{loc}/repositories/{repo}/packages",
        "/v1/projects/{p}/locations/{loc}/repositories/{repo}/packages/{pkg}/versions",
        "/v1/projects/{p}/locations/{loc}/repositories/{repo}/dockerImages",
    }
    assert expected_endpoints.issubset(set(body["endpoints"]))


# ---------------------------------------------------------------------------
# 2. Capability summary — ok
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: GAREngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/gar/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["google_app_creds_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. List locations
# ---------------------------------------------------------------------------


def test_list_locations(configured_engine: GAREngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "v1/projects/aldeci-prod/locations",
        _StubResponse(
            200,
            {
                "locations": [
                    {
                        "name": "projects/aldeci-prod/locations/us-central1",
                        "locationId": "us-central1",
                        "displayName": "us-central1",
                        "labels": {"cloud.googleapis.com/region": "us-central1"},
                        "metadata": {},
                    },
                    {
                        "name": "projects/aldeci-prod/locations/europe-west1",
                        "locationId": "europe-west1",
                        "displayName": "europe-west1",
                        "labels": {},
                        "metadata": {},
                    },
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/gar/v1/projects/aldeci-prod/locations")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["locations"]) == 2
    assert body["locations"][0]["locationId"] == "us-central1"
    assert (
        body["locations"][0]["labels"]["cloud.googleapis.com/region"] == "us-central1"
    )
    # Bearer header was attached
    api_call = next(c for c in stub.calls if c.get("suffix"))
    assert api_call["headers"]["Authorization"] == "Bearer ya29.stub-access-token"


# ---------------------------------------------------------------------------
# 4. List repositories with paging
# ---------------------------------------------------------------------------


def test_list_repositories_with_paging(
    configured_engine: GAREngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "v1/projects/aldeci-prod/locations/us-central1/repositories",
        _StubResponse(
            200,
            {
                "repositories": [
                    {
                        "name": "projects/aldeci-prod/locations/us-central1/repositories/containers",
                        "format": "DOCKER",
                        "mode": "STANDARD_REPOSITORY",
                        "description": "Production container images",
                        "labels": {"env": "prod"},
                        "createTime": "2024-01-01T00:00:00Z",
                        "updateTime": "2024-08-01T00:00:00Z",
                        "kmsKeyName": "projects/aldeci-prod/locations/us-central1/keyRings/r1/cryptoKeys/k1",
                        "dockerConfig": {"immutableTags": True},
                        "sizeBytes": "12345678901",
                        "satisfiesPzs": True,
                        "satisfiesPzi": False,
                        "cleanupPolicies": {
                            "delete-untagged": {
                                "id": "delete-untagged",
                                "action": "DELETE",
                            }
                        },
                        "cleanupPolicyDryRun": False,
                    }
                ],
                "nextPageToken": "next-page-1",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gar/v1/projects/aldeci-prod/locations/us-central1/"
        "repositories?pageSize=50&pageToken=tok-0"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["repositories"]) == 1
    r = body["repositories"][0]
    assert r["format"] == "DOCKER"
    assert r["mode"] == "STANDARD_REPOSITORY"
    assert r["dockerConfig"]["immutableTags"] is True
    assert r["satisfiesPzs"] is True
    assert r["sizeBytes"] == "12345678901"
    assert body["nextPageToken"] == "next-page-1"
    api_call = next(
        c for c in stub.calls if c.get("suffix", "").endswith("/repositories")
    )
    params = api_call["params"]
    assert params["pageSize"] == 50
    assert params["pageToken"] == "tok-0"


# ---------------------------------------------------------------------------
# 5. List packages with filter + orderBy
# ---------------------------------------------------------------------------


def test_list_packages_with_filter(
    configured_engine: GAREngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "v1/projects/aldeci-prod/locations/us-central1/repositories/containers/packages",
        _StubResponse(
            200,
            {
                "packages": [
                    {
                        "name": "projects/aldeci-prod/locations/us-central1/repositories/containers/packages/aldeci-api",
                        "displayName": "aldeci-api",
                        "createTime": "2024-02-01T00:00:00Z",
                        "updateTime": "2024-09-01T00:00:00Z",
                        "annotations": {"team": "platform"},
                    }
                ],
                "nextPageToken": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gar/v1/projects/aldeci-prod/locations/us-central1/"
        "repositories/containers/packages?pageSize=25&filter=name%3D%22aldeci-api%22&orderBy=updateTime+desc"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["packages"]) == 1
    assert body["packages"][0]["displayName"] == "aldeci-api"
    assert body["packages"][0]["annotations"]["team"] == "platform"
    api_call = next(c for c in stub.calls if c.get("suffix", "").endswith("/packages"))
    params = api_call["params"]
    assert params["filter"] == 'name="aldeci-api"'
    assert params["orderBy"] == "updateTime desc"


# ---------------------------------------------------------------------------
# 6. List versions with view + paging
# ---------------------------------------------------------------------------


def test_list_versions_with_view(
    configured_engine: GAREngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "v1/projects/aldeci-prod/locations/us-central1/repositories/containers/packages/aldeci-api/versions",
        _StubResponse(
            200,
            {
                "versions": [
                    {
                        "name": ("projects/aldeci-prod/locations/us-central1/repositories/"
                                  "containers/packages/aldeci-api/versions/sha256:abc123"),
                        "description": "v1.0.0 build",
                        "createTime": "2024-08-01T10:00:00Z",
                        "updateTime": "2024-08-02T10:00:00Z",
                        "relatedTags": [
                            {
                                "name": "projects/aldeci-prod/locations/.../tags/v1.0.0",
                                "version": "v1.0.0",
                            },
                            {
                                "name": "projects/aldeci-prod/locations/.../tags/latest",
                                "version": "v1.0.0",
                            },
                        ],
                        "metadata": {"buildId": "build-9001"},
                        "annotations": {"sbom.attached": "true"},
                    }
                ],
                "nextPageToken": "ver-tok-2",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gar/v1/projects/aldeci-prod/locations/us-central1/"
        "repositories/containers/packages/aldeci-api/versions?view=FULL&pageSize=10"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["versions"]) == 1
    v = body["versions"][0]
    assert v["description"] == "v1.0.0 build"
    assert len(v["relatedTags"]) == 2
    assert v["relatedTags"][0]["version"] == "v1.0.0"
    assert v["annotations"]["sbom.attached"] == "true"
    assert body["nextPageToken"] == "ver-tok-2"
    api_call = next(c for c in stub.calls if c.get("suffix", "").endswith("/versions"))
    assert api_call["params"]["view"] == "FULL"


# ---------------------------------------------------------------------------
# 7. List Docker images with filter
# ---------------------------------------------------------------------------


def test_list_docker_images(
    configured_engine: GAREngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "v1/projects/aldeci-prod/locations/us-central1/repositories/containers/dockerImages",
        _StubResponse(
            200,
            {
                "dockerImages": [
                    {
                        "name": ("projects/aldeci-prod/locations/us-central1/repositories/"
                                  "containers/dockerImages/aldeci-api@sha256:abc123"),
                        "uri": "us-central1-docker.pkg.dev/aldeci-prod/containers/aldeci-api@sha256:abc123",
                        "tags": ["v1.0.0", "latest"],
                        "imageSizeBytes": "98765432",
                        "uploadTime": "2024-08-01T10:00:00Z",
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "buildTime": "2024-08-01T09:00:00Z",
                        "updateTime": "2024-08-02T10:00:00Z",
                    }
                ],
                "nextPageToken": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gar/v1/projects/aldeci-prod/locations/us-central1/"
        "repositories/containers/dockerImages?orderBy=uploadTime+desc&filter=tags%3A%22v1.0.0%22"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["dockerImages"]) == 1
    img = body["dockerImages"][0]
    assert img["tags"] == ["v1.0.0", "latest"]
    assert img["imageSizeBytes"] == "98765432"
    assert (
        img["uri"]
        == "us-central1-docker.pkg.dev/aldeci-prod/containers/aldeci-api@sha256:abc123"
    )
    api_call = next(
        c for c in stub.calls if c.get("suffix", "").endswith("/dockerImages")
    )
    assert api_call["params"]["filter"] == 'tags:"v1.0.0"'
    assert api_call["params"]["orderBy"] == "uploadTime desc"


# ---------------------------------------------------------------------------
# 8. List files
# ---------------------------------------------------------------------------


def test_list_files(configured_engine: GAREngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "v1/projects/aldeci-prod/locations/us-central1/repositories/containers/files",
        _StubResponse(
            200,
            {
                "files": [
                    {
                        "name": ("projects/aldeci-prod/locations/us-central1/repositories/"
                                  "containers/files/sha256:abc123"),
                        "sizeBytes": "98765432",
                        "hashes": [
                            {"type": "SHA256", "value": "abc123def456"},
                            {"type": "MD5", "value": "deadbeef"},
                        ],
                        "createTime": "2024-08-01T10:00:00Z",
                        "updateTime": "2024-08-02T10:00:00Z",
                        "owner": "user@aldeci.example",
                        "fetchTime": "2024-08-01T10:00:00Z",
                        "annotations": {"sbom.attached": "true"},
                    }
                ],
                "nextPageToken": "file-tok-3",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gar/v1/projects/aldeci-prod/locations/us-central1/"
        "repositories/containers/files?pageSize=20"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["files"]) == 1
    f = body["files"][0]
    assert f["sizeBytes"] == "98765432"
    assert {h["type"] for h in f["hashes"]} == {"SHA256", "MD5"}
    assert f["annotations"]["sbom.attached"] == "true"
    assert body["nextPageToken"] == "file-tok-3"


# ---------------------------------------------------------------------------
# 9. IAM policy
# ---------------------------------------------------------------------------


def test_get_iam_policy(configured_engine: GAREngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "v1/projects/aldeci-prod/locations/us-central1/repositories/containers:getIamPolicy",
        _StubResponse(
            200,
            {
                "version": 3,
                "etag": "BwYABCDEF=",
                "bindings": [
                    {
                        "role": "roles/artifactregistry.reader",
                        "members": [
                            "user:alice@aldeci.example",
                            "serviceAccount:ci@aldeci-prod.iam.gserviceaccount.com",
                        ],
                    },
                    {
                        "role": "roles/artifactregistry.writer",
                        "members": ["group:platform@aldeci.example"],
                        "condition": {
                            "title": "expires-2025",
                            "description": "expires end of 2025",
                            "expression": "request.time < timestamp(\"2026-01-01T00:00:00Z\")",
                        },
                    },
                ],
                "auditConfigs": [
                    {
                        "service": "artifactregistry.googleapis.com",
                        "auditLogConfigs": [{"logType": "DATA_READ"}],
                    }
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gar/v1/projects/aldeci-prod/locations/us-central1/"
        "repositories/containers:getIamPolicy?options.requestedPolicyVersion=3"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 3
    assert body["etag"] == "BwYABCDEF="
    assert len(body["bindings"]) == 2
    reader = next(b for b in body["bindings"] if b["role"].endswith(".reader"))
    assert "user:alice@aldeci.example" in reader["members"]
    writer = next(b for b in body["bindings"] if b["role"].endswith(".writer"))
    assert writer["condition"]["title"] == "expires-2025"
    assert body["auditConfigs"][0]["service"] == "artifactregistry.googleapis.com"
    api_call = next(
        c for c in stub.calls if c.get("suffix", "").endswith(":getIamPolicy")
    )
    assert api_call["params"]["options.requestedPolicyVersion"] == 3


# ---------------------------------------------------------------------------
# 10. Lookup endpoint returns 503 when env unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(
    unavailable_engine: GAREngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/gar/v1/projects/aldeci-prod/locations")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "gar_unavailable"


# ---------------------------------------------------------------------------
# 11. Upstream 404 surfaces with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: GAREngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "v1/projects/missing/locations/us-central1/repositories",
        _StubResponse(
            404,
            {"error": {"code": 404, "message": "Project missing not found",
                        "status": "NOT_FOUND"}},
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gar/v1/projects/missing/locations/us-central1/repositories"
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "gar_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["error"]["status"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# 12. Token reuse — second call does not re-exchange
# ---------------------------------------------------------------------------


def test_token_is_cached_across_calls(
    configured_engine: GAREngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "v1/projects/aldeci-prod/locations",
        _StubResponse(200, {"locations": []}),
    )
    client = _build_app(configured_engine)
    resp1 = client.get("/api/v1/gar/v1/projects/aldeci-prod/locations")
    resp2 = client.get("/api/v1/gar/v1/projects/aldeci-prod/locations")
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    # Token endpoint should have been hit exactly once
    assert stub.token_calls == 1
