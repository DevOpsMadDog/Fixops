"""Tests for apigee_router — ALDECI.

Spins up a minimal FastAPI app with the Apigee router mounted. Each test
gets an isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * Capability summary reports ``status="unavailable"`` when GOOGLE_APPLICATION_CREDENTIALS
    or APIGEE_ORG is missing.
  * Live endpoints return HTTP 503 when env vars are unset.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real OAuth2 jwt-bearer flow + parsing code paths.
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# RSA key + service-account JSON helpers (generate fresh per test session)
# ---------------------------------------------------------------------------


def _generate_pkey_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


@pytest.fixture(scope="session")
def _pkey_pem() -> str:
    return _generate_pkey_pem()


@pytest.fixture
def _sa_json_path(tmp_path, _pkey_pem) -> str:
    sa = {
        "type": "service_account",
        "project_id": "aldeci-test",
        "private_key_id": "key-id-1",
        "private_key": _pkey_pem,
        "client_email": "aldeci-tester@aldeci-test.iam.gserviceaccount.com",
        "client_id": "1234567890",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://example.com/cert",
    }
    p = tmp_path / "sa.json"
    p.write_text(json.dumps(sa))
    return str(p)


# ---------------------------------------------------------------------------
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix.

    Path matching is greedy: the most-specific (longest) registered suffix
    that appears in the request URL wins.
    """

    def __init__(self, responses: Dict[str, Any]):
        self._responses = dict(responses)
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, url: str) -> _StubResponse:
        # Find the longest matching key (most specific). Treat token URL
        # specially so callers don't have to register it every time.
        candidates = [
            (path, resp)
            for path, resp in self._responses.items()
            if path in url
        ]
        if not candidates:
            return _StubResponse(404, {"error": "not found"}, text="not found")
        candidates.sort(key=lambda kv: len(kv[0]), reverse=True)
        return candidates[0][1]

    def get(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {})}
        )
        return self._resolve(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "content": content,
            }
        )
        return self._resolve(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_TOKEN_RESPONSE = _StubResponse(
    200, {"access_token": "ya29.test-access-token", "expires_in": 3600}
)


def _build_app(
    *,
    creds_path: Optional[str],
    org: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine. Token endpoint is auto-stubbed."""
    from core import apigee_engine as engine_mod

    engine_mod.reset_apigee_engine()

    # Always include a successful token exchange unless caller overrides it.
    merged: Dict[str, Any] = {"oauth2.googleapis.com/token": _TOKEN_RESPONSE}
    merged.update(stub_responses)
    stub_client = _StubClient(merged)

    if creds_path is None and org is None:
        engine_mod.get_apigee_engine(client=stub_client)
    else:
        engine_mod.get_apigee_engine(
            credentials_path=creds_path,
            org=org,
            client=stub_client,
        )

    from apps.api.apigee_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import apigee_engine as engine_mod

    engine_mod.reset_apigee_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in ("GOOGLE_APPLICATION_CREDENTIALS", "APIGEE_ORG"):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_env():
    app, _ = _build_app(creds_path=None, org=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/apigee/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Apigee Edge X"
    assert body["endpoints"] == [
        "/v1/organizations/{org}/apis",
        "/v1/organizations/{org}/environments",
        "/v1/organizations/{org}/apiproducts",
        "/v1/organizations/{org}/developers",
        "/v1/organizations/{org}/apps",
    ]
    assert body["google_app_creds_present"] is False
    assert body["apigee_org_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_env_present(_sa_json_path):
    app, _ = _build_app(
        creds_path=_sa_json_path, org="aldeci-prod", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/apigee/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["google_app_creds_present"] is True
    assert body["apigee_org_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_list_apis_503_when_env_missing():
    app, _ = _build_app(creds_path=None, org=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/apis", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "GOOGLE_APPLICATION_CREDENTIALS" in detail
    assert "APIGEE_ORG" in detail


def test_list_environments_503_when_env_missing():
    app, _ = _build_app(creds_path=None, org=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/environments",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_list_developers_503_when_only_creds_present(_sa_json_path):
    # creds_path present, org missing -> still unavailable
    app, _ = _build_app(
        creds_path=_sa_json_path, org=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/developers",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "APIGEE_ORG" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_apis_happy_path_normalizes(_sa_json_path):
    raw = {
        "proxies": [
            {
                "name": "weather-v1",
                "latestRevisionId": "3",
                "metaData": {
                    "createdAt": "1700000000000",
                    "lastModifiedAt": "1710000000000",
                    "subType": "Proxy",
                    "createdBy": "alice@example.com",
                    "lastModifiedBy": "bob@example.com",
                },
                "revision": ["1", "2", "3"],
            },
            {
                "name": "billing-v2",
                "latestRevisionId": "1",
                "metaData": {
                    "createdAt": "1720000000000",
                    "lastModifiedAt": "1720000000000",
                    "subType": "Proxy",
                    "createdBy": "ops@example.com",
                    "lastModifiedBy": "ops@example.com",
                },
                "revision": ["1"],
            },
        ]
    }
    app, stub = _build_app(
        creds_path=_sa_json_path,
        org="aldeci-prod",
        stub_responses={
            "/v1/organizations/aldeci-prod/apis": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/apis"
        "?includeRevisions=true&includeMetaData=true",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["proxies"]) == 2
    assert body["proxies"][0]["name"] == "weather-v1"
    assert body["proxies"][0]["latestRevisionId"] == "3"
    assert body["proxies"][0]["revision"] == ["1", "2", "3"]
    assert body["proxies"][0]["metaData"]["subType"] == "Proxy"

    # Verify token was fetched + Bearer header was set on Apigee call.
    assert any(
        c["method"] == "POST" and "oauth2.googleapis.com/token" in c["url"]
        for c in stub.calls
    )
    apigee_calls = [
        c for c in stub.calls if "apigee.googleapis.com" in c["url"]
    ]
    assert apigee_calls, "expected at least one call to apigee.googleapis.com"
    assert apigee_calls[0]["headers"].get("Authorization", "").startswith(
        "Bearer "
    )
    # Query-string flags propagated as ?includeRevisions=true&includeMetaData=true
    assert "includeRevisions=true" in apigee_calls[0]["url"]
    assert "includeMetaData=true" in apigee_calls[0]["url"]


def test_get_api_revision_happy_path(_sa_json_path):
    raw = {
        "name": "weather-v1",
        "revision": "3",
        "createdAt": "1700000000000",
        "lastModifiedAt": "1710000000000",
        "createdBy": "alice@example.com",
        "lastModifiedBy": "bob@example.com",
        "displayName": "Weather v1",
        "description": "weather forecast proxy",
        "configurationVersion": {"majorVersion": 4, "minorVersion": 0},
        "policies": ["VerifyAPIKey", "Quota-1"],
        "proxies": ["default"],
        "proxyEndpoints": ["default"],
        "resources": ["jsc://transform.js"],
        "resourceFiles": {"resourceFile": [{"name": "transform.js", "type": "jsc"}]},
        "targetEndpoints": ["default"],
        "targetServers": [],
        "type": "Application",
        "basepaths": ["/weather"],
    }
    app, _ = _build_app(
        creds_path=_sa_json_path,
        org="aldeci-prod",
        stub_responses={
            "/v1/organizations/aldeci-prod/apis/weather-v1/revisions/3": _StubResponse(
                200, raw
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/apis/weather-v1/revisions/3",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "weather-v1"
    assert body["revision"] == "3"
    assert body["policies"] == ["VerifyAPIKey", "Quota-1"]
    assert body["basepaths"] == ["/weather"]


def test_list_environments_happy_path(_sa_json_path):
    app, _ = _build_app(
        creds_path=_sa_json_path,
        org="aldeci-prod",
        stub_responses={
            "/v1/organizations/aldeci-prod/environments": _StubResponse(
                200, ["prod", "test", "staging"]
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/environments",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    assert r.json() == ["prod", "test", "staging"]


def test_get_environment_deployments_happy_path(_sa_json_path):
    raw = {
        "environment": "prod",
        "apiProxy": "weather-v1",
        "revision": "3",
        "deployStartTime": "1710000123456",
        "basePath": "/weather",
        "state": "READY",
        "errors": [],
        "instances": [{"name": "instance-1", "deployedRevisions": ["3"]}],
        "pods": [{"podName": "runtime-abc", "appVersion": "1.6.0"}],
        "routeConflicts": [],
    }
    app, _ = _build_app(
        creds_path=_sa_json_path,
        org="aldeci-prod",
        stub_responses={
            "/v1/organizations/aldeci-prod/environments/prod/apis/weather-v1/revisions/3/deployments": _StubResponse(
                200, raw
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/environments/prod/"
        "apis/weather-v1/revisions/3/deployments",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "READY"
    assert body["apiProxy"] == "weather-v1"
    assert body["revision"] == "3"
    assert body["instances"][0]["name"] == "instance-1"


def test_list_api_products_happy_path(_sa_json_path):
    raw = {
        "apiProduct": [
            {
                "name": "weather-product",
                "displayName": "Weather Product",
                "description": "free tier weather",
                "approvalType": "auto",
                "attributes": [
                    {"name": "access", "value": "public"},
                ],
                "createdAt": "1700000000000",
                "createdBy": "alice@example.com",
                "lastModifiedAt": "1710000000000",
                "lastModifiedBy": "bob@example.com",
                "scopes": ["read"],
                "proxies": ["weather-v1"],
                "environments": ["prod"],
                "apiResources": ["/weather/**"],
                "quota": "1000",
                "quotaInterval": "1",
                "quotaTimeUnit": "minute",
                "operationGroup": {
                    "operationConfigs": [
                        {
                            "apiSource": "weather-v1",
                            "operations": [
                                {"resource": "/weather", "methods": ["GET"]}
                            ],
                            "quota": {
                                "limit": "100",
                                "interval": "1",
                                "timeUnit": "minute",
                            },
                            "attributes": [],
                        }
                    ],
                    "operationConfigType": "proxy",
                },
            }
        ]
    }
    app, _ = _build_app(
        creds_path=_sa_json_path,
        org="aldeci-prod",
        stub_responses={
            "/v1/organizations/aldeci-prod/apiproducts": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/apiproducts?expand=true",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["apiProduct"]) == 1
    p = body["apiProduct"][0]
    assert p["name"] == "weather-product"
    assert p["approvalType"] == "auto"
    assert p["proxies"] == ["weather-v1"]
    assert p["operationGroup"]["operationConfigType"] == "proxy"
    assert (
        p["operationGroup"]["operationConfigs"][0]["operations"][0]["methods"]
        == ["GET"]
    )


def test_list_developers_happy_path(_sa_json_path):
    raw = {
        "developer": [
            {
                "email": "carol@example.com",
                "firstName": "Carol",
                "lastName": "Lee",
                "userName": "carol",
                "status": "active",
                "organizationName": "aldeci-prod",
                "attributes": [{"name": "tier", "value": "gold"}],
                "apps": ["weather-app"],
                "companies": [],
                "createdAt": "1700000000000",
                "createdBy": "admin@example.com",
                "lastModifiedAt": "1710000000000",
                "lastModifiedBy": "admin@example.com",
                "accessType": "READ",
                "developerId": "dev-1",
            }
        ]
    }
    app, _ = _build_app(
        creds_path=_sa_json_path,
        org="aldeci-prod",
        stub_responses={
            "/v1/organizations/aldeci-prod/developers": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/developers?expand=true&count=50",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["developer"]) == 1
    d = body["developer"][0]
    assert d["email"] == "carol@example.com"
    assert d["status"] == "active"
    assert d["appName"] == ["weather-app"]
    assert d["developerId"] == "dev-1"


def test_list_developer_apps_happy_path(_sa_json_path):
    raw = {
        "app": [
            {
                "appId": "app-uuid-1",
                "name": "weather-app",
                "developerId": "dev-1",
                "status": "approved",
                "attributes": [{"name": "env", "value": "prod"}],
                "callbackUrl": "https://example.com/cb",
                "createdAt": "1700000000000",
                "createdBy": "carol@example.com",
                "lastModifiedAt": "1710000000000",
                "lastModifiedBy": "carol@example.com",
                "credentials": [
                    {
                        "consumerKey": "ck-1",
                        "consumerSecret": "secret-1",
                        "status": "approved",
                    }
                ],
                "scopes": ["read"],
                "apiProducts": [{"apiproduct": "weather-product"}],
            }
        ]
    }
    app, _ = _build_app(
        creds_path=_sa_json_path,
        org="aldeci-prod",
        stub_responses={
            "/v1/organizations/aldeci-prod/developers/carol@example.com/apps": _StubResponse(
                200, raw
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/developers/carol@example.com/apps",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["app"]) == 1
    assert body["app"][0]["name"] == "weather-app"
    assert body["app"][0]["status"] == "approved"
    assert body["app"][0]["credentials"][0]["consumerKey"] == "ck-1"


def test_token_failure_propagates_503(_sa_json_path):
    """If Google's token endpoint refuses the assertion, return 503."""
    app, _ = _build_app(
        creds_path=_sa_json_path,
        org="aldeci-prod",
        stub_responses={
            "oauth2.googleapis.com/token": _StubResponse(
                400,
                {"error": "invalid_grant", "error_description": "expired"},
                text='{"error":"invalid_grant"}',
            ),
            "/v1/organizations/aldeci-prod/apis": _StubResponse(200, {"proxies": []}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/apis", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    assert "Google token endpoint" in r.json()["detail"]


def test_invalid_credentials_file_returns_503(tmp_path):
    """A non-JSON credentials file surfaces as 503 (NO MOCK fallback)."""
    bad = tmp_path / "broken.json"
    bad.write_text("this is not json")
    app, _ = _build_app(
        creds_path=str(bad), org="aldeci-prod", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apigee/v1/organizations/aldeci-prod/apis", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    assert "GOOGLE_APPLICATION_CREDENTIALS" in r.json()["detail"]
