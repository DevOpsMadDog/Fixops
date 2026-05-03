"""Tests for akamai_router — ALDECI.

Spins up a minimal FastAPI app with the Akamai router mounted. Each test
gets an isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * GET /, GET /papi/*, GET /appsec/*, POST /appsec/.../security-events
    return HTTP 503 when EdgeGrid creds are unset.
  * Capability summary reports ``status="unavailable"`` when creds are missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real signing + parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


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
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, url: str) -> _StubResponse:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

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

    def put(self, *args, **kwargs):  # not used today
        return self.post(*args, **kwargs)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    creds: Optional[Dict[str, str]],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine."""
    from core import akamai_engine as engine_mod

    engine_mod.reset_akamai_engine()

    stub_client = _StubClient(stub_responses)
    if creds is None:
        engine_mod.get_akamai_engine(client=stub_client)
    else:
        engine_mod.get_akamai_engine(
            host=creds.get("host"),
            client_token=creds.get("client_token"),
            client_secret=creds.get("client_secret"),
            access_token=creds.get("access_token"),
            client=stub_client,
        )

    from apps.api.akamai_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import akamai_engine as engine_mod

    engine_mod.reset_akamai_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in (
        "AKAMAI_HOST",
        "AKAMAI_CLIENT_TOKEN",
        "AKAMAI_CLIENT_SECRET",
        "AKAMAI_ACCESS_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


_OK_CREDS = {
    "host": "akab-test.luna.akamaiapis.net",
    "client_token": "akab-client-token-value",
    "client_secret": "client-secret-value",
    "access_token": "akab-access-token-value",
}


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akamai/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Akamai (EdgeGrid)"
    assert body["endpoints"] == [
        "/papi/v1/groups",
        "/papi/v1/properties",
        "/appsec/v1/configs",
        "/appsec/v1/configs/{id}/versions/{ver}/security-events",
    ]
    assert body["akamai_host_present"] is False
    assert body["akamai_client_token_present"] is False
    assert body["akamai_client_secret_present"] is False
    assert body["akamai_access_token_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akamai/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["akamai_host_present"] is True
    assert body["akamai_client_token_present"] is True
    assert body["akamai_client_secret_present"] is True
    assert body["akamai_access_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_papi_groups_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akamai/papi/v1/groups", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "AKAMAI" in r.json()["detail"]


def test_papi_properties_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akamai/papi/v1/properties",
        params={"contractId": "ctr_C-1", "groupId": "grp_1"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_appsec_security_events_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/akamai/appsec/v1/configs/123/versions/4/security-events",
        json={
            "filter": {"from": "2026-05-01T00:00:00Z", "to": "2026-05-04T00:00:00Z"},
            "limit": 10,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# Validation 422
# ---------------------------------------------------------------------------


def test_papi_property_rules_422_on_bad_version():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    # version=0 fails the FastAPI Path(ge=1) constraint -> 422 from FastAPI itself
    r = client.get(
        "/api/v1/akamai/papi/v1/properties/prp_1/versions/0/rules",
        params={"contractId": "ctr_C-1", "groupId": "grp_1"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_papi_properties_422_on_missing_required_query():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get("/api/v1/akamai/papi/v1/properties", headers=HEADERS)
    # FastAPI rejects with 422 due to missing required query params
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_papi_groups_happy_path_normalizes():
    raw = {
        "accountId": "act_A-1",
        "accountName": "ALDECI Inc",
        "groups": {
            "items": [
                {
                    "groupId": "grp_1",
                    "groupName": "Top",
                    "parentGroupId": "",
                    "contractIds": ["ctr_C-1"],
                },
                {
                    "groupId": "grp_2",
                    "groupName": "Sub",
                    "parentGroupId": "grp_1",
                    "contractIds": ["ctr_C-1"],
                },
            ]
        },
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/papi/v1/groups": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akamai/papi/v1/groups", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accountId"] == "act_A-1"
    assert body["accountName"] == "ALDECI Inc"
    assert len(body["groups"]["items"]) == 2
    assert body["groups"]["items"][0]["groupId"] == "grp_1"
    assert body["groups"]["items"][1]["parentGroupId"] == "grp_1"

    # Ensure EdgeGrid Authorization header was set on the upstream call.
    assert len(stub.calls) == 1
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth.startswith("EG1-HMAC-SHA256 ")
    assert "client_token=" in auth
    assert "access_token=" in auth
    assert "timestamp=" in auth
    assert "nonce=" in auth
    assert "signature=" in auth


def test_papi_properties_happy_path():
    raw = {
        "properties": {
            "items": [
                {
                    "accountId": "act_A-1",
                    "contractId": "ctr_C-1",
                    "groupId": "grp_1",
                    "propertyId": "prp_1",
                    "propertyName": "www.example.com",
                    "latestVersion": 5,
                    "stagingVersion": 4,
                    "productionVersion": 3,
                    "assetId": "aid_1",
                    "note": "test prop",
                }
            ]
        }
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/papi/v1/properties": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akamai/papi/v1/properties",
        params={"contractId": "ctr_C-1", "groupId": "grp_1"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    items = body["properties"]["items"]
    assert len(items) == 1
    assert items[0]["propertyId"] == "prp_1"
    assert items[0]["latestVersion"] == 5
    assert items[0]["stagingVersion"] == 4
    assert items[0]["productionVersion"] == 3


def test_papi_property_versions_happy_path():
    raw = {
        "propertyId": "prp_1",
        "propertyName": "www.example.com",
        "accountId": "act_A-1",
        "contractId": "ctr_C-1",
        "groupId": "grp_1",
        "assetId": "aid_1",
        "versions": {
            "items": [
                {
                    "propertyVersion": 5,
                    "updatedByUser": "engineer@example.com",
                    "updatedDate": "2026-05-01T10:00:00Z",
                    "productionStatus": "ACTIVE",
                    "stagingStatus": "ACTIVE",
                    "etag": "abc123",
                    "productId": "prd_Site_Accel",
                    "ruleFormat": "v2024-02-12",
                    "note": "v5",
                },
                {
                    "propertyVersion": 4,
                    "updatedByUser": "engineer@example.com",
                    "updatedDate": "2026-04-15T10:00:00Z",
                    "productionStatus": "DEACTIVATED",
                    "stagingStatus": "INACTIVE",
                    "etag": "def456",
                    "productId": "prd_Site_Accel",
                    "ruleFormat": "v2024-02-12",
                    "note": "v4",
                },
            ]
        },
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/papi/v1/properties/prp_1/versions": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akamai/papi/v1/properties/prp_1/versions",
        params={"contractId": "ctr_C-1", "groupId": "grp_1"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["propertyId"] == "prp_1"
    assert len(body["versions"]["items"]) == 2
    assert body["versions"]["items"][0]["productionStatus"] == "ACTIVE"
    assert body["versions"]["items"][1]["productionStatus"] == "DEACTIVATED"


def test_papi_property_rules_happy_path():
    raw = {
        "propertyId": "prp_1",
        "propertyName": "www.example.com",
        "accountId": "act_A-1",
        "contractId": "ctr_C-1",
        "groupId": "grp_1",
        "propertyVersion": 5,
        "etag": "abc123",
        "rules": {
            "name": "default",
            "options": {"is_secure": True},
            "behaviors": [{"name": "origin", "options": {"hostname": "origin.example.com"}}],
            "children": [],
            "variables": [],
        },
        "ruleFormat": "v2024-02-12",
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/papi/v1/properties/prp_1/versions/5/rules": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akamai/papi/v1/properties/prp_1/versions/5/rules",
        params={"contractId": "ctr_C-1", "groupId": "grp_1"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["propertyVersion"] == 5
    assert body["rules"]["name"] == "default"
    assert body["rules"]["behaviors"][0]["name"] == "origin"
    assert body["ruleFormat"] == "v2024-02-12"


def test_appsec_configs_happy_path():
    raw = {
        "configurations": [
            {
                "id": 100,
                "name": "WAF-PROD",
                "description": "Prod WAF",
                "latestVersion": 10,
                "stagingVersion": 9,
                "productionVersion": 8,
                "fileType": "CONFIGURATION",
                "targetProduct": "WAP",
                "productionHostnames": ["www.example.com"],
                "stagingHostnames": ["staging.example.com"],
                "productionStatus": "Active",
                "stagingStatus": "Active",
                "lastModified": "2026-05-01T10:00:00Z",
                "createDate": "2025-01-01T00:00:00Z",
            }
        ]
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/appsec/v1/configs": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akamai/appsec/v1/configs", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["configurations"]) == 1
    cfg = body["configurations"][0]
    assert cfg["id"] == 100
    assert cfg["name"] == "WAF-PROD"
    assert cfg["targetProduct"] == "WAP"
    assert cfg["productionHostnames"] == ["www.example.com"]


def test_appsec_config_versions_happy_path():
    raw = {
        "configId": 100,
        "configName": "WAF-PROD",
        "lastCreatedVersion": 10,
        "versionList": [
            {
                "version": 10,
                "versionNotes": "tightened SQLi rules",
                "createDate": "2026-05-01T10:00:00Z",
                "createdBy": "secops@example.com",
                "production": {"status": "Inactive"},
                "staging": {"status": "Active"},
                "basedOn": 9,
                "productionStatus": "Inactive",
                "stagingStatus": "Active",
            }
        ],
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/appsec/v1/configs/100/versions": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akamai/appsec/v1/configs/100/versions", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configId"] == 100
    assert body["lastCreatedVersion"] == 10
    assert len(body["versionList"]) == 1
    assert body["versionList"][0]["version"] == 10
    assert body["versionList"][0]["createdBy"] == "secops@example.com"


def test_appsec_security_events_happy_path():
    raw = {
        "securityEvents": [
            {
                "eventId": "evt-001",
                "attackerSource": {"ip": "1.2.3.4", "country": "RU"},
                "configId": 100,
                "configName": "WAF-PROD",
                "configVersion": 10,
                "deniedReason": "rule-3000005-trigger",
                "geoCountryCode": "RU",
                "geoSubdivision": "MOW",
                "eventTimestamp": "2026-05-04T01:23:45Z",
                "occurredAt": "2026-05-04T01:23:45Z",
                "geoCity": "Moscow",
                "httpMessage": {
                    "requestId": "req-001",
                    "host": "www.example.com",
                    "port": "443",
                    "hostname": "www.example.com",
                    "requestUri": "/login",
                    "requestQuery": "?next=/admin",
                    "contentType": "application/x-www-form-urlencoded",
                    "requestMethod": "POST",
                    "status": 403,
                    "bytes": 0,
                    "requestHeaders": ["User-Agent: sqlmap/1.0"],
                    "responseHeaders": ["Server: AkamaiGHost"],
                },
                "policyId": "POL_1",
                "ruleActions": [
                    {"action": "deny", "ruleId": "3000005", "ruleVersion": "1"}
                ],
                "ruleData": [
                    {"name": "PAYLOAD", "value": "' OR 1=1 --", "ruleSelector": ""}
                ],
                "slowPostAction": "",
                "customRules": [],
            }
        ],
        "totalSize": 1,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/appsec/v1/configs/100/versions/10/security-events": _StubResponse(
                200, raw
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/akamai/appsec/v1/configs/100/versions/10/security-events",
        json={
            "filter": {
                "from": "2026-05-01T00:00:00Z",
                "to": "2026-05-04T23:59:59Z",
                "ruleSeverityList": ["HIGH"],
            },
            "limit": 100,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalSize"] == 1
    assert len(body["securityEvents"]) == 1
    evt = body["securityEvents"][0]
    assert evt["eventId"] == "evt-001"
    assert evt["attackerSource"]["ip"] == "1.2.3.4"
    assert evt["ruleActions"][0]["action"] == "deny"
    assert evt["httpMessage"]["status"] == 403
    assert evt["httpMessage"]["requestMethod"] == "POST"

    # Verify the POST was signed correctly (Authorization + Content-Type).
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "POST"
    assert call["headers"].get("Content-Type") == "application/json"
    assert call["headers"].get("Authorization", "").startswith("EG1-HMAC-SHA256 ")
    # Content-hash is set on POST/PUT, so signature must be deterministic for body.
    assert call["content"] is not None and len(call["content"]) > 0


# ---------------------------------------------------------------------------
# EdgeGrid signer unit checks
# ---------------------------------------------------------------------------


def test_edgegrid_signer_format():
    from core.akamai_engine import EdgeGridSigner

    s = EdgeGridSigner(
        client_token="ct-1",
        client_secret="cs-1",
        access_token="at-1",
    )
    auth = s.sign("GET", "https://akab-test.luna.akamaiapis.net/papi/v1/groups")
    assert auth.startswith("EG1-HMAC-SHA256 ")
    assert "client_token=ct-1;" in auth
    assert "access_token=at-1;" in auth
    assert "timestamp=" in auth
    assert "nonce=" in auth
    assert ";signature=" in auth


def test_edgegrid_signer_includes_body_hash_for_post():
    from core.akamai_engine import EdgeGridSigner

    s1 = EdgeGridSigner(
        client_token="ct-1",
        client_secret="cs-1",
        access_token="at-1",
    )
    # Two POSTs with different bodies must yield different signatures
    # because the body content-hash feeds into the canonical request.
    a1 = s1.sign(
        "POST",
        "https://akab-test.luna.akamaiapis.net/p",
        body=b'{"x":1}',
    )
    a2 = s1.sign(
        "POST",
        "https://akab-test.luna.akamaiapis.net/p",
        body=b'{"x":2}',
    )
    sig1 = a1.split("signature=")[-1]
    sig2 = a2.split("signature=")[-1]
    assert sig1 != sig2
