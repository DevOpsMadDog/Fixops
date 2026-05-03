"""Tests for the Microsoft Defender XDR router (NO MOCKS, real httpx path).

Each test injects a stub ``httpx.Client`` so the engine's REAL request
construction + OAuth2 token negotiation + JSON parsing is exercised — only
the network is intercepted.

Coverage:
  1. Capability summary returns ``status="unavailable"`` when env unset.
  2. Capability summary returns ``status="ok"`` when all 3 env vars present.
  3. GET /v1.0/security/alerts_v2 returns 503 when env unset.
  4. GET /v1.0/security/alerts_v2 returns Graph alerts via stub + checks
     OAuth2 token request fired against login.microsoftonline.com.
  5. GET /v1.0/security/incidents returns 503 unset, returns incidents
     envelope with $expand=alerts when configured.
  6. GET /api/machines uses the Defender for Endpoint scope (separate token).
  7. POST /api/advancedhunting/run hits the M365 Defender host with a third
     scope and round-trips a Schema/Results envelope.
  8. GET /api/securityrecommendations returns TVM recs via stub.
  9. POST /api/advancedhunting/run with empty Query returns HTTP 400.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------- helpers


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Minimal httpx.Client stand-in: matches by URL substring."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "params": params or {},
            }
        )
        return self._match(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Any = None,
        data: Any = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "json": json,
                "data": data,
                "params": params or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# Token endpoint stub — every scope returns the same fake bearer (the engine
# caches per-scope so we still get one token call per scope).
_TOKEN_RESPONSE = _StubResponse(
    200,
    {
        "token_type": "Bearer",
        "expires_in": 3599,
        "access_token": "fake-bearer-token",
        "ext_expires_in": 3599,
    },
)


def _build_app(
    *,
    tenant_id: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    """Build a minimal FastAPI app mounting the Defender XDR router."""
    from core import defender_xdr_engine as eng_mod

    eng_mod.reset_defender_xdr_engine()
    responses = dict(stub_responses or {})
    # Always include the OAuth2 token endpoint so configured runs work.
    responses.setdefault("/oauth2/v2.0/token", _TOKEN_RESPONSE)
    stub = _StubClient(responses)
    eng_mod.get_defender_xdr_engine(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        client=stub,
        force_refresh=True,
    )

    from apps.api.defender_xdr_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import defender_xdr_engine as eng_mod
    eng_mod.reset_defender_xdr_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    app, _ = _build_app(tenant_id="", client_id="", client_secret="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/defender-xdr/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Microsoft Defender XDR"
    for ep in [
        "/v1.0/security/alerts_v2",
        "/v1.0/security/incidents",
        "/api/machines",
        "/api/advancedhunting/run",
        "/api/securityrecommendations",
    ]:
        assert ep in body["endpoints"], f"missing endpoint {ep}"
    assert body["azure_tenant_present"] is False
    assert body["azure_client_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_creds_present(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    app, _ = _build_app(
        tenant_id="tenant-aaa",
        client_id="client-bbb",
        client_secret="secret-ccc",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/defender-xdr/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["azure_tenant_present"] is True
    assert body["azure_client_present"] is True
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_alerts_v2_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    app, _ = _build_app(tenant_id="", client_id="", client_secret="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/defender-xdr/v1.0/security/alerts_v2",
        headers=HEADERS,
        params={"$top": 5},
    )
    assert r.status_code == 503, r.text
    assert "AZURE_TENANT_ID" in r.json()["detail"]
    _reset()


def test_incidents_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    app, _ = _build_app(tenant_id="", client_id="", client_secret="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/defender-xdr/v1.0/security/incidents",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_machines_and_recs_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    app, _ = _build_app(tenant_id="", client_id="", client_secret="")
    client = TestClient(app, raise_server_exceptions=True)

    for path in (
        "/api/machines",
        "/api/securityrecommendations",
    ):
        r = client.get(f"/api/v1/defender-xdr{path}", headers=HEADERS)
        assert r.status_code == 503, f"{path}: {r.text}"
    _reset()


def test_advanced_hunting_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    app, _ = _build_app(tenant_id="", client_id="", client_secret="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/defender-xdr/api/advancedhunting/run",
        headers=HEADERS,
        json={"Query": "DeviceLogonEvents | take 1"},
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ real httpx path


def test_alerts_v2_returns_data_via_stub_and_oauth2(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    raw = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2",
        "@odata.count": 1,
        "value": [
            {
                "id": "alert-1",
                "providerAlertId": "abc",
                "incidentId": "inc-1",
                "status": "new",
                "severity": "high",
                "classification": "unknown",
                "determination": "unknown",
                "serviceSource": "microsoftDefenderForEndpoint",
                "detectionSource": "microsoftDefenderForEndpoint",
                "detectorId": "1",
                "tenantId": "tenant-aaa",
                "title": "Suspicious process",
                "description": "powershell.exe spawned cmd.exe",
                "recommendedActions": "Investigate the device",
                "category": "Execution",
                "alertWebUrl": "https://security.microsoft.com/alerts/alert-1",
                "mitreTechniques": ["T1059"],
                "systemTags": [],
                "userStates": [],
                "evidence": [
                    {
                        "@odata.type": "#microsoft.graph.security.deviceEvidence",
                        "deviceDnsName": "vm-web-01",
                    }
                ],
                "firstActivityDateTime": "2026-05-04T00:00:00Z",
                "lastActivityDateTime": "2026-05-04T00:05:00Z",
                "createdDateTime": "2026-05-04T00:01:00Z",
                "lastUpdateDateTime": "2026-05-04T00:06:00Z",
                "resolvedDateTime": None,
                "additionalData": {},
                "comments": [],
            }
        ],
    }
    app, stub = _build_app(
        tenant_id="tenant-aaa",
        client_id="client-bbb",
        client_secret="secret-ccc",
        stub_responses={"/v1.0/security/alerts_v2": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/defender-xdr/v1.0/security/alerts_v2",
        headers=HEADERS,
        params={
            "$filter": "severity eq 'high'",
            "$top": 25,
            "$orderby": "createdDateTime desc",
            "$count": "true",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["@odata.count"] == 1
    assert body["value"][0]["id"] == "alert-1"
    assert body["value"][0]["serviceSource"] == "microsoftDefenderForEndpoint"

    # Verify OAuth2 token request fired against the right tenant + scope.
    token_calls = [
        c for c in stub.calls if "/oauth2/v2.0/token" in c["url"]
    ]
    assert token_calls, "expected at least one OAuth2 token request"
    tok = token_calls[0]
    assert tok["method"] == "POST"
    assert "login.microsoftonline.com/tenant-aaa" in tok["url"]
    assert tok["data"]["grant_type"] == "client_credentials"
    assert tok["data"]["client_id"] == "client-bbb"
    assert tok["data"]["client_secret"] == "secret-ccc"
    assert tok["data"]["scope"] == "https://graph.microsoft.com/.default"

    # Verify the alerts call carried the bearer + correct base URL + OData params.
    alerts_calls = [c for c in stub.calls if "/v1.0/security/alerts_v2" in c["url"]]
    assert alerts_calls, "expected at least one alerts call"
    a = alerts_calls[0]
    assert a["url"].startswith("https://graph.microsoft.com/")
    assert a["headers"].get("Authorization") == "Bearer fake-bearer-token"
    assert a["params"].get("$filter") == "severity eq 'high'"
    assert a["params"].get("$top") == 25
    assert a["params"].get("$orderby") == "createdDateTime desc"
    assert a["params"].get("$count") == "true"
    _reset()


def test_incidents_with_expand_alerts_via_stub(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    raw = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/incidents",
        "@odata.count": 1,
        "value": [
            {
                "id": "inc-1",
                "incidentWebUrl": "https://security.microsoft.com/incidents/inc-1",
                "redirectIncidentId": None,
                "displayName": "Multi-stage attack on vm-web-01",
                "tenantId": "tenant-aaa",
                "createdDateTime": "2026-05-04T00:01:00Z",
                "lastUpdateDateTime": "2026-05-04T00:10:00Z",
                "lastModifiedBy": "system",
                "assignedTo": None,
                "classification": "unknown",
                "determination": "unknown",
                "status": "active",
                "severity": "high",
                "customTags": [],
                "comments": [],
                "systemTags": ["multi-stage"],
                "description": "Suspicious sequence of events",
                "summary": None,
                "recommendedActions": "Investigate immediately",
                "recommendedHuntingQueries": [
                    {"kqlText": "DeviceProcessEvents | where DeviceName == 'vm-web-01'"}
                ],
                "alerts": [
                    {"id": "alert-1", "title": "Suspicious process"}
                ],
            }
        ],
    }
    app, stub = _build_app(
        tenant_id="tenant-aaa",
        client_id="client-bbb",
        client_secret="secret-ccc",
        stub_responses={"/v1.0/security/incidents": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/defender-xdr/v1.0/security/incidents",
        headers=HEADERS,
        params={"$top": 10, "$expand": "alerts"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["@odata.count"] == 1
    inc = body["value"][0]
    assert inc["id"] == "inc-1"
    assert inc["status"] == "active"
    assert inc["alerts"][0]["id"] == "alert-1"

    inc_calls = [c for c in stub.calls if "/v1.0/security/incidents" in c["url"]]
    assert inc_calls
    assert inc_calls[0]["params"].get("$expand") == "alerts"
    assert inc_calls[0]["params"].get("$top") == 10
    _reset()


def test_machines_uses_defender_endpoint_scope(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    raw = {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Machines",
        "value": [
            {
                "id": "machine-1",
                "computerDnsName": "vm-web-01.contoso.com",
                "firstSeen": "2025-01-01T00:00:00Z",
                "lastSeen": "2026-05-04T00:00:00Z",
                "osPlatform": "WindowsServer2022",
                "version": "10.0.20348",
                "osBuild": 20348,
                "lastIpAddress": "10.0.0.10",
                "lastExternalIpAddress": "203.0.113.10",
                "agentVersion": "10.8295.22621.1234",
                "osArchitecture": "x64",
                "osProcessor": "x64",
                "healthStatus": "Active",
                "deviceValue": "High",
                "rbacGroupId": 1,
                "rbacGroupName": "Production",
                "riskScore": "High",
                "exposureLevel": "Medium",
                "isAadJoined": True,
                "aadDeviceId": "aad-device-1",
                "machineTags": ["prod", "web"],
                "defenderAvStatus": "Updated",
                "onboardingStatus": "Onboarded",
                "ipAddresses": [
                    {
                        "ipAddress": "10.0.0.10",
                        "macAddress": "00-11-22-33-44-55",
                        "type": "Ethernet",
                        "operationalStatus": "Up",
                    }
                ],
                "vmMetadata": {
                    "vmId": "vm-1",
                    "cloudProvider": "Azure",
                    "resourceId": "/subscriptions/.../vm-web-01",
                    "subscriptionId": "sub-1",
                },
            }
        ],
    }
    app, stub = _build_app(
        tenant_id="tenant-aaa",
        client_id="client-bbb",
        client_secret="secret-ccc",
        stub_responses={"/api/machines": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/defender-xdr/api/machines",
        headers=HEADERS,
        params={
            "$filter": "healthStatus eq 'Active'",
            "$top": 50,
            "$orderby": "lastSeen desc",
            "$skip": 0,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["value"][0]["id"] == "machine-1"
    assert body["value"][0]["healthStatus"] == "Active"

    # Verify a token request specifically requested the Defender for Endpoint scope.
    scopes_requested = [
        c["data"]["scope"]
        for c in stub.calls
        if "/oauth2/v2.0/token" in c["url"] and c.get("data")
    ]
    assert "https://api.securitycenter.microsoft.com/.default" in scopes_requested

    machine_calls = [c for c in stub.calls if "/api/machines" in c["url"]]
    assert machine_calls
    m = machine_calls[0]
    assert m["url"].startswith("https://api.securitycenter.microsoft.com/")
    assert m["params"].get("$filter") == "healthStatus eq 'Active'"
    assert m["params"].get("$top") == 50
    _reset()


def test_advanced_hunting_uses_m365_defender_scope(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    raw = {
        "Schema": [
            {"Name": "Timestamp", "Type": "DateTime"},
            {"Name": "DeviceName", "Type": "String"},
            {"Name": "AccountName", "Type": "String"},
        ],
        "Results": [
            {
                "Timestamp": "2026-05-04T00:00:00Z",
                "DeviceName": "vm-web-01",
                "AccountName": "alice",
            }
        ],
    }
    app, stub = _build_app(
        tenant_id="tenant-aaa",
        client_id="client-bbb",
        client_secret="secret-ccc",
        stub_responses={"/api/advancedhunting/run": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    kql = "DeviceLogonEvents | where DeviceName == 'vm-web-01' | take 10"
    r = client.post(
        "/api/v1/defender-xdr/api/advancedhunting/run",
        headers=HEADERS,
        json={"Query": kql},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["Schema"][0]["Name"] == "Timestamp"
    assert body["Results"][0]["DeviceName"] == "vm-web-01"

    scopes_requested = [
        c["data"]["scope"]
        for c in stub.calls
        if "/oauth2/v2.0/token" in c["url"] and c.get("data")
    ]
    assert "https://api.security.microsoft.com/.default" in scopes_requested

    hunt_calls = [c for c in stub.calls if "/api/advancedhunting/run" in c["url"]]
    assert hunt_calls
    h = hunt_calls[0]
    assert h["method"] == "POST"
    assert h["url"].startswith("https://api.security.microsoft.com/")
    assert h["json"]["Query"] == kql
    _reset()


def test_security_recommendations_via_stub(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    raw = {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Recommendations",
        "value": [
            {
                "id": "rec-1",
                "productName": "windows_10",
                "recommendationName": "Update Windows Defender Antivirus signatures",
                "weaknesses": 0,
                "vendor": "microsoft",
                "recommendedVersion": "1.397.1234.0",
                "recommendationCategory": "SecurityControls",
                "subCategory": "Antivirus",
                "severityScore": 8.0,
                "publicExploit": False,
                "activeAlert": True,
                "associatedThreats": [],
                "remediationType": "Update",
                "status": "Active",
                "configScoreImpact": 5.5,
                "exposureImpact": 2.5,
                "totalMachineCount": 100,
                "exposedMachinesCount": 12,
                "nonProductivityImpactedAssets": 0,
                "relatedComponent": "Microsoft Defender Antivirus",
            }
        ],
    }
    app, stub = _build_app(
        tenant_id="tenant-aaa",
        client_id="client-bbb",
        client_secret="secret-ccc",
        stub_responses={"/api/securityrecommendations": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/defender-xdr/api/securityrecommendations",
        headers=HEADERS,
        params={"$top": 25, "$orderby": "severityScore desc"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["value"][0]["id"] == "rec-1"
    assert body["value"][0]["status"] == "Active"

    rec_calls = [c for c in stub.calls if "/api/securityrecommendations" in c["url"]]
    assert rec_calls
    assert rec_calls[0]["url"].startswith("https://api.securitycenter.microsoft.com/")
    assert rec_calls[0]["params"].get("$top") == 25
    _reset()


def test_advanced_hunting_empty_query_returns_400(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    app, _ = _build_app(
        tenant_id="tenant-aaa",
        client_id="client-bbb",
        client_secret="secret-ccc",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/defender-xdr/api/advancedhunting/run",
        headers=HEADERS,
        json={"Query": "   "},
    )
    assert r.status_code == 400, r.text
    assert "empty" in r.json()["detail"].lower()
    _reset()
