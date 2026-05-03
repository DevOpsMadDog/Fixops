"""Tests for purview_dlp_router (Microsoft Purview DLP / Graph proxy).

Covers:
- GET /                                      capability summary (unavailable + ok)
- GET /v1.0/security/dataLossPreventionPolicies   503 + live-stubbed shape
- GET /v1.0/security/labels/sensitivityLabels     live-stubbed shape
- GET /v1.0/security/incidents                    live-stubbed shape
- GET /v1.0/security/cases/ediscoveryCases        live-stubbed (with $expand=custodians)
- GET /v1.0/dataClassification/sensitiveTypes     live-stubbed shape
- token cached across calls (fetched once)
- $filter validation reaches engine

Usage:
    pytest tests/test_purview_dlp_router.py -x --tb=short -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api on path.
for _p in ("suite-core", "suite-api"):
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def purview_env(monkeypatch):
    """Configure AZURE_* env for the engine."""
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-uuid-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-uuid-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    from core.purview_dlp_engine import reset_purview_dlp_engine
    reset_purview_dlp_engine()
    yield
    reset_purview_dlp_engine()


@pytest.fixture()
def no_purview_env(monkeypatch):
    """Ensure env is unset (NO MOCKS — must surface 503)."""
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    from core.purview_dlp_engine import reset_purview_dlp_engine
    reset_purview_dlp_engine()
    yield
    reset_purview_dlp_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.purview_dlp_router import router
    a = FastAPI()
    a.include_router(router)
    return a


@pytest.fixture()
def client(app) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# httpx stub helpers
# ---------------------------------------------------------------------------


def _install_httpx_stub(monkeypatch, handler):
    """Replace httpx.Client with a transport-mocked instance."""
    import httpx as _httpx

    real_client_init = _httpx.Client.__init__

    def _patched_init(self, *args, **kwargs):
        kwargs.pop("verify", None)
        kwargs["transport"] = _httpx.MockTransport(handler)
        real_client_init(self, *args, **kwargs)

    monkeypatch.setattr(_httpx.Client, "__init__", _patched_init)


def _make_handler(routes, token_calls):
    """Build a handler that resolves AAD token + Graph paths."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        path = request.url.path

        # AAD token endpoint.
        if "login.microsoftonline.com" in host and path.endswith("/oauth2/v2.0/token"):
            token_calls.append(path)
            return httpx.Response(
                200,
                json={
                    "token_type": "Bearer",
                    "expires_in": 3599,
                    "access_token": "live-bearer-token",
                },
            )

        # Graph resource paths.
        for matcher, response in routes:
            if matcher(request):
                return response

        return httpx.Response(
            404, json={"error": f"no stub for {request.method} {path}"}
        )

    return handler


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_purview_env):
    resp = client.get("/api/v1/microsoft-purview/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Microsoft Purview DLP"
    assert body["azure_tenant_present"] is False
    assert body["azure_client_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/v1.0/security/dataLossPreventionPolicies",
        "/v1.0/security/labels/sensitivityLabels",
        "/v1.0/security/incidents",
        "/v1.0/security/cases/ediscoveryCases",
        "/v1.0/dataClassification/sensitiveTypes",
    ):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, purview_env):
    resp = client.get("/api/v1/microsoft-purview/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["azure_tenant_present"] is True
    assert body["azure_client_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_dlp_policies_503_when_unconfigured(client, no_purview_env):
    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/security/dataLossPreventionPolicies"
    )
    assert resp.status_code == 503
    assert "microsoft purview" in resp.json()["detail"].lower()


def test_sensitivity_labels_503_when_unconfigured(client, no_purview_env):
    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/security/labels/sensitivityLabels"
    )
    assert resp.status_code == 503


def test_incidents_503_when_unconfigured(client, no_purview_env):
    resp = client.get("/api/v1/microsoft-purview/v1.0/security/incidents")
    assert resp.status_code == 503


def test_ediscovery_cases_503_when_unconfigured(client, no_purview_env):
    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/security/cases/ediscoveryCases"
    )
    assert resp.status_code == 503


def test_sensitive_types_503_when_unconfigured(client, no_purview_env):
    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/dataClassification/sensitiveTypes"
    )
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Live (stubbed) lookup paths
# ---------------------------------------------------------------------------


def _graph_path(suffix: str) -> str:
    return f"/v1.0/security{suffix}" if not suffix.startswith("/v1.0") else suffix


def test_list_dlp_policies_live(client, purview_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "policy-1",
                "displayName": "Block credit card data",
                "description": "Detect and block PCI data exfil",
                "mode": "enforce",
                "enabled": True,
                "locations": [
                    "ExchangeOnline",
                    "SharePointOnline",
                    "OneDriveForBusiness",
                    "Teams",
                ],
                "rules": [
                    {
                        "id": "rule-1",
                        "name": "PCI rule",
                        "conditions": {
                            "sensitiveInfoTypes": [{"name": "Credit Card Number"}]
                        },
                        "actions": ["Block", "Notify"],
                    }
                ],
            }
        ]
    }

    def _is_dlp(req):
        return (
            req.method == "GET"
            and req.url.path
            == "/v1.0/security/dataLossPreventionPolicies"
        )

    handler = _make_handler(
        [(_is_dlp, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/security/dataLossPreventionPolicies",
        params={"$top": 25, "$skip": 0, "$filter": "mode eq 'enforce'"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["mode"] == "enforce"
    assert body["value"][0]["enabled"] is True
    assert "ExchangeOnline" in body["value"][0]["locations"]
    assert body["value"][0]["rules"][0]["actions"] == ["Block", "Notify"]
    assert len(token_calls) == 1


def test_list_sensitivity_labels_live(client, purview_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "label-confidential",
                "name": "confidential",
                "displayName": "Confidential",
                "description": "Internal-confidential business data",
                "isDefault": False,
                "sensitivity": 3,
                "color": "#FF8C00",
                "tooltip": "Apply to confidential business data",
                "autoLabeling": {
                    "enabled": True,
                    "sensitiveInfoTypes": [
                        {"name": "Credit Card Number"},
                        {"name": "U.S. Social Security Number (SSN)"},
                    ],
                    "conditions": {"matchType": "any"},
                },
                "contentMarking": {
                    "header": {
                        "text": "CONFIDENTIAL",
                        "fontName": "Calibri",
                        "fontSize": 12,
                        "fontColor": "#FF0000",
                        "alignment": "center",
                    },
                    "footer": {"text": "Do not distribute"},
                    "watermark": {"text": "CONFIDENTIAL"},
                },
                "encryption": {
                    "rightsManagementProtectionEnabled": True,
                    "encryptContent": True,
                    "doNotForward": True,
                },
                "parentLabel": {"id": "label-parent", "name": "All Confidential"},
            }
        ]
    }

    def _is_labels(req):
        return (
            req.method == "GET"
            and req.url.path == "/v1.0/security/labels/sensitivityLabels"
        )

    handler = _make_handler(
        [(_is_labels, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/security/labels/sensitivityLabels",
        params={"$top": 50},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    label = body["value"][0]
    assert label["sensitivity"] == 3
    assert label["autoLabeling"]["enabled"] is True
    assert label["encryption"]["doNotForward"] is True
    assert label["contentMarking"]["watermark"]["text"] == "CONFIDENTIAL"


def test_list_incidents_live(client, purview_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "inc-dlp-1",
                "displayName": "DLP policy match — credit card exfil",
                "severity": "high",
                "status": "active",
                "classification": "truePositive",
                "determination": "dataExfiltration",
                "createdDateTime": "2026-05-01T10:00:00Z",
                "lastUpdateDateTime": "2026-05-01T10:05:00Z",
                "alerts": [{"id": "alrt-1", "title": "DLP rule triggered"}],
            }
        ]
    }

    def _is_incidents(req):
        return (
            req.method == "GET"
            and req.url.path == "/v1.0/security/incidents"
        )

    handler = _make_handler(
        [(_is_incidents, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/security/incidents",
        params={
            "$top": 10,
            "$filter": "category eq 'DLP'",
            "$orderby": "createdDateTime desc",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["severity"] == "high"
    assert body["value"][0]["determination"] == "dataExfiltration"


def test_list_ediscovery_cases_live_with_expand(client, purview_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "case-1",
                "displayName": "Investigation 2026 Q2",
                "description": "Internal HR investigation",
                "status": "open",
                "createdBy": {
                    "user": {
                        "id": "user-1",
                        "displayName": "Alice Admin",
                        "userPrincipalName": "alice@contoso.com",
                    }
                },
                "createdDateTime": "2026-05-01T08:00:00Z",
                "lastModifiedDateTime": "2026-05-02T08:00:00Z",
                "lastModifiedBy": {
                    "user": {
                        "id": "user-1",
                        "displayName": "Alice Admin",
                        "userPrincipalName": "alice@contoso.com",
                    }
                },
                "closedDateTime": None,
                "closedBy": None,
                "externalId": "EXT-CASE-2026-Q2",
                "custodians": [
                    {
                        "id": "cust-1",
                        "status": "active",
                        "email": "bob@contoso.com",
                        "applyHoldToSources": True,
                        "sitesIncluded": [
                            "https://contoso.sharepoint.com/sites/HR"
                        ],
                        "unifiedGroupSources": ["group-hr"],
                    }
                ],
            }
        ]
    }

    def _is_cases(req):
        return (
            req.method == "GET"
            and req.url.path == "/v1.0/security/cases/ediscoveryCases"
        )

    handler = _make_handler(
        [(_is_cases, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/security/cases/ediscoveryCases",
        params={
            "$top": 10,
            "$filter": "status eq 'open'",
            "$orderby": "createdDateTime desc",
            "$expand": "custodians",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    case = body["value"][0]
    assert case["status"] == "open"
    assert case["createdBy"]["user"]["userPrincipalName"] == "alice@contoso.com"
    assert case["custodians"][0]["applyHoldToSources"] is True


def test_list_sensitive_types_live(client, purview_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "sit-cc",
                "name": "Credit Card Number",
                "description": "Detects credit card numbers (Luhn checksum)",
                "publisher": "Microsoft",
                "rulePackageType": "builtIn",
                "rulePackageId": "pkg-mip-builtin",
                "contentMatching": {"exactMatch": False},
            },
            {
                "id": "sit-ssn",
                "name": "U.S. Social Security Number (SSN)",
                "description": "Detects SSN format",
                "publisher": "Microsoft",
                "rulePackageType": "builtIn",
                "rulePackageId": "pkg-mip-builtin",
                "contentMatching": {"exactMatch": False},
            },
        ]
    }

    def _is_sit(req):
        return (
            req.method == "GET"
            and req.url.path == "/v1.0/dataClassification/sensitiveTypes"
        )

    handler = _make_handler(
        [(_is_sit, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/dataClassification/sensitiveTypes",
        params={"$top": 100},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["value"]) == 2
    assert body["value"][0]["rulePackageType"] == "builtIn"
    assert body["value"][1]["name"] == "U.S. Social Security Number (SSN)"


# ---------------------------------------------------------------------------
# Token cache
# ---------------------------------------------------------------------------


def test_token_cached_across_two_calls(client, purview_env, monkeypatch):
    token_calls: list = []
    payload = {"value": []}

    def _is_dlp(req):
        return (
            req.method == "GET"
            and req.url.path == "/v1.0/security/dataLossPreventionPolicies"
        )

    handler = _make_handler(
        [(_is_dlp, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    for _ in range(2):
        resp = client.get(
            "/api/v1/microsoft-purview/v1.0/security/dataLossPreventionPolicies"
        )
        assert resp.status_code == 200, resp.text

    # Token should only be fetched once across both calls.
    assert len(token_calls) == 1


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_top_validation_rejects_zero(client, purview_env):
    resp = client.get(
        "/api/v1/microsoft-purview/v1.0/security/dataLossPreventionPolicies",
        params={"$top": 0},
    )
    assert resp.status_code == 422
