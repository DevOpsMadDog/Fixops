"""Tests for lacework_router (Lacework CSPM REST proxy).

Covers:
- GET /                                             capability summary (unavailable + ok)
- POST /api/v2/access/tokens                        token exchange passthrough
- GET  /api/v2/Alerts (+ single by id)              listing + detail
- GET  /api/v2/Compliance/Reports/AwsLatest         aws compliance report
- POST /api/v2/Vulnerabilities/Hosts/search         host vuln search
- POST /api/v2/Vulnerabilities/Containers/search    container vuln search
- GET  /api/v2/Inventory                            inventory listing
- 503 on lookup endpoints when env unset (NO MOCKS rule)
- Two-phase auth + ~50-min in-memory token cache

Usage:
    pytest tests/test_lacework_router.py -x --tb=short -q
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api on path
for _p in ("suite-core", "suite-api"):
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def lw_env(monkeypatch):
    """Configure LACEWORK_ACCOUNT + LACEWORK_KEY_ID + LACEWORK_SECRET."""
    monkeypatch.setenv("LACEWORK_ACCOUNT", "tenant-test")
    monkeypatch.setenv("LACEWORK_KEY_ID", "test-key-id")
    monkeypatch.setenv("LACEWORK_SECRET", "test-secret-value")
    from core.lacework_engine import reset_lacework_engine
    reset_lacework_engine()
    yield
    reset_lacework_engine()


@pytest.fixture()
def no_lw_env(monkeypatch):
    """Ensure env unset (NO MOCKS — must surface 503)."""
    for var in ("LACEWORK_ACCOUNT", "LACEWORK_KEY_ID", "LACEWORK_SECRET"):
        monkeypatch.delenv(var, raising=False)
    from core.lacework_engine import reset_lacework_engine
    reset_lacework_engine()
    yield
    reset_lacework_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.lacework_router import router
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


def _make_lw_handler(routes: Dict[str, Dict[str, Any]], call_log=None):
    """Build a handler that mints access tokens + serves Lacework REST payloads.

    ``routes`` maps a substring of the request path → response body.
    The OAuth /access/tokens path is always served with a fixed bearer payload.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        path = request.url.path
        if call_log is not None:
            call_log.append((request.method, url))
        if "/api/v2/access/tokens" in path:
            return httpx.Response(
                201,
                json={
                    "token": "fake-bearer-token",
                    "expiresAt": "2099-12-31T23:59:59.000Z",
                },
            )
        for sub, body in routes.items():
            if sub in path:
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": f"unmatched: {path}"})

    return handler


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_lw_env):
    resp = client.get("/api/v1/lacework/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Lacework"
    assert body["lacework_account_present"] is False
    assert body["lacework_key_id_present"] is False
    assert body["lacework_secret_present"] is False
    assert body["status"] == "unavailable"
    expected = {
        "/api/v2/Alerts",
        "/api/v2/Compliance/Reports",
        "/api/v2/Vulnerabilities/Hosts/search",
        "/api/v2/Vulnerabilities/Containers/search",
        "/api/v2/Inventory",
    }
    assert expected.issubset(set(body["endpoints"]))


def test_capability_summary_ok_when_configured(client, lw_env):
    resp = client.get("/api/v1/lacework/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["lacework_account_present"] is True
    assert body["lacework_key_id_present"] is True
    assert body["lacework_secret_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_access_tokens_503_when_unconfigured(client, no_lw_env):
    resp = client.post(
        "/api/v1/lacework/api/v2/access/tokens",
        json={"keyId": "k"},
    )
    assert resp.status_code == 503
    assert "lacework" in resp.json()["detail"].lower()


def test_alerts_503_when_unconfigured(client, no_lw_env):
    resp = client.get("/api/v1/lacework/api/v2/Alerts")
    assert resp.status_code == 503


def test_alert_get_503_when_unconfigured(client, no_lw_env):
    resp = client.get("/api/v1/lacework/api/v2/Alerts/abc-123")
    assert resp.status_code == 503


def test_compliance_503_when_unconfigured(client, no_lw_env):
    resp = client.get(
        "/api/v1/lacework/api/v2/Compliance/Reports/AwsLatest",
        params={"accountId": "111122223333"},
    )
    assert resp.status_code == 503


def test_host_vuln_search_503_when_unconfigured(client, no_lw_env):
    resp = client.post(
        "/api/v1/lacework/api/v2/Vulnerabilities/Hosts/search",
        json={"filters": []},
    )
    assert resp.status_code == 503


def test_container_vuln_search_503_when_unconfigured(client, no_lw_env):
    resp = client.post(
        "/api/v1/lacework/api/v2/Vulnerabilities/Containers/search",
        json={"filters": []},
    )
    assert resp.status_code == 503


def test_inventory_503_when_unconfigured(client, no_lw_env):
    resp = client.get("/api/v1/lacework/api/v2/Inventory")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Access token passthrough
# ---------------------------------------------------------------------------


def test_access_tokens_passthrough(client, lw_env, monkeypatch):
    handler = _make_lw_handler({})
    _install_httpx_stub(monkeypatch, handler)

    resp = client.post(
        "/api/v1/lacework/api/v2/access/tokens",
        json={"keyId": "test-key-id", "expiryTime": 3600},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token"] == "fake-bearer-token"
    assert body["expiresAt"].endswith("Z")


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def test_list_alerts_returns_data_and_paging(client, lw_env, monkeypatch):
    handler = _make_lw_handler({
        "/api/v2/Alerts": {
            "data": [
                {
                    "alertId": 12345,
                    "alertName": "Suspicious console login",
                    "alertType": "AwsApiTracker",
                    "severity": "Critical",
                    "status": "Open",
                    "startTime": "2026-05-04T00:00:00Z",
                    "endTime": "2026-05-04T01:00:00Z",
                    "alertModel": {},
                    "internetExposure": True,
                    "accounts": ["111122223333"],
                    "reachability": True,
                    "cveIds": [],
                    "owners": ["alice@aldeci.local"],
                }
            ],
            "paging": {
                "rows": 1,
                "totalRows": 1,
                "urls": {"nextPage": None},
            },
        }
    })
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/lacework/api/v2/Alerts",
        params={
            "startTime": "2026-05-04T00:00:00Z",
            "endTime": "2026-05-04T23:59:59Z",
            "status": "Open",
            "pageSize": 25,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["alertId"] == 12345
    assert body["data"][0]["severity"] == "Critical"
    assert body["paging"]["rows"] == 1


def test_get_alert_by_id(client, lw_env, monkeypatch):
    handler = _make_lw_handler({
        "/api/v2/Alerts/777": {
            "data": [
                {
                    "alertId": 777,
                    "alertName": "Public S3 bucket",
                    "severity": "High",
                    "status": "Open",
                }
            ]
        }
    })
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/lacework/api/v2/Alerts/777")
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"][0]["alertId"] == 777


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------


def test_aws_compliance_latest(client, lw_env, monkeypatch):
    handler = _make_lw_handler({
        "/api/v2/Compliance/Reports/AwsLatest": {
            "data": [
                {
                    "accountId": "111122223333",
                    "accountName": "prod",
                    "recommendation": {
                        "TITLE": "Ensure S3 buckets block public access",
                        "ID": "CIS-2-1-5",
                        "INFO": "Block public access at the bucket level",
                        "ASSESSED_RESOURCE_COUNT": 42,
                        "RESOURCE_COUNT": 50,
                        "STATUS": "NonCompliant",
                        "REC_ID": "CIS-2-1-5",
                        "CATEGORY": "Storage",
                        "SECTION": "S3",
                        "EVAL_GUIDANCE": "set BlockPublicAcls=true",
                        "FAIL_INFO": {"count": 8, "severity": "High"},
                        "VIOLATIONS": [
                            {"region": "us-east-1", "resource": "arn:aws:s3:::leaky", "reasons": ["public-read"]}
                        ],
                    },
                }
            ],
            "reportType": "CIS_1_3_AWS",
            "reportTime": "2026-05-04T00:00:00Z",
        }
    })
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/lacework/api/v2/Compliance/Reports/AwsLatest",
        params={"accountId": "111122223333", "format": "json"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reportType"] == "CIS_1_3_AWS"
    assert body["data"][0]["recommendation"]["STATUS"] == "NonCompliant"


# ---------------------------------------------------------------------------
# Vulnerabilities — hosts + containers
# ---------------------------------------------------------------------------


def test_host_vulnerabilities_search(client, lw_env, monkeypatch):
    handler = _make_lw_handler({
        "/api/v2/Vulnerabilities/Hosts/search": {
            "data": [
                {
                    "startTime": "2026-05-04T00:00:00Z",
                    "endTime": "2026-05-04T23:59:59Z",
                    "mid": 9001,
                    "machineHostName": "ip-10-0-0-1.ec2.internal",
                    "evalCtx": {"exception_props": {}},
                    "status": "Active",
                    "vulnId": "CVE-2024-12345",
                    "severity": "Critical",
                    "cveProps": {
                        "cveBatchId": "batch-1",
                        "description": "Heap overflow",
                        "cve_history": [],
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                        "metadata": {},
                        "link_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                    },
                    "fixInfo": {
                        "fix_available": "1",
                        "fixed_version": "1.2.4",
                        "eval_status": "GOOD",
                        "fix_id": "fix-1",
                    },
                    "props": {"first_seen": "2026-05-01", "last_updated": "2026-05-04"},
                }
            ],
            "paging": {"rows": 1, "totalRows": 1, "urls": {"nextPage": None}},
        }
    })
    _install_httpx_stub(monkeypatch, handler)

    resp = client.post(
        "/api/v1/lacework/api/v2/Vulnerabilities/Hosts/search",
        json={
            "filters": [
                {"field": "severity", "expression": "in", "values": ["Critical", "High"]}
            ],
            "returns": ["mid", "vulnId", "severity"],
            "timeFilter": {
                "startTime": "2026-05-04T00:00:00Z",
                "endTime": "2026-05-04T23:59:59Z",
            },
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["vulnId"] == "CVE-2024-12345"
    assert body["data"][0]["fixInfo"]["fixed_version"] == "1.2.4"


def test_container_vulnerabilities_search(client, lw_env, monkeypatch):
    handler = _make_lw_handler({
        "/api/v2/Vulnerabilities/Containers/search": {
            "data": [
                {
                    "vulnId": "CVE-2024-99999",
                    "severity": "High",
                    "status": "Active",
                    "fixInfo": {"fix_available": "1", "fixed_version": "2.0.1"},
                }
            ],
            "paging": {"rows": 1, "totalRows": 1, "urls": {"nextPage": None}},
        }
    })
    _install_httpx_stub(monkeypatch, handler)

    resp = client.post(
        "/api/v1/lacework/api/v2/Vulnerabilities/Containers/search",
        json={
            "filters": [{"field": "severity", "expression": "eq", "value": "High"}],
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"][0]["vulnId"] == "CVE-2024-99999"


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def test_inventory_returns_data(client, lw_env, monkeypatch):
    handler = _make_lw_handler({
        "/api/v2/Inventory": {
            "data": [
                {
                    "resource_type": "ec2:instance",
                    "resource_config": {"State": {"Name": "running"}},
                    "resource_arn": "arn:aws:ec2:us-east-1:111:instance/i-0abc",
                    "resource_id": "i-0abc",
                    "resource_region": "us-east-1",
                    "resource_tags": {"env": "prod"},
                    "scan_completion_time": "2026-05-04T00:00:00Z",
                }
            ],
            "paging": {"rows": 1, "totalRows": 1, "urls": {"nextPage": None}},
        }
    })
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/lacework/api/v2/Inventory",
        params={
            "type": "AwsResources",
            "csp": "AWS",
            "pageSize": 100,
            "filters": json.dumps(
                [{"field": "resourceRegion", "expression": "eq", "value": "us-east-1"}]
            ),
            "returns": json.dumps(
                ["resource_id", "resource_type", "resource_region"]
            ),
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["resource_id"] == "i-0abc"


def test_inventory_rejects_bad_filters_json(client, lw_env, monkeypatch):
    handler = _make_lw_handler({"/api/v2/Inventory": {"data": []}})
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/lacework/api/v2/Inventory",
        params={"filters": "{not valid json"},
    )
    assert resp.status_code == 400
    assert "filters" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Two-phase auth + token caching
# ---------------------------------------------------------------------------


def test_token_is_cached_across_requests(client, lw_env, monkeypatch):
    call_log: list = []
    handler = _make_lw_handler(
        {"/api/v2/Alerts": {"data": [], "paging": {"rows": 0, "totalRows": 0, "urls": {}}}},
        call_log=call_log,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp1 = client.get("/api/v1/lacework/api/v2/Alerts")
    resp2 = client.get("/api/v1/lacework/api/v2/Alerts")
    assert resp1.status_code == 200
    assert resp2.status_code == 200

    token_calls = [c for c in call_log if "/api/v2/access/tokens" in c[1]]
    assert len(token_calls) == 1, f"expected 1 token call, got {len(token_calls)}: {token_calls}"
    alert_calls = [c for c in call_log if c[0] == "GET" and "/api/v2/Alerts" in c[1]]
    assert len(alert_calls) == 2, f"expected 2 GET Alerts, got {len(alert_calls)}"


def test_token_refreshes_after_ttl(client, lw_env, monkeypatch):
    call_log: list = []
    handler = _make_lw_handler(
        {"/api/v2/Alerts": {"data": [], "paging": {"rows": 0, "totalRows": 0, "urls": {}}}},
        call_log=call_log,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp1 = client.get("/api/v1/lacework/api/v2/Alerts")
    assert resp1.status_code == 200

    from core.lacework_engine import get_lacework_engine
    eng = get_lacework_engine()
    eng._token_expires_at = time.time() - 1.0

    resp2 = client.get("/api/v1/lacework/api/v2/Alerts")
    assert resp2.status_code == 200

    token_calls = [c for c in call_log if "/api/v2/access/tokens" in c[1]]
    assert len(token_calls) == 2, f"expected 2 token calls (refresh), got {len(token_calls)}"
