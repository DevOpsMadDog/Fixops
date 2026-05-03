"""Tests for proofpoint_tap_router (Proofpoint Targeted Attack Protection v2).

Covers (NO MOCKS rule — env-unset → 503):
- GET /                              capability summary unavailable + ok
- GET /v2/siem/all                   passthrough w/ messages + clicks
- GET /v2/siem/clicks/blocked        clicks-only path
- GET /v2/siem/messages/delivered    messages-only path
- GET /v2/forensics?threatId=        threat forensics report
- GET /v2/forensics?campaignId=      campaign forensics
- GET /v2/url/decode?urls=...        decode via query (GET)
- POST /v2/url/decode {"urls":[...]} decode via body (POST)
- GET /v2/people/vap                 Very Attacked People
- GET /v2/people/top-clickers        top clickers
- 503 on lookup endpoints when env unset

Usage:
    pytest tests/test_proofpoint_tap_router.py -x --tb=short -q
"""
from __future__ import annotations

import sys
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

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def pp_env(monkeypatch):
    monkeypatch.setenv("PROOFPOINT_TAP_PRINCIPAL", "test-principal")
    monkeypatch.setenv("PROOFPOINT_TAP_SECRET", "test-secret")
    from core.proofpoint_tap_engine import reset_proofpoint_tap_engine
    reset_proofpoint_tap_engine()
    yield
    reset_proofpoint_tap_engine()


@pytest.fixture()
def no_pp_env(monkeypatch):
    monkeypatch.delenv("PROOFPOINT_TAP_PRINCIPAL", raising=False)
    monkeypatch.delenv("PROOFPOINT_TAP_SECRET", raising=False)
    from core.proofpoint_tap_engine import reset_proofpoint_tap_engine
    reset_proofpoint_tap_engine()
    yield
    reset_proofpoint_tap_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.proofpoint_tap_router import router
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
    real_client_init = httpx.Client.__init__

    def _patched_init(self, *args, **kwargs):
        kwargs.pop("verify", None)
        kwargs["transport"] = httpx.MockTransport(handler)
        real_client_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", _patched_init)


def _make_handler(routes: Dict[str, Dict[str, Any]], call_log=None):
    """routes: {path_substr: {"status": 200, "json": {...}}}"""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if call_log is not None:
            call_log.append((request.method, url))
        for substr, payload in routes.items():
            if substr in url:
                return httpx.Response(
                    payload.get("status", 200), json=payload.get("json", {})
                )
        return httpx.Response(404, json={"error": f"unstubbed: {url}"})

    return handler


# ===========================================================================
# Capability summary
# ===========================================================================


def test_capability_summary_unavailable(client, no_pp_env):
    r = client.get("/api/v1/proofpoint-tap/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Proofpoint TAP"
    assert body["proofpoint_principal_present"] is False
    assert body["proofpoint_secret_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/v2/siem/all",
        "/v2/siem/clicks/blocked",
        "/v2/siem/messages/delivered",
        "/v2/forensics",
        "/v2/url/decode",
    ):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, pp_env):
    r = client.get("/api/v1/proofpoint-tap/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["proofpoint_principal_present"] is True
    assert body["proofpoint_secret_present"] is True
    assert body["status"] == "ok"


# ===========================================================================
# 503 paths (NO MOCKS rule)
# ===========================================================================


def test_siem_all_503_when_unconfigured(client, no_pp_env):
    r = client.get(
        "/api/v1/proofpoint-tap/v2/siem/all",
        headers=HEADERS,
        params={"sinceSeconds": 3600},
    )
    assert r.status_code == 503, r.text
    assert "PROOFPOINT_TAP_PRINCIPAL" in r.json()["detail"]


def test_clicks_blocked_503_when_unconfigured(client, no_pp_env):
    r = client.get(
        "/api/v1/proofpoint-tap/v2/siem/clicks/blocked", headers=HEADERS
    )
    assert r.status_code == 503


def test_messages_delivered_503_when_unconfigured(client, no_pp_env):
    r = client.get(
        "/api/v1/proofpoint-tap/v2/siem/messages/delivered", headers=HEADERS
    )
    assert r.status_code == 503


def test_forensics_503_when_unconfigured(client, no_pp_env):
    r = client.get(
        "/api/v1/proofpoint-tap/v2/forensics",
        headers=HEADERS,
        params={"threatId": "abc123"},
    )
    assert r.status_code == 503


def test_url_decode_get_503_when_unconfigured(client, no_pp_env):
    r = client.get(
        "/api/v1/proofpoint-tap/v2/url/decode",
        headers=HEADERS,
        params={"urls": "encoded-url-1"},
    )
    assert r.status_code == 503


def test_url_decode_post_503_when_unconfigured(client, no_pp_env):
    r = client.post(
        "/api/v1/proofpoint-tap/v2/url/decode",
        headers=HEADERS,
        json={"urls": ["encoded-url-1"]},
    )
    assert r.status_code == 503


def test_people_vap_503_when_unconfigured(client, no_pp_env):
    r = client.get("/api/v1/proofpoint-tap/v2/people/vap", headers=HEADERS)
    assert r.status_code == 503


def test_people_top_clickers_503_when_unconfigured(client, no_pp_env):
    r = client.get(
        "/api/v1/proofpoint-tap/v2/people/top-clickers", headers=HEADERS
    )
    assert r.status_code == 503


# ===========================================================================
# Forensics validation — both threatId & campaignId missing → 503
# ===========================================================================


def test_forensics_requires_threat_or_campaign_id(client, pp_env):
    r = client.get("/api/v1/proofpoint-tap/v2/forensics", headers=HEADERS)
    assert r.status_code == 503
    assert (
        "threatId" in r.json()["detail"]
        or "campaignId" in r.json()["detail"]
    )


# ===========================================================================
# SIEM /all passthrough
# ===========================================================================


def test_siem_all_returns_messages_and_clicks(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/siem/all": {
                "status": 200,
                "json": {
                    "queryEndTime": "2026-05-04T00:00:00Z",
                    "messagesDelivered": [
                        {
                            "GUID": "msg-1",
                            "messageID": "<abc@corp.com>",
                            "sender": "attacker@evil.test",
                            "fromAddress": "ceo@corp.com",
                            "recipient": ["victim@corp.com"],
                            "subject": "URGENT: wire transfer",
                            "phishScore": 87,
                            "spamScore": 23,
                            "malwareScore": 0,
                            "impostorScore": 99,
                            "threatsInfoMap": [
                                {
                                    "threat": "evil.test",
                                    "threatID": "t-1",
                                    "threatType": "url",
                                    "classification": "phish",
                                    "threatStatus": "active",
                                }
                            ],
                            "messageParts": [],
                            "modulesRun": ["pdr", "spam", "url"],
                        }
                    ],
                    "messagesBlocked": [],
                    "clicksBlocked": [
                        {
                            "GUID": "click-1",
                            "messageID": "<abc@corp.com>",
                            "userAgent": "Mozilla/5.0",
                            "clickIP": "203.0.113.5",
                            "sender": "attacker@evil.test",
                            "recipient": "victim@corp.com",
                            "url": "https://evil.test/phish",
                            "classification": "phish",
                            "threatStatus": "active",
                            "clickTime": "2026-05-04T00:00:01Z",
                            "threatTime": "2026-05-04T00:00:02Z",
                            "threatID": "t-1",
                        }
                    ],
                    "clicksPermitted": [],
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/siem/all",
        headers=HEADERS,
        params={"sinceSeconds": 3600},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["messagesDelivered"]) == 1
    assert body["messagesDelivered"][0]["impostorScore"] == 99
    assert len(body["clicksBlocked"]) == 1
    assert body["clicksBlocked"][0]["url"] == "https://evil.test/phish"


# ===========================================================================
# Clicks-only & Messages-only
# ===========================================================================


def test_siem_clicks_blocked_only(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/siem/clicks/blocked": {
                "status": 200,
                "json": {
                    "queryEndTime": "2026-05-04T00:00:00Z",
                    "clicksBlocked": [
                        {"GUID": "c-1", "url": "https://bad.test"}
                    ],
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/siem/clicks/blocked",
        headers=HEADERS,
        params={"sinceSeconds": 600},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["clicksBlocked"][0]["GUID"] == "c-1"


def test_siem_messages_delivered_only(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/siem/messages/delivered": {
                "status": 200,
                "json": {
                    "queryEndTime": "2026-05-04T00:00:00Z",
                    "messagesDelivered": [
                        {"GUID": "m-1", "subject": "weekly report"}
                    ],
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/siem/messages/delivered",
        headers=HEADERS,
        params={"sinceSeconds": 1200},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["messagesDelivered"][0]["GUID"] == "m-1"


# ===========================================================================
# Forensics
# ===========================================================================


def test_forensics_threat_report(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/forensics": {
                "status": 200,
                "json": {
                    "generated": "2026-05-04T00:00:00Z",
                    "reports": [
                        {
                            "name": "Emotet variant",
                            "scope": "threat",
                            "type": "malware",
                            "id": "t-99",
                            "forensics": [
                                {
                                    "type": "file",
                                    "display": "invoice.doc",
                                    "malicious": True,
                                    "time": "2026-05-04T00:00:00Z",
                                    "what": {
                                        "sha256": "deadbeef",
                                        "filename": "invoice.doc",
                                    },
                                    "platforms": ["win10"],
                                }
                            ],
                        }
                    ],
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/forensics",
        headers=HEADERS,
        params={"threatId": "t-99", "aggregate": "true"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reports"][0]["name"] == "Emotet variant"
    assert body["reports"][0]["forensics"][0]["malicious"] is True


def test_forensics_campaign_report(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/forensics": {
                "status": 200,
                "json": {
                    "generated": "2026-05-04T00:00:00Z",
                    "reports": [
                        {
                            "name": "Q2 phishing wave",
                            "scope": "campaign",
                            "type": "phish",
                            "id": "camp-7",
                            "forensics": [],
                        }
                    ],
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/forensics",
        headers=HEADERS,
        params={"campaignId": "camp-7", "aggregate": "true"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reports"][0]["scope"] == "campaign"


# ===========================================================================
# URL decode
# ===========================================================================


def test_url_decode_get(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/url/decode": {
                "status": 200,
                "json": {
                    "urls": [
                        {
                            "encodedUrl": "https://urldefense.proofpoint.com/v2/url?u=...",
                            "decodedUrl": "https://example.com/phish",
                            "success": True,
                            "urlDetails": {"clickerId": "u-1"},
                        }
                    ]
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/url/decode",
        headers=HEADERS,
        params={"urls": "encoded-blob-1,encoded-blob-2"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["urls"][0]["decodedUrl"] == "https://example.com/phish"
    assert body["urls"][0]["success"] is True


def test_url_decode_post(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/url/decode": {
                "status": 200,
                "json": {
                    "urls": [
                        {
                            "encodedUrl": "abc",
                            "decodedUrl": "https://safe.test",
                            "success": True,
                        },
                        {
                            "encodedUrl": "xyz",
                            "decodedUrl": None,
                            "success": False,
                            "error": "invalid encoding",
                        },
                    ]
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.post(
        "/api/v1/proofpoint-tap/v2/url/decode",
        headers=HEADERS,
        json={"urls": ["abc", "xyz"]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["urls"]) == 2
    assert body["urls"][1]["success"] is False


def test_url_decode_post_validates_body(client, pp_env):
    r = client.post(
        "/api/v1/proofpoint-tap/v2/url/decode",
        headers=HEADERS,
        json={"urls": []},
    )
    assert r.status_code == 400


# ===========================================================================
# People — VAP & top-clickers
# ===========================================================================


def test_people_vap(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/people/vap": {
                "status": 200,
                "json": {
                    "users": [
                        {
                            "identity": {
                                "emails": ["ceo@corp.com"],
                                "displayName": "CEO",
                                "department": "Exec",
                                "title": "Chief Executive",
                            },
                            "threatStatistics": {
                                "attackIndex": 87,
                                "families": [
                                    {"name": "BEC", "score": 90},
                                    {"name": "Phish", "score": 60},
                                ],
                            },
                        }
                    ]
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/people/vap",
        headers=HEADERS,
        params={"window": "14d", "size": 10},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["users"][0]["threatStatistics"]["attackIndex"] == 87
    assert body["users"][0]["identity"]["displayName"] == "CEO"


def test_people_top_clickers(client, pp_env, monkeypatch):
    handler = _make_handler(
        {
            "/v2/people/top-clickers": {
                "status": 200,
                "json": {
                    "users": [
                        {
                            "identity": {
                                "emails": ["intern@corp.com"],
                                "displayName": "Intern",
                            },
                            "threatStatistics": {
                                "attackIndex": 42,
                                "families": [{"name": "URL", "score": 99}],
                            },
                        }
                    ]
                },
            }
        }
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/people/top-clickers",
        headers=HEADERS,
        params={"window": "1d", "size": 5, "page": 1},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["users"][0]["identity"]["displayName"] == "Intern"


# ===========================================================================
# Upstream error → 503
# ===========================================================================


def test_upstream_5xx_becomes_503(client, pp_env, monkeypatch):
    handler = _make_handler(
        {"/v2/siem/all": {"status": 502, "json": {"err": "upstream"}}}
    )
    _install_httpx_stub(monkeypatch, handler)

    r = client.get(
        "/api/v1/proofpoint-tap/v2/siem/all", headers=HEADERS
    )
    assert r.status_code == 503
