"""Tests for mimecast_router — ALDECI.

Spins up a minimal FastAPI app with the Mimecast router mounted. Each test
resets the engine singleton and injects a stubbed httpx.Client so the real
HMAC-SHA1 signing + request-shaping code paths execute without going to
api.mimecast.com.

NO MOCKS rule:
  * All endpoints return HTTP 503 when any of the 5 envs unset.
  * Capability summary reports ``status="unavailable"`` when creds missing.
  * Happy paths assert the engine *did* sign the request properly
    (Authorization / x-mc-app-id / x-mc-date / x-mc-req-id).
"""
from __future__ import annotations

import base64
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
    def __init__(
        self,
        status_code: int,
        payload: Any,
        text: str = "",
        content: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.status_code = status_code
        self._payload = payload
        self.text = text or (json.dumps(payload) if payload is not None else "")
        self.content = content if content is not None else self.text.encode("utf-8")
        self.headers = headers or {"content-type": "application/json"}

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class _StubClient:
    """Records POST calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Any = None,
        data: Any = None,
    ):  # noqa: D401, A002
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "json": json,
                "data": data,
            }
        )
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_FAKE_SECRET_B64 = base64.b64encode(b"super-secret-bytes").decode("ascii")


def _set_creds(monkeypatch) -> None:
    monkeypatch.setenv("MIMECAST_BASE_URL", "https://us-api.mimecast.com")
    monkeypatch.setenv("MIMECAST_APP_ID", "app-id-123")
    monkeypatch.setenv("MIMECAST_APP_KEY", "app-key-abc")
    monkeypatch.setenv("MIMECAST_ACCESS_KEY", "access-key-xyz")
    monkeypatch.setenv("MIMECAST_SECRET_KEY", _FAKE_SECRET_B64)


def _clear_creds(monkeypatch) -> None:
    for k in (
        "MIMECAST_BASE_URL",
        "MIMECAST_APP_ID",
        "MIMECAST_APP_KEY",
        "MIMECAST_ACCESS_KEY",
        "MIMECAST_SECRET_KEY",
    ):
        monkeypatch.delenv(k, raising=False)


def _build_app(stub_responses: Dict[str, _StubResponse]):
    from core import mimecast_email_engine as engine_mod

    engine_mod.reset_mimecast_email_engine()
    stub_client = _StubClient(stub_responses)
    engine_mod.get_mimecast_email_engine(client=stub_client)

    from apps.api.mimecast_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import mimecast_email_engine as engine_mod

    engine_mod.reset_mimecast_email_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    _clear_creds(monkeypatch)
    app, _ = _build_app({})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/mimecast/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Mimecast Email Security"
    assert "/api/ttp/url/decode-url" in body["endpoints"]
    assert "/api/gateway/get-hold-message-list" in body["endpoints"]
    assert "/api/ttp/threat-intel/get-feed" in body["endpoints"]
    assert "/api/audit/get-siem-logs" in body["endpoints"]
    assert "/api/managedsender/get-managed-senders" in body["endpoints"]
    assert body["mimecast_app_id_present"] is False
    assert body["mimecast_app_key_present"] is False
    assert body["mimecast_access_key_present"] is False
    assert body["mimecast_secret_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_all_creds_present(monkeypatch):
    _set_creds(monkeypatch)
    app, _ = _build_app({})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/mimecast/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mimecast_app_id_present"] is True
    assert body["mimecast_app_key_present"] is True
    assert body["mimecast_access_key_present"] is True
    assert body["mimecast_secret_key_present"] is True
    assert body["status"] == "ok"
    _reset()


def test_capability_summary_unavailable_when_one_cred_missing(monkeypatch):
    _set_creds(monkeypatch)
    monkeypatch.delenv("MIMECAST_SECRET_KEY", raising=False)
    app, _ = _build_app({})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/mimecast/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["mimecast_secret_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,body",
    [
        ("/api/v1/mimecast/api/ttp/url/decode-url", {"data": [{"url": "https://x.test"}]}),
        (
            "/api/v1/mimecast/api/gateway/get-hold-message-list",
            {"meta": {"pagination": {"pageSize": 10}}, "data": [{"start": "x", "end": "y"}]},
        ),
        (
            "/api/v1/mimecast/api/gateway/release-hold-message",
            {"meta": {}, "data": [{"id": "abc"}]},
        ),
        (
            "/api/v1/mimecast/api/ttp/threat-intel/get-feed",
            {
                "meta": {},
                "data": [
                    {"feedType": "malware", "fileFormat": "csv", "fileType": "incremental"}
                ],
            },
        ),
        (
            "/api/v1/mimecast/api/audit/get-siem-logs",
            {
                "meta": {},
                "data": [
                    {"type": "gateway", "compress": False, "fileFormat": "json"}
                ],
            },
        ),
        (
            "/api/v1/mimecast/api/managedsender/get-managed-senders",
            {"meta": {}, "data": [{"filter": "Permitted", "type": "Email"}]},
        ),
        (
            "/api/v1/mimecast/api/policy/anti-spoofing/get-policy",
            {"meta": {}, "data": [{}]},
        ),
    ],
)
def test_endpoints_return_503_when_creds_missing(path, body, monkeypatch):
    _clear_creds(monkeypatch)
    app, _ = _build_app({})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(path, json=body, headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"].lower()
    assert "mimecast" in detail or "credentials" in detail
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client + assert HMAC headers were set
# ---------------------------------------------------------------------------


def _assert_signed_headers(call: Dict[str, Any]) -> None:
    h = call["headers"]
    assert h.get("Authorization", "").startswith("MC access-key-xyz:"), h
    assert h.get("x-mc-app-id") == "app-id-123"
    assert h.get("x-mc-req-id"), "expected x-mc-req-id"
    assert h.get("x-mc-date"), "expected x-mc-date (RFC2822)"


def test_decode_url_happy_path_signs_request(monkeypatch):
    _set_creds(monkeypatch)
    payload = {
        "meta": {"status": 200},
        "data": [
            {
                "url": "https://protect-eu.mimecast.com/s/AbCd",
                "decodedUrl": "https://example.com/landing",
                "success": True,
                "errors": [],
            }
        ],
    }
    app, stub = _build_app(
        {"/api/ttp/url/decode-url": _StubResponse(200, payload)}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/mimecast/api/ttp/url/decode-url",
        json={"data": [{"url": "https://protect-eu.mimecast.com/s/AbCd"}]},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"][0]["decodedUrl"] == "https://example.com/landing"
    assert body["data"][0]["success"] is True

    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["url"] == "https://us-api.mimecast.com/api/ttp/url/decode-url"
    _assert_signed_headers(call)
    assert call["json"] == {"data": [{"url": "https://protect-eu.mimecast.com/s/AbCd"}]}
    _reset()


def test_get_hold_message_list_happy_path(monkeypatch):
    _set_creds(monkeypatch)
    payload = {
        "meta": {"pagination": {"pageSize": 25, "next": "tok-2"}, "status": 200},
        "data": [
            {
                "id": "msg-1",
                "fromHdr": {"emailAddress": "alice@evil.test"},
                "fromEnv": {"emailAddress": "alice@evil.test"},
                "to": [{"emailAddress": "bob@victim.test"}],
                "sentDateTime": "2026-05-04T10:00:00Z",
                "status": "HELD",
                "route": "Inbound",
                "reason": "Spam_Suspect",
                "info": "Quarantined for review",
                "size": 12345,
                "attachments": [],
                "subject": "Invoice overdue",
                "hasError": False,
                "dateReceived": "2026-05-04T10:00:01Z",
            }
        ],
    }
    app, stub = _build_app(
        {"/api/gateway/get-hold-message-list": _StubResponse(200, payload)}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/mimecast/api/gateway/get-hold-message-list",
        json={
            "meta": {"pagination": {"pageSize": 25}},
            "data": [
                {
                    "start": "2026-05-04T00:00:00Z",
                    "end": "2026-05-04T23:59:59Z",
                    "admin": True,
                }
            ],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"][0]["id"] == "msg-1"
    assert body["data"][0]["status"] == "HELD"
    assert body["data"][0]["reason"] == "Spam_Suspect"

    _assert_signed_headers(stub.calls[0])
    assert stub.calls[0]["url"].endswith("/api/gateway/get-hold-message-list")
    _reset()


def test_threat_intel_feed_returns_b64_envelope(monkeypatch):
    _set_creds(monkeypatch)
    raw_csv = b"indicator,type\n1.2.3.4,ip\n5.6.7.8,ip\n"
    app, stub = _build_app(
        {
            "/api/ttp/threat-intel/get-feed": _StubResponse(
                200,
                None,
                content=raw_csv,
                headers={"content-type": "text/csv"},
            )
        }
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/mimecast/api/ttp/threat-intel/get-feed",
        json={
            "meta": {},
            "data": [
                {
                    "feedType": "malware",
                    "fileFormat": "csv",
                    "compress": False,
                    "fileType": "incremental",
                }
            ],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["content_type"] == "text/csv"
    assert body["content_length"] == len(raw_csv)
    decoded = base64.b64decode(body["content_b64"])
    assert decoded == raw_csv

    _assert_signed_headers(stub.calls[0])
    _reset()


def test_managed_senders_happy_path(monkeypatch):
    _set_creds(monkeypatch)
    payload = {
        "meta": {"status": 200},
        "data": [
            {
                "sender": "noreply@trusted.test",
                "type": "Email",
                "source": "Internal",
                "comment": "Vendor notifications",
                "scope": "Profile",
                "lastUpdated": "2026-04-01T00:00:00Z",
            }
        ],
    }
    app, stub = _build_app(
        {"/api/managedsender/get-managed-senders": _StubResponse(200, payload)}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/mimecast/api/managedsender/get-managed-senders",
        json={"meta": {}, "data": [{"filter": "Permitted", "type": "Email"}]},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"][0]["sender"] == "noreply@trusted.test"
    assert body["data"][0]["scope"] == "Profile"
    _assert_signed_headers(stub.calls[0])
    _reset()


def test_release_and_anti_spoofing_and_siem_smoke(monkeypatch):
    """Quick smoke that release / anti-spoofing-policy / siem-logs all sign + return."""
    _set_creds(monkeypatch)
    app, stub = _build_app(
        {
            "/api/gateway/release-hold-message": _StubResponse(
                200, {"meta": {"status": 200}, "data": [{"id": "msg-1", "released": True}]}
            ),
            "/api/policy/anti-spoofing/get-policy": _StubResponse(
                200,
                {
                    "meta": {"status": 200},
                    "data": [{"id": "pol-1", "policy": {"action": "block"}}],
                },
            ),
            "/api/audit/get-siem-logs": _StubResponse(
                200,
                {
                    "meta": {"isLastToken": True},
                    "data": [{"timestamp": "2026-05-04T10:00:00Z", "event": "delivery"}],
                },
            ),
        }
    )
    client = TestClient(app, raise_server_exceptions=True)

    r1 = client.post(
        "/api/v1/mimecast/api/gateway/release-hold-message",
        json={"meta": {}, "data": [{"id": "msg-1"}]},
        headers=HEADERS,
    )
    assert r1.status_code == 200
    assert r1.json()["data"][0]["released"] is True

    r2 = client.post(
        "/api/v1/mimecast/api/policy/anti-spoofing/get-policy",
        json={"meta": {}, "data": [{}]},
        headers=HEADERS,
    )
    assert r2.status_code == 200
    assert r2.json()["data"][0]["id"] == "pol-1"

    r3 = client.post(
        "/api/v1/mimecast/api/audit/get-siem-logs",
        json={
            "meta": {},
            "data": [
                {"type": "delivery", "compress": False, "fileFormat": "json"}
            ],
        },
        headers=HEADERS,
    )
    assert r3.status_code == 200
    assert r3.json()["data"][0]["event"] == "delivery"

    assert len(stub.calls) == 3
    for call in stub.calls:
        _assert_signed_headers(call)
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths
# ---------------------------------------------------------------------------


def test_decode_url_returns_503_on_upstream_429(monkeypatch):
    _set_creds(monkeypatch)
    app, _ = _build_app(
        {
            "/api/ttp/url/decode-url": _StubResponse(
                429, {"errors": [{"detail": "Too Many Requests"}]}, text="rate limit"
            )
        }
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/mimecast/api/ttp/url/decode-url",
        json={"data": [{"url": "https://x.test"}]},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"].lower()
    assert "rate-limit" in detail or "429" in detail
    _reset()


def test_decode_url_returns_503_on_401(monkeypatch):
    _set_creds(monkeypatch)
    app, _ = _build_app(
        {"/api/ttp/url/decode-url": _StubResponse(401, {"fail": "auth"}, text="unauthorized")}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/mimecast/api/ttp/url/decode-url",
        json={"data": [{"url": "https://x.test"}]},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "rejected credentials" in r.json()["detail"].lower()
    _reset()


def test_invalid_secret_key_base64_returns_503(monkeypatch):
    """Bad base64 in MIMECAST_SECRET_KEY → 503 (not a 500 stack trace)."""
    monkeypatch.setenv("MIMECAST_BASE_URL", "https://us-api.mimecast.com")
    monkeypatch.setenv("MIMECAST_APP_ID", "app-id-123")
    monkeypatch.setenv("MIMECAST_APP_KEY", "app-key-abc")
    monkeypatch.setenv("MIMECAST_ACCESS_KEY", "access-key-xyz")
    # NB: '@' is not a valid base64 character → b64decode raises.
    monkeypatch.setenv("MIMECAST_SECRET_KEY", "not@valid@base64@@@")
    app, _ = _build_app({})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/mimecast/api/ttp/url/decode-url",
        json={"data": [{"url": "https://x.test"}]},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()
