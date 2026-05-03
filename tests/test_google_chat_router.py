"""Tests for the Google Chat router (NO MOCKS in production code).

The engine talks to the Google Chat incoming webhook URL + the Google Chat
REST API v1 via httpx. We:
  - Verify capability summary reflects env presence (status: ok|empty|unavailable).
  - Verify endpoints return HTTP 503 when both env vars are unset.
  - Verify webhook works when only GCHAT_WEBHOOK_URL is set.
  - Verify REST endpoints need GOOGLE_APPLICATION_CREDENTIALS.
  - Inject a stub httpx.Client + a stub access-token to bypass the JWT
    signing path so we still exercise the real parsing/normalisation code.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------- httpx stub


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or (
            json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)
        )

    def json(self) -> Any:
        if isinstance(self._payload, (dict, list)):
            return self._payload
        raise ValueError("non-json payload")


class _StubClient:
    """Routes by URL substring. Records every call."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        # Longest substring wins so /spaces/{id}/members beats /spaces.
        best: Optional[_StubResponse] = None
        best_len = -1
        for path, resp in self._responses.items():
            if path in url and len(path) > best_len:
                best = resp
                best_len = len(path)
        if best is not None:
            return best
        return _StubResponse(404, {"error": "not_found"}, text="not found")

    def get(self, url, headers=None, params=None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {}), "params": params}
        )
        return self._match(url)

    def post(self, url, headers=None, json=None, params=None, data=None):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "json": json,
                "params": params,
                "data": data,
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------- helpers


_FAKE_CREDS = {
    "type": "service_account",
    "project_id": "test-project",
    "private_key_id": "abc",
    "private_key": "-----BEGIN PRIVATE KEY-----\nNOT_A_REAL_KEY\n-----END PRIVATE KEY-----\n",
    "client_email": "aldeci-bot@test-project.iam.gserviceaccount.com",
    "client_id": "1234567890",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
}


def _build_app(
    *,
    webhook_url: Optional[str],
    creds: Optional[Dict[str, Any]],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
    inject_token: Optional[str] = "stub-access-token",
):
    from core import google_chat_engine as eng_mod

    eng_mod.reset_google_chat_engine()

    stub_client = _StubClient(stub_responses or {})
    eng = eng_mod.get_google_chat_engine(
        webhook_url=webhook_url,
        creds_data=creds,
        client=stub_client,
    )
    # Bypass the real JWT/OAuth2 token exchange — set a long-lived stub token.
    if inject_token is not None and creds is not None:
        eng._access_token = inject_token  # type: ignore[attr-defined]
        # 1 hour from now
        import time as _time

        eng._access_token_expiry = _time.time() + 3600  # type: ignore[attr-defined]

    from apps.api.google_chat_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset() -> None:
    from core import google_chat_engine as eng_mod

    eng_mod.reset_google_chat_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_env(monkeypatch):
    monkeypatch.delenv("GCHAT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(webhook_url=None, creds=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/google-chat/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Google Chat"
    assert "/webhook" in body["endpoints"]
    assert "/v1/spaces" in body["endpoints"]
    assert "/v1/spaces/{space}/messages" in body["endpoints"]
    assert "/v1/spaces/{space}/members" in body["endpoints"]
    assert body["gchat_webhook_url_present"] is False
    assert body["google_app_creds_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_only_webhook(monkeypatch):
    monkeypatch.setenv("GCHAT_WEBHOOK_URL", "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t")
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(
        webhook_url="https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t",
        creds=None,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/google-chat/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["gchat_webhook_url_present"] is True
    assert body["google_app_creds_present"] is False
    assert body["status"] == "empty"
    _reset()


def test_capability_summary_ok_when_both_present(monkeypatch):
    monkeypatch.setenv("GCHAT_WEBHOOK_URL", "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t")
    app, _ = _build_app(
        webhook_url="https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t",
        creds=_FAKE_CREDS,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/google-chat/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["gchat_webhook_url_present"] is True
    assert body["google_app_creds_present"] is True
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_webhook_returns_503_when_no_url(monkeypatch):
    monkeypatch.delenv("GCHAT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(webhook_url=None, creds=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/google-chat/webhook",
        headers=HEADERS,
        json={"text": "hello"},
    )
    assert r.status_code == 503, r.text
    assert "GCHAT_WEBHOOK_URL" in r.json()["detail"]
    _reset()


def test_list_spaces_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(webhook_url=None, creds=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/google-chat/v1/spaces", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "GOOGLE_APPLICATION_CREDENTIALS" in r.json()["detail"]
    _reset()


def test_list_members_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(webhook_url=None, creds=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/google-chat/v1/spaces/AAAA/members",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_post_message_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(webhook_url=None, creds=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/google-chat/v1/spaces/AAAA/messages",
        headers=HEADERS,
        json={"text": "hi"},
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ webhook only


def test_webhook_works_with_only_webhook_url_set(monkeypatch):
    """Webhook capability is independent of GOOGLE_APPLICATION_CREDENTIALS."""
    url = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t"
    monkeypatch.setenv("GCHAT_WEBHOOK_URL", url)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, stub = _build_app(
        webhook_url=url,
        creds=None,
        stub_responses={
            "chat.googleapis.com/v1/spaces/AAAA/messages": _StubResponse(
                200, {"name": "spaces/AAAA/messages/M-1"}
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/google-chat/webhook",
        headers=HEADERS,
        json={
            "text": "Critical CVE detected",
            "cards": [
                {
                    "header": {
                        "title": "Critical CVE",
                        "subtitle": "ALDECI alert",
                        "imageUrl": "https://aldeci.example/logo.png",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {"textParagraph": {"text": "CVE-2026-12345 detected"}}
                            ]
                        }
                    ],
                }
            ],
            "fallbackText": "ALDECI critical alert",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["delivered"] is True
    assert body["status"] == 200
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts and "chat.googleapis.com" in posts[0]["url"]
    sent = posts[0]["json"]
    assert sent["text"] == "Critical CVE detected"
    assert sent["cards"][0]["header"]["title"] == "Critical CVE"
    _reset()


def test_webhook_accepts_cards_v2(monkeypatch):
    url = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t"
    monkeypatch.setenv("GCHAT_WEBHOOK_URL", url)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, stub = _build_app(
        webhook_url=url,
        creds=None,
        stub_responses={
            "chat.googleapis.com": _StubResponse(200, {"ok": True}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    payload = {
        "cardsV2": [
            {
                "cardId": "alert-card-1",
                "card": {
                    "header": {"title": "Hello from ALDECI"},
                    "sections": [
                        {
                            "widgets": [
                                {"textParagraph": {"text": "Hi from cardsV2"}}
                            ]
                        }
                    ],
                },
            }
        ],
        "thread": {"threadKey": "incident-42"},
    }
    r = client.post("/api/v1/google-chat/webhook", headers=HEADERS, json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["delivered"] is True
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts
    assert posts[0]["json"]["cardsV2"][0]["cardId"] == "alert-card-1"
    _reset()


def test_webhook_validation_rejects_empty_payload(monkeypatch):
    monkeypatch.setenv(
        "GCHAT_WEBHOOK_URL",
        "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t",
    )
    app, _ = _build_app(
        webhook_url="https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t",
        creds=None,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post("/api/v1/google-chat/webhook", headers=HEADERS, json={})
    assert r.status_code == 422, r.text
    _reset()


def test_webhook_validation_rejects_payload_without_text_or_cards(monkeypatch):
    url = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t"
    monkeypatch.setenv("GCHAT_WEBHOOK_URL", url)
    app, _ = _build_app(webhook_url=url, creds=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/google-chat/webhook",
        headers=HEADERS,
        json={"fallbackText": "no text or card here"},
    )
    assert r.status_code == 422, r.text
    assert "text" in r.json()["detail"].lower() or "card" in r.json()["detail"].lower()
    _reset()


# ============================================================ REST happy paths


def test_list_spaces_happy_path(monkeypatch):
    raw = {
        "spaces": [
            {
                "name": "spaces/AAAA",
                "type": "DIRECT_MESSAGE",
                "displayName": "DM with Alice",
                "externalUserAllowed": False,
                "createTime": "2026-01-01T00:00:00Z",
            },
            {
                "name": "spaces/BBBB",
                "type": "SPACE",
                "displayName": "Engineering",
                "externalUserAllowed": True,
                "createTime": "2026-02-01T00:00:00Z",
            },
        ],
        "nextPageToken": "page-2",
    }
    app, stub = _build_app(
        webhook_url=None,
        creds=_FAKE_CREDS,
        stub_responses={"/v1/spaces": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/google-chat/v1/spaces",
        headers=HEADERS,
        params={"pageSize": 10},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["spaces"]) == 2
    assert body["spaces"][1]["displayName"] == "Engineering"
    assert body["nextPageToken"] == "page-2"
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth == "Bearer stub-access-token"
    sent_params = stub.calls[0]["params"] or {}
    flat = dict(sent_params) if not isinstance(sent_params, dict) else sent_params
    assert flat.get("pageSize") == 10
    _reset()


def test_list_members_happy_path(monkeypatch):
    raw = {
        "memberships": [
            {
                "name": "spaces/BBBB/members/u-1",
                "state": "JOINED",
                "role": "ROLE_MEMBER",
                "member": {
                    "name": "users/u-1",
                    "displayName": "Alice",
                    "type": "HUMAN",
                },
                "createTime": "2026-02-01T00:00:00Z",
            }
        ]
    }
    app, _ = _build_app(
        webhook_url=None,
        creds=_FAKE_CREDS,
        stub_responses={"/spaces/BBBB/members": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/google-chat/v1/spaces/BBBB/members",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["memberships"][0]["member"]["displayName"] == "Alice"
    assert body["memberships"][0]["state"] == "JOINED"
    _reset()


def test_post_message_happy_path(monkeypatch):
    raw = {
        "name": "spaces/BBBB/messages/M-1",
        "sender": {
            "name": "users/bot-1",
            "displayName": "ALDECI Bot",
            "type": "BOT",
        },
        "text": "Hi from the bot",
        "createTime": "2026-05-04T10:00:00Z",
        "space": {"name": "spaces/BBBB", "type": "SPACE"},
        "thread": {"name": "spaces/BBBB/threads/T-1"},
    }
    app, stub = _build_app(
        webhook_url=None,
        creds=_FAKE_CREDS,
        stub_responses={
            "/spaces/BBBB/messages": _StubResponse(201, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/google-chat/v1/spaces/BBBB/messages",
        headers=HEADERS,
        json={"text": "Hi from the bot"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "spaces/BBBB/messages/M-1"
    assert body["sender"]["type"] == "BOT"
    posts = [c for c in stub.calls if c["method"] == "POST"]
    # Only the message POST should be present (token already injected).
    assert posts
    assert posts[0]["json"]["text"] == "Hi from the bot"
    _reset()


def test_post_message_with_thread_reply_option(monkeypatch):
    raw = {"name": "spaces/BBBB/messages/M-2"}
    app, stub = _build_app(
        webhook_url=None,
        creds=_FAKE_CREDS,
        stub_responses={"/spaces/BBBB/messages": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/google-chat/v1/spaces/BBBB/messages",
        headers=HEADERS,
        json={
            "text": "Reply",
            "thread": {"threadKey": "incident-42"},
        },
    )
    assert r.status_code == 200, r.text
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts
    sent_params = posts[0]["params"] or {}
    flat = dict(sent_params) if not isinstance(sent_params, dict) else sent_params
    assert flat.get("messageReplyOption") == "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
    _reset()


def test_post_message_validation_rejects_missing_content(monkeypatch):
    app, _ = _build_app(webhook_url=None, creds=_FAKE_CREDS)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/google-chat/v1/spaces/BBBB/messages",
        headers=HEADERS,
        json={"fallbackText": "no body"},
    )
    assert r.status_code == 422, r.text
    _reset()


# ============================================================ error mapping


def test_webhook_returns_503_on_upstream_failure(monkeypatch):
    url = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t"
    monkeypatch.setenv("GCHAT_WEBHOOK_URL", url)
    app, _ = _build_app(
        webhook_url=url,
        creds=None,
        stub_responses={
            "chat.googleapis.com": _StubResponse(
                500, {"err": "boom"}, text="boom"
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/google-chat/webhook",
        headers=HEADERS,
        json={"text": "hi"},
    )
    assert r.status_code == 503, r.text
    assert "500" in r.json()["detail"]
    _reset()


def test_rest_returns_503_on_401(monkeypatch):
    app, _ = _build_app(
        webhook_url=None,
        creds=_FAKE_CREDS,
        stub_responses={
            "/v1/spaces": _StubResponse(401, {"error": "invalid_token"}, text="401"),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/google-chat/v1/spaces", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"]
    _reset()
