"""Tests for the Microsoft Teams router (NO MOCKS in production code).

The engine talks to the Teams Incoming Webhook URL + https://graph.microsoft.com
via httpx. We:
  - Verify capability summary reflects env presence (status: ok|empty|unavailable).
  - Verify endpoints return HTTP 503 when both env vars are unset.
  - Verify webhook works when only TEAMS_WEBHOOK_URL is set.
  - Verify graph endpoints need TEAMS_GRAPH_TOKEN.
  - Inject a stub httpx.Client into the singleton for happy-path tests so we
    still exercise the real parsing/normalisation code paths.
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
        self.text = text or (json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload))

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
        # Longest prefix-substring wins so /channels/{id}/messages beats /channels.
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

    def post(self, url, headers=None, json=None, data=None):
        self.calls.append(
            {"method": "POST", "url": url, "headers": dict(headers or {}), "json": json}
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------- helpers


def _build_app(
    *,
    webhook_url: Optional[str],
    graph_token: Optional[str],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    from core import microsoft_teams_engine as eng_mod

    eng_mod.reset_microsoft_teams_engine()

    stub_client = _StubClient(stub_responses or {})
    eng_mod.get_microsoft_teams_engine(
        webhook_url=webhook_url,
        graph_token=graph_token,
        client=stub_client,
    )

    from apps.api.microsoft_teams_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset() -> None:
    from core import microsoft_teams_engine as eng_mod
    eng_mod.reset_microsoft_teams_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_env(monkeypatch):
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("TEAMS_GRAPH_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, graph_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/microsoft-teams/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Microsoft Teams"
    assert "/webhook" in body["endpoints"]
    assert "/v1.0/me/joinedTeams" in body["endpoints"]
    assert "/v1.0/teams/{team_id}/channels" in body["endpoints"]
    assert "/v1.0/teams/{team_id}/channels/{channel_id}/messages" in body["endpoints"]
    assert body["webhook_url_present"] is False
    assert body["graph_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_only_webhook(monkeypatch):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/abc/def")
    monkeypatch.delenv("TEAMS_GRAPH_TOKEN", raising=False)
    app, _ = _build_app(
        webhook_url="https://outlook.office.com/webhook/abc/def",
        graph_token=None,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/microsoft-teams/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["webhook_url_present"] is True
    assert body["graph_token_present"] is False
    assert body["status"] == "empty"
    _reset()


def test_capability_summary_ok_when_both_present(monkeypatch):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/abc/def")
    monkeypatch.setenv("TEAMS_GRAPH_TOKEN", "eyJ0eXAiOiJKV1Q.xyz")
    app, _ = _build_app(
        webhook_url="https://outlook.office.com/webhook/abc/def",
        graph_token="eyJ0eXAiOiJKV1Q.xyz",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/microsoft-teams/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["webhook_url_present"] is True
    assert body["graph_token_present"] is True
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_webhook_returns_503_when_no_url(monkeypatch):
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("TEAMS_GRAPH_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, graph_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/microsoft-teams/webhook",
        headers=HEADERS,
        json={"text": "hello"},
    )
    assert r.status_code == 503, r.text
    assert "TEAMS_WEBHOOK_URL" in r.json()["detail"]
    _reset()


def test_joined_teams_returns_503_when_no_graph_token(monkeypatch):
    monkeypatch.delenv("TEAMS_GRAPH_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, graph_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/microsoft-teams/v1.0/me/joinedTeams", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "TEAMS_GRAPH_TOKEN" in r.json()["detail"]
    _reset()


def test_list_channels_returns_503_when_no_graph_token(monkeypatch):
    monkeypatch.delenv("TEAMS_GRAPH_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, graph_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/microsoft-teams/v1.0/teams/team-1/channels",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_post_channel_message_returns_503_when_no_graph_token(monkeypatch):
    monkeypatch.delenv("TEAMS_GRAPH_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, graph_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/microsoft-teams/v1.0/teams/team-1/channels/19:abc@thread.tacv2/messages",
        headers=HEADERS,
        json={"body": {"contentType": "html", "content": "<p>Hi</p>"}},
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ webhook only


def test_webhook_works_with_only_webhook_url_set(monkeypatch):
    """Webhook capability is independent of TEAMS_GRAPH_TOKEN."""
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/abc/def")
    monkeypatch.delenv("TEAMS_GRAPH_TOKEN", raising=False)
    app, stub = _build_app(
        webhook_url="https://outlook.office.com/webhook/abc/def",
        graph_token=None,
        stub_responses={
            "outlook.office.com/webhook": _StubResponse(200, "1", text="1"),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/microsoft-teams/webhook",
        headers=HEADERS,
        json={
            "text": "Critical CVE detected",
            "summary": "ALDECI alert",
            "themeColor": "FF0000",
            "sections": [
                {
                    "activityTitle": "Critical CVE",
                    "facts": [{"name": "CVE", "value": "CVE-2026-12345"}],
                    "markdown": True,
                }
            ],
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "View Alert",
                    "targets": [{"os": "default", "uri": "https://aldeci.example/alerts/1"}],
                }
            ],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["delivered"] is True
    assert body["status"] == 200
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts and "outlook.office.com/webhook" in posts[0]["url"]
    sent = posts[0]["json"]
    assert sent["text"] == "Critical CVE detected"
    assert sent["sections"][0]["facts"][0]["name"] == "CVE"
    _reset()


def test_webhook_accepts_adaptive_card(monkeypatch):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/abc/def")
    monkeypatch.delenv("TEAMS_GRAPH_TOKEN", raising=False)
    app, stub = _build_app(
        webhook_url="https://outlook.office.com/webhook/abc/def",
        graph_token=None,
        stub_responses={
            "outlook.office.com/webhook": _StubResponse(202, {"ok": True}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": "Hello from ALDECI", "weight": "Bolder"},
                    ],
                },
            }
        ],
    }
    r = client.post("/api/v1/microsoft-teams/webhook", headers=HEADERS, json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["delivered"] is True
    assert body["status"] == 202
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts
    assert posts[0]["json"]["attachments"][0]["contentType"].startswith(
        "application/vnd.microsoft.card.adaptive"
    )
    _reset()


def test_webhook_validation_rejects_empty_payload(monkeypatch):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/abc/def")
    app, _ = _build_app(
        webhook_url="https://outlook.office.com/webhook/abc/def",
        graph_token=None,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post("/api/v1/microsoft-teams/webhook", headers=HEADERS, json={})
    assert r.status_code == 422, r.text
    _reset()


# ============================================================ graph happy paths


def test_list_joined_teams_happy_path(monkeypatch):
    monkeypatch.setenv("TEAMS_GRAPH_TOKEN", "eyJ0.token")
    raw = {
        "value": [
            {
                "id": "team-1",
                "displayName": "Engineering",
                "description": "Eng team",
            },
            {
                "id": "team-2",
                "displayName": "Security",
                "description": "Sec team",
            },
        ]
    }
    app, stub = _build_app(
        webhook_url=None,
        graph_token="eyJ0.token",
        stub_responses={"/me/joinedTeams": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/microsoft-teams/v1.0/me/joinedTeams", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["value"]) == 2
    assert body["value"][0]["displayName"] == "Engineering"
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth == "Bearer eyJ0.token"
    _reset()


def test_list_channels_happy_path(monkeypatch):
    monkeypatch.setenv("TEAMS_GRAPH_TOKEN", "eyJ0.token")
    raw = {
        "value": [
            {
                "id": "19:abc@thread.tacv2",
                "displayName": "General",
                "description": "Default channel",
                "email": "general@team1.example",
                "webUrl": "https://teams.microsoft.com/l/channel/abc",
                "membershipType": "standard",
            }
        ]
    }
    app, _ = _build_app(
        webhook_url=None,
        graph_token="eyJ0.token",
        stub_responses={"/teams/team-1/channels": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/microsoft-teams/v1.0/teams/team-1/channels", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["value"][0]["id"] == "19:abc@thread.tacv2"
    assert body["value"][0]["membershipType"] == "standard"
    _reset()


def test_post_channel_message_happy_path(monkeypatch):
    monkeypatch.setenv("TEAMS_GRAPH_TOKEN", "eyJ0.token")
    raw = {
        "id": "1612345678901",
        "etag": "1612345678901",
        "messageType": "message",
        "createdDateTime": "2026-05-04T10:00:00Z",
        "lastModifiedDateTime": "2026-05-04T10:00:00Z",
        "deletedDateTime": None,
        "subject": None,
        "summary": None,
        "importance": "normal",
        "locale": "en-us",
        "from": {
            "user": {
                "id": "u-1",
                "displayName": "Alice",
                "userIdentityType": "aadUser",
            }
        },
        "body": {"contentType": "html", "content": "<p>Hi</p>"},
        "attachments": [],
    }
    app, stub = _build_app(
        webhook_url=None,
        graph_token="eyJ0.token",
        stub_responses={
            "/teams/team-1/channels/19:abc@thread.tacv2/messages": _StubResponse(
                201, raw
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/microsoft-teams/v1.0/teams/team-1/channels/19:abc@thread.tacv2/messages",
        headers=HEADERS,
        json={"body": {"contentType": "html", "content": "<p>Hi</p>"}},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["id"] == "1612345678901"
    assert body["messageType"] == "message"
    assert body["body"]["contentType"] == "html"
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts
    assert posts[0]["json"]["body"]["content"] == "<p>Hi</p>"
    _reset()


def test_list_channel_messages_with_top(monkeypatch):
    monkeypatch.setenv("TEAMS_GRAPH_TOKEN", "eyJ0.token")
    raw = {
        "@odata.count": 1,
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/teams/team-1/channels/19:abc@thread.tacv2/messages?$skiptoken=abc",
        "value": [
            {
                "id": "msg-1",
                "etag": "etag-1",
                "messageType": "message",
                "createdDateTime": "2026-05-04T09:00:00Z",
                "body": {"contentType": "html", "content": "<p>old</p>"},
            }
        ],
    }
    app, stub = _build_app(
        webhook_url=None,
        graph_token="eyJ0.token",
        stub_responses={
            "/teams/team-1/channels/19:abc@thread.tacv2/messages": _StubResponse(
                200, raw
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/microsoft-teams/v1.0/teams/team-1/channels/19:abc@thread.tacv2/messages",
        headers=HEADERS,
        params={"$top": 5},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["value"][0]["id"] == "msg-1"
    assert body["@odata.count"] == 1
    assert body["@odata.nextLink"].startswith("https://graph.microsoft.com")
    sent_params = stub.calls[0]["params"] or {}
    if isinstance(sent_params, list):
        flat = dict(sent_params)
    else:
        flat = dict(sent_params)
    assert flat.get("$top") == 5
    _reset()


# ============================================================ error mapping


def test_webhook_returns_503_on_upstream_failure(monkeypatch):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/abc/def")
    app, _ = _build_app(
        webhook_url="https://outlook.office.com/webhook/abc/def",
        graph_token=None,
        stub_responses={
            "outlook.office.com/webhook": _StubResponse(
                500, {"err": "boom"}, text="boom"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/microsoft-teams/webhook",
        headers=HEADERS,
        json={"text": "hi"},
    )
    assert r.status_code == 503, r.text
    assert "500" in r.json()["detail"]
    _reset()


def test_graph_returns_503_on_401(monkeypatch):
    monkeypatch.setenv("TEAMS_GRAPH_TOKEN", "bad.token")
    app, _ = _build_app(
        webhook_url=None,
        graph_token="bad.token",
        stub_responses={
            "/me/joinedTeams": _StubResponse(401, {"error": "invalid_token"}, text="401")
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/microsoft-teams/v1.0/me/joinedTeams", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"]
    _reset()


def test_post_channel_message_validation_rejects_missing_body(monkeypatch):
    monkeypatch.setenv("TEAMS_GRAPH_TOKEN", "eyJ0.token")
    app, _ = _build_app(webhook_url=None, graph_token="eyJ0.token")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/microsoft-teams/v1.0/teams/team-1/channels/19:abc@thread.tacv2/messages",
        headers=HEADERS,
        json={"mentions": []},
    )
    assert r.status_code == 422, r.text
    _reset()
