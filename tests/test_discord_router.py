"""Tests for the Discord integration router (NO MOCKS).

The engine talks to https://discord.com/api/v10 + https://discord.com/api/webhooks
via httpx. We:
  - Verify capability summary reflects env presence (status: ok|empty|unavailable).
  - Verify endpoints return HTTP 503 when DISCORD_BOT_TOKEN is unset.
  - Inject a stub httpx.Client into the singleton for happy-path tests so we
    still exercise the real parsing/normalisation code paths.

NO HARDCODED MOCK PAYLOADS in production code paths — the only stubs are
in this test file's local httpx adapter.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
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
        return self._payload


class _StubClient:
    """Routes by URL substring. Records every call."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        # Longest substring wins so e.g. /channels/.../messages beats /channels
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

    def post(self, url, headers=None, json=None, data=None, params=None):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "json": json,
                "params": params,
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------- helpers


def _build_app(
    *,
    webhook_url: Optional[str],
    bot_token: Optional[str],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    from core import discord_integration_engine as eng_mod

    eng_mod.reset_discord_integration_engine()

    stub_client = _StubClient(stub_responses or {})
    eng_mod.get_discord_integration_engine(
        webhook_url=webhook_url,
        bot_token=bot_token,
        client=stub_client,
    )

    from apps.api.discord_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset() -> None:
    from core import discord_integration_engine as eng_mod

    eng_mod.reset_discord_integration_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_env(monkeypatch):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, bot_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/discord/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Discord"
    assert "/webhooks/{wh_id}/{wh_token}" in body["endpoints"]
    assert "/api/v10/channels/{channel_id}/messages" in body["endpoints"]
    assert "/api/v10/guilds/{guild_id}/channels" in body["endpoints"]
    assert "/api/v10/users/@me/guilds" in body["endpoints"]
    assert body["webhook_url_present"] is False
    assert body["bot_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_only_webhook(monkeypatch):
    monkeypatch.setenv(
        "DISCORD_WEBHOOK_URL",
        "https://discord.com/api/webhooks/123/abc",
    )
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    app, _ = _build_app(
        webhook_url="https://discord.com/api/webhooks/123/abc",
        bot_token=None,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/discord/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["webhook_url_present"] is True
    assert body["bot_token_present"] is False
    assert body["status"] == "empty"
    _reset()


def test_capability_summary_ok_when_bot_token_present(monkeypatch):
    monkeypatch.setenv(
        "DISCORD_WEBHOOK_URL",
        "https://discord.com/api/webhooks/123/abc",
    )
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "BOT.xxx.yyy")
    app, _ = _build_app(
        webhook_url="https://discord.com/api/webhooks/123/abc",
        bot_token="BOT.xxx.yyy",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/discord/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["webhook_url_present"] is True
    assert body["bot_token_present"] is True
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_list_channel_messages_returns_503_when_no_bot_token(monkeypatch):
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, bot_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/discord/api/v10/channels/123/messages",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "DISCORD_BOT_TOKEN" in r.json()["detail"]
    _reset()


def test_list_guild_channels_returns_503_when_no_bot_token(monkeypatch):
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, bot_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/discord/api/v10/guilds/9999/channels",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_list_user_guilds_returns_503_when_no_bot_token(monkeypatch):
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, bot_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/discord/api/v10/users/@me/guilds",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_create_channel_message_returns_503_when_no_bot_token(monkeypatch):
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    app, _ = _build_app(webhook_url=None, bot_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/discord/api/v10/channels/123/messages",
        headers=HEADERS,
        json={"content": "Hello, world"},
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ happy paths


def test_execute_webhook_returns_204_default(monkeypatch):
    monkeypatch.setenv(
        "DISCORD_WEBHOOK_URL",
        "https://discord.com/api/webhooks/123/abc",
    )
    app, stub = _build_app(
        webhook_url="https://discord.com/api/webhooks/123/abc",
        bot_token=None,
        stub_responses={"/webhooks/123/abc": _StubResponse(204, None, text="")},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/discord/webhooks/123/abc",
        headers=HEADERS,
        json={
            "content": "ALDECI: 3 critical CVEs detected in prod",
            "username": "ALDECI Bot",
            "embeds": [
                {
                    "title": "Critical CVE Alert",
                    "description": "CVE-2026-12345",
                    "color": 16711680,
                    "fields": [
                        {"name": "Severity", "value": "9.8", "inline": True}
                    ],
                }
            ],
        },
    )
    assert r.status_code == 204, r.text
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts, "expected at least one POST"
    sent = posts[0]["json"]
    assert sent["content"].startswith("ALDECI:")
    assert sent["embeds"][0]["title"] == "Critical CVE Alert"
    _reset()


def test_execute_webhook_with_wait_returns_message(monkeypatch):
    monkeypatch.setenv(
        "DISCORD_WEBHOOK_URL",
        "https://discord.com/api/webhooks/123/abc",
    )
    raw = {
        "id": "987654321",
        "channel_id": "555",
        "content": "Sent via webhook",
        "timestamp": "2026-05-04T10:00:00.000000+00:00",
        "author": {"id": "1", "username": "ALDECI Bot", "bot": True},
    }
    app, stub = _build_app(
        webhook_url="https://discord.com/api/webhooks/123/abc",
        bot_token=None,
        stub_responses={"/webhooks/123/abc": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/discord/webhooks/123/abc?wait=true",
        headers=HEADERS,
        json={"content": "Sent via webhook"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "987654321"
    assert body["content"] == "Sent via webhook"
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts
    sent_params = posts[0]["params"]
    flat = (
        list(sent_params)
        if isinstance(sent_params, list)
        else (list(sent_params.items()) if sent_params else [])
    )
    assert ("wait", "true") in flat
    _reset()


def test_list_channel_messages_happy_path(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "BOT.xxx.yyy")
    raw = [
        {
            "id": "111",
            "channel_id": "555",
            "author": {
                "id": "1",
                "username": "alice",
                "discriminator": "0001",
                "avatar": None,
                "bot": False,
                "system": False,
                "mfa_enabled": True,
                "locale": "en-US",
                "verified": True,
                "email": None,
                "flags": 0,
                "premium_type": 0,
                "public_flags": 0,
            },
            "content": "Hello world",
            "timestamp": "2026-05-04T09:00:00+00:00",
            "edited_timestamp": None,
            "tts": False,
            "mention_everyone": False,
            "mentions": [],
            "mention_roles": [],
            "attachments": [],
            "embeds": [],
            "reactions": [],
            "pinned": False,
            "type": 0,
            "flags": 0,
            "referenced_message": None,
        }
    ]
    app, stub = _build_app(
        webhook_url=None,
        bot_token="BOT.xxx.yyy",
        stub_responses={"/channels/555/messages": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/discord/api/v10/channels/555/messages",
        headers=HEADERS,
        params={"limit": 25, "before": "999"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["messages"][0]["id"] == "111"
    assert body["messages"][0]["author"]["username"] == "alice"
    # Verify Authorization: Bot ... was set
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth.startswith("Bot ")
    sent_params = stub.calls[0]["params"]
    flat = (
        [(k, v) for k, v in sent_params]
        if isinstance(sent_params, list)
        else list(sent_params.items())
    )
    assert ("limit", "25") in flat
    assert ("before", "999") in flat
    _reset()


def test_create_channel_message_happy_path(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "BOT.xxx.yyy")
    raw = {
        "id": "222",
        "channel_id": "555",
        "content": "Posted via bot",
        "timestamp": "2026-05-04T10:00:00+00:00",
        "author": {"id": "10", "username": "ALDECI", "bot": True},
    }
    app, stub = _build_app(
        webhook_url=None,
        bot_token="BOT.xxx.yyy",
        stub_responses={"/channels/555/messages": _StubResponse(201, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/discord/api/v10/channels/555/messages",
        headers=HEADERS,
        json={
            "content": "Posted via bot",
            "embeds": [{"title": "Notice", "description": "deploy ok"}],
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["message"]["id"] == "222"
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts and posts[0]["headers"].get("Authorization", "").startswith("Bot ")
    sent_body = posts[0]["json"]
    assert sent_body["content"] == "Posted via bot"
    assert sent_body["embeds"][0]["title"] == "Notice"
    _reset()


def test_list_guild_channels_happy_path(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "BOT.xxx.yyy")
    raw = [
        {
            "id": "1001",
            "type": 0,
            "guild_id": "9999",
            "position": 0,
            "permission_overwrites": [],
            "name": "general",
            "topic": "General chat",
            "nsfw": False,
            "last_message_id": "111",
            "rate_limit_per_user": 0,
            "parent_id": None,
        },
        {
            "id": "1002",
            "type": 2,
            "guild_id": "9999",
            "position": 1,
            "permission_overwrites": [],
            "name": "voice-1",
            "bitrate": 64000,
            "user_limit": 0,
            "parent_id": None,
        },
    ]
    app, stub = _build_app(
        webhook_url=None,
        bot_token="BOT.xxx.yyy",
        stub_responses={"/guilds/9999/channels": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/discord/api/v10/guilds/9999/channels",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["channels"]) == 2
    assert body["channels"][0]["name"] == "general"
    assert body["channels"][1]["type"] == 2
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth.startswith("Bot ")
    _reset()


def test_list_user_guilds_happy_path(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "BOT.xxx.yyy")
    raw = [
        {
            "id": "9999",
            "name": "ALDECI HQ",
            "icon": None,
            "owner": False,
            "permissions": "2147483647",
            "features": ["COMMUNITY"],
        }
    ]
    app, stub = _build_app(
        webhook_url=None,
        bot_token="BOT.xxx.yyy",
        stub_responses={"/users/@me/guilds": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/discord/api/v10/users/@me/guilds",
        headers=HEADERS,
        params={"limit": 50},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["guilds"][0]["id"] == "9999"
    assert body["guilds"][0]["name"] == "ALDECI HQ"
    sent_params = stub.calls[0]["params"]
    flat = (
        [(k, v) for k, v in sent_params]
        if isinstance(sent_params, list)
        else list(sent_params.items())
    )
    assert ("limit", "50") in flat
    _reset()


# ============================================================ error mapping


def test_create_channel_message_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "BOT.xxx.yyy")
    app, _ = _build_app(
        webhook_url=None,
        bot_token="BOT.xxx.yyy",
        stub_responses={
            "/channels/555/messages": _StubResponse(
                429, {"error": "rate"}, text="rate"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/discord/api/v10/channels/555/messages",
        headers=HEADERS,
        json={"content": "Hi"},
    )
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()


def test_execute_webhook_validation_rejects_empty_body(monkeypatch):
    monkeypatch.setenv(
        "DISCORD_WEBHOOK_URL",
        "https://discord.com/api/webhooks/123/abc",
    )
    app, _ = _build_app(
        webhook_url="https://discord.com/api/webhooks/123/abc",
        bot_token=None,
    )
    client = TestClient(app, raise_server_exceptions=True)

    # No content, no embeds → 422 (engine ValueError)
    r = client.post(
        "/api/v1/discord/webhooks/123/abc",
        headers=HEADERS,
        json={"username": "ALDECI Bot"},
    )
    assert r.status_code == 422, r.text
    _reset()
