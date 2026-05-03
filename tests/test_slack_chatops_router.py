"""Tests for the Slack ChatOps router (NO MOCKS, real httpx path).

Each test uses a stub ``httpx.Client`` so the engine's REAL request
construction + Bearer auth header is exercised - only the network is
intercepted.

Coverage:
  1. Capability summary returns ``status="unavailable"`` when env unset.
  2. Capability summary returns ``status="ok"`` + token echo when env set.
  3. POST /api/chat.postMessage returns 503 unset; returns ok envelope when configured.
  4. POST /api/chat.update returns 503 unset; returns ok envelope when configured.
  5. POST /api/chat.delete returns 503 unset; returns ok envelope when configured.
  6. GET /api/users.list returns 503 unset; returns members[] when configured.
  7. GET /api/conversations.list returns 503 unset; returns channels[] when configured + propagates types.
  8. POST /api/files.upload returns 503 unset; multipart accepted when configured.
  9. POST /api/reactions.add returns 503 unset; returns ok when configured.
  10. Bearer header carries the SLACK_BOT_TOKEN value.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------- helpers


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        if text:
            self.text = text
        elif payload is None:
            self.text = ""
        else:
            self.text = json.dumps(payload)

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


class _StubClient:
    """Minimal httpx.Client stand-in: matches by URL substring."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        candidates = [
            (path, resp) for path, resp in self._responses.items() if path in url
        ]
        if candidates:
            candidates.sort(key=lambda kv: len(kv[0]), reverse=True)
            return candidates[0][1]
        return _StubResponse(404, {"ok": False, "error": "stub_not_found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {"method": "GET", "url": url, "headers": headers or {}, "params": params or {}}
        )
        return self._match(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Any = None,
        data: Any = None,
        files: Any = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "json": json,
                "data": data,
                "files": files,
                "params": params or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


def _build_app(
    *,
    token: Optional[str],
    base_url: Optional[str] = None,
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    from core import slack_chatops_engine as eng_mod

    eng_mod.reset_slack_chatops_engine()
    stub = _StubClient(stub_responses or {})
    eng_mod.get_slack_chatops_engine(
        token=token,
        base_url=base_url,
        client=stub,
        force_refresh=True,
    )

    from apps.api.slack_chatops_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import slack_chatops_engine as eng_mod
    eng_mod.reset_slack_chatops_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_token(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/slack-chatops/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Slack ChatOps"
    for ep in [
        "/api/chat.postMessage",
        "/api/chat.update",
        "/api/chat.delete",
        "/api/users.list",
        "/api/conversations.list",
        "/api/files.upload",
        "/api/reactions.add",
    ]:
        assert ep in body["endpoints"], f"missing endpoint {ep}"
    assert body["slack_bot_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-token")
    app, _ = _build_app(token="xoxb-test-token")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/slack-chatops/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["slack_bot_token_present"] is True
    assert body["status"] == "ok"
    _reset()


# ============================================================ chat.postMessage


def test_chat_post_message_503_when_no_token(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/slack-chatops/api/chat.postMessage",
        headers=HEADERS,
        json={"channel": "C12345", "text": "hi"},
    )
    assert r.status_code == 503, r.text
    assert "SLACK_BOT_TOKEN" in r.json()["detail"]
    _reset()


def test_chat_post_message_returns_envelope_via_stub(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-token")
    payload = {
        "ok": True,
        "channel": "C12345",
        "ts": "1620000000.000100",
        "message": {
            "user": "U999",
            "type": "message",
            "ts": "1620000000.000100",
            "text": "hi",
        },
    }
    stub = {"/api/chat.postMessage": _StubResponse(200, payload)}
    app, captured = _build_app(token="xoxb-test-token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/slack-chatops/api/chat.postMessage",
        headers=HEADERS,
        json={
            "channel": "C12345",
            "text": "hi",
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "*hi*"}}],
            "thread_ts": "1620000000.000099",
            "reply_broadcast": True,
            "mrkdwn": True,
            "unfurl_links": False,
            "username": "aldeci-bot",
        },
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["ok"] is True
    assert out["ts"] == "1620000000.000100"
    assert out["message"]["text"] == "hi"

    last = captured.calls[-1]
    assert last["headers"]["Authorization"] == "Bearer xoxb-test-token"
    assert "application/json" in last["headers"]["Content-Type"]
    assert last["json"]["channel"] == "C12345"
    assert last["json"]["thread_ts"] == "1620000000.000099"
    assert last["json"]["reply_broadcast"] is True
    _reset()


# ============================================================ chat.update


def test_chat_update_503_then_ok(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/slack-chatops/api/chat.update",
        headers=HEADERS,
        json={"channel": "C1", "ts": "1620000000.0001", "text": "edited"},
    )
    assert r.status_code == 503, r.text
    _reset()

    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-token")
    payload = {"ok": True, "channel": "C1", "ts": "1620000000.0001", "text": "edited"}
    stub = {"/api/chat.update": _StubResponse(200, payload)}
    app, _ = _build_app(token="xoxb-test-token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/slack-chatops/api/chat.update",
        headers=HEADERS,
        json={"channel": "C1", "ts": "1620000000.0001", "text": "edited"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["text"] == "edited"
    _reset()


# ============================================================ chat.delete


def test_chat_delete_503_then_ok(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/slack-chatops/api/chat.delete",
        headers=HEADERS,
        json={"channel": "C1", "ts": "1620000000.0001"},
    )
    assert r.status_code == 503, r.text
    _reset()

    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-token")
    payload = {"ok": True, "channel": "C1", "ts": "1620000000.0001"}
    stub = {"/api/chat.delete": _StubResponse(200, payload)}
    app, _ = _build_app(token="xoxb-test-token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/slack-chatops/api/chat.delete",
        headers=HEADERS,
        json={"channel": "C1", "ts": "1620000000.0001", "as_user": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    _reset()


# ============================================================ users.list


def test_users_list_503_then_ok(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/slack-chatops/api/users.list", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()

    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-token")
    payload = {
        "ok": True,
        "members": [
            {
                "id": "U001",
                "name": "alice",
                "real_name": "Alice Example",
                "profile": {
                    "email": "alice@example.com",
                    "image_72": "https://avatars/alice.png",
                    "status_text": "On call",
                    "status_emoji": ":pager:",
                },
                "is_bot": False,
                "is_admin": True,
                "is_owner": False,
                "deleted": False,
            }
        ],
        "cache_ts": 1620000000,
        "response_metadata": {"next_cursor": "next-page-token"},
    }
    stub = {"/api/users.list": _StubResponse(200, payload)}
    app, captured = _build_app(token="xoxb-test-token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/slack-chatops/api/users.list?limit=50&cursor=abc",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["members"][0]["id"] == "U001"
    assert body["response_metadata"]["next_cursor"] == "next-page-token"

    last = captured.calls[-1]
    assert last["params"].get("limit") == 50
    assert last["params"].get("cursor") == "abc"
    _reset()


# ============================================================ conversations.list


def test_conversations_list_503_then_ok(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/slack-chatops/api/conversations.list", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()

    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-token")
    payload = {
        "ok": True,
        "channels": [
            {
                "id": "C001",
                "name": "general",
                "is_channel": True,
                "is_group": False,
                "is_im": False,
                "created": 1620000000,
                "creator": "U001",
                "is_archived": False,
                "is_general": True,
                "name_normalized": "general",
                "num_members": 12,
                "topic": {"value": "general chat", "creator": "U001", "last_set": 1620000000},
                "purpose": {"value": "everyone here", "creator": "U001", "last_set": 1620000000},
            }
        ],
        "response_metadata": {"next_cursor": ""},
    }
    stub = {"/api/conversations.list": _StubResponse(200, payload)}
    app, captured = _build_app(token="xoxb-test-token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/slack-chatops/api/conversations.list"
        "?types=public_channel,private_channel&limit=20&exclude_archived=true",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["channels"][0]["id"] == "C001"
    last = captured.calls[-1]
    assert last["params"]["types"] == "public_channel,private_channel"
    assert last["params"]["limit"] == 20
    assert last["params"]["exclude_archived"] == "true"
    _reset()


# ============================================================ files.upload


def test_files_upload_503_when_no_token(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/slack-chatops/api/files.upload",
        headers=HEADERS,
        data={"channels": "C001", "content": "hello world"},
    )
    assert r.status_code == 503, r.text
    _reset()


def test_files_upload_ok_with_content(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-token")
    payload = {
        "ok": True,
        "file": {
            "id": "F001",
            "name": "snippet.txt",
            "title": "snippet",
            "url_private": "https://files/F001",
            "url_private_download": "https://files/F001/download",
            "permalink": "https://slack/perma/F001",
            "channels": ["C001"],
        },
    }
    stub = {"/api/files.upload": _StubResponse(200, payload)}
    app, captured = _build_app(token="xoxb-test-token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/slack-chatops/api/files.upload",
        headers=HEADERS,
        data={
            "channels": "C001",
            "content": "hello world",
            "filename": "snippet.txt",
            "filetype": "text",
            "initial_comment": "see attached",
            "title": "snippet",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["file"]["id"] == "F001"
    last = captured.calls[-1]
    assert last["headers"]["Authorization"] == "Bearer xoxb-test-token"
    # multipart path: data should carry channels + content
    assert last["data"]["channels"] == "C001"
    assert last["data"]["content"] == "hello world"
    _reset()


# ============================================================ reactions.add


def test_reactions_add_503_then_ok(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/slack-chatops/api/reactions.add",
        headers=HEADERS,
        json={"channel": "C001", "name": "thumbsup", "timestamp": "1620000000.0001"},
    )
    assert r.status_code == 503, r.text
    _reset()

    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-token")
    stub = {"/api/reactions.add": _StubResponse(200, {"ok": True})}
    app, _ = _build_app(token="xoxb-test-token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/slack-chatops/api/reactions.add",
        headers=HEADERS,
        json={"channel": "C001", "name": "thumbsup", "timestamp": "1620000000.0001"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    _reset()
