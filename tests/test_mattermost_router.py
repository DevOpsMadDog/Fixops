"""Router-level HTTP tests for Mattermost pass-through API.

Covers /api/v1/mattermost/* via FastAPI TestClient with a stub httpx.Client
so no real Mattermost call is made.

Tests:
1. GET /                                   — capability summary (unavailable)
2. GET /                                   — capability summary (ok)
3. POST /api/v4/posts                      — create a post
4. GET  /api/v4/posts/{post_id}            — fetch a post
5. PUT  /api/v4/posts/{post_id}            — update a post
6. DELETE /api/v4/posts/{post_id}          — soft delete returns {status: OK}
7. GET  /api/v4/users/{id}/teams           — list user teams
8. GET  /api/v4/teams/{id}/channels        — list team channels with pagination
9. GET  /api/v4/channels/{id}/posts        — paged channel feed envelope
10. POST /api/v4/files (multipart)         — file upload returns file_infos
11. unavailable env returns 503 on lookup endpoint
12. upstream 404 surfaces as 404 with payload echo
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite paths are importable regardless of cwd
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import apps.api.mattermost_router as _router_mod
from apps.api.mattermost_router import router
from core.mattermost_engine import MattermostEngine, reset_mattermost_engine


# ---------------------------------------------------------------------------
# Stub httpx.Client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(
        self,
        status_code: int,
        json_payload: Any = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        if json_payload is not None:
            self.content = b"{}"
        elif text:
            self.content = text.encode("utf-8")
        else:
            self.content = b""

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class StubHTTPXClient:
    """Captures requests and returns scripted responses keyed by (METHOD, suffix)."""

    def __init__(self, routes: Optional[Dict[str, _StubResponse]] = None) -> None:
        # routes keyed by f"{METHOD} {path-suffix-after-/api/v4/}"
        self.routes: Dict[str, _StubResponse] = routes or {}
        self.calls: List[Dict[str, Any]] = []

    def set(self, method: str, suffix: str, response: _StubResponse) -> None:
        self.routes[f"{method.upper()} {suffix}"] = response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,  # noqa: A002
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Any = None,
        data: Any = None,
    ) -> _StubResponse:
        marker = "/api/v4/"
        idx = url.find(marker)
        suffix = url[idx + len(marker):] if idx >= 0 else url
        key = f"{method.upper()} {suffix}"
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "suffix": suffix,
                "json": json,
                "params": params,
                "headers": headers,
                "files": files,
                "data": data,
            }
        )
        if key in self.routes:
            return self.routes[key]
        return _StubResponse(200, {})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_mattermost_engine()
    yield
    reset_mattermost_engine()


def _build_app(engine: MattermostEngine) -> TestClient:
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> MattermostEngine:
    return MattermostEngine(
        mattermost_url="https://mm.example.com",
        mattermost_token="tok-abc-123",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> MattermostEngine:
    return MattermostEngine(
        mattermost_url="",
        mattermost_token="",
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: MattermostEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/mattermost/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Mattermost"
    assert body["mattermost_url_present"] is False
    assert body["mattermost_token_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/api/v4/posts",
        "/api/v4/users",
        "/api/v4/teams",
        "/api/v4/channels",
        "/api/v4/files",
    ):
        assert ep in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: MattermostEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/mattermost/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["mattermost_url_present"] is True
    assert body["mattermost_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. Create post
# ---------------------------------------------------------------------------


def test_create_post(configured_engine: MattermostEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "POST",
        "posts",
        _StubResponse(
            201,
            {
                "id": "post-1",
                "create_at": 1714000000000,
                "update_at": 1714000000000,
                "edit_at": 0,
                "delete_at": 0,
                "user_id": "user-1",
                "channel_id": "chan-1",
                "root_id": "",
                "original_id": "",
                "message": "hello world",
                "type": "",
                "props": {},
                "hashtags": "",
                "file_ids": [],
                "pending_post_id": "",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/mattermost/api/v4/posts",
        json={"channel_id": "chan-1", "message": "hello world"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "post-1"
    assert body["channel_id"] == "chan-1"
    assert body["message"] == "hello world"
    # Auth header was Bearer
    assert stub.calls[0]["headers"]["Authorization"] == "Bearer tok-abc-123"
    sent = stub.calls[0]["json"]
    assert sent == {"channel_id": "chan-1", "message": "hello world"}


# ---------------------------------------------------------------------------
# 4. Fetch post
# ---------------------------------------------------------------------------


def test_get_post(configured_engine: MattermostEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "posts/post-1",
        _StubResponse(
            200,
            {
                "id": "post-1",
                "create_at": 1714000000000,
                "update_at": 1714000000000,
                "delete_at": 0,
                "user_id": "user-1",
                "channel_id": "chan-1",
                "message": "hello world",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/mattermost/api/v4/posts/post-1",
        params={"include_deleted": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "post-1"
    assert stub.calls[0]["params"]["include_deleted"] == "false"


# ---------------------------------------------------------------------------
# 5. Update post
# ---------------------------------------------------------------------------


def test_update_post(configured_engine: MattermostEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "PUT",
        "posts/post-1",
        _StubResponse(
            200,
            {
                "id": "post-1",
                "create_at": 1714000000000,
                "update_at": 1714000000999,
                "edit_at": 1714000000999,
                "delete_at": 0,
                "user_id": "user-1",
                "channel_id": "chan-1",
                "message": "edited body",
                "file_ids": ["file-9"],
                "props": {"reviewed": True},
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.put(
        "/api/v1/mattermost/api/v4/posts/post-1",
        json={
            "message": "edited body",
            "file_ids": ["file-9"],
            "has_reactions": False,
            "props": {"reviewed": True},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["message"] == "edited body"
    assert body["edit_at"] > 0
    sent = stub.calls[0]["json"]
    assert sent["id"] == "post-1"
    assert sent["message"] == "edited body"
    assert sent["file_ids"] == ["file-9"]
    assert sent["props"] == {"reviewed": True}


# ---------------------------------------------------------------------------
# 6. Delete post
# ---------------------------------------------------------------------------


def test_delete_post_returns_status_ok(
    configured_engine: MattermostEngine, stub: StubHTTPXClient
) -> None:
    stub.set("DELETE", "posts/post-1", _StubResponse(200, {"status": "OK"}))
    client = _build_app(configured_engine)
    resp = client.delete("/api/v1/mattermost/api/v4/posts/post-1")
    assert resp.status_code == 200
    assert resp.json() == {"status": "OK"}


# ---------------------------------------------------------------------------
# 7. List user teams
# ---------------------------------------------------------------------------


def test_get_user_teams(configured_engine: MattermostEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "users/user-1/teams",
        _StubResponse(
            200,
            [
                {
                    "id": "team-1",
                    "create_at": 1714000000000,
                    "update_at": 1714000000000,
                    "delete_at": 0,
                    "display_name": "Security",
                    "name": "security",
                    "description": "Security team",
                    "email": "sec@example.com",
                    "type": "O",
                    "company_name": "Example",
                    "allowed_domains": "example.com",
                    "invite_id": "inv-123",
                    "allow_open_invite": False,
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/mattermost/api/v4/users/user-1/teams")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == "team-1"
    assert body[0]["type"] == "O"


# ---------------------------------------------------------------------------
# 8. List team channels with pagination
# ---------------------------------------------------------------------------


def test_get_team_channels(configured_engine: MattermostEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "teams/team-1/channels",
        _StubResponse(
            200,
            [
                {
                    "id": "chan-1",
                    "create_at": 1714000000000,
                    "update_at": 1714000000000,
                    "delete_at": 0,
                    "team_id": "team-1",
                    "type": "O",
                    "display_name": "general",
                    "name": "general",
                    "header": "",
                    "purpose": "",
                    "last_post_at": 1714000099999,
                    "total_msg_count": 42,
                    "extra_update_at": 0,
                    "creator_id": "user-1",
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/mattermost/api/v4/teams/team-1/channels",
        params={"per_page": 50, "page": 0},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["team_id"] == "team-1"
    sent_params = stub.calls[0]["params"]
    assert sent_params["per_page"] == 50
    assert sent_params["page"] == 0


# ---------------------------------------------------------------------------
# 9. Channel posts envelope
# ---------------------------------------------------------------------------


def test_get_channel_posts_envelope(
    configured_engine: MattermostEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "channels/chan-1/posts",
        _StubResponse(
            200,
            {
                "order": ["post-2", "post-1"],
                "posts": {
                    "post-1": {"id": "post-1", "message": "hi"},
                    "post-2": {"id": "post-2", "message": "there"},
                },
                "prev_post_id": "post-0",
                "next_post_id": "",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/mattermost/api/v4/channels/chan-1/posts",
        params={"per_page": 50, "page": 0, "since": 1700000000000},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["order"] == ["post-2", "post-1"]
    assert "post-1" in body["posts"]
    assert body["prev_post_id"] == "post-0"
    sent_params = stub.calls[0]["params"]
    assert sent_params["since"] == 1700000000000
    assert sent_params["per_page"] == 50


# ---------------------------------------------------------------------------
# 10. File upload (multipart)
# ---------------------------------------------------------------------------


def test_upload_files_multipart(
    configured_engine: MattermostEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "files",
        _StubResponse(
            201,
            {
                "file_infos": [
                    {
                        "id": "file-1",
                        "user_id": "user-1",
                        "post_id": "",
                        "create_at": 1714000000000,
                        "update_at": 1714000000000,
                        "delete_at": 0,
                        "name": "report.txt",
                        "extension": "txt",
                        "size": 11,
                        "mime_type": "text/plain",
                        "width": 0,
                        "height": 0,
                        "has_preview_image": False,
                    }
                ],
                "client_ids": [],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/mattermost/api/v4/files",
        data={"channel_id": "chan-1"},
        files=[("files", ("report.txt", b"hello world", "text/plain"))],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["file_infos"][0]["id"] == "file-1"
    assert body["file_infos"][0]["name"] == "report.txt"
    # Verify multipart was forwarded
    call = stub.calls[0]
    assert call["method"] == "POST"
    assert call["data"] == {"channel_id": "chan-1"}
    assert call["files"] is not None
    assert len(call["files"]) == 1
    # Auth header WITHOUT Content-Type for multipart
    assert call["headers"]["Authorization"] == "Bearer tok-abc-123"
    assert "Content-Type" not in call["headers"]


# ---------------------------------------------------------------------------
# 11. Unavailable env returns 503
# ---------------------------------------------------------------------------


def test_lookup_returns_503_when_unavailable(
    unavailable_engine: MattermostEngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/mattermost/api/v4/posts/post-1")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "mattermost_unavailable"


# ---------------------------------------------------------------------------
# 12. Upstream 404 surfaces with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: MattermostEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "posts/missing",
        _StubResponse(
            404,
            {
                "id": "store.sql_post.get.app_error",
                "message": "Unable to get the post",
                "status_code": 404,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/mattermost/api/v4/posts/missing")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "mattermost_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["status_code"] == 404
