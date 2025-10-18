from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, status
from src.api import dependencies
from src.config.settings import get_settings


class StubRequest:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self._body = body
        self.headers = headers or {}
        self.state = SimpleNamespace()

    async def body(self) -> bytes:
        return self._body


@pytest.mark.usefixtures("signing_env")
def test_authenticated_payload_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXOPS_API_KEY", "secret-token")
    get_settings.cache_clear()
    request = StubRequest(
        body=b'{"hello": "world"}',
        headers={
            "Authorization": "Bearer secret-token",
            "content-type": "application/json",
        },
    )

    async def invoke() -> dict[str, str]:
        payload = await dependencies.validated_payload(request)
        await dependencies.authenticate(request)
        return await dependencies.authenticated_payload(payload=payload, _=None)

    payload = asyncio.run(invoke())
    assert payload == {"hello": "world"}
    assert request.state.payload == payload


@pytest.mark.usefixtures("signing_env")
def test_validated_payload_size_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXOPS_MAX_PAYLOAD_BYTES", "2")
    get_settings.cache_clear()

    class _StubSettings:
        FIXOPS_MAX_PAYLOAD_BYTES = 2

    monkeypatch.setattr(dependencies, "get_settings", lambda: _StubSettings())
    monkeypatch.setattr(
        dependencies.status, "HTTP_413_REQUEST_ENTITY_TOO_LARGE", 413, raising=False
    )
    request = StubRequest(body=b"12345", headers={"content-type": "application/json"})

    async def invoke() -> None:
        await dependencies.validated_payload(request)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(invoke())
    assert exc.value.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


@pytest.mark.usefixtures("signing_env")
def test_authenticate_invalid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXOPS_API_KEY", "expected")
    get_settings.cache_clear()
    get_settings()
    monkeypatch.setattr(dependencies.status, "HTTP_403_FORBIDDEN", 403, raising=False)
    request = StubRequest(body=b"{}", headers={"Authorization": "Bearer wrong"})

    async def invoke() -> None:
        await dependencies.authenticate(request)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(invoke())
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.usefixtures("signing_env")
def test_authenticate_missing_header(monkeypatch: pytest.MonkeyPatch) -> None:
    get_settings.cache_clear()
    monkeypatch.setattr(
        dependencies.status, "HTTP_401_UNAUTHORIZED", 401, raising=False
    )
    request = StubRequest(body=b"{}", headers={})

    async def invoke() -> None:
        await dependencies.authenticate(request)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(invoke())
    assert exc.value.status_code == 401


@pytest.mark.usefixtures("signing_env")
def test_validated_payload_content_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dependencies.status, "HTTP_415_UNSUPPORTED_MEDIA_TYPE", 415, raising=False
    )
    request = StubRequest(body=b"{}", headers={"content-type": "text/plain"})

    async def invoke() -> None:
        await dependencies.validated_payload(request)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(invoke())
    assert exc.value.status_code == 415


@pytest.mark.usefixtures("signing_env")
def test_validated_payload_requires_object(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dependencies.status, "HTTP_400_BAD_REQUEST", 400, raising=False)
    request = StubRequest(body=b"[]", headers={"content-type": "application/json"})

    async def invoke() -> None:
        await dependencies.validated_payload(request)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(invoke())
    assert exc.value.status_code == 400
