"""Tests for guardrails_router (Guardrails AI surface) — ALDECI.

Spins up a minimal FastAPI app with the Guardrails router mounted. Each test
resets the engine singleton so state doesn't bleed between tests, and injects
a stub httpx.Client so we exercise the real networking + parsing code paths.

NO MOCKS rule:
  * /v1/validate, /v1/specs, /v1/spec, /v1/guards/.../validate,
    /v1/openai/chat/completions, /v1/health → HTTP 503 when no key.
  * Capability summary reports ``status="unavailable"`` when key is missing.
  * Happy paths inject a stub httpx.Client returning canned upstream JSON.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for httpx.Response with .json() + .status_code."""

    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

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
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "json": json or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    api_key: Optional[str],
    base_url: Optional[str] = None,
    stub_responses: Optional[Dict[str, Any]] = None,
):
    """Construct an isolated app+engine bound to a stub httpx client."""
    from core import guardrails_engine as engine_mod

    engine_mod.reset_guardrails_engine()

    stub_client = _StubClient(stub_responses or {})
    engine_mod.get_guardrails_engine(
        api_key=api_key, base_url=base_url, client=stub_client
    )

    from apps.api.guardrails_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import guardrails_engine as engine_mod

    engine_mod.reset_guardrails_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


class TestCapability:
    def test_summary_unavailable_when_no_key(self, monkeypatch):
        monkeypatch.delenv("GUARDRAILS_API_KEY", raising=False)
        monkeypatch.delenv("GUARDRAILS_BASE_URL", raising=False)
        app, _ = _build_app(api_key=None)
        try:
            with TestClient(app) as client:
                r = client.get("/api/v1/guardrails/", headers=HEADERS)
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["service"] == "Guardrails AI"
                assert body["status"] == "unavailable"
                assert body["guardrails_api_key_present"] is False
                assert body["guardrails_base_url"] == "https://api.guardrailsai.com"
                assert "/v1/validate" in body["endpoints"]
                assert "/v1/openai/chat/completions" in body["endpoints"]
        finally:
            _reset()

    def test_summary_ok_when_key_present(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        monkeypatch.setenv("GUARDRAILS_BASE_URL", "https://my-grails.example.com")
        app, _ = _build_app(api_key="test-key", base_url="https://my-grails.example.com")
        try:
            with TestClient(app) as client:
                r = client.get("/api/v1/guardrails/", headers=HEADERS)
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["status"] == "ok"
                assert body["guardrails_api_key_present"] is True
                assert body["guardrails_base_url"] == "https://my-grails.example.com"
        finally:
            _reset()


# ---------------------------------------------------------------------------
# 503 surface when no key
# ---------------------------------------------------------------------------


class TestUnavailable503:
    def test_validate_503_no_key(self, monkeypatch):
        monkeypatch.delenv("GUARDRAILS_API_KEY", raising=False)
        app, _ = _build_app(api_key=None)
        try:
            with TestClient(app) as client:
                r = client.post(
                    "/api/v1/guardrails/v1/validate",
                    headers=HEADERS,
                    json={
                        "prompt": "Hello",
                        "guards": [{"name": "profanity-free"}],
                    },
                )
                assert r.status_code == 503, r.text
                assert "GUARDRAILS_API_KEY" in r.json()["detail"]
        finally:
            _reset()

    def test_specs_503_no_key(self, monkeypatch):
        monkeypatch.delenv("GUARDRAILS_API_KEY", raising=False)
        app, _ = _build_app(api_key=None)
        try:
            with TestClient(app) as client:
                r = client.get("/api/v1/guardrails/v1/specs", headers=HEADERS)
                assert r.status_code == 503
        finally:
            _reset()

    def test_health_503_no_key(self, monkeypatch):
        monkeypatch.delenv("GUARDRAILS_API_KEY", raising=False)
        app, _ = _build_app(api_key=None)
        try:
            with TestClient(app) as client:
                r = client.get("/api/v1/guardrails/v1/health", headers=HEADERS)
                assert r.status_code == 503
        finally:
            _reset()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class TestValidate:
    def test_validate_passes(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        upstream = {
            "validation_passed": True,
            "validated_output": "Hello world",
            "validation_summaries": [
                {
                    "guard_name": "profanity-free",
                    "validator_status": "pass",
                    "validator_logs": [],
                    "validation_method": "guard",
                    "error_messages": [],
                }
            ],
        }
        app, stub = _build_app(
            api_key="test-key",
            stub_responses={"/v1/validate": _StubResponse(200, upstream)},
        )
        try:
            with TestClient(app) as client:
                r = client.post(
                    "/api/v1/guardrails/v1/validate",
                    headers=HEADERS,
                    json={
                        "prompt": "Hello world",
                        "guards": [{"name": "profanity-free", "on_fail": "exception"}],
                    },
                )
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["validation_passed"] is True
                assert body["validated_output"] == "Hello world"
                # Auth header forwarded to upstream
                assert (
                    stub.calls[0]["headers"].get("Authorization")
                    == "Bearer test-key"
                )
                # Body shape forwarded
                sent = stub.calls[0]["json"]
                assert sent["prompt"] == "Hello world"
                assert sent["guards"][0]["name"] == "profanity-free"
        finally:
            _reset()


class TestSpecs:
    def test_list_specs(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        upstream = {
            "specs": [
                {
                    "name": "default-pii",
                    "description": "Block PII",
                    "version": "1.0.0",
                    "validators": [
                        {"name": "guardrails-pii", "on_fail": "filter", "kwargs": {}}
                    ],
                    "schema": {},
                }
            ]
        }
        app, _ = _build_app(
            api_key="test-key",
            stub_responses={"/v1/specs": _StubResponse(200, upstream)},
        )
        try:
            with TestClient(app) as client:
                r = client.get("/api/v1/guardrails/v1/specs", headers=HEADERS)
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["specs"][0]["name"] == "default-pii"
        finally:
            _reset()

    def test_get_spec(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        upstream = {
            "name": "default-pii",
            "description": "Block PII",
            "version": "1.0.0",
            "validators": [],
            "schema": {},
        }
        app, _ = _build_app(
            api_key="test-key",
            stub_responses={
                "/v1/specs/default-pii": _StubResponse(200, upstream)
            },
        )
        try:
            with TestClient(app) as client:
                r = client.get(
                    "/api/v1/guardrails/v1/specs/default-pii", headers=HEADERS
                )
                assert r.status_code == 200, r.text
                assert r.json()["name"] == "default-pii"
        finally:
            _reset()

    def test_create_spec_201(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        upstream = {"name": "my-custom", "version": "1.0.0"}
        app, stub = _build_app(
            api_key="test-key",
            stub_responses={"/v1/spec": _StubResponse(201, upstream)},
        )
        try:
            with TestClient(app) as client:
                r = client.post(
                    "/api/v1/guardrails/v1/spec",
                    headers=HEADERS,
                    json={
                        "name": "my-custom",
                        "description": "Custom guard",
                        "guards": [{"name": "profanity-free"}],
                        "schema": {"type": "string"},
                    },
                )
                assert r.status_code == 201, r.text
                assert r.json()["name"] == "my-custom"
                # Verify schema field aliased correctly to upstream body
                sent = stub.calls[0]["json"]
                assert sent["schema"] == {"type": "string"}
        finally:
            _reset()


class TestGuardValidate:
    def test_validate_named_guard(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        upstream = {
            "validated_value": "clean text",
            "validation_passed": True,
            "validator_logs": [],
        }
        app, _ = _build_app(
            api_key="test-key",
            stub_responses={
                "/v1/guards/profanity-free/validate": _StubResponse(
                    200, upstream
                )
            },
        )
        try:
            with TestClient(app) as client:
                r = client.post(
                    "/api/v1/guardrails/v1/guards/profanity-free/validate",
                    headers=HEADERS,
                    json={"value": "clean text"},
                )
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["validation_passed"] is True
        finally:
            _reset()


class TestOpenAIPassthrough:
    def test_chat_completions_passthrough(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        upstream = {
            "id": "chatcmpl-abc123",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello!"},
                    "finish_reason": "stop",
                }
            ],
            "validation_summaries": [
                {"guard_name": "profanity-free", "validator_status": "pass"}
            ],
        }
        app, stub = _build_app(
            api_key="test-key",
            stub_responses={
                "/v1/openai/chat/completions": _StubResponse(200, upstream)
            },
        )
        try:
            with TestClient(app) as client:
                r = client.post(
                    "/api/v1/guardrails/v1/openai/chat/completions",
                    headers=HEADERS,
                    json={
                        "model": "gpt-4",
                        "messages": [{"role": "user", "content": "Hi"}],
                        "guards": [{"name": "profanity-free"}],
                    },
                )
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["choices"][0]["message"]["content"] == "Hello!"
                assert body["validation_summaries"][0]["validator_status"] == "pass"
                # Auth header forwarded
                assert (
                    stub.calls[0]["headers"].get("Authorization")
                    == "Bearer test-key"
                )
        finally:
            _reset()


class TestHealth:
    def test_health_delegated(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        upstream = {"status": "healthy", "version": "0.5.0"}
        app, _ = _build_app(
            api_key="test-key",
            stub_responses={"/v1/health": _StubResponse(200, upstream)},
        )
        try:
            with TestClient(app) as client:
                r = client.get("/api/v1/guardrails/v1/health", headers=HEADERS)
                assert r.status_code == 200, r.text
                assert r.json()["status"] == "healthy"
        finally:
            _reset()


class TestUpstreamFailures:
    def test_upstream_500_returns_503(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "test-key")
        app, _ = _build_app(
            api_key="test-key",
            stub_responses={
                "/v1/specs": _StubResponse(500, {"error": "internal"}, text="oops")
            },
        )
        try:
            with TestClient(app) as client:
                r = client.get("/api/v1/guardrails/v1/specs", headers=HEADERS)
                assert r.status_code == 503
        finally:
            _reset()

    def test_upstream_401_returns_503(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_API_KEY", "bad-key")
        app, _ = _build_app(
            api_key="bad-key",
            stub_responses={
                "/v1/specs": _StubResponse(401, {"error": "unauthorized"})
            },
        )
        try:
            with TestClient(app) as client:
                r = client.get("/api/v1/guardrails/v1/specs", headers=HEADERS)
                assert r.status_code == 503
                assert "credentials" in r.json()["detail"].lower()
        finally:
            _reset()
