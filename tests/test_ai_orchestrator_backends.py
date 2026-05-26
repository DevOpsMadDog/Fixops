"""Tests for AI Orchestrator — LLM backend paths and 503 degradation.

Covers:
- _call_llm auto-detects OpenRouter key when FIXOPS_LLM_BACKEND not set
- _call_llm explicit mock returns [MOCK_LLM]-prefixed string (not fabricated real)
- _call_llm unknown backend raises ValueError (never silent mock fallback)
- _call_llm no key + no backend returns [LLM_UNAVAILABLE] marker (not fabricated content)
- _call_llm with backend=openrouter (success)
- _call_llm with backend=openrouter (HTTP error)
- _openrouter_call with missing API key returns [LLM_UNAVAILABLE] stub
- _openrouter_call with missing httpx returns [LLM_UNAVAILABLE] stub
- _resolve_openrouter_key checks all three env vars
- REST 503 when _ORCHESTRATOR_AVAILABLE=False
- list /tasks returns 200 with empty tasks when orchestrator unavailable

Usage:
    pytest tests/test_ai_orchestrator_backends.py -v --timeout=30
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_FIXOPS_ROOT = Path(__file__).parent.parent
_SUITE_CORE = _FIXOPS_ROOT / "suite-core"
_SUITE_API = _FIXOPS_ROOT / "suite-api"

for _p in [str(_FIXOPS_ROOT), str(_SUITE_CORE), str(_SUITE_API)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.ai_orchestrator import (
    AgentRole,
    AIOrchestrator,
    _call_llm,
    _mock_llm_response,
    _openrouter_call,
    _resolve_openrouter_key,
    _UNAVAILABLE_PREFIX,
    _MOCK_PREFIX,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "backends_test.db")


@pytest.fixture
def orch(tmp_db):
    return AIOrchestrator(db_path=tmp_db)


# ---------------------------------------------------------------------------
# 1. _call_llm backend dispatch
# ---------------------------------------------------------------------------

class TestCallLlmBackend:
    # ── Explicit mock opt-in ──────────────────────────────────────────────────

    def test_explicit_mock_returns_mock_prefix(self):
        """FIXOPS_LLM_BACKEND=mock must return [MOCK_LLM]-prefixed string."""
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "mock"}):
            result = _call_llm(AgentRole.ANALYST, "test prompt")
        assert isinstance(result, str)
        assert result.startswith(_MOCK_PREFIX), (
            f"Expected {_MOCK_PREFIX!r} prefix, got: {result[:60]!r}"
        )

    def test_explicit_mock_all_roles(self):
        """All 6 roles return mock-prefixed strings under explicit mock backend."""
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "mock"}):
            for role in AgentRole:
                result = _call_llm(role, f"prompt for {role.value}")
                assert result.startswith(_MOCK_PREFIX), (
                    f"Role {role.value} did not get {_MOCK_PREFIX!r} prefix"
                )

    # ── Unknown backend → honest error, never silent mock ────────────────────

    def test_unknown_backend_raises_value_error(self):
        """An unknown FIXOPS_LLM_BACKEND must raise ValueError, never silently mock."""
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "nonexistent_backend_xyz"}):
            with pytest.raises(ValueError, match="Unknown FIXOPS_LLM_BACKEND"):
                _call_llm(AgentRole.REVIEWER, "test prompt")

    def test_unknown_backend_error_message_names_the_backend(self):
        """ValueError message must include the bad backend name for debuggability."""
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "bad_backend"}):
            with pytest.raises(ValueError, match="bad_backend"):
                _call_llm(AgentRole.ANALYST, "prompt")

    # ── Auto-detect: no backend set, no key → honest unavailable ─────────────

    def test_no_backend_no_key_returns_unavailable_marker(self):
        """No FIXOPS_LLM_BACKEND + no key must return [LLM_UNAVAILABLE] marker,
        not fabricated mock content."""
        env_patch = {k: "" for k in (
            "FIXOPS_LLM_BACKEND", "OPENROUTER_API_KEY",
            "MULEROUTER_API_KEY", "FIXOPS_OPENROUTER_KEY",
        )}
        with patch.dict(os.environ, env_patch):
            result = _call_llm(AgentRole.ANALYST, "test")
        assert result.startswith(_UNAVAILABLE_PREFIX), (
            f"Expected {_UNAVAILABLE_PREFIX!r} prefix, got: {result[:80]!r}"
        )
        # Must NOT look like canned mock content
        assert "ANALYSIS COMPLETE" not in result
        assert "REVIEW VERDICT" not in result

    def test_no_backend_no_key_result_is_not_fabricated(self):
        """The unavailable marker must not pretend to be a real LLM answer."""
        env_patch = {k: "" for k in (
            "FIXOPS_LLM_BACKEND", "OPENROUTER_API_KEY",
            "MULEROUTER_API_KEY", "FIXOPS_OPENROUTER_KEY",
        )}
        with patch.dict(os.environ, env_patch):
            for role in AgentRole:
                result = _call_llm(role, "test")
                assert result.startswith(_UNAVAILABLE_PREFIX), (
                    f"Role {role.value}: expected unavailable marker, got: {result[:60]!r}"
                )

    # ── Auto-detect: no backend set, key present → routes to openrouter ──────

    def test_no_backend_with_key_calls_openrouter(self):
        """When FIXOPS_LLM_BACKEND is unset but a key is present, auto-route to openrouter."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Auto-detected OpenRouter result"}}]
        }
        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp

        env_patch = {
            "OPENROUTER_API_KEY": "sk-auto-key",
            "FIXOPS_LLM_BACKEND": "",  # unset
        }
        with patch.dict(os.environ, env_patch), \
             patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = _call_llm(AgentRole.ANALYST, "Auto-detect test")

        assert result == "Auto-detected OpenRouter result"
        mock_httpx.post.assert_called_once()

    def test_mulerouter_key_also_auto_detected(self):
        """MULEROUTER_API_KEY is also accepted for auto-detection."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "MuleRouter result"}}]
        }
        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp

        env_patch = {
            "OPENROUTER_API_KEY": "",
            "MULEROUTER_API_KEY": "sk-mule-key",
            "FIXOPS_LLM_BACKEND": "",
        }
        with patch.dict(os.environ, env_patch), \
             patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = _call_llm(AgentRole.REVIEWER, "Mule key test")

        assert result == "MuleRouter result"

    # ── Explicit openrouter backend ───────────────────────────────────────────

    def test_openrouter_backend_success(self):
        """openrouter backend with a valid API key calls httpx and returns content."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "OpenRouter analysis result"}}]
        }
        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp

        with patch.dict(os.environ, {
            "FIXOPS_LLM_BACKEND": "openrouter",
            "OPENROUTER_API_KEY": "sk-test-key-123",
        }), patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = _call_llm(AgentRole.ANALYST, "Analyse this finding")

        assert result == "OpenRouter analysis result"

    def test_openrouter_backend_http_error_returns_stub(self):
        """HTTP error from OpenRouter returns an error stub, not an exception."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 502 Bad Gateway")
        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp

        with patch.dict(os.environ, {
            "FIXOPS_LLM_BACKEND": "openrouter",
            "OPENROUTER_API_KEY": "sk-test-key-123",
        }), patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = _call_llm(AgentRole.THREAT_HUNTER, "Hunt threats")

        assert isinstance(result, str)
        assert "[LLM error:" in result or "error" in result.lower()


# ---------------------------------------------------------------------------
# 2. _openrouter_call direct unit tests
# ---------------------------------------------------------------------------

class TestOpenrouterCall:
    def test_missing_api_key_returns_unavailable_prefix(self):
        """No key at all must return [LLM_UNAVAILABLE] prefix, never [MOCK_LLM]."""
        env_clear = {k: "" for k in (
            "OPENROUTER_API_KEY", "MULEROUTER_API_KEY", "FIXOPS_OPENROUTER_KEY"
        )}
        with patch.dict(os.environ, env_clear):
            result = _openrouter_call("some prompt")
        assert isinstance(result, str)
        assert result.startswith(_UNAVAILABLE_PREFIX), (
            f"Expected {_UNAVAILABLE_PREFIX!r}, got: {result[:80]!r}"
        )
        # Must not contain [MOCK_LLM] — these are distinct failure modes
        assert _MOCK_PREFIX not in result

    def test_httpx_unavailable_returns_unavailable_prefix(self):
        """If httpx is not installed, return [LLM_UNAVAILABLE] prefix."""
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-abc"}), \
             patch("builtins.__import__", side_effect=lambda name, *a, **kw: (
                 (_ for _ in ()).throw(ImportError("no httpx")) if name == "httpx"
                 else __import__(name, *a, **kw)
             )):
            # Can't easily intercept the import inside _openrouter_call cleanly
            # without module reload; test via the actual function with a None module.
            pass
        # Verify the code path by patching sys.modules["httpx"] = None
        import sys
        original = sys.modules.get("httpx")
        sys.modules["httpx"] = None  # type: ignore[assignment]
        try:
            result = _openrouter_call("test prompt")
        finally:
            if original is None:
                sys.modules.pop("httpx", None)
            else:
                sys.modules["httpx"] = original
        assert isinstance(result, str)
        assert result.startswith(_UNAVAILABLE_PREFIX) or "[LLM" in result

    def test_openrouter_call_sets_auth_header(self):
        """Ensure Authorization header carries the API key."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "ok"}}]
        }
        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-abc"}), \
             patch.dict("sys.modules", {"httpx": mock_httpx}):
            _openrouter_call("security prompt")

        call_kwargs = mock_httpx.post.call_args
        headers = call_kwargs[1]["headers"] if call_kwargs[1] else call_kwargs[0][1]
        assert "sk-abc" in headers.get("Authorization", "")

    def test_openrouter_call_uses_mulerouter_key_as_fallback(self):
        """MULEROUTER_API_KEY is accepted when OPENROUTER_API_KEY is absent."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "mule result"}}]
        }
        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp

        env_patch = {
            "OPENROUTER_API_KEY": "",
            "MULEROUTER_API_KEY": "sk-mule-xyz",
        }
        with patch.dict(os.environ, env_patch), \
             patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = _openrouter_call("mule test")

        assert result == "mule result"
        call_kwargs = mock_httpx.post.call_args
        headers = call_kwargs[1]["headers"]
        assert "sk-mule-xyz" in headers.get("Authorization", "")


# ---------------------------------------------------------------------------
# 3. _resolve_openrouter_key
# ---------------------------------------------------------------------------

class TestResolveOpenrouterKey:
    def test_openrouter_key_first(self):
        with patch.dict(os.environ, {
            "OPENROUTER_API_KEY": "sk-primary",
            "MULEROUTER_API_KEY": "sk-secondary",
            "FIXOPS_OPENROUTER_KEY": "sk-tertiary",
        }):
            assert _resolve_openrouter_key() == "sk-primary"

    def test_mulerouter_key_fallback(self):
        with patch.dict(os.environ, {
            "OPENROUTER_API_KEY": "",
            "MULEROUTER_API_KEY": "sk-mule",
            "FIXOPS_OPENROUTER_KEY": "",
        }):
            assert _resolve_openrouter_key() == "sk-mule"

    def test_fixops_key_tertiary(self):
        with patch.dict(os.environ, {
            "OPENROUTER_API_KEY": "",
            "MULEROUTER_API_KEY": "",
            "FIXOPS_OPENROUTER_KEY": "sk-fixops",
        }):
            assert _resolve_openrouter_key() == "sk-fixops"

    def test_no_key_returns_empty(self):
        with patch.dict(os.environ, {
            "OPENROUTER_API_KEY": "",
            "MULEROUTER_API_KEY": "",
            "FIXOPS_OPENROUTER_KEY": "",
        }):
            assert _resolve_openrouter_key() == ""


# ---------------------------------------------------------------------------
# 3. REST API 503 degradation when orchestrator unavailable
# ---------------------------------------------------------------------------

from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def degraded_client():
    """TestClient with _ORCHESTRATOR_AVAILABLE=False to test 503 paths."""
    app = FastAPI()
    with patch("apps.api.ai_orchestrator_router._ORCHESTRATOR_AVAILABLE", False):
        from apps.api.ai_orchestrator_router import router
        app.include_router(router)
        yield TestClient(app)


class TestOrchestratorUnavailable503:
    def test_create_task_503(self, degraded_client):
        resp = degraded_client.post("/api/v1/ai-orchestrator/tasks", json={
            "role": "analyst",
            "prompt": "test",
        })
        assert resp.status_code == 503

    def test_execute_task_503(self, degraded_client):
        resp = degraded_client.post("/api/v1/ai-orchestrator/tasks/fake-id/execute")
        assert resp.status_code == 503

    def test_get_task_503(self, degraded_client):
        resp = degraded_client.get("/api/v1/ai-orchestrator/tasks/fake-id")
        assert resp.status_code == 503

    def test_list_tasks_returns_empty_not_503(self, degraded_client):
        """GET /tasks gracefully degrades to empty list, not 503."""
        resp = degraded_client.get("/api/v1/ai-orchestrator/tasks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tasks"] == []
        assert data["total"] == 0

    def test_consensus_503(self, degraded_client):
        resp = degraded_client.post("/api/v1/ai-orchestrator/consensus", json={
            "prompt": "Is this critical?",
        })
        assert resp.status_code == 503

    def test_stats_503(self, degraded_client):
        resp = degraded_client.get("/api/v1/ai-orchestrator/stats")
        assert resp.status_code == 503
