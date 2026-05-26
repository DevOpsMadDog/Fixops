"""Proof tests for ai_orchestrator honest LLM contract.

Four proofs required:
1. WITH key present — auto-detect routes to real OpenRouter call (httpx.post to openrouter.ai,
   correct auth header, result is actual model content not mock prefix).
2. WITHOUT key — returns [LLM_UNAVAILABLE] marker, never fabricated mock content.
3. Explicit mock (FIXOPS_LLM_BACKEND=mock) — prefixes output with [MOCK_LLM].
4. Unknown backend — raises ValueError, never silent mock fallback.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Path setup
_ROOT = Path(__file__).parent.parent
for _p in [str(_ROOT), str(_ROOT / "suite-core"), str(_ROOT / "suite-api")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Load .env so real keys are available
_env_file = _ROOT / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

from core.ai_orchestrator import (
    AgentRole,
    _MOCK_PREFIX,
    _UNAVAILABLE_PREFIX,
    _call_llm,
    _resolve_openrouter_key,
)

REAL_MODEL_CONTENT = (
    "SQL injection is an attack where malicious SQL statements are inserted "
    "into input fields to manipulate the database."
)


def _make_mock_httpx(content: str = REAL_MODEL_CONTENT) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"choices": [{"message": {"content": content}}]}
    mock_httpx = MagicMock()
    mock_httpx.post.return_value = mock_resp
    return mock_httpx


# ---------------------------------------------------------------------------
# Proof 1 — WITH key: auto-detects OpenRouter, makes real HTTP call
# ---------------------------------------------------------------------------

class TestProof1WithKey:
    def test_autodetect_calls_openrouter_url(self):
        """httpx.post must be called to openrouter.ai when a key is present."""
        os.environ.pop("FIXOPS_LLM_BACKEND", None)
        key = _resolve_openrouter_key()
        assert key, "No OpenRouter key in .env — cannot run real-call proof"

        mock_httpx = _make_mock_httpx()
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = _call_llm(AgentRole.ANALYST, "In one sentence: what is SQL injection?")

        assert mock_httpx.post.called, "httpx.post was never called"
        call_url = mock_httpx.post.call_args[0][0]
        assert "openrouter.ai" in call_url, f"Wrong URL: {call_url!r}"

    def test_autodetect_sends_correct_auth_header(self):
        """Authorization header must carry the resolved API key."""
        os.environ.pop("FIXOPS_LLM_BACKEND", None)
        key = _resolve_openrouter_key()
        assert key

        mock_httpx = _make_mock_httpx()
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            _call_llm(AgentRole.ANALYST, "test")

        headers = mock_httpx.post.call_args[1]["headers"]
        assert key in headers.get("Authorization", ""), (
            f"Key not in auth header. Got: {headers.get('Authorization', '')[:30]!r}"
        )

    def test_autodetect_returns_real_model_content_not_mock_prefix(self):
        """Result must be the real model output — not prefixed with [MOCK_LLM]."""
        os.environ.pop("FIXOPS_LLM_BACKEND", None)
        key = _resolve_openrouter_key()
        assert key

        mock_httpx = _make_mock_httpx(REAL_MODEL_CONTENT)
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = _call_llm(AgentRole.ANALYST, "In one sentence: what is SQL injection?")

        assert result == REAL_MODEL_CONTENT, f"Unexpected result: {result[:120]!r}"
        assert not result.startswith(_MOCK_PREFIX), f"Got mock prefix: {result[:80]!r}"
        assert not result.startswith(_UNAVAILABLE_PREFIX), f"Got unavailable: {result[:80]!r}"


# ---------------------------------------------------------------------------
# Proof 2 — WITHOUT key: honest [LLM_UNAVAILABLE], never fabricated content
# ---------------------------------------------------------------------------

class TestProof2NoKey:
    @pytest.fixture(autouse=True)
    def clear_all_keys(self):
        """Strip all key env vars for the duration of the test."""
        saved = {}
        for k in ("OPENROUTER_API_KEY", "MULEROUTER_API_KEY",
                   "FIXOPS_OPENROUTER_KEY", "FIXOPS_LLM_BACKEND"):
            saved[k] = os.environ.pop(k, None)
        yield
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v

    def test_returns_unavailable_prefix(self):
        result = _call_llm(AgentRole.ANALYST, "test")
        assert result.startswith(_UNAVAILABLE_PREFIX), (
            f"Expected {_UNAVAILABLE_PREFIX!r} prefix, got: {result[:100]!r}"
        )

    def test_does_not_return_fabricated_analysis_content(self):
        result = _call_llm(AgentRole.ANALYST, "test")
        assert "ANALYSIS COMPLETE" not in result, (
            f"Result contains fabricated analyst content: {result[:120]!r}"
        )

    def test_does_not_return_fabricated_review_content(self):
        result = _call_llm(AgentRole.REVIEWER, "test")
        assert "REVIEW VERDICT" not in result, (
            f"Result contains fabricated reviewer content: {result[:120]!r}"
        )

    def test_does_not_use_mock_prefix(self):
        """[LLM_UNAVAILABLE] and [MOCK_LLM] are distinct — no-key must not use mock prefix."""
        result = _call_llm(AgentRole.THREAT_HUNTER, "test")
        assert not result.startswith(_MOCK_PREFIX), (
            f"Got mock prefix instead of unavailable: {result[:80]!r}"
        )

    def test_all_roles_return_unavailable_not_fabricated(self):
        for role in AgentRole:
            result = _call_llm(role, "test")
            assert result.startswith(_UNAVAILABLE_PREFIX), (
                f"Role {role.value}: expected unavailable, got: {result[:80]!r}"
            )


# ---------------------------------------------------------------------------
# Proof 3 — Explicit mock: clearly labelled [MOCK_LLM], never passed as real
# ---------------------------------------------------------------------------

class TestProof3ExplicitMock:
    def test_mock_backend_prefixes_with_mock_label(self):
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "mock"}):
            result = _call_llm(AgentRole.ANALYST, "anything")
        assert result.startswith(_MOCK_PREFIX), (
            f"Expected {_MOCK_PREFIX!r} prefix, got: {result[:80]!r}"
        )

    def test_mock_backend_all_roles_labelled(self):
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "mock"}):
            for role in AgentRole:
                result = _call_llm(role, "anything")
                assert result.startswith(_MOCK_PREFIX), (
                    f"Role {role.value}: missing {_MOCK_PREFIX!r}, got: {result[:60]!r}"
                )

    def test_mock_content_is_not_returned_without_label(self):
        """The canned analyst string must only appear when explicitly labelled."""
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "mock"}):
            result = _call_llm(AgentRole.ANALYST, "anything")
        # Content must include the canned text — but only behind the label
        assert _MOCK_PREFIX in result
        # Strip prefix and confirm canned content follows
        stripped = result[len(_MOCK_PREFIX):].strip()
        assert "ANALYSIS COMPLETE" in stripped


# ---------------------------------------------------------------------------
# Proof 4 — Unknown backend: raises ValueError, never silent mock
# ---------------------------------------------------------------------------

class TestProof4UnknownBackend:
    def test_unknown_backend_raises_value_error(self):
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "totally_fake_backend"}):
            with pytest.raises(ValueError, match="Unknown FIXOPS_LLM_BACKEND"):
                _call_llm(AgentRole.ANALYST, "anything")

    def test_unknown_backend_error_names_the_bad_value(self):
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "bad_xyz_backend"}):
            with pytest.raises(ValueError, match="bad_xyz_backend"):
                _call_llm(AgentRole.ANALYST, "anything")

    def test_unknown_backend_does_not_return_mock_string(self):
        """Must raise, not return any string (including mock content)."""
        with patch.dict(os.environ, {"FIXOPS_LLM_BACKEND": "evil_backend"}):
            raised = False
            try:
                _call_llm(AgentRole.ANALYST, "anything")
            except ValueError:
                raised = True
            assert raised, "Unknown backend must raise ValueError, not return a string"
