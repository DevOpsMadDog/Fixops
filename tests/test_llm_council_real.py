"""Tests for the real LLM Council engine and router.

Coverage:
1. _parse_vote — normalisation, synonym mapping, invalid JSON
2. _aggregate — majority, no-majority, avg confidence, error votes
3. LLMCouncil — raises CouncilNotConfiguredError when key absent
4. LLMCouncil.convene — happy path (majority, no escalation)
5. LLMCouncil.convene — escalation when avg confidence < threshold
6. LLMCouncil.convene — escalation when no majority
7. 4 parallel calls to OpenRouter are made (mocked httpx)
8. DPO persist is called once per convene
9. Opus escalation path (mocked Anthropic API)
10. Opus escalation fallback when ANTHROPIC_API_KEY absent
11. Router POST /api/v1/council/convene — 200 happy path
12. Router POST /api/v1/council/convene — 503 when key missing
13. Router GET /api/v1/council/health
14. Router GET /api/v1/council/status
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sqlite3
import sys
import tempfile
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Make sure suite-core is importable
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in [
    os.path.join(_REPO_ROOT, "suite-core"),
    os.path.join(_REPO_ROOT, "suite-api"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_council_import_cache():
    """Force fresh import of llm_council_real for each test."""
    mods_to_drop = [k for k in sys.modules if "llm_council_real" in k]
    for m in mods_to_drop:
        del sys.modules[m]
    yield
    for m in [k for k in sys.modules if "llm_council_real" in k]:
        del sys.modules[m]


@pytest.fixture()
def tmp_dpo_db(tmp_path):
    return str(tmp_path / "dpo_pairs.db")


@pytest.fixture()
def env_with_key(monkeypatch, tmp_dpo_db):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test-key-abc123")
    monkeypatch.setenv("FIXOPS_DPO_DB", tmp_dpo_db)
    # Remove Anthropic key so Opus escalation fallback path is also tested
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture()
def env_with_both_keys(monkeypatch, tmp_dpo_db):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test-key-abc123")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
    monkeypatch.setenv("FIXOPS_DPO_DB", tmp_dpo_db)


@pytest.fixture()
def env_no_key(monkeypatch, tmp_dpo_db):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("FIXOPS_DPO_DB", tmp_dpo_db)


# ---------------------------------------------------------------------------
# Helper: build a fake httpx response
# ---------------------------------------------------------------------------

def _or_response(vote: str, reasoning: str = "looks fine", confidence: float = 0.9) -> MagicMock:
    body = json.dumps(
        {"choices": [{"message": {"content": json.dumps(
            {"vote": vote, "reasoning": reasoning, "confidence": confidence}
        )}}]}
    )
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = json.loads(body)
    mock.raise_for_status = MagicMock()
    return mock


def _anth_response(vote: str, reasoning: str = "Opus says ok") -> MagicMock:
    body = json.dumps(
        {"content": [{"text": json.dumps({"vote": vote, "reasoning": reasoning})}]}
    )
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = json.loads(body)
    mock.raise_for_status = MagicMock()
    return mock


# ---------------------------------------------------------------------------
# Unit tests — _parse_vote
# ---------------------------------------------------------------------------

class TestParseVote:
    def _mod(self):
        import core.llm_council_real as m
        return m

    def test_valid_json_approve(self, env_with_key):
        m = self._mod()
        result = m._parse_vote('{"vote":"approve","reasoning":"safe","confidence":0.9}')
        assert result["vote"] == "approve"
        assert result["confidence"] == 0.9
        assert result["reasoning"] == "safe"

    def test_valid_json_reject(self, env_with_key):
        m = self._mod()
        result = m._parse_vote('{"vote":"reject","confidence":0.8}')
        assert result["vote"] == "reject"

    def test_synonym_yes(self, env_with_key):
        m = self._mod()
        result = m._parse_vote('{"vote":"yes","confidence":0.7}')
        assert result["vote"] == "approve"

    def test_synonym_block(self, env_with_key):
        m = self._mod()
        result = m._parse_vote('{"vote":"block","confidence":0.6}')
        assert result["vote"] == "reject"

    def test_unknown_vote_maps_to_escalate(self, env_with_key):
        m = self._mod()
        result = m._parse_vote('{"vote":"maybe","confidence":0.5}')
        assert result["vote"] == "escalate"

    def test_invalid_json_returns_escalate(self, env_with_key):
        m = self._mod()
        result = m._parse_vote("this is not json")
        assert result["vote"] == "escalate"
        assert result["confidence"] == 0.5

    def test_confidence_clamped(self, env_with_key):
        m = self._mod()
        result = m._parse_vote('{"vote":"approve","confidence":1.5}')
        assert result["confidence"] == 1.0

    def test_markdown_fenced_json(self, env_with_key):
        m = self._mod()
        raw = '```json\n{"vote":"reject","confidence":0.85}\n```'
        result = m._parse_vote(raw)
        assert result["vote"] == "reject"


# ---------------------------------------------------------------------------
# Unit tests — _aggregate
# ---------------------------------------------------------------------------

class TestAggregate:
    def _mod(self):
        import core.llm_council_real as m
        return m

    def test_clear_majority_approve(self, env_with_key):
        m = self._mod()
        votes = [
            {"vote": "approve", "confidence": 0.9},
            {"vote": "approve", "confidence": 0.8},
            {"vote": "approve", "confidence": 0.85},
            {"vote": "reject",  "confidence": 0.6},
        ]
        counts, avg_conf, majority = m._aggregate(votes)
        assert majority == "approve"
        assert counts["approve"] == 3
        assert counts["reject"] == 1
        assert abs(avg_conf - (0.9 + 0.8 + 0.85 + 0.6) / 4) < 0.01

    def test_no_majority_two_two(self, env_with_key):
        m = self._mod()
        votes = [
            {"vote": "approve", "confidence": 0.9},
            {"vote": "approve", "confidence": 0.8},
            {"vote": "reject",  "confidence": 0.9},
            {"vote": "reject",  "confidence": 0.8},
        ]
        counts, avg_conf, majority = m._aggregate(votes)
        assert majority is None

    def test_error_votes_dont_inflate_confidence(self, env_with_key):
        m = self._mod()
        votes = [
            {"vote": "approve", "confidence": 0.9},
            {"vote": "escalate", "confidence": 0.0, "error": "timeout"},
        ]
        counts, avg_conf, majority = m._aggregate(votes)
        # Only the non-error vote contributes to avg
        assert abs(avg_conf - 0.9) < 0.01

    def test_all_error_votes_avg_zero(self, env_with_key):
        m = self._mod()
        votes = [
            {"vote": "escalate", "confidence": 0.0, "error": "http 500"},
            {"vote": "escalate", "confidence": 0.0, "error": "timeout"},
        ]
        counts, avg_conf, majority = m._aggregate(votes)
        assert avg_conf == 0.0


# ---------------------------------------------------------------------------
# Unit tests — LLMCouncil construction
# ---------------------------------------------------------------------------

class TestLLMCouncilConstruction:
    def test_raises_when_key_absent(self, env_no_key):
        import core.llm_council_real as m
        with pytest.raises(m.CouncilNotConfiguredError):
            m.LLMCouncil()

    def test_succeeds_when_key_present(self, env_with_key):
        import core.llm_council_real as m
        council = m.LLMCouncil()
        assert council is not None


# ---------------------------------------------------------------------------
# Integration tests — LLMCouncil.convene
# ---------------------------------------------------------------------------

class TestConveneHappyPath:
    """All 4 models return approve with high confidence — no escalation."""

    @pytest.mark.asyncio
    async def test_four_parallel_calls_made(self, env_with_key):
        import core.llm_council_real as mod

        call_count = 0
        async def fake_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            model = kwargs.get("json", {}).get("model", "unknown")
            return _or_response("approve", f"{model} approves", 0.9)

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(side_effect=fake_post)
            MockClient.return_value = instance

            council = mod.LLMCouncil()
            result = await council.convene("Is this CVE exploitable?", {"severity": "high"})

        assert call_count == 4
        assert result["verdict"] == "approve"
        assert result["escalated"] is False
        assert result["vote_counts"]["approve"] == 4
        assert len(result["individual_votes"]) == 4
        assert result["latency_ms"] >= 0

    @pytest.mark.asyncio
    async def test_dpo_persisted_after_convene(self, env_with_key, tmp_dpo_db):
        import core.llm_council_real as mod

        async def fake_post(url, **kwargs):
            return _or_response("approve", "safe", 0.9)

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(side_effect=fake_post)
            MockClient.return_value = instance

            council = mod.LLMCouncil(dpo_db_path=tmp_dpo_db)
            await council.convene("Deploy this fix?", {"fix": "patch CVE-2024-001"})

        # Check DB has exactly 1 row
        conn = sqlite3.connect(tmp_dpo_db)
        rows = conn.execute("SELECT verdict, escalated FROM dpo_pairs").fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0][0] == "approve"
        assert rows[0][1] == 0  # not escalated


class TestConveneEscalation:
    """Tests for escalation paths."""

    @pytest.mark.asyncio
    async def test_escalates_when_no_majority(self, env_with_key):
        """2 approve, 2 reject → no majority → escalate (fallback, no Anthropic key)."""
        import core.llm_council_real as mod

        votes = ["approve", "approve", "reject", "reject"]
        call_idx = 0

        async def fake_post(url, **kwargs):
            nonlocal call_idx
            v = votes[call_idx % len(votes)]
            call_idx += 1
            return _or_response(v, f"reasoning {v}", 0.8)

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(side_effect=fake_post)
            MockClient.return_value = instance

            council = mod.LLMCouncil()
            result = await council.convene("Allow root access?", {})

        assert result["escalated"] is True
        assert result["verdict"] == "escalate"  # no Anthropic key → conservative

    @pytest.mark.asyncio
    async def test_escalates_when_confidence_below_threshold(self, env_with_key):
        """All approve but confidence 0.4 < threshold 0.75."""
        import core.llm_council_real as mod

        async def fake_post(url, **kwargs):
            return _or_response("approve", "not sure", 0.4)

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(side_effect=fake_post)
            MockClient.return_value = instance

            council = mod.LLMCouncil()
            result = await council.convene("Safe to merge?", {}, threshold=0.75)

        assert result["escalated"] is True

    @pytest.mark.asyncio
    async def test_opus_escalation_called(self, env_with_both_keys):
        """When no majority, Opus is called and its verdict is returned."""
        import core.llm_council_real as mod

        or_votes = ["approve", "approve", "reject", "reject"]
        call_idx = 0
        anth_called = False

        async def fake_post(url, **kwargs):
            nonlocal call_idx, anth_called
            if "anthropic" in url:
                anth_called = True
                return _anth_response("reject", "Opus says reject")
            v = or_votes[call_idx % len(or_votes)]
            call_idx += 1
            return _or_response(v, f"vote {v}", 0.8)

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(side_effect=fake_post)
            MockClient.return_value = instance

            council = mod.LLMCouncil()
            result = await council.convene("High-stakes decision?", {})

        assert result["escalated"] is True
        assert anth_called is True
        assert result["verdict"] == "reject"
        assert "Opus" in result["final_reasoning"]

    @pytest.mark.asyncio
    async def test_dpo_persisted_on_escalation(self, env_with_key, tmp_dpo_db):
        """DPO row is written even when escalation occurs."""
        import core.llm_council_real as mod

        votes = ["approve", "approve", "reject", "reject"]
        idx = 0

        async def fake_post(url, **kwargs):
            nonlocal idx
            v = votes[idx % len(votes)]
            idx += 1
            return _or_response(v, "reason", 0.8)

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(side_effect=fake_post)
            MockClient.return_value = instance

            council = mod.LLMCouncil(dpo_db_path=tmp_dpo_db)
            await council.convene("Merge this?", {})

        conn = sqlite3.connect(tmp_dpo_db)
        rows = conn.execute("SELECT escalated FROM dpo_pairs").fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0][0] == 1  # escalated=True


class TestConveneErrorHandling:
    """Model errors are handled gracefully."""

    @pytest.mark.asyncio
    async def test_model_error_becomes_escalate_vote(self, env_with_key):
        """One model errors out — its vote is recorded as escalate with error flag."""
        import core.llm_council_real as mod

        call_idx = 0

        async def fake_post(url, **kwargs):
            nonlocal call_idx
            call_idx += 1
            if call_idx == 1:
                raise httpx_exc()
            return _or_response("approve", "ok", 0.9)

        import httpx
        def httpx_exc():
            return httpx.ConnectError("connection refused")

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(side_effect=fake_post)
            MockClient.return_value = instance

            council = mod.LLMCouncil()
            result = await council.convene("Is it safe?", {})

        # 3 approve + 1 error(escalate) → approve majority
        assert result["verdict"] == "approve"
        error_votes = [v for v in result["individual_votes"] if v.get("error")]
        assert len(error_votes) == 1


# ---------------------------------------------------------------------------
# Router tests
# ---------------------------------------------------------------------------

class TestCouncilRouter:
    """FastAPI router tests — mock the council singleton."""

    def _get_client(self, env_with_key):
        """Build a TestClient with council router mounted."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        # Patch _get_council on the router module
        import apps.api.council_router as cr
        app = FastAPI()
        app.include_router(cr.router)
        return TestClient(app, raise_server_exceptions=False)

    def test_convene_happy_path(self, env_with_key, monkeypatch):
        import apps.api.council_router as cr

        mock_council = AsyncMock()
        mock_council.convene = AsyncMock(return_value={
            "verdict":          "approve",
            "vote_counts":      {"approve": 4, "reject": 0, "escalate": 0},
            "individual_votes": [],
            "escalated":        False,
            "final_reasoning":  "All models agree.",
            "latency_ms":       120,
        })
        monkeypatch.setattr(cr, "_council", mock_council)

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(cr.router)
        client = TestClient(app)

        resp = client.post(
            "/api/v1/council/convene",
            json={"prompt": "Is CVE-2024-001 critical?", "context": {"severity": "high"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "approve"
        assert data["escalated"] is False
        assert data["latency_ms"] == 120

    def test_convene_503_when_key_missing(self, env_no_key, monkeypatch):
        import apps.api.council_router as cr

        # Reset singleton so it tries to init
        monkeypatch.setattr(cr, "_council", None)

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(cr.router)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/v1/council/convene",
            json={"prompt": "Is this safe?", "context": {}},
        )
        assert resp.status_code == 503
        assert "council not configured" in resp.json()["detail"].lower()

    def test_convene_422_blank_prompt(self, env_with_key, monkeypatch):
        import apps.api.council_router as cr

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(cr.router)
        client = TestClient(app)

        resp = client.post(
            "/api/v1/council/convene",
            json={"prompt": "   ", "context": {}},
        )
        assert resp.status_code == 422

    def test_health_returns_200(self, env_with_key, monkeypatch):
        import apps.api.council_router as cr

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(cr.router)
        client = TestClient(app)

        resp = client.get("/api/v1/council/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert "openrouter_configured" in data

    def test_status_alias_matches_health(self, env_with_key, monkeypatch):
        import apps.api.council_router as cr

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(cr.router)
        client = TestClient(app)

        health = client.get("/api/v1/council/health").json()
        status = client.get("/api/v1/council/status").json()
        assert health == status
