"""
tests/test_pipeline_council_real_wiring.py

Verification tests for the Brain Pipeline ↔ LLM Council wiring fixes.

Scenarios:
  A. WITH key present  → pipeline selects _step_llm_council; council runs via
     create_consensus_engine_replacement().analyse(); providers_responded counts
     only real votes; cost_usd > 0; method is council-based (not deterministic).
  B. WITHOUT key       → pipeline selects _step_llm_consensus; council path
     returns honest "llm_not_configured" result (NOT deterministic fabrication);
     cost_usd == 0; decision is None.
  C. Fallback votes    → votes with metadata mode in
     {fallback, deterministic, no_key, unknown} are excluded from
     providers_responded; quorum < 2 real votes → council_low_trust result.
"""

import importlib
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure suite-core is importable
# ---------------------------------------------------------------------------
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITE_CORE = os.path.join(REPO_ROOT, "suite-core")
if SUITE_CORE not in sys.path:
    sys.path.insert(0, SUITE_CORE)


# ===========================================================================
# Scenario A — step selection WITH key
# ===========================================================================

class TestStepSelection:
    """A. Verify _select_llm_step returns correct callable based on env."""

    def _get_pipeline_class(self):
        # Re-import to pick up current module state
        if "core.brain_pipeline" in sys.modules:
            del sys.modules["core.brain_pipeline"]
        from core.brain_pipeline import BrainPipeline  # noqa: PLC0415
        return BrainPipeline

    def test_select_council_when_openrouter_key_present(self, monkeypatch):
        """With OPENROUTER_API_KEY set, _select_llm_step returns _step_llm_council."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-key-1234")
        monkeypatch.delenv("FIXOPS_USE_COUNCIL", raising=False)
        BP = self._get_pipeline_class()
        bp = BP.__new__(BP)
        step = bp._select_llm_step()
        assert step.__func__ is BP._step_llm_council, (
            f"Expected _step_llm_council, got {step.__func__.__name__}"
        )

    def test_select_council_when_mulerouter_key_present(self, monkeypatch):
        """With MULEROUTER_API_KEY set, _select_llm_step returns _step_llm_council."""
        monkeypatch.setenv("MULEROUTER_API_KEY", "mr-test-key-5678")
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("FIXOPS_USE_COUNCIL", raising=False)
        BP = self._get_pipeline_class()
        bp = BP.__new__(BP)
        step = bp._select_llm_step()
        assert step.__func__ is BP._step_llm_council

    def test_select_consensus_when_no_key(self, monkeypatch):
        """With no API keys, _select_llm_step returns _step_llm_consensus."""
        for k in ("OPENROUTER_API_KEY", "MULEROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.delenv("FIXOPS_USE_COUNCIL", raising=False)
        BP = self._get_pipeline_class()
        bp = BP.__new__(BP)
        step = bp._select_llm_step()
        assert step.__func__ is BP._step_llm_consensus, (
            f"Expected _step_llm_consensus, got {step.__func__.__name__}"
        )

    def test_force_council_via_env_override(self, monkeypatch):
        """FIXOPS_USE_COUNCIL=1 forces _step_llm_council even without a key."""
        for k in ("OPENROUTER_API_KEY", "MULEROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("FIXOPS_USE_COUNCIL", "1")
        BP = self._get_pipeline_class()
        bp = BP.__new__(BP)
        step = bp._select_llm_step()
        assert step.__func__ is BP._step_llm_council

    def test_force_consensus_via_env_override(self, monkeypatch):
        """FIXOPS_USE_COUNCIL=0 forces _step_llm_consensus even with a key."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-key")
        monkeypatch.setenv("FIXOPS_USE_COUNCIL", "0")
        BP = self._get_pipeline_class()
        bp = BP.__new__(BP)
        step = bp._select_llm_step()
        assert step.__func__ is BP._step_llm_consensus


# ===========================================================================
# Scenario B — no key → honest not_configured, not fabrication
# ===========================================================================

class TestNoKeyHonestResult:
    """B. Without a key, _step_llm_council returns honest not-configured result."""

    def _make_pipeline(self):
        from core.brain_pipeline import BrainPipeline  # noqa: PLC0415
        bp = BrainPipeline.__new__(BrainPipeline)
        # Reset the singleton so it tries to create fresh
        BrainPipeline._council_adapter = None
        return bp

    def test_no_key_returns_not_configured(self, monkeypatch):
        """_step_llm_council with no key must return method=llm_not_configured, decision=None."""
        for k in ("OPENROUTER_API_KEY", "MULEROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(k, raising=False)

        # Simulate CouncilNotConfiguredError being raised by _get_council_adapter
        from core.llm_providers import CouncilNotConfiguredError  # noqa: PLC0415
        bp = self._make_pipeline()

        with patch.object(
            type(bp), "_get_council_adapter",
            side_effect=CouncilNotConfiguredError("No API key configured"),
        ):
            ctx = {"findings": [{"risk_score": 0.9, "severity": "critical", "title": "SQLi"}]}
            inp = MagicMock()
            inp.org_id = "test-org"
            result = bp._step_llm_council(ctx, inp)

        assert result["method"] == "llm_not_configured", (
            f"Expected llm_not_configured, got {result['method']}"
        )
        assert result.get("decision") is None, (
            f"decision must be None for not-configured, got {result.get('decision')!r}"
        )
        assert result.get("cost_usd", 0) == 0.0, "cost_usd must be 0 when no LLM ran"

    def test_no_key_result_is_not_deterministic_fabrication(self, monkeypatch):
        """Result must not look like a deterministic fabricated verdict."""
        for k in ("OPENROUTER_API_KEY", "MULEROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(k, raising=False)

        from core.llm_providers import CouncilNotConfiguredError  # noqa: PLC0415
        bp = self._make_pipeline()

        with patch.object(
            type(bp), "_get_council_adapter",
            side_effect=CouncilNotConfiguredError("No key"),
        ):
            ctx = {"findings": [{"risk_score": 0.95, "severity": "critical", "title": "RCE"}]}
            inp = MagicMock()
            inp.org_id = "test-org"
            result = bp._step_llm_council(ctx, inp)

        # Must NOT have method="deterministic" or method="deterministic_unverified"
        # with a real-looking decision
        assert result.get("method") not in ("deterministic",), (
            "No-key result must not claim method=deterministic (would look authoritative)"
        )
        # decision must be None — not "block", "review", "allow"
        assert result.get("decision") not in ("block", "review", "allow"), (
            f"decision={result.get('decision')!r} — a not-configured path must not produce a verdict"
        )

    def test_deterministic_consensus_method_is_clearly_labeled(self):
        """_deterministic_consensus must return method=deterministic_unverified (not deterministic)."""
        from core.brain_pipeline import BrainPipeline  # noqa: PLC0415
        bp = BrainPipeline.__new__(BrainPipeline)
        ctx: dict = {}
        findings = [{"risk_score": 0.9, "severity": "critical", "title": "X"}]
        result = bp._deterministic_consensus(findings, ctx)
        assert result["method"] == "deterministic_unverified", (
            f"Expected deterministic_unverified, got {result['method']!r}"
        )
        assert result.get("skipped") is True
        assert "note" in result, "Must include a note explaining it is not an LLM verdict"


# ===========================================================================
# Scenario C — fallback votes excluded from providers_responded
# ===========================================================================

class TestFallbackVoteExclusion:
    """C. Fallback/deterministic votes are excluded from providers_responded; quorum enforced."""

    def _make_adapter(self):
        from core.council_pipeline_adapter import CouncilPipelineAdapter  # noqa: PLC0415
        adapter = CouncilPipelineAdapter.__new__(CouncilPipelineAdapter)
        adapter._council = None
        adapter._memory_store = None
        adapter._feedback_loop = None
        import threading
        adapter._lock = threading.Lock()
        adapter._session_history = []
        # Build a minimal escalation object that never escalates (budget=0)
        esc = MagicMock()
        esc.can_escalate.return_value = False
        adapter._escalation = esc
        return adapter

    def _make_member_analysis(self, mode: str, stage: str = "2_peer_review"):
        """Build a minimal MemberAnalysis with the given mode."""
        from core.llm_council import MemberAnalysis  # noqa: PLC0415
        return MemberAnalysis(
            member_name="test-member",
            expertise="vulnerability_assessment",
            stage=stage,
            position="block",
            confidence=0.8,
            reasoning="test",
            metadata={"mode": mode, "cost_usd": 0.001 if mode not in ("fallback", "deterministic", "no_key", "unknown") else 0.0},
        )

    def _make_verdict(self, raw_analyses, member_vote_count: int = None):
        """Build a minimal CouncilVerdict with given raw_analyses."""
        from core.llm_council import CouncilVerdict, MemberVote  # noqa: PLC0415
        n = member_vote_count if member_vote_count is not None else len(raw_analyses)
        votes = [
            MemberVote(
                member_name=f"member-{i}",
                expertise="vuln",
                action="block",
                confidence=0.8,
                weight=1.0,
            )
            for i in range(n)
        ]
        return CouncilVerdict(
            action="block",
            confidence=0.85,
            reasoning="test verdict",
            member_votes=votes,
            raw_analyses=raw_analyses,
            cost_usd=0.005,
        )

    def test_real_votes_only_counted_in_providers_responded(self, monkeypatch):
        """providers_responded must count only non-fallback votes."""
        adapter = self._make_adapter()

        # 2 real votes + 2 fallback votes
        real1 = self._make_member_analysis("remote")
        real2 = self._make_member_analysis("remote")
        fake1 = self._make_member_analysis("fallback")
        fake2 = self._make_member_analysis("deterministic")
        verdict = self._make_verdict([real1, real2, fake1, fake2], member_vote_count=4)

        # Mock _ensure_council to return a mock that produces this verdict
        mock_council = MagicMock()
        mock_council.convene.return_value = verdict
        adapter._council = mock_council

        result = adapter.analyse(
            prompt="test",
            context={"org_id": "test"},
            findings=[{"risk_score": 0.9, "severity": "critical", "title": "SQLi"}],
        )

        assert result.get("providers_responded") == 2, (
            f"Expected 2 real providers, got {result.get('providers_responded')}"
        )

    def test_quorum_not_met_returns_low_trust(self, monkeypatch):
        """With only 1 real vote (below quorum=2), result must be council_low_trust."""
        adapter = self._make_adapter()

        # 1 real vote + 2 fallback votes = below quorum
        real1 = self._make_member_analysis("remote")
        fake1 = self._make_member_analysis("fallback")
        fake2 = self._make_member_analysis("no_key")
        verdict = self._make_verdict([real1, fake1, fake2], member_vote_count=3)

        mock_council = MagicMock()
        mock_council.convene.return_value = verdict
        adapter._council = mock_council

        result = adapter.analyse(
            prompt="test",
            context={"org_id": "test"},
            findings=[{"risk_score": 0.9, "severity": "critical", "title": "RCE"}],
        )

        assert result.get("method") == "council_low_trust", (
            f"Expected council_low_trust, got {result.get('method')!r}"
        )
        assert result.get("decision") is None, (
            f"Low-trust result must have decision=None, got {result.get('decision')!r}"
        )
        assert result.get("providers_responded") == 1

    def test_all_real_votes_full_quorum(self, monkeypatch):
        """With 3 real votes (≥quorum), providers_responded=3 and method=council_verdict."""
        adapter = self._make_adapter()

        real1 = self._make_member_analysis("remote")
        real2 = self._make_member_analysis("remote")
        real3 = self._make_member_analysis("remote")
        verdict = self._make_verdict([real1, real2, real3], member_vote_count=3)

        mock_council = MagicMock()
        mock_council.convene.return_value = verdict
        adapter._council = mock_council

        result = adapter.analyse(
            prompt="test",
            context={"org_id": "test"},
            findings=[{"risk_score": 0.9, "severity": "critical", "title": "SSRF"}],
        )

        assert result.get("providers_responded") == 3
        assert result.get("method") == "council_verdict"
        assert result.get("decision") == "block"

    def test_no_api_key_council_error_is_honest(self, monkeypatch):
        """CouncilNotConfiguredError in adapter.analyse returns method=no_api_key, decision=None."""
        adapter = self._make_adapter()

        from core.llm_providers import CouncilNotConfiguredError  # noqa: PLC0415

        # Make _ensure_council raise CouncilNotConfiguredError
        with patch.object(adapter, "_ensure_council", side_effect=CouncilNotConfiguredError("no key")):
            result = adapter.analyse(
                prompt="test",
                context={"org_id": "test"},
                findings=[{"risk_score": 0.9, "severity": "critical", "title": "XSS"}],
            )

        assert result.get("method") == "no_api_key", (
            f"Expected no_api_key, got {result.get('method')!r}"
        )
        assert result.get("decision") is None or result.get("decision") == "no_api_key", (
            f"decision must be null/no_api_key for not-configured, got {result.get('decision')!r}"
        )

    def test_generic_council_error_is_honest(self, monkeypatch):
        """A generic RuntimeError in adapter.analyse returns method=llm_unavailable, decision=None."""
        adapter = self._make_adapter()

        with patch.object(adapter, "_ensure_council", side_effect=OSError("network unreachable")):
            result = adapter.analyse(
                prompt="test",
                context={"org_id": "test"},
                findings=[{"risk_score": 0.9, "severity": "critical", "title": "Vuln"}],
            )

        assert result.get("method") == "llm_unavailable", (
            f"Expected llm_unavailable, got {result.get('method')!r}"
        )
        assert result.get("decision") is None, (
            f"decision must be None for unavailable, got {result.get('decision')!r}"
        )
        # Must not look like a real verdict
        assert result.get("decision") not in ("block", "review", "allow"), (
            "Generic error must not produce a fabricated verdict"
        )


# ===========================================================================
# Scenario A (live) — real council path with key (skip if no key in env)
# ===========================================================================

HAS_REAL_KEY = bool(
    os.environ.get("OPENROUTER_API_KEY") or os.environ.get("MULEROUTER_API_KEY")
)


@pytest.mark.skipif(not HAS_REAL_KEY, reason="No OPENROUTER_API_KEY / MULEROUTER_API_KEY in env")
class TestRealCouncilWithKey:
    """A (live). With a real key, create_consensus_engine_replacement().analyse() works."""

    def test_real_council_returns_nonzero_cost(self):
        """Real council call must return cost_usd > 0 and a valid method."""
        from core.council_pipeline_adapter import create_consensus_engine_replacement  # noqa: PLC0415
        adapter = create_consensus_engine_replacement()
        result = adapter.analyse(
            prompt="Analyze this critical SQL injection finding for risk decision.",
            context={"org_id": "test-live", "service_name": "test-service"},
            findings=[{
                "risk_score": 0.9,
                "severity": "critical",
                "title": "SQL Injection in login endpoint",
                "cve_id": "CVE-2021-44228",
            }],
        )
        # Must be a real council method
        assert result.get("method") in (
            "council_verdict", "council_escalation", "council_low_trust"
        ), f"Unexpected method: {result.get('method')!r} — expected a council-based method"
        # providers_responded must count only real votes
        assert result.get("providers_responded", 0) >= 1, (
            "At least 1 real provider should have responded"
        )
        # cost_usd > 0 for a real LLM call
        assert result.get("cost_usd", 0) > 0, (
            f"cost_usd={result.get('cost_usd')} — real council must have non-zero cost"
        )

    def test_brain_pipeline_selects_council_step_with_key(self, monkeypatch):
        """With key present, _select_llm_step returns _step_llm_council (pipeline wiring)."""
        from core.brain_pipeline import BrainPipeline  # noqa: PLC0415
        bp = BrainPipeline.__new__(BrainPipeline)
        monkeypatch.delenv("FIXOPS_USE_COUNCIL", raising=False)
        step = bp._select_llm_step()
        assert step.__func__ is BrainPipeline._step_llm_council, (
            f"With key present, pipeline must use _step_llm_council, got {step.__func__.__name__}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
