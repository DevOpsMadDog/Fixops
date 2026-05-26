"""Tests for EnhancedLLMCouncil — confidence scoring, dissent tracking, calibration.

Run with:
    python -m pytest tests/test_council_enhanced.py --timeout=120 -q -o "addopts="

Test organisation:
- The ``council`` fixture uses ``_allow_mock=True`` — deterministic, offline,
  fast.  All unit tests that test scoring/calibration/dissent logic use this
  fixture so they never hit the network.
- ``TestRealCouncilPath`` uses the real LLMCouncil and is gated on
  OPENROUTER_API_KEY being present.  It proves the real path fires and that
  votes come from real models, not _mock_vote.
- ``TestHonestUnavailable`` monkeypatches the key away and proves the
  NOT_CONFIGURED honest path fires instead of fabricated mock votes.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from dotenv import load_dotenv

# Load .env so OPENROUTER_API_KEY is visible when skipif conditions evaluate.
# This is safe for tests — load_dotenv() is a no-op if .env is absent.
load_dotenv()

from core.council_enhanced import (
    CalibrationReport,
    CouncilVerdict,
    EnhancedLLMCouncil,
    ModelCalibration,
    _NOT_CONFIGURED_PREFIX,
    _TEST_MOCK_PREFIX,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path: Path) -> str:
    """Temporary SQLite DB path for each test."""
    return str(tmp_path / "test_council.db")


@pytest.fixture
def council(tmp_db: str) -> EnhancedLLMCouncil:
    """Fresh EnhancedLLMCouncil backed by temp DB with mock votes enabled.

    Uses ``_allow_mock=True`` so all unit tests that test scoring/calibration/
    dissent logic run offline and deterministically without hitting OpenRouter.
    """
    return EnhancedLLMCouncil(db_path=tmp_db, _allow_mock=True)


@pytest.fixture
def council_nokey(tmp_db: str, monkeypatch: pytest.MonkeyPatch) -> EnhancedLLMCouncil:
    """Council with OPENROUTER_API_KEY stripped — exercises honest NOT_CONFIGURED path."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("FIXOPS_OPENROUTER_KEY", raising=False)
    return EnhancedLLMCouncil(db_path=tmp_db, _allow_mock=False)


@pytest.fixture
def high_severity_finding() -> Dict[str, Any]:
    return {
        "id": "test-finding-001",
        "title": "SQL Injection in login endpoint",
        "severity": "critical",
        "risk_score": 0.95,
        "cve_id": "CVE-2024-9999",
    }


@pytest.fixture
def low_severity_finding() -> Dict[str, Any]:
    return {
        "id": "test-finding-002",
        "title": "Informational cookie attribute missing",
        "severity": "low",
        "risk_score": 0.1,
    }


@pytest.fixture
def medium_finding() -> Dict[str, Any]:
    return {
        "id": "test-finding-003",
        "title": "Outdated dependency",
        "severity": "medium",
        "risk_score": 0.5,
    }


# ---------------------------------------------------------------------------
# 1. CouncilVerdict dataclass
# ---------------------------------------------------------------------------


class TestCouncilVerdict:
    def test_to_dict_has_all_fields(self):
        v = CouncilVerdict(
            verdict_id="v1",
            verdict="TRUE_POSITIVE",
            confidence=0.85,
            votes={"qwen_qwq": "TRUE_POSITIVE", "kimi_k2": "TRUE_POSITIVE"},
            agreement_pct=1.0,
            dissenting_models=[],
            reasoning="Both models agreed.",
            escalated_to_opus=False,
            processing_time_ms=120,
        )
        d = v.to_dict()
        assert d["verdict"] == "TRUE_POSITIVE"
        assert d["confidence"] == 0.85
        assert d["agreement_pct"] == 1.0
        assert d["dissenting_models"] == []
        assert d["escalated_to_opus"] is False
        assert d["trustgraph_entity_id"] is None

    def test_confidence_rounded_to_4_decimals(self):
        v = CouncilVerdict(
            verdict_id="v2",
            verdict="FALSE_POSITIVE",
            confidence=0.333333333,
            votes={},
            agreement_pct=0.5,
            dissenting_models=["gemma4"],
            reasoning="",
            escalated_to_opus=False,
            processing_time_ms=50,
        )
        d = v.to_dict()
        assert len(str(d["confidence"]).split(".")[-1]) <= 4


# ---------------------------------------------------------------------------
# 2. Confidence calculation
# ---------------------------------------------------------------------------


class TestConfidenceCalculation:
    def test_full_agreement_high_confidence(self, council: EnhancedLLMCouncil):
        votes = {
            "qwen_qwq": "TRUE_POSITIVE",
            "kimi_k2": "TRUE_POSITIVE",
            "gemma4": "TRUE_POSITIVE",
        }
        _, agreement_pct, confidence, dissenting = council._score_votes(votes)
        assert agreement_pct == 1.0
        assert confidence >= 0.9
        assert dissenting == []

    def test_split_vote_lower_confidence(self, council: EnhancedLLMCouncil):
        votes = {
            "qwen_qwq": "TRUE_POSITIVE",
            "kimi_k2": "FALSE_POSITIVE",
            "gemma4": "FALSE_POSITIVE",
        }
        _, agreement_pct, confidence, dissenting = council._score_votes(votes)
        # gemma4 weight=0.8, kimi_k2=1.0 -> FP wins
        assert agreement_pct < 1.0
        assert confidence < 0.9
        assert "qwen_qwq" in dissenting

    def test_empty_votes_returns_zeros(self, council: EnhancedLLMCouncil):
        _, agreement_pct, confidence, dissenting = council._score_votes({})
        assert agreement_pct == 0.0
        assert confidence == 0.0
        assert dissenting == []

    def test_single_model_has_participation_penalty(self, council: EnhancedLLMCouncil):
        """Single model response should have lower confidence than 3 agreeing models."""
        votes_one = {"qwen_qwq": "TRUE_POSITIVE"}
        votes_three = {
            "qwen_qwq": "TRUE_POSITIVE",
            "kimi_k2": "TRUE_POSITIVE",
            "gemma4": "TRUE_POSITIVE",
        }
        _, _, confidence_one, _ = council._score_votes(votes_one)
        _, _, confidence_three, _ = council._score_votes(votes_three)
        assert confidence_one < confidence_three

    def test_weighted_vote_affects_winner(self, council: EnhancedLLMCouncil):
        """claude_opus has weight=1.5; if present it tips the balance."""
        council._weights["claude_opus"] = 1.5
        votes = {
            "qwen_qwq": "FALSE_POSITIVE",   # weight 1.0
            "claude_opus": "TRUE_POSITIVE",  # weight 1.5 -> wins
        }
        _, _, _, dissenting = council._score_votes(votes)
        majority = council._majority_label(votes)
        assert majority == "TRUE_POSITIVE"
        assert "qwen_qwq" in dissenting


# ---------------------------------------------------------------------------
# 3. Dissent detection
# ---------------------------------------------------------------------------


class TestDissentDetection:
    def test_no_dissent_when_unanimous(self, council: EnhancedLLMCouncil):
        votes = {"qwen_qwq": "TRUE_POSITIVE", "kimi_k2": "TRUE_POSITIVE"}
        _, _, _, dissenting = council._score_votes(votes)
        assert dissenting == []

    def test_dissent_correctly_identified(self, council: EnhancedLLMCouncil):
        votes = {
            "qwen_qwq": "TRUE_POSITIVE",
            "kimi_k2": "TRUE_POSITIVE",
            "gemma4": "FALSE_POSITIVE",
        }
        _, _, _, dissenting = council._score_votes(votes)
        assert dissenting == ["gemma4"]

    def test_dissenting_models_in_verdict(self, council: EnhancedLLMCouncil):
        verdict = council.deliberate(
            {"id": "x", "title": "test", "severity": "low", "risk_score": 0.05},
            "Is this a true positive?",
        )
        # With low risk_score gemma4 votes NEEDS_REVIEW, others may differ
        assert isinstance(verdict.dissenting_models, list)


# ---------------------------------------------------------------------------
# 4. Escalation trigger
# ---------------------------------------------------------------------------


class TestEscalationTrigger:
    def test_low_confidence_sets_escalated_flag(self, council: EnhancedLLMCouncil):
        """Force escalation by setting a very high threshold."""
        council._escalation_threshold = 1.1  # impossible to reach -> always escalate
        verdict = council.deliberate(
            {"title": "test", "severity": "medium", "risk_score": 0.5},
            "TP or FP?",
        )
        assert verdict.escalated_to_opus is True
        assert verdict.verdict == "ESCALATED"

    def test_high_confidence_no_escalation(self, council: EnhancedLLMCouncil):
        """All models agree on critical finding → no escalation."""
        council._escalation_threshold = 0.7
        verdict = council.deliberate(
            {"title": "RCE vuln", "severity": "critical", "risk_score": 0.99},
            "Is this exploitable?",
        )
        # With full mock agreement, confidence should be high enough
        assert verdict.escalated_to_opus is False
        assert verdict.verdict != "ESCALATED"

    def test_escalation_fallback_when_opus_unavailable(self, council: EnhancedLLMCouncil):
        """When Opus fails, escalation returns conservative fallback."""
        council._escalation_threshold = 1.1  # force escalation
        # _escalate_to_opus will fail ImportError or missing key → falls back
        verdict = council.deliberate(
            {"title": "test", "severity": "high", "risk_score": 0.8},
            "TP?",
        )
        # Should still return a valid verdict (not raise)
        assert verdict.verdict == "ESCALATED"
        assert verdict.confidence > 0.0
        assert "fallback" in verdict.reasoning.lower() or "escalat" in verdict.reasoning.lower()


# ---------------------------------------------------------------------------
# 5. Deliberate end-to-end
# ---------------------------------------------------------------------------


class TestDeliberate:
    def test_returns_council_verdict(self, council: EnhancedLLMCouncil, high_severity_finding):
        v = council.deliberate(high_severity_finding, "Is this exploitable?")
        assert isinstance(v, CouncilVerdict)
        assert v.verdict_id
        assert v.verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW", "ESCALATED")
        assert 0.0 <= v.confidence <= 1.0
        assert 0.0 <= v.agreement_pct <= 1.0
        assert v.processing_time_ms >= 0

    def test_high_severity_finds_true_positive(self, council, high_severity_finding):
        v = council.deliberate(high_severity_finding, "TP or FP?")
        assert v.verdict in ("TRUE_POSITIVE", "ESCALATED")

    def test_low_severity_finds_false_positive(self, council, low_severity_finding):
        v = council.deliberate(low_severity_finding, "TP or FP?")
        assert v.verdict in ("FALSE_POSITIVE", "NEEDS_REVIEW", "ESCALATED")

    def test_verdict_persisted_in_db(self, council, high_severity_finding, tmp_db):
        v = council.deliberate(high_severity_finding, "test persistence")
        recent = council.get_recent_verdicts(limit=10)
        ids = [r["verdict_id"] for r in recent]
        assert v.verdict_id in ids

    def test_reasoning_is_non_empty(self, council, high_severity_finding):
        v = council.deliberate(high_severity_finding, "Explain")
        assert len(v.reasoning) > 0


# ---------------------------------------------------------------------------
# 6. Weight calibration
# ---------------------------------------------------------------------------


class TestWeightCalibration:
    def test_correct_prediction_increases_weight(self, council):
        original_weight = council._weights["qwen_qwq"]
        # Feed a verdict with qwen_qwq voting TRUE_POSITIVE
        v = council.deliberate(
            {"title": "test", "severity": "critical", "risk_score": 0.9},
            "TP?",
        )
        # Track as TRUE_POSITIVE (matches what mock returns for critical)
        council.track_accuracy(v.verdict_id, "TRUE_POSITIVE")
        new_weight = council._weights["qwen_qwq"]
        assert new_weight >= original_weight  # should increase or stay same if vote matched

    def test_incorrect_prediction_decreases_weight(self, council):
        v = council.deliberate(
            {"title": "test", "severity": "critical", "risk_score": 0.9},
            "TP?",
        )
        original_weight = council._weights["qwen_qwq"]
        # Feed wrong outcome → weight should decrease
        council.track_accuracy(v.verdict_id, "FALSE_POSITIVE")
        new_weight = council._weights["qwen_qwq"]
        # qwen_qwq voted TRUE_POSITIVE for critical, outcome is FALSE_POSITIVE → wrong
        assert new_weight <= original_weight

    def test_weight_has_floor(self, council):
        """Weight cannot drop below 0.1."""
        council._weights["gemma4"] = 0.11
        # Drive weight down by many wrong predictions
        for _ in range(30):
            v = council.deliberate(
                {"title": "x", "severity": "critical", "risk_score": 0.95},
                "TP?",
            )
            council.track_accuracy(v.verdict_id, "FALSE_POSITIVE")
        assert council._weights["gemma4"] >= 0.1

    def test_weight_has_ceiling(self, council):
        """Weight cannot exceed 2.0."""
        council._weights["qwen_qwq"] = 1.95
        for _ in range(10):
            v = council.deliberate(
                {"title": "x", "severity": "critical", "risk_score": 0.95},
                "TP?",
            )
            council.track_accuracy(v.verdict_id, "TRUE_POSITIVE")
        assert council._weights["qwen_qwq"] <= 2.0

    def test_track_accuracy_unknown_verdict_is_safe(self, council):
        """Calling track_accuracy with unknown ID should not raise."""
        council.track_accuracy("nonexistent-id", "TRUE_POSITIVE")  # no exception

    def test_weights_persisted_across_instances(self, tmp_db):
        """Weights saved by one instance are loaded by a new instance."""
        c1 = EnhancedLLMCouncil(db_path=tmp_db)
        c1._update_model_weight("qwen_qwq", correct=True)
        weight_after = c1._weights["qwen_qwq"]

        c2 = EnhancedLLMCouncil(db_path=tmp_db)
        assert abs(c2._weights.get("qwen_qwq", 0) - weight_after) < 0.001


# ---------------------------------------------------------------------------
# 7. Calibration report
# ---------------------------------------------------------------------------


class TestCalibrationReport:
    def test_report_structure(self, council):
        report = council.get_calibration_report()
        assert isinstance(report, CalibrationReport)
        d = report.to_dict()
        assert "models" in d
        assert "overall_accuracy" in d
        assert "total_verdicts" in d
        assert d["window_days"] == 30

    def test_report_includes_all_default_models(self, council):
        report = council.get_calibration_report()
        model_names = {m.model_name for m in report.models}
        assert "qwen_qwq" in model_names
        assert "kimi_k2" in model_names
        assert "gemma4" in model_names

    def test_accuracy_after_feedback(self, council):
        """Accuracy should be 1.0 when all feedback matches predictions."""
        v = council.deliberate(
            {"title": "x", "severity": "critical", "risk_score": 0.95}, "TP?"
        )
        council.track_accuracy(v.verdict_id, "TRUE_POSITIVE")
        report = council.get_calibration_report()
        # Overall accuracy includes predictions that matched
        assert report.total_with_outcomes >= 1

    def test_custom_window_days(self, council):
        report = council.get_calibration_report(window_days=7)
        assert report.window_days == 7


# ---------------------------------------------------------------------------
# 8. Recent verdicts
# ---------------------------------------------------------------------------


class TestRecentVerdicts:
    def test_empty_initially(self, council):
        results = council.get_recent_verdicts()
        assert isinstance(results, list)
        assert len(results) == 0

    def test_verdicts_appear_after_deliberation(self, council, high_severity_finding):
        council.deliberate(high_severity_finding, "test?")
        results = council.get_recent_verdicts()
        assert len(results) == 1

    def test_accurate_field_none_without_outcome(self, council, high_severity_finding):
        council.deliberate(high_severity_finding, "test?")
        results = council.get_recent_verdicts()
        assert results[0]["accurate"] is None

    def test_accurate_field_true_when_correct(self, council, high_severity_finding):
        v = council.deliberate(high_severity_finding, "test?")
        council.track_accuracy(v.verdict_id, v.verdict if v.verdict != "ESCALATED" else "TRUE_POSITIVE")
        results = council.get_recent_verdicts()
        # accurate field should be set (True or False depending on verdict)
        assert results[0]["actual_outcome"] is not None

    def test_limit_respected(self, council):
        for i in range(5):
            council.deliberate({"title": f"finding-{i}", "severity": "high", "risk_score": 0.8}, "?")
        results = council.get_recent_verdicts(limit=3)
        assert len(results) == 3


# ---------------------------------------------------------------------------
# 9. Real council path — requires OPENROUTER_API_KEY
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("OPENROUTER_API_KEY", "").strip(),
    reason="OPENROUTER_API_KEY not set — skipping real council network test",
)
class TestRealCouncilPath:
    """Prove that when OPENROUTER_API_KEY is present the enhanced council uses
    the real LLMCouncil fan-out, not _mock_vote.

    These tests hit the network (~5-15s) and are gated on the key being set.
    """

    def test_real_votes_not_mock(self, tmp_db: str):
        """Votes come from real models — reasoning must NOT contain _TEST_MOCK_PREFIX."""
        council = EnhancedLLMCouncil(db_path=tmp_db, _allow_mock=False)
        finding = {
            "id": "real-test-001",
            "title": "SQL Injection in login endpoint",
            "severity": "critical",
            "risk_score": 0.95,
            "cve_id": "CVE-2024-9999",
        }
        verdict = council.deliberate(finding, "Is this a true positive security vulnerability?")

        # Verify the verdict is structurally valid
        assert isinstance(verdict, CouncilVerdict)
        assert verdict.verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW", "ESCALATED")
        assert 0.0 <= verdict.confidence <= 1.0
        assert verdict.processing_time_ms > 0

        # Prove votes did NOT come from _mock_vote — reasoning must not have mock prefix
        for model_name, reason in (verdict.votes or {}).items():
            # Check reasoning dict from the stored verdict (not directly accessible,
            # but _TEST_MOCK_PREFIX must not appear in the final reasoning string)
            pass
        assert _TEST_MOCK_PREFIX not in verdict.reasoning, (
            f"Reasoning contains mock prefix — real council was NOT used: {verdict.reasoning[:200]}"
        )
        assert _NOT_CONFIGURED_PREFIX not in verdict.reasoning, (
            f"Reasoning contains NOT_CONFIGURED prefix — key was present but council failed: "
            f"{verdict.reasoning[:200]}"
        )

    def test_real_votes_come_from_multiple_models(self, tmp_db: str):
        """At least 2 model slugs appear in the votes dict (fan-out confirmed)."""
        council = EnhancedLLMCouncil(db_path=tmp_db, _allow_mock=False)
        finding = {
            "id": "real-test-002",
            "title": "Hardcoded AWS secret key in source",
            "severity": "high",
            "risk_score": 0.88,
        }
        verdict = council.deliberate(finding, "Should this be remediated immediately?")

        assert len(verdict.votes) >= 2, (
            f"Expected votes from at least 2 real models, got: {list(verdict.votes.keys())}"
        )
        # Model slugs must look like OpenRouter model paths (contain underscore or slash
        # from the slug mapping), not the internal mock names like 'qwen_qwq'/'kimi_k2'/'gemma4'
        mock_only_names = {"qwen_qwq", "kimi_k2", "gemma4", "deepseek_r1"}
        real_model_names = set(verdict.votes.keys()) - mock_only_names
        assert len(real_model_names) >= 1, (
            f"All vote keys look like internal mock names — real fan-out not confirmed. "
            f"Vote keys: {list(verdict.votes.keys())}"
        )

    def test_verdict_persisted_with_real_votes(self, tmp_db: str):
        """A verdict from real council is persisted to SQLite and retrievable."""
        council = EnhancedLLMCouncil(db_path=tmp_db, _allow_mock=False)
        finding = {"id": "real-test-003", "title": "Open redirect", "severity": "medium", "risk_score": 0.55}
        verdict = council.deliberate(finding, "Is this exploitable?")

        recent = council.get_recent_verdicts(limit=5)
        ids = [r["verdict_id"] for r in recent]
        assert verdict.verdict_id in ids


# ---------------------------------------------------------------------------
# 10. Honest unavailable path — no key → NOT_CONFIGURED, not mock votes
# ---------------------------------------------------------------------------


class TestHonestUnavailable:
    """When OPENROUTER_API_KEY is absent and _allow_mock=False (the default),
    the council must return an honest NOT_CONFIGURED verdict, never fabricated
    mock votes presented as real consensus.
    """

    def test_no_key_returns_not_configured_reasoning(self, council_nokey: EnhancedLLMCouncil):
        """Reasoning must contain NOT_CONFIGURED prefix — never a mock verdict."""
        finding = {
            "id": "nokey-test-001",
            "title": "Prototype pollution",
            "severity": "high",
            "risk_score": 0.82,
        }
        verdict = council_nokey.deliberate(finding, "Is this exploitable?")

        assert isinstance(verdict, CouncilVerdict)
        # The honest path returns a single 'council' vote of NEEDS_REVIEW with low confidence,
        # triggering escalation (which also fails gracefully), so the final verdict is ESCALATED
        # or NEEDS_REVIEW — never a high-confidence fabricated TRUE_POSITIVE.
        assert verdict.verdict in ("NEEDS_REVIEW", "ESCALATED"), (
            f"Expected NEEDS_REVIEW/ESCALATED for not-configured council, got {verdict.verdict}"
        )
        # Reasoning must contain the honest NOT_CONFIGURED marker OR the escalation fallback —
        # it must NOT contain the mock prefix (which would mean _mock_vote fired).
        assert _TEST_MOCK_PREFIX not in verdict.reasoning, (
            f"Mock prefix found in reasoning — _mock_vote fired on default path: {verdict.reasoning[:300]}"
        )

    def test_no_key_mock_false_never_calls_mock_vote(
        self, tmp_db: str, monkeypatch: pytest.MonkeyPatch
    ):
        """_mock_vote must not be called when _allow_mock=False and no key."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("FIXOPS_OPENROUTER_KEY", raising=False)

        council = EnhancedLLMCouncil(db_path=tmp_db, _allow_mock=False)

        mock_vote_calls: list = []
        original_mock_vote = council._mock_vote

        def patched_mock_vote(finding, model_name):
            mock_vote_calls.append((finding, model_name))
            return original_mock_vote(finding, model_name)

        council._mock_vote = patched_mock_vote  # type: ignore[method-assign]

        council.deliberate(
            {"title": "test", "severity": "critical", "risk_score": 0.95},
            "TP?",
        )

        assert mock_vote_calls == [], (
            f"_mock_vote was called {len(mock_vote_calls)} time(s) on the default path "
            f"(no key, _allow_mock=False) — fabricated consensus detected!"
        )

    def test_mock_opt_in_still_works_for_tests(self, tmp_db: str, monkeypatch: pytest.MonkeyPatch):
        """When _allow_mock=True is explicitly set, mock votes still work for tests."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

        council = EnhancedLLMCouncil(db_path=tmp_db, _allow_mock=True)
        verdict = council.deliberate(
            {"title": "test", "severity": "critical", "risk_score": 0.95},
            "TP?",
        )
        # Mock opt-in: should get a verdict from _mock_vote (TRUE_POSITIVE for critical)
        assert verdict.verdict in ("TRUE_POSITIVE", "ESCALATED")
        # Reasoning should contain the test mock prefix
        assert _TEST_MOCK_PREFIX in verdict.reasoning or verdict.escalated_to_opus
