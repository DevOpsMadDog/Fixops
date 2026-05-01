"""Tests for AutoFixEngine LLMCouncil consensus path (Wave 3C).

Covers the FIXOPS_USE_COUNCIL=1 gated branch in AutoFixEngine.generate_fix
that augments fix prompts and confidence with multi-model council verdicts.
"""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.autofix_engine import AutoFixEngine, FixType


def _make_finding(**kwargs):
    base = {
        "id": "find-council-001",
        "title": "SQL Injection in login endpoint",
        "severity": "high",
        "cwe_id": "CWE-89",
        "cve_ids": [],
        "description": "Unsanitized user input in SQL query",
        "file_path": "app/login.py",
        "category": "injection",
        "language": "python",
    }
    base.update(kwargs)
    return base


@pytest.fixture
def engine():
    e = AutoFixEngine()
    e._fixes = {}
    e._history = []
    return e


@pytest.fixture(autouse=True)
def _restore_env():
    """Save & restore FIXOPS_USE_COUNCIL across tests."""
    prev = os.environ.get("FIXOPS_USE_COUNCIL")
    yield
    if prev is None:
        os.environ.pop("FIXOPS_USE_COUNCIL", None)
    else:
        os.environ["FIXOPS_USE_COUNCIL"] = prev


def _verdict(reasoning="Council says fix the SQLi via parameterised queries.",
             confidence=0.92):
    return SimpleNamespace(reasoning=reasoning, confidence=confidence,
                           action="remediate_high")


def test_critical_uses_council_when_flag_set(engine):
    """Critical severity + FIXOPS_USE_COUNCIL=1 -> council.convene called."""
    os.environ["FIXOPS_USE_COUNCIL"] = "1"
    finding = _make_finding(severity="critical", id="find-crit-1")

    fake_council = MagicMock()
    fake_council.convene.return_value = _verdict()
    fake_factory = MagicMock()
    fake_factory.create_security_council.return_value = fake_council

    with patch("core.llm_council.CouncilFactory", return_value=fake_factory):
        reasoning, confidence = engine._maybe_council_consensus(
            finding=finding, fix_type=FixType.CODE_PATCH, severity="critical",
        )

    assert fake_council.convene.called, "council.convene must be invoked for critical"
    call_kwargs = fake_council.convene.call_args.kwargs
    assert call_kwargs.get("org_id") == "default"
    assert call_kwargs.get("finding") == finding
    assert "fix_type" in call_kwargs.get("context", {})
    assert "Council says" in reasoning
    assert confidence == pytest.approx(0.92)


def test_high_uses_council_when_flag_set(engine):
    """High severity + flag set -> council convened."""
    os.environ["FIXOPS_USE_COUNCIL"] = "1"
    finding = _make_finding(severity="high", id="find-high-1")

    fake_council = MagicMock()
    fake_council.convene.return_value = _verdict(confidence=0.81)
    fake_factory = MagicMock()
    fake_factory.create_security_council.return_value = fake_council

    with patch("core.llm_council.CouncilFactory", return_value=fake_factory):
        reasoning, confidence = engine._maybe_council_consensus(
            finding=finding, fix_type=FixType.CODE_PATCH, severity="high",
        )

    assert fake_council.convene.called
    assert reasoning != ""
    assert confidence == pytest.approx(0.81)


def test_medium_skips_council(engine):
    """Medium severity -> council never invoked, even with flag set."""
    os.environ["FIXOPS_USE_COUNCIL"] = "1"
    finding = _make_finding(severity="medium", id="find-med-1")

    fake_council = MagicMock()
    fake_factory = MagicMock()
    fake_factory.create_security_council.return_value = fake_council

    with patch("core.llm_council.CouncilFactory", return_value=fake_factory):
        reasoning, confidence = engine._maybe_council_consensus(
            finding=finding, fix_type=FixType.CODE_PATCH, severity="medium",
        )

    assert not fake_council.convene.called, "council must NOT be invoked for medium"
    assert not fake_factory.create_security_council.called
    assert reasoning == ""
    assert confidence == 0.0


def test_council_failure_falls_back_to_single_llm(engine):
    """Council convene() raising must NOT block — returns ('', 0.0)."""
    os.environ["FIXOPS_USE_COUNCIL"] = "1"
    finding = _make_finding(severity="critical", id="find-fail-1")

    fake_council = MagicMock()
    fake_council.convene.side_effect = RuntimeError("council blew up")
    fake_factory = MagicMock()
    fake_factory.create_security_council.return_value = fake_council

    with patch("core.llm_council.CouncilFactory", return_value=fake_factory):
        reasoning, confidence = engine._maybe_council_consensus(
            finding=finding, fix_type=FixType.CODE_PATCH, severity="critical",
        )

    assert reasoning == ""
    assert confidence == 0.0
    # Most importantly: no exception propagated.


def test_council_confidence_boosts_fix_confidence(engine):
    """End-to-end: council confidence=0.95 -> FixSuggestion.confidence_score >= 0.95."""
    os.environ["FIXOPS_USE_COUNCIL"] = "1"
    finding = _make_finding(severity="critical", id="find-boost-1")

    fake_council = MagicMock()
    fake_council.convene.return_value = _verdict(confidence=0.95)
    fake_factory = MagicMock()
    fake_factory.create_security_council.return_value = fake_council

    # Force lower baseline LLM-derived confidence so we can prove the boost.
    with patch("core.llm_council.CouncilFactory", return_value=fake_factory), \
         patch.object(engine, "_compute_confidence", return_value=0.40):
        # Stub fix-type generators so we don't need real LLMs.
        async def _fake_code_patch(suggestion, finding_, src, repo_ctx, graph_ctx):
            suggestion.title = "stub fix"
            suggestion.description = "stub"
            return suggestion

        with patch.object(engine, "_generate_code_patch", side_effect=_fake_code_patch):
            suggestion = asyncio.run(engine.generate_fix(finding))

    assert suggestion.confidence_score >= 0.95, (
        f"council confidence (0.95) must boost final score (got {suggestion.confidence_score})"
    )
    assert suggestion.metadata.get("council_confidence") == pytest.approx(0.95)
    assert "Council says" in (suggestion.metadata.get("council_reasoning") or "")
