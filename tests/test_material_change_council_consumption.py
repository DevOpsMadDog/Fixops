"""Tests that MaterialChangeDetector._ask_council() correctly consumes the
dict returned by CouncilPipelineAdapter.analyse(), and does NOT fall back to
the hardcoded confidence=0.5 / empty-string-match behaviour that existed
before the getattr-on-dict bug was fixed.

Constraints:
- council_pipeline_adapter.py is NOT touched here.
- Only material_change_detector.py is under test.
- adapter.analyse() is monkeypatched to return known dicts.
"""

from __future__ import annotations

import importlib
import sys
import types
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analyzer():
    """Return a fresh PushEventAnalyzer with no real disk/DB side-effects."""
    # Avoid touching SQLite during tests.
    from core.material_change_detector import PushEventAnalyzer

    analyzer = PushEventAnalyzer.__new__(PushEventAnalyzer)
    analyzer._repo_root = None  # not needed for _ask_council tests
    analyzer._webhook_secret = ""
    return analyzer


def _minimal_result():
    """Return a minimal MaterialChangeResult suitable for passing to _ask_council."""
    from core.material_change_detector import MaterialChangeResult, BlastRadius, BlastRadiusCategory

    r = MaterialChangeResult(
        commit_sha="abc1234",
        repository="org/repo",
        branch="main",
        author="dev",
    )
    r.changed_files = ["src/auth.py"]
    r.blast_radius = BlastRadius(
        category=BlastRadiusCategory.HIGH,
        changed_files=["src/auth.py"],
        critical_files=[],
        high_files=["src/auth.py"],
        medium_files=[],
        low_files=[],
        security_critical_ratio=0.0,
    )
    r.sast_findings = []
    return r


# ---------------------------------------------------------------------------
# Case 1: Real council verdict — decision="block", confidence=0.9
# ---------------------------------------------------------------------------

def test_ask_council_consumes_real_verdict():
    """When adapter returns a real verdict dict, _ask_council must return it
    with the actual decision and confidence — NOT the old 0.5 fallback."""
    analyzer = _make_analyzer()
    result = _minimal_result()

    real_verdict = {
        "analyzed": 3,
        "decision": "block",
        "method": "council_verdict",
        "confidence": 0.9,
        "reasoning": "High-severity auth bypass found; block is warranted.",
        "consensus_pct": 1.0,
        "providers_responded": 3,
        "escalated": False,
        "cost_usd": 0.002,
        "session_id": "test-sess-001",
        "mitre_techniques": [],
        "compliance_concerns": [],
    }

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = real_verdict

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is not None, "_ask_council returned None for a real verdict"
    # Must use real confidence, not the hardcoded 0.5
    assert verdict["confidence"] == 0.9, (
        f"Expected confidence=0.9 from adapter, got {verdict['confidence']} — "
        "getattr-on-dict bug may still be present"
    )
    # Must map decision="block" → is_material=True
    assert verdict["is_material"] is True, (
        f"Expected is_material=True for decision='block', got {verdict['is_material']}"
    )
    # Reasoning must be the real string, not empty
    assert "auth bypass" in verdict["reasoning"], (
        f"Expected real reasoning text, got: {verdict['reasoning']!r}"
    )


# ---------------------------------------------------------------------------
# Case 2: Real council verdict — decision="remediate", confidence=0.75
# ---------------------------------------------------------------------------

def test_ask_council_remediate_is_material():
    analyzer = _make_analyzer()
    result = _minimal_result()

    real_verdict = {
        "analyzed": 2,
        "decision": "remediate",
        "method": "council_verdict",
        "confidence": 0.75,
        "reasoning": "Medium risk — remediation required within 48h.",
        "consensus_pct": 0.67,
        "providers_responded": 2,
        "escalated": False,
        "cost_usd": 0.001,
        "session_id": "test-sess-002",
        "mitre_techniques": ["T1190"],
        "compliance_concerns": [],
    }

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = real_verdict

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is not None
    assert verdict["is_material"] is True
    assert verdict["confidence"] == 0.75


# ---------------------------------------------------------------------------
# Case 3: Real council verdict — decision="accept", confidence=0.85
# ---------------------------------------------------------------------------

def test_ask_council_accept_is_not_material():
    analyzer = _make_analyzer()
    result = _minimal_result()

    real_verdict = {
        "analyzed": 1,
        "decision": "accept",
        "method": "council_verdict",
        "confidence": 0.85,
        "reasoning": "Low risk cosmetic change; acceptable.",
        "consensus_pct": 1.0,
        "providers_responded": 3,
        "escalated": False,
        "cost_usd": 0.001,
        "session_id": "test-sess-003",
        "mitre_techniques": [],
        "compliance_concerns": [],
    }

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = real_verdict

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is not None
    assert verdict["is_material"] is False
    assert verdict["confidence"] == 0.85


# ---------------------------------------------------------------------------
# Case 4: "skipped" shape (no critical findings) → honest None, no fabrication
# ---------------------------------------------------------------------------

def test_ask_council_skipped_returns_none():
    """When adapter returns analyzed=0 / method='skipped', _ask_council must
    return None so the caller falls back to the deterministic heuristic,
    NOT fabricate a non-material verdict."""
    analyzer = _make_analyzer()
    result = _minimal_result()

    skipped_result = {
        "analyzed": 0,
        "reason": "no critical findings",
        "method": "skipped",
    }

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = skipped_result

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is None, (
        f"Expected None for skipped council result, got {verdict!r} — "
        "was fabricating a materiality verdict when council didn't run"
    )


# ---------------------------------------------------------------------------
# Case 5: "no_api_key" shape → honest None
# ---------------------------------------------------------------------------

def test_ask_council_no_api_key_returns_none():
    analyzer = _make_analyzer()
    result = _minimal_result()

    no_key_result = {
        "analyzed": 0,
        "decision": "no_api_key",
        "method": "no_api_key",
        "confidence": 0.0,
        "reason": "No LLM API keys configured",
        "session_id": "test-sess-nokey",
    }

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = no_key_result

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is None, (
        f"Expected None for no_api_key result, got {verdict!r}"
    )


# ---------------------------------------------------------------------------
# Case 6: "llm_unavailable" shape → honest None
# ---------------------------------------------------------------------------

def test_ask_council_llm_unavailable_returns_none():
    analyzer = _make_analyzer()
    result = _minimal_result()

    unavailable_result = {
        "analyzed": 0,
        "decision": None,
        "method": "llm_unavailable",
        "confidence": 0.0,
        "cost_usd": 0.0,
        "reason": "Council error: TimeoutError",
        "note": "No security verdict produced. Do not treat this as an authoritative decision.",
        "session_id": "test-sess-timeout",
    }

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = unavailable_result

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is None, (
        f"Expected None for llm_unavailable result, got {verdict!r}"
    )


# ---------------------------------------------------------------------------
# Case 7: "council_low_trust" (below quorum) → honest None
# ---------------------------------------------------------------------------

def test_ask_council_low_trust_returns_none():
    analyzer = _make_analyzer()
    result = _minimal_result()

    low_trust_result = {
        "analyzed": 2,
        "decision": None,
        "method": "council_low_trust",
        "confidence": 0.45,
        "providers_responded": 1,
        "cost_usd": 0.001,
        "note": "Quorum not met (1/2 real votes). Verdict withheld.",
        "session_id": "test-sess-lowtrust",
    }

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = low_trust_result

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is None, (
        f"Expected None for council_low_trust result, got {verdict!r}"
    )


# ---------------------------------------------------------------------------
# Case 8: Adapter raises an exception → _ask_council returns None gracefully
# ---------------------------------------------------------------------------

def test_ask_council_exception_returns_none():
    analyzer = _make_analyzer()
    result = _minimal_result()

    fake_adapter = MagicMock()
    fake_adapter.analyse.side_effect = RuntimeError("network timeout")

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is None, (
        f"Expected None when adapter raises, got {verdict!r}"
    )


# ---------------------------------------------------------------------------
# Case 9: Reasoning contains embedded JSON with is_material key (legacy path)
# ---------------------------------------------------------------------------

def test_ask_council_embedded_json_in_reasoning():
    """If the adapter's reasoning text contains a JSON blob with 'is_material',
    the legacy JSON-extraction path should honour it, with real confidence."""
    analyzer = _make_analyzer()
    result = _minimal_result()

    real_verdict = {
        "analyzed": 1,
        "decision": "block",
        "method": "council_verdict",
        "confidence": 0.88,
        "reasoning": 'Analysis complete. {"is_material": true, "confidence": 0.88, "reasoning": "RCE risk"}',
        "providers_responded": 2,
        "escalated": False,
        "cost_usd": 0.001,
        "session_id": "test-sess-emb",
        "mitre_techniques": [],
        "compliance_concerns": [],
    }

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = real_verdict

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is not None
    assert verdict["is_material"] is True
    # Confidence must come from the embedded JSON (0.88) or the adapter dict (0.88) — same here
    assert verdict["confidence"] == 0.88


# ---------------------------------------------------------------------------
# Case 10: Unexpected non-dict return type → None (no crash)
# ---------------------------------------------------------------------------

def test_ask_council_non_dict_return_type_returns_none():
    """If the adapter somehow returns a non-dict (e.g. a string), _ask_council
    must return None rather than crashing."""
    analyzer = _make_analyzer()
    result = _minimal_result()

    fake_adapter = MagicMock()
    fake_adapter.analyse.return_value = "unexpected string response"

    with patch(
        "core.council_pipeline_adapter.create_consensus_engine_replacement",
        return_value=fake_adapter,
    ):
        verdict = analyzer._ask_council(result)

    assert verdict is None, (
        f"Expected None for non-dict adapter return, got {verdict!r}"
    )
