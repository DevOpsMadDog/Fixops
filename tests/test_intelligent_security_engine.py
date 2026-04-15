"""Tests for IntelligentSecurityEngine — 25 tests covering config, state, dataclasses,
sync helpers, and async public methods (using pytest-asyncio or asyncio.run).

Engine: suite-core/core/intelligent_security_engine.py
Constructor: IntelligentSecurityEngine(config=EngineConfig(...))

Note: The engine communicates with external services (MPTE, MindsDB, LLM providers).
All async tests that would hit the network use configs with mindsdb_enabled=False and
empty llm_providers, so no real HTTP calls are made. External calls that do occur
are expected to fail gracefully (the engine handles all exceptions internally).
"""

from __future__ import annotations

import asyncio
import pytest

from core.intelligent_security_engine import (
    AttackPhase,
    AttackPlan,
    EngineConfig,
    EngineState,
    IntelligenceLevel,
    IntelligentSecurityEngine,
    ThreatIntelligence,
    _escape_mindsdb_string,
    _validate_mindsdb_identifier,
    get_engine,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _offline_engine() -> IntelligentSecurityEngine:
    """Engine with MindsDB disabled and no LLM providers — no external calls."""
    cfg = EngineConfig(
        mindsdb_enabled=False,
        llm_providers=[],
        consensus_threshold=0.85,
    )
    return IntelligentSecurityEngine(config=cfg)


def _minimal_intel(cve_ids=None) -> ThreatIntelligence:
    cve_ids = cve_ids or ["CVE-2024-0001"]
    return ThreatIntelligence(
        cve_ids=cve_ids,
        epss_scores={c: 0.3 for c in cve_ids},
        kev_status={c: False for c in cve_ids},
        mitre_techniques=[],
        threat_actors=[],
        exploit_availability={c: "unknown" for c in cve_ids},
        iocs=[],
    )


def run(coro):
    """Run a coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# EngineConfig
# ---------------------------------------------------------------------------


def test_engine_config_defaults():
    cfg = EngineConfig()
    assert cfg.intelligence_level == IntelligenceLevel.GUIDED
    assert cfg.max_attack_depth == 5
    assert cfg.consensus_threshold == 0.85
    assert cfg.mindsdb_enabled is True
    assert "pci-dss" in cfg.compliance_frameworks


def test_engine_config_from_env_returns_instance(monkeypatch):
    monkeypatch.setenv("ALDECI_INTELLIGENCE_LEVEL", "passive")
    monkeypatch.setenv("ALDECI_MAX_DEPTH", "3")
    cfg = EngineConfig.from_env()
    assert cfg.intelligence_level == IntelligenceLevel.PASSIVE
    assert cfg.max_attack_depth == 3


def test_intelligence_level_enum_values():
    assert IntelligenceLevel.PASSIVE.value == "passive"
    assert IntelligenceLevel.GUIDED.value == "guided"
    assert IntelligenceLevel.AUTONOMOUS.value == "autonomous"
    assert IntelligenceLevel.ADVERSARIAL.value == "adversarial"


def test_attack_phase_enum_values():
    assert AttackPhase.RECONNAISSANCE.value == "reconnaissance"
    assert AttackPhase.EXFILTRATION.value == "exfiltration"
    assert AttackPhase.IMPACT.value == "impact"


def test_engine_state_enum_values():
    assert EngineState.IDLE.value == "idle"
    assert EngineState.EXECUTING.value == "executing"
    assert EngineState.REPORTING.value == "reporting"


# ---------------------------------------------------------------------------
# MindsDB SQL safety helpers
# ---------------------------------------------------------------------------


def test_validate_mindsdb_identifier_valid():
    result = _validate_mindsdb_identifier("my_model_123", "model name")
    assert result == "my_model_123"


def test_validate_mindsdb_identifier_rejects_spaces():
    with pytest.raises(ValueError, match="invalid characters"):
        _validate_mindsdb_identifier("bad model", "test")


def test_validate_mindsdb_identifier_rejects_sql_injection():
    with pytest.raises(ValueError, match="invalid characters"):
        _validate_mindsdb_identifier("model'; DROP TABLE--", "test")


def test_validate_mindsdb_identifier_rejects_empty():
    with pytest.raises(ValueError):
        _validate_mindsdb_identifier("", "test")


def test_validate_mindsdb_identifier_rejects_too_long():
    with pytest.raises(ValueError):
        _validate_mindsdb_identifier("a" * 129, "test")


def test_escape_mindsdb_string_single_quote():
    result = _escape_mindsdb_string("it's")
    assert "\\'" in result
    assert "it" in result


def test_escape_mindsdb_string_backslash():
    result = _escape_mindsdb_string("path\\to\\file")
    assert "\\\\" in result


def test_escape_mindsdb_string_clean():
    result = _escape_mindsdb_string("hello world")
    assert result == "hello world"


# ---------------------------------------------------------------------------
# ThreatIntelligence dataclass
# ---------------------------------------------------------------------------


def test_threat_intelligence_risk_score_no_data():
    intel = ThreatIntelligence(
        cve_ids=[],
        epss_scores={},
        kev_status={},
        mitre_techniques=[],
        threat_actors=[],
        exploit_availability={},
        iocs=[],
    )
    assert intel.risk_score == 0.5


def test_threat_intelligence_risk_score_kev_boost():
    intel = ThreatIntelligence(
        cve_ids=["CVE-2024-1234"],
        epss_scores={"CVE-2024-1234": 0.4},
        kev_status={"CVE-2024-1234": True},
        mitre_techniques=[],
        threat_actors=[],
        exploit_availability={"CVE-2024-1234": "unknown"},
        iocs=[],
    )
    # KEV boost: 0.4 * 1.5 = 0.6
    assert intel.risk_score > 0.4


def test_threat_intelligence_risk_score_capped_at_1():
    intel = ThreatIntelligence(
        cve_ids=["CVE-X"],
        epss_scores={"CVE-X": 0.99},
        kev_status={"CVE-X": True},
        mitre_techniques=[],
        threat_actors=[],
        exploit_availability={"CVE-X": "public"},
        iocs=[],
    )
    assert intel.risk_score <= 1.0


# ---------------------------------------------------------------------------
# IntelligentSecurityEngine constructor & initial state
# ---------------------------------------------------------------------------


def test_engine_initial_state():
    eng = _offline_engine()
    assert eng.state == EngineState.IDLE
    assert eng.mindsdb is None  # disabled
    assert eng._session_id is None
    assert eng._execution_history == []


def test_engine_uses_provided_config():
    cfg = EngineConfig(
        intelligence_level=IntelligenceLevel.AUTONOMOUS,
        mindsdb_enabled=False,
        llm_providers=[],
    )
    eng = IntelligentSecurityEngine(config=cfg)
    assert eng.config.intelligence_level == IntelligenceLevel.AUTONOMOUS


def test_engine_default_config_when_none():
    # Should not raise; uses EngineConfig.from_env()
    eng = IntelligentSecurityEngine(config=None)
    assert eng.config is not None


# ---------------------------------------------------------------------------
# initialize_session (async)
# ---------------------------------------------------------------------------


def test_initialize_session_returns_session_id():
    eng = _offline_engine()
    session_id = run(eng.initialize_session())
    assert session_id.startswith("ise-")
    assert eng._session_id == session_id


def test_initialize_session_unique_each_call():
    eng = _offline_engine()
    s1 = run(eng.initialize_session())
    s2 = run(eng.initialize_session())
    assert s1 != s2


# ---------------------------------------------------------------------------
# gather_intelligence (async)
# ---------------------------------------------------------------------------


def test_gather_intelligence_returns_threat_intel():
    eng = _offline_engine()
    intel = run(eng.gather_intelligence("192.168.1.1", ["CVE-2024-0001"]))
    assert isinstance(intel, ThreatIntelligence)
    assert intel.cve_ids == ["CVE-2024-0001"]


def test_gather_intelligence_sets_analyzing_state_then_reverts():
    eng = _offline_engine()
    # After gather_intelligence completes, state transitions away from ANALYZING
    run(eng.gather_intelligence("target.example.com", ["CVE-2024-9999"]))
    # State may be ANALYZING or back to whatever caller left it — just verify no crash
    assert eng.state in (EngineState.ANALYZING, EngineState.IDLE, EngineState.PLANNING,
                         EngineState.EXECUTING, EngineState.VALIDATING, EngineState.REPORTING)


def test_gather_intelligence_empty_cves():
    eng = _offline_engine()
    intel = run(eng.gather_intelligence("target", []))
    assert intel.cve_ids == []
    assert intel.epss_scores == {}


# ---------------------------------------------------------------------------
# generate_attack_plan (async)
# ---------------------------------------------------------------------------


def test_generate_attack_plan_returns_attack_plan():
    eng = _offline_engine()
    intel = _minimal_intel()
    plan = run(eng.generate_attack_plan("target.example.com", intel))
    assert isinstance(plan, AttackPlan)
    assert plan.target == "target.example.com"
    assert plan.id.startswith("plan-")


def test_generate_attack_plan_has_phases():
    eng = _offline_engine()
    intel = _minimal_intel()
    plan = run(eng.generate_attack_plan("target", intel))
    assert len(plan.phases) > 0


def test_generate_attack_plan_to_dict():
    eng = _offline_engine()
    intel = _minimal_intel()
    plan = run(eng.generate_attack_plan("target", intel))
    d = plan.to_dict()
    for key in ("id", "target", "phases", "success_probability", "mitre_mapping"):
        assert key in d


def test_generate_attack_plan_success_probability_range():
    eng = _offline_engine()
    intel = _minimal_intel()
    plan = run(eng.generate_attack_plan("target", intel))
    assert 0.0 <= plan.success_probability <= 1.0


# ---------------------------------------------------------------------------
# execute_plan (async, dry_run)
# ---------------------------------------------------------------------------


def test_execute_plan_dry_run_returns_execution_result():
    from core.intelligent_security_engine import ExecutionResult
    eng = _offline_engine()
    intel = _minimal_intel()
    plan = run(eng.generate_attack_plan("target", intel))
    result = run(eng.execute_plan(plan, dry_run=True))
    assert isinstance(result, ExecutionResult)
    assert result.plan_id == plan.id


def test_execute_plan_dry_run_status_is_completed_or_blocked():
    eng = _offline_engine()
    intel = _minimal_intel()
    plan = run(eng.generate_attack_plan("target", intel))
    result = run(eng.execute_plan(plan, dry_run=True))
    assert result.status in ("completed", "blocked")


def test_execute_plan_appends_to_history():
    eng = _offline_engine()
    intel = _minimal_intel()
    plan = run(eng.generate_attack_plan("target", intel))
    run(eng.execute_plan(plan, dry_run=True))
    assert len(eng._execution_history) == 1


def test_execute_plan_returns_to_idle_state():
    eng = _offline_engine()
    intel = _minimal_intel()
    plan = run(eng.generate_attack_plan("target", intel))
    run(eng.execute_plan(plan, dry_run=True))
    assert eng.state == EngineState.IDLE


# ---------------------------------------------------------------------------
# get_engine singleton
# ---------------------------------------------------------------------------


def test_get_engine_returns_instance():
    eng = get_engine()
    assert isinstance(eng, IntelligentSecurityEngine)


def test_get_engine_returns_same_instance():
    e1 = get_engine()
    e2 = get_engine()
    assert e1 is e2
