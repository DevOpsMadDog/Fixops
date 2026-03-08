"""Tests for core.intelligent_security_engine — ISE data models and config."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.intelligent_security_engine import (
    AttackPhase,
    AttackPlan,
    EngineConfig,
    EngineState,
    IntelligenceLevel,
    ThreatIntelligence,
)


# ── Enums ────────────────────────────────────────────────────────────

class TestIntelligenceLevel:
    def test_values(self):
        assert IntelligenceLevel.PASSIVE.value == "passive"
        assert IntelligenceLevel.GUIDED.value == "guided"
        assert IntelligenceLevel.AUTONOMOUS.value == "autonomous"
        assert IntelligenceLevel.ADVERSARIAL.value == "adversarial"

    def test_count(self):
        assert len(IntelligenceLevel) == 4


class TestAttackPhase:
    def test_all_mitre_phases(self):
        phases = [p.value for p in AttackPhase]
        assert "reconnaissance" in phases
        assert "initial_access" in phases
        assert "execution" in phases
        assert "persistence" in phases
        assert "privilege_escalation" in phases
        assert "defense_evasion" in phases
        assert "credential_access" in phases
        assert "discovery" in phases
        assert "lateral_movement" in phases
        assert "collection" in phases
        assert "exfiltration" in phases
        assert "impact" in phases

    def test_count(self):
        assert len(AttackPhase) == 13


class TestEngineState:
    def test_values(self):
        assert EngineState.IDLE.value == "idle"
        assert EngineState.ANALYZING.value == "analyzing"
        assert EngineState.PLANNING.value == "planning"
        assert EngineState.EXECUTING.value == "executing"
        assert EngineState.VALIDATING.value == "validating"
        assert EngineState.REPORTING.value == "reporting"
        assert EngineState.LEARNING.value == "learning"

    def test_count(self):
        assert len(EngineState) == 7


# ── EngineConfig ────────────────────────────────────────────────────

class TestEngineConfig:
    def test_defaults(self):
        config = EngineConfig()
        assert config.intelligence_level == IntelligenceLevel.GUIDED
        assert config.max_attack_depth == 5
        assert config.timeout_seconds == 600.0
        assert config.consensus_threshold == 0.85
        assert config.mindsdb_enabled is True
        assert len(config.llm_providers) == 4
        assert "openai" in config.llm_providers

    def test_custom_config(self):
        config = EngineConfig(
            intelligence_level=IntelligenceLevel.AUTONOMOUS,
            max_attack_depth=10,
            timeout_seconds=300.0,
            consensus_threshold=0.9,
        )
        assert config.intelligence_level == IntelligenceLevel.AUTONOMOUS
        assert config.max_attack_depth == 10
        assert config.timeout_seconds == 300.0
        assert config.consensus_threshold == 0.9

    def test_compliance_frameworks(self):
        config = EngineConfig()
        assert "pci-dss" in config.compliance_frameworks
        assert "soc2" in config.compliance_frameworks
        assert "hipaa" in config.compliance_frameworks

    def test_guardrails(self):
        config = EngineConfig()
        g = config.guardrails
        assert g["max_requests_per_second"] == 10
        assert "data_destruction" in g["blocked_actions"]
        assert g["auto_stop_on_detection"] is True
        assert g["evidence_collection_enabled"] is True

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("ALDECI_INTELLIGENCE_LEVEL", "autonomous")
        monkeypatch.setenv("ALDECI_MAX_DEPTH", "10")
        monkeypatch.setenv("ALDECI_CONSENSUS_THRESHOLD", "0.95")
        monkeypatch.setenv("ALDECI_MINDSDB_ENABLED", "false")
        config = EngineConfig.from_env()
        assert config.intelligence_level == IntelligenceLevel.AUTONOMOUS
        assert config.max_attack_depth == 10
        assert config.consensus_threshold == 0.95
        assert config.mindsdb_enabled is False

    def test_from_env_defaults(self, monkeypatch):
        for key in [
            "ALDECI_INTELLIGENCE_LEVEL",
            "ALDECI_MAX_DEPTH",
            "ALDECI_CONSENSUS_THRESHOLD",
            "ALDECI_MINDSDB_ENABLED",
        ]:
            monkeypatch.delenv(key, raising=False)
        config = EngineConfig.from_env()
        assert config.intelligence_level == IntelligenceLevel.GUIDED
        assert config.max_attack_depth == 5
        assert config.consensus_threshold == 0.85
        assert config.mindsdb_enabled is True


# ── ThreatIntelligence ──────────────────────────────────────────────

class TestThreatIntelligence:
    def test_risk_score_basic(self):
        ti = ThreatIntelligence(
            cve_ids=["CVE-2024-1234"],
            epss_scores={"CVE-2024-1234": 0.6},
            kev_status={"CVE-2024-1234": False},
            mitre_techniques=["T1059"],
            threat_actors=["APT29"],
            exploit_availability={"CVE-2024-1234": "none"},
            iocs=[],
        )
        assert 0 <= ti.risk_score <= 1
        assert ti.risk_score == 0.6

    def test_risk_score_kev_boost(self):
        ti = ThreatIntelligence(
            cve_ids=["CVE-2024-1234"],
            epss_scores={"CVE-2024-1234": 0.5},
            kev_status={"CVE-2024-1234": True},
            mitre_techniques=[],
            threat_actors=[],
            exploit_availability={},
            iocs=[],
        )
        assert ti.risk_score > 0.5  # KEV boosts score

    def test_risk_score_exploit_boost(self):
        ti = ThreatIntelligence(
            cve_ids=["CVE-2024-1234"],
            epss_scores={"CVE-2024-1234": 0.5},
            kev_status={"CVE-2024-1234": False},
            mitre_techniques=[],
            threat_actors=[],
            exploit_availability={"CVE-2024-1234": "public"},
            iocs=[],
        )
        assert ti.risk_score > 0.5  # Public exploit boosts

    def test_risk_score_kev_and_exploit(self):
        ti = ThreatIntelligence(
            cve_ids=["CVE-2024-1234"],
            epss_scores={"CVE-2024-1234": 0.6},
            kev_status={"CVE-2024-1234": True},
            mitre_techniques=[],
            threat_actors=[],
            exploit_availability={"CVE-2024-1234": "public"},
            iocs=[],
        )
        assert ti.risk_score <= 1.0  # Capped at 1.0

    def test_risk_score_no_epss(self):
        ti = ThreatIntelligence(
            cve_ids=[],
            epss_scores={},
            kev_status={},
            mitre_techniques=[],
            threat_actors=[],
            exploit_availability={},
            iocs=[],
        )
        assert ti.risk_score == 0.5  # Default when no EPSS

    def test_risk_score_max_epss(self):
        ti = ThreatIntelligence(
            cve_ids=["CVE-1", "CVE-2"],
            epss_scores={"CVE-1": 0.3, "CVE-2": 0.8},
            kev_status={"CVE-1": False, "CVE-2": False},
            mitre_techniques=[],
            threat_actors=[],
            exploit_availability={},
            iocs=[],
        )
        assert ti.risk_score == 0.8  # Uses max EPSS


# ── AttackPlan ───────────────────────────────────────────────────────

class TestAttackPlan:
    def test_basic(self):
        plan = AttackPlan(
            id="plan-001",
            target="webapp.example.com",
            phases=[{"phase": "recon", "tools": ["nmap"]}],
            estimated_duration=3600.0,
            success_probability=0.7,
            mitre_mapping={"T1059": ["execution"]},
            required_tools=["nmap", "sqlmap"],
            compliance_checks=["pci-dss-6.5.1"],
            llm_consensus={"agree": 3, "disagree": 1},
        )
        assert plan.id == "plan-001"
        assert plan.target == "webapp.example.com"
        assert plan.success_probability == 0.7

    def test_to_dict(self):
        plan = AttackPlan(
            id="plan-002",
            target="api.example.com",
            phases=[],
            estimated_duration=1800.0,
            success_probability=0.5,
            mitre_mapping={},
            required_tools=[],
            compliance_checks=[],
            llm_consensus={},
        )
        d = plan.to_dict()
        assert d["id"] == "plan-002"
        assert d["target"] == "api.example.com"
        assert d["estimated_duration"] == 1800.0
        assert d["success_probability"] == 0.5
