"""Tests for core.decision_policy — policy-based verdict overrides."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.decision_policy import DecisionPolicyEngine, PolicyOverride


# ── PolicyOverride ───────────────────────────────────────────────────

class TestPolicyOverride:
    def test_not_triggered(self):
        po = PolicyOverride(triggered=False)
        assert po.triggered is False
        assert po.new_verdict is None
        assert po.reason == ""
        assert po.policy_id == ""
        assert po.confidence_boost == 0.0

    def test_triggered(self):
        po = PolicyOverride(
            triggered=True,
            new_verdict="block",
            reason="Critical vuln",
            policy_id="test_policy",
            confidence_boost=0.15,
        )
        assert po.triggered is True
        assert po.new_verdict == "block"
        assert po.policy_id == "test_policy"


# ── DecisionPolicyEngine ────────────────────────────────────────────

class TestDecisionPolicyEngine:
    @pytest.fixture
    def engine(self):
        return DecisionPolicyEngine()

    @pytest.fixture
    def custom_engine(self):
        return DecisionPolicyEngine(
            config={
                "decision_policy": {
                    "block_internet_facing_sqli": True,
                    "block_auth_path_sqli": True,
                    "block_critical_internet_facing": True,
                    "internet_facing_multiplier": 4.0,
                    "auth_path_multiplier": 3.0,
                    "critical_service_multiplier": 2.0,
                }
            }
        )

    # --- Init ---
    def test_defaults(self, engine):
        assert engine.block_internet_facing_sqli is True
        assert engine.block_auth_path_sqli is True
        assert engine.block_critical_internet_facing is True
        assert engine.internet_facing_multiplier == 3.0
        assert engine.auth_path_multiplier == 2.0
        assert engine.critical_service_multiplier == 1.5

    def test_custom_config(self, custom_engine):
        assert custom_engine.internet_facing_multiplier == 4.0
        assert custom_engine.auth_path_multiplier == 3.0
        assert custom_engine.critical_service_multiplier == 2.0

    def test_none_config(self):
        engine = DecisionPolicyEngine(config=None)
        assert engine.block_internet_facing_sqli is True

    # --- evaluate_overrides: internet-facing SQLi ---
    def test_block_internet_facing_sqli(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.5,
            severity="high",
            exposures=[{"type": "internet_facing"}],
            finding_metadata={"cwe_ids": ["CWE-89"]},
        )
        assert result.triggered is True
        assert result.new_verdict == "block"
        assert result.policy_id == "block_internet_facing_sqli"

    def test_block_internet_facing_sqli_cwe(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.6,
            severity="high",
            exposures=[{"type": "public"}],
            finding_metadata={"cwe_ids": ["CWE-89"]},
        )
        assert result.triggered is True
        assert result.new_verdict == "block"

    def test_no_block_if_already_blocked(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="block",
            base_confidence=0.9,
            severity="critical",
            exposures=[{"type": "internet_facing"}],
            finding_metadata={"type": "sql_injection"},
        )
        # Should not re-trigger if already blocked
        assert result.triggered is False or result.new_verdict == "block"

    # --- evaluate_overrides: auth path SQLi ---
    def test_block_auth_path_sqli(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.5,
            severity="high",
            exposures=[],
            context_summary={"service_name": "auth-service"},
            finding_metadata={"cwe_ids": ["CWE-89"]},
        )
        assert result.triggered is True
        assert result.new_verdict == "block"
        assert result.policy_id == "block_auth_path_sqli"

    def test_block_auth_path_sqli_by_file(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.5,
            severity="medium",
            exposures=[],
            finding_metadata={"file": "src/auth/login.py", "type": "sqli"},
        )
        assert result.triggered is True

    # --- evaluate_overrides: critical internet-facing ---
    def test_block_critical_internet_facing(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.7,
            severity="critical",
            exposures=[{"traits": ["internet-accessible"]}],
        )
        assert result.triggered is True
        assert result.new_verdict == "block"
        assert result.policy_id == "block_critical_internet_facing"

    # --- evaluate_overrides: auth internet-facing escalation ---
    def test_escalate_auth_internet_facing(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.5,
            severity="high",
            exposures=[{"type": "public_endpoint"}],
            context_summary={"service_name": "login-service"},
        )
        assert result.triggered is True
        assert result.new_verdict in ("block", "review")

    # --- evaluate_overrides: no trigger ---
    def test_no_trigger_internal(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.5,
            severity="low",
            exposures=[],
        )
        assert result.triggered is False

    def test_no_trigger_medium_no_sqli(self, engine):
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.5,
            severity="medium",
            exposures=[{"type": "internal"}],
            finding_metadata={"type": "xss"},
        )
        assert result.triggered is False

    # --- calculate_exposure_multiplier ---
    def test_multiplier_no_exposure(self, engine):
        mult = engine.calculate_exposure_multiplier(
            exposures=[], context_summary=None
        )
        assert mult == 1.0

    def test_multiplier_internet_facing(self, engine):
        mult = engine.calculate_exposure_multiplier(
            exposures=[{"type": "internet_facing"}]
        )
        assert mult == 3.0

    def test_multiplier_auth_path(self, engine):
        mult = engine.calculate_exposure_multiplier(
            exposures=[],
            finding_metadata={"file": "auth/handler.py"},
        )
        assert mult == 2.0

    def test_multiplier_critical_service(self, engine):
        mult = engine.calculate_exposure_multiplier(
            exposures=[],
            context_summary={"business_impact": "critical"},
        )
        assert mult == 1.5

    def test_multiplier_stacked(self, engine):
        mult = engine.calculate_exposure_multiplier(
            exposures=[{"type": "public"}],
            context_summary={"business_impact": "critical"},
            finding_metadata={"file": "auth/login.py"},
        )
        assert mult == 3.0 * 2.0 * 1.5  # All three multiplied

    # --- internal helpers ---
    def test_is_internet_facing_via_context(self, engine):
        assert engine._is_internet_facing([], {"exposure": "internet-facing"}) is True

    def test_is_internet_facing_via_service(self, engine):
        ctx = {"service": {"exposure": "public"}}
        assert engine._is_internet_facing([], ctx) is True

    def test_is_internet_facing_false(self, engine):
        assert engine._is_internet_facing([], {}) is False

    def test_is_auth_path_via_metadata_location(self, engine):
        assert engine._is_auth_path(
            finding_metadata={"location": "/api/auth/login"}
        ) is True

    def test_is_auth_path_via_context_service(self, engine):
        assert engine._is_auth_path(
            context_summary={"service": "credential-manager"}
        ) is True

    def test_is_auth_path_false(self, engine):
        assert engine._is_auth_path(
            context_summary={"service_name": "orders"},
            finding_metadata={"file": "orders/handler.py"},
        ) is False

    def test_is_sql_injection_by_type(self, engine):
        assert engine._is_sql_injection({"type": "SQL Injection"}) is True
        assert engine._is_sql_injection({"type": "sqli"}) is True

    def test_is_sql_injection_by_cwe(self, engine):
        assert engine._is_sql_injection({"cwe_ids": ["CWE-89"]}) is True
        assert engine._is_sql_injection({"cwe_ids": ["CWE-564"]}) is True

    def test_is_sql_injection_false(self, engine):
        assert engine._is_sql_injection({"type": "xss"}) is False

    def test_is_sql_injection_none(self, engine):
        assert engine._is_sql_injection(None) is False

    def test_is_critical_service_by_impact(self, engine):
        assert engine._is_critical_service({"business_impact": "critical"}) is True

    def test_is_critical_service_by_nested(self, engine):
        assert engine._is_critical_service(
            {"service": {"criticality": "high"}}
        ) is True

    def test_is_critical_service_false(self, engine):
        assert engine._is_critical_service({"business_impact": "low"}) is False
        assert engine._is_critical_service(None) is False
