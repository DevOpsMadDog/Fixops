"""Unit tests for core.decision_policy — V3 Decision Intelligence policy engine.

Tests the DecisionPolicyEngine that evaluates policy rules to override
decision verdicts for critical vulnerability combinations (e.g., internet-facing
SQL injection in authentication services).
"""



class TestPolicyOverride:
    """Test PolicyOverride dataclass."""

    def test_not_triggered_default(self):
        from core.decision_policy import PolicyOverride
        po = PolicyOverride(triggered=False)
        assert po.triggered is False
        assert po.new_verdict is None
        assert po.reason == ""
        assert po.policy_id == ""
        assert po.confidence_boost == 0.0

    def test_triggered_override(self):
        from core.decision_policy import PolicyOverride
        po = PolicyOverride(
            triggered=True,
            new_verdict="block",
            reason="Critical policy violation",
            policy_id="test_policy",
            confidence_boost=0.15,
        )
        assert po.triggered is True
        assert po.new_verdict == "block"
        assert po.reason == "Critical policy violation"
        assert po.policy_id == "test_policy"
        assert po.confidence_boost == 0.15


class TestDecisionPolicyEngineInit:
    """Test DecisionPolicyEngine initialization."""

    def test_default_config(self):
        from core.decision_policy import DecisionPolicyEngine
        engine = DecisionPolicyEngine()
        assert engine.block_internet_facing_sqli is True
        assert engine.block_auth_path_sqli is True
        assert engine.block_critical_internet_facing is True
        assert engine.internet_facing_multiplier == 3.0
        assert engine.auth_path_multiplier == 2.0
        assert engine.critical_service_multiplier == 1.5

    def test_custom_config(self):
        from core.decision_policy import DecisionPolicyEngine
        config = {
            "decision_policy": {
                "block_internet_facing_sqli": False,
                "internet_facing_multiplier": 5.0,
            }
        }
        engine = DecisionPolicyEngine(config=config)
        assert engine.block_internet_facing_sqli is False
        assert engine.internet_facing_multiplier == 5.0

    def test_empty_config(self):
        from core.decision_policy import DecisionPolicyEngine
        engine = DecisionPolicyEngine(config={})
        assert engine.block_internet_facing_sqli is True

    def test_none_config(self):
        from core.decision_policy import DecisionPolicyEngine
        engine = DecisionPolicyEngine(config=None)
        assert engine.block_internet_facing_sqli is True


class TestEvaluateOverrides:
    """Test policy override evaluation."""

    def _engine(self, **kwargs):
        from core.decision_policy import DecisionPolicyEngine
        return DecisionPolicyEngine(config=kwargs.get("config"))

    def test_no_override_for_benign_finding(self):
        engine = self._engine()
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.7,
            severity="low",
            exposures=[],
        )
        assert result.triggered is False

    def test_block_internet_facing_sqli(self):
        engine = self._engine()
        exposures = [{"type": "internet-facing", "traits": []}]
        finding_metadata = {"cwe_ids": ["CWE-89"]}
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.5,
            severity="high",
            exposures=exposures,
            finding_metadata=finding_metadata,
        )
        assert result.triggered is True
        assert result.new_verdict == "block"
        assert result.policy_id == "block_internet_facing_sqli"
        assert result.confidence_boost == 0.15

    def test_block_internet_facing_sqli_via_traits(self):
        engine = self._engine()
        exposures = [{"type": "service", "traits": ["internet-facing"]}]
        finding_metadata = {"type": "sql injection"}
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.6,
            severity="high",
            exposures=exposures,
            finding_metadata=finding_metadata,
        )
        assert result.triggered is True
        assert result.new_verdict == "block"

    def test_no_override_when_already_blocked(self):
        engine = self._engine()
        exposures = [{"type": "internet-facing"}]
        finding_metadata = {"cwe_ids": ["CWE-89"]}
        result = engine.evaluate_overrides(
            base_verdict="block",
            base_confidence=0.9,
            severity="critical",
            exposures=exposures,
            finding_metadata=finding_metadata,
        )
        assert result.triggered is False

    def test_block_auth_path_sqli(self):
        engine = self._engine()
        finding_metadata = {
            "cwe_ids": ["CWE-89"],
            "location": "/auth/login",
        }
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.6,
            severity="high",
            exposures=[],
            finding_metadata=finding_metadata,
        )
        assert result.triggered is True
        assert result.new_verdict == "block"
        assert result.policy_id == "block_auth_path_sqli"

    def test_block_critical_internet_facing(self):
        engine = self._engine()
        exposures = [{"type": "public-endpoint"}]
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.6,
            severity="critical",
            exposures=exposures,
        )
        assert result.triggered is True
        assert result.new_verdict == "block"
        assert result.policy_id == "block_critical_internet_facing"

    def test_escalate_auth_internet_facing_high(self):
        engine = self._engine()
        exposures = [{"type": "internet-facing"}]
        context_summary = {"service_name": "auth-service"}
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.5,
            severity="high",
            exposures=exposures,
            context_summary=context_summary,
        )
        assert result.triggered is True
        assert result.new_verdict == "review"
        assert result.policy_id == "escalate_auth_internet_facing"

    def test_disabled_policy_no_override(self):
        config = {
            "decision_policy": {
                "block_internet_facing_sqli": False,
                "block_auth_path_sqli": False,
                "block_critical_internet_facing": False,
            }
        }
        engine = self._engine(config=config)
        exposures = [{"type": "internet-facing"}]
        finding_metadata = {"cwe_ids": ["CWE-89"]}
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.5,
            severity="critical",
            exposures=exposures,
            finding_metadata=finding_metadata,
        )
        # The escalation policy still fires since auth-path not matched here
        # But main block policies disabled
        assert result.triggered is False

    def test_context_summary_internet_exposure(self):
        engine = self._engine()
        context_summary = {"exposure": "internet-facing"}
        finding_metadata = {"cwe_ids": ["CWE-89"]}
        result = engine.evaluate_overrides(
            base_verdict="allow",
            base_confidence=0.5,
            severity="high",
            exposures=[],
            context_summary=context_summary,
            finding_metadata=finding_metadata,
        )
        assert result.triggered is True

    def test_sql_injection_via_rule_id(self):
        engine = self._engine()
        exposures = [{"type": "internet"}]
        finding_metadata = {"rule_id": "sqli-detection-001"}
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.5,
            severity="high",
            exposures=exposures,
            finding_metadata=finding_metadata,
        )
        assert result.triggered is True

    def test_sql_injection_via_message(self):
        engine = self._engine()
        exposures = [{"type": "internet"}]
        finding_metadata = {"message": "Potential SQL injection vulnerability detected"}
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.5,
            severity="high",
            exposures=exposures,
            finding_metadata=finding_metadata,
        )
        assert result.triggered is True

    def test_cwe_564_detected_as_sqli(self):
        engine = self._engine()
        exposures = [{"type": "internet"}]
        finding_metadata = {"cwe_ids": ["CWE-564"]}
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.5,
            severity="high",
            exposures=exposures,
            finding_metadata=finding_metadata,
        )
        assert result.triggered is True

    def test_auth_via_password_keyword(self):
        engine = self._engine()
        finding_metadata = {
            "cwe_ids": ["CWE-89"],
            "file": "services/password_reset.py",
        }
        result = engine.evaluate_overrides(
            base_verdict="review",
            base_confidence=0.5,
            severity="high",
            exposures=[],
            finding_metadata=finding_metadata,
        )
        assert result.triggered is True
        assert result.policy_id == "block_auth_path_sqli"


class TestExposureMultiplier:
    """Test exposure multiplier calculation."""

    def _engine(self):
        from core.decision_policy import DecisionPolicyEngine
        return DecisionPolicyEngine()

    def test_no_exposure_multiplier_1(self):
        engine = self._engine()
        multiplier = engine.calculate_exposure_multiplier(exposures=[])
        assert multiplier == 1.0

    def test_internet_facing_multiplier(self):
        engine = self._engine()
        exposures = [{"type": "internet-facing"}]
        multiplier = engine.calculate_exposure_multiplier(exposures=exposures)
        assert multiplier == 3.0

    def test_auth_path_multiplier(self):
        engine = self._engine()
        finding_metadata = {"location": "/auth/login"}
        multiplier = engine.calculate_exposure_multiplier(
            exposures=[], finding_metadata=finding_metadata
        )
        assert multiplier == 2.0

    def test_combined_multipliers(self):
        engine = self._engine()
        exposures = [{"type": "internet-facing"}]
        context_summary = {"business_impact": "critical"}
        finding_metadata = {"location": "/auth/api"}
        multiplier = engine.calculate_exposure_multiplier(
            exposures=exposures,
            context_summary=context_summary,
            finding_metadata=finding_metadata,
        )
        # internet (3.0) * auth (2.0) * critical (1.5) = 9.0
        assert multiplier == 9.0

    def test_critical_service_multiplier(self):
        engine = self._engine()
        context_summary = {"service": {"criticality": "critical"}}
        multiplier = engine.calculate_exposure_multiplier(
            exposures=[], context_summary=context_summary
        )
        assert multiplier == 1.5

    def test_non_mapping_exposure_ignored(self):
        engine = self._engine()
        exposures = ["not-a-dict", 42, None]
        multiplier = engine.calculate_exposure_multiplier(exposures=exposures)
        assert multiplier == 1.0


class TestPrivateHelpers:
    """Test private helper methods."""

    def _engine(self):
        from core.decision_policy import DecisionPolicyEngine
        return DecisionPolicyEngine()

    def test_is_sql_injection_none_metadata(self):
        engine = self._engine()
        assert engine._is_sql_injection(None) is False

    def test_is_sql_injection_empty_metadata(self):
        engine = self._engine()
        assert engine._is_sql_injection({}) is False

    def test_is_critical_service_none(self):
        engine = self._engine()
        assert engine._is_critical_service(None) is False

    def test_is_critical_service_high_impact(self):
        engine = self._engine()
        assert engine._is_critical_service({"business_impact": "high"}) is True

    def test_is_auth_path_via_context_service_type(self):
        engine = self._engine()
        context = {"service_type": "authentication"}
        assert engine._is_auth_path(context_summary=context) is True

    def test_is_auth_path_none_metadata(self):
        engine = self._engine()
        assert engine._is_auth_path(None, None) is False

    def test_is_internet_facing_via_service_exposure(self):
        engine = self._engine()
        context = {"service": {"exposure": "public"}}
        assert engine._is_internet_facing([], context) is True
