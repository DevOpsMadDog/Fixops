"""
Unit tests for suite-api/apps/api/pipeline.py

Tests the pipeline orchestrator including:
- evaluate_compliance: control mapping, status resolution, coverage computation
- PipelineOrchestrator static methods: severity ordering, SARIF level mapping
- PipelineOrchestrator._normalise_sarif_severity
- PipelineOrchestrator._severity_index
- PipelineOrchestrator._normalise_cve_severity
- PipelineOrchestrator._determine_highest_severity
- PipelineOrchestrator._evaluate_guardrails
- PipelineOrchestrator._compute_risk_profile_heuristic
- PipelineOrchestrator._derive_marketplace_recommendations
- Module-level constants: _SEVERITY_ORDER, _SEVERITY_INDEX_MAP, etc.
"""

import os
from collections import Counter
from types import SimpleNamespace
from unittest.mock import MagicMock


os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.pipeline import (
    PipelineOrchestrator,
    _CNAPP_SEVERITY_MAP,
    _CVE_SEVERITY_MAP,
    _SARIF_LEVEL_MAP,
    _SEVERITY_INDEX_MAP,
    _SEVERITY_ORDER,
    evaluate_compliance,
)


# ===========================================================================
# Module constant tests
# ===========================================================================


class TestModuleConstants:
    def test_severity_order(self):
        assert _SEVERITY_ORDER == ("low", "medium", "high", "critical")

    def test_severity_index_map(self):
        assert _SEVERITY_INDEX_MAP["low"] == 0
        assert _SEVERITY_INDEX_MAP["medium"] == 1
        assert _SEVERITY_INDEX_MAP["high"] == 2
        assert _SEVERITY_INDEX_MAP["critical"] == 3

    def test_sarif_level_map(self):
        assert _SARIF_LEVEL_MAP[None] == "low"
        assert _SARIF_LEVEL_MAP[""] == "low"
        assert _SARIF_LEVEL_MAP["none"] == "low"
        assert _SARIF_LEVEL_MAP["note"] == "low"
        assert _SARIF_LEVEL_MAP["info"] == "low"
        assert _SARIF_LEVEL_MAP["warning"] == "medium"
        assert _SARIF_LEVEL_MAP["error"] == "high"

    def test_cve_severity_map(self):
        assert _CVE_SEVERITY_MAP["critical"] == "critical"
        assert _CVE_SEVERITY_MAP["high"] == "high"
        assert _CVE_SEVERITY_MAP["medium"] == "medium"
        assert _CVE_SEVERITY_MAP["moderate"] == "medium"
        assert _CVE_SEVERITY_MAP["low"] == "low"

    def test_cnapp_severity_map(self):
        assert _CNAPP_SEVERITY_MAP["critical"] == "critical"
        assert _CNAPP_SEVERITY_MAP["high"] == "high"
        assert _CNAPP_SEVERITY_MAP["info"] == "low"


# ===========================================================================
# evaluate_compliance tests
# ===========================================================================


class TestEvaluateCompliance:
    def test_empty_mapping(self):
        result = evaluate_compliance(None, None, None)
        assert result == []

    def test_with_overlay_mapping(self):
        """When overlay is a Mapping (dict), compliance.control_map is extracted."""
        overlay = {
            "compliance": {
                "control_map": {
                    "CTRL-1": ["guardrails.check_a"],
                }
            }
        }
        guardrails = {"check_a": "pass"}
        result = evaluate_compliance(guardrails, None, overlay)
        assert len(result) == 1
        assert result[0]["control_id"] == "CTRL-1"
        assert result[0]["passed"] == 1
        assert result[0]["coverage"] == 1.0

    def test_with_dict_overlay(self):
        overlay = {
            "compliance": {
                "control_map": {
                    "CTRL-1": ["guardrails.check_a"],
                    "CTRL-2": ["policy.check_b"],
                }
            }
        }
        guardrails = {"check_a": "pass"}
        policies = {"check_b": "fail"}
        result = evaluate_compliance(guardrails, policies, overlay)
        assert len(result) == 2
        ctrl1 = next(r for r in result if r["control_id"] == "CTRL-1")
        ctrl2 = next(r for r in result if r["control_id"] == "CTRL-2")
        assert ctrl1["passed"] == 1
        assert ctrl2["failed"] == 1

    def test_status_passed_values(self):
        overlay = {
            "compliance": {
                "control_map": {
                    "CTRL-1": [
                        "guardrails.a",
                        "guardrails.b",
                        "guardrails.c",
                    ],
                }
            }
        }
        guardrails = {
            "a": "satisfied",
            "b": "completed",
            "c": "ok",
        }
        result = evaluate_compliance(guardrails, None, overlay)
        assert result[0]["passed"] == 3

    def test_status_failed_values(self):
        overlay = {
            "compliance": {
                "control_map": {
                    "CTRL-1": ["guardrails.a", "guardrails.b"],
                }
            }
        }
        guardrails = {"a": "fail", "b": "gap"}
        result = evaluate_compliance(guardrails, None, overlay)
        assert result[0]["failed"] == 2

    def test_boolean_status(self):
        overlay = {
            "compliance": {
                "control_map": {
                    "CTRL-1": ["guardrails.a", "guardrails.b"],
                }
            }
        }
        guardrails = {"a": True, "b": False}
        result = evaluate_compliance(guardrails, None, overlay)
        assert result[0]["passed"] == 1
        assert result[0]["failed"] == 1

    def test_nested_path_resolution(self):
        overlay = {
            "compliance": {
                "control_map": {
                    "CTRL-1": ["guardrails.top.nested"],
                }
            }
        }
        guardrails = {"top": {"nested": "pass"}}
        result = evaluate_compliance(guardrails, None, overlay)
        assert result[0]["passed"] == 1

    def test_prefixed_rules(self):
        overlay = {
            "compliance": {
                "control_map": {
                    "CTRL-1": ["policies:check_a"],
                }
            }
        }
        policies = {"check_a": "pass"}
        result = evaluate_compliance(None, policies, overlay)
        assert result[0]["passed"] == 1

    def test_non_mapping_overlay(self):
        result = evaluate_compliance(None, None, "not-a-mapping")
        assert result == []


# ===========================================================================
# PipelineOrchestrator static method tests
# ===========================================================================


class TestPipelineOrchestratorStatic:
    def test_determine_highest_severity(self):
        counts = {"low": 5, "medium": 3, "high": 1}
        assert PipelineOrchestrator._determine_highest_severity(counts) == "high"

    def test_determine_highest_severity_critical(self):
        counts = {"low": 5, "critical": 1}
        assert PipelineOrchestrator._determine_highest_severity(counts) == "critical"

    def test_determine_highest_severity_empty(self):
        assert PipelineOrchestrator._determine_highest_severity({}) == "low"

    def test_determine_highest_severity_only_low(self):
        assert PipelineOrchestrator._determine_highest_severity({"low": 10}) == "low"

    def test_normalise_sarif_severity_error(self):
        assert PipelineOrchestrator._normalise_sarif_severity("error") == "high"

    def test_normalise_sarif_severity_warning(self):
        assert PipelineOrchestrator._normalise_sarif_severity("warning") == "medium"

    def test_normalise_sarif_severity_note(self):
        assert PipelineOrchestrator._normalise_sarif_severity("note") == "low"

    def test_normalise_sarif_severity_none(self):
        assert PipelineOrchestrator._normalise_sarif_severity(None) == "low"

    def test_normalise_sarif_severity_unknown(self):
        assert PipelineOrchestrator._normalise_sarif_severity("unknown") == "medium"

    def test_severity_index(self):
        assert PipelineOrchestrator._severity_index("low") == 0
        assert PipelineOrchestrator._severity_index("medium") == 1
        assert PipelineOrchestrator._severity_index("high") == 2
        assert PipelineOrchestrator._severity_index("critical") == 3

    def test_severity_index_unknown_defaults_to_medium(self):
        assert PipelineOrchestrator._severity_index("unknown") == 1


class TestNormaliseCVESeverity:
    def test_with_severity_field(self):
        from apps.api.normalizers import CVERecordSummary

        record = CVERecordSummary(
            cve_id="CVE-1", title="T", severity="high", exploited=False, raw={}
        )
        assert PipelineOrchestrator._normalise_cve_severity(record) == "high"

    def test_with_cvssV3Severity(self):
        from apps.api.normalizers import CVERecordSummary

        record = CVERecordSummary(
            cve_id="CVE-1", title="T", severity=None, exploited=False,
            raw={"cvssV3Severity": "critical"},
        )
        assert PipelineOrchestrator._normalise_cve_severity(record) == "critical"

    def test_with_impact_metric(self):
        from apps.api.normalizers import CVERecordSummary

        record = CVERecordSummary(
            cve_id="CVE-1", title="T", severity=None, exploited=False,
            raw={"impact": {"baseMetricV3": {"baseSeverity": "LOW"}}},
        )
        assert PipelineOrchestrator._normalise_cve_severity(record) == "low"

    def test_fallback_to_medium(self):
        from apps.api.normalizers import CVERecordSummary

        record = CVERecordSummary(
            cve_id="CVE-1", title="T", severity=None, exploited=False, raw={},
        )
        assert PipelineOrchestrator._normalise_cve_severity(record) == "medium"


# ===========================================================================
# PipelineOrchestrator._evaluate_guardrails tests
# ===========================================================================


class TestEvaluateGuardrails:
    def _make_orchestrator(self):
        return PipelineOrchestrator()

    def _make_overlay(self, fail_on="high", warn_on="medium", maturity="L1"):
        overlay = MagicMock()
        overlay.guardrail_policy = {
            "fail_on": fail_on,
            "warn_on": warn_on,
            "maturity": maturity,
        }
        return overlay

    def test_pass_below_warn(self):
        orch = self._make_orchestrator()
        overlay = self._make_overlay(fail_on="critical", warn_on="high")
        result = orch._evaluate_guardrails(
            overlay, Counter({"low": 10}), "low", None
        )
        assert result["status"] == "pass"

    def test_warn_at_warn_threshold(self):
        orch = self._make_orchestrator()
        overlay = self._make_overlay(fail_on="critical", warn_on="high")
        result = orch._evaluate_guardrails(
            overlay, Counter({"high": 3}), "high", None
        )
        assert result["status"] == "warn"

    def test_fail_at_fail_threshold(self):
        orch = self._make_orchestrator()
        overlay = self._make_overlay(fail_on="high", warn_on="medium")
        result = orch._evaluate_guardrails(
            overlay, Counter({"critical": 1}), "critical", None
        )
        assert result["status"] == "fail"

    def test_fail_exactly_at_fail_on(self):
        orch = self._make_orchestrator()
        overlay = self._make_overlay(fail_on="high", warn_on="low")
        result = orch._evaluate_guardrails(
            overlay, Counter({"high": 5}), "high", None
        )
        assert result["status"] == "fail"

    def test_trigger_included(self):
        orch = self._make_orchestrator()
        overlay = self._make_overlay()
        trigger = {"source": "sarif", "rule_id": "R1"}
        result = orch._evaluate_guardrails(
            overlay, Counter({"high": 1}), "high", trigger
        )
        assert result["trigger"] == trigger

    def test_result_structure(self):
        orch = self._make_orchestrator()
        overlay = self._make_overlay()
        result = orch._evaluate_guardrails(
            overlay, Counter({"medium": 5}), "medium", None
        )
        assert "maturity" in result
        assert "policy" in result
        assert "highest_detected" in result
        assert "severity_counts" in result
        assert "rationale" in result


# ===========================================================================
# PipelineOrchestrator._compute_risk_profile_heuristic tests
# ===========================================================================


class TestComputeRiskProfileHeuristic:
    def _make_orchestrator(self):
        return PipelineOrchestrator()

    def test_no_data_returns_none(self):
        orch = self._make_orchestrator()
        result = orch._compute_risk_profile(None, None, [], [])
        assert result is None

    def test_basic_epss_scoring(self):
        orch = self._make_orchestrator()
        exploit_summary = {
            "signals": {
                "epss_probability": {
                    "matches": [{"value": 0.85}]
                }
            }
        }
        result = orch._compute_risk_profile_heuristic(None, exploit_summary, [], [])
        assert result["score"] > 0.0
        assert result["method"] == "epss"
        assert result["model_used"] == "heuristic"

    def test_kev_boosts_score(self):
        orch = self._make_orchestrator()
        exploit_summary = {
            "signals": {
                "kev_exploited": {
                    "matches": [{"value": True}]
                }
            }
        }
        result = orch._compute_risk_profile_heuristic(None, exploit_summary, [], [])
        assert result["score"] >= 0.90
        assert "kev" in result["method"]

    def test_epss_normalization(self):
        """EPSS scores > 1.0 are treated as percentages and divided by 100."""
        orch = self._make_orchestrator()
        exploit_summary = {
            "signals": {
                "epss_probability": {
                    "matches": [{"value": 85.0}]  # 85% -> 0.85
                }
            }
        }
        result = orch._compute_risk_profile_heuristic(None, exploit_summary, [], [])
        assert result["components"]["epss"] <= 1.0

    def test_bayesian_priors(self):
        orch = self._make_orchestrator()
        processing_result = SimpleNamespace(
            bayesian_priors={"risk": 0.7},
            markov_projection=None,
        )
        result = orch._compute_risk_profile_heuristic(processing_result, None, [], [])
        assert result["components"]["bayesian_used"] is True
        assert "bayesian" in result["method"]

    def test_markov_projection(self):
        orch = self._make_orchestrator()
        processing_result = SimpleNamespace(
            bayesian_priors=None,
            markov_projection={
                "next_states": [{"severity": "critical", "probability": 0.8}]
            },
        )
        result = orch._compute_risk_profile_heuristic(processing_result, None, [], [])
        assert result["components"]["markov_used"] is True
        assert "markov" in result["method"]

    def test_score_clamped_to_0_1(self):
        orch = self._make_orchestrator()
        exploit_summary = {
            "signals": {
                "kev_exploited": {"matches": [{"value": True}]},
                "epss_probability": {"matches": [{"value": 0.99}]},
            }
        }
        processing_result = SimpleNamespace(
            bayesian_priors={"risk": 0.99},
            markov_projection={"next_states": [{"severity": "critical"}]},
        )
        result = orch._compute_risk_profile_heuristic(
            processing_result, exploit_summary, [], []
        )
        assert 0.0 <= result["score"] <= 1.0

    def test_exposure_not_applied(self):
        orch = self._make_orchestrator()
        result = orch._compute_risk_profile_heuristic(None, {"signals": {}}, [], [])
        assert result["exposure_applied"] is False

    def test_empty_signals(self):
        orch = self._make_orchestrator()
        result = orch._compute_risk_profile_heuristic(None, {"signals": {}}, [], [])
        assert result["score"] == round(0.02, 4)  # baseline prior
        assert result["method"] == "epss"


# ===========================================================================
# PipelineOrchestrator._derive_marketplace_recommendations tests
# ===========================================================================


class TestDeriveMarketplaceRecommendations:
    def _make_orchestrator(self):
        return PipelineOrchestrator()

    def test_no_input_returns_empty(self):
        orch = self._make_orchestrator()
        result = orch._derive_marketplace_recommendations(None, None, None)
        assert result == []

    def test_compliance_gap(self):
        orch = self._make_orchestrator()
        compliance = {"gaps": ["SOC2-CC6.1"]}
        result = orch._derive_marketplace_recommendations(compliance, None, None)
        assert len(result) == 1
        assert "SOC2-CC6.1" in result[0]["match"]

    def test_guardrail_fail(self):
        orch = self._make_orchestrator()
        guardrail = {"status": "fail", "highest_detected": "critical"}
        result = orch._derive_marketplace_recommendations(None, guardrail, None)
        assert len(result) == 1
        assert "guardrail:fail" in result[0]["match"]
        assert "guardrail:critical" in result[0]["match"]

    def test_guardrail_warn(self):
        orch = self._make_orchestrator()
        guardrail = {"status": "warn", "highest_detected": "high"}
        result = orch._derive_marketplace_recommendations(None, guardrail, None)
        assert len(result) == 1

    def test_guardrail_pass_returns_empty(self):
        orch = self._make_orchestrator()
        guardrail = {"status": "pass"}
        result = orch._derive_marketplace_recommendations(None, guardrail, None)
        assert result == []

    def test_policy_failed_actions(self):
        orch = self._make_orchestrator()
        policy = {
            "execution": {
                "results": [
                    {"id": "rule-1", "status": "failed"},
                    {"id": "rule-2", "status": "passed"},
                ]
            }
        }
        result = orch._derive_marketplace_recommendations(None, None, policy)
        assert len(result) == 1
        assert "policy:rule-1" in result[0]["match"]

    def test_compliance_framework_controls(self):
        orch = self._make_orchestrator()
        compliance = {
            "frameworks": [{
                "name": "SOC2",
                "controls": [
                    {"id": "CC6.1", "status": "gap"},
                    {"id": "CC7.1", "status": "satisfied"},
                ],
            }]
        }
        result = orch._derive_marketplace_recommendations(compliance, None, None)
        assert len(result) == 1
        assert "SOC2:CC6.1" in result[0]["match"]


# ===========================================================================
# PipelineOrchestrator initialization tests
# ===========================================================================


class TestPipelineOrchestratorInit:
    def test_initialization(self):
        orch = PipelineOrchestrator()
        assert orch._vector_matcher is None
        assert orch._vector_signature is None
        assert orch._dedup_service is None

    def test_ensure_dedup_service(self):
        orch = PipelineOrchestrator()
        service = orch._ensure_dedup_service()
        assert service is not None
        # Second call returns same instance
        assert orch._ensure_dedup_service() is service
