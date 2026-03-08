"""Tests for core.feature_matrix — pipeline result aggregation utilities."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.feature_matrix import (
    _as_mapping,
    _as_sequence,
    _to_float,
    _to_int,
    _guardrail_metrics,
    _context_metrics,
    _onboarding_metrics,
    _compliance_metrics,
    _policy_metrics,
    _evidence_metrics,
    _analytics_metrics,
    _exploit_metrics,
)


# ── Helper Functions ────────────────────────────────────────────────

class TestHelpers:
    def test_as_mapping_dict(self):
        assert _as_mapping({"a": 1}) == {"a": 1}

    def test_as_mapping_none(self):
        assert _as_mapping(None) == {}

    def test_as_mapping_string(self):
        assert _as_mapping("not a dict") == {}

    def test_as_mapping_list(self):
        assert _as_mapping([1, 2]) == {}

    def test_as_sequence_list(self):
        assert _as_sequence([1, 2, 3]) == [1, 2, 3]

    def test_as_sequence_none(self):
        assert _as_sequence(None) == []

    def test_as_sequence_string(self):
        assert _as_sequence("hello") == []

    def test_as_sequence_dict(self):
        assert _as_sequence({"a": 1}) == []

    def test_to_int_valid(self):
        assert _to_int(42) == 42
        assert _to_int("10") == 10
        assert _to_int(3.7) == 3

    def test_to_int_invalid(self):
        assert _to_int(None) == 0
        assert _to_int("abc") == 0
        assert _to_int("abc", default=5) == 5

    def test_to_float_valid(self):
        assert _to_float(3.14) == 3.14
        assert _to_float("2.5") == 2.5
        assert _to_float(42) == 42.0

    def test_to_float_invalid(self):
        assert _to_float(None) == 0.0
        assert _to_float("abc") == 0.0
        assert _to_float("abc", default=1.5) == 1.5


# ── Metric Extractors ──────────────────────────────────────────────

class TestGuardrailMetrics:
    def test_empty(self):
        m = _guardrail_metrics({})
        assert m["maturity"] is None
        assert m["highest_detected"] is None
        assert m["severity_counts"] == {}

    def test_with_data(self):
        m = _guardrail_metrics({
            "guardrail_evaluation": {
                "maturity": "advanced",
                "highest_detected": "critical",
                "severity_counts": {"critical": 5, "high": 10},
            }
        })
        assert m["maturity"] == "advanced"
        assert m["highest_detected"] == "critical"
        assert m["severity_counts"]["critical"] == 5


class TestContextMetrics:
    def test_empty(self):
        m = _context_metrics({})
        assert m["components_evaluated"] == 0
        assert m["average_score"] == 0.0

    def test_with_data(self):
        m = _context_metrics({
            "context_summary": {
                "summary": {
                    "components_evaluated": 15,
                    "average_score": 7.5,
                    "highest_component": {
                        "name": "auth-service",
                        "playbook": {"name": "remediate-auth"},
                    },
                }
            }
        })
        assert m["components_evaluated"] == 15
        assert m["average_score"] == 7.5
        assert m["top_component"] == "auth-service"
        assert m["top_playbook"] == "remediate-auth"


class TestOnboardingMetrics:
    def test_empty(self):
        m = _onboarding_metrics({})
        assert m["mode"] is None
        assert m["step_count"] == 0

    def test_with_data(self):
        m = _onboarding_metrics({
            "onboarding": {
                "mode": "full",
                "steps": [{"label": "step1"}, {"label": "step2"}],
                "time_to_value_minutes": 15,
                "integrations": {"jira": True, "slack": True},
            }
        })
        assert m["mode"] == "full"
        assert m["step_count"] == 2
        assert m["time_to_value_minutes"] == 15.0
        assert m["integrations_configured"] == 2


class TestComplianceMetrics:
    def test_empty(self):
        m = _compliance_metrics({})
        assert m["framework_count"] == 0
        assert m["satisfied_frameworks"] == 0
        assert m["gap_count"] == 0

    def test_with_data(self):
        m = _compliance_metrics({
            "compliance_status": {
                "frameworks": [
                    {"name": "PCI-DSS", "status": "satisfied"},
                    {"name": "SOC2", "status": "partial"},
                ],
                "gaps": [{"id": "gap-1"}],
            }
        })
        assert m["framework_count"] == 2
        assert m["satisfied_frameworks"] == 1
        assert m["gap_count"] == 1


class TestPolicyMetrics:
    def test_empty(self):
        m = _policy_metrics({})
        assert m["action_count"] == 0

    def test_with_data(self):
        m = _policy_metrics({
            "policy_automation": {
                "actions": [{"type": "notify"}, {"type": "block"}],
                "execution": {
                    "status": "completed",
                    "results": [
                        {"delivery": {"status": "sent"}},
                        {"delivery": {"status": "failed"}},
                    ],
                },
            }
        })
        assert m["action_count"] == 2
        assert m["execution_status"] == "completed"
        assert m["results_recorded"] == 2
        assert m["deliveries_sent"] == 1


class TestEvidenceMetrics:
    def test_empty(self):
        m = _evidence_metrics({})
        assert m["bundle_id"] is None
        assert m["file_count"] == 0

    def test_with_data(self):
        m = _evidence_metrics({
            "evidence_bundle": {
                "bundle_id": "EB-123",
                "files": {"sarif": "scan.sarif", "sbom": "sbom.json"},
                "sections": ["findings", "summary"],
                "compressed": True,
                "encrypted": False,
            }
        })
        assert m["bundle_id"] == "EB-123"
        assert m["file_count"] == 2
        assert m["section_count"] == 2
        assert m["compressed"] is True
        assert m["encrypted"] is False


class TestAnalyticsMetrics:
    def test_empty(self):
        m = _analytics_metrics({})
        assert m["estimated_value"] == 0.0
        assert m["insight_count"] == 0

    def test_with_data(self):
        m = _analytics_metrics({
            "analytics": {
                "overview": {
                    "estimated_value": 50000.0,
                    "noise_reduction_percent": 35.0,
                },
                "insights": [{"id": "i1"}, {"id": "i2"}],
            }
        })
        assert m["estimated_value"] == 50000.0
        assert m["noise_reduction_percent"] == 35.0
        assert m["insight_count"] == 2


class TestExploitMetrics:
    def test_empty(self):
        m = _exploit_metrics({})
        assert m["matched_records"] == 0

    def test_with_data(self):
        m = _exploit_metrics({
            "exploitability_insights": {
                "overview": {
                    "matched_records": 12,
                    "signals_configured": 5,
                },
                "escalations": [{"cve": "CVE-1"}],
            }
        })
        assert m["matched_records"] == 12
        assert m["signals_configured"] == 5
        assert m["escalation_count"] == 1
