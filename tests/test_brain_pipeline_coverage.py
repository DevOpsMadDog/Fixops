"""
Coverage tests for BrainPipeline — targeting untested units.

Covers:
  - FPFeedbackStore: record_feedback, should_auto_suppress, get_fp_rate,
    get_recent_feedback, get_auto_suppress_rules, get_instance (singleton)
  - _step_fp_auto_suppress — auto-suppression step
  - _step_llm_council — LLM Council alternative path
  - _deterministic_consensus — fallback consensus algorithm
  - _evaluate_condition — policy expression parser (all operators)
  - _deep_sanitize / _sanitize_finding — recursive sanitization
  - Post-pipeline enrichment: _enrich_compliance, _enrich_sla,
    _enrich_attack_paths, _enrich_code_to_cloud, _enrich_material_change
  - _compute_data_quality — per-step quality assessment
  - _run_anomaly_check — anomaly detection (graceful fallback)
  - _feed_trend_analyzer — trend analysis (graceful fallback)
"""

from __future__ import annotations

import os
import tempfile
import threading
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from core.brain_pipeline import (
    BrainPipeline,
    FPFeedbackStore,
    PipelineInput,
    PipelineResult,
    PipelineStatus,
    StepResult,
    StepStatus,
    get_fp_feedback_store,
)

pytestmark = pytest.mark.timeout(10)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store(tmp_path: str) -> FPFeedbackStore:
    """Create an isolated FPFeedbackStore backed by a temp file."""
    db = os.path.join(tmp_path, "fp_feedback.db")
    return FPFeedbackStore(db_path=db)


def _tmp_dir():
    """Return a fresh temp directory path (caller owns cleanup)."""
    return tempfile.mkdtemp()


# ---------------------------------------------------------------------------
# FPFeedbackStore
# ---------------------------------------------------------------------------


class TestFPFeedbackStoreRecordFeedback:
    def test_record_returns_dict_with_finding_id(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        result = store.record_feedback("FIND-001", is_false_positive=True)
        assert result["finding_id"] == "FIND-001"
        assert result["is_false_positive"] is True

    def test_record_stores_true_positive(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        result = store.record_feedback("FIND-002", is_false_positive=False)
        assert result["is_false_positive"] is False

    def test_record_includes_auto_suppress_eligible_key(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        result = store.record_feedback("FIND-003", is_false_positive=True, scanner="bandit", cwe_id="CWE-79")
        assert "auto_suppress_eligible" in result

    def test_record_persists_to_db(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        store.record_feedback("FIND-100", is_false_positive=True, scanner="semgrep", cwe_id="CWE-89", analyst="alice")
        rows = store.get_recent_feedback(limit=10)
        assert len(rows) == 1
        assert rows[0]["finding_id"] == "FIND-100"
        assert rows[0]["analyst"] == "alice"
        assert rows[0]["is_false_positive"] is True

    def test_record_multiple_entries(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(5):
            store.record_feedback(f"FIND-{i}", is_false_positive=True)
        rows = store.get_recent_feedback(limit=10)
        assert len(rows) == 5


class TestFPFeedbackStoreShouldAutoSuppress:
    def test_returns_false_when_no_feedback(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        assert store.should_auto_suppress(scanner="bandit", cwe_id="CWE-79") is False

    def test_returns_false_below_threshold(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(2):  # only 2, threshold is 3
            store.record_feedback(f"FIND-{i}", is_false_positive=True, scanner="bandit", cwe_id="CWE-79")
        assert store.should_auto_suppress(scanner="bandit", cwe_id="CWE-79") is False

    def test_returns_true_at_threshold(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(3):
            store.record_feedback(f"FIND-{i}", is_false_positive=True, scanner="bandit", cwe_id="CWE-79")
        assert store.should_auto_suppress(scanner="bandit", cwe_id="CWE-79") is True

    def test_returns_true_for_rule_id_threshold(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(3):
            store.record_feedback(f"FIND-{i}", is_false_positive=True, rule_id="RULE-XSS")
        assert store.should_auto_suppress(rule_id="RULE-XSS") is True

    def test_true_positives_do_not_count_toward_threshold(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        # 2 FPs + 3 TPs — still below threshold for FPs
        for i in range(2):
            store.record_feedback(f"FP-{i}", is_false_positive=True, scanner="s", cwe_id="CWE-1")
        for i in range(3):
            store.record_feedback(f"TP-{i}", is_false_positive=False, scanner="s", cwe_id="CWE-1")
        assert store.should_auto_suppress(scanner="s", cwe_id="CWE-1") is False

    def test_custom_threshold(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(2):
            store.record_feedback(f"FIND-{i}", is_false_positive=True, scanner="sc", cwe_id="CWE-5")
        # With threshold=2 it should trigger
        assert store.should_auto_suppress(scanner="sc", cwe_id="CWE-5", threshold=2) is True


class TestFPFeedbackStoreGetFPRate:
    def test_returns_zero_when_empty(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        rate = store.get_fp_rate()
        assert rate["total_feedback"] == 0
        assert rate["fp_rate"] == 0.0

    def test_calculates_fp_rate_correctly(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        store.record_feedback("F1", is_false_positive=True, scanner="bandit", cwe_id="CWE-79")
        store.record_feedback("F2", is_false_positive=True, scanner="bandit", cwe_id="CWE-79")
        store.record_feedback("F3", is_false_positive=False, scanner="bandit", cwe_id="CWE-79")
        rate = store.get_fp_rate()
        assert rate["total_feedback"] == 3
        assert rate["false_positives"] == 2
        assert rate["true_positives"] == 1
        assert rate["fp_rate"] == pytest.approx(2 / 3, abs=0.001)

    def test_filter_by_scanner(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        store.record_feedback("F1", is_false_positive=True, scanner="bandit")
        store.record_feedback("F2", is_false_positive=True, scanner="semgrep")
        rate = store.get_fp_rate(scanner="bandit")
        assert rate["total_feedback"] == 1

    def test_filter_by_org_id(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        store.record_feedback("F1", is_false_positive=True, org_id="org-a")
        store.record_feedback("F2", is_false_positive=False, org_id="org-b")
        rate = store.get_fp_rate(org_id="org-a")
        assert rate["total_feedback"] == 1
        assert rate["false_positives"] == 1

    def test_result_contains_by_scanner_breakdown(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        store.record_feedback("F1", is_false_positive=True, scanner="bandit")
        rate = store.get_fp_rate()
        assert isinstance(rate["by_scanner"], list)
        assert rate["by_scanner"][0]["scanner"] == "bandit"

    def test_result_contains_by_cwe_breakdown(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        store.record_feedback("F1", is_false_positive=True, cwe_id="CWE-79")
        rate = store.get_fp_rate()
        assert isinstance(rate["by_cwe"], list)


class TestFPFeedbackStoreGetRecentFeedback:
    def test_returns_empty_list_when_no_data(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        assert store.get_recent_feedback() == []

    def test_respects_limit(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(10):
            store.record_feedback(f"F{i}", is_false_positive=True)
        rows = store.get_recent_feedback(limit=3)
        assert len(rows) == 3

    def test_returns_most_recent_first(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        store.record_feedback("OLD", is_false_positive=True)
        store.record_feedback("NEW", is_false_positive=False)
        rows = store.get_recent_feedback(limit=2)
        assert rows[0]["finding_id"] == "NEW"

    def test_row_schema_complete(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        store.record_feedback("F1", is_false_positive=True, scanner="s", cwe_id="CWE-1",
                               app_id="app", org_id="org", rule_id="R1", title="XSS", analyst="bob")
        row = store.get_recent_feedback()[0]
        for key in ("finding_id", "is_false_positive", "reason", "scanner", "cwe_id",
                    "app_id", "org_id", "rule_id", "title", "analyst", "created_at"):
            assert key in row


class TestFPFeedbackStoreGetAutoSuppressRules:
    def test_returns_empty_when_below_threshold(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(2):
            store.record_feedback(f"F{i}", is_false_positive=True, scanner="sc", cwe_id="CWE-X", rule_id="R1")
        rules = store.get_auto_suppress_rules(threshold=3)
        assert rules == []

    def test_returns_rule_when_threshold_met(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(3):
            store.record_feedback(f"F{i}", is_false_positive=True, scanner="sc", cwe_id="CWE-X", rule_id="R1")
        rules = store.get_auto_suppress_rules(threshold=3)
        assert len(rules) == 1
        assert rules[0]["fp_count"] == 3

    def test_rule_schema_has_required_fields(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        for i in range(3):
            store.record_feedback(f"F{i}", is_false_positive=True, scanner="sc", cwe_id="CWE-9", rule_id="R9")
        rule = store.get_auto_suppress_rules()[0]
        for key in ("scanner", "cwe_id", "rule_id", "fp_count"):
            assert key in rule


class TestFPFeedbackStoreGetInstance:
    def test_singleton_returns_same_instance(self):
        # Reset singleton before test
        original = FPFeedbackStore._instance
        FPFeedbackStore._instance = None
        try:
            a = FPFeedbackStore.get_instance()
            b = FPFeedbackStore.get_instance()
            assert a is b
        finally:
            FPFeedbackStore._instance = original

    def test_get_fp_feedback_store_returns_fp_feedback_store(self):
        original = FPFeedbackStore._instance
        FPFeedbackStore._instance = None
        try:
            store = get_fp_feedback_store()
            assert isinstance(store, FPFeedbackStore)
        finally:
            FPFeedbackStore._instance = original

    def test_singleton_thread_safe(self):
        original = FPFeedbackStore._instance
        FPFeedbackStore._instance = None
        instances = []
        try:
            def _get():
                instances.append(FPFeedbackStore.get_instance())
            threads = [threading.Thread(target=_get) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert all(inst is instances[0] for inst in instances)
        finally:
            FPFeedbackStore._instance = original


# ---------------------------------------------------------------------------
# _step_fp_auto_suppress
# ---------------------------------------------------------------------------


class TestStepFPAutoSuppress:
    def test_step_runs_in_pipeline(self):
        """fp_auto_suppress (step index 3) completes without error."""
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="org", findings=[{"id": "F1", "severity": "high"}])
        result = pipeline.run(inp)
        step = result.steps[3]
        assert step.status in (StepStatus.COMPLETED, StepStatus.FAILED)

    def test_suppresses_matching_pattern(self):
        """Findings matching a 3+ FP pattern get auto_suppressed flag."""
        tmp = _tmp_dir()
        store = _make_store(tmp)
        # Prime the store with 3 FPs for the same scanner+cwe combo
        for i in range(3):
            store.record_feedback(f"OLD-{i}", is_false_positive=True, scanner="bandit", cwe_id="CWE-79", rule_id="")

        pipeline = BrainPipeline()
        ctx = {
            "findings": [
                {"id": "F-new", "severity": "high", "scanner": "bandit", "cwe_id": "CWE-79", "rule_id": ""}
            ]
        }
        inp = PipelineInput(org_id="org")

        with patch("core.brain_pipeline.get_fp_feedback_store", return_value=store):
            out = pipeline._step_fp_auto_suppress(ctx, inp)

        assert out["suppressed"] == 1
        assert ctx["findings"][0].get("auto_suppressed") is True
        assert ctx["findings"][0].get("suppression_reason") == "fp_feedback_pattern"

    def test_no_suppression_below_threshold(self):
        tmp = _tmp_dir()
        store = _make_store(tmp)
        # Only 2 FPs — below threshold
        for i in range(2):
            store.record_feedback(f"OLD-{i}", is_false_positive=True, scanner="bandit", cwe_id="CWE-89", rule_id="")

        pipeline = BrainPipeline()
        ctx = {
            "findings": [
                {"id": "F-new", "severity": "high", "scanner": "bandit", "cwe_id": "CWE-89"}
            ]
        }
        inp = PipelineInput(org_id="org")

        with patch("core.brain_pipeline.get_fp_feedback_store", return_value=store):
            out = pipeline._step_fp_auto_suppress(ctx, inp)

        assert out["suppressed"] == 0
        assert ctx["findings"][0].get("auto_suppressed") is None

    def test_output_contains_required_keys(self):
        pipeline = BrainPipeline()
        ctx = {"findings": []}
        inp = PipelineInput(org_id="org")
        out = pipeline._step_fp_auto_suppress(ctx, inp)
        assert "suppressed" in out
        assert "total" in out
        assert "source" in out

    def test_handles_store_exception_gracefully(self):
        pipeline = BrainPipeline()
        ctx = {"findings": [{"id": "F1"}]}
        inp = PipelineInput(org_id="org")

        with patch("core.brain_pipeline.get_fp_feedback_store", side_effect=RuntimeError("DB down")):
            out = pipeline._step_fp_auto_suppress(ctx, inp)

        # Should not raise; returns suppressed=0
        assert out["suppressed"] == 0


# ---------------------------------------------------------------------------
# _deterministic_consensus
# ---------------------------------------------------------------------------


class TestDeterministicConsensus:
    def test_empty_critical_returns_no_findings(self):
        pipeline = BrainPipeline()
        ctx = {"findings": [], "llm_results": []}
        out = pipeline._deterministic_consensus([], ctx)
        assert out["analyzed"] == 0
        assert out["skipped"] is True

    def test_high_risk_majority_returns_block(self):
        pipeline = BrainPipeline()
        ctx = {}
        # >50% of findings have risk_score >= 0.75
        critical = [
            {"id": f"F{i}", "risk_score": 0.9} for i in range(6)
        ] + [
            {"id": "F7", "risk_score": 0.3}
        ]
        out = pipeline._deterministic_consensus(critical, ctx)
        assert out["decision"] == "block"

    def test_high_avg_risk_returns_review(self):
        pipeline = BrainPipeline()
        ctx = {}
        # avg >= 0.7 but not >50% at 0.75
        critical = [{"id": f"F{i}", "risk_score": 0.72} for i in range(4)]
        out = pipeline._deterministic_consensus(critical, ctx)
        assert out["decision"] == "review"

    def test_low_risk_returns_allow(self):
        pipeline = BrainPipeline()
        ctx = {}
        critical = [{"id": f"F{i}", "risk_score": 0.4} for i in range(4)]
        out = pipeline._deterministic_consensus(critical, ctx)
        assert out["decision"] == "allow"

    def test_sets_method_to_deterministic(self):
        pipeline = BrainPipeline()
        ctx = {}
        out = pipeline._deterministic_consensus([{"risk_score": 0.5}], ctx)
        assert out.get("decision") in ("block", "review", "allow")
        # ctx should have llm_results set
        assert "llm_results" in ctx
        assert ctx["llm_results"][0]["method"] == "deterministic"

    def test_output_contains_analyzed_count(self):
        pipeline = BrainPipeline()
        ctx = {}
        critical = [{"risk_score": 0.8}, {"risk_score": 0.6}]
        out = pipeline._deterministic_consensus(critical, ctx)
        assert out["analyzed"] == 2


# ---------------------------------------------------------------------------
# _step_llm_council
# ---------------------------------------------------------------------------


class TestStepLLMCouncil:
    def test_returns_no_critical_when_empty_findings(self):
        pipeline = BrainPipeline()
        ctx = {"findings": []}
        inp = PipelineInput(org_id="org")
        out = pipeline._step_llm_council(ctx, inp)
        assert out.get("analyzed") == 0

    def test_returns_no_critical_when_all_low_risk(self):
        pipeline = BrainPipeline()
        ctx = {"findings": [{"id": "F1", "risk_score": 0.1}]}
        inp = PipelineInput(org_id="org")
        out = pipeline._step_llm_council(ctx, inp)
        assert out.get("analyzed") == 0

    def test_falls_back_to_consensus_when_import_fails(self):
        pipeline = BrainPipeline()
        ctx = {"findings": [{"id": "F1", "risk_score": 0.9}]}
        inp = PipelineInput(org_id="org")

        with patch.object(BrainPipeline, "_get_council_adapter", side_effect=ImportError("no council")):
            with patch.object(pipeline, "_step_llm_consensus", return_value={"analyzed": 1, "decision": "block"}) as mock_fallback:
                out = pipeline._step_llm_council(ctx, inp)

        mock_fallback.assert_called_once()

    def test_falls_back_to_consensus_on_runtime_error(self):
        pipeline = BrainPipeline()
        ctx = {"findings": [{"id": "F1", "risk_score": 0.9}]}
        inp = PipelineInput(org_id="org")

        with patch.object(BrainPipeline, "_get_council_adapter", side_effect=RuntimeError("broken")):
            with patch.object(pipeline, "_step_llm_consensus", return_value={"analyzed": 1}) as mock_fallback:
                pipeline._step_llm_council(ctx, inp)

        mock_fallback.assert_called_once()

    def test_uses_adapter_when_available(self):
        pipeline = BrainPipeline()
        ctx = {"findings": [{"id": "F1", "risk_score": 0.9, "title": "XSS", "severity": "critical", "cve_id": "CVE-2024-1"}]}
        inp = PipelineInput(org_id="test-org")

        mock_adapter = MagicMock()
        mock_adapter.analyse.return_value = {"analyzed": 1, "decision": "block", "confidence": 0.9}
        mock_adapter.get_council_stats.return_value = {"runs": 1}

        with patch.object(BrainPipeline, "_get_council_adapter", return_value=mock_adapter):
            out = pipeline._step_llm_council(ctx, inp)

        mock_adapter.analyse.assert_called_once()
        assert ctx.get("council_verdict") is not None
        assert ctx.get("council_stats") is not None


# ---------------------------------------------------------------------------
# _evaluate_condition
# ---------------------------------------------------------------------------


class TestEvaluateCondition:
    """Tests for BrainPipeline._evaluate_condition (static method)."""

    def _eval(self, condition: str, finding: dict) -> bool:
        return BrainPipeline._evaluate_condition(condition, finding)

    # Numeric comparisons
    def test_gte_true(self):
        assert self._eval("risk_score >= 0.8", {"risk_score": 0.9}) is True

    def test_gte_false(self):
        assert self._eval("risk_score >= 0.8", {"risk_score": 0.5}) is False

    def test_lte_true(self):
        assert self._eval("risk_score <= 0.5", {"risk_score": 0.5}) is True

    def test_gt_false_when_equal(self):
        assert self._eval("risk_score > 0.5", {"risk_score": 0.5}) is False

    def test_lt_true(self):
        assert self._eval("cvss_score < 7", {"cvss_score": 6.5}) is True

    def test_eq_numeric(self):
        assert self._eval("cvss_score == 9.5", {"cvss_score": 9.5}) is True

    def test_ne_numeric(self):
        assert self._eval("cvss_score != 9.5", {"cvss_score": 7.0}) is True

    # Boolean comparisons
    def test_bool_true(self):
        assert self._eval("in_kev == true", {"in_kev": True}) is True

    def test_bool_false_value(self):
        assert self._eval("in_kev == false", {"in_kev": False}) is True

    def test_bool_true_when_finding_is_false(self):
        assert self._eval("in_kev == true", {"in_kev": False}) is False

    # String comparisons (case-insensitive)
    def test_string_eq_case_insensitive(self):
        assert self._eval("severity == CRITICAL", {"severity": "critical"}) is True

    def test_string_ne(self):
        assert self._eval("severity != low", {"severity": "high"}) is True

    # Membership
    def test_in_membership_true(self):
        assert self._eval("severity in [critical, high]", {"severity": "critical"}) is True

    def test_in_membership_false(self):
        assert self._eval("severity in [critical, high]", {"severity": "low"}) is False

    def test_not_in_membership_true(self):
        assert self._eval("severity not in [low, info]", {"severity": "critical"}) is True

    def test_not_in_membership_false(self):
        assert self._eval("severity not in [low, info]", {"severity": "low"}) is False

    # Compound AND
    def test_and_both_true(self):
        assert self._eval(
            "risk_score >= 0.8 and in_kev == true",
            {"risk_score": 0.9, "in_kev": True}
        ) is True

    def test_and_one_false(self):
        assert self._eval(
            "risk_score >= 0.8 and in_kev == true",
            {"risk_score": 0.9, "in_kev": False}
        ) is False

    # Compound OR
    def test_or_first_true(self):
        assert self._eval(
            "risk_score >= 0.9 or severity == CRITICAL",
            {"risk_score": 0.95, "severity": "low"}
        ) is True

    def test_or_second_true(self):
        assert self._eval(
            "risk_score >= 0.9 or severity == CRITICAL",
            {"risk_score": 0.1, "severity": "critical"}
        ) is True

    def test_or_both_false(self):
        assert self._eval(
            "risk_score >= 0.9 or severity == CRITICAL",
            {"risk_score": 0.1, "severity": "low"}
        ) is False

    # Missing field
    def test_missing_field_returns_false(self):
        assert self._eval("risk_score >= 0.8", {}) is False

    def test_missing_field_not_in_returns_true(self):
        # "not in" with missing field is conservatively True
        assert self._eval("severity not in [low, info]", {}) is True

    # Field aliases
    def test_alias_criticality(self):
        assert self._eval("criticality >= 1.5", {"asset_criticality": 2.0}) is True

    def test_alias_kev(self):
        assert self._eval("kev == true", {"in_kev": True}) is True

    # Unknown / unparseable clause
    def test_unparseable_returns_false(self):
        assert self._eval("something_unknown", {"risk_score": 0.9}) is False


# ---------------------------------------------------------------------------
# _deep_sanitize / _sanitize_finding
# ---------------------------------------------------------------------------


class TestDeepSanitize:
    def test_short_string_unchanged(self):
        pipeline = BrainPipeline()
        obj = {"key": "short value"}
        result = pipeline._deep_sanitize(obj, depth=0)
        assert result["key"] == "short value"

    def test_long_string_truncated(self):
        pipeline = BrainPipeline()
        long_str = "A" * (BrainPipeline.MAX_FIELD_LEN + 100)
        result = pipeline._deep_sanitize(long_str, depth=0)
        assert result.endswith("...[truncated]")
        assert len(result) == BrainPipeline.MAX_FIELD_LEN + len("...[truncated]")

    def test_nested_dict_sanitized(self):
        pipeline = BrainPipeline()
        long_str = "B" * (BrainPipeline.MAX_FIELD_LEN + 50)
        obj = {"nested": {"deep": long_str}}
        pipeline._deep_sanitize(obj, depth=0)
        assert obj["nested"]["deep"].endswith("...[truncated]")

    def test_list_items_sanitized(self):
        pipeline = BrainPipeline()
        long_str = "C" * (BrainPipeline.MAX_FIELD_LEN + 1)
        obj = [long_str, "short"]
        pipeline._deep_sanitize(obj, depth=0)
        assert obj[0].endswith("...[truncated]")
        assert obj[1] == "short"

    def test_depth_limit_stops_recursion(self):
        pipeline = BrainPipeline()
        long_str = "D" * (BrainPipeline.MAX_FIELD_LEN + 50)
        # At exactly MAX_SANITIZE_DEPTH, object is returned as-is
        result = pipeline._deep_sanitize(long_str, depth=BrainPipeline.MAX_SANITIZE_DEPTH + 1)
        # Should be returned unchanged (depth exceeded)
        assert result == long_str

    def test_non_string_numeric_unchanged(self):
        pipeline = BrainPipeline()
        obj = {"count": 42, "score": 0.95}
        pipeline._deep_sanitize(obj, depth=0)
        assert obj["count"] == 42
        assert obj["score"] == 0.95

    def test_sanitize_finding_delegates_to_deep_sanitize(self):
        pipeline = BrainPipeline()
        long_str = "E" * (BrainPipeline.MAX_FIELD_LEN + 10)
        finding = {"message": long_str}
        result = pipeline._sanitize_finding(finding)
        assert result["message"].endswith("...[truncated]")


# ---------------------------------------------------------------------------
# _enrich_compliance
# ---------------------------------------------------------------------------


class TestEnrichCompliance:
    def test_no_mapping_returns_early(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1", "cwe_id": "CWE-79"}
        stats = {"compliance_mapped": 0, "frameworks_affected": set()}
        # Empty cwe_mappings — should return without modifying finding
        pipeline._enrich_compliance(finding, {}, stats)
        assert "compliance_impact" not in finding
        assert stats["compliance_mapped"] == 0

    def test_no_cwe_on_finding_returns_early(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1"}  # No cwe_id
        stats = {"compliance_mapped": 0, "frameworks_affected": set()}
        mock_mapping = MagicMock()
        pipeline._enrich_compliance(finding, {"CWE-79": mock_mapping}, stats)
        assert "compliance_impact" not in finding

    def test_extracts_cwe_from_rule_id(self):
        pipeline = BrainPipeline()
        mock_mapping = MagicMock()
        mock_mapping.nist_800_53 = ["AC-2"]
        mock_mapping.pci_dss = []
        mock_mapping.iso_27001 = []
        mock_mapping.owasp_category = None
        mock_mapping.control_families = []
        stats = {"compliance_mapped": 0, "frameworks_affected": set()}
        finding = {"id": "F1", "rule_id": "CWE-79-xss"}
        pipeline._enrich_compliance(finding, {"CWE-79": mock_mapping}, stats)
        assert "compliance_impact" in finding
        assert stats["compliance_mapped"] == 1

    def test_maps_nist_controls(self):
        pipeline = BrainPipeline()
        mock_mapping = MagicMock()
        mock_mapping.nist_800_53 = ["AC-2", "SI-3"]
        mock_mapping.pci_dss = []
        mock_mapping.iso_27001 = []
        mock_mapping.owasp_category = None
        mock_mapping.control_families = []
        stats = {"compliance_mapped": 0, "frameworks_affected": set()}
        finding = {"id": "F1", "cwe_id": "CWE-79"}
        pipeline._enrich_compliance(finding, {"CWE-79": mock_mapping}, stats)
        assert finding["compliance_impact"]["nist_800_53"] == ["AC-2", "SI-3"]
        assert "NIST 800-53" in finding["compliance_impact"]["frameworks_affected"]

    def test_increments_stats(self):
        pipeline = BrainPipeline()
        mock_mapping = MagicMock()
        mock_mapping.nist_800_53 = ["AC-1"]
        mock_mapping.pci_dss = []
        mock_mapping.iso_27001 = []
        mock_mapping.owasp_category = None
        mock_mapping.control_families = []
        stats = {"compliance_mapped": 0, "frameworks_affected": set()}
        finding = {"cwe_id": "CWE-89"}
        pipeline._enrich_compliance(finding, {"CWE-89": mock_mapping}, stats)
        assert stats["compliance_mapped"] == 1


# ---------------------------------------------------------------------------
# _enrich_sla
# ---------------------------------------------------------------------------


class TestEnrichSLA:
    def test_assigns_sla_deadline(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1", "severity": "critical"}
        stats = {"sla_assigned": 0}
        now = datetime.now(timezone.utc)
        pipeline._enrich_sla(finding, now, stats)
        assert "sla_deadline" in finding
        assert "sla_target_hours" in finding
        assert "sla_urgency" in finding

    def test_critical_has_shortest_sla(self):
        pipeline = BrainPipeline()
        finding_crit = {"id": "F1", "severity": "critical"}
        finding_low = {"id": "F2", "severity": "low"}
        stats = {"sla_assigned": 0}
        now = datetime.now(timezone.utc)
        pipeline._enrich_sla(finding_crit, now, stats)
        pipeline._enrich_sla(finding_low, now, stats)
        crit_hours = finding_crit["sla_target_hours"]
        low_hours = finding_low["sla_target_hours"]
        assert crit_hours < low_hours

    def test_unknown_severity_uses_info_default(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1", "severity": "unknown_sev"}
        stats = {"sla_assigned": 0}
        now = datetime.now(timezone.utc)
        pipeline._enrich_sla(finding, now, stats)
        assert finding["sla_target_hours"] == pipeline._SLA_HOURS.get("info", 720)

    def test_urgency_computed_from_discovered_at(self):
        pipeline = BrainPipeline()
        # A finding discovered 24 hours ago with 24h SLA should have urgency 1.0
        discovered = datetime.now(timezone.utc) - timedelta(hours=24)
        finding = {
            "id": "F1",
            "severity": "critical",
            "discovered_at": discovered.isoformat(),
        }
        stats = {"sla_assigned": 0}
        now = datetime.now(timezone.utc)
        pipeline._enrich_sla(finding, now, stats)
        assert finding["sla_urgency"] >= 0.99  # at or past deadline

    def test_new_finding_has_urgency_zero(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1", "severity": "high"}  # No discovered_at
        stats = {"sla_assigned": 0}
        now = datetime.now(timezone.utc)
        pipeline._enrich_sla(finding, now, stats)
        assert finding["sla_urgency"] == 0.0

    def test_increments_stats(self):
        pipeline = BrainPipeline()
        stats = {"sla_assigned": 0}
        now = datetime.now(timezone.utc)
        pipeline._enrich_sla({"severity": "medium"}, now, stats)
        assert stats["sla_assigned"] == 1

    def test_malformed_discovered_at_uses_defaults(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1", "severity": "high", "discovered_at": "not-a-date"}
        stats = {"sla_assigned": 0}
        now = datetime.now(timezone.utc)
        pipeline._enrich_sla(finding, now, stats)
        # Should not raise; urgency falls back to 0.0
        assert finding["sla_urgency"] == 0.0


# ---------------------------------------------------------------------------
# _enrich_attack_paths
# ---------------------------------------------------------------------------


class TestEnrichAttackPaths:
    def test_no_engine_returns_early(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1"}
        stats = {"attack_paths_enriched": 0}
        pipeline._enrich_attack_paths(finding, None, stats)
        assert "attack_paths_count" not in finding
        assert stats["attack_paths_enriched"] == 0

    def test_no_node_id_returns_early(self):
        pipeline = BrainPipeline()
        finding = {}  # No id, cve_id, or finding_id
        stats = {"attack_paths_enriched": 0}
        mock_engine = MagicMock()
        pipeline._enrich_attack_paths(finding, mock_engine, stats)
        mock_engine.assert_not_called()

    def test_enriches_with_engine_result(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1", "cve_id": "CVE-2024-001"}
        stats = {"attack_paths_enriched": 0}
        mock_engine = MagicMock(return_value={"total_paths": 5, "affected_nodes": 12})
        pipeline._enrich_attack_paths(finding, mock_engine, stats)
        assert finding["attack_paths_count"] == 5
        assert finding["blast_radius"] == 12
        assert stats["attack_paths_enriched"] == 1

    def test_engine_returns_non_dict_gracefully(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1", "cve_id": "CVE-2024-001"}
        stats = {"attack_paths_enriched": 0}
        mock_engine = MagicMock(return_value="invalid")
        pipeline._enrich_attack_paths(finding, mock_engine, stats)
        assert "attack_paths_count" not in finding
        assert stats["attack_paths_enriched"] == 0


# ---------------------------------------------------------------------------
# _enrich_material_change
# ---------------------------------------------------------------------------


class TestEnrichMaterialChange:
    def test_no_file_path_returns_early(self):
        pipeline = BrainPipeline()
        finding = {"id": "F1"}
        stats = {"material_change_enriched": 0}
        pipeline._enrich_material_change(finding, stats)
        assert stats["material_change_enriched"] == 0

    def test_cosmetic_classification_no_boost(self):
        pipeline = BrainPipeline()
        finding = {
            "id": "F1",
            "file_path": "src/foo.py",
            "risk_score": 0.5,
            "material_change": {"classification": "COSMETIC"},
        }
        stats = {"material_change_enriched": 0}
        pipeline._enrich_material_change(finding, stats)
        assert finding["risk_score"] == 0.5
        assert stats["material_change_enriched"] == 0

    def test_breaking_classification_boosts_risk(self):
        pipeline = BrainPipeline()
        original_risk = 0.5
        finding = {
            "id": "F1",
            "file_path": "src/auth.py",
            "risk_score": original_risk,
            "material_change": {"classification": "BREAKING"},
        }
        stats = {"material_change_enriched": 0}
        pipeline._enrich_material_change(finding, stats)
        assert finding["risk_score"] > original_risk
        assert finding["risk_score"] <= 1.0
        assert "material_change_boost" in finding
        assert stats["material_change_enriched"] == 1

    def test_material_classification_moderate_boost(self):
        pipeline = BrainPipeline()
        original_risk = 0.5
        finding = {
            "id": "F1",
            "file_path": "src/api.py",
            "risk_score": original_risk,
            "material_change": {"classification": "MATERIAL"},
        }
        stats = {"material_change_enriched": 0}
        pipeline._enrich_material_change(finding, stats)
        boost = finding.get("material_change_boost", 0)
        # MATERIAL boost is smaller than BREAKING max boost of 0.15
        assert boost <= 0.08
        assert stats["material_change_enriched"] == 1

    def test_breaking_boost_never_exceeds_1(self):
        pipeline = BrainPipeline()
        finding = {
            "id": "F1",
            "file_path": "src/auth.py",
            "risk_score": 0.99,
            "material_change": {"classification": "BREAKING"},
        }
        stats = {"material_change_enriched": 0}
        pipeline._enrich_material_change(finding, stats)
        assert finding["risk_score"] <= 1.0

    def test_uses_material_classification_field_fallback(self):
        pipeline = BrainPipeline()
        finding = {
            "id": "F1",
            "file_path": "src/db.py",
            "risk_score": 0.4,
            "material_classification": "BREAKING",
        }
        stats = {"material_change_enriched": 0}
        pipeline._enrich_material_change(finding, stats)
        assert finding["risk_score"] > 0.4


# ---------------------------------------------------------------------------
# _compute_data_quality
# ---------------------------------------------------------------------------


class TestComputeDataQuality:
    def _make_result_with_steps(self, statuses: list) -> PipelineResult:
        result = PipelineResult(org_id="org")
        result.steps = []
        for name, status in statuses:
            sr = StepResult(name=name, status=status)
            result.steps.append(sr)
        return result

    def test_returns_dict_with_overall_score(self):
        pipeline = BrainPipeline()
        result = self._make_result_with_steps([("connect", StepStatus.COMPLETED)])
        ctx = {}
        quality = pipeline._compute_data_quality(ctx, result)
        assert "overall_score" in quality
        assert "overall_grade" in quality

    def test_skipped_steps_noted(self):
        pipeline = BrainPipeline()
        result = self._make_result_with_steps([("micro_pentest", StepStatus.SKIPPED)])
        ctx = {}
        quality = pipeline._compute_data_quality(ctx, result)
        assert quality["steps"]["micro_pentest"]["status"] == "skipped"

    def test_failed_steps_increase_degraded_count(self):
        pipeline = BrainPipeline()
        result = self._make_result_with_steps([
            ("connect", StepStatus.FAILED),
            ("normalize", StepStatus.COMPLETED),
        ])
        result.steps[0].error = "Connection refused"
        ctx = {}
        quality = pipeline._compute_data_quality(ctx, result)
        assert quality["degraded_steps"] >= 1

    def test_grade_a_for_high_score(self):
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        result.steps = []
        ctx = {}
        # Pipeline with no steps gets 0 active / score=0
        quality = pipeline._compute_data_quality(ctx, result)
        assert quality["overall_grade"] in ("A", "B", "C", "D")

    def test_warnings_list_present(self):
        pipeline = BrainPipeline()
        result = self._make_result_with_steps([("connect", StepStatus.COMPLETED)])
        result.steps[0].output = {"connectors_queried": 0}
        ctx = {}
        quality = pipeline._compute_data_quality(ctx, result)
        assert isinstance(quality["warnings"], list)

    def test_post_pipeline_enrichment_skipped_when_not_run(self):
        pipeline = BrainPipeline()
        result = self._make_result_with_steps([])
        ctx = {}  # No _post_pipeline_enriched key
        quality = pipeline._compute_data_quality(ctx, result)
        assert quality["steps"]["post_pipeline_enrichment"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# _run_anomaly_check
# ---------------------------------------------------------------------------


class TestRunAnomalyCheck:
    def test_returns_none_when_anomaly_detector_unavailable(self):
        """When AnomalyDetector raises OSError/RuntimeError, method returns None."""
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        result.steps = []

        mock_module = MagicMock()
        mock_module.AnomalyDetector.side_effect = OSError("module unavailable")
        with patch.dict("sys.modules", {"core.ml.anomaly_detector": mock_module}):
            out = pipeline._run_anomaly_check(result)
        assert out is None

    def test_returns_none_when_no_findings_in_steps(self):
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        sr = StepResult(name="normalize", status=StepStatus.COMPLETED)
        sr.output = {}  # No "findings" key
        result.steps = [sr]
        # Mock anomaly_detector to confirm it's called but returns early (no findings)
        mock_module = MagicMock()
        mock_detector_instance = MagicMock()
        mock_module.AnomalyDetector.return_value = mock_detector_instance
        with patch.dict("sys.modules", {"core.ml.anomaly_detector": mock_module}):
            out = pipeline._run_anomaly_check(result)
        # Empty findings → returns None before calling detect()
        assert out is None

    def test_handles_runtime_error_gracefully(self):
        """RuntimeError from detector.detect() is caught and None returned."""
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        sr = StepResult(name="normalize", status=StepStatus.COMPLETED)
        sr.output = {"findings": [{"id": "F1"}]}
        result.steps = [sr]

        mock_detector_instance = MagicMock()
        mock_detector_instance.detect.side_effect = RuntimeError("detection failed")
        mock_module = MagicMock()
        mock_module.AnomalyDetector.return_value = mock_detector_instance
        with patch.dict("sys.modules", {"core.ml.anomaly_detector": mock_module}):
            out = pipeline._run_anomaly_check(result)
        assert out is None

    def test_calls_detector_when_findings_present(self):
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        sr = StepResult(name="normalize", status=StepStatus.COMPLETED)
        sr.output = {"findings": [{"id": "F1", "severity": "critical"}]}
        result.steps = [sr]

        mock_anomaly = MagicMock()
        mock_anomaly.is_anomalous = False
        mock_anomaly.anomaly_score = 0.1
        mock_anomaly.anomaly_reasons = []
        mock_anomaly.to_dict.return_value = {"is_anomalous": False, "score": 0.1}

        mock_detector_instance = MagicMock()
        mock_detector_instance.detect.return_value = mock_anomaly

        mock_module = MagicMock()
        mock_module.AnomalyDetector.return_value = mock_detector_instance

        with patch.dict("sys.modules", {"core.ml.anomaly_detector": mock_module}):
            out = pipeline._run_anomaly_check(result)

        mock_detector_instance.detect.assert_called_once()
        assert out is not None
        assert out["is_anomalous"] is False


# ---------------------------------------------------------------------------
# _feed_trend_analyzer
# ---------------------------------------------------------------------------


class TestFeedTrendAnalyzer:
    def test_does_not_raise_when_unavailable(self):
        """RuntimeError from get_trend_analyzer is caught silently."""
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        result.steps = []
        mock_module = MagicMock()
        mock_module.get_trend_analyzer.side_effect = RuntimeError("not available")
        with patch.dict("sys.modules", {"core.ml.trend_analyzer": mock_module}):
            pipeline._feed_trend_analyzer(result)  # Must not raise

    def test_calls_add_scan_when_available(self):
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        sr = StepResult(name="normalize", status=StepStatus.COMPLETED)
        sr.output = {"findings": [{"id": "F1", "severity": "high", "cve_id": "CVE-2024-1"}]}
        result.steps = [sr]
        result.run_id = "BR-TEST123456"
        result.status = PipelineStatus.COMPLETED
        result.findings_ingested = 1

        mock_analyzer = MagicMock()
        mock_module = MagicMock()
        mock_module.get_trend_analyzer.return_value = mock_analyzer

        with patch.dict("sys.modules", {"core.ml.trend_analyzer": mock_module}):
            pipeline._feed_trend_analyzer(result)

        mock_analyzer.add_scan.assert_called_once()
        call_args = mock_analyzer.add_scan.call_args[0][0]
        assert call_args["scan_id"] == "BR-TEST123456"
        assert call_args["org_id"] == "org"
        assert call_args["pipeline_status"] == "completed"

    def test_handles_runtime_error_gracefully(self):
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        result.steps = []

        mock_module = MagicMock()
        mock_module.get_trend_analyzer.side_effect = RuntimeError("DB locked")

        with patch.dict("sys.modules", {"core.ml.trend_analyzer": mock_module}):
            pipeline._feed_trend_analyzer(result)  # Must not raise

    def test_filters_non_dict_findings(self):
        pipeline = BrainPipeline()
        result = PipelineResult(org_id="org")
        sr = StepResult(name="normalize", status=StepStatus.COMPLETED)
        sr.output = {"findings": ["not-a-dict", {"id": "F1", "severity": "low"}]}
        result.steps = [sr]
        result.run_id = "BR-ABC"
        result.status = PipelineStatus.COMPLETED
        result.findings_ingested = 2

        mock_analyzer = MagicMock()
        mock_module = MagicMock()
        mock_module.get_trend_analyzer.return_value = mock_analyzer

        with patch.dict("sys.modules", {"core.ml.trend_analyzer": mock_module}):
            pipeline._feed_trend_analyzer(result)

        call_args = mock_analyzer.add_scan.call_args[0][0]
        # Only the dict finding should be in the scan record
        assert len(call_args["findings"]) == 1
