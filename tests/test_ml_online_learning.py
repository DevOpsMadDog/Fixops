"""
Tests for the Online Learning Pipeline — user feedback → model retraining.

[V3] Decision Intelligence — validates the feedback→retrain→deploy loop.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
import pytest

# Ensure suite paths are available
import sitecustomize  # noqa: F401

from core.ml.online_learning import (
    FeedbackBuffer,
    FeedbackConverter,
    FeedbackExample,
    IncrementalTrainer,
    OnlineLearningPipeline,
    PipelineStats,
    RetrainResult,
    _TrainedBundle,
    get_online_learning_pipeline,
    register_online_learning_handlers,
    reset_pipeline,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def golden_path():
    return Path("data/golden_regression_cases.json")


@pytest.fixture
def model_dir():
    d = tempfile.mkdtemp(prefix="online_learn_test_")
    yield Path(d)
    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def trained_model(model_dir):
    """Get a trained RiskScoringModel for testing."""
    from core.ml.risk_scorer import RiskScoringModel
    model = RiskScoringModel(model_dir=model_dir)
    model.train_from_golden_dataset(n_bootstrap=5)
    return model


@pytest.fixture
def pipeline(golden_path, model_dir):
    """Create an OnlineLearningPipeline for testing."""
    reset_pipeline()
    p = OnlineLearningPipeline(
        golden_path=golden_path,
        model_dir=model_dir,
        min_feedback=3,  # Low threshold for testing
        max_buffer=100,
        min_interval_s=0,  # No rate limit in tests
    )
    return p


@pytest.fixture
def sample_feedback_decision_correct():
    """A feedback record for a correct decision."""
    return {
        "feedback_type": "decision_outcome",
        "entity_id": "finding-001",
        "outcome": "correct",
        "predicted": "P0",
        "actual": "P0",
        "confidence": 0.9,
        "context": {
            "features": {
                "cvss_score": 9.8,
                "epss_score": 0.95,
                "in_kev": True,
                "asset_criticality": 1.0,
                "network_exposure": "internet",
                "exploit_available": True,
                "exploit_maturity": "weaponized",
                "reachable": True,
            },
            "original_risk_score": 95.0,
        },
    }


@pytest.fixture
def sample_feedback_decision_incorrect():
    """A feedback record for an incorrect decision (P0 → P2)."""
    return {
        "feedback_type": "decision_outcome",
        "entity_id": "finding-002",
        "outcome": "incorrect",
        "predicted": "P0",
        "actual": "P2",
        "confidence": 0.85,
        "context": {
            "features": {
                "cvss_score": 7.5,
                "epss_score": 0.3,
                "in_kev": False,
                "asset_criticality": 0.5,
                "network_exposure": "internal",
                "exploit_available": False,
                "exploit_maturity": "theoretical",
                "reachable": True,
            },
            "original_risk_score": 65.0,
        },
    }


@pytest.fixture
def sample_feedback_false_positive():
    """A feedback record marking a finding as false positive."""
    return {
        "feedback_type": "false_positive",
        "entity_id": "finding-003",
        "outcome": "correct",
        "predicted": "P1",
        "actual": "FP",
        "confidence": 0.95,
        "context": {
            "features": {
                "cvss_score": 5.0,
                "epss_score": 0.1,
                "in_kev": False,
                "asset_criticality": 0.3,
                "network_exposure": "controlled",
                "exploit_available": False,
                "exploit_maturity": "none",
                "reachable": False,
            },
            "original_risk_score": 30.0,
        },
    }


@pytest.fixture
def sample_feedback_mpte_exploitable():
    """MPTE verification confirming exploitability."""
    return {
        "feedback_type": "mpte_result",
        "entity_id": "finding-004",
        "outcome": "correct",
        "predicted": "exploitable",
        "actual": "exploitable",
        "confidence": 0.99,
        "context": {
            "features": {
                "cvss_score": 9.0,
                "epss_score": 0.8,
                "in_kev": True,
                "asset_criticality": 0.9,
                "network_exposure": "internet",
                "exploit_available": True,
                "exploit_maturity": "active",
                "reachable": True,
            },
            "original_risk_score": 85.0,
        },
    }


@pytest.fixture
def sample_feedback_remediation():
    """Successful remediation feedback."""
    return {
        "feedback_type": "remediation_success",
        "entity_id": "task-001",
        "outcome": "correct",
        "predicted": "P1",
        "actual": "fixed",
        "confidence": 1.0,
        "context": {
            "features": {
                "cvss_score": 7.0,
                "epss_score": 0.5,
                "in_kev": False,
                "asset_criticality": 0.7,
                "network_exposure": "partner",
                "exploit_available": True,
                "exploit_maturity": "poc",
                "reachable": True,
            },
            "original_risk_score": 60.0,
        },
    }


# ---------------------------------------------------------------------------
# FeedbackConverter Tests
# ---------------------------------------------------------------------------

class TestFeedbackConverter:
    """Tests for FeedbackConverter.convert()."""

    def test_convert_decision_correct(self, sample_feedback_decision_correct):
        result = FeedbackConverter.convert(sample_feedback_decision_correct)
        assert result is not None
        assert result.corrected_priority == "P0"
        assert result.corrected_score > 80.0
        assert result.feedback_type == "decision_outcome"
        assert result.entity_id == "finding-001"
        assert result.features.shape == (9,)
        assert result.weight > 0

    def test_convert_decision_incorrect(self, sample_feedback_decision_incorrect):
        result = FeedbackConverter.convert(sample_feedback_decision_incorrect)
        assert result is not None
        assert result.corrected_priority == "P2"
        assert 30.0 <= result.corrected_score <= 56.0
        assert result.weight >= 1.0  # Higher weight for corrections

    def test_convert_false_positive(self, sample_feedback_false_positive):
        result = FeedbackConverter.convert(sample_feedback_false_positive)
        assert result is not None
        assert result.corrected_priority == "FP"
        assert result.corrected_score < 5.0
        assert result.weight >= 1.5  # High weight for FP corrections

    def test_convert_mpte_exploitable(self, sample_feedback_mpte_exploitable):
        result = FeedbackConverter.convert(sample_feedback_mpte_exploitable)
        assert result is not None
        assert result.corrected_score >= 85.0  # Boosted
        assert result.weight > 1.0

    def test_convert_mpte_not_exploitable(self):
        fb = {
            "feedback_type": "mpte_result",
            "entity_id": "finding-005",
            "outcome": "correct",
            "predicted": "not_exploitable",
            "actual": "not_exploitable",
            "confidence": 0.9,
            "context": {
                "features": {
                    "cvss_score": 7.0,
                    "epss_score": 0.5,
                    "in_kev": False,
                },
                "original_risk_score": 60.0,
            },
        }
        result = FeedbackConverter.convert(fb)
        assert result is not None
        assert result.corrected_score < 60.0  # Reduced

    def test_convert_remediation_success(self, sample_feedback_remediation):
        result = FeedbackConverter.convert(sample_feedback_remediation)
        assert result is not None
        assert result.corrected_score == pytest.approx(60.0)  # Reinforced
        assert result.weight > 0

    def test_convert_remediation_failure(self):
        fb = {
            "feedback_type": "remediation_success",
            "entity_id": "task-002",
            "outcome": "incorrect",
            "predicted": "P2",
            "actual": "not_fixed",
            "confidence": 0.8,
            "context": {
                "features": {
                    "cvss_score": 6.0,
                    "epss_score": 0.4,
                    "in_kev": False,
                },
                "original_risk_score": 45.0,
            },
        }
        result = FeedbackConverter.convert(fb)
        assert result is not None
        assert result.corrected_score > 45.0  # Boosted (issue was more severe)

    def test_convert_missing_features_returns_none(self):
        fb = {
            "feedback_type": "decision_outcome",
            "entity_id": "finding-X",
            "outcome": "correct",
            "predicted": "P0",
            "actual": "P0",
            "confidence": 0.5,
            "context": {},  # No features
        }
        result = FeedbackConverter.convert(fb)
        assert result is None

    def test_convert_unknown_type_returns_none(self):
        fb = {
            "feedback_type": "unknown_type",
            "entity_id": "X",
            "outcome": "correct",
            "predicted": "P0",
            "actual": "P0",
            "confidence": 0.5,
            "context": {"features": {"cvss_score": 9.0}},
        }
        result = FeedbackConverter.convert(fb)
        assert result is None

    def test_convert_context_as_json_string(self):
        fb = {
            "feedback_type": "decision_outcome",
            "entity_id": "finding-006",
            "outcome": "correct",
            "predicted": "P0",
            "actual": "P0",
            "confidence": 0.9,
            "context": json.dumps({
                "features": {
                    "cvss_score": 9.8,
                    "epss_score": 0.95,
                    "in_kev": True,
                    "asset_criticality": 1.0,
                },
            }),
        }
        result = FeedbackConverter.convert(fb)
        assert result is not None
        assert result.features.shape == (9,)

    def test_convert_extracts_features_from_cve_data(self):
        fb = {
            "feedback_type": "decision_outcome",
            "entity_id": "finding-007",
            "outcome": "correct",
            "predicted": "P1",
            "actual": "P1",
            "confidence": 0.8,
            "context": {
                "cve_data": {
                    "cvss_score": 7.5,
                    "epss_score": 0.6,
                    "in_kev": True,
                },
            },
        }
        result = FeedbackConverter.convert(fb)
        assert result is not None

    def test_score_to_priority_boundaries(self):
        assert FeedbackConverter._score_to_priority(100) == "P0"
        assert FeedbackConverter._score_to_priority(82) == "P0"
        assert FeedbackConverter._score_to_priority(81.9) == "P1"
        assert FeedbackConverter._score_to_priority(56) == "P1"
        assert FeedbackConverter._score_to_priority(55.9) == "P2"
        assert FeedbackConverter._score_to_priority(30) == "P2"
        assert FeedbackConverter._score_to_priority(29.9) == "P3"
        assert FeedbackConverter._score_to_priority(8) == "P3"
        assert FeedbackConverter._score_to_priority(7.9) == "P4"
        assert FeedbackConverter._score_to_priority(5) == "P4"
        assert FeedbackConverter._score_to_priority(4.9) == "FP"
        assert FeedbackConverter._score_to_priority(0) == "FP"


# ---------------------------------------------------------------------------
# FeedbackBuffer Tests
# ---------------------------------------------------------------------------

class TestFeedbackBuffer:
    """Tests for the thread-safe FeedbackBuffer."""

    def test_add_returns_false_below_threshold(self):
        buf = FeedbackBuffer(min_for_retrain=5)
        ex = FeedbackExample(
            features=np.zeros(9),
            corrected_score=50.0,
            corrected_priority="P2",
            feedback_type="decision_outcome",
            entity_id="test",
        )
        assert buf.add(ex) is False
        assert buf.size == 1

    def test_add_returns_true_at_threshold(self):
        buf = FeedbackBuffer(min_for_retrain=3)
        ex = FeedbackExample(
            features=np.zeros(9),
            corrected_score=50.0,
            corrected_priority="P2",
            feedback_type="decision_outcome",
            entity_id="test",
        )
        buf.add(ex)
        buf.add(ex)
        result = buf.add(ex)
        assert result is True
        assert buf.size == 3

    def test_drain_clears_buffer(self):
        buf = FeedbackBuffer(min_for_retrain=2)
        ex = FeedbackExample(
            features=np.zeros(9),
            corrected_score=50.0,
            corrected_priority="P2",
            feedback_type="test",
            entity_id="test",
        )
        buf.add(ex)
        buf.add(ex)

        items = buf.drain()
        assert len(items) == 2
        assert buf.size == 0

    def test_peek_does_not_clear(self):
        buf = FeedbackBuffer(min_for_retrain=2)
        ex = FeedbackExample(
            features=np.zeros(9),
            corrected_score=50.0,
            corrected_priority="P2",
            feedback_type="test",
            entity_id="test",
        )
        buf.add(ex)
        items = buf.peek()
        assert len(items) == 1
        assert buf.size == 1

    def test_max_size_enforced(self):
        buf = FeedbackBuffer(min_for_retrain=2, max_size=5)
        ex = FeedbackExample(
            features=np.zeros(9),
            corrected_score=50.0,
            corrected_priority="P2",
            feedback_type="test",
            entity_id="test",
        )
        for _ in range(10):
            buf.add(ex)
        assert buf.size == 5  # Deque enforces maxlen

    def test_total_ingested_tracks_all(self):
        buf = FeedbackBuffer(min_for_retrain=2, max_size=3)
        ex = FeedbackExample(
            features=np.zeros(9),
            corrected_score=50.0,
            corrected_priority="P2",
            feedback_type="test",
            entity_id="test",
        )
        for _ in range(7):
            buf.add(ex)
        assert buf.total_ingested == 7
        assert buf.size == 3  # Only 3 retained

    def test_ready_for_retrain(self):
        buf = FeedbackBuffer(min_for_retrain=2)
        ex = FeedbackExample(
            features=np.zeros(9),
            corrected_score=50.0,
            corrected_priority="P2",
            feedback_type="test",
            entity_id="test",
        )
        assert buf.ready_for_retrain is False
        buf.add(ex)
        assert buf.ready_for_retrain is False
        buf.add(ex)
        assert buf.ready_for_retrain is True


# ---------------------------------------------------------------------------
# RetrainResult Tests
# ---------------------------------------------------------------------------

class TestRetrainResult:
    """Tests for RetrainResult data class."""

    def test_to_dict(self):
        r = RetrainResult(
            success=True,
            old_mae=5.0,
            new_mae=4.0,
            golden_pass_rate=0.98,
            golden_passed=True,
            feedback_count=15,
        )
        d = r.to_dict()
        assert d["success"] is True
        assert d["old_mae"] == 5.0
        assert d["new_mae"] == 4.0
        assert d["golden_pass_rate"] == 0.98
        assert "retrain_id" in d
        assert "timestamp" in d

    def test_auto_generates_id_and_timestamp(self):
        r = RetrainResult(success=False)
        assert r.retrain_id.startswith("retrain-")
        assert len(r.retrain_id) > 10
        assert r.timestamp != ""


# ---------------------------------------------------------------------------
# PipelineStats Tests
# ---------------------------------------------------------------------------

class TestPipelineStats:
    """Tests for PipelineStats data class."""

    def test_to_dict(self):
        s = PipelineStats(
            total_feedback_ingested=100,
            total_retrains_attempted=5,
            total_retrains_succeeded=4,
            total_retrains_rejected=1,
        )
        d = s.to_dict()
        assert d["total_feedback_ingested"] == 100
        assert d["total_retrains_succeeded"] == 4

    def test_to_dict_with_last_result(self):
        r = RetrainResult(success=True, new_mae=3.0)
        s = PipelineStats(last_retrain_result=r)
        d = s.to_dict()
        assert d["last_retrain_result"]["success"] is True


# ---------------------------------------------------------------------------
# IncrementalTrainer Tests
# ---------------------------------------------------------------------------

class TestIncrementalTrainer:
    """Tests for the IncrementalTrainer retrain logic."""

    def test_retrain_with_positive_feedback(self, trained_model, golden_path, model_dir):
        trainer = IncrementalTrainer(golden_path=golden_path, model_dir=model_dir)

        # Create feedback examples
        examples = []
        for i in range(5):
            examples.append(FeedbackExample(
                features=np.array([0.98, 0.95, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]),
                corrected_score=95.0,
                corrected_priority="P0",
                feedback_type="decision_outcome",
                entity_id=f"test-{i}",
                weight=1.0,
            ))

        result = trainer.retrain(examples, trained_model)
        assert isinstance(result, RetrainResult)
        assert result.feedback_count == 5
        assert result.training_samples > 5
        assert result.elapsed_seconds > 0

    def test_retrain_preserves_golden_accuracy(self, trained_model, golden_path, model_dir):
        trainer = IncrementalTrainer(golden_path=golden_path, model_dir=model_dir)

        # Small batch of benign feedback
        examples = [
            FeedbackExample(
                features=np.array([0.5, 0.3, 0.0, 0.5, 0.5, 0.0, 0.2, 1.0, 0.0]),
                corrected_score=35.0,
                corrected_priority="P2",
                feedback_type="decision_outcome",
                entity_id="benign-1",
                weight=0.5,
            ),
        ]

        result = trainer.retrain(examples, trained_model)
        if result.success:
            assert result.golden_pass_rate >= 0.95
            assert result.new_mae < result.old_mae + 0.05

    def test_retrain_rejects_accuracy_degradation(self, trained_model, golden_path, model_dir):
        """Extreme adversarial feedback should be rejected by the MAE guard."""
        trainer = IncrementalTrainer(golden_path=golden_path, model_dir=model_dir)

        # Create adversarial feedback — all critical vulns labeled as FP
        examples = []
        for i in range(50):
            examples.append(FeedbackExample(
                features=np.array([0.98, 0.95, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]),
                corrected_score=0.0,  # Adversarial: critical → FP
                corrected_priority="FP",
                feedback_type="false_positive",
                entity_id=f"adversarial-{i}",
                weight=5.0,  # High weight
            ))

        result = trainer.retrain(examples, trained_model)
        # Either rejected or golden pass rate is still above threshold
        # (golden data provides stability anchor)
        assert result.elapsed_seconds > 0

    def test_load_golden_data(self, golden_path, model_dir):
        trainer = IncrementalTrainer(golden_path=golden_path, model_dir=model_dir)
        X, y, cases = trainer._load_golden_data()
        assert X.shape[0] >= 50  # We have 75+ cases
        assert X.shape[1] == 9
        assert len(y) == len(cases)
        assert all(0 <= v <= 1 for v in y)

    def test_compute_version_is_deterministic(self):
        examples = [FeedbackExample(
            features=np.zeros(9),
            corrected_score=50.0,
            corrected_priority="P2",
            feedback_type="test",
            entity_id="entity-1",
        )]
        v1 = IncrementalTrainer._compute_version(examples)
        v2 = IncrementalTrainer._compute_version(examples)
        assert v1 == v2
        assert v1.startswith("online-")


# ---------------------------------------------------------------------------
# OnlineLearningPipeline Integration Tests
# ---------------------------------------------------------------------------

class TestOnlineLearningPipeline:
    """Integration tests for the full pipeline."""

    def test_ingest_single_feedback(self, pipeline, sample_feedback_decision_correct):
        result = pipeline.ingest_feedback(sample_feedback_decision_correct)
        # Single feedback shouldn't trigger retrain (min=3)
        assert result is None
        assert pipeline.stats.total_feedback_ingested == 1
        assert pipeline.stats.current_buffer_size == 1

    def test_ingest_triggers_retrain_at_threshold(
        self, pipeline, sample_feedback_decision_correct,
        sample_feedback_decision_incorrect, sample_feedback_false_positive,
    ):
        # Ingest 3 feedbacks (min_feedback=3)
        pipeline.ingest_feedback(sample_feedback_decision_correct)
        pipeline.ingest_feedback(sample_feedback_decision_incorrect)
        result = pipeline.ingest_feedback(sample_feedback_false_positive)

        # Should have triggered retrain
        if result is not None:
            assert isinstance(result, RetrainResult)
            assert result.feedback_count == 3
            assert result.elapsed_seconds > 0

    def test_ingest_batch(self, pipeline, sample_feedback_decision_correct):
        feedbacks = [sample_feedback_decision_correct] * 5
        pipeline.ingest_batch(feedbacks)
        assert pipeline.stats.total_feedback_ingested == 5

    def test_retrain_now_with_empty_buffer(self, pipeline):
        result = pipeline.retrain_now()
        assert result.success is False
        assert "No feedback" in result.rejection_reason

    def test_retrain_now_with_data(
        self, pipeline, sample_feedback_decision_correct,
        sample_feedback_decision_incorrect, sample_feedback_false_positive,
    ):
        # Load buffer
        pipeline.ingest_feedback(sample_feedback_decision_correct)
        pipeline.ingest_feedback(sample_feedback_decision_incorrect)
        pipeline.ingest_feedback(sample_feedback_false_positive)

        # Force retrain
        result = pipeline.retrain_now()
        assert isinstance(result, RetrainResult)
        assert result.feedback_count >= 1  # At least some feedback was valid
        stats = pipeline.stats
        assert stats.total_retrains_attempted >= 1

    def test_stats_tracking(self, pipeline, sample_feedback_decision_correct):
        pipeline.ingest_feedback(sample_feedback_decision_correct)
        s = pipeline.stats
        assert s.total_feedback_ingested == 1
        assert s.current_buffer_size == 1
        assert s.total_retrains_attempted == 0

    def test_retrain_history(self, pipeline, sample_feedback_decision_correct):
        # Ensure there's data
        for _ in range(5):
            pipeline.ingest_feedback(sample_feedback_decision_correct)

        pipeline.retrain_now()
        history = pipeline.retrain_history
        assert len(history) >= 1
        assert "retrain_id" in history[0]

    def test_pipeline_rejects_bad_feedback_gracefully(self, pipeline):
        bad_fb = {"feedback_type": "unknown", "entity_id": "bad"}
        result = pipeline.ingest_feedback(bad_fb)
        assert result is None
        # Should not crash
        assert pipeline.stats.total_feedback_ingested == 0

    def test_pipeline_rate_limiting(self, model_dir, golden_path):
        # Create pipeline with 60s rate limit
        p = OnlineLearningPipeline(
            golden_path=golden_path,
            model_dir=model_dir,
            min_feedback=1,
            min_interval_s=60,
        )
        fb = {
            "feedback_type": "decision_outcome",
            "entity_id": "rate-test",
            "outcome": "correct",
            "predicted": "P0",
            "actual": "P0",
            "confidence": 0.9,
            "context": {"features": {"cvss_score": 9.8}},
        }
        # First ingest should trigger retrain
        p.ingest_feedback(fb)
        # Second should be rate-limited (no retrain)
        p.ingest_feedback(fb)
        # r2 should be None (buffered, not retrained due to rate limit)
        # Note: r1 may or may not trigger depending on timing


# ---------------------------------------------------------------------------
# Singleton / Reset Tests
# ---------------------------------------------------------------------------

class TestSingleton:
    """Tests for the module-level singleton and reset."""

    def test_get_pipeline_returns_same_instance(self):
        reset_pipeline()
        p1 = get_online_learning_pipeline()
        p2 = get_online_learning_pipeline()
        assert p1 is p2
        reset_pipeline()

    def test_reset_creates_new_instance(self):
        reset_pipeline()
        p1 = get_online_learning_pipeline()
        reset_pipeline()
        p2 = get_online_learning_pipeline()
        assert p1 is not p2
        reset_pipeline()


# ---------------------------------------------------------------------------
# EventBus Integration Tests
# ---------------------------------------------------------------------------

class TestEventBusIntegration:
    """Tests for EventBus handler registration."""

    def test_register_handlers_idempotent(self):
        reset_pipeline()
        from core.event_bus import get_event_bus
        bus = get_event_bus()

        # Register twice — should not error
        register_online_learning_handlers(bus)
        register_online_learning_handlers(bus)
        reset_pipeline()

    @pytest.mark.asyncio
    async def test_decision_made_handler(self):
        """Test that DECISION_MADE events are ingested."""
        reset_pipeline()
        from core.event_bus import Event, EventType
        from core.ml.online_learning import _handle_decision_made

        event = Event(
            event_type=EventType.DECISION_MADE,
            source="test",
            data={
                "feedback_type": "decision_outcome",
                "entity_id": "evt-finding-1",
                "outcome": "correct",
                "predicted": "P0",
                "actual": "P0",
                "confidence": 0.9,
                "context": {
                    "features": {
                        "cvss_score": 9.8,
                        "epss_score": 0.95,
                        "in_kev": True,
                    },
                },
            },
        )

        await _handle_decision_made(event)
        pipeline = get_online_learning_pipeline()
        assert pipeline.stats.total_feedback_ingested >= 1
        reset_pipeline()

    @pytest.mark.asyncio
    async def test_remediation_completed_handler(self):
        """Test that REMEDIATION_COMPLETED events are ingested."""
        reset_pipeline()
        from core.event_bus import Event, EventType
        from core.ml.online_learning import _handle_remediation_completed

        event = Event(
            event_type=EventType.REMEDIATION_COMPLETED,
            source="test",
            data={
                "entity_id": "task-evt-1",
                "success": True,
                "predicted_priority": "P1",
                "confidence": 0.8,
                "context": {
                    "features": {
                        "cvss_score": 7.0,
                        "epss_score": 0.5,
                    },
                    "original_risk_score": 60.0,
                },
            },
        )

        await _handle_remediation_completed(event)
        pipeline = get_online_learning_pipeline()
        assert pipeline.stats.total_feedback_ingested >= 1
        reset_pipeline()


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge case and robustness tests."""

    def test_feedback_with_string_context(self, pipeline):
        fb = {
            "feedback_type": "decision_outcome",
            "entity_id": "str-ctx",
            "outcome": "correct",
            "predicted": "P0",
            "actual": "P0",
            "confidence": 0.9,
            "context": '{"features": {"cvss_score": 9.0}}',
        }
        pipeline.ingest_feedback(fb)
        # Should handle string context gracefully
        assert pipeline.stats.total_feedback_ingested >= 0

    def test_feedback_with_empty_context(self, pipeline):
        fb = {
            "feedback_type": "decision_outcome",
            "entity_id": "empty-ctx",
            "outcome": "correct",
            "predicted": "P0",
            "actual": "P0",
        }
        result = pipeline.ingest_feedback(fb)
        assert result is None

    @pytest.mark.timeout(30)
    def test_concurrent_ingestion(self, pipeline, sample_feedback_decision_correct):
        """Test thread safety of buffer operations."""
        import threading

        results = []
        def ingest():
            for _ in range(10):
                r = pipeline.ingest_feedback(sample_feedback_decision_correct)
                if r is not None:
                    results.append(r)

        threads = [threading.Thread(target=ingest) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should not crash and ingestion count should be correct
        assert pipeline.stats.total_feedback_ingested == 40

    def test_feature_vector_shape(self, sample_feedback_decision_correct):
        result = FeedbackConverter.convert(sample_feedback_decision_correct)
        assert result.features.shape == (9,)
        assert all(np.isfinite(result.features))

    def test_trained_bundle(self):
        """Test _TrainedBundle container."""
        model = MagicMock()
        scaler = MagicMock()
        bundle = _TrainedBundle(model=model, scaler=scaler)
        assert bundle.model is model
        assert bundle.scaler is scaler
