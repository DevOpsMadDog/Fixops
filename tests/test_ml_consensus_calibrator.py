"""
Tests for ALdeci AI Consensus Calibrator.

[V3] Decision Intelligence — Validates multi-LLM weight calibration.

Tests cover:
1. Model evaluation recording
2. Calibration methods (F1-weighted, grid search, equal)
3. Weight normalization (must sum to 1)
4. Degradation detection
5. Golden dataset calibration
6. Calibration persistence
7. Default evaluations
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.ml.consensus_calibrator import (
    MODEL_NAMES,
    CalibrationResult,
    ConsensusCalibrator,
    ModelEvaluation,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def calibrator():
    return ConsensusCalibrator(
        output_dir=Path(tempfile.mkdtemp())
    )


@pytest.fixture
def perfect_predictions():
    """Predictions that perfectly match ground truth."""
    return [
        {"finding_id": f"F-{i}", "is_exploitable": i < 5, "confidence": 0.9}
        for i in range(10)
    ]


@pytest.fixture
def ground_truth():
    """Ground truth labels."""
    return [
        {"finding_id": f"F-{i}", "is_exploitable": i < 5, "severity": "high"}
        for i in range(10)
    ]


@pytest.fixture
def bad_predictions():
    """Predictions that are mostly wrong."""
    return [
        {"finding_id": f"F-{i}", "is_exploitable": i >= 5, "confidence": 0.3}
        for i in range(10)
    ]


# ---------------------------------------------------------------------------
# Evaluation recording tests
# ---------------------------------------------------------------------------

class TestEvaluationRecording:
    """Test recording of model evaluations."""

    def test_record_returns_evaluation(self, calibrator, perfect_predictions, ground_truth):
        ev = calibrator.record_evaluation("claude", perfect_predictions, ground_truth)
        assert isinstance(ev, ModelEvaluation)
        assert ev.model_name == "claude"

    def test_perfect_predictions_high_f1(self, calibrator, perfect_predictions, ground_truth):
        ev = calibrator.record_evaluation("claude", perfect_predictions, ground_truth)
        assert ev.f1 == pytest.approx(1.0, abs=0.01)
        assert ev.precision == pytest.approx(1.0, abs=0.01)
        assert ev.recall == pytest.approx(1.0, abs=0.01)

    def test_bad_predictions_low_f1(self, calibrator, bad_predictions, ground_truth):
        ev = calibrator.record_evaluation("gpt4", bad_predictions, ground_truth)
        assert ev.f1 < 0.3

    def test_evaluation_to_dict(self, calibrator, perfect_predictions, ground_truth):
        ev = calibrator.record_evaluation("claude", perfect_predictions, ground_truth)
        d = ev.to_dict()
        assert "precision" in d
        assert "recall" in d
        assert "f1" in d
        assert "confusion_matrix" in d


# ---------------------------------------------------------------------------
# Calibration tests
# ---------------------------------------------------------------------------

class TestCalibration:
    """Test weight calibration."""

    def test_weights_sum_to_one(self, calibrator, perfect_predictions, ground_truth):
        for model in MODEL_NAMES:
            calibrator.record_evaluation(model, perfect_predictions, ground_truth)
        result = calibrator.calibrate(method="f1_weighted")
        total = sum(result.recommended_weights.values())
        assert total == pytest.approx(1.0, abs=0.01)

    def test_f1_weighted_method(self, calibrator, perfect_predictions, ground_truth):
        for model in MODEL_NAMES:
            calibrator.record_evaluation(model, perfect_predictions, ground_truth)
        result = calibrator.calibrate(method="f1_weighted")
        assert isinstance(result, CalibrationResult)
        assert result.calibration_method == "f1_weighted"

    def test_equal_method(self, calibrator, perfect_predictions, ground_truth):
        for model in MODEL_NAMES:
            calibrator.record_evaluation(model, perfect_predictions, ground_truth)
        result = calibrator.calibrate(method="equal")
        expected = 1.0 / len(MODEL_NAMES)
        for w in result.recommended_weights.values():
            assert w == pytest.approx(expected, abs=0.01)

    def test_grid_search_method(self, calibrator, perfect_predictions, ground_truth):
        for model in MODEL_NAMES:
            calibrator.record_evaluation(model, perfect_predictions, ground_truth)
        result = calibrator.calibrate(method="grid_search")
        total = sum(result.recommended_weights.values())
        assert total == pytest.approx(1.0, abs=0.01)

    def test_calibration_to_dict(self, calibrator, perfect_predictions, ground_truth):
        for model in MODEL_NAMES:
            calibrator.record_evaluation(model, perfect_predictions, ground_truth)
        result = calibrator.calibrate()
        d = result.to_dict()
        assert "recommended_weights" in d
        assert "model_performance" in d
        assert "ensemble_f1" in d

    def test_no_evaluations_uses_defaults(self, calibrator):
        result = calibrator.calibrate()
        assert isinstance(result, CalibrationResult)
        # Should still produce weights
        assert sum(result.recommended_weights.values()) == pytest.approx(1.0, abs=0.01)


# ---------------------------------------------------------------------------
# Degradation detection tests
# ---------------------------------------------------------------------------

class TestDegradationDetection:
    """Test detection of degraded models."""

    def test_degraded_model_detected(self, calibrator, bad_predictions, ground_truth, perfect_predictions):
        # Claude is bad, others are good
        calibrator.record_evaluation("claude", bad_predictions, ground_truth)
        calibrator.record_evaluation("gpt4", perfect_predictions, ground_truth)
        calibrator.record_evaluation("gemini", perfect_predictions, ground_truth)
        result = calibrator.calibrate()
        assert "claude" in result.degraded_models

    def test_no_degradation_when_all_good(self, calibrator, perfect_predictions, ground_truth):
        for model in MODEL_NAMES:
            calibrator.record_evaluation(model, perfect_predictions, ground_truth)
        result = calibrator.calibrate()
        assert len(result.degraded_models) == 0


# ---------------------------------------------------------------------------
# Golden dataset calibration tests
# ---------------------------------------------------------------------------

class TestGoldenCalibration:
    """Test calibration from golden dataset."""

    def test_golden_calibration(self, calibrator):
        golden_path = Path("data/golden_regression_cases.json")
        if not golden_path.exists():
            pytest.skip("Golden dataset not found")
        result = calibrator.calibrate_from_golden_dataset(golden_path)
        assert isinstance(result, CalibrationResult)
        assert result.ensemble_f1 > 0
        total = sum(result.recommended_weights.values())
        assert total == pytest.approx(1.0, abs=0.01)


# ---------------------------------------------------------------------------
# Persistence tests
# ---------------------------------------------------------------------------

class TestPersistence:
    """Test calibration save/load."""

    def test_save_creates_file(self, calibrator, perfect_predictions, ground_truth):
        for model in MODEL_NAMES:
            calibrator.record_evaluation(model, perfect_predictions, ground_truth)
        calibrator.calibrate()
        path = calibrator.save_calibration()
        assert path.exists()

    def test_saved_file_valid_json(self, calibrator, perfect_predictions, ground_truth):
        for model in MODEL_NAMES:
            calibrator.record_evaluation(model, perfect_predictions, ground_truth)
        calibrator.calibrate()
        path = calibrator.save_calibration()
        with open(path) as f:
            data = json.load(f)
        assert "recommended_weights" in data
        assert "model_performance" in data
