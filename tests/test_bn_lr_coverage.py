"""Tests for core.bn_lr — Bayesian Network + Logistic Regression hybrid risk model."""

import json
import os
import sys
import tempfile
from pathlib import Path

import numpy as np
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.bn_lr import (  # noqa: E402
    backtest,
    compute_bn_cpd_hash,
    extract_bn_posteriors,
    load_model,
    predict_proba,
    save_model,
    train,
)


# ---------------------------------------------------------------------------
# compute_bn_cpd_hash
# ---------------------------------------------------------------------------


class TestComputeBnCpdHash:
    def test_returns_hex_string(self):
        h = compute_bn_cpd_hash()
        assert isinstance(h, str)
        assert len(h) == 64  # SHA256 hex digest
        int(h, 16)  # Valid hex

    def test_deterministic(self):
        assert compute_bn_cpd_hash() == compute_bn_cpd_hash()


# ---------------------------------------------------------------------------
# extract_bn_posteriors
# ---------------------------------------------------------------------------


class TestExtractBnPosteriors:
    def test_returns_four_floats(self):
        context = {
            "exploitation": "high",
            "exposure": "medium",
            "utility": "efficient",
            "safety_impact": "major",
            "mission_impact": "crippled",
        }
        posteriors = extract_bn_posteriors(context)
        assert len(posteriors) == 4
        assert all(isinstance(p, float) for p in posteriors)

    def test_posteriors_sum_roughly_one(self):
        context = {
            "exploitation": "low",
            "exposure": "low",
            "utility": "laborious",
            "safety_impact": "negligible",
            "mission_impact": "degraded",
        }
        posteriors = extract_bn_posteriors(context)
        assert abs(sum(posteriors) - 1.0) < 0.01

    def test_empty_context_has_defaults(self):
        posteriors = extract_bn_posteriors({})
        assert len(posteriors) == 4
        assert all(p >= 0 for p in posteriors)


# ---------------------------------------------------------------------------
# train + predict_proba
# ---------------------------------------------------------------------------


class TestTrainAndPredict:
    @pytest.fixture
    def trained_model(self):
        """Train a simple model for testing."""
        np.random.seed(42)
        n = 100
        X = np.random.rand(n, 4)
        y = (X[:, 3] > 0.5).astype(int)  # Label based on 4th feature
        model, metadata = train(X, y)
        return model, metadata

    def test_train_returns_model_and_metadata(self, trained_model):
        model, metadata = trained_model
        assert model is not None
        assert isinstance(metadata, dict)
        assert metadata["n_samples"] == 100
        assert metadata["n_features"] == 4
        assert "trained_at" in metadata
        assert "bn_cpd_hash" in metadata
        assert metadata["calibration_method"] == "sigmoid"

    def test_predict_proba_returns_float(self, trained_model):
        model, _ = trained_model
        prob = predict_proba(model, [0.25, 0.25, 0.25, 0.25])
        assert isinstance(prob, float)
        assert 0.0 <= prob <= 1.0

    def test_predict_proba_high_risk(self, trained_model):
        model, _ = trained_model
        prob_high = predict_proba(model, [0.05, 0.1, 0.2, 0.65])
        prob_low = predict_proba(model, [0.65, 0.2, 0.1, 0.05])
        # Higher 4th feature → higher probability
        assert prob_high > prob_low


# ---------------------------------------------------------------------------
# save_model + load_model
# ---------------------------------------------------------------------------


class TestSaveLoadModel:
    def test_save_and_load(self):
        np.random.seed(42)
        X = np.random.rand(60, 4)
        y = (X[:, 0] > 0.5).astype(int)
        model, metadata = train(X, y)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "model_out"
            save_model(model, metadata, path)

            assert (path / "model.joblib").exists()
            assert (path / "metadata.json").exists()

            loaded_model, loaded_meta = load_model(path, verify_cpd_hash=True)
            assert loaded_meta["n_samples"] == 60

            # Verify loaded model works
            prob = predict_proba(loaded_model, [0.3, 0.3, 0.2, 0.2])
            assert isinstance(prob, float)

    def test_load_missing_model_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            with pytest.raises(FileNotFoundError):
                load_model(path)

    def test_load_missing_metadata_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Create only model file
            import joblib
            joblib.dump("dummy", path / "model.joblib")
            with pytest.raises(FileNotFoundError):
                load_model(path)

    def test_cpd_hash_mismatch(self):
        np.random.seed(42)
        X = np.random.rand(60, 4)
        y = (X[:, 0] > 0.5).astype(int)
        model, metadata = train(X, y)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "model_out"
            save_model(model, metadata, path)

            # Tamper with hash
            meta_file = path / "metadata.json"
            with open(meta_file) as f:
                meta = json.load(f)
            meta["bn_cpd_hash"] = "deadbeef"
            with open(meta_file, "w") as f:
                json.dump(meta, f)

            with pytest.raises(ValueError, match="BN CPD hash mismatch"):
                load_model(path, verify_cpd_hash=True)

            # Should work with verify_cpd_hash=False
            loaded_model, loaded_meta = load_model(path, verify_cpd_hash=False)
            assert loaded_meta is not None


# ---------------------------------------------------------------------------
# backtest
# ---------------------------------------------------------------------------


class TestBacktest:
    def test_backtest_returns_metrics(self):
        np.random.seed(42)
        n = 100
        X = np.random.rand(n, 4)
        y = (X[:, 3] > 0.5).astype(int)
        model, _ = train(X, y)

        X_test = np.random.rand(50, 4)
        y_test = (X_test[:, 3] > 0.5).astype(int)

        metrics = backtest(model, X_test, y_test)
        assert "accuracy" in metrics
        assert "roc_auc" in metrics
        assert "n_samples" in metrics
        assert "thresholds" in metrics
        assert isinstance(metrics["accuracy"], float)
        assert 0.0 <= metrics["accuracy"] <= 1.0

    def test_backtest_custom_thresholds(self):
        np.random.seed(42)
        n = 100
        X = np.random.rand(n, 4)
        y = (X[:, 3] > 0.5).astype(int)
        model, _ = train(X, y)

        X_test = np.random.rand(50, 4)
        y_test = (X_test[:, 3] > 0.5).astype(int)

        metrics = backtest(model, X_test, y_test, thresholds=[0.3, 0.5, 0.7, 0.9])
        assert len(metrics["thresholds"]) == 4
        for key, val in metrics["thresholds"].items():
            assert "precision" in val
            assert "recall" in val

    def test_backtest_sample_counts(self):
        np.random.seed(42)
        n = 80
        X = np.random.rand(n, 4)
        y = np.array([1] * 30 + [0] * 50)
        model, _ = train(X, y)

        metrics = backtest(model, X, y)
        assert metrics["n_samples"] == 80
        assert metrics["n_positive"] == 30
        assert metrics["n_negative"] == 50
