"""
End-to-end tests for BN-LR (Bayesian Network + Logistic Regression) hybrid model.

Tests the complete pipeline from training to prediction to backtesting.
"""

import json
import tempfile
from pathlib import Path


class TestBNLRHybrid:
    """Test BN-LR hybrid model implementation."""

    def test_train_bn_lr_end_to_end(self, cli_runner):
        """Test training BN-LR model on tiny dataset."""
        data_path = (
            Path(__file__).parent.parent / "fixtures" / "data" / "bn_lr_tiny.csv"
        )

        assert data_path.exists(), f"Training data not found: {data_path}"

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model"

            result = cli_runner.run(
                ["train-bn-lr", "--data", str(data_path), "--output", str(model_path)]
            )

            assert result.exit_code == 0, f"Training failed: {result.stderr}"
            assert "Training BN-LR model" in result.stdout
            assert "Model saved" in result.stdout

            assert (model_path / "model.joblib").exists()
            assert (model_path / "metadata.json").exists()

            with open(model_path / "metadata.json", "r") as f:
                metadata = json.load(f)

            assert "bn_cpd_hash" in metadata
            assert "calibration_method" in metadata
            assert metadata["calibration_method"] == "sigmoid"
            assert "trained_at" in metadata
            assert metadata["n_samples"] == 46
            assert metadata["n_features"] == 4

    def test_backtest_bn_lr_end_to_end(self, cli_runner):
        """Test backtesting BN-LR model on tiny dataset."""
        data_path = (
            Path(__file__).parent.parent / "fixtures" / "data" / "bn_lr_tiny.csv"
        )

        assert data_path.exists(), f"Training data not found: {data_path}"

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model"

            train_result = cli_runner.run(
                [
                    "train-bn-lr",
                    "--data",
                    str(data_path),
                    "--output",
                    str(model_path),
                    "--quiet",
                ]
            )
            assert train_result.exit_code == 0

            backtest_result = cli_runner.run(
                ["backtest-bn-lr", "--model", str(model_path), "--data", str(data_path)]
            )

            assert (
                backtest_result.exit_code == 0
            ), f"Backtest failed: {backtest_result.stderr}"
            assert "Backtest results" in backtest_result.stdout
            assert "Accuracy:" in backtest_result.stdout
            assert "ROC-AUC:" in backtest_result.stdout

            assert "0.6:" in backtest_result.stdout
            assert "0.85:" in backtest_result.stdout

    def test_backtest_with_output_file(self, cli_runner):
        """Test backtesting with JSON output file."""
        data_path = (
            Path(__file__).parent.parent / "fixtures" / "data" / "bn_lr_tiny.csv"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model"
            output_path = Path(tmpdir) / "backtest_results.json"

            train_result = cli_runner.run(
                [
                    "train-bn-lr",
                    "--data",
                    str(data_path),
                    "--output",
                    str(model_path),
                    "--quiet",
                ]
            )
            assert train_result.exit_code == 0

            backtest_result = cli_runner.run(
                [
                    "backtest-bn-lr",
                    "--model",
                    str(model_path),
                    "--data",
                    str(data_path),
                    "--output",
                    str(output_path),
                    "--pretty",
                    "--quiet",
                ]
            )

            assert backtest_result.exit_code == 0
            assert output_path.exists()

            with open(output_path, "r") as f:
                metrics = json.load(f)

            assert "accuracy" in metrics
            assert "roc_auc" in metrics
            assert "n_samples" in metrics
            assert "thresholds" in metrics

            assert metrics["n_samples"] == 46
            assert "0.6" in metrics["thresholds"]
            assert "0.85" in metrics["thresholds"]

            assert 0.0 <= metrics["accuracy"] <= 1.0
            assert 0.0 <= metrics["roc_auc"] <= 1.0

    def test_predict_bn_lr_end_to_end(self, cli_runner):
        """Test prediction with BN-LR model."""
        data_path = (
            Path(__file__).parent.parent / "fixtures" / "data" / "bn_lr_tiny.csv"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model"
            context_path = Path(tmpdir) / "context.json"
            output_path = Path(tmpdir) / "prediction.json"

            train_result = cli_runner.run(
                [
                    "train-bn-lr",
                    "--data",
                    str(data_path),
                    "--output",
                    str(model_path),
                    "--quiet",
                ]
            )
            assert train_result.exit_code == 0

            context = {
                "exploitation": "active",
                "exposure": "open",
                "utility": "super_effective",
                "safety_impact": "hazardous",
                "mission_impact": "mev",
            }

            with open(context_path, "w") as f:
                json.dump(context, f)

            predict_result = cli_runner.run(
                [
                    "predict-bn-lr",
                    "--model",
                    str(model_path),
                    "--context",
                    str(context_path),
                    "--output",
                    str(output_path),
                    "--pretty",
                ]
            )

            assert (
                predict_result.exit_code == 0
            ), f"Prediction failed: {predict_result.stderr}"
            assert "Risk probability:" in predict_result.stdout
            assert "BN posteriors:" in predict_result.stdout

            assert output_path.exists()

            with open(output_path, "r") as f:
                result = json.load(f)

            assert "risk_probability" in result
            assert "bn_posteriors" in result
            assert "model_metadata" in result

            assert 0.0 <= result["risk_probability"] <= 1.0

            posteriors = result["bn_posteriors"]
            assert "low" in posteriors
            assert "medium" in posteriors
            assert "high" in posteriors
            assert "critical" in posteriors

            metadata = result["model_metadata"]
            assert "bn_cpd_hash" in metadata
            assert "trained_at" in metadata
            assert "calibration_method" in metadata

    def test_bn_cpd_hash_verification(self, cli_runner):
        """Test that BN CPD hash verification works."""
        data_path = (
            Path(__file__).parent.parent / "fixtures" / "data" / "bn_lr_tiny.csv"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model"
            context_path = Path(tmpdir) / "context.json"

            train_result = cli_runner.run(
                [
                    "train-bn-lr",
                    "--data",
                    str(data_path),
                    "--output",
                    str(model_path),
                    "--quiet",
                ]
            )
            assert train_result.exit_code == 0

            metadata_file = model_path / "metadata.json"
            with open(metadata_file, "r") as f:
                metadata = json.load(f)

            metadata["bn_cpd_hash"] = "0" * 64
            with open(metadata_file, "w") as f:
                json.dump(metadata, f)

            context = {
                "exploitation": "none",
                "exposure": "controlled",
                "utility": "efficient",
                "safety_impact": "negligible",
                "mission_impact": "degraded",
            }

            with open(context_path, "w") as f:
                json.dump(context, f)

            predict_result = cli_runner.run(
                [
                    "predict-bn-lr",
                    "--model",
                    str(model_path),
                    "--context",
                    str(context_path),
                ]
            )

            assert predict_result.exit_code != 0, "Should fail with CPD hash mismatch"
            assert (
                "BN CPD hash mismatch" in predict_result.stderr
                or "mismatch" in predict_result.stderr.lower()
            )

            predict_with_override = cli_runner.run(
                [
                    "predict-bn-lr",
                    "--model",
                    str(model_path),
                    "--context",
                    str(context_path),
                    "--allow-skew",
                ]
            )

            assert (
                predict_with_override.exit_code == 0
            ), "Should succeed with --allow-skew flag"

    def test_custom_thresholds(self, cli_runner):
        """Test backtesting with custom thresholds."""
        data_path = (
            Path(__file__).parent.parent / "fixtures" / "data" / "bn_lr_tiny.csv"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model"
            output_path = Path(tmpdir) / "backtest_results.json"

            train_result = cli_runner.run(
                [
                    "train-bn-lr",
                    "--data",
                    str(data_path),
                    "--output",
                    str(model_path),
                    "--quiet",
                ]
            )
            assert train_result.exit_code == 0

            backtest_result = cli_runner.run(
                [
                    "backtest-bn-lr",
                    "--model",
                    str(model_path),
                    "--data",
                    str(data_path),
                    "--output",
                    str(output_path),
                    "--thresholds",
                    "0.5,0.7,0.9",
                    "--quiet",
                ]
            )

            assert backtest_result.exit_code == 0

            with open(output_path, "r") as f:
                metrics = json.load(f)

            assert "0.5" in metrics["thresholds"]
            assert "0.7" in metrics["thresholds"]
            assert "0.9" in metrics["thresholds"]
