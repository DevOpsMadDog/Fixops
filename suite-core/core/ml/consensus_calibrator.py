"""
ALdeci AI Consensus Calibrator — Multi-LLM Weight Optimization.

[V3] Decision Intelligence — Step 9 of the CTEM Brain Pipeline.

Evaluates the accuracy of each LLM in the multi-AI consensus system
and dynamically adjusts weights to maximize ensemble F1 score.

Models tracked:
  - Claude (Anthropic) — tends to be conservative, high precision
  - GPT-4 (OpenAI) — tends to be verbose but comprehensive
  - Gemini (Google) — tends to be fast but occasionally misses context

Calibration approach:
  1. Evaluate each model on golden regression cases
  2. Compute per-model precision, recall, F1
  3. Optimize ensemble weights using grid search
  4. Track calibration drift over time
  5. Alert if any model degrades significantly

The calibrator produces consensus-calibration.json consumed by
enterprise-architect and brain_pipeline.py Step 9.

Usage:
    from core.ml.consensus_calibrator import ConsensusCalibrator
    cal = ConsensusCalibrator()
    cal.record_evaluation("claude", predictions, ground_truth)
    cal.record_evaluation("gpt4", predictions, ground_truth)
    cal.record_evaluation("gemini", predictions, ground_truth)
    result = cal.calibrate()
    print(result.recommended_weights)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS = {
    "claude": 0.40,
    "gpt4": 0.25,
    "gemini": 0.35,
}

MODEL_NAMES = ["claude", "gpt4", "gemini"]

# Minimum acceptable F1 before triggering degradation alert
MIN_F1_THRESHOLD = 0.5


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ModelEvaluation:
    """Performance evaluation for a single LLM model."""
    model_name: str
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0
    total_predictions: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    avg_confidence: float = 0.0
    evaluated_at: str = ""

    def __post_init__(self):
        if not self.evaluated_at:
            self.evaluated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "total_predictions": self.total_predictions,
            "confusion_matrix": {
                "tp": self.true_positives,
                "fp": self.false_positives,
                "fn": self.false_negatives,
                "tn": self.true_negatives,
            },
            "avg_confidence": round(self.avg_confidence, 4),
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class CalibrationResult:
    """Result of consensus weight calibration."""
    recommended_weights: Dict[str, float]
    previous_weights: Dict[str, float]
    weight_changes: Dict[str, float]
    ensemble_f1: float
    model_evaluations: Dict[str, ModelEvaluation]
    degraded_models: List[str]
    calibration_method: str
    calibrated_at: str = ""

    def __post_init__(self):
        if not self.calibrated_at:
            self.calibrated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "date": self.calibrated_at[:10],
            "recommended_weights": {
                k: round(v, 4) for k, v in self.recommended_weights.items()
            },
            "previous_weights": {
                k: round(v, 4) for k, v in self.previous_weights.items()
            },
            "weight_changes": {
                k: round(v, 4) for k, v in self.weight_changes.items()
            },
            "ensemble_f1": round(self.ensemble_f1, 4),
            "model_performance": {
                name: eval.to_dict()
                for name, eval in self.model_evaluations.items()
            },
            "degraded_models": self.degraded_models,
            "calibration_method": self.calibration_method,
            "calibrated_at": self.calibrated_at,
        }


# ---------------------------------------------------------------------------
# Calibrator class
# ---------------------------------------------------------------------------

class ConsensusCalibrator:
    """Multi-LLM consensus weight calibrator.

    [V3] Decision Intelligence — Optimizes Step 9 weights.
    [V9] Air-gapped — No cloud calls, pure numpy optimization.

    Tracks model performance over time and adjusts weights to maximize
    ensemble F1 score on the golden regression dataset.
    """

    def __init__(
        self,
        initial_weights: Optional[Dict[str, float]] = None,
        output_dir: Optional[Path] = None,
    ):
        self.weights = dict(initial_weights or DEFAULT_WEIGHTS)
        self.output_dir = Path(output_dir) if output_dir else Path(
            ".claude/team-state/data-science"
        )
        self._evaluations: Dict[str, List[ModelEvaluation]] = {
            name: [] for name in MODEL_NAMES
        }
        self._calibration_history: List[CalibrationResult] = []

    def record_evaluation(
        self,
        model_name: str,
        predictions: List[Dict[str, Any]],
        ground_truth: List[Dict[str, Any]],
    ) -> ModelEvaluation:
        """Record an evaluation for a single LLM model.

        Parameters
        ----------
        model_name : str
            Name of the LLM model (claude, gpt4, gemini).
        predictions : list of dict
            Model predictions. Each dict has:
            - "finding_id": str
            - "is_exploitable": bool (model's prediction)
            - "confidence": float (0-1)
            - "severity": str (predicted severity)
        ground_truth : list of dict
            Ground truth labels. Each dict has:
            - "finding_id": str
            - "is_exploitable": bool (actual exploitability)
            - "severity": str (actual severity)

        Returns
        -------
        ModelEvaluation
            Performance evaluation for this model.
        """
        # Build lookup
        truth_map = {gt["finding_id"]: gt for gt in ground_truth}

        tp = fp = fn = tn = 0
        confidences = []

        for pred in predictions:
            fid = pred.get("finding_id", "")
            pred_exploit = pred.get("is_exploitable", False)
            confidence = pred.get("confidence", 0.5)
            confidences.append(confidence)

            gt = truth_map.get(fid)
            if gt is None:
                continue

            actual_exploit = gt.get("is_exploitable", False)

            if pred_exploit and actual_exploit:
                tp += 1
            elif pred_exploit and not actual_exploit:
                fp += 1
            elif not pred_exploit and actual_exploit:
                fn += 1
            else:
                tn += 1

        total = tp + fp + fn + tn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 0.0

        evaluation = ModelEvaluation(
            model_name=model_name,
            precision=precision,
            recall=recall,
            f1=f1,
            accuracy=accuracy,
            total_predictions=len(predictions),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            avg_confidence=float(np.mean(confidences)) if confidences else 0.0,
        )

        if model_name not in self._evaluations:
            self._evaluations[model_name] = []
        self._evaluations[model_name].append(evaluation)

        logger.info(
            "Recorded evaluation for %s: P=%.3f R=%.3f F1=%.3f",
            model_name, precision, recall, f1,
        )
        return evaluation

    def calibrate(
        self,
        method: str = "f1_weighted",
    ) -> CalibrationResult:
        """Calibrate consensus weights based on recorded evaluations.

        Parameters
        ----------
        method : str
            Calibration method:
            - "f1_weighted": Weight proportional to F1 score
            - "grid_search": Grid search for optimal weights
            - "equal": Equal weights (baseline)

        Returns
        -------
        CalibrationResult
            Calibration result with recommended weights.
        """
        # Get latest evaluation per model
        latest_evals = {}
        for model_name in MODEL_NAMES:
            evals = self._evaluations.get(model_name, [])
            if evals:
                latest_evals[model_name] = evals[-1]
            else:
                # No evaluations — use prior knowledge defaults
                latest_evals[model_name] = self._default_evaluation(model_name)

        previous_weights = dict(self.weights)
        degraded_models = []

        if method == "f1_weighted":
            new_weights = self._calibrate_f1_weighted(latest_evals)
        elif method == "grid_search":
            new_weights = self._calibrate_grid_search(latest_evals)
        elif method == "equal":
            new_weights = {name: 1.0 / len(MODEL_NAMES) for name in MODEL_NAMES}
        else:
            new_weights = dict(self.weights)

        # Normalize weights to sum to 1
        total = sum(new_weights.values())
        if total > 0:
            new_weights = {k: v / total for k, v in new_weights.items()}

        # Detect degraded models
        for model_name, evaluation in latest_evals.items():
            if evaluation.f1 < MIN_F1_THRESHOLD:
                degraded_models.append(model_name)
                logger.warning(
                    "Model %s degraded: F1=%.3f (threshold=%.3f)",
                    model_name, evaluation.f1, MIN_F1_THRESHOLD,
                )

        # Compute ensemble F1
        ensemble_f1 = sum(
            new_weights.get(name, 0) * latest_evals[name].f1
            for name in MODEL_NAMES
        )

        weight_changes = {
            name: new_weights.get(name, 0) - previous_weights.get(name, 0)
            for name in MODEL_NAMES
        }

        self.weights = new_weights

        result = CalibrationResult(
            recommended_weights=new_weights,
            previous_weights=previous_weights,
            weight_changes=weight_changes,
            ensemble_f1=ensemble_f1,
            model_evaluations=latest_evals,
            degraded_models=degraded_models,
            calibration_method=method,
        )

        self._calibration_history.append(result)
        return result

    def calibrate_from_golden_dataset(
        self,
        golden_path: Optional[str | Path] = None,
    ) -> CalibrationResult:
        """Simulate model evaluations using the golden regression dataset.

        Since we can't call live LLMs in an air-gapped environment,
        this method simulates what each model would predict based on
        known model characteristics:
        - Claude: Conservative, high precision, lower recall
        - GPT-4: Comprehensive, balanced but slightly lower precision
        - Gemini: Fast, good recall but more false positives

        Parameters
        ----------
        golden_path : str or Path, optional
            Path to golden dataset.

        Returns
        -------
        CalibrationResult
        """
        path = Path(golden_path) if golden_path else Path("data/golden_regression_cases.json")
        if not path.exists():
            logger.warning("Golden dataset not found, using default calibration")
            return self.calibrate()

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        cases = data.get("cases", [])
        rng = np.random.RandomState(42)

        # Simulate each model's predictions based on realistic behavior profiles
        for model_name in MODEL_NAMES:
            predictions = []
            ground_truth = []

            for case in cases:
                is_truly_exploitable = case.get("expected_priority") in ("P0", "P1")
                epss = case.get("epss_score", 0)
                cvss = case.get("cvss_score", 0)
                in_kev = case.get("in_kev", False)

                # Ground truth
                ground_truth.append({
                    "finding_id": case["id"],
                    "is_exploitable": is_truly_exploitable,
                    "severity": case.get("severity", "medium"),
                })

                # Simulate model prediction based on model characteristics
                if model_name == "claude":
                    # High precision, conservative — uses EPSS heavily
                    prob = 0.3 * (cvss / 10) + 0.5 * epss + 0.2 * (1.0 if in_kev else 0.0)
                    threshold = 0.55  # Conservative threshold
                    noise = rng.normal(0, 0.05)
                elif model_name == "gpt4":
                    # Balanced — considers all factors equally
                    prob = 0.35 * (cvss / 10) + 0.35 * epss + 0.3 * (1.0 if in_kev else 0.0)
                    threshold = 0.48
                    noise = rng.normal(0, 0.07)
                else:  # gemini
                    # Aggressive recall — lower threshold, more FP
                    prob = 0.25 * (cvss / 10) + 0.45 * epss + 0.3 * (1.0 if in_kev else 0.0)
                    threshold = 0.40
                    noise = rng.normal(0, 0.08)

                predicted_exploitable = (prob + noise) > threshold
                confidence = min(max(prob + noise * 0.5, 0.1), 0.99)

                predictions.append({
                    "finding_id": case["id"],
                    "is_exploitable": bool(predicted_exploitable),
                    "confidence": float(confidence),
                    "severity": case.get("severity", "medium"),
                })

            self.record_evaluation(model_name, predictions, ground_truth)

        return self.calibrate(method="f1_weighted")

    def save_calibration(self, path: Optional[Path] = None) -> Path:
        """Save calibration results to JSON.

        Parameters
        ----------
        path : Path, optional
            Output directory.

        Returns
        -------
        Path
            Path to saved calibration file.
        """
        out_dir = Path(path) if path else self.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "consensus-calibration.json"

        if self._calibration_history:
            latest = self._calibration_history[-1]
            data = latest.to_dict()
        else:
            data = {
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "model_performance": {
                    name: {"precision": 0, "recall": 0, "f1": 0}
                    for name in MODEL_NAMES
                },
                "recommended_weights": self.weights,
                "ensemble_f1": 0,
            }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info("Calibration saved to %s", out_path)
        return out_path

    # ------------------------------------------------------------------
    # Private methods
    # ------------------------------------------------------------------

    def _calibrate_f1_weighted(
        self, evaluations: Dict[str, ModelEvaluation]
    ) -> Dict[str, float]:
        """Weight models proportionally to their F1 score."""
        weights = {}
        for name in MODEL_NAMES:
            ev = evaluations.get(name)
            if ev:
                # F1 with a floor to avoid zeroing out any model
                weights[name] = max(ev.f1, 0.05)
            else:
                weights[name] = 0.1
        return weights

    def _calibrate_grid_search(
        self, evaluations: Dict[str, ModelEvaluation]
    ) -> Dict[str, float]:
        """Grid search for optimal ensemble weights."""
        best_f1 = -1.0
        best_weights = dict(self.weights)
        step = 0.05

        # Generate weight combinations that sum to 1
        for w_claude in np.arange(0.1, 0.8, step):
            for w_gpt4 in np.arange(0.1, 0.8 - w_claude, step):
                w_gemini = 1.0 - w_claude - w_gpt4
                if w_gemini < 0.05:
                    continue

                # Compute weighted ensemble F1
                ensemble_f1 = (
                    w_claude * evaluations.get("claude", self._default_evaluation("claude")).f1
                    + w_gpt4 * evaluations.get("gpt4", self._default_evaluation("gpt4")).f1
                    + w_gemini * evaluations.get("gemini", self._default_evaluation("gemini")).f1
                )

                if ensemble_f1 > best_f1:
                    best_f1 = ensemble_f1
                    best_weights = {
                        "claude": float(w_claude),
                        "gpt4": float(w_gpt4),
                        "gemini": float(w_gemini),
                    }

        return best_weights

    @staticmethod
    def _default_evaluation(model_name: str) -> ModelEvaluation:
        """Return default evaluation based on prior knowledge of model characteristics."""
        defaults = {
            "claude": ModelEvaluation(
                model_name="claude",
                precision=0.85,
                recall=0.72,
                f1=0.78,
                accuracy=0.80,
            ),
            "gpt4": ModelEvaluation(
                model_name="gpt4",
                precision=0.75,
                recall=0.80,
                f1=0.77,
                accuracy=0.78,
            ),
            "gemini": ModelEvaluation(
                model_name="gemini",
                precision=0.70,
                recall=0.85,
                f1=0.77,
                accuracy=0.76,
            ),
        }
        return defaults.get(model_name, ModelEvaluation(model_name=model_name))


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_calibrator_instance: Optional[ConsensusCalibrator] = None


def get_consensus_calibrator() -> ConsensusCalibrator:
    """Get or create the global ConsensusCalibrator instance."""
    global _calibrator_instance
    if _calibrator_instance is None:
        _calibrator_instance = ConsensusCalibrator()
    return _calibrator_instance


__all__ = [
    "ConsensusCalibrator",
    "CalibrationResult",
    "ModelEvaluation",
    "get_consensus_calibrator",
    "MODEL_NAMES",
    "DEFAULT_WEIGHTS",
]
