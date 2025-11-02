"""
Bayesian Network + Logistic Regression (BN-LR) hybrid risk model.

This module implements the BN-LR hybrid approach from the research paper:
https://pmc.ncbi.nlm.nih.gov/articles/PMC12287328/#CR19

The approach:
1. Bayesian Network computes posterior probabilities P(risk=low/med/high/critical)
2. These posteriors are used as features in a Logistic Regression classifier
3. LR is trained on CISA KEV positives vs matched negatives
4. Calibrated probability output predicts exploitation risk

This implementation uses the existing FixOps Bayesian Network structure
(exploitation, exposure, utility, safety_impact, mission_impact → risk)
rather than the paper's Bow-Tie model. This is documented as a deviation
that can be addressed in a future refactor.
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score

from core.processing_layer import ProcessingLayer

logger = logging.getLogger(__name__)


def compute_bn_cpd_hash() -> str:
    """Compute hash of Bayesian Network CPD configuration.

    This hash is used to detect training/serving skew. If the BN CPDs
    change after training, the trained LR model may be invalid.

    Returns:
        SHA256 hash of CPD configuration as hex string
    """
    cpd_config = {
        "exploitation": [[0.6], [0.3], [0.1]],
        "exposure": [[0.5], [0.3], [0.2]],
        "utility": [[0.4], [0.4], [0.2]],
        "safety_impact": [[0.5], [0.3], [0.15], [0.05]],
        "mission_impact": [[0.5], [0.35], [0.15]],
        "risk": [[0.35] * 324, [0.3] * 324, [0.2] * 324, [0.15] * 324],
    }

    config_str = json.dumps(cpd_config, sort_keys=True)
    return hashlib.sha256(config_str.encode()).hexdigest()


def extract_bn_posteriors(context: Dict[str, Any]) -> List[float]:
    """Extract Bayesian Network posterior probabilities as feature vector.

    Args:
        context: Context dict with exploitation, exposure, utility, etc.

    Returns:
        Fixed-order feature vector: [p_low, p_medium, p_high, p_critical]
    """
    processing_layer = ProcessingLayer()
    priors = processing_layer._compute_bayesian_priors(context)

    distribution = priors.get("distribution", {})

    features = [
        distribution.get("low", 0.25),
        distribution.get("medium", 0.25),
        distribution.get("high", 0.25),
        distribution.get("critical", 0.25),
    ]

    return features


def train(
    X: np.ndarray,
    y: np.ndarray,
    *,
    class_weight: str = "balanced",
    calibration_method: str = "sigmoid",
    cv: int = 3,
) -> Tuple[Any, Dict[str, Any]]:
    """Train Logistic Regression classifier with calibration.

    Args:
        X: Feature matrix (n_samples, n_features)
        y: Labels (n_samples,) - 0 for low risk, 1 for high risk
        class_weight: Class weighting strategy (default: "balanced")
        calibration_method: Calibration method (default: "sigmoid" for Platt scaling)
        cv: Number of cross-validation folds (default: 3)

    Returns:
        Tuple of (trained_model, metadata_dict)
    """
    base_lr = LogisticRegression(
        class_weight=class_weight,
        solver="liblinear",
        random_state=42,
        max_iter=1000,
    )

    calibrated_lr = CalibratedClassifierCV(
        base_lr,
        method=calibration_method,
        cv=cv,
    )

    calibrated_lr.fit(X, y)

    metadata = {
        "feature_names": ["bn_p_low", "bn_p_medium", "bn_p_high", "bn_p_critical"],
        "bn_cpd_hash": compute_bn_cpd_hash(),
        "calibration_method": calibration_method,
        "class_weight": class_weight,
        "cv_folds": cv,
        "sklearn_version": "1.3+",
        "trained_at": datetime.utcnow().isoformat(),
        "n_samples": len(X),
        "n_features": X.shape[1],
    }

    return calibrated_lr, metadata


def predict_proba(model: Any, features: List[float]) -> float:
    """Predict exploitation risk probability using trained model.

    Args:
        model: Trained sklearn model
        features: Feature vector [p_low, p_medium, p_high, p_critical]

    Returns:
        Probability of high risk class (float in [0, 1])
    """
    X = np.array([features])
    proba = model.predict_proba(X)[0]

    return float(proba[1])


def save_model(model: Any, metadata: Dict[str, Any], output_path: Path) -> None:
    """Save trained model and metadata to disk.

    Args:
        model: Trained sklearn model
        metadata: Model metadata dict
        output_path: Directory to save model artifacts
    """
    output_path.mkdir(parents=True, exist_ok=True)

    model_file = output_path / "model.joblib"
    metadata_file = output_path / "metadata.json"

    joblib.dump(model, model_file)

    with open(metadata_file, "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Saved model to {model_file}")
    logger.info(f"Saved metadata to {metadata_file}")


def load_model(
    model_path: Path, *, verify_cpd_hash: bool = True
) -> Tuple[Any, Dict[str, Any]]:
    """Load trained model and metadata from disk.

    Args:
        model_path: Directory containing model artifacts
        verify_cpd_hash: If True, verify BN CPD hash matches training time

    Returns:
        Tuple of (model, metadata_dict)

    Raises:
        ValueError: If CPD hash mismatch and verify_cpd_hash=True
    """
    model_file = model_path / "model.joblib"
    metadata_file = model_path / "metadata.json"

    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_file}")

    if not metadata_file.exists():
        raise FileNotFoundError(f"Metadata file not found: {metadata_file}")

    model = joblib.load(model_file)

    with open(metadata_file, "r") as f:
        metadata = json.load(f)

    if verify_cpd_hash:
        current_hash = compute_bn_cpd_hash()
        trained_hash = metadata.get("bn_cpd_hash")

        if current_hash != trained_hash:
            raise ValueError(
                f"BN CPD hash mismatch! "
                f"Current: {current_hash}, Trained: {trained_hash}. "
                f"The Bayesian Network CPDs have changed since training. "
                f"Retrain the model or set verify_cpd_hash=False to override."
            )

    logger.info(f"Loaded model from {model_file}")

    return model, metadata


def backtest(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    *,
    thresholds: Optional[List[float]] = None,
) -> Dict[str, Any]:
    """Backtest trained model on test dataset.

    Args:
        model: Trained sklearn model
        X_test: Test feature matrix
        y_test: Test labels
        thresholds: Decision thresholds to evaluate (default: [0.6, 0.85])

    Returns:
        Dict with metrics: accuracy, roc_auc, precision/recall at thresholds
    """
    if thresholds is None:
        thresholds = [0.6, 0.85]

    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred = model.predict(X_test)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "n_samples": len(y_test),
        "n_positive": int(np.sum(y_test)),
        "n_negative": int(len(y_test) - np.sum(y_test)),
        "thresholds": {},
    }

    for threshold in thresholds:
        y_pred_threshold = (y_proba >= threshold).astype(int)

        precision = precision_score(y_test, y_pred_threshold, zero_division=0)
        recall = recall_score(y_test, y_pred_threshold, zero_division=0)

        metrics["thresholds"][str(threshold)] = {
            "precision": float(precision),
            "recall": float(recall),
        }

    return metrics


__all__ = [
    "compute_bn_cpd_hash",
    "extract_bn_posteriors",
    "train",
    "predict_proba",
    "save_model",
    "load_model",
    "backtest",
]
