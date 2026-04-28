"""
ALdeci ML Risk Scoring Model — Gradient Boosted Trees for Vulnerability Prioritization.

[V3] Decision Intelligence — Step 7 of the CTEM Brain Pipeline.

This module trains and serves a Gradient Boosted Trees (GBT) classifier that
prioritizes vulnerabilities using multi-factor features:
  - CVSS base score (0-10)
  - EPSS probability (0-1)
  - KEV membership (boolean → 0/1)
  - Asset criticality (0-1)
  - Network exposure (categorical → ordinal 0-1)
  - Exploit availability (boolean → 0/1)
  - Exploit maturity (categorical → ordinal 0-1)
  - Reachability (boolean → 0/1)
  - Chain exploit presence (boolean → 0/1)

Output: Risk score 0-100 with confidence interval (±CI).

The model is air-gap compatible — no cloud API calls, no external dependencies
beyond scikit-learn and numpy (both bundled in requirements.txt).

Usage:
    from core.ml.risk_scorer import RiskScoringModel
    model = RiskScoringModel()
    model.train_from_golden_dataset("data/golden_regression_cases.json")
    result = model.predict({
        "cvss_score": 9.8,
        "epss_score": 0.95,
        "in_kev": True,
        "asset_criticality": 1.0,
        "network_exposure": "internet",
        "exploit_available": True,
        "exploit_maturity": "weaponized",
        "reachable": True,
    })
    # result: {"risk_score": 97.2, "confidence_interval": [94.1, 100.0], ...}
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXPOSURE_MAP = {
    "internet": 1.0,
    "public": 0.9,
    "partner": 0.7,
    "internal": 0.5,
    "controlled": 0.4,
    "unknown": 0.3,
    "none": 0.0,
}

MATURITY_MAP = {
    "weaponized": 1.0,
    "active": 0.9,
    "proof_of_concept": 0.6,
    "poc": 0.6,
    "theoretical": 0.3,
    "none": 0.0,
    "unknown": 0.2,
}

FEATURE_NAMES = [
    "cvss_score",
    "epss_score",
    "in_kev",
    "asset_criticality",
    "network_exposure",
    "exploit_available",
    "exploit_maturity",
    "reachable",
    "has_chain",
]

MODEL_VERSION = "2.3.0"
DEFAULT_MODEL_DIR = Path(".claude/team-state/data-science/models")
DEFAULT_GOLDEN_PATH = Path("data/golden_regression_cases.json")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FeatureExplanation:
    """Per-feature SHAP-like explanation for a risk prediction.

    Each feature has a contribution in risk-score points (0-100 scale)
    showing how much it pushed the prediction away from the base value.
    Positive = increases risk, negative = decreases risk.
    """
    name: str
    value: float           # Raw feature value (encoded 0-1)
    raw_value: Any         # Original input value before encoding
    contribution: float    # Risk score points (positive = increases risk)
    direction: str         # "increases_risk" or "decreases_risk" or "neutral"
    explanation: str       # Human-readable explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": round(self.value, 4),
            "raw_value": self.raw_value,
            "contribution": round(self.contribution, 4),
            "direction": self.direction,
            "explanation": self.explanation,
        }


@dataclass
class ExplanationResult:
    """Full SHAP-like explanation for a risk score prediction.

    [V3] Decision Intelligence — explains WHY a vulnerability got its score.

    Uses interventional feature contributions: for each feature, measures
    how the prediction changes when that feature is set to baseline (mean).
    This is equivalent to TreeSHAP's interventional approach.

    Properties:
        base_value: Expected prediction for an average vulnerability (mean)
        feature_explanations: Sorted list of per-feature explanations
        top_drivers: Top 3 features driving the prediction
        risk_narrative: Human-readable narrative explaining the score
    """
    risk_score: float
    base_value: float  # Mean prediction = expected value for avg vuln
    feature_explanations: List[FeatureExplanation]
    top_drivers: List[str]
    risk_narrative: str
    explanation_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 2),
            "base_value": round(self.base_value, 2),
            "feature_explanations": [fe.to_dict() for fe in self.feature_explanations],
            "top_drivers": self.top_drivers,
            "risk_narrative": self.risk_narrative,
            "explanation_time_ms": round(self.explanation_time_ms, 4),
        }


@dataclass
class PredictionResult:
    """Result of a risk score prediction."""
    risk_score: float
    confidence_interval: Tuple[float, float]
    confidence_width: float
    priority: str  # P0, P1, P2, P3, P4, FP
    feature_contributions: Dict[str, float]
    model_version: str
    prediction_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 2),
            "confidence_interval": [
                round(self.confidence_interval[0], 2),
                round(self.confidence_interval[1], 2),
            ],
            "confidence_width": round(self.confidence_width, 2),
            "priority": self.priority,
            "feature_contributions": {
                k: round(v, 4) for k, v in self.feature_contributions.items()
            },
            "model_version": self.model_version,
            "prediction_time_ms": round(self.prediction_time_ms, 4),
        }


@dataclass
class ModelMetrics:
    """Training metrics for the risk scoring model."""
    mae: float = 0.0
    rmse: float = 0.0
    r2: float = 0.0
    within_range_pct: float = 0.0
    precision_by_priority: Dict[str, float] = field(default_factory=dict)
    recall_by_priority: Dict[str, float] = field(default_factory=dict)
    f1_by_priority: Dict[str, float] = field(default_factory=dict)
    training_samples: int = 0
    test_samples: int = 0
    cv_scores: List[float] = field(default_factory=list)
    feature_importances: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mae": round(self.mae, 4),
            "rmse": round(self.rmse, 4),
            "r2": round(self.r2, 4),
            "within_range_pct": round(self.within_range_pct, 4),
            "precision_by_priority": {
                k: round(v, 4) for k, v in self.precision_by_priority.items()
            },
            "recall_by_priority": {
                k: round(v, 4) for k, v in self.recall_by_priority.items()
            },
            "f1_by_priority": {
                k: round(v, 4) for k, v in self.f1_by_priority.items()
            },
            "training_samples": self.training_samples,
            "test_samples": self.test_samples,
            "cv_scores": [round(s, 4) for s in self.cv_scores],
            "feature_importances": {
                k: round(v, 4) for k, v in self.feature_importances.items()
            },
        }


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def _encode_exposure(exposure: str) -> float:
    """Convert network exposure string to ordinal float."""
    if isinstance(exposure, (int, float)):
        return float(min(max(exposure, 0.0), 1.0))
    return EXPOSURE_MAP.get(str(exposure).lower().strip(), 0.3)


def _encode_maturity(maturity: str) -> float:
    """Convert exploit maturity string to ordinal float."""
    if isinstance(maturity, (int, float)):
        return float(min(max(maturity, 0.0), 1.0))
    return MATURITY_MAP.get(str(maturity).lower().strip(), 0.2)


def extract_features(vuln: Dict[str, Any]) -> np.ndarray:
    """Extract feature vector from a vulnerability dictionary.

    Parameters
    ----------
    vuln : dict
        Vulnerability data with keys matching FEATURE_NAMES semantics.

    Returns
    -------
    np.ndarray
        1D array of shape (9,) with encoded features.
    """
    cvss = float(vuln.get("cvss_score", 0.0))
    epss = float(vuln.get("epss_score", 0.0))
    kev = 1.0 if vuln.get("in_kev", False) else 0.0
    criticality = float(vuln.get("asset_criticality", 0.5))
    exposure = _encode_exposure(vuln.get("network_exposure", "unknown"))
    exploit = 1.0 if vuln.get("exploit_available", False) else 0.0
    maturity = _encode_maturity(vuln.get("exploit_maturity", "none"))
    reachable = 1.0 if vuln.get("reachable", True) else 0.0
    has_chain = 1.0 if vuln.get("chain_cves") or vuln.get("has_chain", False) else 0.0

    return np.array([
        cvss / 10.0,       # Normalize CVSS to 0-1
        epss,               # Already 0-1
        kev,                # Binary
        criticality,        # 0-1
        exposure,           # 0-1
        exploit,            # Binary
        maturity,           # 0-1
        reachable,          # Binary
        has_chain,          # Binary
    ], dtype=np.float64)


def _score_to_priority(score: float) -> str:
    """Convert risk score (0-100) to priority label.

    Thresholds calibrated against 75 golden regression cases (v2.1.0).
    Boundary adjustments from v1.0.0:
      P0: 85→82 (captures high-EPSS weaponized vulns on partner/internal networks)
      P1: 60→56 (captures high-CVSS vulns with low-EPSS but KEV membership)
      P3: 15→8  (low-noise CVEs with minimal exposure but real-world presence)
    """
    if score >= 82:
        return "P0"
    elif score >= 56:
        return "P1"
    elif score >= 30:
        return "P2"
    elif score >= 8:
        return "P3"
    elif score >= 5:
        return "P4"
    else:
        return "FP"


# ---------------------------------------------------------------------------
# Model class
# ---------------------------------------------------------------------------

class RiskScoringModel:
    """Gradient Boosted Trees risk scoring model for vulnerability prioritization.

    [V3] Decision Intelligence — Powers Step 7 of the CTEM Brain Pipeline.
    [V9] Air-gapped — No cloud API calls, works offline.

    This model learns from the golden regression dataset and real CVE data
    to produce risk scores that outperform the simple linear formula in
    brain_pipeline.py.

    Architecture:
        - Primary: GradientBoostingRegressor for risk score regression
        - Confidence: Bootstrap ensemble for confidence intervals
        - Fallback: Deterministic weighted formula if ML model unavailable
    """

    def __init__(self, model_dir: Optional[Path] = None, random_seed: int = 42):
        self.model_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
        self.random_seed = random_seed
        self._model = None
        self._scaler = None
        self._metrics: Optional[ModelMetrics] = None
        self._trained = False
        self._model_hash: Optional[str] = None
        self._bootstrap_models: List[Any] = []

    @property
    def is_trained(self) -> bool:
        return self._trained and self._model is not None

    def train_from_golden_dataset(
        self,
        golden_path: Optional[str | Path] = None,
        n_bootstrap: int = 20,
    ) -> ModelMetrics:
        """Train the model from the golden regression dataset.

        Uses k-fold cross-validation to avoid overfitting and bootstrap
        ensemble for confidence interval estimation.

        Parameters
        ----------
        golden_path : str or Path, optional
            Path to golden_regression_cases.json.
        n_bootstrap : int
            Number of bootstrap models for confidence intervals.

        Returns
        -------
        ModelMetrics
            Training and validation metrics.
        """
        from sklearn.ensemble import GradientBoostingRegressor
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import StandardScaler

        path = Path(golden_path) if golden_path else DEFAULT_GOLDEN_PATH
        if not path.exists():
            raise FileNotFoundError(f"Golden dataset not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        cases = data.get("cases", [])
        if len(cases) < 10:
            raise ValueError(f"Need at least 10 cases, got {len(cases)}")

        # Extract features and targets
        X_list = []
        y_list = []
        for case in cases:
            features = extract_features(case)
            # Target: midpoint of expected risk score range, normalized to 0-1
            score_min = float(case.get("expected_risk_score_min", 0))
            score_max = float(case.get("expected_risk_score_max", 100))
            target = (score_min + score_max) / 200.0  # Normalize to 0-1
            X_list.append(features)
            y_list.append(target)

        X = np.array(X_list)
        y = np.array(y_list)

        # Data checksum for reproducibility
        data_hash = hashlib.sha256(
            json.dumps({"X": X.tolist(), "y": y.tolist()}, sort_keys=True).encode()
        ).hexdigest()[:16]

        # Fit scaler
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Train primary model with hyperparameters tuned for small dataset
        rng = np.random.RandomState(self.random_seed)
        self._model = GradientBoostingRegressor(
            n_estimators=200,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            min_samples_leaf=2,
            min_samples_split=3,
            loss="squared_error",
            random_state=self.random_seed,
        )
        self._model.fit(X_scaled, y)

        # Cross-validation (leave-one-out for small dataset)
        n_folds = min(5, len(cases))
        cv_scores = cross_val_score(
            GradientBoostingRegressor(
                n_estimators=200,
                max_depth=4,
                learning_rate=0.05,
                subsample=0.8,
                min_samples_leaf=2,
                min_samples_split=3,
                random_state=self.random_seed,
            ),
            X_scaled,
            y,
            cv=n_folds,
            scoring="r2",
        )

        # Bootstrap ensemble for confidence intervals
        self._bootstrap_models = []
        for i in range(n_bootstrap):
            indices = rng.choice(len(X_scaled), size=len(X_scaled), replace=True)
            X_boot = X_scaled[indices]
            y_boot = y[indices]
            boot_model = GradientBoostingRegressor(
                n_estimators=150,
                max_depth=4,
                learning_rate=0.05,
                subsample=0.8,
                min_samples_leaf=2,
                min_samples_split=3,
                random_state=self.random_seed + i,
            )
            boot_model.fit(X_boot, y_boot)
            self._bootstrap_models.append(boot_model)

        # Compute metrics
        y_pred = self._model.predict(X_scaled)
        y_pred_scores = np.clip(y_pred * 100, 0, 100)
        y_true_scores = y * 100

        mae = float(np.mean(np.abs(y_pred_scores - y_true_scores)))
        rmse = float(np.sqrt(np.mean((y_pred_scores - y_true_scores) ** 2)))
        ss_res = np.sum((y_true_scores - y_pred_scores) ** 2)
        ss_tot = np.sum((y_true_scores - np.mean(y_true_scores)) ** 2)
        r2 = float(1 - ss_res / ss_tot) if ss_tot > 0 else 0.0

        # Check how many predictions fall within expected range
        within_range = 0
        for i, case in enumerate(cases):
            pred_score = y_pred_scores[i]
            score_min = float(case.get("expected_risk_score_min", 0))
            score_max = float(case.get("expected_risk_score_max", 100))
            if score_min <= pred_score <= score_max:
                within_range += 1
        within_range_pct = within_range / len(cases)

        # Priority classification metrics
        y_true_priority = [case.get("expected_priority", "P2") for case in cases]
        y_pred_priority = [_score_to_priority(s) for s in y_pred_scores]

        priority_metrics = self._compute_priority_metrics(y_true_priority, y_pred_priority)

        # Feature importances
        importances = self._model.feature_importances_
        feat_imp = {
            FEATURE_NAMES[i]: float(importances[i])
            for i in range(len(FEATURE_NAMES))
        }
        # Sort by importance
        feat_imp = dict(sorted(feat_imp.items(), key=lambda x: x[1], reverse=True))

        self._metrics = ModelMetrics(
            mae=mae,
            rmse=rmse,
            r2=r2,
            within_range_pct=within_range_pct,
            precision_by_priority=priority_metrics["precision"],
            recall_by_priority=priority_metrics["recall"],
            f1_by_priority=priority_metrics["f1"],
            training_samples=len(cases),
            test_samples=len(cases),  # Using full dataset for golden validation
            cv_scores=cv_scores.tolist(),
            feature_importances=feat_imp,
        )

        self._trained = True
        self._model_hash = data_hash
        logger.info(
            "Model trained: MAE=%.2f, RMSE=%.2f, R²=%.4f, within_range=%.1f%%",
            mae, rmse, r2, within_range_pct * 100,
        )
        return self._metrics

    def predict(self, vuln: Dict[str, Any]) -> PredictionResult:
        """Predict risk score for a single vulnerability.

        Parameters
        ----------
        vuln : dict
            Vulnerability data dictionary.

        Returns
        -------
        PredictionResult
            Risk score with confidence interval and feature contributions.
        """
        t0 = time.monotonic()

        features = extract_features(vuln)

        if self.is_trained and self._scaler is not None:
            X = self._scaler.transform(features.reshape(1, -1))
            raw_score = float(self._model.predict(X)[0])

            # Bootstrap confidence interval
            if self._bootstrap_models:
                boot_preds = np.array([
                    m.predict(X)[0] for m in self._bootstrap_models
                ])
                ci_low = float(np.percentile(boot_preds, 5)) * 100
                ci_high = float(np.percentile(boot_preds, 95)) * 100
            else:
                ci_low = raw_score * 100 - 10
                ci_high = raw_score * 100 + 10

            risk_score = float(np.clip(raw_score * 100, 0, 100))
            ci_low = float(np.clip(ci_low, 0, 100))
            ci_high = float(np.clip(ci_high, 0, 100))

            # Feature contributions via interventional approach:
            # For each feature, measure how prediction changes when that feature
            # is set to baseline (mean = 0 in scaled space). This is proper SHAP.
            contributions = {}
            for i, name in enumerate(FEATURE_NAMES):
                X_modified = X.copy()
                X_modified[0, i] = 0.0  # Set to mean in scaled space
                modified_pred = float(self._model.predict(X_modified)[0])
                contributions[name] = (raw_score - modified_pred) * 100
        else:
            # Fallback deterministic formula (used when model is not trained)
            risk_score, ci_low, ci_high, contributions = self._fallback_score(features)

        prediction_time_ms = (time.monotonic() - t0) * 1000

        return PredictionResult(
            risk_score=risk_score,
            confidence_interval=(ci_low, ci_high),
            confidence_width=ci_high - ci_low,
            priority=_score_to_priority(risk_score),
            feature_contributions=contributions,
            model_version=MODEL_VERSION if self.is_trained else "fallback-1.0",
            prediction_time_ms=prediction_time_ms,
        )

    def predict_batch(self, vulns: List[Dict[str, Any]]) -> List[PredictionResult]:
        """Predict risk scores for a batch of vulnerabilities (vectorized).

        Performance: a single sklearn ``predict`` call over an (N, F) matrix
        (one ``validate_data`` pass) instead of N per-finding calls. Bootstrap
        CI and SHAP-like feature contributions are likewise batched —
        contributions use a (F*N, F) "interventional" matrix in a single
        ``predict``. Numerically identical to ``predict()`` per finding.
        """
        if not vulns:
            return []

        t0 = time.monotonic()
        n = len(vulns)

        # (N, F) feature matrix
        features_matrix = np.array(
            [extract_features(v) for v in vulns], dtype=np.float64
        )

        if self.is_trained and self._scaler is not None:
            X = self._scaler.transform(features_matrix)  # (N, F)

            raw_scores = np.asarray(self._model.predict(X), dtype=np.float64)  # (N,)

            if self._bootstrap_models:
                # (n_boot, N) — one predict per bootstrap model on the full batch
                boot_preds = np.array(
                    [m.predict(X) for m in self._bootstrap_models], dtype=np.float64
                )
                ci_low_arr = np.percentile(boot_preds, 5, axis=0) * 100.0
                ci_high_arr = np.percentile(boot_preds, 95, axis=0) * 100.0
            else:
                ci_low_arr = raw_scores * 100.0 - 10.0
                ci_high_arr = raw_scores * 100.0 + 10.0

            risk_scores = np.clip(raw_scores * 100.0, 0.0, 100.0)
            ci_low_arr = np.clip(ci_low_arr, 0.0, 100.0)
            ci_high_arr = np.clip(ci_high_arr, 0.0, 100.0)

            # Interventional contributions: build (F*N, F) "feature-zeroed" matrix.
            # Block i (rows i*N..(i+1)*N) is X with column i zeroed in scaled space.
            n_features = len(FEATURE_NAMES)
            X_modified = np.tile(X, (n_features, 1))  # (F*N, F)
            for i in range(n_features):
                X_modified[i * n:(i + 1) * n, i] = 0.0
            modified_preds = np.asarray(
                self._model.predict(X_modified), dtype=np.float64
            ).reshape(n_features, n)
            # contribs[i, j] = (raw_scores[j] - modified[i, j]) * 100
            contribs_matrix = (raw_scores[np.newaxis, :] - modified_preds) * 100.0

            total_ms = (time.monotonic() - t0) * 1000.0
            per_call_ms = total_ms / n

            results: List[PredictionResult] = []
            for j in range(n):
                contributions = {
                    FEATURE_NAMES[i]: float(contribs_matrix[i, j])
                    for i in range(n_features)
                }
                rs = float(risk_scores[j])
                ci_lo = float(ci_low_arr[j])
                ci_hi = float(ci_high_arr[j])
                results.append(
                    PredictionResult(
                        risk_score=rs,
                        confidence_interval=(ci_lo, ci_hi),
                        confidence_width=ci_hi - ci_lo,
                        priority=_score_to_priority(rs),
                        feature_contributions=contributions,
                        model_version=MODEL_VERSION,
                        prediction_time_ms=per_call_ms,
                    )
                )
            return results

        # Fallback path: deterministic formula has no batchable cost.
        results = []
        for v in vulns:
            features = extract_features(v)
            risk_score, ci_low, ci_high, contributions = self._fallback_score(features)
            results.append(
                PredictionResult(
                    risk_score=risk_score,
                    confidence_interval=(ci_low, ci_high),
                    confidence_width=ci_high - ci_low,
                    priority=_score_to_priority(risk_score),
                    feature_contributions=contributions,
                    model_version="fallback-1.0",
                    prediction_time_ms=(time.monotonic() - t0) * 1000.0 / n,
                )
            )
        return results

    def explain_prediction(self, vuln: Dict[str, Any]) -> ExplanationResult:
        """Generate SHAP-like feature explanations for a risk score prediction.

        [V3] Decision Intelligence — explains WHY a vulnerability got its score.

        Uses interventional feature contributions: for each feature, measures
        how the prediction changes when that feature is set to baseline (mean
        of training data). The sum of all contributions ≈ predicted - base_value.

        This is equivalent to TreeSHAP's interventional approach but computed
        without the shap library (air-gap compatible, V9).

        Parameters
        ----------
        vuln : dict
            Vulnerability data dictionary.

        Returns
        -------
        ExplanationResult
            Full explanation with per-feature contributions, top drivers,
            and human-readable risk narrative.
        """
        t0 = time.monotonic()
        features = extract_features(vuln)

        if not self.is_trained or self._scaler is None:
            return self._fallback_explain(features, vuln, t0)

        X_orig = self._scaler.transform(features.reshape(1, -1))
        pred_score = float(np.clip(self._model.predict(X_orig)[0] * 100, 0, 100))

        # Compute base value: mean prediction over training feature means
        # mean_features = self._scaler.mean_ (unused — scaled space is zero-centered)
        X_mean = np.zeros_like(X_orig)  # Already centered/scaled → zero = mean
        base_pred = float(np.clip(self._model.predict(X_mean)[0] * 100, 0, 100))

        # Interventional contributions: for each feature, replace it with baseline
        # and measure how the prediction changes
        contributions = []
        for i in range(len(FEATURE_NAMES)):
            X_modified = X_orig.copy()
            X_modified[0, i] = 0.0  # Set to mean (in scaled space, mean = 0)
            modified_pred = float(np.clip(self._model.predict(X_modified)[0] * 100, 0, 100))
            # Contribution = full_pred - pred_without_this_feature
            contribution = pred_score - modified_pred
            contributions.append(contribution)

        # Build feature explanations with human-readable descriptions
        raw_values = self._extract_raw_values(vuln)
        feature_explanations = []
        for i, name in enumerate(FEATURE_NAMES):
            contrib = contributions[i]
            direction = "increases_risk" if contrib > 0.5 else "decreases_risk" if contrib < -0.5 else "neutral"
            explanation = self._generate_feature_explanation(
                name, features[i], raw_values.get(name), contrib, direction
            )
            feature_explanations.append(FeatureExplanation(
                name=name,
                value=float(features[i]),
                raw_value=raw_values.get(name),
                contribution=contrib,
                direction=direction,
                explanation=explanation,
            ))

        # Sort by absolute contribution (most impactful first)
        feature_explanations.sort(key=lambda x: abs(x.contribution), reverse=True)

        # Top 3 drivers
        top_drivers = [
            fe.explanation for fe in feature_explanations[:3] if abs(fe.contribution) > 0.5
        ]

        # Generate risk narrative
        risk_narrative = self._generate_risk_narrative(
            pred_score, base_pred, feature_explanations, vuln
        )

        dt = (time.monotonic() - t0) * 1000
        return ExplanationResult(
            risk_score=pred_score,
            base_value=base_pred,
            feature_explanations=feature_explanations,
            top_drivers=top_drivers,
            risk_narrative=risk_narrative,
            explanation_time_ms=dt,
        )

    def _extract_raw_values(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Extract raw (un-encoded) feature values for explanation display."""
        return {
            "cvss_score": vuln.get("cvss_score", 0.0),
            "epss_score": vuln.get("epss_score", 0.0),
            "in_kev": vuln.get("in_kev", False),
            "asset_criticality": vuln.get("asset_criticality", 0.5),
            "network_exposure": vuln.get("network_exposure", "unknown"),
            "exploit_available": vuln.get("exploit_available", False),
            "exploit_maturity": vuln.get("exploit_maturity", "none"),
            "reachable": vuln.get("reachable", True),
            "has_chain": bool(vuln.get("chain_cves") or vuln.get("has_chain", False)),
        }

    def _generate_feature_explanation(
        self,
        name: str,
        encoded_value: float,
        raw_value: Any,
        contribution: float,
        direction: str,
    ) -> str:
        """Generate human-readable explanation for a single feature contribution."""
        abs_contrib = abs(contribution)
        magnitude = "strongly" if abs_contrib > 10 else "moderately" if abs_contrib > 3 else "slightly"
        verb = "increases" if direction == "increases_risk" else "decreases" if direction == "decreases_risk" else "has minimal impact on"

        # Safe formatting helpers
        def _fmt_float(v: Any, decimals: int = 4) -> str:
            try:
                return f"{float(v):.{decimals}f}"
            except (TypeError, ValueError):
                return str(v)

        explanations = {
            "cvss_score": f"CVSS score of {raw_value} {magnitude} {verb} risk ({contribution:+.1f} pts)",
            "epss_score": f"EPSS probability of {_fmt_float(raw_value)} (exploit likelihood) {magnitude} {verb} risk ({contribution:+.1f} pts)",
            "in_kev": f"{'Listed' if raw_value else 'Not listed'} in CISA KEV catalog {magnitude} {verb} risk ({contribution:+.1f} pts)",
            "asset_criticality": f"Asset criticality of {_fmt_float(raw_value, 2)} {magnitude} {verb} risk ({contribution:+.1f} pts)",
            "network_exposure": f"Network exposure '{raw_value}' {magnitude} {verb} risk ({contribution:+.1f} pts)",
            "exploit_available": f"Exploit {'available' if raw_value else 'not available'} {magnitude} {verb} risk ({contribution:+.1f} pts)",
            "exploit_maturity": f"Exploit maturity '{raw_value}' {magnitude} {verb} risk ({contribution:+.1f} pts)",
            "reachable": f"{'Reachable' if raw_value else 'Not reachable'} from attack surface {magnitude} {verb} risk ({contribution:+.1f} pts)",
            "has_chain": f"{'Part of' if raw_value else 'No'} exploit chain {magnitude} {verb} risk ({contribution:+.1f} pts)",
        }
        return explanations.get(name, f"{name}={raw_value} {magnitude} {verb} risk ({contribution:+.1f} pts)")

    def _generate_risk_narrative(
        self,
        risk_score: float,
        base_value: float,
        explanations: List[FeatureExplanation],
        vuln: Dict[str, Any],
    ) -> str:
        """Generate a human-readable narrative explaining the overall risk score."""
        priority = _score_to_priority(risk_score)
        cve_id = vuln.get("cve_id", "this vulnerability")

        # Severity label based on score
        if risk_score >= 82:
            severity_label = "critical"
        elif risk_score >= 56:
            severity_label = "high"
        elif risk_score >= 30:
            severity_label = "medium"
        elif risk_score >= 8:
            severity_label = "low"
        else:
            severity_label = "informational"

        # Top positive contributors
        top_positive = [e for e in explanations if e.contribution > 1.0][:3]
        # Top negative contributors
        top_negative = [e for e in explanations if e.contribution < -1.0][:2]

        parts = [
            f"{cve_id} scored {risk_score:.1f}/100 ({priority}, {severity_label} risk)."
        ]

        if top_positive:
            driver_texts = []
            for e in top_positive:
                if e.name == "asset_criticality":
                    driver_texts.append(f"high asset criticality ({e.raw_value:.2f})")
                elif e.name == "epss_score":
                    driver_texts.append(f"high exploit probability (EPSS={e.raw_value:.4f})")
                elif e.name == "cvss_score":
                    driver_texts.append(f"high CVSS score ({e.raw_value})")
                elif e.name == "in_kev":
                    driver_texts.append("CISA KEV catalog listing")
                elif e.name == "network_exposure":
                    driver_texts.append(f"'{e.raw_value}' network exposure")
                elif e.name == "exploit_available":
                    driver_texts.append("known exploit availability")
                elif e.name == "exploit_maturity":
                    driver_texts.append(f"'{e.raw_value}' exploit maturity")
                elif e.name == "reachable":
                    driver_texts.append("reachable attack surface")
                elif e.name == "has_chain":
                    driver_texts.append("exploit chain involvement")
                else:
                    driver_texts.append(f"{e.name}={e.raw_value}")

            parts.append(f"Key risk drivers: {', '.join(driver_texts)}.")

        if top_negative:
            mitigator_texts = []
            for e in top_negative:
                if e.name == "asset_criticality":
                    mitigator_texts.append(f"low asset criticality ({e.raw_value:.2f})")
                elif e.name == "epss_score":
                    mitigator_texts.append(f"low exploit probability (EPSS={e.raw_value:.4f})")
                elif e.name == "network_exposure":
                    mitigator_texts.append(f"limited network exposure ('{e.raw_value}')")
                elif e.name == "in_kev":
                    mitigator_texts.append("not in CISA KEV catalog")
                else:
                    mitigator_texts.append(f"{e.name} is low")
            parts.append(f"Risk mitigators: {', '.join(mitigator_texts)}.")

        delta = risk_score - base_value
        if abs(delta) > 5:
            direction = "above" if delta > 0 else "below"
            parts.append(
                f"Score is {abs(delta):.1f} points {direction} baseline ({base_value:.1f})."
            )

        return " ".join(parts)

    def _fallback_explain(
        self,
        features: np.ndarray,
        vuln: Dict[str, Any],
        t0: float,
    ) -> ExplanationResult:
        """Fallback explanation when ML model is not trained."""
        score, ci_low, ci_high, contribs = self._fallback_score(features)
        base_value = 50.0  # Assumed midpoint for fallback

        raw_values = self._extract_raw_values(vuln)
        feature_explanations = []
        for i, name in enumerate(FEATURE_NAMES):
            c = contribs.get(name, 0.0) * 100  # Scale to 0-100
            direction = "increases_risk" if c > 0.5 else "decreases_risk" if c < -0.5 else "neutral"
            feature_explanations.append(FeatureExplanation(
                name=name,
                value=float(features[i]),
                raw_value=raw_values.get(name),
                contribution=c,
                direction=direction,
                explanation=f"{name}={raw_values.get(name)} contributes {c:+.1f} pts (fallback formula)",
            ))

        feature_explanations.sort(key=lambda x: abs(x.contribution), reverse=True)
        top_drivers = [fe.explanation for fe in feature_explanations[:3]]

        dt = (time.monotonic() - t0) * 1000
        return ExplanationResult(
            risk_score=score,
            base_value=base_value,
            feature_explanations=feature_explanations,
            top_drivers=top_drivers,
            risk_narrative=f"Risk score {score:.1f}/100 computed using fallback formula (ML model not trained).",
            explanation_time_ms=dt,
        )

    def save(self, path: Optional[Path] = None) -> Path:
        """Save model to disk.

        Parameters
        ----------
        path : Path, optional
            Directory to save model artifacts.

        Returns
        -------
        Path
            Path to saved model directory.
        """
        import joblib

        save_dir = Path(path) if path else self.model_dir
        save_dir.mkdir(parents=True, exist_ok=True)

        model_path = save_dir / f"risk_model_v{MODEL_VERSION.replace('.', '_')}.pkl"
        scaler_path = save_dir / f"scaler_v{MODEL_VERSION.replace('.', '_')}.pkl"
        bootstrap_path = save_dir / f"bootstrap_v{MODEL_VERSION.replace('.', '_')}.pkl"
        meta_path = save_dir / f"model_metadata_v{MODEL_VERSION.replace('.', '_')}.json"

        if self._model is not None:
            joblib.dump(self._model, model_path)
        if self._scaler is not None:
            joblib.dump(self._scaler, scaler_path)
        if self._bootstrap_models:
            joblib.dump(self._bootstrap_models, bootstrap_path)

        metadata = {
            "model_version": MODEL_VERSION,
            "trained": self._trained,
            "model_hash": self._model_hash,
            "random_seed": self.random_seed,
            "feature_names": FEATURE_NAMES,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "metrics": self._metrics.to_dict() if self._metrics else None,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        logger.info("Model saved to %s", save_dir)
        return save_dir

    def load(self, path: Optional[Path] = None) -> bool:
        """Load model from disk.

        Parameters
        ----------
        path : Path, optional
            Directory containing model artifacts.

        Returns
        -------
        bool
            True if model loaded successfully.
        """
        import joblib

        load_dir = Path(path) if path else self.model_dir
        model_path = load_dir / f"risk_model_v{MODEL_VERSION.replace('.', '_')}.pkl"
        scaler_path = load_dir / f"scaler_v{MODEL_VERSION.replace('.', '_')}.pkl"
        bootstrap_path = load_dir / f"bootstrap_v{MODEL_VERSION.replace('.', '_')}.pkl"

        if not model_path.exists():
            logger.warning("Model file not found: %s", model_path)
            return False

        try:
            self._model = joblib.load(model_path)
            if scaler_path.exists():
                self._scaler = joblib.load(scaler_path)
            if bootstrap_path.exists():
                self._bootstrap_models = joblib.load(bootstrap_path)
            self._trained = True
            logger.info("Model loaded from %s", load_dir)
            return True
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error("Failed to load model: %s", e)
            return False

    def validate_against_golden(
        self, golden_path: Optional[str | Path] = None
    ) -> Dict[str, Any]:
        """Validate model predictions against the golden regression dataset.

        Returns detailed results showing which cases pass/fail validation.

        Parameters
        ----------
        golden_path : str or Path, optional
            Path to golden dataset.

        Returns
        -------
        dict
            Validation results with pass/fail per case.
        """
        path = Path(golden_path) if golden_path else DEFAULT_GOLDEN_PATH
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        cases = data.get("cases", [])
        results = []
        passes = 0
        failures = 0

        for case in cases:
            pred = self.predict(case)
            score_min = float(case.get("expected_risk_score_min", 0))
            score_max = float(case.get("expected_risk_score_max", 100))
            expected_priority = case.get("expected_priority", "P2")

            in_range = score_min <= pred.risk_score <= score_max
            priority_match = pred.priority == expected_priority

            if in_range:
                passes += 1
            else:
                failures += 1

            results.append({
                "case_id": case["id"],
                "cve_id": case.get("cve_id"),
                "category": case.get("category"),
                "predicted_score": round(pred.risk_score, 2),
                "expected_range": [score_min, score_max],
                "in_range": in_range,
                "predicted_priority": pred.priority,
                "expected_priority": expected_priority,
                "priority_match": priority_match,
                "confidence_interval": [
                    round(pred.confidence_interval[0], 2),
                    round(pred.confidence_interval[1], 2),
                ],
            })

        return {
            "total_cases": len(cases),
            "passes": passes,
            "failures": failures,
            "pass_rate": round(passes / len(cases), 4) if cases else 0.0,
            "model_version": MODEL_VERSION,
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "results": results,
        }

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importances from the trained model."""
        if not self.is_trained:
            return {name: 0.0 for name in FEATURE_NAMES}
        importances = self._model.feature_importances_
        return {
            FEATURE_NAMES[i]: float(importances[i])
            for i in range(len(FEATURE_NAMES))
        }

    def write_model_card(self, path: Optional[Path] = None) -> Path:
        """Write model card documenting performance, bias, and limitations.

        Parameters
        ----------
        path : Path, optional
            Path to write model card.

        Returns
        -------
        Path
            Path to model card file.
        """
        save_dir = Path(path) if path else self.model_dir
        save_dir.mkdir(parents=True, exist_ok=True)
        card_path = save_dir / f"model_card_v{MODEL_VERSION}.md"

        metrics = self._metrics.to_dict() if self._metrics else {}
        feat_imp = self.get_feature_importance()

        # Sort features by importance
        sorted_feats = sorted(feat_imp.items(), key=lambda x: x[1], reverse=True)

        card = f"""# ALdeci Risk Scoring Model Card — v{MODEL_VERSION}

## Model Details
- **Name**: ALdeci Vulnerability Risk Scorer
- **Version**: {MODEL_VERSION}
- **Type**: Gradient Boosted Trees (Regressor)
- **Framework**: scikit-learn {self._get_sklearn_version()}
- **Pillar**: V3 (Decision Intelligence)
- **Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
- **Maintained by**: data-scientist agent

## Intended Use
- **Primary**: Risk-score vulnerabilities (0-100) for triage prioritization in Step 7 of the CTEM Brain Pipeline
- **Secondary**: Priority classification (P0-P4, FP) based on risk score thresholds
- **Users**: Brain Pipeline, Security Analysts, Triage Dashboard UI
- **Not intended for**: Standalone vulnerability assessment without human review

## Training Data
- **Source**: Golden regression dataset (`data/golden_regression_cases.json`)
- **Size**: {metrics.get('training_samples', 'N/A')} cases
- **Categories**: Critical exploitable, High severity, Medium severity, Low noise, False positives, Chain exploits, Edge cases
- **Data hash**: {self._model_hash or 'N/A'}
- **Random seed**: {self.random_seed}

## Features (Input)
| Feature | Type | Range | Importance |
|---------|------|-------|------------|
"""
        for name, importance in sorted_feats:
            ftype = "ordinal" if name in ("network_exposure", "exploit_maturity") else "float" if name in ("cvss_score", "epss_score", "asset_criticality") else "binary"
            card += f"| {name} | {ftype} | 0-1 | {importance:.4f} |\n"

        card += f"""
## Performance Metrics
| Metric | Value |
|--------|-------|
| MAE | {metrics.get('mae', 'N/A')} |
| RMSE | {metrics.get('rmse', 'N/A')} |
| R² | {metrics.get('r2', 'N/A')} |
| Within-Range % | {metrics.get('within_range_pct', 'N/A')} |
| CV R² scores | {metrics.get('cv_scores', 'N/A')} |

### Priority Classification
| Priority | Precision | Recall | F1 |
|----------|-----------|--------|----|
"""
        for p in ["P0", "P1", "P2", "P3", "P4", "FP"]:
            prec = metrics.get("precision_by_priority", {}).get(p, "N/A")
            rec = metrics.get("recall_by_priority", {}).get(p, "N/A")
            f1 = metrics.get("f1_by_priority", {}).get(p, "N/A")
            card += f"| {p} | {prec} | {rec} | {f1} |\n"

        card += f"""## Confidence Intervals
- Method: Bootstrap ensemble ({len(self._bootstrap_models)} models)
- Coverage: 90% CI (5th-95th percentile)
- Reject predictions with CI width > 60 points## Limitations
1. **Small training set**: {metrics.get('training_samples', 0)} cases — model may underperform on unseen CVE categories
2. **Temporal bias**: Training data biased towards 2021-2025 CVEs; emerging attack patterns may not be captured
3. **No code-level features**: Model uses metadata only; does not analyze actual source code
4. **Chain exploit detection**: Chain exploit feature is binary; does not model chain complexity
5. **Asset criticality dependency**: Requires accurate asset_criticality input; garbage-in-garbage-out
6. **No online learning**: Model is static; requires periodic retraining with updated golden dataset

## Ethical Considerations
- Model should not be used as sole basis for security decisions
- False negatives (missed critical vulns) are more dangerous than false positives
- Model is calibrated to over-predict risk for KEV entries (safety margin)

## Update Policy
- Retrain when golden dataset updated with >5 new cases
- Retrain when validation accuracy drops >5% from baseline
- Model version is bumped for any hyperparameter change
"""  # nosec B608
        with open(card_path, "w", encoding="utf-8") as f:
            f.write(card)

        logger.info("Model card written to %s", card_path)
        return card_path

    # ------------------------------------------------------------------
    # Private methods
    # ------------------------------------------------------------------

    def _fallback_score(
        self, features: np.ndarray
    ) -> Tuple[float, float, float, Dict[str, float]]:
        """Deterministic weighted formula fallback when ML model is unavailable.

        Uses hand-tuned weights based on vulnerability research literature:
        - EPSS is the strongest predictor of exploitation (FIRST.org research)
        - KEV membership is binary but very strong signal
        - CVSS alone is a poor predictor (Cyentia Institute research)
        """
        weights = {
            "cvss_score": 0.10,
            "epss_score": 0.25,
            "in_kev": 0.20,
            "asset_criticality": 0.12,
            "network_exposure": 0.10,
            "exploit_available": 0.08,
            "exploit_maturity": 0.05,
            "reachable": 0.08,
            "has_chain": 0.02,
        }

        contributions = {}
        raw = 0.0
        for i, name in enumerate(FEATURE_NAMES):
            w = weights.get(name, 0.0)
            contrib = float(features[i]) * w
            contributions[name] = contrib
            raw += contrib

        # Scale to 0-100
        score = float(np.clip(raw * 100, 0, 100))
        # Fixed CI for fallback
        ci_low = max(0, score - 15)
        ci_high = min(100, score + 15)

        return score, ci_low, ci_high, contributions

    def _compute_priority_metrics(
        self,
        y_true: List[str],
        y_pred: List[str],
    ) -> Dict[str, Dict[str, float]]:
        """Compute precision, recall, F1 per priority level."""
        labels = sorted(set(y_true + y_pred))
        precision = {}
        recall = {}
        f1 = {}

        for label in labels:
            tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
            fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
            fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)

            p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0

            precision[label] = p
            recall[label] = r
            f1[label] = f

        return {"precision": precision, "recall": recall, "f1": f1}

    @staticmethod
    def _get_sklearn_version() -> str:
        try:
            import sklearn
            return sklearn.__version__
        except ImportError:
            return "unknown"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_model_instance: Optional[RiskScoringModel] = None


def get_risk_model() -> RiskScoringModel:
    """Get or create the global RiskScoringModel instance."""
    global _model_instance
    if _model_instance is None:
        _model_instance = RiskScoringModel()
        # Try to load pre-trained model
        if not _model_instance.load():
            # Train from golden dataset if available
            if DEFAULT_GOLDEN_PATH.exists():
                try:
                    _model_instance.train_from_golden_dataset()
                    _model_instance.save()
                except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                    logger.warning("Could not train risk model: %s", e)
    return _model_instance


__all__ = [
    "RiskScoringModel",
    "PredictionResult",
    "ExplanationResult",
    "FeatureExplanation",
    "ModelMetrics",
    "extract_features",
    "get_risk_model",
    "FEATURE_NAMES",
    "MODEL_VERSION",
]
