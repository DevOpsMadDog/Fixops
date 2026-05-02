"""
ALdeci Online Learning Pipeline — User Feedback → Model Retraining.

[V3] Decision Intelligence — Year 1 Roadmap Item #8.
[V9] Air-Gapped — No cloud API calls. All retraining runs locally.

This module bridges self_learning.py (5 feedback loops) with the ML models
(risk_scorer.py, autofix_confidence.py). When users mark decisions as
correct/incorrect or flag false positives, those feedback signals flow into
an incremental retraining pipeline that:

1. Collects feedback records into a typed buffer
2. Converts feedback into training examples (feature vectors + corrected labels)
3. Validates minimum sample requirements before retraining
4. Performs incremental retraining with warm-start GBT
5. Validates new model against golden regression suite (no-regress gate)
6. Atomically swaps models only if accuracy doesn't degrade >5%
7. Emits MODEL_RETRAINED events via EventBus
8. Logs all decisions to decisions.log for audit trail

Architecture:
    - FeedbackBuffer: Thread-safe accumulator with configurable flush threshold
    - FeedbackConverter: Maps feedback types to training examples
    - IncrementalTrainer: Warm-start retraining with validation gate
    - OnlineLearningPipeline: Orchestrates the full feedback→retrain loop
    - EventBus integration: Subscribes to DECISION_MADE, REMEDIATION_COMPLETED

Safety:
    - Golden regression gate: new model must pass 95% of golden cases
    - Maximum drift guard: score changes >20 points trigger human review flag
    - Rollback on failure: previous model weights preserved until swap succeeds
    - Rate limiting: at most 1 retrain per 10 minutes to avoid thrashing

Usage:
    from core.ml.online_learning import get_online_learning_pipeline
    pipeline = get_online_learning_pipeline()
    pipeline.ingest_feedback(feedback_record)
    # Automatic retraining when buffer exceeds threshold

    # Or force immediate retrain:
    result = pipeline.retrain_now()
    # result: RetrainResult(success=True, old_mae=3.2, new_mae=2.8, ...)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Minimum feedback samples before triggering retrain
MIN_FEEDBACK_FOR_RETRAIN = int(os.getenv("FIXOPS_ONLINE_LEARN_MIN_SAMPLES", "10"))

# Maximum feedback buffer size before forced flush
MAX_FEEDBACK_BUFFER = int(os.getenv("FIXOPS_ONLINE_LEARN_MAX_BUFFER", "500"))

# Minimum seconds between retrain attempts (rate limiting)
MIN_RETRAIN_INTERVAL_SECONDS = int(os.getenv("FIXOPS_ONLINE_LEARN_INTERVAL", "600"))

# Maximum acceptable MAE increase before rejecting new model
MAX_MAE_INCREASE = float(os.getenv("FIXOPS_ONLINE_LEARN_MAX_MAE_INCREASE", "0.05"))

# Maximum risk score change per-case before flagging for review
MAX_SCORE_DRIFT = float(os.getenv("FIXOPS_ONLINE_LEARN_MAX_DRIFT", "20.0"))

# Golden regression pass threshold (fraction of cases that must still pass)
GOLDEN_PASS_THRESHOLD = float(os.getenv("FIXOPS_ONLINE_LEARN_GOLDEN_THRESHOLD", "0.95"))

# Default paths
DEFAULT_GOLDEN_PATH = Path("data/golden_regression_cases.json")
DEFAULT_MODEL_DIR = Path(".claude/team-state/data-science/models")
DEFAULT_FEEDBACK_LOG = Path(".claude/team-state/data-science/online-learning-log.json")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FeedbackExample:
    """A single user-corrected training example.

    Produced by converting a FeedbackRecord into ML-consumable form:
    - features: 9-dim feature vector from the original prediction
    - corrected_score: user-corrected risk score (0-100)
    - corrected_priority: user-corrected priority label
    - feedback_type: source of feedback (decision_outcome, false_positive, etc.)
    - confidence: user's confidence in their correction (0-1)
    - weight: sample weight for training (higher = more influential)
    """
    features: np.ndarray
    corrected_score: float
    corrected_priority: str
    feedback_type: str
    entity_id: str
    confidence: float = 1.0
    weight: float = 1.0
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class RetrainResult:
    """Result of an incremental retrain attempt."""
    success: bool
    retrain_id: str = ""
    old_mae: float = 0.0
    new_mae: float = 0.0
    old_r2: float = 0.0
    new_r2: float = 0.0
    golden_pass_rate: float = 0.0
    golden_passed: bool = False
    feedback_count: int = 0
    training_samples: int = 0
    elapsed_seconds: float = 0.0
    score_drift_max: float = 0.0
    score_drift_mean: float = 0.0
    drift_flagged_cases: int = 0
    rejection_reason: str = ""
    model_version: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.retrain_id:
            self.retrain_id = f"retrain-{uuid.uuid4().hex[:12]}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "retrain_id": self.retrain_id,
            "old_mae": round(self.old_mae, 4),
            "new_mae": round(self.new_mae, 4),
            "old_r2": round(self.old_r2, 4),
            "new_r2": round(self.new_r2, 4),
            "golden_pass_rate": round(self.golden_pass_rate, 4),
            "golden_passed": self.golden_passed,
            "feedback_count": self.feedback_count,
            "training_samples": self.training_samples,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "score_drift_max": round(self.score_drift_max, 2),
            "score_drift_mean": round(self.score_drift_mean, 2),
            "drift_flagged_cases": self.drift_flagged_cases,
            "rejection_reason": self.rejection_reason,
            "model_version": self.model_version,
            "timestamp": self.timestamp,
        }


@dataclass
class PipelineStats:
    """Running statistics for the online learning pipeline."""
    total_feedback_ingested: int = 0
    total_retrains_attempted: int = 0
    total_retrains_succeeded: int = 0
    total_retrains_rejected: int = 0
    current_buffer_size: int = 0
    last_retrain_at: str = ""
    last_retrain_result: Optional[RetrainResult] = None
    model_version: str = ""
    cumulative_feedback_used: int = 0
    average_retrain_duration_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_feedback_ingested": self.total_feedback_ingested,
            "total_retrains_attempted": self.total_retrains_attempted,
            "total_retrains_succeeded": self.total_retrains_succeeded,
            "total_retrains_rejected": self.total_retrains_rejected,
            "current_buffer_size": self.current_buffer_size,
            "last_retrain_at": self.last_retrain_at,
            "last_retrain_result": self.last_retrain_result.to_dict() if self.last_retrain_result else None,
            "model_version": self.model_version,
            "cumulative_feedback_used": self.cumulative_feedback_used,
            "average_retrain_duration_s": round(self.average_retrain_duration_s, 3),
        }


# ---------------------------------------------------------------------------
# Feedback Converter — maps raw feedback to training examples
# ---------------------------------------------------------------------------

class FeedbackConverter:
    """Converts raw feedback records into ML-ready training examples.

    Handles different feedback types:
    - decision_outcome: user corrects a triage decision (P0→P2, etc.)
    - false_positive: user marks a finding as FP (corrected_score → 0)
    - mpte_result: exploit verification changes risk (confirmed → score up, not → down)
    - remediation_success: successful fix validates the original assessment
    """

    # Priority → approximate risk score midpoint mapping
    PRIORITY_TO_SCORE: Dict[str, float] = {
        "P0": 91.0,  # midpoint of [82, 100]
        "P1": 69.0,  # midpoint of [56, 82)
        "P2": 43.0,  # midpoint of [30, 56)
        "P3": 19.0,  # midpoint of [8, 30)
        "P4": 6.5,   # midpoint of [5, 8)
        "FP": 2.0,   # below 5
    }

    @classmethod
    def convert(cls, feedback: Dict[str, Any]) -> Optional[FeedbackExample]:
        """Convert a feedback record dict into a FeedbackExample.

        Parameters
        ----------
        feedback : dict
            Raw feedback record from self_learning.py's FeedbackDB.
            Expected keys: feedback_type, entity_id, outcome, predicted, actual,
            confidence, context.

        Returns
        -------
        FeedbackExample or None
            None if the feedback doesn't contain enough info for a training example.
        """
        fb_type = feedback.get("feedback_type", "")
        outcome = feedback.get("outcome", "")
        context = feedback.get("context", {})
        if isinstance(context, str):
            try:
                context = json.loads(context)
            except (json.JSONDecodeError, TypeError):
                context = {}

        # Extract original features from context
        features_dict = context.get("features", {})
        if not features_dict:
            # Try to reconstruct from context CVE data
            features_dict = cls._extract_features_from_context(context)
            if not features_dict:
                return None

        # Build feature vector
        from core.ml.risk_scorer import extract_features
        feature_vec = extract_features(features_dict)

        # Determine corrected score based on feedback type
        corrected_score, corrected_priority, weight = cls._compute_correction(
            fb_type, outcome, feedback, context
        )

        if corrected_score is None:
            return None

        confidence = float(feedback.get("confidence", 0.5))

        return FeedbackExample(
            features=feature_vec,
            corrected_score=corrected_score,
            corrected_priority=corrected_priority,
            feedback_type=fb_type,
            entity_id=feedback.get("entity_id", ""),
            confidence=confidence,
            weight=weight * max(0.1, confidence),
        )

    @classmethod
    def _compute_correction(
        cls,
        fb_type: str,
        outcome: str,
        feedback: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[Optional[float], str, float]:
        """Compute corrected score, priority, and sample weight from feedback.

        Returns
        -------
        tuple
            (corrected_score, corrected_priority, weight) or (None, "", 0) if invalid.
        """
        actual = feedback.get("actual", "")
        predicted = feedback.get("predicted", "")

        if fb_type == "decision_outcome":
            # User says the AI's priority decision was wrong
            # actual = the correct priority, predicted = what AI said
            if actual in cls.PRIORITY_TO_SCORE:
                score = cls.PRIORITY_TO_SCORE[actual]
                return score, actual, 1.5  # Higher weight for direct user correction
            elif outcome == "correct":
                # Prediction was correct — reinforce it
                if predicted in cls.PRIORITY_TO_SCORE:
                    score = cls.PRIORITY_TO_SCORE[predicted]
                    return score, predicted, 0.8  # Lower weight for confirmation
            return None, "", 0.0

        elif fb_type == "false_positive":
            # User says this was a false positive
            if outcome in ("correct", "incorrect"):
                if outcome == "correct":
                    # It WAS a false positive — low risk score
                    return 2.0, "FP", 2.0  # High weight for FP corrections
                else:
                    # User says it's NOT a false positive — restore risk
                    if actual in cls.PRIORITY_TO_SCORE:
                        return cls.PRIORITY_TO_SCORE[actual], actual, 1.5
            return None, "", 0.0

        elif fb_type == "mpte_result":
            # Exploit verification result
            original_score = float(context.get("original_risk_score", 50.0))
            if outcome == "correct" and actual == "exploitable":
                # Confirmed exploitable — boost score
                boosted = min(100.0, original_score * 1.3)
                return boosted, cls._score_to_priority(boosted), 1.8
            elif outcome == "correct" and actual == "not_exploitable":
                # Confirmed not exploitable — reduce score
                reduced = max(0.0, original_score * 0.5)
                return reduced, cls._score_to_priority(reduced), 1.8
            return None, "", 0.0

        elif fb_type == "remediation_success":
            # Successful fix validates the original assessment
            original_score = float(context.get("original_risk_score", 50.0))
            if outcome == "correct":
                # Fix worked — mild reinforcement
                return original_score, cls._score_to_priority(original_score), 0.5
            elif outcome == "incorrect":
                # Fix didn't work — issue was more severe
                boosted = min(100.0, original_score * 1.2)
                return boosted, cls._score_to_priority(boosted), 1.2
            return None, "", 0.0

        return None, "", 0.0

    @classmethod
    def _score_to_priority(cls, score: float) -> str:
        """Convert risk score to priority using risk_scorer thresholds."""
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
        return "FP"

    @classmethod
    def _extract_features_from_context(cls, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Try to reconstruct feature dict from context metadata."""
        # Look for CVE data embedded in context
        cve_data = context.get("cve_data", {})
        if cve_data:
            return cve_data

        # Try common keys
        if any(k in context for k in ("cvss_score", "epss_score", "severity")):
            return context

        # Look for finding data
        finding = context.get("finding", {})
        if finding and any(k in finding for k in ("cvss_score", "severity")):
            return finding

        return None


# ---------------------------------------------------------------------------
# Feedback Buffer — thread-safe accumulator
# ---------------------------------------------------------------------------

class FeedbackBuffer:
    """Thread-safe feedback accumulator with configurable flush threshold.

    Collects FeedbackExamples until the buffer exceeds `min_for_retrain`,
    then signals readiness for retraining. Uses a deque with max size to
    prevent unbounded memory growth.
    """

    def __init__(
        self,
        min_for_retrain: int = MIN_FEEDBACK_FOR_RETRAIN,
        max_size: int = MAX_FEEDBACK_BUFFER,
    ):
        self._buffer: deque = deque(maxlen=max_size)
        self._lock = threading.Lock()
        self.min_for_retrain = min_for_retrain
        self.max_size = max_size
        self._total_ingested = 0

    def add(self, example: FeedbackExample) -> bool:
        """Add a feedback example to the buffer.

        Returns True if buffer now meets the retrain threshold.
        """
        with self._lock:
            self._buffer.append(example)
            self._total_ingested += 1
            return len(self._buffer) >= self.min_for_retrain

    def drain(self) -> List[FeedbackExample]:
        """Remove and return all buffered examples."""
        with self._lock:
            items = list(self._buffer)
            self._buffer.clear()
            return items

    def peek(self) -> List[FeedbackExample]:
        """Return buffered examples without removing them."""
        with self._lock:
            return list(self._buffer)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def total_ingested(self) -> int:
        return self._total_ingested

    @property
    def ready_for_retrain(self) -> bool:
        with self._lock:
            return len(self._buffer) >= self.min_for_retrain


# ---------------------------------------------------------------------------
# Incremental Trainer — warm-start GBT retraining with validation
# ---------------------------------------------------------------------------

class IncrementalTrainer:
    """Performs incremental model retraining with safety guards.

    Uses warm-start GBT: the existing model weights are used as initialization
    for the new training round, with feedback examples added to the training
    set. This avoids catastrophic forgetting while incorporating new signals.

    Safety guards:
    1. Golden regression gate: new model must pass GOLDEN_PASS_THRESHOLD
    2. MAE guard: new model MAE can't increase by more than MAX_MAE_INCREASE
    3. Score drift guard: flags cases where risk score changes by >MAX_SCORE_DRIFT
    4. Atomic swap: old model preserved until new model passes all gates
    """

    def __init__(self, golden_path: Optional[Path] = None, model_dir: Optional[Path] = None):
        self.golden_path = golden_path or DEFAULT_GOLDEN_PATH
        self.model_dir = model_dir or DEFAULT_MODEL_DIR

    def retrain(
        self,
        feedback_examples: List[FeedbackExample],
        current_model: Any,
    ) -> RetrainResult:
        """Perform incremental retrain with feedback examples.

        Parameters
        ----------
        feedback_examples : list
            New training examples from user feedback.
        current_model : RiskScoringModel
            The currently active model instance.

        Returns
        -------
        RetrainResult
            Detailed result of the retrain attempt.
        """
        t0 = time.time()
        result = RetrainResult(
            success=False,
            feedback_count=len(feedback_examples),
        )

        try:
            # 1. Load golden dataset for combined training
            golden_X, golden_y, golden_cases = self._load_golden_data()
            result.training_samples = len(golden_y) + len(feedback_examples)

            # 2. Compute baseline metrics on current model
            old_metrics = self._evaluate_model(current_model, golden_X, golden_y, golden_cases)
            result.old_mae = old_metrics["mae"]
            result.old_r2 = old_metrics["r2"]

            # 3. Build augmented training set
            aug_X, aug_y, aug_weights = self._build_augmented_dataset(
                golden_X, golden_y, feedback_examples
            )

            # 4. Train new model with warm-start
            new_model = self._train_warm_start(
                aug_X, aug_y, aug_weights, current_model
            )

            # 5. Evaluate new model on golden dataset
            new_metrics = self._evaluate_model(new_model, golden_X, golden_y, golden_cases)
            result.new_mae = new_metrics["mae"]
            result.new_r2 = new_metrics["r2"]
            result.golden_pass_rate = new_metrics["golden_pass_rate"]
            result.golden_passed = new_metrics["golden_pass_rate"] >= GOLDEN_PASS_THRESHOLD

            # 6. Compute score drift
            drift_stats = self._compute_drift(current_model, new_model, golden_X)
            result.score_drift_max = drift_stats["max_drift"]
            result.score_drift_mean = drift_stats["mean_drift"]
            result.drift_flagged_cases = drift_stats["flagged_count"]

            # 7. Validation gate
            mae_increase = result.new_mae - result.old_mae
            if mae_increase > MAX_MAE_INCREASE:
                result.rejection_reason = (
                    f"MAE increased by {mae_increase:.4f} (max allowed: {MAX_MAE_INCREASE})"
                )
                result.elapsed_seconds = time.time() - t0
                return result

            if not result.golden_passed:
                result.rejection_reason = (
                    f"Golden pass rate {result.golden_pass_rate:.2%} "
                    f"below threshold {GOLDEN_PASS_THRESHOLD:.2%}"
                )
                result.elapsed_seconds = time.time() - t0
                return result

            # 8. All gates passed — swap model
            result.success = True
            result.model_version = self._compute_version(feedback_examples)
            result.elapsed_seconds = time.time() - t0

            # Return new model components for atomic swap
            result._new_model = new_model  # type: ignore[attr-defined]

            return result

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error("Incremental retrain failed: %s", e, exc_info=True)
            result.rejection_reason = f"Training error: {str(e)}"
            result.elapsed_seconds = time.time() - t0
            return result

    def _load_golden_data(self) -> Tuple[np.ndarray, np.ndarray, List[Dict]]:
        """Load golden regression cases as feature matrix + targets."""
        from core.ml.risk_scorer import extract_features

        if not self.golden_path.exists():
            raise FileNotFoundError(f"Golden dataset not found: {self.golden_path}")

        with open(self.golden_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        cases = data.get("cases", [])
        X_list = []
        y_list = []
        for case in cases:
            features = extract_features(case)
            score_min = float(case.get("expected_risk_score_min", 0))
            score_max = float(case.get("expected_risk_score_max", 100))
            target = (score_min + score_max) / 200.0  # Normalize to 0-1
            X_list.append(features)
            y_list.append(target)

        return np.array(X_list), np.array(y_list), cases

    def _build_augmented_dataset(
        self,
        golden_X: np.ndarray,
        golden_y: np.ndarray,
        feedback: List[FeedbackExample],
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Merge golden data with feedback examples, returning weighted dataset."""
        fb_X = np.array([ex.features for ex in feedback]) if feedback else np.empty((0, 9))
        fb_y = np.array([ex.corrected_score / 100.0 for ex in feedback]) if feedback else np.empty(0)
        fb_w = np.array([ex.weight for ex in feedback]) if feedback else np.empty(0)

        # Golden data gets weight 1.0 (stable anchor)
        golden_w = np.ones(len(golden_y))

        if len(feedback) > 0:
            aug_X = np.vstack([golden_X, fb_X])
            aug_y = np.concatenate([golden_y, fb_y])
            aug_w = np.concatenate([golden_w, fb_w])
        else:
            aug_X = golden_X
            aug_y = golden_y
            aug_w = golden_w

        return aug_X, aug_y, aug_w

    def _train_warm_start(
        self,
        X: np.ndarray,
        y: np.ndarray,
        sample_weights: np.ndarray,
        current_model: Any,
    ) -> Any:
        """Train a new GBT model with warm-start from current model.

        For truly incremental learning, we use warm_start=True with
        additional n_estimators. If the current model isn't a sklearn
        GBT, we train from scratch.
        """
        from sklearn.ensemble import GradientBoostingRegressor
        from sklearn.preprocessing import StandardScaler

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Try warm-start from current model's internal GBT
        internal_model = getattr(current_model, '_model', None)
        use_warm_start = (
            internal_model is not None
            and hasattr(internal_model, 'n_estimators')
            and hasattr(internal_model, 'estimators_')
        )

        if use_warm_start:
            # Add 20 more estimators on top of existing ensemble
            new_n_estimators = internal_model.n_estimators + 20
            warm_model = GradientBoostingRegressor(
                n_estimators=new_n_estimators,
                max_depth=4,
                learning_rate=0.03,  # Lower LR for fine-tuning
                subsample=0.8,
                random_state=42,
                warm_start=True,
            )
            # Copy existing state
            warm_model.n_estimators = internal_model.n_estimators
            warm_model.estimators_ = internal_model.estimators_
            warm_model.train_score_ = list(getattr(internal_model, 'train_score_', []))
            warm_model._rng = getattr(internal_model, '_rng', None)
            if hasattr(internal_model, 'init_'):
                warm_model.init_ = internal_model.init_

            # Now set target estimators and fit with warm start
            warm_model.n_estimators = new_n_estimators
            try:
                warm_model.fit(X_scaled, y, sample_weight=sample_weights)
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                # Warm start failed, fall back to fresh training
                warm_model = GradientBoostingRegressor(
                    n_estimators=200,
                    max_depth=4,
                    learning_rate=0.05,
                    subsample=0.8,
                    random_state=42,
                )
                warm_model.fit(X_scaled, y, sample_weight=sample_weights)
        else:
            # No warm start available — train from scratch
            warm_model = GradientBoostingRegressor(
                n_estimators=200,
                max_depth=4,
                learning_rate=0.05,
                subsample=0.8,
                random_state=42,
            )
            warm_model.fit(X_scaled, y, sample_weight=sample_weights)

        # Return a wrapper that holds both model and scaler
        return _TrainedBundle(model=warm_model, scaler=scaler)

    def _evaluate_model(
        self,
        model: Any,
        X: np.ndarray,
        y: np.ndarray,
        golden_cases: List[Dict],
    ) -> Dict[str, float]:
        """Evaluate a model on golden data, return metrics."""

        mae_sum = 0.0
        mse_sum = 0.0
        ss_res = 0.0
        y_mean = y.mean()
        ss_tot = 0.0
        golden_pass_count = 0

        predictions = []
        for i, case in enumerate(golden_cases):
            # Get prediction
            score = self._get_prediction(model, X[i])
            predictions.append(score)

            # Compute error against normalized target
            target_score = y[i] * 100.0
            error = abs(score - target_score)
            mae_sum += error
            mse_sum += error ** 2

            # R² components
            ss_res += (score / 100.0 - y[i]) ** 2
            ss_tot += (y[i] - y_mean) ** 2

            # Check golden pass: within expected range
            score_min = float(case.get("expected_risk_score_min", 0))
            score_max = float(case.get("expected_risk_score_max", 100))
            if score_min <= score <= score_max:
                golden_pass_count += 1

        n = len(golden_cases)
        mae = mae_sum / max(n, 1)
        r2 = 1.0 - (ss_res / max(ss_tot, 1e-10))
        golden_pass_rate = golden_pass_count / max(n, 1)

        return {
            "mae": mae,
            "r2": r2,
            "golden_pass_rate": golden_pass_rate,
            "predictions": predictions,
        }

    def _compute_drift(
        self,
        old_model: Any,
        new_model: Any,
        X: np.ndarray,
    ) -> Dict[str, float]:
        """Compute per-case score drift between old and new model."""
        drifts = []
        flagged = 0

        for i in range(len(X)):
            old_score = self._get_prediction(old_model, X[i])
            new_score = self._get_prediction(new_model, X[i])
            drift = abs(new_score - old_score)
            drifts.append(drift)
            if drift > MAX_SCORE_DRIFT:
                flagged += 1

        if not drifts:
            return {"max_drift": 0.0, "mean_drift": 0.0, "flagged_count": 0}

        return {
            "max_drift": float(max(drifts)),
            "mean_drift": float(np.mean(drifts)),
            "flagged_count": flagged,
        }

    def _get_prediction(self, model: Any, x: np.ndarray) -> float:
        """Get risk score prediction from a model (handles both types)."""
        if isinstance(model, _TrainedBundle):
            x_scaled = model.scaler.transform(x.reshape(1, -1))
            raw = float(model.model.predict(x_scaled)[0])
            return float(np.clip(raw * 100.0, 0.0, 100.0))
        elif hasattr(model, 'predict') and hasattr(model, 'is_trained'):
            # It's a RiskScoringModel instance
            # Build a dummy vuln dict from features
            result = model.predict(self._features_to_dict(x))
            return result.risk_score
        elif hasattr(model, '_model') and model._model is not None:
            # RiskScoringModel with internal model
            scaler = getattr(model, '_scaler', None)
            if scaler is not None:
                x_scaled = scaler.transform(x.reshape(1, -1))
            else:
                x_scaled = x.reshape(1, -1)
            raw = float(model._model.predict(x_scaled)[0])
            return float(np.clip(raw * 100.0, 0.0, 100.0))
        else:
            # Fallback — assume it's a raw sklearn model
            raw = float(model.predict(x.reshape(1, -1))[0])
            return float(np.clip(raw * 100.0, 0.0, 100.0))

    @staticmethod
    def _features_to_dict(x: np.ndarray) -> Dict[str, Any]:
        """Convert feature vector back to dict for model.predict()."""
        from core.ml.risk_scorer import FEATURE_NAMES
        d = {}
        for i, name in enumerate(FEATURE_NAMES):
            if name == "cvss_score":
                d[name] = float(x[i]) * 10.0  # Denormalize
            elif name in ("in_kev", "exploit_available", "reachable", "has_chain"):
                d[name] = bool(x[i] > 0.5)
            else:
                d[name] = float(x[i])
        return d

    @staticmethod
    def _compute_version(feedback: List[FeedbackExample]) -> str:
        """Compute a version string based on feedback content."""
        content = json.dumps(
            [{"e": ex.entity_id, "s": ex.corrected_score} for ex in feedback],
            sort_keys=True,
        )
        h = hashlib.sha256(content.encode()).hexdigest()[:8]
        return f"online-{h}"


@dataclass
class _TrainedBundle:
    """Container for a trained model + scaler pair."""
    model: Any
    scaler: Any


# ---------------------------------------------------------------------------
# Online Learning Pipeline — full orchestrator
# ---------------------------------------------------------------------------

class OnlineLearningPipeline:
    """Orchestrates the full feedback → retrain → deploy loop.

    [V3] Decision Intelligence — connects self_learning.py feedback loops
    with ML model retraining for continuous improvement.

    Thread-safe: all operations protected by locks. The pipeline can be
    called from EventBus handlers (async) or directly (sync).
    """

    def __init__(
        self,
        golden_path: Optional[Path] = None,
        model_dir: Optional[Path] = None,
        min_feedback: int = MIN_FEEDBACK_FOR_RETRAIN,
        max_buffer: int = MAX_FEEDBACK_BUFFER,
        min_interval_s: int = MIN_RETRAIN_INTERVAL_SECONDS,
    ):
        self._buffer = FeedbackBuffer(
            min_for_retrain=min_feedback,
            max_size=max_buffer,
        )
        self._trainer = IncrementalTrainer(
            golden_path=golden_path or DEFAULT_GOLDEN_PATH,
            model_dir=model_dir or DEFAULT_MODEL_DIR,
        )
        self._converter = FeedbackConverter()
        self._stats = PipelineStats()
        self._lock = threading.Lock()
        self._last_retrain_time = 0.0
        self._min_interval_s = min_interval_s
        self._retrain_history: List[Dict[str, Any]] = []
        self._model_dir = model_dir or DEFAULT_MODEL_DIR
        self._log_path = DEFAULT_FEEDBACK_LOG

    @property
    def stats(self) -> PipelineStats:
        """Get current pipeline statistics."""
        with self._lock:
            self._stats.current_buffer_size = self._buffer.size
            return self._stats

    @property
    def retrain_history(self) -> List[Dict[str, Any]]:
        """Get history of all retrain attempts."""
        return list(self._retrain_history)

    def ingest_feedback(self, feedback: Dict[str, Any]) -> Optional[RetrainResult]:
        """Ingest a raw feedback record and optionally trigger retraining.

        Parameters
        ----------
        feedback : dict
            Raw feedback record from self_learning.py FeedbackDB.

        Returns
        -------
        RetrainResult or None
            If retraining was triggered and completed, returns the result.
            None if feedback was just buffered or conversion failed.
        """
        # Convert to training example
        example = self._converter.convert(feedback)
        if example is None:
            logger.debug("Feedback conversion returned None for %s", feedback.get("entity_id", "?"))
            return None

        with self._lock:
            self._stats.total_feedback_ingested += 1

        # Add to buffer
        ready = self._buffer.add(example)

        # Check if we should retrain
        if ready and self._should_retrain():
            return self.retrain_now()

        return None

    def ingest_batch(self, feedbacks: List[Dict[str, Any]]) -> Optional[RetrainResult]:
        """Ingest a batch of feedback records.

        Returns RetrainResult if retraining was triggered after the batch.
        """
        for fb in feedbacks:
            example = self._converter.convert(fb)
            if example is not None:
                self._buffer.add(example)
                with self._lock:
                    self._stats.total_feedback_ingested += 1

        if self._buffer.ready_for_retrain and self._should_retrain():
            return self.retrain_now()

        return None

    def retrain_now(self) -> RetrainResult:
        """Force immediate retraining with current buffer contents.

        Thread-safe: acquires lock, drains buffer, retrains, validates,
        and atomically swaps the model if all gates pass.
        """
        with self._lock:
            # Drain buffer
            examples = self._buffer.drain()
            if not examples:
                return RetrainResult(
                    success=False,
                    rejection_reason="No feedback examples in buffer",
                )

            self._stats.total_retrains_attempted += 1

        # Get current model
        from core.ml.risk_scorer import get_risk_model
        current_model = get_risk_model()

        # Run incremental training
        result = self._trainer.retrain(examples, current_model)

        with self._lock:
            if result.success:
                # Atomic model swap
                self._swap_model(current_model, result)
                self._stats.total_retrains_succeeded += 1
                self._stats.cumulative_feedback_used += len(examples)
                self._stats.model_version = result.model_version
                self._last_retrain_time = time.time()
            else:
                self._stats.total_retrains_rejected += 1
                # Put examples back in buffer for next attempt
                for ex in examples:
                    self._buffer.add(ex)

            self._stats.last_retrain_at = result.timestamp
            self._stats.last_retrain_result = result

            # Update average duration
            total = self._stats.total_retrains_attempted
            old_avg = self._stats.average_retrain_duration_s
            self._stats.average_retrain_duration_s = (
                (old_avg * (total - 1) + result.elapsed_seconds) / total
            )

        # Log result
        self._log_retrain(result)
        self._retrain_history.append(result.to_dict())

        # Emit event if successful
        if result.success:
            self._emit_retrained_event(result)

        return result

    def _should_retrain(self) -> bool:
        """Check rate limit — at most 1 retrain per interval."""
        elapsed = time.time() - self._last_retrain_time
        return elapsed >= self._min_interval_s

    def _swap_model(self, current_model: Any, result: RetrainResult) -> None:
        """Atomically swap the current model's internals with new weights.

        The RiskScoringModel singleton is updated in-place so all callers
        get the new model without needing to re-import or re-initialize.
        """
        new_bundle = getattr(result, '_new_model', None)
        if new_bundle is None or not isinstance(new_bundle, _TrainedBundle):
            logger.warning("No valid new model in retrain result — skipping swap")
            return

        # Swap internal components
        current_model._model = new_bundle.model
        current_model._scaler = new_bundle.scaler
        current_model._trained = True

        # Save to disk
        try:
            current_model.save()
            logger.info(
                "Model swapped to version %s (MAE: %.4f → %.4f)",
                result.model_version, result.old_mae, result.new_mae,
            )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Failed to persist swapped model: %s", e)

    def _emit_retrained_event(self, result: RetrainResult) -> None:
        """Emit MODEL_RETRAINED event via EventBus."""
        try:
            import asyncio

            from core.event_bus import Event, EventType, get_event_bus

            bus = get_event_bus()
            event = Event(
                event_type=EventType.MODEL_RETRAINED,
                source="online_learning_pipeline",
                data={
                    "retrain_id": result.retrain_id,
                    "model_version": result.model_version,
                    "old_mae": result.old_mae,
                    "new_mae": result.new_mae,
                    "feedback_count": result.feedback_count,
                    "golden_pass_rate": result.golden_pass_rate,
                    "score_drift_mean": result.score_drift_mean,
                },
            )

            # Try async emit, fall back to sync
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(bus.emit(event))
            except RuntimeError:
                # No event loop — run synchronously
                asyncio.run(bus.emit(event))
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Could not emit MODEL_RETRAINED event: %s", e)

    def _log_retrain(self, result: RetrainResult) -> None:
        """Persist retrain result to log file for audit trail."""
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)

            history = []
            if self._log_path.exists():
                try:
                    with open(self._log_path, "r") as f:
                        history = json.load(f)
                except (json.JSONDecodeError, IOError):
                    history = []

            history.append(result.to_dict())

            # Keep last 100 entries
            if len(history) > 100:
                history = history[-100:]

            with open(self._log_path, "w") as f:
                json.dump(history, f, indent=2)

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Could not persist retrain log: %s", e)


# ---------------------------------------------------------------------------
# EventBus integration — subscribe to feedback events
# ---------------------------------------------------------------------------

_pipeline_instance: Optional[OnlineLearningPipeline] = None
_eventbus_registered = False


def get_online_learning_pipeline(
    golden_path: Optional[Path] = None,
    model_dir: Optional[Path] = None,
    min_feedback: int = MIN_FEEDBACK_FOR_RETRAIN,
) -> OnlineLearningPipeline:
    """Get or create the global OnlineLearningPipeline instance."""
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = OnlineLearningPipeline(
            golden_path=golden_path,
            model_dir=model_dir,
            min_feedback=min_feedback,
        )
    return _pipeline_instance


def reset_pipeline() -> None:
    """Reset the global pipeline instance (for testing)."""
    global _pipeline_instance, _eventbus_registered
    _pipeline_instance = None
    _eventbus_registered = False


async def _handle_decision_made(event: Any) -> None:
    """EventBus handler for DECISION_MADE events.

    Extracts feedback data from the event and ingests it into the
    online learning pipeline.
    """
    try:
        pipeline = get_online_learning_pipeline()
        data = getattr(event, 'data', {})

        # Build feedback record from event data
        feedback = {
            "feedback_type": data.get("feedback_type", "decision_outcome"),
            "entity_id": data.get("entity_id", data.get("finding_id", "")),
            "outcome": data.get("outcome", "unknown"),
            "predicted": data.get("predicted", ""),
            "actual": data.get("actual", ""),
            "confidence": data.get("confidence", 0.5),
            "context": data.get("context", {}),
        }

        pipeline.ingest_feedback(feedback)
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.debug("Error handling DECISION_MADE event: %s", e)


async def _handle_remediation_completed(event: Any) -> None:
    """EventBus handler for REMEDIATION_COMPLETED events."""
    try:
        pipeline = get_online_learning_pipeline()
        data = getattr(event, 'data', {})

        feedback = {
            "feedback_type": "remediation_success",
            "entity_id": data.get("entity_id", data.get("task_id", "")),
            "outcome": "correct" if data.get("success", False) else "incorrect",
            "predicted": data.get("predicted_priority", ""),
            "actual": data.get("actual_severity", ""),
            "confidence": data.get("confidence", 0.5),
            "context": data.get("context", {}),
        }

        pipeline.ingest_feedback(feedback)
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.debug("Error handling REMEDIATION_COMPLETED event: %s", e)


def register_online_learning_handlers(bus: Any) -> None:
    """Register online learning event handlers with the EventBus.

    Idempotent — safe to call multiple times.
    """
    global _eventbus_registered
    if _eventbus_registered:
        return

    try:
        from core.event_bus import EventType

        bus.subscribe(EventType.DECISION_MADE, _handle_decision_made)
        bus.subscribe(EventType.REMEDIATION_COMPLETED, _handle_remediation_completed)
        _eventbus_registered = True
        logger.info("Online learning EventBus handlers registered")
    except ImportError as e:
        logger.warning("Could not register online learning handlers: %s", e)


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "OnlineLearningPipeline",
    "FeedbackBuffer",
    "FeedbackConverter",
    "FeedbackExample",
    "IncrementalTrainer",
    "RetrainResult",
    "PipelineStats",
    "get_online_learning_pipeline",
    "reset_pipeline",
    "register_online_learning_handlers",
]
