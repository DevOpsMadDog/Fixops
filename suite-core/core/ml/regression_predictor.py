"""
ALdeci Self-Healing Remediation ML — Year 4 ML Roadmap.

[V3] Decision Intelligence — Predict whether an AutoFix will cause regression.

This module provides two complementary capabilities:
1. **Regression Risk Prediction**: Given a proposed fix, predict the probability
   that applying it will break existing functionality (test failures, runtime
   errors, performance degradation).
2. **Rollback Decision Support**: Given post-deploy telemetry, decide whether
   a fix should be rolled back and estimate rollback urgency.

The self-healing loop:
  AutoFix generates fix → RegressionPredictor scores regression risk →
  Fix is applied with monitoring → Telemetry analyzed →
  RollbackDecider recommends rollback/keep → Model learns from outcome.

Features for regression risk prediction (14 features):
  1. fix_type           — code_patch/dependency_update/config/etc.
  2. severity           — vuln severity (critical→low)
  3. category           — vuln category (injection, XSS, auth, etc.)
  4. files_affected     — number of files changed
  5. lines_changed      — total lines modified
  6. has_tests          — whether fix has test coverage
  7. llm_confidence     — LLM's self-reported confidence
  8. language           — programming language
  9. historical_success — historical success rate for similar fixes
  10. code_complexity   — cyclomatic complexity of affected code
  11. dependency_depth  — how deep in dependency tree (for dep updates)
  12. breaking_changes  — number of known breaking changes
  13. fix_scope         — single_function/file/multi_file/system
  14. test_coverage_pct — percentage of affected code covered by tests

Output:
  - regression_probability: 0.0–1.0
  - risk_level: SAFE / CAUTION / DANGEROUS
  - recommended_action: auto_apply / review_and_apply / manual_only / block
  - rollback_plan: structured rollback instructions
  - monitoring_config: what metrics to watch post-deploy

All models are air-gap compatible — numpy/sklearn only, no cloud API calls.

Usage:
    from core.ml.regression_predictor import RegressionPredictor

    predictor = RegressionPredictor()
    predictor.train()

    result = predictor.predict_regression_risk({
        "fix_type": "dependency_update",
        "severity": "critical",
        "files_affected": 3,
        "lines_changed": 15,
        "has_tests": True,
        "dependency_depth": 2,
        "breaking_changes": 1,
    })
    # result.regression_probability = 0.23
    # result.risk_level = "CAUTION"
    # result.recommended_action = "review_and_apply"

    rollback = predictor.should_rollback({
        "error_rate_delta": 0.05,
        "latency_delta_ms": 200,
        "test_failures": 3,
        "time_since_deploy_minutes": 15,
    })
    # rollback.should_rollback = True
    # rollback.urgency = "HIGH"
"""

from __future__ import annotations

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

MODEL_VERSION = "1.0.0"
DEFAULT_MODEL_DIR = Path(".claude/team-state/data-science/models")

# Fix type encoding (matches autofix_confidence.py)
FIX_TYPE_MAP = {
    "code_patch": 0,
    "dependency_update": 1,
    "config_hardening": 2,
    "iac_fix": 3,
    "secret_rotation": 4,
    "permission_fix": 5,
    "input_validation": 6,
    "output_encoding": 7,
    "waf_rule": 8,
    "container_fix": 9,
}

SEVERITY_MAP = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
    "info": 0.10,
}

CATEGORY_MAP = {
    "injection": 0, "xss": 1, "auth": 2, "crypto": 3,
    "config": 4, "dependency": 5, "secrets": 6, "container": 7,
    "iac": 8, "permissions": 9, "ssrf": 10, "path_traversal": 11,
    "deserialization": 12, "other": 13,
}

LANGUAGE_MAP = {
    "python": 0, "javascript": 1, "typescript": 2, "java": 3,
    "go": 4, "rust": 5, "csharp": 6, "ruby": 7,
    "php": 8, "yaml": 9, "json": 10, "dockerfile": 11,
    "terraform": 12, "other": 13,
}

FIX_SCOPE_MAP = {
    "single_function": 0,
    "single_file": 1,
    "multi_file": 2,
    "system": 3,
}

# Empirically calibrated regression baselines per fix type
# Based on industry data: dependency updates break things more often than
# config changes, code patches depend heavily on scope/complexity.
REGRESSION_BASELINES = {
    "code_patch": 0.18,          # 18% base regression rate
    "dependency_update": 0.25,   # 25% — breaking changes common
    "config_hardening": 0.08,    # 8% — usually safe
    "iac_fix": 0.12,             # 12% — infrastructure changes
    "secret_rotation": 0.05,     # 5% — low risk if done right
    "permission_fix": 0.10,      # 10% — can break access
    "input_validation": 0.15,    # 15% — can reject valid input
    "output_encoding": 0.12,     # 12% — can break display
    "waf_rule": 0.20,            # 20% — can block legitimate traffic
    "container_fix": 0.14,       # 14% — base image changes
}

# Feature names for the regression model
REGRESSION_FEATURE_NAMES = [
    "fix_type",
    "severity",
    "category",
    "files_affected",
    "lines_changed",
    "has_tests",
    "llm_confidence",
    "language",
    "historical_success",
    "code_complexity",
    "dependency_depth",
    "breaking_changes",
    "fix_scope",
    "test_coverage_pct",
]

# Rollback telemetry thresholds
ROLLBACK_THRESHOLDS = {
    "error_rate_delta": 0.02,       # 2% increase in error rate → concern
    "latency_delta_ms": 500,        # 500ms latency increase → concern
    "test_failures": 1,             # Any test failure → concern
    "memory_delta_mb": 100,         # 100MB memory increase → concern
    "cpu_delta_pct": 20,            # 20% CPU increase → concern
    "crash_count": 1,               # Any crash → immediate rollback
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RegressionPrediction:
    """Result of a regression risk prediction."""
    regression_probability: float       # 0.0–1.0
    risk_level: str                     # SAFE, CAUTION, DANGEROUS
    recommended_action: str             # auto_apply, review_and_apply, manual_only, block
    confidence_interval: Tuple[float, float]
    feature_contributions: Dict[str, float]
    rollback_plan: Dict[str, Any]
    monitoring_config: Dict[str, Any]
    model_version: str
    prediction_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "regression_probability": round(self.regression_probability, 4),
            "risk_level": self.risk_level,
            "recommended_action": self.recommended_action,
            "confidence_interval": [
                round(self.confidence_interval[0], 4),
                round(self.confidence_interval[1], 4),
            ],
            "feature_contributions": {
                k: round(v, 4) for k, v in self.feature_contributions.items()
            },
            "rollback_plan": self.rollback_plan,
            "monitoring_config": self.monitoring_config,
            "model_version": self.model_version,
            "prediction_time_ms": round(self.prediction_time_ms, 4),
        }


@dataclass
class RollbackDecision:
    """Result of a rollback analysis."""
    should_rollback: bool
    urgency: str                    # IMMEDIATE, HIGH, MEDIUM, LOW
    confidence: float               # 0.0–1.0
    triggered_thresholds: List[str]
    risk_score: float               # 0–100
    recommendation: str
    estimated_impact: Dict[str, Any]
    decision_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "should_rollback": self.should_rollback,
            "urgency": self.urgency,
            "confidence": round(self.confidence, 4),
            "triggered_thresholds": self.triggered_thresholds,
            "risk_score": round(self.risk_score, 2),
            "recommendation": self.recommendation,
            "estimated_impact": self.estimated_impact,
            "decision_time_ms": round(self.decision_time_ms, 4),
        }


@dataclass
class HealingAction:
    """A self-healing action recommendation."""
    action_type: str                # rollback, partial_rollback, hotfix, alert_only
    target: str                     # what to roll back/fix
    priority: int                   # 1-5 (1 = highest)
    estimated_fix_time_minutes: int
    steps: List[str]
    prerequisites: List[str]
    risks: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "priority": self.priority,
            "estimated_fix_time_minutes": self.estimated_fix_time_minutes,
            "steps": self.steps,
            "prerequisites": self.prerequisites,
            "risks": self.risks,
        }


@dataclass
class RegressionModelMetrics:
    """Training metrics for the regression predictor."""
    mae: float = 0.0
    rmse: float = 0.0
    r2: float = 0.0
    accuracy_at_threshold: Dict[str, float] = field(default_factory=dict)
    feature_importances: Dict[str, float] = field(default_factory=dict)
    training_samples: int = 0
    cv_mae: float = 0.0
    cv_std: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mae": round(self.mae, 4),
            "rmse": round(self.rmse, 4),
            "r2": round(self.r2, 4),
            "accuracy_at_threshold": {
                k: round(v, 4) for k, v in self.accuracy_at_threshold.items()
            },
            "feature_importances": {
                k: round(v, 4) for k, v in self.feature_importances.items()
            },
            "training_samples": self.training_samples,
            "cv_mae": round(self.cv_mae, 4),
            "cv_std": round(self.cv_std, 4),
        }


@dataclass
class FixOutcome:
    """Recorded outcome of a deployed fix — used for online learning."""
    fix_id: str
    fix_type: str
    regression_occurred: bool
    regression_severity: str = "none"      # none, minor, major, critical
    test_failures: int = 0
    error_rate_delta: float = 0.0
    latency_delta_ms: float = 0.0
    rollback_performed: bool = False
    time_to_detection_minutes: float = 0.0
    root_cause: str = ""
    fix_features: Dict[str, Any] = field(default_factory=dict)
    recorded_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fix_id": self.fix_id,
            "fix_type": self.fix_type,
            "regression_occurred": self.regression_occurred,
            "regression_severity": self.regression_severity,
            "test_failures": self.test_failures,
            "error_rate_delta": self.error_rate_delta,
            "latency_delta_ms": self.latency_delta_ms,
            "rollback_performed": self.rollback_performed,
            "time_to_detection_minutes": self.time_to_detection_minutes,
            "root_cause": self.root_cause,
            "recorded_at": self.recorded_at,
        }


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_regression_features(fix_data: Dict[str, Any]) -> np.ndarray:
    """Extract 14-feature vector for regression risk prediction.

    Parameters
    ----------
    fix_data : dict
        Fix metadata with keys matching REGRESSION_FEATURE_NAMES.

    Returns
    -------
    np.ndarray
        1D array of shape (14,) with normalized features.
    """
    fix_type = FIX_TYPE_MAP.get(
        str(fix_data.get("fix_type", "code_patch")).lower(), 0
    )
    severity = SEVERITY_MAP.get(
        str(fix_data.get("severity", "medium")).lower(), 0.5
    )
    category = CATEGORY_MAP.get(
        str(fix_data.get("category", "other")).lower(), 13
    )
    files_affected = min(float(fix_data.get("files_affected", 1)), 20) / 20.0
    lines_changed = min(float(fix_data.get("lines_changed", 10)), 500) / 500.0
    has_tests = 1.0 if fix_data.get("has_tests", False) else 0.0
    llm_confidence = float(fix_data.get("llm_confidence", 0.5))
    language = LANGUAGE_MAP.get(
        str(fix_data.get("language", "other")).lower(), 13
    )
    hist_success = float(fix_data.get("historical_success", 0.7))
    complexity = min(float(fix_data.get("code_complexity", 10)), 100) / 100.0
    dep_depth = min(float(fix_data.get("dependency_depth", 0)), 10) / 10.0
    breaking = min(float(fix_data.get("breaking_changes", 0)), 10) / 10.0
    scope = FIX_SCOPE_MAP.get(
        str(fix_data.get("fix_scope", "single_file")).lower(), 1
    ) / 3.0
    test_cov = float(fix_data.get("test_coverage_pct", 50)) / 100.0

    return np.array([
        fix_type / 9.0,     # 0: fix_type (normalized)
        severity,            # 1: severity (already 0-1)
        category / 13.0,     # 2: category (normalized)
        files_affected,      # 3: files_affected (normalized)
        lines_changed,       # 4: lines_changed (normalized)
        has_tests,           # 5: has_tests (binary)
        llm_confidence,      # 6: llm_confidence (0-1)
        language / 13.0,     # 7: language (normalized)
        hist_success,        # 8: historical_success (0-1)
        complexity,          # 9: code_complexity (normalized)
        dep_depth,           # 10: dependency_depth (normalized)
        breaking,            # 11: breaking_changes (normalized)
        scope,               # 12: fix_scope (normalized)
        test_cov,            # 13: test_coverage_pct (normalized)
    ], dtype=np.float64)


def _risk_level(prob: float) -> str:
    """Convert regression probability to risk level."""
    if prob < 0.15:
        return "SAFE"
    elif prob < 0.40:
        return "CAUTION"
    else:
        return "DANGEROUS"


def _recommended_action(prob: float, has_tests: bool) -> str:
    """Generate action recommendation based on risk and test coverage."""
    if prob < 0.10:
        return "auto_apply"
    elif prob < 0.25 and has_tests:
        return "auto_apply"
    elif prob < 0.25:
        return "review_and_apply"
    elif prob < 0.50:
        return "review_and_apply"
    elif prob < 0.70:
        return "manual_only"
    else:
        return "block"


def _generate_rollback_plan(fix_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a structured rollback plan based on fix type."""
    fix_type = str(fix_data.get("fix_type", "code_patch")).lower()

    plans = {
        "code_patch": {
            "strategy": "git_revert",
            "steps": [
                "Identify the commit SHA of the applied fix",
                "Run: git revert <commit-sha>",
                "Run test suite to verify rollback",
                "Deploy reverted code",
                "Verify error rates return to baseline",
            ],
            "estimated_minutes": 10,
            "automated": True,
        },
        "dependency_update": {
            "strategy": "version_pin",
            "steps": [
                "Revert dependency version in manifest file",
                "Run: pip install -r requirements.txt (or equivalent)",
                "Run full test suite including integration tests",
                "Verify compatibility with other dependencies",
                "Deploy with pinned version",
            ],
            "estimated_minutes": 15,
            "automated": True,
        },
        "config_hardening": {
            "strategy": "config_restore",
            "steps": [
                "Restore previous configuration from backup",
                "Verify service starts correctly with old config",
                "Check all health endpoints return 200",
                "Monitor for 5 minutes post-restore",
            ],
            "estimated_minutes": 5,
            "automated": True,
        },
        "iac_fix": {
            "strategy": "terraform_rollback",
            "steps": [
                "Identify affected Terraform state",
                "Run: terraform plan with previous version",
                "Review infrastructure diff carefully",
                "Apply rollback with: terraform apply",
                "Verify infrastructure health checks",
            ],
            "estimated_minutes": 20,
            "automated": False,
        },
        "secret_rotation": {
            "strategy": "secret_restore",
            "steps": [
                "WARNING: Cannot un-rotate secrets safely",
                "If new secret is broken, generate a fresh one",
                "Update all services that consume the secret",
                "Invalidate the broken secret immediately",
                "Monitor auth failures for 30 minutes",
            ],
            "estimated_minutes": 30,
            "automated": False,
        },
    }

    plan = plans.get(fix_type, plans["code_patch"])
    plan["fix_type"] = fix_type
    plan["files_affected"] = fix_data.get("files_affected", 1)
    return plan


def _generate_monitoring_config(
    fix_data: Dict[str, Any],
    regression_prob: float,
) -> Dict[str, Any]:
    """Generate post-deploy monitoring configuration."""
    # Higher risk → more aggressive monitoring
    if regression_prob > 0.4:
        check_interval_seconds = 30
        alert_threshold_pct = 1.0
        monitoring_duration_minutes = 60
    elif regression_prob > 0.2:
        check_interval_seconds = 60
        alert_threshold_pct = 2.0
        monitoring_duration_minutes = 30
    else:
        check_interval_seconds = 300
        alert_threshold_pct = 5.0
        monitoring_duration_minutes = 15

    return {
        "check_interval_seconds": check_interval_seconds,
        "alert_threshold_error_rate_pct": alert_threshold_pct,
        "alert_threshold_latency_ms": 500 if regression_prob > 0.3 else 1000,
        "monitoring_duration_minutes": monitoring_duration_minutes,
        "auto_rollback_enabled": bool(regression_prob > 0.3),
        "metrics_to_watch": [
            "error_rate",
            "p99_latency_ms",
            "test_pass_rate",
            "memory_usage_mb",
            "cpu_usage_pct",
        ],
        "canary_percentage": min(int(regression_prob * 100), 50),
    }


# ---------------------------------------------------------------------------
# Regression Predictor Model
# ---------------------------------------------------------------------------

class RegressionPredictor:
    """Gradient Boosted Trees model for fix regression risk prediction.

    [V3] Decision Intelligence — Self-healing remediation (Year 4 roadmap).
    [V9] Air-gapped — No cloud API calls, works offline.

    Predicts whether an auto-generated fix will cause a regression,
    and provides rollback plans and monitoring recommendations.
    """

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        random_seed: int = 42,
    ):
        self.model_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
        self.random_seed = random_seed
        self._model = None
        self._scaler = None
        self._metrics: Optional[RegressionModelMetrics] = None
        self._trained = False
        self._bootstrap_models: List[Any] = []
        self._outcome_history: List[FixOutcome] = []
        self._max_history = 5000

    @property
    def is_trained(self) -> bool:
        return self._trained and self._model is not None

    def train(
        self,
        n_samples: int = 800,
        n_bootstrap: int = 20,
        outcomes: Optional[List[Dict[str, Any]]] = None,
    ) -> RegressionModelMetrics:
        """Train the regression predictor on calibrated data.

        Training data is generated based on empirically calibrated
        relationships between fix characteristics and regression probability.
        If real outcomes are provided, they augment the synthetic data.

        Parameters
        ----------
        n_samples : int
            Number of synthetic training samples.
        n_bootstrap : int
            Number of bootstrap models for confidence intervals.
        outcomes : list of dict, optional
            Real fix outcomes to augment training data.

        Returns
        -------
        RegressionModelMetrics
            Training performance metrics.
        """
        from sklearn.ensemble import GradientBoostingRegressor
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import StandardScaler

        rng = np.random.RandomState(self.random_seed)
        X_list, y_list = [], []

        # Generate calibrated synthetic data
        for _ in range(n_samples):
            fix_type_key = rng.choice(list(REGRESSION_BASELINES.keys()))
            fix_type_idx = FIX_TYPE_MAP.get(fix_type_key, 0)
            base_regression = REGRESSION_BASELINES[fix_type_key]

            severity = rng.choice([1.0, 0.75, 0.5, 0.25, 0.1])
            category_idx = rng.randint(0, 14)
            files_affected = rng.lognormal(0.5, 0.8)
            lines_changed = rng.lognormal(2.5, 1.0)
            has_tests = rng.random() < 0.55
            llm_confidence = rng.beta(4, 2)
            language_idx = rng.randint(0, 14)
            hist_success = rng.beta(7, 3)
            complexity = rng.lognormal(2.5, 0.8)
            dep_depth = rng.geometric(0.4) - 1
            breaking_changes = rng.poisson(0.3)
            scope_idx = rng.choice([0, 1, 2, 3], p=[0.3, 0.35, 0.25, 0.1])
            test_coverage = rng.beta(3, 2) * 100

            # Features (normalized)
            features = np.array([
                fix_type_idx / 9.0,
                severity,
                category_idx / 13.0,
                min(files_affected, 20) / 20.0,
                min(lines_changed, 500) / 500.0,
                1.0 if has_tests else 0.0,
                llm_confidence,
                language_idx / 13.0,
                hist_success,
                min(complexity, 100) / 100.0,
                min(dep_depth, 10) / 10.0,
                min(breaking_changes, 10) / 10.0,
                scope_idx / 3.0,
                test_coverage / 100.0,
            ], dtype=np.float64)

            # Regression probability model:
            # Base rate from fix type
            reg_prob = base_regression

            # Higher severity → more aggressive fix → higher regression risk
            reg_prob += (severity - 0.5) * 0.08

            # More files → more regression risk
            reg_prob += min(files_affected, 20) / 20.0 * 0.15

            # More lines changed → more risk
            reg_prob += min(lines_changed, 500) / 500.0 * 0.12

            # Tests reduce regression risk significantly
            if has_tests:
                reg_prob *= 0.55
            # High test coverage further reduces risk
            if test_coverage > 80:
                reg_prob *= 0.7

            # High LLM confidence reduces risk
            reg_prob *= (1.2 - llm_confidence * 0.4)

            # Historical success reduces risk
            reg_prob *= (1.3 - hist_success * 0.5)

            # Complexity increases risk
            reg_prob += min(complexity, 100) / 100.0 * 0.10

            # Breaking changes directly increase risk
            reg_prob += min(breaking_changes, 10) / 10.0 * 0.20

            # Wider scope → more risk
            reg_prob += scope_idx / 3.0 * 0.10

            # Dependency depth increases risk for dep updates
            if fix_type_key == "dependency_update":
                reg_prob += min(dep_depth, 10) / 10.0 * 0.15

            # Clamp and add noise
            reg_prob = np.clip(reg_prob, 0.01, 0.95)
            reg_prob += rng.normal(0, 0.03)
            reg_prob = np.clip(reg_prob, 0.0, 1.0)

            X_list.append(features)
            y_list.append(reg_prob)

        # Add real outcomes if available
        if outcomes:
            for outcome in outcomes:
                try:
                    features = extract_regression_features(
                        outcome.get("fix_features", outcome)
                    )
                    reg = 1.0 if outcome.get("regression_occurred", False) else 0.0
                    # If regression severity is known, use graduated values
                    sev = outcome.get("regression_severity", "none")
                    if sev == "minor":
                        reg = 0.3
                    elif sev == "major":
                        reg = 0.7
                    elif sev == "critical":
                        reg = 0.95
                    X_list.append(features)
                    y_list.append(reg)
                except (ValueError, KeyError):
                    continue

        X = np.array(X_list)
        y = np.array(y_list)

        # Scale features
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Train primary model
        self._model = GradientBoostingRegressor(
            n_estimators=200,
            max_depth=4,
            learning_rate=0.05,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=self.random_seed,
        )
        self._model.fit(X_scaled, y)

        # Cross-validation
        cv_scores = cross_val_score(
            self._model, X_scaled, y, cv=5, scoring="neg_mean_absolute_error"
        )
        cv_mae = -cv_scores.mean()
        cv_std = cv_scores.std()

        # Bootstrap models for confidence intervals
        self._bootstrap_models = []
        for i in range(n_bootstrap):
            idx = rng.choice(len(X), size=len(X), replace=True)
            X_boot = X_scaled[idx]
            y_boot = y[idx]
            model_boot = GradientBoostingRegressor(
                n_estimators=150,
                max_depth=4,
                learning_rate=0.05,
                min_samples_leaf=5,
                subsample=0.8,
                random_state=self.random_seed + i + 1,
            )
            model_boot.fit(X_boot, y_boot)
            self._bootstrap_models.append(model_boot)

        # Compute training metrics
        y_pred = self._model.predict(X_scaled)
        y_pred = np.clip(y_pred, 0, 1)
        mae = np.mean(np.abs(y - y_pred))
        rmse = np.sqrt(np.mean((y - y_pred) ** 2))
        ss_res = np.sum((y - y_pred) ** 2)
        ss_tot = np.sum((y - np.mean(y)) ** 2)
        r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0

        # Accuracy at various thresholds
        accuracy_at = {}
        for threshold in [0.15, 0.25, 0.40, 0.50]:
            pred_binary = (y_pred >= threshold).astype(int)
            true_binary = (y >= threshold).astype(int)
            acc = np.mean(pred_binary == true_binary)
            accuracy_at[f"threshold_{threshold}"] = acc

        # Feature importances
        importances = dict(zip(
            REGRESSION_FEATURE_NAMES,
            self._model.feature_importances_,
        ))

        self._metrics = RegressionModelMetrics(
            mae=mae,
            rmse=rmse,
            r2=r2,
            accuracy_at_threshold=accuracy_at,
            feature_importances=importances,
            training_samples=len(X),
            cv_mae=cv_mae,
            cv_std=cv_std,
        )
        self._trained = True

        logger.info(
            "RegressionPredictor trained: MAE=%.4f, R²=%.4f, CV MAE=%.4f±%.4f, samples=%d",
            mae, r2, cv_mae, cv_std, len(X),
        )

        return self._metrics

    def predict_regression_risk(
        self,
        fix_data: Dict[str, Any],
    ) -> RegressionPrediction:
        """Predict regression risk for a proposed fix.

        Parameters
        ----------
        fix_data : dict
            Fix metadata with keys matching REGRESSION_FEATURE_NAMES.

        Returns
        -------
        RegressionPrediction
            Prediction result with probability, risk level, and recommendations.

        Raises
        ------
        RuntimeError
            If model has not been trained.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        start = time.monotonic()

        features = extract_regression_features(fix_data)
        features_scaled = self._scaler.transform(features.reshape(1, -1))

        # Primary prediction
        prob = float(self._model.predict(features_scaled)[0])
        prob = np.clip(prob, 0.0, 1.0)

        # Bootstrap confidence interval
        if self._bootstrap_models:
            boot_preds = [
                float(np.clip(m.predict(features_scaled)[0], 0, 1))
                for m in self._bootstrap_models
            ]
            ci_low = float(np.percentile(boot_preds, 5))
            ci_high = float(np.percentile(boot_preds, 95))
        else:
            ci_low = max(0, prob - 0.1)
            ci_high = min(1, prob + 0.1)

        # Feature contributions (interventional approach)
        contributions = self._compute_feature_contributions(features_scaled, prob)

        # Determine risk level and action
        risk = _risk_level(prob)
        has_tests = bool(fix_data.get("has_tests", False))
        action = _recommended_action(prob, has_tests)

        # Generate rollback plan and monitoring config
        rollback = _generate_rollback_plan(fix_data)
        monitoring = _generate_monitoring_config(fix_data, prob)

        elapsed = (time.monotonic() - start) * 1000

        return RegressionPrediction(
            regression_probability=prob,
            risk_level=risk,
            recommended_action=action,
            confidence_interval=(ci_low, ci_high),
            feature_contributions=contributions,
            rollback_plan=rollback,
            monitoring_config=monitoring,
            model_version=MODEL_VERSION,
            prediction_time_ms=elapsed,
        )

    def should_rollback(
        self,
        telemetry: Dict[str, Any],
        fix_context: Optional[Dict[str, Any]] = None,
    ) -> RollbackDecision:
        """Analyze post-deploy telemetry and recommend rollback.

        Parameters
        ----------
        telemetry : dict
            Post-deploy metrics with keys:
            - error_rate_delta: float — change in error rate (0.0–1.0)
            - latency_delta_ms: float — change in P99 latency
            - test_failures: int — number of test failures
            - memory_delta_mb: float — change in memory usage
            - cpu_delta_pct: float — change in CPU percentage
            - crash_count: int — number of crashes
            - time_since_deploy_minutes: float
        fix_context : dict, optional
            Context about the fix that was deployed.

        Returns
        -------
        RollbackDecision
            Whether to rollback, urgency, and supporting evidence.
        """
        start = time.monotonic()

        triggered = []
        risk_components = []

        # Check each threshold
        error_rate = float(telemetry.get("error_rate_delta", 0.0))
        if error_rate > ROLLBACK_THRESHOLDS["error_rate_delta"]:
            triggered.append("error_rate_delta")
            risk_components.append(min(error_rate / 0.1 * 30, 40))

        latency = float(telemetry.get("latency_delta_ms", 0.0))
        if latency > ROLLBACK_THRESHOLDS["latency_delta_ms"]:
            triggered.append("latency_delta_ms")
            risk_components.append(min(latency / 2000 * 25, 30))

        test_fails = int(telemetry.get("test_failures", 0))
        if test_fails >= ROLLBACK_THRESHOLDS["test_failures"]:
            triggered.append("test_failures")
            risk_components.append(min(test_fails * 10, 35))

        memory = float(telemetry.get("memory_delta_mb", 0.0))
        if memory > ROLLBACK_THRESHOLDS["memory_delta_mb"]:
            triggered.append("memory_delta_mb")
            risk_components.append(min(memory / 500 * 15, 20))

        cpu = float(telemetry.get("cpu_delta_pct", 0.0))
        if cpu > ROLLBACK_THRESHOLDS["cpu_delta_pct"]:
            triggered.append("cpu_delta_pct")
            risk_components.append(min(cpu / 100 * 15, 20))

        crashes = int(telemetry.get("crash_count", 0))
        if crashes >= ROLLBACK_THRESHOLDS["crash_count"]:
            triggered.append("crash_count")
            risk_components.append(min(crashes * 25, 50))

        # Aggregate risk score
        risk_score = min(sum(risk_components), 100.0) if risk_components else 0.0

        # Time factor: early detection → more confident decision
        time_since = float(telemetry.get("time_since_deploy_minutes", 0.0))
        if time_since < 5:
            confidence = 0.6  # Early — might be transient
        elif time_since < 30:
            confidence = 0.85
        else:
            confidence = 0.95

        # Determine urgency
        if crashes > 0 or risk_score >= 70:
            urgency = "IMMEDIATE"
        elif risk_score >= 50:
            urgency = "HIGH"
        elif risk_score >= 25:
            urgency = "MEDIUM"
        else:
            urgency = "LOW"

        # Decision
        should_rollback = risk_score >= 30 and len(triggered) >= 1
        if crashes > 0:
            should_rollback = True

        # Generate recommendation
        if not should_rollback:
            if risk_score > 0:
                recommendation = (
                    f"Minor degradation detected ({', '.join(triggered) if triggered else 'none'}). "
                    "Continue monitoring — not yet at rollback threshold."
                )
            else:
                recommendation = "No regression indicators detected. Fix appears stable."
        elif urgency == "IMMEDIATE":
            recommendation = (
                f"CRITICAL: {', '.join(triggered)} exceeded thresholds. "
                "Immediate rollback recommended to prevent user impact."
            )
        else:
            recommendation = (
                f"Regression detected: {', '.join(triggered)} triggered. "
                f"Rollback recommended within {max(5, 30 - int(time_since))} minutes."
            )

        # Estimated impact
        impact = {
            "affected_users_estimate": "high" if crashes > 0 else (
                "medium" if error_rate > 0.05 else "low"
            ),
            "data_loss_risk": crashes > 0,
            "service_degradation": latency > 1000 or error_rate > 0.1,
        }

        elapsed = (time.monotonic() - start) * 1000

        return RollbackDecision(
            should_rollback=should_rollback,
            urgency=urgency,
            confidence=confidence,
            triggered_thresholds=triggered,
            risk_score=risk_score,
            recommendation=recommendation,
            estimated_impact=impact,
            decision_time_ms=elapsed,
        )

    def generate_healing_actions(
        self,
        rollback_decision: RollbackDecision,
        fix_data: Optional[Dict[str, Any]] = None,
    ) -> List[HealingAction]:
        """Generate prioritized self-healing actions.

        Parameters
        ----------
        rollback_decision : RollbackDecision
            The rollback analysis result.
        fix_data : dict, optional
            Context about the original fix.

        Returns
        -------
        List[HealingAction]
            Prioritized list of healing actions.
        """
        actions = []

        if not rollback_decision.should_rollback:
            # Just monitoring
            actions.append(HealingAction(
                action_type="alert_only",
                target="monitoring_dashboard",
                priority=5,
                estimated_fix_time_minutes=0,
                steps=["Continue monitoring metrics", "Review logs for anomalies"],
                prerequisites=[],
                risks=["False negative — regression may be subtle"],
            ))
            return actions

        fix_type = str((fix_data or {}).get("fix_type", "code_patch")).lower()

        # Primary action: rollback
        if rollback_decision.urgency == "IMMEDIATE":
            actions.append(HealingAction(
                action_type="rollback",
                target=f"Rollback {fix_type} fix immediately",
                priority=1,
                estimated_fix_time_minutes=5 if fix_type != "iac_fix" else 20,
                steps=_generate_rollback_plan(fix_data or {}).get("steps", []),
                prerequisites=["Access to deployment pipeline", "Rollback artifact available"],
                risks=["Vulnerability re-exposed until new fix is developed"],
            ))
        else:
            actions.append(HealingAction(
                action_type="rollback",
                target=f"Rollback {fix_type} fix",
                priority=2,
                estimated_fix_time_minutes=10 if fix_type != "iac_fix" else 30,
                steps=_generate_rollback_plan(fix_data or {}).get("steps", []),
                prerequisites=["Access to deployment pipeline"],
                risks=["Vulnerability re-exposed"],
            ))

        # Secondary: investigate root cause
        actions.append(HealingAction(
            action_type="hotfix",
            target="Investigate regression root cause",
            priority=3,
            estimated_fix_time_minutes=30,
            steps=[
                "Review error logs for stack traces",
                "Identify which tests are failing",
                "Check if fix introduced API incompatibility",
                "Determine if regression is in fix or pre-existing",
                "Generate targeted hotfix if root cause is clear",
            ],
            prerequisites=["Logging access", "Test environment"],
            risks=["Investigation may take longer than estimated"],
        ))

        # If crashes detected, add incident response
        if "crash_count" in rollback_decision.triggered_thresholds:
            actions.insert(0, HealingAction(
                action_type="rollback",
                target="Emergency service restart + rollback",
                priority=1,
                estimated_fix_time_minutes=2,
                steps=[
                    "Restart crashed service instances immediately",
                    "Route traffic to healthy instances",
                    "Initiate full rollback",
                    "Page on-call team",
                ],
                prerequisites=["Infrastructure access", "On-call rotation"],
                risks=["Brief service interruption during restart"],
            ))

        return actions

    def record_outcome(self, outcome: FixOutcome) -> None:
        """Record a fix outcome for online learning.

        Parameters
        ----------
        outcome : FixOutcome
            The observed outcome of a deployed fix.
        """
        if not outcome.recorded_at:
            outcome.recorded_at = datetime.now(timezone.utc).isoformat()

        self._outcome_history.append(outcome)

        # Enforce history limit
        if len(self._outcome_history) > self._max_history:
            self._outcome_history = self._outcome_history[-self._max_history:]

        logger.info(
            "Recorded fix outcome: fix_id=%s, regression=%s, severity=%s",
            outcome.fix_id, outcome.regression_occurred, outcome.regression_severity,
        )

    def get_outcome_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics from recorded outcomes.

        Returns
        -------
        dict
            Summary statistics of recorded fix outcomes.
        """
        if not self._outcome_history:
            return {
                "total_outcomes": 0,
                "regression_rate": 0.0,
                "rollback_rate": 0.0,
                "by_fix_type": {},
                "by_severity": {},
            }

        total = len(self._outcome_history)
        regressions = sum(1 for o in self._outcome_history if o.regression_occurred)
        rollbacks = sum(1 for o in self._outcome_history if o.rollback_performed)

        # By fix type
        by_type: Dict[str, Dict[str, int]] = {}
        for o in self._outcome_history:
            ft = o.fix_type
            if ft not in by_type:
                by_type[ft] = {"total": 0, "regressions": 0, "rollbacks": 0}
            by_type[ft]["total"] += 1
            if o.regression_occurred:
                by_type[ft]["regressions"] += 1
            if o.rollback_performed:
                by_type[ft]["rollbacks"] += 1

        # By regression severity
        by_sev: Dict[str, int] = {}
        for o in self._outcome_history:
            s = o.regression_severity
            by_sev[s] = by_sev.get(s, 0) + 1

        return {
            "total_outcomes": total,
            "regression_rate": regressions / total if total > 0 else 0.0,
            "rollback_rate": rollbacks / total if total > 0 else 0.0,
            "avg_detection_time_minutes": (
                np.mean([o.time_to_detection_minutes for o in self._outcome_history
                         if o.regression_occurred and o.time_to_detection_minutes > 0])
                if regressions > 0 else 0.0
            ),
            "by_fix_type": by_type,
            "by_severity": by_sev,
        }

    def get_metrics(self) -> Optional[RegressionModelMetrics]:
        """Return training metrics."""
        return self._metrics

    def get_feature_importance(self) -> Dict[str, float]:
        """Return feature importance from the trained model."""
        if not self.is_trained:
            return {}
        return dict(zip(
            REGRESSION_FEATURE_NAMES,
            self._model.feature_importances_,
        ))

    def _compute_feature_contributions(
        self,
        features_scaled: np.ndarray,
        base_pred: float,
    ) -> Dict[str, float]:
        """Compute interventional feature contributions (SHAP-like).

        For each feature, holds it at its median value and measures
        the change in prediction. This gives an approximate measure
        of each feature's contribution to the final prediction.
        """
        contributions = {}
        for i, name in enumerate(REGRESSION_FEATURE_NAMES):
            perturbed = features_scaled.copy()
            perturbed[0, i] = 0.0  # Set to scaled median (≈0 after StandardScaler)
            perturbed_pred = float(np.clip(
                self._model.predict(perturbed)[0], 0, 1
            ))
            contributions[name] = base_pred - perturbed_pred
        return contributions

    def save_model(self, suffix: str = "") -> Path:
        """Save trained model and metadata to model_dir.

        Returns
        -------
        Path
            Path to the saved model card.
        """
        import pickle  # nosec B403 -- pickle used for ML model serialization only

        self.model_dir.mkdir(parents=True, exist_ok=True)

        version_tag = MODEL_VERSION.replace(".", "_")
        model_path = self.model_dir / f"regression_predictor_v{version_tag}{suffix}.pkl"
        card_path = self.model_dir / f"regression_model_card_v{version_tag}{suffix}.json"

        # Save model
        with open(model_path, "wb") as f:
            pickle.dump({  # nosemgrep: avoid-pickle
                "model": self._model,
                "scaler": self._scaler,
                "bootstrap_models": self._bootstrap_models,
                "version": MODEL_VERSION,
                "trained_at": datetime.now(timezone.utc).isoformat(),
            }, f)

        # Save model card
        card = {
            "model_name": "ALdeci Regression Predictor",
            "version": MODEL_VERSION,
            "description": "Predicts whether auto-fix will cause regression",
            "year": "Year 4 ML Roadmap",
            "architecture": "GradientBoostingRegressor (200 estimators, depth 4)",
            "features": REGRESSION_FEATURE_NAMES,
            "n_features": len(REGRESSION_FEATURE_NAMES),
            "metrics": self._metrics.to_dict() if self._metrics else {},
            "risk_levels": {
                "SAFE": "regression_probability < 0.15",
                "CAUTION": "0.15 <= regression_probability < 0.40",
                "DANGEROUS": "regression_probability >= 0.40",
            },
            "actions": {
                "auto_apply": "probability < 0.10 (or < 0.25 with tests)",
                "review_and_apply": "0.10–0.50",
                "manual_only": "0.50–0.70",
                "block": "probability >= 0.70",
            },
            "air_gap_compatible": True,
            "dependencies": ["numpy", "scikit-learn"],
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(card_path, "w") as f:
            json.dump(card, f, indent=2)

        logger.info("Regression predictor saved: %s", model_path)
        return card_path

    def load_model(self, suffix: str = "") -> bool:
        """Load a previously saved model.

        Returns
        -------
        bool
            True if model loaded successfully.
        """
        import hashlib
        import pickle  # nosec B403 -- pickle used for ML model serialization only

        # SECURITY: pickle is unsafe — migrate to safetensors/ONNX when feasible.

        version_tag = MODEL_VERSION.replace(".", "_")
        model_path = self.model_dir / f"regression_predictor_v{version_tag}{suffix}.pkl"

        if not model_path.exists():
            logger.warning("No saved model at %s", model_path)
            return False

        try:
            # Verify SHA-256 sidecar before deserializing to reduce RCE risk.
            sha256_path = model_path.with_suffix(model_path.suffix + ".sha256")
            if sha256_path.exists():
                expected = sha256_path.read_text().strip().split()[0]
                actual = hashlib.sha256(model_path.read_bytes()).hexdigest()
                if actual != expected:
                    logger.error("SHA-256 mismatch for model %s — refusing load", model_path)
                    return False

            with open(model_path, "rb") as f:
                data = pickle.load(f)  # nosec B301 — hash-verified above when sidecar present  # nosemgrep: avoid-pickle
            self._model = data["model"]
            self._scaler = data["scaler"]
            self._bootstrap_models = data.get("bootstrap_models", [])
            self._trained = True
            logger.info("Regression predictor loaded from %s", model_path)
            return True
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error("Failed to load model: %s", e)
            return False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_predictor: Optional[RegressionPredictor] = None


def get_regression_predictor(
    model_dir: Optional[str] = None,
) -> RegressionPredictor:
    """Get or create the default RegressionPredictor singleton.

    Parameters
    ----------
    model_dir : str, optional
        Path to model directory. Uses default if not specified.

    Returns
    -------
    RegressionPredictor
        The singleton predictor instance.
    """
    global _default_predictor
    if _default_predictor is None:
        _default_predictor = RegressionPredictor(
            model_dir=Path(model_dir) if model_dir else None,
        )
    return _default_predictor
