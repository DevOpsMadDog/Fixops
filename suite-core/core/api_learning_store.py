"""API Traffic Learning Store — SQLite + ML for API intelligence.

Captures all API request/response traffic, trains lightweight ML models
for anomaly detection, pattern recognition, and threat prediction.
Acts as the local MindsDB-compatible learning layer.

Phase 6 of FixOps Transformation Plan (R1).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_DB_DIR = Path(os.getenv("FIXOPS_DATA_DIR", ".fixops_data"))
_DB_PATH = _DB_DIR / "api_learning.db"
_MIN_SAMPLES_FOR_TRAINING = 20
_ANOMALY_CONTAMINATION = 0.05  # 5% expected anomaly rate
_MAX_BATCH_SIZE = 500


class ModelStatus(str, Enum):
    UNTRAINED = "untrained"
    TRAINING = "training"
    READY = "ready"
    STALE = "stale"


class PredictionType(str, Enum):
    ANOMALY = "anomaly"
    RESPONSE_TIME = "response_time"
    THREAT_SCORE = "threat_score"
    USAGE_PATTERN = "usage_pattern"
    ERROR_PROBABILITY = "error_probability"


@dataclass
class TrafficRecord:
    """Single API request/response record."""
    method: str
    path: str
    status_code: int
    duration_ms: float
    request_size: int = 0
    response_size: int = 0
    client_ip: str = ""
    user_agent: str = ""
    correlation_id: str = ""
    query_params: str = ""
    error_type: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ModelInfo:
    """ML model metadata."""
    name: str
    type: str
    status: ModelStatus = ModelStatus.UNTRAINED
    samples_trained: int = 0
    accuracy: float = 0.0
    last_trained: Optional[str] = None
    feature_names: List[str] = field(default_factory=list)


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    is_anomaly: bool
    score: float  # -1 to 1, lower = more anomalous
    confidence: float
    reason: str = ""


@dataclass
class ThreatAssessment:
    """Threat assessment for an API request."""
    threat_score: float  # 0.0 to 1.0
    risk_level: str  # low, medium, high, critical
    indicators: List[str] = field(default_factory=list)
    recommended_action: str = ""


# ---------------------------------------------------------------------------
# API Learning Store
# ---------------------------------------------------------------------------

class APILearningStore:
    """SQLite-backed API traffic store with ML learning capabilities.

    Features:
    - Stores all API request/response pairs
    - Trains anomaly detection model (IsolationForest)
    - Predicts response times
    - Detects potential threats based on traffic patterns
    - Provides API health scoring
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or _DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._models: Dict[str, Any] = {}
        self._model_info: Dict[str, ModelInfo] = {}
        self._batch: List[TrafficRecord] = []
        self._path_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "durations": [], "errors": 0, "statuses": defaultdict(int)}
        )
        self._init_db()
        self._init_models()
        self._load_path_stats()
        logger.info("APILearningStore initialized at %s", self._db_path)

    # -- Database Setup -------------------------------------------------------

    def _init_db(self):
        """Initialize SQLite tables."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS api_traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    duration_ms REAL NOT NULL,
                    request_size INTEGER DEFAULT 0,
                    response_size INTEGER DEFAULT 0,
                    client_ip TEXT DEFAULT '',
                    user_agent TEXT DEFAULT '',
                    correlation_id TEXT DEFAULT '',
                    query_params TEXT DEFAULT '',
                    error_type TEXT DEFAULT '',
                    is_anomaly INTEGER DEFAULT 0,
                    threat_score REAL DEFAULT 0.0,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON api_traffic(timestamp);
                CREATE INDEX IF NOT EXISTS idx_traffic_path ON api_traffic(path);
                CREATE INDEX IF NOT EXISTS idx_traffic_method_path ON api_traffic(method, path);
                CREATE INDEX IF NOT EXISTS idx_traffic_anomaly ON api_traffic(is_anomaly);

                CREATE TABLE IF NOT EXISTS ml_models (
                    name TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    status TEXT DEFAULT 'untrained',
                    samples_trained INTEGER DEFAULT 0,
                    accuracy REAL DEFAULT 0.0,
                    last_trained TEXT,
                    model_data BLOB,
                    feature_names TEXT DEFAULT '[]',
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS api_patterns (
                    path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    hour_of_day INTEGER,
                    avg_duration_ms REAL,
                    p95_duration_ms REAL,
                    avg_request_size REAL,
                    error_rate REAL,
                    requests_per_minute REAL,
                    last_updated TEXT DEFAULT (datetime('now')),
                    PRIMARY KEY (path, method)
                );

                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    indicator_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT DEFAULT 'low',
                    source_ip TEXT DEFAULT '',
                    target_path TEXT DEFAULT '',
                    details TEXT DEFAULT '{}',
                    acknowledged INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now'))
                );
            """)

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local SQLite connection."""
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_models(self):
        """Initialize ML model registry."""
        model_defs = [
            ("anomaly_detector", "IsolationForest", ["method_enc", "path_enc", "status_code",
             "duration_ms", "request_size", "response_size", "hour", "minute"]),
            ("response_predictor", "LinearRegression", ["method_enc", "path_enc",
             "request_size", "hour", "day_of_week"]),
            ("threat_classifier", "GradientBoosting", ["method_enc", "path_enc",
             "status_code", "duration_ms", "error_rate", "request_rate", "unique_paths"]),
            ("error_predictor", "LogisticRegression", ["method_enc", "path_enc",
             "request_size", "hour", "recent_error_rate"]),
        ]
        for name, mtype, features in model_defs:
            self._model_info[name] = ModelInfo(
                name=name, type=mtype, feature_names=features
            )

    def _load_path_stats(self):
        """Load aggregated path stats from DB."""
        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT path, method, avg_duration_ms, error_rate "
                    "FROM api_patterns"
                ).fetchall()
                for row in rows:
                    key = f"{row['method']}:{row['path']}"
                    self._path_stats[key]["avg_duration"] = row["avg_duration_ms"]
                    self._path_stats[key]["error_rate"] = row["error_rate"]
        except Exception as e:
            logger.debug("Could not load path stats: %s", e)

    # -- Traffic Recording ----------------------------------------------------

    def record(self, rec: TrafficRecord):
        """Record a single API traffic event (non-blocking batch append)."""
        with self._lock:
            self._batch.append(rec)
            key = f"{rec.method}:{rec.path}"
            stats = self._path_stats[key]
            stats["count"] += 1
            stats["durations"].append(rec.duration_ms)
            if len(stats["durations"]) > 1000:
                stats["durations"] = stats["durations"][-500:]
            stats["statuses"][rec.status_code] += 1
            if rec.status_code >= 400:
                stats["errors"] += 1

            if len(self._batch) >= _MAX_BATCH_SIZE:
                self._flush_batch()

    def _flush_batch(self):
        """Flush the batch to SQLite."""
        if not self._batch:
            return
        batch = self._batch[:]
        self._batch.clear()
        try:
            with self._get_conn() as conn:
                conn.executemany(
                    "INSERT INTO api_traffic "
                    "(timestamp, method, path, status_code, duration_ms, "
                    " request_size, response_size, client_ip, user_agent, "
                    " correlation_id, query_params, error_type) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    [(r.timestamp, r.method, r.path, r.status_code,
                      r.duration_ms, r.request_size, r.response_size,
                      r.client_ip, r.user_agent, r.correlation_id,
                      r.query_params, r.error_type) for r in batch],
                )
            logger.debug("Flushed %d traffic records to DB", len(batch))
        except Exception as e:
            logger.error("Failed to flush traffic batch: %s", e)

    def flush(self):
        """Force flush any pending records."""
        with self._lock:
            self._flush_batch()

    # -- ML Training ----------------------------------------------------------

    def _encode_method(self, method: str) -> int:
        """Encode HTTP method as integer."""
        mapping = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4, "HEAD": 5, "OPTIONS": 6}
        return mapping.get(method.upper(), 7)

    def _encode_path(self, path: str) -> int:
        """Encode path as hash integer for ML features."""
        return hash(path.split("?")[0].rstrip("/")) % 10000

    def _extract_features(self, rows: List[dict]) -> np.ndarray:
        """Extract feature matrix from traffic rows."""
        features = []
        for row in rows:
            ts = row.get("timestamp", 0)
            dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)
            features.append([
                self._encode_method(row.get("method", "GET")),
                self._encode_path(row.get("path", "/")),
                row.get("status_code", 200),
                row.get("duration_ms", 0),
                row.get("request_size", 0),
                row.get("response_size", 0),
                dt.hour,
                dt.minute,
            ])
        return np.array(features, dtype=np.float64)

    def train_anomaly_detector(self) -> ModelInfo:
        """Train the anomaly detection model on stored traffic."""
        info = self._model_info["anomaly_detector"]
        info.status = ModelStatus.TRAINING

        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM api_traffic ORDER BY timestamp DESC LIMIT 10000"
                ).fetchall()

            if len(rows) < _MIN_SAMPLES_FOR_TRAINING:
                info.status = ModelStatus.UNTRAINED
                logger.info("Not enough samples for anomaly training: %d < %d",
                            len(rows), _MIN_SAMPLES_FOR_TRAINING)
                return info

            data = [dict(r) for r in rows]
            X = self._extract_features(data)

            from sklearn.ensemble import IsolationForest
            model = IsolationForest(
                n_estimators=100,
                contamination=_ANOMALY_CONTAMINATION,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X)

            self._models["anomaly_detector"] = model
            info.status = ModelStatus.READY
            info.samples_trained = len(rows)
            info.last_trained = datetime.now(timezone.utc).isoformat()

            # Calculate training score
            scores = model.decision_function(X)
            info.accuracy = float(np.mean(scores > 0))

            logger.info("Anomaly detector trained on %d samples, accuracy=%.3f",
                        len(rows), info.accuracy)
            self._save_model_info(info)
            return info

        except Exception as e:
            info.status = ModelStatus.STALE
            logger.error("Failed to train anomaly detector: %s", e)
            return info

    def train_response_predictor(self) -> ModelInfo:
        """Train response time prediction model."""
        info = self._model_info["response_predictor"]
        info.status = ModelStatus.TRAINING

        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM api_traffic ORDER BY timestamp DESC LIMIT 10000"
                ).fetchall()

            if len(rows) < _MIN_SAMPLES_FOR_TRAINING:
                info.status = ModelStatus.UNTRAINED
                return info

            data = [dict(r) for r in rows]
            X = self._extract_features(data)
            y = np.array([d.get("duration_ms", 0) for d in data], dtype=np.float64)

            # Use features: method, path, request_size, hour, day_of_week
            X_pred = X[:, [0, 1, 4, 6, 7]]  # method, path, req_size, hour, minute

            from sklearn.linear_model import Ridge
            model = Ridge(alpha=1.0)
            model.fit(X_pred, y)

            self._models["response_predictor"] = model
            info.status = ModelStatus.READY
            info.samples_trained = len(rows)
            info.last_trained = datetime.now(timezone.utc).isoformat()
            info.accuracy = float(model.score(X_pred, y))

            logger.info("Response predictor trained, R²=%.3f", info.accuracy)
            self._save_model_info(info)
            return info

        except Exception as e:
            info.status = ModelStatus.STALE
            logger.error("Failed to train response predictor: %s", e)
            return info

    def train_threat_classifier(self) -> ModelInfo:
        """Train threat classification model (GradientBoosting)."""
        info = self._model_info["threat_classifier"]
        info.status = ModelStatus.TRAINING

        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM api_traffic ORDER BY timestamp DESC LIMIT 10000"
                ).fetchall()

            if len(rows) < _MIN_SAMPLES_FOR_TRAINING:
                info.status = ModelStatus.UNTRAINED
                return info

            data = [dict(r) for r in rows]
            X = self._extract_features(data)

            # Label: 1 if status >= 400 or duration > 2000ms (suspicious), else 0
            y = np.array(
                [1 if d.get("status_code", 200) >= 400 or d.get("duration_ms", 0) > 2000 else 0
                 for d in data], dtype=np.int32
            )

            from sklearn.ensemble import GradientBoostingClassifier
            model = GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42)
            model.fit(X, y)

            self._models["threat_classifier"] = model
            info.status = ModelStatus.READY
            info.samples_trained = len(rows)
            info.last_trained = datetime.now(timezone.utc).isoformat()
            info.accuracy = float(model.score(X, y))

            logger.info("Threat classifier trained, accuracy=%.3f", info.accuracy)
            self._save_model_info(info)
            return info
        except Exception as e:
            info.status = ModelStatus.STALE
            logger.error("Failed to train threat classifier: %s", e)
            return info

    def train_error_predictor(self) -> ModelInfo:
        """Train error probability model (LogisticRegression)."""
        info = self._model_info["error_predictor"]
        info.status = ModelStatus.TRAINING

        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM api_traffic ORDER BY timestamp DESC LIMIT 10000"
                ).fetchall()

            if len(rows) < _MIN_SAMPLES_FOR_TRAINING:
                info.status = ModelStatus.UNTRAINED
                return info

            data = [dict(r) for r in rows]
            X = self._extract_features(data)
            # Use subset: method, path, request_size, hour, minute
            X_sub = X[:, [0, 1, 4, 6, 7]]

            # Label: 1 if status >= 500 (server error), else 0
            y = np.array(
                [1 if d.get("status_code", 200) >= 500 else 0 for d in data],
                dtype=np.int32,
            )

            from sklearn.linear_model import LogisticRegression
            model = LogisticRegression(max_iter=200, random_state=42)
            model.fit(X_sub, y)

            self._models["error_predictor"] = model
            info.status = ModelStatus.READY
            info.samples_trained = len(rows)
            info.last_trained = datetime.now(timezone.utc).isoformat()
            info.accuracy = float(model.score(X_sub, y))

            logger.info("Error predictor trained, accuracy=%.3f", info.accuracy)
            self._save_model_info(info)
            return info
        except Exception as e:
            info.status = ModelStatus.STALE
            logger.error("Failed to train error predictor: %s", e)
            return info

    def train_all_models(self) -> Dict[str, ModelInfo]:
        """Train all ML models."""
        self.flush()
        results = {}
        results["anomaly_detector"] = self.train_anomaly_detector()
        results["response_predictor"] = self.train_response_predictor()
        results["threat_classifier"] = self.train_threat_classifier()
        results["error_predictor"] = self.train_error_predictor()
        self._update_api_patterns()
        return results

    def _save_model_info(self, info: ModelInfo):
        """Save model metadata to DB."""
        try:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO ml_models "
                    "(name, type, status, samples_trained, accuracy, last_trained, feature_names, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,datetime('now'))",
                    (info.name, info.type, info.status.value, info.samples_trained,
                     info.accuracy, info.last_trained, json.dumps(info.feature_names)),
                )
        except Exception as e:
            logger.error("Failed to save model info: %s", e)


    # -- Predictions -----------------------------------------------------------

    def detect_anomaly(self, method: str, path: str, status_code: int,
                       duration_ms: float, request_size: int = 0,
                       response_size: int = 0) -> AnomalyResult:
        """Detect if a request is anomalous."""
        model = self._models.get("anomaly_detector")
        if model is None:
            # Fallback: statistical anomaly detection
            return self._statistical_anomaly(method, path, duration_ms, status_code)

        now = datetime.now(timezone.utc)
        features = np.array([[
            self._encode_method(method),
            self._encode_path(path),
            status_code,
            duration_ms,
            request_size,
            response_size,
            now.hour,
            now.minute,
        ]], dtype=np.float64)

        try:
            score = float(model.decision_function(features)[0])
            prediction = int(model.predict(features)[0])
            is_anomaly = prediction == -1

            reason = ""
            if is_anomaly:
                reasons = []
                key = f"{method}:{path}"
                stats = self._path_stats.get(key)
                if stats and stats["durations"]:
                    avg = mean(stats["durations"])
                    if duration_ms > avg * 3:
                        reasons.append(f"Response time {duration_ms:.0f}ms >> avg {avg:.0f}ms")
                if status_code >= 500:
                    reasons.append(f"Server error {status_code}")
                elif status_code >= 400:
                    reasons.append(f"Client error {status_code}")
                reason = "; ".join(reasons) if reasons else "Statistical outlier"

            return AnomalyResult(
                is_anomaly=is_anomaly,
                score=score,
                confidence=min(abs(score) * 2, 1.0),
                reason=reason,
            )
        except Exception as e:
            logger.error("Anomaly detection failed: %s", e)
            return AnomalyResult(is_anomaly=False, score=0.0, confidence=0.0)

    def _statistical_anomaly(self, method: str, path: str,
                              duration_ms: float, status_code: int) -> AnomalyResult:
        """Fallback statistical anomaly detection (before model is trained)."""
        key = f"{method}:{path}"
        stats = self._path_stats.get(key)
        if not stats or len(stats["durations"]) < 5:
            return AnomalyResult(is_anomaly=False, score=0.0, confidence=0.1,
                                  reason="Insufficient data")

        avg = mean(stats["durations"])
        sd = stdev(stats["durations"]) if len(stats["durations"]) > 1 else avg * 0.5
        z_score = (duration_ms - avg) / max(sd, 0.001)

        is_anomaly = abs(z_score) > 3 or status_code >= 500
        score = max(-1.0, min(1.0, -z_score / 5))

        reasons = []
        if abs(z_score) > 3:
            reasons.append(f"Duration z-score={z_score:.1f}")
        if status_code >= 500:
            reasons.append(f"Server error {status_code}")

        return AnomalyResult(
            is_anomaly=is_anomaly,
            score=score,
            confidence=min(abs(z_score) / 5, 1.0) if z_score else 0.1,
            reason="; ".join(reasons) if reasons else "Normal",
        )

    def predict_response_time(self, method: str, path: str,
                               request_size: int = 0) -> Dict[str, Any]:
        """Predict expected response time for a request."""
        model = self._models.get("response_predictor")
        now = datetime.now(timezone.utc)

        # Fallback: use historical average
        key = f"{method}:{path}"
        stats = self._path_stats.get(key)
        hist_avg = mean(stats["durations"]) if stats and stats["durations"] else None

        if model is None:
            return {
                "predicted_ms": hist_avg or 100.0,
                "confidence": 0.3 if hist_avg else 0.1,
                "method": "historical_average" if hist_avg else "default",
            }

        try:
            features = np.array([[
                self._encode_method(method),
                self._encode_path(path),
                request_size,
                now.hour,
                now.minute,
            ]], dtype=np.float64)
            predicted = float(model.predict(features)[0])
            return {
                "predicted_ms": max(predicted, 1.0),
                "historical_avg_ms": hist_avg,
                "confidence": 0.7,
                "method": "ml_model",
            }
        except Exception as e:
            logger.error("Response time prediction failed: %s", e)
            return {"predicted_ms": hist_avg or 100.0, "confidence": 0.1, "method": "fallback"}

    def assess_threat(self, method: str, path: str, client_ip: str = "",
                       status_code: int = 200, duration_ms: float = 0,
                       user_agent: str = "") -> ThreatAssessment:
        """Assess threat level of a request based on patterns."""
        indicators = []
        score = 0.0

        # Check for rapid requests from same IP
        if client_ip:
            recent_count = self._count_recent_from_ip(client_ip, window_seconds=60)
            if recent_count > 100:
                indicators.append(f"High request rate: {recent_count}/min from {client_ip}")
                score += 0.3
            elif recent_count > 50:
                indicators.append(f"Elevated request rate: {recent_count}/min from {client_ip}")
                score += 0.15

        # Check for scanning patterns (many 404s)
        if status_code == 404:
            indicators.append("404 Not Found — possible path enumeration")
            score += 0.1
        elif status_code == 401 or status_code == 403:
            indicators.append(f"Auth failure {status_code} — possible brute force")
            score += 0.15

        # Check for unusual methods on sensitive paths
        sensitive_paths = ["/api/v1/auth", "/api/v1/users", "/api/v1/teams",
                          "/api/v1/admin", "/api/v1/mpte"]
        if any(path.startswith(sp) for sp in sensitive_paths):
            if method in ("DELETE", "PUT", "PATCH"):
                indicators.append(f"Sensitive path {path} with {method}")
                score += 0.1

        # Check for anomalous user agents
        suspicious_agents = ["sqlmap", "nikto", "nmap", "burp", "dirbuster", "gobuster"]
        if user_agent and any(sa in user_agent.lower() for sa in suspicious_agents):
            indicators.append(f"Suspicious user agent: {user_agent[:50]}")
            score += 0.4

        score = min(score, 1.0)
        if score >= 0.7:
            level = "critical"
            action = "Block and investigate immediately"
        elif score >= 0.4:
            level = "high"
            action = "Rate limit and monitor closely"
        elif score >= 0.2:
            level = "medium"
            action = "Monitor for additional indicators"
        else:
            level = "low"
            action = "Normal traffic"

        return ThreatAssessment(
            threat_score=score,
            risk_level=level,
            indicators=indicators,
            recommended_action=action,
        )

    def _count_recent_from_ip(self, client_ip: str, window_seconds: int = 60) -> int:
        """Count recent requests from an IP address."""
        cutoff = time.time() - window_seconds
        try:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM api_traffic "
                    "WHERE client_ip = ? AND timestamp > ?",
                    (client_ip, cutoff),
                ).fetchone()
                return row["cnt"] if row else 0
        except Exception:
            return 0

    # -- Analytics & Stats ----------------------------------------------------

    def _update_api_patterns(self):
        """Update aggregated API patterns in DB."""
        try:
            with self._get_conn() as conn:
                for key, stats in self._path_stats.items():
                    if ":" not in key or stats["count"] == 0:
                        continue
                    method, path = key.split(":", 1)
                    durations = stats["durations"]
                    avg_dur = mean(durations) if durations else 0
                    p95_dur = float(np.percentile(durations, 95)) if len(durations) > 5 else avg_dur
                    error_rate = stats["errors"] / max(stats["count"], 1)
                    conn.execute(
                        "INSERT OR REPLACE INTO api_patterns "
                        "(path, method, avg_duration_ms, p95_duration_ms, error_rate, last_updated) "
                        "VALUES (?,?,?,?,?,datetime('now'))",
                        (path, method, avg_dur, p95_dur, error_rate),
                    )
        except Exception as e:
            logger.error("Failed to update API patterns: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        """Get overall API traffic statistics."""
        self.flush()
        try:
            with self._get_conn() as conn:
                total = conn.execute("SELECT COUNT(*) as cnt FROM api_traffic").fetchone()
                errors = conn.execute(
                    "SELECT COUNT(*) as cnt FROM api_traffic WHERE status_code >= 400"
                ).fetchone()
                anomalies = conn.execute(
                    "SELECT COUNT(*) as cnt FROM api_traffic WHERE is_anomaly = 1"
                ).fetchone()
                avg_duration = conn.execute(
                    "SELECT AVG(duration_ms) as avg_ms FROM api_traffic"
                ).fetchone()
                unique_paths = conn.execute(
                    "SELECT COUNT(DISTINCT path) as cnt FROM api_traffic"
                ).fetchone()
                top_paths = conn.execute(
                    "SELECT path, COUNT(*) as cnt FROM api_traffic "
                    "GROUP BY path ORDER BY cnt DESC LIMIT 10"
                ).fetchall()

            return {
                "total_requests": total["cnt"] if total else 0,
                "total_errors": errors["cnt"] if errors else 0,
                "total_anomalies": anomalies["cnt"] if anomalies else 0,
                "avg_duration_ms": round(avg_duration["avg_ms"] or 0, 2) if avg_duration else 0,
                "unique_endpoints": unique_paths["cnt"] if unique_paths else 0,
                "error_rate": round((errors["cnt"] / max(total["cnt"], 1)) * 100, 2)
                    if total and errors else 0,
                "top_endpoints": [
                    {"path": r["path"], "count": r["cnt"]} for r in (top_paths or [])
                ],
                "models": {
                    name: {
                        "status": info.status.value,
                        "samples_trained": info.samples_trained,
                        "accuracy": round(info.accuracy, 4),
                        "last_trained": info.last_trained,
                    }
                    for name, info in self._model_info.items()
                },
            }
        except Exception as e:
            logger.error("Failed to get stats: %s", e)
            return {"error": str(e)}

    def get_recent_anomalies(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent anomalous requests."""
        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM api_traffic WHERE is_anomaly = 1 "
                    "ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    def get_threat_indicators(self, limit: int = 20,
                               acknowledged: bool = False) -> List[Dict[str, Any]]:
        """Get recent threat indicators."""
        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM threat_indicators WHERE acknowledged = ? "
                    "ORDER BY timestamp DESC LIMIT ?",
                    (int(acknowledged), limit),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    def record_threat(self, indicator_type: str, description: str,
                       severity: str = "low", source_ip: str = "",
                       target_path: str = "", details: Optional[Dict] = None):
        """Record a threat indicator."""
        try:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO threat_indicators "
                    "(timestamp, indicator_type, description, severity, "
                    " source_ip, target_path, details) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (time.time(), indicator_type, description, severity,
                     source_ip, target_path, json.dumps(details or {})),
                )
        except Exception as e:
            logger.error("Failed to record threat: %s", e)

    def get_api_health(self) -> Dict[str, Any]:
        """Get API health scores based on learned patterns."""
        self.flush()
        health = {}
        for key, stats in self._path_stats.items():
            if ":" not in key or stats["count"] < 3:
                continue
            method, path = key.split(":", 1)
            durations = stats["durations"]
            error_rate = stats["errors"] / max(stats["count"], 1)
            avg_dur = mean(durations) if durations else 0

            # Health score: 100 - penalties
            score = 100.0
            score -= min(error_rate * 200, 50)  # -50 max for errors
            if avg_dur > 1000:
                score -= min((avg_dur - 1000) / 100, 30)  # -30 max for slow
            score = max(score, 0)

            health[f"{method} {path}"] = {
                "score": round(score, 1),
                "avg_ms": round(avg_dur, 1),
                "error_rate": round(error_rate * 100, 2),
                "requests": stats["count"],
            }
        return health


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_store: Optional[APILearningStore] = None
_store_lock = threading.Lock()


def get_learning_store() -> APILearningStore:
    """Get or create the singleton learning store."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = APILearningStore()
    return _store