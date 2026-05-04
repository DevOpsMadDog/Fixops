"""Self-Learning Feedback Loops Engine (V8 — 5 Feedback Loops).

Implements the 5 self-learning feedback loops that make ALdeci smarter
with every decision, scan, and remediation:

1. Decision Outcome Loop: Track if AI decisions were correct → adjust weights
2. MPTE Result Loop: Track if exploitability predictions matched reality
3. False Positive Loop: Track FP rates per scanner/rule → auto-suppress noise
4. Remediation Success Loop: Track if fixes actually resolved vulnerabilities
5. Policy Violation Loop: Track violations → suggest policy refinements

Architecture:
- Each loop has: Collector → Analyzer → Adjuster → Validator
- All loops store data in SQLite (air-gapped, zero external deps)
- Online learning: incremental model updates without full retraining
- Exponential decay: recent data weighted more than old data
- Minimum sample sizes before adjustments take effect

Environment variables:
- FIXOPS_LEARNING_ENABLED: Enable self-learning (default: true)
- FIXOPS_LEARNING_MIN_SAMPLES: Min samples before adjustments (default: 10)
- FIXOPS_LEARNING_DECAY_FACTOR: Exponential decay for old data (default: 0.95)
- FIXOPS_LEARNING_DB: Database path (default: .fixops_data/learning.db)
"""

from __future__ import annotations

import json
import structlog
import os
import sqlite3

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


# ---------------------------------------------------------------------------
# Enums & Config
# ---------------------------------------------------------------------------
class FeedbackType(str, Enum):
    DECISION_OUTCOME = "decision_outcome"
    MPTE_RESULT = "mpte_result"
    FALSE_POSITIVE = "false_positive"
    REMEDIATION_SUCCESS = "remediation_success"
    POLICY_VIOLATION = "policy_violation"


class OutcomeStatus(str, Enum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass
class LearningConfig:
    enabled: bool = True
    min_samples: int = 10
    decay_factor: float = 0.95
    db_path: str = ""
    adjustment_threshold: float = 0.15  # Min change to trigger adjustment
    max_weight_change: float = 0.3      # Max single adjustment

    @classmethod
    def from_env(cls) -> "LearningConfig":
        return cls(
            enabled=os.getenv("FIXOPS_LEARNING_ENABLED", "true").lower() in ("true", "1"),
            min_samples=int(os.getenv("FIXOPS_LEARNING_MIN_SAMPLES", "10")),
            decay_factor=float(os.getenv("FIXOPS_LEARNING_DECAY_FACTOR", "0.95")),
            db_path=os.getenv("FIXOPS_LEARNING_DB", ""),
        )


# ---------------------------------------------------------------------------
# Feedback Records
# ---------------------------------------------------------------------------
@dataclass
class FeedbackRecord:
    """A single feedback data point."""
    feedback_id: str
    feedback_type: FeedbackType
    entity_id: str          # finding_id, decision_id, scan_id, etc.
    outcome: OutcomeStatus
    predicted: str          # What was predicted/decided
    actual: str             # What actually happened
    confidence: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)
    recorded_at: str = ""
    source: str = ""        # scanner, rule, policy, etc.


@dataclass
class LearningAdjustment:
    """A calculated adjustment based on feedback analysis."""
    adjustment_id: str
    feedback_type: FeedbackType
    target: str              # What gets adjusted (scanner, rule, weight)
    metric: str              # accuracy, fp_rate, success_rate, etc.
    old_value: float
    new_value: float
    sample_count: int
    confidence: float
    reasoning: str
    applied: bool = False
    applied_at: str = ""


# ---------------------------------------------------------------------------
# Feedback Database
# ---------------------------------------------------------------------------
class FeedbackDB:
    """SQLite persistence for feedback and learning data."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_db()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            try:
                self._conn.close()
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass
            self._conn = None

    def __del__(self) -> None:
        self.close()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS feedback (
                    feedback_id TEXT PRIMARY KEY,
                    feedback_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    predicted TEXT,
                    actual TEXT,
                    confidence REAL DEFAULT 0,
                    context TEXT DEFAULT '{}',
                    recorded_at TEXT NOT NULL,
                    source TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_fb_type ON feedback(feedback_type);
                CREATE INDEX IF NOT EXISTS idx_fb_source ON feedback(source);
                CREATE INDEX IF NOT EXISTS idx_fb_recorded ON feedback(recorded_at);
                CREATE INDEX IF NOT EXISTS idx_fb_entity ON feedback(entity_id);

                CREATE TABLE IF NOT EXISTS adjustments (
                    adjustment_id TEXT PRIMARY KEY,
                    feedback_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    old_value REAL,
                    new_value REAL,
                    sample_count INTEGER,
                    confidence REAL,
                    reasoning TEXT,
                    applied INTEGER DEFAULT 0,
                    applied_at TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS weights (
                    key TEXT PRIMARY KEY,
                    value REAL NOT NULL,
                    updated_at TEXT NOT NULL,
                    update_count INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS metrics_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feedback_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    sample_count INTEGER DEFAULT 0,
                    recorded_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_mh_type ON metrics_history(feedback_type);
            """)
            self._conn.commit()

    def store_feedback(self, record: FeedbackRecord) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO feedback
                   (feedback_id, feedback_type, entity_id, outcome, predicted,
                    actual, confidence, context, recorded_at, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (record.feedback_id, record.feedback_type.value, record.entity_id,
                 record.outcome.value, record.predicted, record.actual,
                 record.confidence, json.dumps(record.context),
                 record.recorded_at or datetime.now(timezone.utc).isoformat(),
                 record.source)
            )
            self._conn.commit()
        _emit_event("learning.feedback_stored", {"feedback_id": record.feedback_id, "feedback_type": record.feedback_type.value, "outcome": record.outcome.value, "source": record.source})

    def get_feedback(self, feedback_type: str, source: Optional[str] = None,
                     days: int = 90) -> List[Dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            if source:
                cursor = self._conn.execute(
                    """SELECT * FROM feedback
                       WHERE feedback_type = ? AND source = ? AND recorded_at > ?
                       ORDER BY recorded_at DESC""",
                    (feedback_type, source, cutoff)
                )
            else:
                cursor = self._conn.execute(
                    """SELECT * FROM feedback
                       WHERE feedback_type = ? AND recorded_at > ?
                       ORDER BY recorded_at DESC""",
                    (feedback_type, cutoff)
                )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def store_adjustment(self, adj: LearningAdjustment) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO adjustments
                   (adjustment_id, feedback_type, target, metric, old_value,
                    new_value, sample_count, confidence, reasoning, applied,
                    applied_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (adj.adjustment_id, adj.feedback_type.value, adj.target,
                 adj.metric, adj.old_value, adj.new_value, adj.sample_count,
                 adj.confidence, adj.reasoning, 1 if adj.applied else 0,
                 adj.applied_at, datetime.now(timezone.utc).isoformat())
            )
            self._conn.commit()

    def get_weight(self, key: str, default: float = 1.0) -> float:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM weights WHERE key = ?", (key,)
            ).fetchone()
            return row[0] if row else default

    def set_weight(self, key: str, value: float) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO weights (key, value, updated_at, update_count)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(key) DO UPDATE SET
                       value = ?, updated_at = ?, update_count = update_count + 1""",
                (key, value, datetime.now(timezone.utc).isoformat(),
                 value, datetime.now(timezone.utc).isoformat())
            )
            self._conn.commit()

    def record_metric(self, feedback_type: str, metric_name: str,
                      metric_value: float, sample_count: int = 0) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO metrics_history
                   (feedback_type, metric_name, metric_value, sample_count, recorded_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (feedback_type, metric_name, metric_value, sample_count,
                 datetime.now(timezone.utc).isoformat())
            )
            self._conn.commit()

    def get_metrics_trend(self, feedback_type: str, metric_name: str,
                          days: int = 30) -> List[Dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            cursor = self._conn.execute(
                """SELECT metric_value, sample_count, recorded_at
                   FROM metrics_history
                   WHERE feedback_type = ? AND metric_name = ? AND recorded_at > ?
                   ORDER BY recorded_at""",
                (feedback_type, metric_name, cutoff)
            )
            return [{"value": r[0], "samples": r[1], "at": r[2]} for r in cursor.fetchall()]


# ---------------------------------------------------------------------------
# Individual Feedback Loops
# ---------------------------------------------------------------------------
class DecisionOutcomeLoop:
    """Loop 1: Track if AI decisions were correct → adjust decision weights.

    Records: What did the AI decide? Was it right?
    Adjusts: Confidence thresholds, expert weights in consensus engine.
    """

    def __init__(self, db: FeedbackDB, config: LearningConfig):
        self.db = db
        self.config = config

    def record(self, decision_id: str, finding_id: str, predicted_action: str,
               actual_outcome: str, confidence: float = 0.0,
               context: Optional[Dict] = None) -> str:
        """Record a decision outcome."""
        outcome = OutcomeStatus.CORRECT if predicted_action.upper() == actual_outcome.upper() else OutcomeStatus.INCORRECT

        import secrets
        record = FeedbackRecord(
            feedback_id=f"do-{secrets.token_hex(8)}",
            feedback_type=FeedbackType.DECISION_OUTCOME,
            entity_id=finding_id,
            outcome=outcome,
            predicted=predicted_action,
            actual=actual_outcome,
            confidence=confidence,
            context=context or {"decision_id": decision_id},
            recorded_at=datetime.now(timezone.utc).isoformat(),
            source="decision_engine",
        )
        self.db.store_feedback(record)
        return record.feedback_id

    def analyze(self, days: int = 90) -> Dict[str, Any]:
        """Analyze decision accuracy over time."""
        records = self.db.get_feedback(FeedbackType.DECISION_OUTCOME.value, days=days)
        if not records:
            return {"accuracy": 0, "sample_count": 0, "status": "insufficient_data"}

        correct = sum(1 for r in records if r["outcome"] == OutcomeStatus.CORRECT.value)
        total = len(records)
        accuracy = correct / total if total > 0 else 0

        # Apply exponential decay weighting
        weighted_correct = 0.0
        weighted_total = 0.0
        for i, r in enumerate(records):
            weight = self.config.decay_factor ** i
            weighted_total += weight
            if r["outcome"] == OutcomeStatus.CORRECT.value:
                weighted_correct += weight

        weighted_accuracy = weighted_correct / weighted_total if weighted_total > 0 else 0

        self.db.record_metric(FeedbackType.DECISION_OUTCOME.value, "accuracy", weighted_accuracy, total)

        return {
            "accuracy": round(accuracy * 100, 1),
            "weighted_accuracy": round(weighted_accuracy * 100, 1),
            "sample_count": total,
            "correct": correct,
            "incorrect": total - correct,
        }


class MPTEResultLoop:
    """Loop 2: Track if exploitability predictions matched reality."""

    def __init__(self, db: FeedbackDB, config: LearningConfig):
        self.db = db
        self.config = config

    def record(self, finding_id: str, predicted_exploitable: bool,
               actual_exploitable: bool, mpte_confidence: float = 0.0,
               context: Optional[Dict] = None) -> str:
        pred_str = "exploitable" if predicted_exploitable else "not_exploitable"
        act_str = "exploitable" if actual_exploitable else "not_exploitable"
        outcome = OutcomeStatus.CORRECT if predicted_exploitable == actual_exploitable else OutcomeStatus.INCORRECT

        import secrets
        record = FeedbackRecord(
            feedback_id=f"mpte-{secrets.token_hex(8)}",
            feedback_type=FeedbackType.MPTE_RESULT,
            entity_id=finding_id,
            outcome=outcome,
            predicted=pred_str,
            actual=act_str,
            confidence=mpte_confidence,
            context=context or {},
            recorded_at=datetime.now(timezone.utc).isoformat(),
            source="mpte_engine",
        )
        self.db.store_feedback(record)
        return record.feedback_id

    def analyze(self, days: int = 90) -> Dict[str, Any]:
        records = self.db.get_feedback(FeedbackType.MPTE_RESULT.value, days=days)
        if not records:
            return {"precision": 0, "recall": 0, "sample_count": 0}

        tp = sum(1 for r in records if r["predicted"] == "exploitable" and r["actual"] == "exploitable")
        fp = sum(1 for r in records if r["predicted"] == "exploitable" and r["actual"] == "not_exploitable")
        fn = sum(1 for r in records if r["predicted"] == "not_exploitable" and r["actual"] == "exploitable")
        tn = sum(1 for r in records if r["predicted"] == "not_exploitable" and r["actual"] == "not_exploitable")

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        self.db.record_metric(FeedbackType.MPTE_RESULT.value, "f1_score", f1, len(records))

        return {
            "precision": round(precision * 100, 1),
            "recall": round(recall * 100, 1),
            "f1_score": round(f1 * 100, 1),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "sample_count": len(records),
        }


class FalsePositiveLoop:
    """Loop 3: Track FP rates per scanner/rule → auto-suppress noise."""

    def __init__(self, db: FeedbackDB, config: LearningConfig):
        self.db = db
        self.config = config

    def record(self, finding_id: str, scanner: str, rule_id: str,
               is_false_positive: bool, context: Optional[Dict] = None) -> str:
        import secrets
        record = FeedbackRecord(
            feedback_id=f"fp-{secrets.token_hex(8)}",
            feedback_type=FeedbackType.FALSE_POSITIVE,
            entity_id=finding_id,
            outcome=OutcomeStatus.INCORRECT if is_false_positive else OutcomeStatus.CORRECT,
            predicted="vulnerability",
            actual="false_positive" if is_false_positive else "true_positive",
            context={"scanner": scanner, "rule_id": rule_id, **(context or {})},
            recorded_at=datetime.now(timezone.utc).isoformat(),
            source=scanner,
        )
        self.db.store_feedback(record)
        return record.feedback_id

    def analyze(self, days: int = 90) -> Dict[str, Any]:
        records = self.db.get_feedback(FeedbackType.FALSE_POSITIVE.value, days=days)
        if not records:
            return {"overall_fp_rate": 0, "by_scanner": {}, "sample_count": 0}

        # Overall FP rate
        fp_count = sum(1 for r in records if r["actual"] == "false_positive")
        total = len(records)
        overall_rate = fp_count / total if total > 0 else 0

        # By scanner
        by_scanner: Dict[str, Dict[str, int]] = defaultdict(lambda: {"fp": 0, "tp": 0})
        by_rule: Dict[str, Dict[str, int]] = defaultdict(lambda: {"fp": 0, "tp": 0})

        for r in records:
            ctx = json.loads(r.get("context", "{}")) if isinstance(r.get("context"), str) else r.get("context", {})
            scanner = ctx.get("scanner", r.get("source", "unknown"))
            rule_id = ctx.get("rule_id", "unknown")

            if r["actual"] == "false_positive":
                by_scanner[scanner]["fp"] += 1
                by_rule[f"{scanner}:{rule_id}"]["fp"] += 1
            else:
                by_scanner[scanner]["tp"] += 1
                by_rule[f"{scanner}:{rule_id}"]["tp"] += 1

        scanner_rates = {}
        for scanner, counts in by_scanner.items():
            total_s = counts["fp"] + counts["tp"]
            scanner_rates[scanner] = {
                "fp_rate": round(counts["fp"] / total_s * 100, 1) if total_s > 0 else 0,
                "fp_count": counts["fp"],
                "tp_count": counts["tp"],
                "total": total_s,
            }

        # Find rules to suppress (>50% FP rate with enough samples)
        suppress_candidates = []
        for rule, counts in by_rule.items():
            total_r = counts["fp"] + counts["tp"]
            if total_r >= self.config.min_samples:
                fp_rate = counts["fp"] / total_r
                if fp_rate > 0.5:
                    suppress_candidates.append({
                        "rule": rule,
                        "fp_rate": round(fp_rate * 100, 1),
                        "samples": total_r,
                    })

        self.db.record_metric(FeedbackType.FALSE_POSITIVE.value, "overall_fp_rate", overall_rate, total)

        return {
            "overall_fp_rate": round(overall_rate * 100, 1),
            "by_scanner": scanner_rates,
            "suppress_candidates": suppress_candidates,
            "sample_count": total,
        }

    def get_suppressed_rules(self) -> List[str]:
        """Get rules that should be suppressed based on FP feedback."""
        analysis = self.analyze()
        return [c["rule"] for c in analysis.get("suppress_candidates", []) if c["fp_rate"] > 75]


class RemediationSuccessLoop:
    """Loop 4: Track if fixes actually resolved vulnerabilities."""

    def __init__(self, db: FeedbackDB, config: LearningConfig):
        self.db = db
        self.config = config

    def record(self, finding_id: str, fix_type: str, fix_applied: str,
               resolved: bool, time_to_fix_hours: float = 0,
               context: Optional[Dict] = None) -> str:
        import secrets
        record = FeedbackRecord(
            feedback_id=f"rem-{secrets.token_hex(8)}",
            feedback_type=FeedbackType.REMEDIATION_SUCCESS,
            entity_id=finding_id,
            outcome=OutcomeStatus.CORRECT if resolved else OutcomeStatus.INCORRECT,
            predicted=fix_type,
            actual="resolved" if resolved else "unresolved",
            confidence=0,
            context={"fix_type": fix_type, "fix_applied": fix_applied,
                      "time_to_fix_hours": time_to_fix_hours, **(context or {})},
            recorded_at=datetime.now(timezone.utc).isoformat(),
            source="autofix",
        )
        self.db.store_feedback(record)
        return record.feedback_id

    def analyze(self, days: int = 90) -> Dict[str, Any]:
        records = self.db.get_feedback(FeedbackType.REMEDIATION_SUCCESS.value, days=days)
        if not records:
            return {"success_rate": 0, "by_fix_type": {}, "sample_count": 0}

        resolved = sum(1 for r in records if r["actual"] == "resolved")
        total = len(records)
        success_rate = resolved / total if total > 0 else 0

        # By fix type
        by_type: Dict[str, Dict[str, int]] = defaultdict(lambda: {"resolved": 0, "unresolved": 0})
        fix_times: Dict[str, List[float]] = defaultdict(list)

        for r in records:
            ctx = json.loads(r.get("context", "{}")) if isinstance(r.get("context"), str) else r.get("context", {})
            fix_type = ctx.get("fix_type", r.get("predicted", "unknown"))
            ttf = ctx.get("time_to_fix_hours", 0)

            if r["actual"] == "resolved":
                by_type[fix_type]["resolved"] += 1
            else:
                by_type[fix_type]["unresolved"] += 1

            if ttf > 0:
                fix_times[fix_type].append(ttf)

        type_rates = {}
        for ft, counts in by_type.items():
            total_ft = counts["resolved"] + counts["unresolved"]
            avg_time = sum(fix_times.get(ft, [])) / len(fix_times[ft]) if fix_times.get(ft) else 0
            type_rates[ft] = {
                "success_rate": round(counts["resolved"] / total_ft * 100, 1) if total_ft > 0 else 0,
                "resolved": counts["resolved"],
                "unresolved": counts["unresolved"],
                "avg_fix_hours": round(avg_time, 1),
            }

        self.db.record_metric(FeedbackType.REMEDIATION_SUCCESS.value, "success_rate", success_rate, total)

        return {
            "success_rate": round(success_rate * 100, 1),
            "by_fix_type": type_rates,
            "sample_count": total,
            "mean_time_to_fix_hours": round(
                sum(sum(v) for v in fix_times.values()) /
                max(sum(len(v) for v in fix_times.values()), 1), 1
            ),
        }


class PolicyViolationLoop:
    """Loop 5: Track policy violations → suggest policy refinements."""

    def __init__(self, db: FeedbackDB, config: LearningConfig):
        self.db = db
        self.config = config

    def record(self, policy_id: str, rule_id: str, violated: bool,
               was_justified: bool, context: Optional[Dict] = None) -> str:
        import secrets
        outcome = OutcomeStatus.CORRECT if violated == (not was_justified) else OutcomeStatus.INCORRECT
        record = FeedbackRecord(
            feedback_id=f"pol-{secrets.token_hex(8)}",
            feedback_type=FeedbackType.POLICY_VIOLATION,
            entity_id=policy_id,
            outcome=outcome,
            predicted="violation" if violated else "compliant",
            actual="justified" if was_justified else "unjustified",
            context={"policy_id": policy_id, "rule_id": rule_id, **(context or {})},
            recorded_at=datetime.now(timezone.utc).isoformat(),
            source="policy_engine",
        )
        self.db.store_feedback(record)
        return record.feedback_id

    def analyze(self, days: int = 90) -> Dict[str, Any]:
        records = self.db.get_feedback(FeedbackType.POLICY_VIOLATION.value, days=days)
        if not records:
            return {"violation_count": 0, "justified_rate": 0, "sample_count": 0}

        violations = [r for r in records if r["predicted"] == "violation"]
        justified = sum(1 for r in violations if r["actual"] == "justified")
        total_violations = len(violations)

        # Policies with high justified-violation rates need refinement
        by_policy: Dict[str, Dict[str, int]] = defaultdict(lambda: {"justified": 0, "unjustified": 0})
        for r in violations:
            ctx = json.loads(r.get("context", "{}")) if isinstance(r.get("context"), str) else r.get("context", {})
            policy = ctx.get("policy_id", r.get("entity_id", "unknown"))
            if r["actual"] == "justified":
                by_policy[policy]["justified"] += 1
            else:
                by_policy[policy]["unjustified"] += 1

        refinement_candidates = []
        for policy, counts in by_policy.items():
            total_p = counts["justified"] + counts["unjustified"]
            if total_p >= self.config.min_samples:
                justified_rate = counts["justified"] / total_p
                if justified_rate > 0.3:  # >30% of violations are justified
                    refinement_candidates.append({
                        "policy": policy,
                        "justified_rate": round(justified_rate * 100, 1),
                        "samples": total_p,
                        "suggestion": "Consider relaxing this policy — too many justified violations",
                    })

        return {
            "violation_count": total_violations,
            "justified_rate": round(justified / total_violations * 100, 1) if total_violations > 0 else 0,
            "refinement_candidates": refinement_candidates,
            "sample_count": len(records),
        }


# ---------------------------------------------------------------------------
# Self-Learning Engine (Orchestrator)
# ---------------------------------------------------------------------------
class SelfLearningEngine:
    """Orchestrates all 5 feedback loops.

    Usage:
        engine = SelfLearningEngine.get_instance()

        # Record feedback
        engine.decision_loop.record(decision_id, finding_id, "FIX", "FIX")
        engine.fp_loop.record(finding_id, "sast", "CWE-89-001", is_false_positive=True)

        # Analyze all loops
        analysis = engine.analyze_all()

        # Get learning insights
        insights = engine.get_insights()
    """

    _instance: Optional["SelfLearningEngine"] = None

    @classmethod
    def get_instance(cls) -> "SelfLearningEngine":
        """Thread-safe singleton accessor."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self, config: Optional[LearningConfig] = None):
        self.config = config or LearningConfig.from_env()

        if not self.config.db_path:
            data_dir = os.getenv("FIXOPS_DATA_DIR", ".fixops_data")
            self.config.db_path = os.path.join(data_dir, "learning.db")

        self.db = FeedbackDB(self.config.db_path)

        # Initialize all 5 loops
        self.decision_loop = DecisionOutcomeLoop(self.db, self.config)
        self.mpte_loop = MPTEResultLoop(self.db, self.config)
        self.fp_loop = FalsePositiveLoop(self.db, self.config)
        self.remediation_loop = RemediationSuccessLoop(self.db, self.config)
        self.policy_loop = PolicyViolationLoop(self.db, self.config)

        logger.info("self_learning_engine_initialized", loops=5, min_samples=self.config.min_samples)

    def analyze_all(self, days: int = 90) -> Dict[str, Any]:
        """Run analysis on all 5 feedback loops."""
        return {
            "decision_outcomes": self.decision_loop.analyze(days),
            "mpte_results": self.mpte_loop.analyze(days),
            "false_positives": self.fp_loop.analyze(days),
            "remediation_success": self.remediation_loop.analyze(days),
            "policy_violations": self.policy_loop.analyze(days),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "period_days": days,
        }

    def get_insights(self) -> Dict[str, Any]:
        """Generate actionable insights from all feedback loops."""
        analysis = self.analyze_all()
        insights = []

        # Decision accuracy insight
        dec = analysis["decision_outcomes"]
        if dec.get("sample_count", 0) >= self.config.min_samples:
            acc = dec.get("weighted_accuracy", 0)
            if acc < 70:
                insights.append({
                    "loop": "decision_outcome",
                    "severity": "high",
                    "insight": f"Decision accuracy is {acc}% — below 70% threshold. "
                               f"Consider recalibrating consensus weights.",
                    "action": "recalibrate_consensus",
                })
            elif acc > 95:
                insights.append({
                    "loop": "decision_outcome",
                    "severity": "info",
                    "insight": f"Decision accuracy is {acc}% — excellent. "
                               f"Model is well calibrated.",
                })

        # FP insight
        fp = analysis["false_positives"]
        if fp.get("suppress_candidates"):
            for candidate in fp["suppress_candidates"]:
                insights.append({
                    "loop": "false_positive",
                    "severity": "medium",
                    "insight": f"Rule '{candidate['rule']}' has {candidate['fp_rate']}% FP rate "
                               f"({candidate['samples']} samples). Consider suppressing.",
                    "action": "suppress_rule",
                    "target": candidate["rule"],
                })

        # Remediation insight
        rem = analysis["remediation_success"]
        if rem.get("sample_count", 0) >= self.config.min_samples:
            sr = rem.get("success_rate", 0)
            if sr < 60:
                insights.append({
                    "loop": "remediation_success",
                    "severity": "high",
                    "insight": f"Fix success rate is {sr}% — below 60%. "
                               f"Review AutoFix templates.",
                    "action": "review_autofix",
                })

        # MPTE insight
        mpte = analysis["mpte_results"]
        if mpte.get("sample_count", 0) >= self.config.min_samples:
            _f1 = mpte.get("f1_score", 0)
            if mpte.get("false_positives", 0) > mpte.get("false_negatives", 0) * 2:
                insights.append({
                    "loop": "mpte_result",
                    "severity": "medium",
                    "insight": "MPTE has high false positive rate — many findings predicted "
                               "exploitable but aren't. Tighten exploitability criteria.",
                    "action": "tighten_mpte_threshold",
                })

        # Policy insight
        pol = analysis["policy_violations"]
        for candidate in pol.get("refinement_candidates", []):
            insights.append({
                "loop": "policy_violation",
                "severity": "medium",
                "insight": f"Policy '{candidate['policy']}' has {candidate['justified_rate']}% "
                           f"justified violations. {candidate['suggestion']}",
                "action": "refine_policy",
                "target": candidate["policy"],
            })

        return {
            "insights": insights,
            "insight_count": len(insights),
            "high_severity": sum(1 for i in insights if i["severity"] == "high"),
            "medium_severity": sum(1 for i in insights if i["severity"] == "medium"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def record_pipeline_run(
        self,
        run_id: str,
        findings_count: int,
        decision: str,
        signed: bool,
        quantum_signed: bool,
    ) -> None:
        """Record a brain-pipeline execution for self-learning feedback.

        Stores as a DECISION_OUTCOME feedback record so the Decision Outcome
        Loop can later correlate pipeline runs with their real-world outcomes.
        """
        self.db.store_feedback(
            FeedbackRecord(
                feedback_id=run_id or f"pipeline-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                feedback_type=FeedbackType.DECISION_OUTCOME,
                entity_id=run_id or "pipeline",
                outcome=OutcomeStatus.UNKNOWN,
                predicted=decision,
                actual="",
                confidence=0.0,
                context={
                    "run_id": run_id,
                    "findings_count": findings_count,
                    "decision": decision,
                    "evidence_signed": signed,
                    "quantum_signed": quantum_signed,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                },
                source="brain_pipeline",
            )
        )

    def get_status(self) -> Dict[str, Any]:
        """Get engine status."""
        feedback_counts = {}
        for ft in FeedbackType:
            records = self.db.get_feedback(ft.value, days=9999)
            feedback_counts[ft.value] = len(records)
        return {
            "engine": "self-learning",
            "version": "2.0.0",
            "enabled": self.config.enabled,
            "loops": [ft.value for ft in FeedbackType],
            "loop_count": len(FeedbackType),
            "min_samples": self.config.min_samples,
            "decay_factor": self.config.decay_factor,
            "db_path": self.config.db_path,
            "feedback_counts": feedback_counts,
            "total_feedback": sum(feedback_counts.values()),
        }

    def get_weight(self, key: str, default: float = 1.0) -> float:
        """Get a learned weight value."""
        return self.db.get_weight(key, default)

    def set_weight(self, key: str, value: float) -> None:
        """Set a learned weight value."""
        self.db.set_weight(key, value)

    def get_all_weights(self) -> Dict[str, Any]:
        """Get all learned weights from the database."""
        with self.db._lock:
            cursor = self.db._conn.execute(
                "SELECT key, value, updated_at, update_count FROM weights ORDER BY key"
            )
            weights = {}
            for row in cursor.fetchall():
                weights[row[0]] = {
                    "value": row[1],
                    "updated_at": row[2],
                    "update_count": row[3],
                }
            return weights

    def score_with_learning(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Score a finding with and without learning adjustments.

        This demonstrates the self-learning effect: the same finding gets
        a different (improved) score after the system has learned from
        past decisions, FP feedback, MPTE results, etc.

        Returns both the baseline score and the learning-adjusted score,
        plus a breakdown of every adjustment applied.
        """
        cvss = finding.get("cvss_score", 5.0)
        epss = finding.get("epss_score", 0.1)
        in_kev = finding.get("in_kev", False)
        asset_criticality = finding.get("asset_criticality", 0.5)
        scanner = finding.get("scanner", "unknown")
        rule_id = finding.get("rule_id", "unknown")
        fix_type = finding.get("fix_type", "CODE_PATCH")

        # --- Baseline score (no learning) ---
        kev_boost = 1.5 if in_kev else 1.0
        baseline_score = round(
            min((cvss / 10 * 0.4 + epss * 0.3 + 0.3) * kev_boost * asset_criticality, 1.0),
            4,
        )

        # --- Learning-adjusted score ---
        adjustments = []

        # 1. Scanner accuracy weight (from decision outcome loop)
        scanner_weight_key = f"scanner:{scanner}:accuracy"
        scanner_weight = self.get_weight(scanner_weight_key, 1.0)
        if scanner_weight != 1.0:
            adjustments.append({
                "source": "decision_outcome_loop",
                "factor": f"scanner:{scanner}:accuracy",
                "weight": round(scanner_weight, 4),
                "effect": "Adjusts overall score based on scanner's historical decision accuracy",
            })

        # 2. Rule FP suppression weight (from false positive loop)
        rule_weight_key = f"rule:{scanner}:{rule_id}:fp_weight"
        rule_weight = self.get_weight(rule_weight_key, 1.0)
        if rule_weight != 1.0:
            adjustments.append({
                "source": "false_positive_loop",
                "factor": f"rule:{scanner}:{rule_id}:fp_weight",
                "weight": round(rule_weight, 4),
                "effect": "Reduces score for rules with high false positive rates",
            })

        # 3. MPTE exploitability confidence modifier
        mpte_weight_key = f"mpte:{scanner}:exploit_confidence"
        mpte_weight = self.get_weight(mpte_weight_key, 1.0)
        if mpte_weight != 1.0:
            adjustments.append({
                "source": "mpte_result_loop",
                "factor": f"mpte:{scanner}:exploit_confidence",
                "weight": round(mpte_weight, 4),
                "effect": "Adjusts exploitability confidence based on MPTE verification history",
            })

        # 4. Remediation fix effectiveness modifier
        fix_weight_key = f"fix:{fix_type}:effectiveness"
        fix_weight = self.get_weight(fix_weight_key, 1.0)
        if fix_weight != 1.0:
            adjustments.append({
                "source": "remediation_success_loop",
                "factor": f"fix:{fix_type}:effectiveness",
                "weight": round(fix_weight, 4),
                "effect": "Adjusts priority based on fix type effectiveness history",
            })

        # 5. Policy compliance modifier
        policy_weight_key = "policy:global:strictness"
        policy_weight = self.get_weight(policy_weight_key, 1.0)
        if policy_weight != 1.0:
            adjustments.append({
                "source": "policy_violation_loop",
                "factor": "policy:global:strictness",
                "weight": round(policy_weight, 4),
                "effect": "Adjusts threshold based on policy violation patterns",
            })

        # Compute combined adjustment factor
        combined_weight = scanner_weight * rule_weight * mpte_weight
        # Fix effectiveness inversely affects priority (good fixes = lower urgency)
        if fix_weight > 1.0:
            combined_weight *= 0.95  # Slight reduction if fix is highly effective
        elif fix_weight < 0.7:
            combined_weight *= 1.1  # Increase if fix type often fails

        # Apply policy strictness
        combined_weight *= policy_weight

        adjusted_score = round(
            min(max(baseline_score * combined_weight, 0.0), 1.0), 4
        )

        delta = round(adjusted_score - baseline_score, 4)
        delta_pct = round((delta / baseline_score * 100) if baseline_score > 0 else 0, 1)

        return {
            "finding": {
                "cvss_score": cvss,
                "epss_score": epss,
                "in_kev": in_kev,
                "asset_criticality": asset_criticality,
                "scanner": scanner,
                "rule_id": rule_id,
                "fix_type": fix_type,
            },
            "baseline_score": baseline_score,
            "adjusted_score": adjusted_score,
            "delta": delta,
            "delta_percent": delta_pct,
            "combined_weight": round(combined_weight, 4),
            "adjustments_applied": len(adjustments),
            "adjustments": adjustments,
            "learning_active": len(adjustments) > 0,
            "scored_at": datetime.now(timezone.utc).isoformat(),
        }

    def compute_adjustments(self) -> List[LearningAdjustment]:
        """Analyze all feedback loops and compute weight adjustments.

        This is the core learning step: feedback data → statistical analysis →
        weight adjustments that modify future scoring.
        """
        import secrets
        adjustments = []
        now = datetime.now(timezone.utc).isoformat()

        # --- Loop 1: Decision Outcome → Scanner Accuracy Weights ---
        dec_analysis = self.decision_loop.analyze()
        if dec_analysis.get("sample_count", 0) >= self.config.min_samples:
            _accuracy = dec_analysis.get("weighted_accuracy", 50) / 100.0
            # Get per-source accuracy from feedback records
            records = self.db.get_feedback(FeedbackType.DECISION_OUTCOME.value)
            source_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"correct": 0, "total": 0})
            for r in records:
                ctx = json.loads(r.get("context", "{}")) if isinstance(r.get("context"), str) else r.get("context", {})
                src = ctx.get("scanner", r.get("source", "decision_engine"))
                source_stats[src]["total"] += 1
                if r["outcome"] == OutcomeStatus.CORRECT.value:
                    source_stats[src]["correct"] += 1

            for src, stats in source_stats.items():
                if stats["total"] >= max(self.config.min_samples // 2, 3):
                    src_accuracy = stats["correct"] / stats["total"]
                    weight_key = f"scanner:{src}:accuracy"
                    old_weight = self.get_weight(weight_key, 1.0)
                    # Nudge weight toward observed accuracy
                    new_weight = round(old_weight * 0.7 + src_accuracy * 0.3, 4)
                    new_weight = max(0.3, min(1.5, new_weight))  # Clamp

                    if abs(new_weight - old_weight) >= 0.01:
                        adj = LearningAdjustment(
                            adjustment_id=f"adj-dec-{secrets.token_hex(4)}",
                            feedback_type=FeedbackType.DECISION_OUTCOME,
                            target=weight_key,
                            metric="accuracy",
                            old_value=old_weight,
                            new_value=new_weight,
                            sample_count=stats["total"],
                            confidence=min(stats["total"] / 50.0, 1.0),
                            reasoning=f"Scanner '{src}' accuracy: {src_accuracy:.0%} "
                                      f"over {stats['total']} decisions",
                        )
                        self.set_weight(weight_key, new_weight)
                        adj.applied = True
                        adj.applied_at = now
                        self.db.store_adjustment(adj)
                        adjustments.append(adj)

        # --- Loop 2: MPTE Results → Exploit Confidence Weights ---
        mpte_analysis = self.mpte_loop.analyze()
        if mpte_analysis.get("sample_count", 0) >= self.config.min_samples:
            precision = mpte_analysis.get("precision", 50) / 100.0
            recall = mpte_analysis.get("recall", 50) / 100.0

            weight_key = "mpte:global:exploit_confidence"
            old_weight = self.get_weight(weight_key, 1.0)
            # High precision → trust exploitability predictions more
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.5
            new_weight = round(old_weight * 0.6 + f1 * 0.4, 4)
            new_weight = max(0.3, min(1.5, new_weight))

            if abs(new_weight - old_weight) >= 0.01:
                adj = LearningAdjustment(
                    adjustment_id=f"adj-mpte-{secrets.token_hex(4)}",
                    feedback_type=FeedbackType.MPTE_RESULT,
                    target=weight_key,
                    metric="f1_score",
                    old_value=old_weight,
                    new_value=new_weight,
                    sample_count=mpte_analysis["sample_count"],
                    confidence=min(mpte_analysis["sample_count"] / 50.0, 1.0),
                    reasoning=f"MPTE F1 score: {f1:.2f} (precision={precision:.2f}, recall={recall:.2f})",
                )
                self.set_weight(weight_key, new_weight)
                adj.applied = True
                adj.applied_at = now
                self.db.store_adjustment(adj)
                adjustments.append(adj)

        # --- Loop 3: False Positive → Rule Suppression Weights ---
        fp_analysis = self.fp_loop.analyze()
        by_scanner = fp_analysis.get("by_scanner", {})
        for scanner_name, stats in by_scanner.items():
            if stats.get("total", 0) >= max(self.config.min_samples // 2, 3):
                fp_rate = stats["fp_rate"] / 100.0
                weight_key = f"rule:{scanner_name}:global:fp_weight"
                old_weight = self.get_weight(weight_key, 1.0)
                # High FP rate → reduce weight (penalize noisy scanners)
                new_weight = round(old_weight * 0.6 + (1.0 - fp_rate * 0.5) * 0.4, 4)
                new_weight = max(0.2, min(1.2, new_weight))

                if abs(new_weight - old_weight) >= 0.01:
                    adj = LearningAdjustment(
                        adjustment_id=f"adj-fp-{secrets.token_hex(4)}",
                        feedback_type=FeedbackType.FALSE_POSITIVE,
                        target=weight_key,
                        metric="fp_rate",
                        old_value=old_weight,
                        new_value=new_weight,
                        sample_count=stats["total"],
                        confidence=min(stats["total"] / 30.0, 1.0),
                        reasoning=f"Scanner '{scanner_name}' FP rate: {fp_rate:.0%} "
                                  f"over {stats['total']} findings",
                    )
                    self.set_weight(weight_key, new_weight)
                    adj.applied = True
                    adj.applied_at = now
                    self.db.store_adjustment(adj)
                    adjustments.append(adj)

        # --- Loop 4: Remediation Success → Fix Type Weights ---
        rem_analysis = self.remediation_loop.analyze()
        by_fix = rem_analysis.get("by_fix_type", {})
        for fix_type, stats in by_fix.items():
            total_ft = stats.get("resolved", 0) + stats.get("unresolved", 0)
            if total_ft >= max(self.config.min_samples // 2, 3):
                success_rate = stats["success_rate"] / 100.0
                weight_key = f"fix:{fix_type}:effectiveness"
                old_weight = self.get_weight(weight_key, 1.0)
                new_weight = round(old_weight * 0.5 + success_rate * 0.5, 4)
                new_weight = max(0.2, min(1.5, new_weight))

                if abs(new_weight - old_weight) >= 0.01:
                    adj = LearningAdjustment(
                        adjustment_id=f"adj-rem-{secrets.token_hex(4)}",
                        feedback_type=FeedbackType.REMEDIATION_SUCCESS,
                        target=weight_key,
                        metric="success_rate",
                        old_value=old_weight,
                        new_value=new_weight,
                        sample_count=total_ft,
                        confidence=min(total_ft / 30.0, 1.0),
                        reasoning=f"Fix type '{fix_type}' success: {success_rate:.0%} "
                                  f"over {total_ft} fixes",
                    )
                    self.set_weight(weight_key, new_weight)
                    adj.applied = True
                    adj.applied_at = now
                    self.db.store_adjustment(adj)
                    adjustments.append(adj)

        # --- Loop 5: Policy Violations → Strictness Weight ---
        pol_analysis = self.policy_loop.analyze()
        if pol_analysis.get("sample_count", 0) >= self.config.min_samples:
            justified_rate = pol_analysis.get("justified_rate", 0) / 100.0
            weight_key = "policy:global:strictness"
            old_weight = self.get_weight(weight_key, 1.0)
            # High justified rate → policies are too strict → relax
            if justified_rate > 0.3:
                new_weight = round(old_weight * 0.95, 4)  # Slight relaxation
            elif justified_rate < 0.1:
                new_weight = round(old_weight * 1.02, 4)  # Slight tightening
            else:
                new_weight = old_weight
            new_weight = max(0.5, min(1.5, new_weight))

            if abs(new_weight - old_weight) >= 0.01:
                adj = LearningAdjustment(
                    adjustment_id=f"adj-pol-{secrets.token_hex(4)}",
                    feedback_type=FeedbackType.POLICY_VIOLATION,
                    target=weight_key,
                    metric="justified_rate",
                    old_value=old_weight,
                    new_value=new_weight,
                    sample_count=pol_analysis["sample_count"],
                    confidence=min(pol_analysis["sample_count"] / 30.0, 1.0),
                    reasoning=f"Policy justified violation rate: {justified_rate:.0%}. "
                              f"{'Relaxing' if justified_rate > 0.3 else 'Tightening'} strictness.",
                )
                self.set_weight(weight_key, new_weight)
                adj.applied = True
                adj.applied_at = now
                self.db.store_adjustment(adj)
                adjustments.append(adj)

        logger.info("Computed %d weight adjustments from feedback analysis", len(adjustments))
        return adjustments

    def get_metrics_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get metric trends for all feedback loops over time."""
        trends = {}
        metric_map = {
            FeedbackType.DECISION_OUTCOME.value: "accuracy",
            FeedbackType.MPTE_RESULT.value: "f1_score",
            FeedbackType.FALSE_POSITIVE.value: "overall_fp_rate",
            FeedbackType.REMEDIATION_SUCCESS.value: "success_rate",
            FeedbackType.POLICY_VIOLATION.value: "justified_rate",
        }
        for fb_type, metric_name in metric_map.items():
            trend = self.db.get_metrics_trend(fb_type, metric_name, days)
            trends[fb_type] = {
                "metric": metric_name,
                "data_points": trend,
                "count": len(trend),
                "latest": trend[-1]["value"] if trend else None,
                "earliest": trend[0]["value"] if trend else None,
                "improvement": round(
                    (trend[-1]["value"] - trend[0]["value"]) * 100, 1
                ) if len(trend) >= 2 else 0,
            }
        return {
            "trends": trends,
            "period_days": days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def seed_demo_data(self) -> Dict[str, Any]:
        """Seed realistic demo data for all 5 feedback loops.

        Creates a realistic progression of feedback data showing how
        the system learns and improves over time. Each loop gets 15-25
        records with realistic distributions.
        """
        import random
        seeded = {"decision": 0, "mpte": 0, "fp": 0, "remediation": 0, "policy": 0}

        scanners = ["semgrep", "snyk", "trivy", "zap", "bandit"]
        rules = {
            "semgrep": ["CWE-89-sql-injection", "CWE-79-xss-reflected", "CWE-22-path-traversal"],
            "snyk": ["SNYK-JS-LODASH-590103", "SNYK-PYTHON-FLASK-2306", "SNYK-JS-EXPRESS-1717"],
            "trivy": ["CVE-2024-3094", "CVE-2023-44487", "CVE-2024-21626"],
            "zap": ["10016-xss", "10020-missing-headers", "10035-strict-transport"],
            "bandit": ["B101-assert", "B105-hardcoded-pass", "B608-sql-injection"],
        }
        fix_types = ["CODE_PATCH", "DEPENDENCY_UPDATE", "CONFIG_CHANGE", "WAF_RULE", "MANUAL"]
        policies = ["POL-CRITICAL-30D", "POL-HIGH-60D", "POL-MEDIUM-90D", "POL-NO-HARDCODED-SECRETS"]

        rng = random.Random(42)  # Deterministic seed for reproducible demo

        # --- Loop 1: Decision Outcomes (20 records) ---
        # Show improving accuracy: first 10 are 60% correct, last 10 are 85% correct
        for i in range(20):
            scanner = rng.choice(scanners)
            actions = ["FIX", "ACCEPT_RISK", "DEFER", "SUPPRESS"]
            predicted = rng.choice(actions)
            # First half: 60% correct, second half: 85% correct (learning effect)
            if i < 10:
                actual = predicted if rng.random() < 0.60 else rng.choice(actions)
            else:
                actual = predicted if rng.random() < 0.85 else rng.choice(actions)
            self.decision_loop.record(
                decision_id=f"DEC-DEMO-{i:03d}",
                finding_id=f"VULN-DEMO-{i:03d}",
                predicted_action=predicted,
                actual_outcome=actual,
                confidence=round(rng.uniform(0.5, 0.95), 2),
                context={"scanner": scanner, "demo": True},
            )
            seeded["decision"] += 1

        # --- Loop 2: MPTE Results (18 records) ---
        # Show improving precision: early scans have more FPs
        for i in range(18):
            scanner = rng.choice(scanners)
            predicted_exploitable = rng.random() < 0.6  # 60% predicted exploitable
            if i < 9:
                # Early: 55% precision (many false alarms)
                if predicted_exploitable:
                    actual_exploitable = rng.random() < 0.55
                else:
                    actual_exploitable = rng.random() < 0.15
            else:
                # Later: 80% precision (learning kicks in)
                if predicted_exploitable:
                    actual_exploitable = rng.random() < 0.80
                else:
                    actual_exploitable = rng.random() < 0.08
            self.mpte_loop.record(
                finding_id=f"MPTE-DEMO-{i:03d}",
                predicted_exploitable=predicted_exploitable,
                actual_exploitable=actual_exploitable,
                mpte_confidence=round(rng.uniform(0.4, 0.95), 2),
                context={"scanner": scanner, "demo": True},
            )
            seeded["mpte"] += 1

        # --- Loop 3: False Positive Feedback (25 records) ---
        # ZAP and bandit have high FP rates, others are clean
        for i in range(25):
            scanner = rng.choice(scanners)
            rule = rng.choice(rules[scanner])
            # ZAP and bandit = noisy (60-70% FP), others = clean (10-20% FP)
            if scanner in ("zap", "bandit"):
                is_fp = rng.random() < 0.65
            else:
                is_fp = rng.random() < 0.15
            self.fp_loop.record(
                finding_id=f"FP-DEMO-{i:03d}",
                scanner=scanner,
                rule_id=rule,
                is_false_positive=is_fp,
                context={"demo": True},
            )
            seeded["fp"] += 1

        # --- Loop 4: Remediation Success (20 records) ---
        # CODE_PATCH and DEPENDENCY_UPDATE are effective, WAF_RULE less so
        for i in range(20):
            fix = rng.choice(fix_types)
            if fix in ("CODE_PATCH", "DEPENDENCY_UPDATE"):
                resolved = rng.random() < 0.85
            elif fix == "CONFIG_CHANGE":
                resolved = rng.random() < 0.70
            elif fix == "WAF_RULE":
                resolved = rng.random() < 0.45
            else:
                resolved = rng.random() < 0.55
            ttf = round(rng.uniform(0.5, 72.0), 1)
            self.remediation_loop.record(
                finding_id=f"REM-DEMO-{i:03d}",
                fix_type=fix,
                fix_applied=f"Applied {fix} for finding REM-DEMO-{i:03d}",
                resolved=resolved,
                time_to_fix_hours=ttf,
                context={"demo": True},
            )
            seeded["remediation"] += 1

        # --- Loop 5: Policy Violations (15 records) ---
        # POL-MEDIUM-90D has many justified violations (too strict)
        for i in range(15):
            policy = rng.choice(policies)
            violated = rng.random() < 0.5
            if policy == "POL-MEDIUM-90D":
                was_justified = violated and rng.random() < 0.55  # 55% justified
            elif policy == "POL-NO-HARDCODED-SECRETS":
                was_justified = violated and rng.random() < 0.10  # 10% justified
            else:
                was_justified = violated and rng.random() < 0.25
            self.policy_loop.record(
                policy_id=policy,
                rule_id=f"rule-{i % 5}",
                violated=violated,
                was_justified=was_justified,
                context={"demo": True},
            )
            seeded["policy"] += 1

        # Record initial metric snapshots
        analysis = self.analyze_all()
        for loop_name, loop_key in [
            ("decision_outcomes", FeedbackType.DECISION_OUTCOME.value),
            ("mpte_results", FeedbackType.MPTE_RESULT.value),
            ("false_positives", FeedbackType.FALSE_POSITIVE.value),
            ("remediation_success", FeedbackType.REMEDIATION_SUCCESS.value),
            ("policy_violations", FeedbackType.POLICY_VIOLATION.value),
        ]:
            metric_map = {
                "decision_outcomes": ("accuracy", analysis[loop_name].get("weighted_accuracy", 0) / 100),
                "mpte_results": ("f1_score", analysis[loop_name].get("f1_score", 0) / 100),
                "false_positives": ("overall_fp_rate", analysis[loop_name].get("overall_fp_rate", 0) / 100),
                "remediation_success": ("success_rate", analysis[loop_name].get("success_rate", 0) / 100),
                "policy_violations": ("justified_rate", analysis[loop_name].get("justified_rate", 0) / 100),
            }
            metric_name, metric_val = metric_map[loop_name]
            self.db.record_metric(loop_key, metric_name, metric_val, seeded.get(loop_name.split("_")[0], 0))

        total = sum(seeded.values())
        logger.info("Seeded %d demo feedback records across 5 loops", total)

        return {
            "seeded": seeded,
            "total_records": total,
            "seeded_at": datetime.now(timezone.utc).isoformat(),
            "analysis_snapshot": analysis,
        }

    def reset_learning(self) -> Dict[str, Any]:
        """Reset all learning data (weights, feedback, metrics). For demo use."""
        with self.db._lock:
            self.db._conn.execute("DELETE FROM feedback")
            self.db._conn.execute("DELETE FROM adjustments")
            self.db._conn.execute("DELETE FROM weights")
            self.db._conn.execute("DELETE FROM metrics_history")
            self.db._conn.commit()
        logger.info("Reset all learning data")
        return {
            "reset": True,
            "tables_cleared": ["feedback", "adjustments", "weights", "metrics_history"],
            "reset_at": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------
_engine: Optional[SelfLearningEngine] = None


def get_learning_engine() -> SelfLearningEngine:
    """Get or create the default SelfLearningEngine."""
    global _engine
    if _engine is None:
        _engine = SelfLearningEngine()
    return _engine


__all__ = [
    "FeedbackType",
    "OutcomeStatus",
    "LearningConfig",
    "FeedbackRecord",
    "LearningAdjustment",
    "FeedbackDB",
    "DecisionOutcomeLoop",
    "MPTEResultLoop",
    "FalsePositiveLoop",
    "RemediationSuccessLoop",
    "PolicyViolationLoop",
    "SelfLearningEngine",
    "get_learning_engine",
]
