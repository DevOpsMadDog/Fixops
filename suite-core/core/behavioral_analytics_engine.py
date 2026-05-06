"""Behavioral Analytics Engine — ALDECI.

Monitors user behavior baselines and detects anomalies:
  - Baseline establishment per user per behavior dimension
  - Anomaly detection with severity scoring
  - Alert lifecycle management (new → investigating → confirmed/false_positive/resolved)
  - User risk profiling
  - Org-level behavioral stats

Compliance: UEBA frameworks, NIST SP 800-207, ISO 27001 A.12.4
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "behavioral_analytics.db"
)

# ---------------------------------------------------------------------------
# ML anomaly detector (optional — degrades gracefully if unavailable)
# ---------------------------------------------------------------------------

try:
    from core.ml.anomaly_detector import AnomalyDetector as _AnomalyDetector
    _anomaly_ml: Optional[_AnomalyDetector] = _AnomalyDetector()
    _anomaly_ml.fit_from_synthetic_baseline()
except (ImportError, Exception):
    _anomaly_ml = None

_VALID_BEHAVIOR_TYPES = {
    "login_anomaly", "data_access_spike", "privilege_escalation",
    "lateral_movement", "exfiltration_attempt", "policy_violation",
    "off_hours_activity", "geo_anomaly",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_BASELINE_TYPES = {
    "login_hours", "access_volume", "data_transfer",
    "command_frequency", "location",
}
_VALID_ALERT_STATUSES = {"new", "investigating", "confirmed", "false_positive", "resolved"}

_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS ba_baselines (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    baseline_type  TEXT NOT NULL DEFAULT 'login_hours',
    normal_value   REAL NOT NULL DEFAULT 0.0,
    std_deviation  REAL NOT NULL DEFAULT 0.0,
    samples_count  INTEGER NOT NULL DEFAULT 0,
    established_at DATETIME,
    updated_at     DATETIME,
    UNIQUE(org_id, user_id, baseline_type)
);

CREATE TABLE IF NOT EXISTS ba_anomalies (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    behavior_type   TEXT NOT NULL DEFAULT 'login_anomaly',
    severity        TEXT NOT NULL DEFAULT 'medium',
    observed_value  REAL NOT NULL DEFAULT 0.0,
    baseline_value  REAL NOT NULL DEFAULT 0.0,
    deviation_score REAL NOT NULL DEFAULT 0.0,
    description     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'new',
    notes           TEXT NOT NULL DEFAULT '',
    detected_at     DATETIME,
    resolved_at     DATETIME
);

CREATE TABLE IF NOT EXISTS commit_signals (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL,
    author_email  TEXT NOT NULL,
    signal_type   TEXT NOT NULL,
    evidence      TEXT NOT NULL DEFAULT '{}',
    commit_sha    TEXT NOT NULL DEFAULT '',
    created_at    DATETIME NOT NULL,
    UNIQUE(org_id, author_email, signal_type, commit_sha)
);

CREATE INDEX IF NOT EXISTS idx_commit_signals_org_author
    ON commit_signals (org_id, author_email, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_commit_signals_type
    ON commit_signals (org_id, signal_type, created_at DESC);
"""

# SCM signal detection patterns
_IAM_PRIV_PATTERN = re.compile(r"(_iam_|rbac|permissions)", re.IGNORECASE)
_SECRET_FILE_PATTERN = re.compile(
    r"(\.env$|\.env\.|\.pem$|\.key$|credentials\.|\.secrets\.|secrets\.)",
    re.IGNORECASE,
)
_BULK_RENAME_THRESHOLD = 50
_OFF_HOURS_START = 9  # inclusive
_OFF_HOURS_END = 18   # exclusive — on-hours is [9, 18)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BehavioralAnalyticsEngine:
    """SQLite WAL-backed UEBA engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_DDL)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    def establish_baseline(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a user behavioral baseline."""
        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required")

        baseline_type = data.get("baseline_type", "login_hours")
        if baseline_type not in _VALID_BASELINE_TYPES:
            raise ValueError(
                f"Invalid baseline_type {baseline_type!r}. "
                f"Must be one of {sorted(_VALID_BASELINE_TYPES)}"
            )

        now = _now_iso()
        normal_value = float(data.get("normal_value", 0.0))
        std_deviation = float(data.get("std_deviation", 0.0))
        samples_count = int(data.get("samples_count", 0))

        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM ba_baselines WHERE org_id = ? AND user_id = ? AND baseline_type = ?",
                    (org_id, user_id, baseline_type),
                ).fetchone()

                if existing:
                    conn.execute(
                        """UPDATE ba_baselines
                           SET normal_value = ?, std_deviation = ?, samples_count = ?, updated_at = ?
                           WHERE org_id = ? AND user_id = ? AND baseline_type = ?""",
                        (normal_value, std_deviation, samples_count, now,
                         org_id, user_id, baseline_type),
                    )
                    row = conn.execute(
                        "SELECT * FROM ba_baselines WHERE org_id = ? AND user_id = ? AND baseline_type = ?",
                        (org_id, user_id, baseline_type),
                    ).fetchone()
                    return self._row(row)
                else:
                    baseline_id = str(uuid.uuid4())
                    new_row = {
                        "id": baseline_id,
                        "org_id": org_id,
                        "user_id": user_id,
                        "baseline_type": baseline_type,
                        "normal_value": normal_value,
                        "std_deviation": std_deviation,
                        "samples_count": samples_count,
                        "established_at": now,
                        "updated_at": now,
                    }
                    conn.execute(
                        """INSERT INTO ba_baselines
                           (id, org_id, user_id, baseline_type, normal_value,
                            std_deviation, samples_count, established_at, updated_at)
                           VALUES
                           (:id, :org_id, :user_id, :baseline_type, :normal_value,
                            :std_deviation, :samples_count, :established_at, :updated_at)""",
                        new_row,
                    )
                    return new_row

    def list_baselines(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        baseline_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List baselines with optional filters."""
        sql = "SELECT * FROM ba_baselines WHERE org_id = ?"
        params: list = [org_id]

        if user_id is not None:
            sql += " AND user_id = ?"
            params.append(user_id)
        if baseline_type is not None:
            sql += " AND baseline_type = ?"
            params.append(baseline_type)

        sql += " ORDER BY established_at DESC"

        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Anomaly Detection
    # ------------------------------------------------------------------

    def detect_anomaly(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a detected behavioral anomaly."""
        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required")

        behavior_type = data.get("behavior_type", "login_anomaly")
        if behavior_type not in _VALID_BEHAVIOR_TYPES:
            raise ValueError(
                f"Invalid behavior_type {behavior_type!r}. "
                f"Must be one of {sorted(_VALID_BEHAVIOR_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        anomaly_id = str(uuid.uuid4())
        now = _now_iso()

        row = {
            "id": anomaly_id,
            "org_id": org_id,
            "user_id": user_id,
            "behavior_type": behavior_type,
            "severity": severity,
            "observed_value": float(data.get("observed_value", 0.0)),
            "baseline_value": float(data.get("baseline_value", 0.0)),
            "deviation_score": float(data.get("deviation_score", 0.0)),
            "description": data.get("description", ""),
            "status": "new",
            "notes": "",
            "detected_at": data.get("detected_at") or now,
            "resolved_at": None,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ba_anomalies
                       (id, org_id, user_id, behavior_type, severity,
                        observed_value, baseline_value, deviation_score,
                        description, status, notes, detected_at, resolved_at)
                       VALUES
                       (:id, :org_id, :user_id, :behavior_type, :severity,
                        :observed_value, :baseline_value, :deviation_score,
                        :description, :status, :notes, :detected_at, :resolved_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("ANOMALY_DETECTED", {"entity_type": "behavioral_anomaly", "entity_id": str(anomaly_id), "org_id": org_id, "source_engine": "behavioral_analytics_engine"})
            except Exception:
                pass  # Event emission should never break the main operation
        return row

    def list_anomalies(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        behavior_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List anomalies with optional filters, ordered newest first."""
        sql = "SELECT * FROM ba_anomalies WHERE org_id = ?"
        params: list = [org_id]

        if user_id is not None:
            sql += " AND user_id = ?"
            params.append(user_id)
        if behavior_type is not None:
            sql += " AND behavior_type = ?"
            params.append(behavior_type)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)

        sql += " ORDER BY detected_at DESC"

        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def update_anomaly_status(
        self,
        org_id: str,
        anomaly_id: str,
        status: str,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Update the status of an anomaly."""
        if status not in _VALID_ALERT_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. "
                f"Must be one of {sorted(_VALID_ALERT_STATUSES)}"
            )

        now = _now_iso()
        resolved_at = now if status == "resolved" else None

        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM ba_anomalies WHERE org_id = ? AND id = ?",
                    (org_id, anomaly_id),
                ).fetchone()
                if not existing:
                    return None

                conn.execute(
                    """UPDATE ba_anomalies
                       SET status = ?, notes = ?, resolved_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (status, notes, resolved_at, org_id, anomaly_id),
                )
                row = conn.execute(
                    "SELECT * FROM ba_anomalies WHERE org_id = ? AND id = ?",
                    (org_id, anomaly_id),
                ).fetchone()
                return self._row(row) if row else None

    # ------------------------------------------------------------------
    # User Risk Profile
    # ------------------------------------------------------------------

    def get_user_risk_profile(self, org_id: str, user_id: str) -> Dict[str, Any]:
        """Return a risk profile for a specific user.

        Perf: previously 5 sequential COUNT queries; now a single aggregated
        query (COUNT(*) + SUM(CASE) + MAX) — ~5x fewer SQLite round-trips.
        """
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*)                                                      AS total_anomalies,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END)       AS critical_count,
                    SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END)       AS high_count,
                    SUM(CASE WHEN status NOT IN ('resolved','false_positive')
                             THEN 1 ELSE 0 END)                                  AS open_anomalies,
                    MAX(detected_at)                                              AS last_anomaly_at
                FROM ba_anomalies
                WHERE org_id = ? AND user_id = ?
                """,
                (org_id, user_id),
            ).fetchone()

        total_anomalies  = row["total_anomalies"]  or 0
        critical_count   = row["critical_count"]   or 0
        high_count       = row["high_count"]        or 0
        open_anomalies   = row["open_anomalies"]    or 0
        last_anomaly_at  = row["last_anomaly_at"]

        if _anomaly_ml is not None:
            try:
                # Map behavioral anomaly counts into scan-finding format for ML
                findings = (
                    [{"severity": "critical"} for _ in range(critical_count)]
                    + [{"severity": "high"} for _ in range(high_count)]
                    + [{"severity": "medium"} for _ in range(max(0, open_anomalies - critical_count - high_count))]
                )
                ml_result = _anomaly_ml.detect(findings)
                # anomaly_score is -1 (most anomalous) to 1 (most normal); map to 0-100 risk
                risk_score = round(max(0.0, min(100.0, (1.0 - ml_result.anomaly_score) * 50.0)), 2)
            except Exception:
                risk_score = min(total_anomalies * 10, 100)
        else:
            risk_score = min(total_anomalies * 10, 100)

        return {
            "user_id": user_id,
            "total_anomalies": total_anomalies,
            "critical_count": critical_count,
            "high_count": high_count,
            "open_anomalies": open_anomalies,
            "risk_score": risk_score,
            "last_anomaly_at": last_anomaly_at,
        }

    # ------------------------------------------------------------------
    # SCM Commit Signals (GAP-016: dev-identity behavioral)
    # ------------------------------------------------------------------

    def analyze_commit_signals(
        self,
        org_id: str,
        author_email: str,
        commits: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Detect 5 SCM commit signal types for a developer.

        Signals detected:
          1. off_hours: commit timestamp local-hour NOT in [9,18)
          2. privilege_escalation: files match IAM/RBAC/permissions regex
          3. secret_file: files match .env/.pem/.key/credentials/*.secrets.* regex
          4. bulk_rename: >50 files changed per commit
          5. force_push: commit flagged with `force_push: true`

        Persists detected signals to commit_signals table (INSERT OR IGNORE on UNIQUE).

        Args:
            org_id: Tenant id.
            author_email: Developer identity.
            commits: List of commit dicts with keys:
                sha, timestamp (ISO), files (List[str]), force_push (bool, optional).
                `timestamp` may include tz offset; local-hour is derived from the
                supplied ISO string's hour component when tz is present, else UTC.

        Returns:
            {
              author_email, total_commits,
              signals: [{type, count, examples: [...]}],
              risk_score_delta: float
            }
        """
        import os as _os_mod  # local import, unused globally
        _ = _os_mod  # no-op to silence unused-import checkers

        if not author_email:
            raise ValueError("author_email is required")
        if commits is None:
            commits = []

        total_commits = len(commits)

        # Accumulator: type -> {count, examples}
        signal_acc: Dict[str, Dict[str, Any]] = {
            "off_hours": {"count": 0, "examples": []},
            "privilege_escalation": {"count": 0, "examples": []},
            "secret_file": {"count": 0, "examples": []},
            "bulk_rename": {"count": 0, "examples": []},
            "force_push": {"count": 0, "examples": []},
        }

        # Weights per signal type (for risk_score_delta)
        _weights = {
            "off_hours": 5.0,
            "privilege_escalation": 15.0,
            "secret_file": 25.0,
            "bulk_rename": 10.0,
            "force_push": 20.0,
        }

        now = _now_iso()
        detected_rows: List[Tuple[str, str, str, str, str, str, str]] = []

        for commit in commits:
            sha = str(commit.get("sha") or commit.get("commit_sha") or "")
            timestamp = commit.get("timestamp") or commit.get("committed_at") or ""
            files = commit.get("files") or commit.get("changed_files") or []
            if isinstance(files, str):
                files = [files]
            force_push = bool(commit.get("force_push", False))

            # ---- Signal 1: off_hours ----
            local_hour: Optional[int] = None
            if timestamp:
                try:
                    # Accept 'Z' as UTC indicator
                    ts_norm = str(timestamp).replace("Z", "+00:00")
                    dt = datetime.fromisoformat(ts_norm)
                    # If tz-aware, datetime.hour already reflects the local tz of
                    # the supplied offset (e.g. -07:00 => local hour).
                    local_hour = dt.hour
                except (ValueError, TypeError):
                    local_hour = None
            if local_hour is not None and not (
                _OFF_HOURS_START <= local_hour < _OFF_HOURS_END
            ):
                acc = signal_acc["off_hours"]
                acc["count"] += 1
                if len(acc["examples"]) < 3:
                    acc["examples"].append({
                        "sha": sha, "timestamp": timestamp, "hour": local_hour,
                    })
                import json as _j
                detected_rows.append((
                    str(uuid.uuid4()), org_id, author_email, "off_hours",
                    _j.dumps({"sha": sha, "timestamp": timestamp, "hour": local_hour}),
                    sha, now,
                ))

            # ---- Signal 2: privilege_escalation ----
            priv_matches = [f for f in files if _IAM_PRIV_PATTERN.search(str(f))]
            if priv_matches:
                acc = signal_acc["privilege_escalation"]
                acc["count"] += 1
                if len(acc["examples"]) < 3:
                    acc["examples"].append({"sha": sha, "files": priv_matches[:5]})
                import json as _j
                detected_rows.append((
                    str(uuid.uuid4()), org_id, author_email, "privilege_escalation",
                    _j.dumps({"sha": sha, "files": priv_matches}),
                    sha, now,
                ))

            # ---- Signal 3: secret_file ----
            secret_matches = [f for f in files if _SECRET_FILE_PATTERN.search(str(f))]
            if secret_matches:
                acc = signal_acc["secret_file"]
                acc["count"] += 1
                if len(acc["examples"]) < 3:
                    acc["examples"].append({"sha": sha, "files": secret_matches[:5]})
                import json as _j
                detected_rows.append((
                    str(uuid.uuid4()), org_id, author_email, "secret_file",
                    _j.dumps({"sha": sha, "files": secret_matches}),
                    sha, now,
                ))

            # ---- Signal 4: bulk_rename (>50 files) ----
            if len(files) > _BULK_RENAME_THRESHOLD:
                acc = signal_acc["bulk_rename"]
                acc["count"] += 1
                if len(acc["examples"]) < 3:
                    acc["examples"].append({"sha": sha, "file_count": len(files)})
                import json as _j
                detected_rows.append((
                    str(uuid.uuid4()), org_id, author_email, "bulk_rename",
                    _j.dumps({"sha": sha, "file_count": len(files)}),
                    sha, now,
                ))

            # ---- Signal 5: force_push ----
            if force_push:
                acc = signal_acc["force_push"]
                acc["count"] += 1
                if len(acc["examples"]) < 3:
                    acc["examples"].append({"sha": sha})
                import json as _j
                detected_rows.append((
                    str(uuid.uuid4()), org_id, author_email, "force_push",
                    _j.dumps({"sha": sha}),
                    sha, now,
                ))

        # Persist rows (INSERT OR IGNORE on UNIQUE)
        if detected_rows:
            with self._lock:
                with self._conn() as conn:
                    conn.executemany(
                        """INSERT OR IGNORE INTO commit_signals
                           (id, org_id, author_email, signal_type, evidence, commit_sha, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        detected_rows,
                    )

        # Build signals list (only non-zero)
        signals_out: List[Dict[str, Any]] = []
        risk_delta = 0.0
        for sig_type, acc in signal_acc.items():
            if acc["count"] > 0:
                signals_out.append({
                    "type": sig_type,
                    "count": acc["count"],
                    "examples": acc["examples"],
                })
                risk_delta += _weights[sig_type] * acc["count"]

        # Cap risk_score_delta at 100
        risk_delta = min(risk_delta, 100.0)

        # Emit TG event if any signals fired
        if signals_out and _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("ANOMALY_DETECTED", {
                        "entity_type": "scm_commit_signals",
                        "entity_id": author_email,
                        "org_id": org_id,
                        "source_engine": "behavioral_analytics_engine",
                        "signal_count": sum(s["count"] for s in signals_out),
                    })
            except Exception:
                pass

        return {
            "author_email": author_email,
            "total_commits": total_commits,
            "signals": signals_out,
            "risk_score_delta": round(risk_delta, 2),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_behavioral_stats(self, org_id: str) -> Dict[str, Any]:
        """Return org-level behavioral analytics statistics."""
        with self._conn() as conn:
            total_users_monitored = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM ba_baselines WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            total_anomalies = conn.execute(
                "SELECT COUNT(*) FROM ba_anomalies WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_anomalies = conn.execute(
                "SELECT COUNT(*) FROM ba_anomalies WHERE org_id = ? AND status NOT IN ('resolved','false_positive')",
                (org_id,),
            ).fetchone()[0]

            critical_anomalies = conn.execute(
                "SELECT COUNT(*) FROM ba_anomalies WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            confirmed_threats = conn.execute(
                "SELECT COUNT(*) FROM ba_anomalies WHERE org_id = ? AND status = 'confirmed'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT behavior_type, COUNT(*) as cnt FROM ba_anomalies WHERE org_id = ? GROUP BY behavior_type",
                (org_id,),
            ).fetchall()
            by_behavior_type = {r["behavior_type"]: r["cnt"] for r in type_rows}

            fp_count = conn.execute(
                "SELECT COUNT(*) FROM ba_anomalies WHERE org_id = ? AND status = 'false_positive'",
                (org_id,),
            ).fetchone()[0]
            false_positive_rate = (fp_count / total_anomalies * 100) if total_anomalies > 0 else 0.0

        return {
            "total_users_monitored": total_users_monitored,
            "total_anomalies": total_anomalies,
            "open_anomalies": open_anomalies,
            "critical_anomalies": critical_anomalies,
            "confirmed_threats": confirmed_threats,
            "by_behavior_type": by_behavior_type,
            "false_positive_rate": false_positive_rate,
        }
