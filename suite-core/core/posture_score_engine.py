"""Security Posture Score Engine — ALDECI.

Computes weighted security posture scores across 8 control domains,
tracks score history, and manages industry benchmarks.

Compliance: NIST CSF 2.0, CIS Controls v8, ISO 27001:2022
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "posture_score.db"
)

# Real-findings store — used to derive vulnerability_mgmt_score when no manual
# component value is set for a tenant.  Same path convention as
# ``security_findings_engine._DEFAULT_DB``.
_FINDINGS_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_findings_engine.db"
)

# Weighted components — must sum to 1.0
_COMPONENT_WEIGHTS: Dict[str, float] = {
    "vulnerability_mgmt_score": 0.20,
    "identity_security_score": 0.15,
    "endpoint_security_score": 0.15,
    "network_security_score": 0.15,
    "cloud_security_score": 0.10,
    "compliance_score": 0.10,
    "incident_response_score": 0.10,
    "training_score": 0.05,
}

# Severity → penalty contribution per open finding.  Tuned so a tenant with
# ~100 mediums or ~25 highs lands around 50; a tenant with hundreds of
# criticals lands near 0.  Calibrated against the 15-tenant fleet
# (webgoat-llc 3.9k findings, axios-llc 0.7k, juice-shop-corp 163).
# Synonyms (``informational``, ``warn``) are normalised in
# ``_derive_vuln_mgmt_score`` so the engine survives heterogeneous scanner
# output without falling back to BASELINE.
_SEVERITY_PENALTY: Dict[str, float] = {
    "critical": 4.0,
    "high":     1.5,
    "medium":   0.4,
    "low":      0.05,
    "info":     0.01,
}
_SEVERITY_ALIASES: Dict[str, str] = {
    "crit": "critical",
    "sev1": "critical",
    "sev2": "high",
    "sev3": "medium",
    "sev4": "low",
    "warn": "medium",
    "warning": "medium",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unknown": "medium",
    "":      "medium",
}
# Baseline returned for the vuln-mgmt component when zero open findings exist.
_VULN_MGMT_BASELINE = 50

_GRADE_THRESHOLDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
]


def _score_to_grade(score: float) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


class PostureScoreEngine:
    """SQLite WAL-backed security posture score engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS posture_scores (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    overall_score REAL NOT NULL DEFAULT 0.0,
                    grade        TEXT NOT NULL DEFAULT 'F',
                    trend        TEXT NOT NULL DEFAULT 'stable',
                    computed_at  DATETIME NOT NULL,
                    components   TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_pscore_org
                    ON posture_scores (org_id, computed_at DESC);

                CREATE TABLE IF NOT EXISTS score_components (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    component    TEXT NOT NULL,
                    score        INTEGER NOT NULL DEFAULT 0,
                    source       TEXT NOT NULL DEFAULT '',
                    updated_at   DATETIME NOT NULL,
                    UNIQUE(org_id, component)
                );

                CREATE INDEX IF NOT EXISTS idx_comp_org
                    ON score_components (org_id);

                CREATE TABLE IF NOT EXISTS score_history (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    overall_score REAL NOT NULL,
                    grade        TEXT NOT NULL,
                    components   TEXT NOT NULL DEFAULT '{}',
                    recorded_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_history_org
                    ON score_history (org_id, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS benchmarks (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    industry         TEXT NOT NULL DEFAULT '',
                    company_size     TEXT NOT NULL DEFAULT '',
                    avg_score        REAL NOT NULL DEFAULT 0.0,
                    percentile_rank  INTEGER NOT NULL DEFAULT 50,
                    source           TEXT NOT NULL DEFAULT '',
                    as_of_date       TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bench_org
                    ON benchmarks (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _get_components_map(self, org_id: str) -> Dict[str, int]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT component, score FROM score_components WHERE org_id=?",
                (org_id,),
            ).fetchall()
        return {r["component"]: r["score"] for r in rows}

    def _derive_vuln_mgmt_score(self, org_id: str) -> Optional[int]:
        """Derive ``vulnerability_mgmt_score`` from real open findings.

        Reads ``security_findings_engine.db`` (same path the SecurityFindings
        engine writes to) and computes a 0-100 score using
        ``_SEVERITY_PENALTY``.  Returns ``None`` if the findings DB is
        unavailable so the caller can fall back to the manual value or the
        baseline 50.

        Bug history: prior to 2026-04-26 the posture score for fleet tenants
        was always 0.0 because no manual ``score_components`` rows existed
        AND there was no integration with the live findings table.  See
        Multica issue ``2de77fae-bbda-483d-bd93-00abe07bbc67``.
        """
        findings_path = Path(_FINDINGS_DB)
        if not findings_path.exists():
            return None
        try:
            conn = sqlite3.connect(str(findings_path), timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    """
                    SELECT severity, COUNT(*) AS cnt
                    FROM security_findings
                    WHERE org_id = ? AND status = 'open'
                    GROUP BY severity
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            _logger.warning(
                "posture.vuln_mgmt.derive_failed",
                extra={"org_id": org_id, "error": str(exc)},
            )
            return None

        if not rows:
            # No open findings at all → near-perfect vuln-mgmt posture.
            return 100

        penalty = 0.0
        for row in rows:
            raw = (row["severity"] or "medium").lower().strip()
            sev = _SEVERITY_ALIASES.get(raw, raw)
            penalty += _SEVERITY_PENALTY.get(sev, _SEVERITY_PENALTY["medium"]) * row["cnt"]

        # Cap to 0-100 range.  100 = no findings, 0 = overwhelmed.
        score = max(0, min(100, int(round(100.0 - penalty))))
        return score

    def _compute_trend(self, org_id: str, current_score: float) -> str:
        """Compare current score to prior snapshot to determine trend."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT overall_score FROM score_history WHERE org_id=? ORDER BY recorded_at DESC LIMIT 1",
                (org_id,),
            ).fetchone()
        if not row:
            return "stable"
        delta = current_score - row["overall_score"]
        if delta >= 2.0:
            return "improving"
        if delta <= -2.0:
            return "declining"
        return "stable"

    # ------------------------------------------------------------------
    # Core scoring
    # ------------------------------------------------------------------

    def compute_posture_score(self, org_id: str) -> Dict[str, Any]:
        """Calculate overall security posture from weighted components.

        Returns overall_score, grade, components, trend, computed_at.

        Component-resolution order (per component):
          1. Manual value persisted in ``score_components`` (operator-set).
          2. Derived from live data — currently only
             ``vulnerability_mgmt_score`` is derived (from
             ``security_findings_engine.db``).  Other components fall through.
          3. Baseline 50.

        This change (2026-04-26) ensures fleet tenants whose only signal is
        scanner findings get a real, non-zero posture score instead of the
        previous 0.0 that surfaced through ``get_posture_stats``.
        """
        components_map = self._get_components_map(org_id)

        # Lazily derive live components when no manual value is stored.
        derived_vuln_mgmt: Optional[int] = None
        if "vulnerability_mgmt_score" not in components_map:
            derived_vuln_mgmt = self._derive_vuln_mgmt_score(org_id)

        weighted_sum = 0.0
        components_out: Dict[str, int] = {}
        for component, weight in _COMPONENT_WEIGHTS.items():
            if component in components_map:
                score = components_map[component]
            elif component == "vulnerability_mgmt_score" and derived_vuln_mgmt is not None:
                score = derived_vuln_mgmt
            else:
                score = _VULN_MGMT_BASELINE if component == "vulnerability_mgmt_score" else 50
            weighted_sum += score * weight
            components_out[component] = score

        overall = round(weighted_sum, 2)
        grade = _score_to_grade(overall)
        trend = self._compute_trend(org_id, overall)
        now = datetime.now(timezone.utc).isoformat()

        return {
            "overall_score": overall,
            "grade": grade,
            "components": components_out,
            "trend": trend,
            "computed_at": now,
        }

    def save_score(self, org_id: str, score_data: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a computed posture score and add to history."""
        score_id = str(uuid.uuid4())
        hist_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        overall = float(score_data.get("overall_score", 0.0))
        grade = score_data.get("grade", _score_to_grade(overall))
        trend = score_data.get("trend", "stable")
        components = json.dumps(score_data.get("components", {}))
        computed_at = score_data.get("computed_at", now)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO posture_scores
                        (id, org_id, overall_score, grade, trend, computed_at, components)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (score_id, org_id, overall, grade, trend, computed_at, components),
                )
                conn.execute(
                    """
                    INSERT INTO score_history
                        (id, org_id, overall_score, grade, components, recorded_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (hist_id, org_id, overall, grade, components, now),
                )
        return {"id": score_id, "org_id": org_id, **score_data}

    def get_current_score(self, org_id: str) -> Dict[str, Any]:
        """Return the most recent saved score for an org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM posture_scores WHERE org_id=? ORDER BY computed_at DESC LIMIT 1",
                (org_id,),
            ).fetchone()
        if not row:
            return {}
        d = self._row_to_dict(row)
        d["components"] = json.loads(d.get("components") or "{}")
        return d

    def get_score_history(self, org_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Return score snapshots for the last N days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM score_history
                WHERE org_id=? AND recorded_at >= ?
                ORDER BY recorded_at DESC
                """,
                (org_id, cutoff),
            ).fetchall()
        result = []
        for r in rows:
            d = self._row_to_dict(r)
            d["components"] = json.loads(d.get("components") or "{}")
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Component management
    # ------------------------------------------------------------------

    def update_component(
        self, org_id: str, component_name: str, score: int, source: str
    ) -> bool:
        """Upsert a single component score. Returns True on success."""
        if component_name not in _COMPONENT_WEIGHTS:
            return False
        score = max(0, min(100, score))
        now = datetime.now(timezone.utc).isoformat()
        comp_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO score_components (id, org_id, component, score, source, updated_at)
                    VALUES (?,?,?,?,?,?)
                    ON CONFLICT(org_id, component) DO UPDATE SET
                        score=excluded.score,
                        source=excluded.source,
                        updated_at=excluded.updated_at
                    """,
                    (comp_id, org_id, component_name, score, source, now),
                )
        return True

    def list_components(self, org_id: str) -> List[Dict[str, Any]]:
        """List all component scores for an org, including weight info."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM score_components WHERE org_id=? ORDER BY component",
                (org_id,),
            ).fetchall()
        stored = {r["component"]: self._row_to_dict(r) for r in rows}

        result = []
        for comp, weight in _COMPONENT_WEIGHTS.items():
            if comp in stored:
                entry = stored[comp]
            else:
                entry = {
                    "id": None,
                    "org_id": org_id,
                    "component": comp,
                    "score": 50,
                    "source": "",
                    "updated_at": None,
                }
            entry["weight"] = weight
            result.append(entry)
        return result

    # ------------------------------------------------------------------
    # Benchmarks
    # ------------------------------------------------------------------

    def add_benchmark(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an industry benchmark record."""
        bench_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO benchmarks
                        (id, org_id, industry, company_size, avg_score,
                         percentile_rank, source, as_of_date, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        bench_id,
                        org_id,
                        data.get("industry", ""),
                        data.get("company_size", ""),
                        float(data.get("avg_score", 0.0)),
                        int(data.get("percentile_rank", 50)),
                        data.get("source", ""),
                        data.get("as_of_date", ""),
                        now,
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "posture_score", "org_id": org_id, "source_engine": "posture_score"})
            except Exception:
                pass

        return {"benchmark_id": bench_id, "org_id": org_id, "created_at": now, **data}

    def list_benchmarks(self, org_id: str) -> List[Dict[str, Any]]:
        """List all benchmarks for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM benchmarks WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_posture_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary stats: current score, grade, 30d best/worst, trend, days_at_risk.

        Behaviour change (2026-04-26): if no persisted ``posture_scores`` row
        exists for the tenant, fall through to a fresh ``compute_posture_score``
        call instead of returning ``current_score=0.0``.  This was the
        customer-visible 0.0 bug for fleet tenants
        (Multica issue 2de77fae-bbda-483d-bd93-00abe07bbc67).
        """
        current = self.get_current_score(org_id)
        if not current:
            # No saved score yet — compute live so the customer never sees
            # a deceptive 0.0 simply because the score has never been
            # persisted.  We do NOT auto-save here to keep this read-only.
            current = self.compute_posture_score(org_id)
        history = self.get_score_history(org_id, days=30)

        current_score = current.get("overall_score", 0.0)
        grade = current.get("grade", _score_to_grade(current_score))
        trend = current.get("trend", "stable")

        scores_30d = [h["overall_score"] for h in history]
        best_30d = max(scores_30d) if scores_30d else current_score
        worst_30d = min(scores_30d) if scores_30d else current_score
        days_at_risk = sum(1 for s in scores_30d if s < 60)

        return {
            "current_score": current_score,
            "grade": grade,
            "best_score_30d": best_30d,
            "worst_score_30d": worst_30d,
            "trend": trend,
            "days_at_risk": days_at_risk,
        }
