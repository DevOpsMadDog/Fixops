"""
Vulnerability Risk Scoring Engine — ALDECI.

Computes contextual risk scores that go beyond CVSS by incorporating:
  - EPSS (exploitation probability)
  - KEV (CISA Known Exploited Vulnerabilities)
  - Asset criticality multiplier
  - Internet exposure bonus
  - Business context weighting

Formula:
  base  = cvss_base * 10
        + epss_score * 20
        + 20  (if kev)
        + 10  (if internet_exposed)
  score = min(base * criticality_multiplier, 100)

Priority mapping:
  P1 (score >= 80): respond within 24h
  P2 (score >= 60): respond within 72h
  P3 (score >= 40): respond within 7d
  P4 (score <  40): respond within 30d

Compliance: NIST SP 800-30, ISO27001 A.12.6, SOC2 CC7.1
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# DB path (WAL mode)
# ---------------------------------------------------------------------------

_DB_PATH = str(
    Path(__file__).resolve().parents[2] / "data" / "vuln_risk_scores.db"
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS vuln_risk_scores (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    asset_id        TEXT,
    composite_score REAL NOT NULL,
    priority        TEXT NOT NULL,
    factors         TEXT NOT NULL,
    recommendation  TEXT NOT NULL,
    sla_hours       INTEGER NOT NULL,
    context         TEXT NOT NULL,
    scored_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vrs_org_cve  ON vuln_risk_scores(org_id, cve_id);
CREATE INDEX IF NOT EXISTS idx_vrs_org_pri  ON vuln_risk_scores(org_id, priority);
CREATE INDEX IF NOT EXISTS idx_vrs_org_time ON vuln_risk_scores(org_id, scored_at);
"""

# ---------------------------------------------------------------------------
# Criticality multipliers
# ---------------------------------------------------------------------------

_CRITICALITY_MULTIPLIER: Dict[str, float] = {
    "critical": 1.5,
    "high":     1.2,
    "medium":   1.0,
    "low":      0.7,
}

_DEFAULT_CRITICALITY = "medium"

# ---------------------------------------------------------------------------
# Priority thresholds and SLA hours
# ---------------------------------------------------------------------------

_PRIORITY_THRESHOLDS = [
    (80, "P1",  24),
    (60, "P2",  72),
    (40, "P3",  168),   # 7 days
    (0,  "P4",  720),   # 30 days
]

_PRIORITY_RECOMMENDATIONS: Dict[str, str] = {
    "P1": "CRITICAL: Patch or mitigate within 24 hours. Isolate asset if internet-exposed.",
    "P2": "HIGH: Remediate within 72 hours. Apply compensating controls immediately.",
    "P3": "MEDIUM: Schedule patching within 7 days. Monitor for active exploitation.",
    "P4": "LOW: Address in next patch cycle within 30 days. Track for status changes.",
}


# ---------------------------------------------------------------------------
# VulnRiskScorer
# ---------------------------------------------------------------------------

class VulnRiskScorer:
    """Contextual vulnerability risk scoring engine backed by SQLite (WAL)."""

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Core scoring logic
    # ------------------------------------------------------------------

    @staticmethod
    def _compute(context: Dict[str, Any]) -> Dict[str, Any]:
        """Pure scoring function — no side effects, no DB access."""
        cvss_base: float = float(context.get("cvss_base", 0.0))
        epss_score: float = float(context.get("epss_score", 0.0))
        kev: bool = bool(context.get("kev", False))
        internet_exposed: bool = bool(context.get("internet_exposed", False))
        has_known_exploit: bool = bool(context.get("has_known_exploit", False))
        criticality: str = str(
            context.get("asset_criticality", _DEFAULT_CRITICALITY)
        ).lower()

        if criticality not in _CRITICALITY_MULTIPLIER:
            criticality = _DEFAULT_CRITICALITY

        # Weights / bonuses
        cvss_weight = cvss_base * 10
        epss_weight = epss_score * 20
        kev_bonus = 20.0 if kev else 0.0
        exploit_bonus = 5.0 if has_known_exploit and not kev else 0.0
        exposure_bonus = 10.0 if internet_exposed else 0.0
        criticality_multiplier = _CRITICALITY_MULTIPLIER[criticality]

        raw = (cvss_weight + epss_weight + kev_bonus + exploit_bonus + exposure_bonus)
        composite = min(raw * criticality_multiplier, 100.0)
        composite = round(composite, 2)

        # Priority + SLA
        priority = "P4"
        sla_hours = 720
        for threshold, pri, sla in _PRIORITY_THRESHOLDS:
            if composite >= threshold:
                priority = pri
                sla_hours = sla
                break

        recommendation = _PRIORITY_RECOMMENDATIONS[priority]

        factors = {
            "cvss_weight":             round(cvss_weight, 2),
            "epss_weight":             round(epss_weight, 2),
            "kev_bonus":               kev_bonus,
            "exploit_bonus":           exploit_bonus,
            "exposure_bonus":          exposure_bonus,
            "criticality_multiplier":  criticality_multiplier,
            "raw_before_cap":          round(raw * criticality_multiplier, 2),
        }

        return {
            "composite_score": composite,
            "priority":        priority,
            "factors":         factors,
            "recommendation":  recommendation,
            "sla_hours":       sla_hours,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_vulnerability(
        self,
        cve_id: str,
        org_id: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Score a single vulnerability with full context."""
        result = self._compute(context)
        result["cve_id"] = cve_id
        result["org_id"] = org_id
        return result

    def batch_score(
        self,
        vulnerabilities: List[Dict[str, Any]],
        org_id: str,
    ) -> List[Dict[str, Any]]:
        """Score a list of vulnerabilities, sorted by composite_score DESC.

        Each item must include ``cve_id`` and optionally any context keys
        accepted by ``score_vulnerability``.
        """
        results: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "UNKNOWN")
            ctx = {k: v for k, v in vuln.items() if k != "cve_id"}
            scored = self.score_vulnerability(cve_id, org_id, ctx)
            results.append(scored)

        results.sort(key=lambda x: x["composite_score"], reverse=True)
        return results

    def save_score(
        self,
        org_id: str,
        cve_id: str,
        asset_id: Optional[str],
        score_data: Dict[str, Any],
    ) -> str:
        """Persist a scored result to the DB for tracking and trending.

        Returns the generated record ID.
        """
        record_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vuln_risk_scores
                  (id, org_id, cve_id, asset_id, composite_score, priority,
                   factors, recommendation, sla_hours, context, scored_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    org_id,
                    cve_id,
                    asset_id,
                    score_data.get("composite_score", 0.0),
                    score_data.get("priority", "P4"),
                    json.dumps(score_data.get("factors", {})),
                    score_data.get("recommendation", ""),
                    score_data.get("sla_hours", 720),
                    json.dumps(score_data.get("context", {})),
                    now,
                ),
            )
        _logger.info("saved_vuln_score", org_id=org_id, cve_id=cve_id, record_id=record_id)
        return record_id

    def get_score_trend(self, org_id: str, cve_id: str) -> List[Dict[str, Any]]:
        """Return historical score records for a CVE, oldest first."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, composite_score, priority, factors, recommendation,
                       sla_hours, asset_id, scored_at
                FROM   vuln_risk_scores
                WHERE  org_id = ? AND cve_id = ?
                ORDER  BY scored_at ASC
                """,
                (org_id, cve_id),
            ).fetchall()
        return [
            {
                "id":              r["id"],
                "composite_score": r["composite_score"],
                "priority":        r["priority"],
                "factors":         json.loads(r["factors"]),
                "recommendation":  r["recommendation"],
                "sla_hours":       r["sla_hours"],
                "asset_id":        r["asset_id"],
                "scored_at":       r["scored_at"],
            }
            for r in rows
        ]

    def get_priority_queue(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all saved scores for an org, sorted P1→P4 then composite DESC."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, cve_id, asset_id, composite_score, priority,
                       factors, recommendation, sla_hours, scored_at
                FROM   vuln_risk_scores
                WHERE  org_id = ?
                ORDER  BY
                    CASE priority
                        WHEN 'P1' THEN 1
                        WHEN 'P2' THEN 2
                        WHEN 'P3' THEN 3
                        WHEN 'P4' THEN 4
                        ELSE 5
                    END ASC,
                    composite_score DESC
                """,
                (org_id,),
            ).fetchall()
        return [
            {
                "id":              r["id"],
                "cve_id":          r["cve_id"],
                "asset_id":        r["asset_id"],
                "composite_score": r["composite_score"],
                "priority":        r["priority"],
                "factors":         json.loads(r["factors"]),
                "recommendation":  r["recommendation"],
                "sla_hours":       r["sla_hours"],
                "scored_at":       r["scored_at"],
            }
            for r in rows
        ]

    def get_scoring_stats(self, org_id: str) -> Dict[str, Any]:
        """Return priority distribution counts for the org."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT priority, COUNT(*) AS cnt
                FROM   vuln_risk_scores
                WHERE  org_id = ?
                GROUP  BY priority
                """,
                (org_id,),
            ).fetchall()

        dist: Dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for r in rows:
            if r["priority"] in dist:
                dist[r["priority"]] = r["cnt"]

        total = sum(dist.values())
        return {
            "org_id":       org_id,
            "distribution": dist,
            "total":        total,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_scorer: Optional[VulnRiskScorer] = None
_scorer_lock = threading.Lock()


def get_scorer(db_path: str = _DB_PATH) -> VulnRiskScorer:
    global _scorer
    with _scorer_lock:
        if _scorer is None:
            _scorer = VulnRiskScorer(db_path=db_path)
    return _scorer
