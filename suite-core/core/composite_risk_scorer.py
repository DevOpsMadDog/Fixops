"""
Composite Risk Scorer — ML-powered multi-signal risk scoring for ALDECI.

Combines signals from all existing ALDECI engines into a single 0-100
composite risk score per asset/finding.

Formula (weighted sum of normalized 0-100 components):
    composite = (
        cvss_component      * 0.25 +   # base vulnerability severity
        epss_component      * 0.20 +   # exploitability in the wild
        kev_component       * 0.20 +   # CISA known exploited
        asset_criticality   * 0.15 +   # how critical is the affected asset
        sla_breach_risk     * 0.10 +   # overdue remediation
        lateral_movement    * 0.10     # attack path / exposure potential
    )

Grades: CRITICAL>=80, HIGH>=60, MEDIUM>=40, LOW>=20, MINIMAL<20

Reads from existing SQLite DBs with graceful fallback to defaults when a
DB or record is missing.  No external ML libraries — pure Python math.

Compliance: NIST CSF ID.RA, CIS Control 7, ISO27001 A.12.6
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# DB paths — read existing databases, write own composite db
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Where to write composite risk scores
_COMPOSITE_DB = os.getenv(
    "FIXOPS_COMPOSITE_RISK_DB",
    str(_REPO_ROOT / ".fixops_data" / "composite_risk.db"),
)

# Source DBs (read-only, graceful fallback)
_ASSET_INVENTORY_DB = os.getenv(
    "FIXOPS_ASSET_INVENTORY_DB",
    str(_REPO_ROOT / ".fixops_data" / "asset_inventory.db"),
)
_SLA_DB = str(_REPO_ROOT / "data" / "sla_tracking.db")
_POSTURE_DB = str(_REPO_ROOT / "data" / "posture_tracker.db")
_INCIDENT_DB = str(_REPO_ROOT / "data" / "incident_response.db")
_VULN_DB = os.getenv(
    "FIXOPS_VULN_ENRICHER_DB",
    str(_REPO_ROOT / ".fixops_data" / "vuln_enricher.db"),
)

# ---------------------------------------------------------------------------
# Grading thresholds
# ---------------------------------------------------------------------------

_GRADE_CRITICAL = 80.0
_GRADE_HIGH = 60.0
_GRADE_MEDIUM = 40.0
_GRADE_LOW = 20.0

# ---------------------------------------------------------------------------
# Component weights (must sum to 1.0)
# ---------------------------------------------------------------------------

_W_CVSS = 0.25
_W_EPSS = 0.20
_W_KEV = 0.20
_W_ASSET = 0.15
_W_SLA = 0.10
_W_LATERAL = 0.10

# ---------------------------------------------------------------------------
# Schema for composite risk DB
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS composite_scores (
    score_id        TEXT PRIMARY KEY,
    asset_id        TEXT,
    finding_id      TEXT,
    org_id          TEXT NOT NULL DEFAULT 'default',
    score           REAL NOT NULL,
    grade           TEXT NOT NULL,
    factors_json    TEXT NOT NULL DEFAULT '[]',
    scored_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_crs_org       ON composite_scores(org_id);
CREATE INDEX IF NOT EXISTS idx_crs_asset     ON composite_scores(asset_id);
CREATE INDEX IF NOT EXISTS idx_crs_finding   ON composite_scores(finding_id);
CREATE INDEX IF NOT EXISTS idx_crs_score     ON composite_scores(org_id, score DESC);
"""


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RiskFactor(BaseModel):
    """One contributing signal to the composite score."""

    name: str = Field(..., description="Signal name, e.g. 'cvss', 'epss'")
    value: float = Field(..., ge=0.0, le=100.0, description="Normalised 0-100 value")
    weight: float = Field(..., ge=0.0, le=1.0, description="Weighting coefficient")
    explanation: str = Field("", description="Human-readable explanation of this signal")

    @property
    def weighted_value(self) -> float:
        return self.value * self.weight


class CompositeRiskScore(BaseModel):
    """Full composite risk result for an asset or finding."""

    score_id: str = Field(
        default_factory=lambda: f"crs-{uuid.uuid4().hex[:12]}",
        description="Unique score identifier",
    )
    asset_id: Optional[str] = Field(None, description="Asset being scored")
    finding_id: Optional[str] = Field(None, description="Finding being scored")
    org_id: str = Field("default", description="Organisation")
    score: float = Field(..., ge=0.0, le=100.0, description="Composite 0-100 risk score")
    grade: str = Field(..., description="CRITICAL/HIGH/MEDIUM/LOW/MINIMAL")
    factors: List[RiskFactor] = Field(default_factory=list, description="Component signals")
    scored_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp",
    )


# ---------------------------------------------------------------------------
# Internal DB helpers
# ---------------------------------------------------------------------------


def _safe_connect(db_path: str) -> Optional[sqlite3.Connection]:
    """Open a SQLite connection or return None if the file doesn't exist."""
    try:
        p = Path(db_path)
        if not p.exists():
            return None
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as exc:
        logger.warning("composite_risk_scorer.db_open_failed", path=db_path, error=str(exc))
        return None


def _query_one(db_path: str, sql: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    """Run a scalar SELECT, return first row as dict or None."""
    conn = _safe_connect(db_path)
    if conn is None:
        return None
    try:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None
    except Exception as exc:
        logger.warning("composite_risk_scorer.query_failed", sql=sql[:80], error=str(exc))
        return None
    finally:
        conn.close()


def _query_all(db_path: str, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Run a SELECT, return all rows as list of dicts."""
    conn = _safe_connect(db_path)
    if conn is None:
        return []
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("composite_risk_scorer.query_all_failed", sql=sql[:80], error=str(exc))
        return []
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Signal extractors — each returns a float 0-100
# ---------------------------------------------------------------------------


def _get_cvss_component(cve_id: Optional[str], finding_id: Optional[str]) -> Tuple[float, str]:
    """
    Extract CVSS score from vuln_enricher DB and normalise to 0-100.
    Falls back to 50.0 (medium) if not found.
    """
    if cve_id:
        row = _query_one(
            _VULN_DB,
            "SELECT cvss_score FROM enriched_vulns WHERE cve_id = ? LIMIT 1",
            (cve_id,),
        )
        if row and row.get("cvss_score") is not None:
            cvss = float(row["cvss_score"])
            normalised = min(cvss / 10.0 * 100.0, 100.0)
            return normalised, f"CVSS {cvss:.1f}/10 for {cve_id}"

    if finding_id:
        row = _query_one(
            _VULN_DB,
            "SELECT cvss_score FROM enriched_vulns WHERE finding_id = ? LIMIT 1",
            (finding_id,),
        )
        if row and row.get("cvss_score") is not None:
            cvss = float(row["cvss_score"])
            normalised = min(cvss / 10.0 * 100.0, 100.0)
            return normalised, f"CVSS {cvss:.1f}/10 (finding lookup)"

    return 50.0, "CVSS unavailable — using default 5.0/10"


def _get_epss_component(cve_id: Optional[str]) -> Tuple[float, str]:
    """
    Extract EPSS probability from vuln_enricher DB, normalise 0-1 → 0-100.
    Falls back to 10.0 if not found.
    """
    if not cve_id:
        return 10.0, "EPSS unavailable — no CVE ID"

    row = _query_one(
        _VULN_DB,
        "SELECT epss_score FROM enriched_vulns WHERE cve_id = ? LIMIT 1",
        (cve_id,),
    )
    if row and row.get("epss_score") is not None:
        epss = float(row["epss_score"])
        normalised = min(epss * 100.0, 100.0)
        return normalised, f"EPSS {epss:.4f} ({normalised:.1f}/100)"

    return 10.0, f"EPSS not cached for {cve_id} — using default"


def _get_kev_component(cve_id: Optional[str]) -> Tuple[float, str]:
    """
    Return 100.0 if CVE is in CISA KEV (known exploited), else 0.0.
    Checks vuln_enricher DB kev flag.
    """
    if not cve_id:
        return 0.0, "KEV status unknown — no CVE ID"

    row = _query_one(
        _VULN_DB,
        "SELECT in_kev FROM enriched_vulns WHERE cve_id = ? LIMIT 1",
        (cve_id,),
    )
    if row is not None:
        in_kev = bool(row.get("in_kev", False))
        if in_kev:
            return 100.0, f"{cve_id} is in CISA KEV (Known Exploited Vulnerabilities)"
        return 0.0, f"{cve_id} not in CISA KEV"

    return 0.0, f"KEV status not cached for {cve_id}"


def _get_asset_criticality(asset_id: Optional[str]) -> Tuple[float, str]:
    """
    Map asset criticality from asset_inventory to 0-100.
    critical=100, high=75, medium=50, low=25, informational=10, unknown=50.
    """
    _CRIT_MAP = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0,
        "informational": 10.0,
        "info": 10.0,
    }

    if not asset_id:
        return 50.0, "Asset criticality unknown — no asset ID"

    row = _query_one(
        _ASSET_INVENTORY_DB,
        "SELECT criticality FROM assets WHERE asset_id = ? LIMIT 1",
        (asset_id,),
    )
    if row and row.get("criticality"):
        crit = str(row["criticality"]).lower()
        value = _CRIT_MAP.get(crit, 50.0)
        return value, f"Asset criticality: {crit} ({value}/100)"

    return 50.0, "Asset not found in inventory — using default medium criticality"


def _get_sla_breach_risk(finding_id: Optional[str], org_id: str) -> Tuple[float, str]:
    """
    Calculate SLA breach risk from sla_engine DB.
    BREACHED=100, AT_RISK=60, ON_TRACK=10, missing=30.
    """
    _STATUS_MAP = {
        "BREACHED": 100.0,
        "AT_RISK": 60.0,
        "ON_TRACK": 10.0,
    }

    if not finding_id:
        return 30.0, "SLA status unknown — no finding ID"

    row = _query_one(
        _SLA_DB,
        "SELECT status, deadline, created_at FROM sla_tracking WHERE finding_id = ? AND org_id = ? LIMIT 1",
        (finding_id, org_id),
    )
    if row:
        status = str(row.get("status", "ON_TRACK")).upper()
        value = _STATUS_MAP.get(status, 30.0)
        deadline = row.get("deadline", "unknown")
        return value, f"SLA status: {status}, deadline: {deadline}"

    # Also try without org_id filter as fallback
    row = _query_one(
        _SLA_DB,
        "SELECT status, deadline FROM sla_tracking WHERE finding_id = ? LIMIT 1",
        (finding_id,),
    )
    if row:
        status = str(row.get("status", "ON_TRACK")).upper()
        value = _STATUS_MAP.get(status, 30.0)
        return value, f"SLA status: {status}"

    return 30.0, "No SLA record found — using default risk"


def _get_lateral_movement_risk(asset_id: Optional[str], org_id: str) -> Tuple[float, str]:
    """
    Estimate lateral movement / attack path risk.
    Uses posture_tracker: degrading trend + high open findings → higher risk.
    Falls back to 30.0 default.
    """
    # Pull most recent posture snapshot for the org
    row = _query_one(
        _POSTURE_DB,
        """SELECT overall_score, critical_findings, high_findings, trend
           FROM posture_snapshots
           WHERE org_id = ?
           ORDER BY timestamp DESC LIMIT 1""",
        (org_id,),
    )
    if row:
        posture = float(row.get("overall_score", 50.0))
        critical = int(row.get("critical_findings", 0))
        high = int(row.get("high_findings", 0))
        trend = str(row.get("trend", "stable"))

        # Inverse of posture score = exposure
        exposure = 100.0 - min(posture, 100.0)

        # Boost for open critical/high findings (log scale, capped)
        import math
        finding_boost = min(math.log1p(critical * 3 + high) * 5.0, 20.0)

        # Trend modifier: degrading +10, improving -5
        trend_mod = 10.0 if trend == "degrading" else (-5.0 if trend == "improving" else 0.0)

        value = min(max(exposure + finding_boost + trend_mod, 0.0), 100.0)
        return value, (
            f"Posture {posture:.0f}/100 ({trend}), "
            f"{critical} critical + {high} high open findings"
        )

    return 30.0, "No posture history available — using default lateral movement risk"


# ---------------------------------------------------------------------------
# Core scorer
# ---------------------------------------------------------------------------


class CompositeRiskScorer:
    """
    Combines CVSS, EPSS, KEV, asset criticality, SLA breach, and lateral
    movement signals into a single 0-100 composite risk score per finding
    or asset.

    Thread-safe via a per-instance lock on the write DB.
    """

    def __init__(self, db_path: str = _COMPOSITE_DB) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------ DB

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    def _persist(self, score: CompositeRiskScore) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO composite_scores
                       (score_id, asset_id, finding_id, org_id, score, grade, factors_json, scored_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        score.score_id,
                        score.asset_id,
                        score.finding_id,
                        score.org_id,
                        score.score,
                        score.grade,
                        json.dumps([f.model_dump() for f in score.factors]),
                        score.scored_at,
                    ),
                )
                conn.commit()

    # ------------------------------------------------------------------ Grading

    @staticmethod
    def grade_score(score: float) -> str:
        """Map a 0-100 composite score to a severity grade string."""
        if score >= _GRADE_CRITICAL:
            return "CRITICAL"
        if score >= _GRADE_HIGH:
            return "HIGH"
        if score >= _GRADE_MEDIUM:
            return "MEDIUM"
        if score >= _GRADE_LOW:
            return "LOW"
        return "MINIMAL"

    # ------------------------------------------------------------------ Core computation

    def _compute(
        self,
        finding_id: Optional[str],
        cve_id: Optional[str],
        asset_id: Optional[str],
        org_id: str,
    ) -> CompositeRiskScore:
        """Compute composite risk score from all signals."""

        # --- gather signals ---
        cvss_val, cvss_expl = _get_cvss_component(cve_id, finding_id)
        epss_val, epss_expl = _get_epss_component(cve_id)
        kev_val, kev_expl = _get_kev_component(cve_id)
        asset_val, asset_expl = _get_asset_criticality(asset_id)
        sla_val, sla_expl = _get_sla_breach_risk(finding_id, org_id)
        lateral_val, lateral_expl = _get_lateral_movement_risk(asset_id, org_id)

        # --- build factor list ---
        factors = [
            RiskFactor(name="cvss", value=cvss_val, weight=_W_CVSS, explanation=cvss_expl),
            RiskFactor(name="epss", value=epss_val, weight=_W_EPSS, explanation=epss_expl),
            RiskFactor(name="kev", value=kev_val, weight=_W_KEV, explanation=kev_expl),
            RiskFactor(name="asset_criticality", value=asset_val, weight=_W_ASSET, explanation=asset_expl),
            RiskFactor(name="sla_breach_risk", value=sla_val, weight=_W_SLA, explanation=sla_expl),
            RiskFactor(name="lateral_movement", value=lateral_val, weight=_W_LATERAL, explanation=lateral_expl),
        ]

        # --- weighted sum ---
        raw = sum(f.weighted_value for f in factors)
        score = round(min(max(raw, 0.0), 100.0), 2)
        grade = self.grade_score(score)

        return CompositeRiskScore(
            asset_id=asset_id,
            finding_id=finding_id,
            org_id=org_id,
            score=score,
            grade=grade,
            factors=factors,
        )

    # ------------------------------------------------------------------ Public API

    def score_finding(
        self,
        finding_id: str,
        cve_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        org_id: str = "default",
    ) -> CompositeRiskScore:
        """Score a single finding.  Persists result to SQLite."""
        result = self._compute(finding_id, cve_id, asset_id, org_id)
        self._persist(result)
        logger.info(
            "composite_risk_scorer.scored_finding",
            finding_id=finding_id,
            score=result.score,
            grade=result.grade,
        )
        return result

    def score_asset(self, asset_id: str, org_id: str = "default") -> CompositeRiskScore:
        """
        Score an asset by aggregating all finding scores for that asset.
        Returns a CompositeRiskScore whose score is the MAX of per-finding
        scores (worst-case exposure) if any findings exist, otherwise
        computes directly from asset signals alone.
        """
        # Look up existing finding scores for this asset
        rows = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """SELECT score FROM composite_scores
                       WHERE asset_id = ? AND org_id = ? AND finding_id IS NOT NULL
                       ORDER BY scored_at DESC LIMIT 50""",
                    (asset_id, org_id),
                ).fetchall()
        except Exception:
            pass

        if rows:
            max_score = max(float(r["score"]) for r in rows)
            avg_score = sum(float(r["score"]) for r in rows) / len(rows)
            # Use weighted combo: 70% max, 30% avg (surface worst risk, tempered by breadth)
            agg_score = round(0.70 * max_score + 0.30 * avg_score, 2)
            grade = self.grade_score(agg_score)
            asset_val, asset_expl = _get_asset_criticality(asset_id)
            lateral_val, lateral_expl = _get_lateral_movement_risk(asset_id, org_id)
            factors = [
                RiskFactor(
                    name="finding_max_score",
                    value=max_score,
                    weight=0.70,
                    explanation=f"Worst finding score across {len(rows)} scored findings",
                ),
                RiskFactor(
                    name="finding_avg_score",
                    value=avg_score,
                    weight=0.30,
                    explanation=f"Average finding score across {len(rows)} findings",
                ),
                RiskFactor(
                    name="asset_criticality",
                    value=asset_val,
                    weight=0.0,  # informational only at asset level
                    explanation=asset_expl,
                ),
                RiskFactor(
                    name="lateral_movement",
                    value=lateral_val,
                    weight=0.0,  # informational only at asset level
                    explanation=lateral_expl,
                ),
            ]
            result = CompositeRiskScore(
                asset_id=asset_id,
                finding_id=None,
                org_id=org_id,
                score=agg_score,
                grade=grade,
                factors=factors,
            )
        else:
            # No findings yet — score from asset signals only
            result = self._compute(None, None, asset_id, org_id)
            result.asset_id = asset_id

        self._persist(result)
        logger.info(
            "composite_risk_scorer.scored_asset",
            asset_id=asset_id,
            score=result.score,
            grade=result.grade,
        )
        return result

    def batch_score(
        self,
        org_id: str = "default",
        limit: int = 100,
    ) -> List[CompositeRiskScore]:
        """
        Batch-score up to `limit` findings for an org.
        Reads finding IDs from any source DB that has a findings table.
        Falls back to empty list if no findings exist.
        """
        # Try to gather finding IDs from vuln_enricher or sla_tracking
        finding_rows = _query_all(
            _VULN_DB,
            "SELECT finding_id, cve_id FROM enriched_vulns WHERE finding_id IS NOT NULL LIMIT ?",
            (limit,),
        )
        if not finding_rows:
            finding_rows = _query_all(
                _SLA_DB,
                "SELECT finding_id, NULL as cve_id FROM sla_tracking WHERE org_id = ? LIMIT ?",
                (org_id, limit),
            )

        results: List[CompositeRiskScore] = []
        for row in finding_rows:
            fid = row.get("finding_id")
            cve = row.get("cve_id")
            if not fid:
                continue
            try:
                result = self._compute(fid, cve, None, org_id)
                self._persist(result)
                results.append(result)
            except Exception as exc:
                logger.warning(
                    "composite_risk_scorer.batch_score_error",
                    finding_id=fid,
                    error=str(exc),
                )

        logger.info(
            "composite_risk_scorer.batch_scored",
            org_id=org_id,
            count=len(results),
        )
        return results

    def top_risks(self, org_id: str = "default", n: int = 10) -> List[CompositeRiskScore]:
        """Return top N risks sorted by score descending."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """SELECT * FROM composite_scores
                       WHERE org_id = ?
                       ORDER BY score DESC
                       LIMIT ?""",
                    (org_id, n),
                ).fetchall()
        except Exception as exc:
            logger.warning("composite_risk_scorer.top_risks_error", error=str(exc))
            return []

        results: List[CompositeRiskScore] = []
        for row in rows:
            try:
                factors_raw = json.loads(row["factors_json"] or "[]")
                factors = [RiskFactor(**f) for f in factors_raw]
                results.append(
                    CompositeRiskScore(
                        score_id=row["score_id"],
                        asset_id=row["asset_id"],
                        finding_id=row["finding_id"],
                        org_id=row["org_id"],
                        score=float(row["score"]),
                        grade=row["grade"],
                        factors=factors,
                        scored_at=row["scored_at"],
                    )
                )
            except Exception as exc:
                logger.warning(
                    "composite_risk_scorer.top_risks_parse_error", error=str(exc)
                )
        return results

    def get_latest_asset_score(
        self, asset_id: str, org_id: str = "default"
    ) -> Optional[CompositeRiskScore]:
        """Retrieve the most recent composite score for an asset."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    """SELECT * FROM composite_scores
                       WHERE asset_id = ? AND org_id = ?
                       ORDER BY scored_at DESC LIMIT 1""",
                    (asset_id, org_id),
                ).fetchone()
        except Exception:
            return None

        if not row:
            return None
        try:
            factors_raw = json.loads(row["factors_json"] or "[]")
            factors = [RiskFactor(**f) for f in factors_raw]
            return CompositeRiskScore(
                score_id=row["score_id"],
                asset_id=row["asset_id"],
                finding_id=row["finding_id"],
                org_id=row["org_id"],
                score=float(row["score"]),
                grade=row["grade"],
                factors=factors,
                scored_at=row["scored_at"],
            )
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_singleton: Optional[CompositeRiskScorer] = None
_singleton_lock = threading.Lock()


def get_composite_risk_scorer(db_path: str = _COMPOSITE_DB) -> CompositeRiskScorer:
    """Return (or create) the module-level singleton CompositeRiskScorer."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = CompositeRiskScorer(db_path=db_path)
    return _singleton
