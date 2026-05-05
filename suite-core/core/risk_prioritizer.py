"""
ML-based Risk Prioritization Engine — ALDECI.

Composite risk scoring using CVSS + EPSS + CISA KEV + asset criticality:
- CVSS base score (40%): severity → CRITICAL=10, HIGH=7.5, MED=5, LOW=2.5
- EPSS exploit probability (25%): 0.0-1.0 from api.first.org (with local cache)
- CISA KEV presence (20%): in known-exploited catalog = 1.0, absent = 0.0
- Asset criticality (15%): production=1.0, staging=0.5, dev=0.2

Composite score = 100 × (
    0.40 × (cvss_raw / 10.0)
  + 0.25 × epss
  + 0.20 × kev
  + 0.15 × asset_criticality
)

Exploit window heuristic:
  KEV + EPSS > 0.5               → "days"
  (HIGH|CRITICAL) + EPSS > 0.1   → "weeks"
  MEDIUM + any EPSS              → "months"
  LOW / INFO                     → "quarters"

Compliance: NIST SP 800-40 (patch management), CISA KEV alignment, FIRST EPSS v3
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import urlopen

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "risk_prioritizer.db")

# EPSS API (FIRST.org public — no auth)
_EPSS_API_BASE = "https://api.first.org/data/1.0/epss"

# CISA KEV catalog (public JSON feed)
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cache TTLs
_EPSS_CACHE_TTL_HOURS = 24
_KEV_CACHE_TTL_HOURS = 6

# Factor weights — must sum to 1.0
_WEIGHT_CVSS = 0.40
_WEIGHT_EPSS = 0.25
_WEIGHT_KEV = 0.20
_WEIGHT_ASSET = 0.15

# CVSS severity → normalised score (0-10 scale)
_CVSS_SEVERITY: Dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
    "informational": 0.5,
    "none": 0.0,
}

# Asset environment → criticality weight (0-1)
_ASSET_CRITICALITY: Dict[str, float] = {
    "production": 1.0,
    "prod": 1.0,
    "staging": 0.5,
    "stage": 0.5,
    "development": 0.2,
    "dev": 0.2,
    "test": 0.2,
    "sandbox": 0.1,
    "unknown": 0.5,
}


# ============================================================================
# ENUMS
# ============================================================================


class ExploitWindow(str, Enum):
    """Estimated time-to-exploit."""

    DAYS = "days"
    WEEKS = "weeks"
    MONTHS = "months"
    QUARTERS = "quarters"
    UNKNOWN = "unknown"


class RemediationUrgency(str, Enum):
    """Urgency tier for remediation queue."""

    IMMEDIATE = "immediate"
    URGENT = "urgent"
    PLANNED = "planned"
    BACKLOG = "backlog"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class RiskScore(BaseModel):
    """Composite risk score for a single finding."""

    finding_id: str = Field(..., description="Finding identifier")
    composite_score: float = Field(
        ..., ge=0.0, le=100.0, description="Overall risk score 0-100"
    )
    cvss_contribution: float = Field(..., ge=0.0, le=100.0, description="CVSS factor (0-100)")
    epss_contribution: float = Field(..., ge=0.0, le=100.0, description="EPSS factor (0-100)")
    kev_contribution: float = Field(..., ge=0.0, le=100.0, description="CISA KEV factor (0-100)")
    asset_contribution: float = Field(
        ..., ge=0.0, le=100.0, description="Asset criticality factor (0-100)"
    )
    exploit_window: ExploitWindow = Field(
        ExploitWindow.UNKNOWN, description="Estimated time-to-exploit"
    )
    rationale: str = Field("", description="Human-readable scoring rationale")
    scored_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Raw inputs used for scoring (for transparency)
    cvss_raw: float = Field(0.0, description="CVSS base score or severity mapping")
    epss_raw: float = Field(0.0, ge=0.0, le=1.0, description="EPSS probability 0-1")
    kev_present: bool = Field(False, description="Whether CVE is in CISA KEV catalog")
    asset_criticality_raw: float = Field(
        0.5, ge=0.0, le=1.0, description="Asset criticality 0-1"
    )


class PriorityItem(BaseModel):
    """Single item in a remediation priority queue."""

    rank: int = Field(..., description="1-based remediation rank (1 = fix first)")
    finding_id: str
    composite_score: float
    exploit_window: ExploitWindow
    urgency: RemediationUrgency
    rationale: str


class PriorityQueue(BaseModel):
    """Prioritised remediation queue."""

    total: int
    items: List[PriorityItem]
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ============================================================================
# HELPERS
# ============================================================================


def _normalise_severity(finding: Dict[str, Any]) -> float:
    """Extract and normalise CVSS/severity to 0-10 scale."""
    # Prefer explicit cvss_score field
    cvss = finding.get("cvss_score") or finding.get("cvss_base_score")
    if cvss is not None:
        try:
            val = float(cvss)
            if 0.0 <= val <= 10.0:
                return val
        except (TypeError, ValueError):
            pass

    # Fall back to severity string
    severity = (
        finding.get("severity") or finding.get("risk_level") or "unknown"
    ).lower().strip()
    return _CVSS_SEVERITY.get(severity, 5.0)  # default medium


def _normalise_asset_criticality(finding: Dict[str, Any]) -> float:
    """Extract asset environment criticality from finding."""
    # Direct criticality value
    crit = finding.get("asset_criticality")
    if crit is not None:
        try:
            val = float(crit)
            if 0.0 <= val <= 1.0:
                return val
        except (TypeError, ValueError):
            pass

    # Environment string
    env = (
        finding.get("asset_environment")
        or finding.get("environment")
        or finding.get("asset_env")
        or "unknown"
    ).lower().strip()
    return _ASSET_CRITICALITY.get(env, 0.5)


def _determine_exploit_window(
    severity_str: str,
    epss: float,
    kev_present: bool,
) -> ExploitWindow:
    """Heuristic time-to-exploit estimate."""
    sev = severity_str.lower().strip()
    if kev_present and epss > 0.5:
        return ExploitWindow.DAYS
    if kev_present:
        return ExploitWindow.WEEKS
    if sev in ("critical", "high") and epss > 0.1:
        return ExploitWindow.WEEKS
    if sev in ("critical", "high"):
        return ExploitWindow.MONTHS
    if sev == "medium":
        return ExploitWindow.MONTHS
    return ExploitWindow.QUARTERS


def _urgency_from_score(score: float) -> RemediationUrgency:
    if score >= 80:
        return RemediationUrgency.IMMEDIATE
    if score >= 60:
        return RemediationUrgency.URGENT
    if score >= 30:
        return RemediationUrgency.PLANNED
    return RemediationUrgency.BACKLOG


# ============================================================================
# RISK PRIORITIZER
# ============================================================================


class RiskPrioritizer:
    """ML-based risk scoring using CVSS + EPSS + asset criticality + exploit availability."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._kev_cves: set[str] = set()
        self._kev_loaded_at: Optional[datetime] = None
        self._init_db()
        self._warm_kev_cache()

    # ------------------------------------------------------------------
    # DB init
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS epss_cache (
                    cve_id      TEXT PRIMARY KEY,
                    epss        REAL NOT NULL,
                    percentile  REAL NOT NULL DEFAULT 0.0,
                    cached_at   TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS risk_scores (
                    finding_id          TEXT NOT NULL,
                    composite_score     REAL NOT NULL,
                    cvss_contribution   REAL NOT NULL,
                    epss_contribution   REAL NOT NULL,
                    kev_contribution    REAL NOT NULL,
                    asset_contribution  REAL NOT NULL,
                    exploit_window      TEXT NOT NULL,
                    rationale           TEXT NOT NULL,
                    scored_at           TEXT NOT NULL,
                    cvss_raw            REAL NOT NULL DEFAULT 0.0,
                    epss_raw            REAL NOT NULL DEFAULT 0.0,
                    kev_present         INTEGER NOT NULL DEFAULT 0,
                    asset_criticality_raw REAL NOT NULL DEFAULT 0.5,
                    PRIMARY KEY (finding_id, scored_at)
                );
                """
            )

    # ------------------------------------------------------------------
    # EPSS lookup (FIRST.org API, with SQLite cache)
    # ------------------------------------------------------------------

    def _get_epss(self, cve_id: Optional[str], force_refresh: bool = False) -> float:
        """Return EPSS probability for a CVE; 0.0 if not available."""
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return 0.0

        cve_id = cve_id.upper()

        if not force_refresh:
            cached = self._epss_from_cache(cve_id)
            if cached is not None:
                return cached

        try:
            url = f"{_EPSS_API_BASE}?cve={cve_id}"
            with urlopen(url, timeout=5) as resp:  # nosec
                data = json.loads(resp.read().decode())
            entries = data.get("data", [])
            if entries:
                epss_val = float(entries[0].get("epss", 0.0))
                percentile = float(entries[0].get("percentile", 0.0))
                self._epss_to_cache(cve_id, epss_val, percentile)
                return epss_val
        except (URLError, json.JSONDecodeError, KeyError, ValueError) as exc:
            _logger.debug("EPSS lookup failed for %s: %s", cve_id, exc)

        return 0.0

    def _epss_from_cache(self, cve_id: str) -> Optional[float]:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=_EPSS_CACHE_TTL_HOURS)
        ).isoformat()
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT epss FROM epss_cache WHERE cve_id = ? AND cached_at >= ?",
                (cve_id, cutoff),
            ).fetchone()
        return float(row[0]) if row else None

    def _epss_to_cache(self, cve_id: str, epss: float, percentile: float) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO epss_cache (cve_id, epss, percentile, cached_at)
                VALUES (?, ?, ?, ?)
                """,
                (cve_id, epss, percentile, datetime.now(timezone.utc).isoformat()),
            )

    # ------------------------------------------------------------------
    # CISA KEV catalog (in-memory set, refreshed every 6 hours)
    # ------------------------------------------------------------------

    def _warm_kev_cache(self) -> None:
        now = datetime.now(timezone.utc)
        if self._kev_loaded_at is not None:
            age_hours = (now - self._kev_loaded_at).total_seconds() / 3600
            if age_hours < _KEV_CACHE_TTL_HOURS:
                return

        try:
            with urlopen(_CISA_KEV_URL, timeout=10) as resp:  # nosec
                data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            self._kev_cves = {v.get("cveID", "").upper() for v in vulns if v.get("cveID")}
            self._kev_loaded_at = now
            _logger.info("CISA KEV loaded: %d CVEs", len(self._kev_cves))
        except (URLError, json.JSONDecodeError, KeyError) as exc:
            _logger.warning("Could not load CISA KEV catalog: %s", exc)
            if self._kev_loaded_at is None:
                self._kev_loaded_at = now  # avoid hammering on every call

    def _is_in_kev(self, cve_id: Optional[str]) -> bool:
        if not cve_id:
            return False
        self._warm_kev_cache()
        return cve_id.upper() in self._kev_cves

    # ------------------------------------------------------------------
    # Core scoring
    # ------------------------------------------------------------------

    def score_finding(self, finding: Dict[str, Any]) -> RiskScore:
        """Produce a composite risk score 0-100 for a finding."""
        finding_id = str(finding.get("id") or finding.get("finding_id") or uuid.uuid4())
        cve_id: Optional[str] = finding.get("cve_id") or finding.get("cve")

        # Factor: CVSS (40%)
        cvss_raw = _normalise_severity(finding)
        cvss_normalised = cvss_raw / 10.0
        cvss_contribution = _WEIGHT_CVSS * cvss_normalised * 100

        # Factor: EPSS (25%)
        epss_raw = self._get_epss(cve_id)
        epss_contribution = _WEIGHT_EPSS * epss_raw * 100

        # Factor: CISA KEV (20%)
        kev_present = self._is_in_kev(cve_id)
        kev_raw = 1.0 if kev_present else 0.0
        kev_contribution = _WEIGHT_KEV * kev_raw * 100

        # Factor: Asset criticality (15%)
        asset_crit = _normalise_asset_criticality(finding)
        asset_contribution = _WEIGHT_ASSET * asset_crit * 100

        composite_score = round(
            cvss_contribution + epss_contribution + kev_contribution + asset_contribution,
            2,
        )
        composite_score = max(0.0, min(100.0, composite_score))

        severity_str = str(
            finding.get("severity") or finding.get("risk_level") or "unknown"
        )
        window = _determine_exploit_window(severity_str, epss_raw, kev_present)

        rationale_parts = [
            f"CVSS={cvss_raw:.1f} ({cvss_contribution:.1f}pts)",
            f"EPSS={epss_raw:.3f} ({epss_contribution:.1f}pts)",
            f"KEV={'yes' if kev_present else 'no'} ({kev_contribution:.1f}pts)",
            f"asset_criticality={asset_crit:.2f} ({asset_contribution:.1f}pts)",
        ]
        rationale = "; ".join(rationale_parts)

        score = RiskScore(
            finding_id=finding_id,
            composite_score=composite_score,
            cvss_contribution=round(cvss_contribution, 2),
            epss_contribution=round(epss_contribution, 2),
            kev_contribution=round(kev_contribution, 2),
            asset_contribution=round(asset_contribution, 2),
            exploit_window=window,
            rationale=rationale,
            cvss_raw=cvss_raw,
            epss_raw=epss_raw,
            kev_present=kev_present,
            asset_criticality_raw=asset_crit,
        )

        self._persist_score(score)
        return score

    @staticmethod
    def _score_to_row(score: RiskScore) -> tuple:
        """Convert a RiskScore to the tuple expected by the risk_scores INSERT."""
        return (
            score.finding_id,
            score.composite_score,
            score.cvss_contribution,
            score.epss_contribution,
            score.kev_contribution,
            score.asset_contribution,
            score.exploit_window.value,
            score.rationale,
            score.scored_at.isoformat(),
            score.cvss_raw,
            score.epss_raw,
            1 if score.kev_present else 0,
            score.asset_criticality_raw,
        )

    _UPSERT_SQL = """
        INSERT OR REPLACE INTO risk_scores
        (finding_id, composite_score, cvss_contribution, epss_contribution,
         kev_contribution, asset_contribution, exploit_window, rationale,
         scored_at, cvss_raw, epss_raw, kev_present, asset_criticality_raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    def _persist_score(self, score: RiskScore) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(self._UPSERT_SQL, self._score_to_row(score))

    def _persist_scores_batch(self, scores: List[RiskScore]) -> None:
        """Persist multiple scores in a single DB connection (one executemany).

        Reduces N sqlite3.connect() calls to 1 for batch operations, cutting
        per-finding DB overhead from ~2ms each to <0.1ms amortised.
        """
        if not scores:
            return
        rows = [self._score_to_row(s) for s in scores]
        with sqlite3.connect(self._db_path) as conn:
            conn.executemany(self._UPSERT_SQL, rows)

    # ------------------------------------------------------------------
    # Batch ranking
    # ------------------------------------------------------------------

    def rank_findings(self, findings: List[Dict[str, Any]]) -> List[RiskScore]:
        """Rank findings by composite risk score, highest first.

        Scores are computed without per-finding DB writes; all scores are
        persisted in a single batched executemany call at the end, reducing
        DB overhead from O(N) connections to O(1).
        """
        # Compute scores without triggering _persist_score on each call.
        # We temporarily bypass persistence by scoring inline, then batch-write.
        scores: List[RiskScore] = []
        for f in findings:
            finding_id = str(f.get("id") or f.get("finding_id") or uuid.uuid4())
            cve_id: Optional[str] = f.get("cve_id") or f.get("cve")
            cvss_raw = _normalise_severity(f)
            cvss_normalised = cvss_raw / 10.0
            cvss_contribution = _WEIGHT_CVSS * cvss_normalised * 100
            epss_raw = self._get_epss(cve_id)
            epss_contribution = _WEIGHT_EPSS * epss_raw * 100
            kev_present = self._is_in_kev(cve_id)
            kev_raw = 1.0 if kev_present else 0.0
            kev_contribution = _WEIGHT_KEV * kev_raw * 100
            asset_crit = _normalise_asset_criticality(f)
            asset_contribution = _WEIGHT_ASSET * asset_crit * 100
            composite_score = round(
                cvss_contribution + epss_contribution + kev_contribution + asset_contribution,
                2,
            )
            composite_score = max(0.0, min(100.0, composite_score))
            severity_str = str(f.get("severity") or f.get("risk_level") or "unknown")
            window = _determine_exploit_window(severity_str, epss_raw, kev_present)
            rationale_parts = [
                f"CVSS={cvss_raw:.1f} ({cvss_contribution:.1f}pts)",
                f"EPSS={epss_raw:.3f} ({epss_contribution:.1f}pts)",
                f"KEV={'yes' if kev_present else 'no'} ({kev_contribution:.1f}pts)",
                f"asset_criticality={asset_crit:.2f} ({asset_contribution:.1f}pts)",
            ]
            scores.append(RiskScore(
                finding_id=finding_id,
                composite_score=composite_score,
                cvss_contribution=round(cvss_contribution, 2),
                epss_contribution=round(epss_contribution, 2),
                kev_contribution=round(kev_contribution, 2),
                asset_contribution=round(asset_contribution, 2),
                exploit_window=window,
                rationale="; ".join(rationale_parts),
                cvss_raw=cvss_raw,
                epss_raw=epss_raw,
                kev_present=kev_present,
                asset_criticality_raw=asset_crit,
            ))
        self._persist_scores_batch(scores)
        return sorted(scores, key=lambda s: s.composite_score, reverse=True)

    # ------------------------------------------------------------------
    # Exploit window prediction
    # ------------------------------------------------------------------

    def predict_exploit_window(self, finding: Dict[str, Any]) -> ExploitWindow:
        """Estimate time-to-exploit based on finding characteristics."""
        cve_id: Optional[str] = finding.get("cve_id") or finding.get("cve")
        epss = self._get_epss(cve_id)
        kev = self._is_in_kev(cve_id)
        severity_str = str(
            finding.get("severity") or finding.get("risk_level") or "unknown"
        )
        return _determine_exploit_window(severity_str, epss, kev)

    # ------------------------------------------------------------------
    # Remediation priority queue
    # ------------------------------------------------------------------

    def get_remediation_priority(self, findings: List[Dict[str, Any]]) -> PriorityQueue:
        """Return prioritized remediation queue with rationale."""
        ranked = self.rank_findings(findings)
        items: List[PriorityItem] = []
        for rank, score in enumerate(ranked, start=1):
            items.append(
                PriorityItem(
                    rank=rank,
                    finding_id=score.finding_id,
                    composite_score=score.composite_score,
                    exploit_window=score.exploit_window,
                    urgency=_urgency_from_score(score.composite_score),
                    rationale=score.rationale,
                )
            )
        return PriorityQueue(total=len(items), items=items)


# ============================================================================
# SINGLETON
# ============================================================================

_instance: Optional[RiskPrioritizer] = None
_instance_lock = threading.Lock()


def get_risk_prioritizer(db_path: str = _DEFAULT_DB) -> RiskPrioritizer:
    """Return the process-wide RiskPrioritizer singleton."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = RiskPrioritizer(db_path=db_path)
    return _instance
