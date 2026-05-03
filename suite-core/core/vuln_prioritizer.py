"""
Vulnerability Prioritization Engine — ALDECI.

Composite risk scoring with EPSS + reachability + business context:
- EPSS Integration: probability a CVE is exploited in the next 30 days
- Reachability Analysis: confirmed-reachable / potentially-reachable / not-reachable
- Business Context Weighting: revenue, data sensitivity, regulatory, customer impact
- Composite Risk Score: EPSS × reachability_factor × business_impact × (1 - controls)
- SLA-Based Remediation Deadlines: Critical=24h, High=7d, Medium=30d, Low=90d
- Trend Analysis: backlog, MTTR, SLA breach rate, risk debt
- Auto-Grouping: by CVE, library, misconfiguration pattern
- Remediation Recommendations: upgrade path, workaround, accept-risk template

Compliance: NIST SP 800-40 (patch management), CISA KEV alignment
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
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import urlopen

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "vuln_prioritizer.db")

# EPSS API endpoint (FIRST.org public API — no auth required)
_EPSS_API_BASE = "https://api.first.org/data/1.0/epss"

# SLA deadlines in hours per severity bucket
_SLA_HOURS: Dict[str, int] = {
    "critical": 24,
    "high": 168,    # 7 days
    "medium": 720,  # 30 days
    "low": 2160,    # 90 days
    "info": 8760,   # 365 days
}

# Reachability multipliers — not-reachable code cannot be exploited in practice
_REACHABILITY_FACTOR: Dict[str, float] = {
    "confirmed_reachable": 1.0,
    "potentially_reachable": 0.5,
    "not_reachable": 0.1,
}

# Default scoring weights and thresholds (operator-tunable via scoring_config table)
_DEFAULT_SCORING_WEIGHTS: Dict[str, float] = {
    "revenue_impact": 0.35,
    "data_sensitivity": 0.30,
    "customer_impact": 0.20,
    "regulatory": 0.15,
    "regulatory_per_framework": 0.15,
    "regulatory_cap": 0.60,
    "unknown_asset_default": 0.40,
}
_DEFAULT_BUCKET_THRESHOLDS: Dict[str, float] = {
    "critical": 75.0,
    "high": 50.0,
    "medium": 20.0,
    "low": 5.0,
}


# ============================================================================
# ENUMS
# ============================================================================


class ReachabilityLevel(str, Enum):
    """Execution path reachability for the vulnerable code."""

    CONFIRMED_REACHABLE = "confirmed_reachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


class RiskBucket(str, Enum):
    """Risk severity bucket for a prioritized vulnerability."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RemediationAction(str, Enum):
    """Type of recommended remediation action."""

    UPGRADE = "upgrade"
    PATCH = "patch"
    WORKAROUND = "workaround"
    ACCEPT_RISK = "accept_risk"
    MITIGATE = "mitigate"


class ComplianceFramework(str, Enum):
    """Regulatory compliance frameworks."""

    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"
    FEDRAMP = "fedramp"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class EPSSScore(BaseModel):
    """EPSS score for a single CVE."""

    cve_id: str
    epss: float = Field(ge=0.0, le=1.0, description="Probability of exploitation in 30 days")
    percentile: float = Field(ge=0.0, le=1.0, description="Percentile rank among all CVEs")
    model_version: str = "v3"
    score_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cached: bool = False


class BusinessContext(BaseModel):
    """Business context weighting for an asset."""

    asset_id: str
    asset_name: str
    revenue_impact: float = Field(
        ge=0.0, le=1.0,
        description="Revenue fraction lost if asset is compromised (0=none, 1=total outage)",
    )
    data_sensitivity: float = Field(
        ge=0.0, le=1.0,
        description="Data sensitivity score (0=public, 1=classified/PHI/PII/PCI)",
    )
    regulatory_frameworks: List[ComplianceFramework] = Field(default_factory=list)
    customer_count: int = Field(ge=0, default=0, description="Number of end users on this asset")
    customer_impact_score: float = Field(
        ge=0.0, le=1.0,
        description="Derived from customer_count relative to total user base",
    )
    compensating_controls: float = Field(
        ge=0.0, le=1.0,
        description="WAF, IPS, network segmentation etc. (0=none, 1=fully mitigated)",
    )
    tier: str = Field(default="tier3", description="Asset tier: tier1 (crown jewel) to tier4")
    org_id: str = "default"


class ReachabilityResult(BaseModel):
    """Reachability analysis for a finding."""

    finding_id: str
    level: ReachabilityLevel
    call_path: List[str] = Field(default_factory=list, description="Call graph path to vuln code")
    evidence: str = ""
    analyzer: str = "static_analysis"
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationRecommendation(BaseModel):
    """Recommended remediation for a vulnerability."""

    action: RemediationAction
    description: str
    affected_version: Optional[str] = None
    fixed_version: Optional[str] = None
    workaround_detail: Optional[str] = None
    accept_risk_template: Optional[str] = None
    effort_hours: Optional[float] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class PrioritizedVuln(BaseModel):
    """A vulnerability with full composite priority score."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    cve_id: Optional[str] = None
    title: str
    asset_id: str
    asset_name: str

    # Component scores
    epss_score: float = Field(ge=0.0, le=1.0, default=0.0)
    reachability: ReachabilityLevel = ReachabilityLevel.UNKNOWN
    reachability_factor: float = Field(ge=0.0, le=1.0, default=0.5)
    business_impact: float = Field(ge=0.0, le=1.0, default=0.5)
    compensating_controls: float = Field(ge=0.0, le=1.0, default=0.0)

    # Composite score (0-100) and bucket
    composite_score: float = Field(ge=0.0, le=100.0, default=0.0)
    risk_bucket: RiskBucket = RiskBucket.MEDIUM

    # SLA
    sla_deadline: Optional[datetime] = None
    sla_breached: bool = False
    days_open: int = 0
    assigned_team: Optional[str] = None

    # Metadata
    group_id: Optional[str] = None
    recommendations: List[RemediationRecommendation] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_prioritized: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = "default"


class VulnGroup(BaseModel):
    """Auto-group of related vulnerabilities."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    group_type: str  # "same_cve", "same_library", "same_pattern"
    label: str
    finding_ids: List[str] = Field(default_factory=list)
    cve_id: Optional[str] = None
    library: Optional[str] = None
    pattern: Optional[str] = None
    max_composite_score: float = 0.0
    fix_once_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = "default"


class SLAStatus(BaseModel):
    """SLA compliance dashboard per team."""

    org_id: str
    team: Optional[str] = None
    total_open: int
    within_sla: int
    breached: int
    breach_rate: float
    by_bucket: Dict[str, int] = Field(default_factory=dict)
    breached_by_bucket: Dict[str, int] = Field(default_factory=dict)
    as_of: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VulnTrend(BaseModel):
    """Vulnerability backlog trend data point."""

    org_id: str
    period_start: datetime
    period_end: datetime
    new_vulns: int
    resolved_vulns: int
    total_open: int
    mean_time_to_remediate_hours: Optional[float] = None
    sla_breach_rate: float
    risk_debt_score: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class PrioritizeRequest(BaseModel):
    """Request to trigger re-prioritization."""

    org_id: str = "default"
    asset_ids: Optional[List[str]] = None
    force_epss_refresh: bool = False


class PrioritizationSummary(BaseModel):
    """Result of a re-prioritization run."""

    org_id: str
    vulns_evaluated: int
    epss_refreshed: int
    duration_ms: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScoringWeights(BaseModel):
    """Operator-tunable business-impact weights (must sum to ~1.0)."""

    revenue_impact: float = Field(
        default=0.35, ge=0.0, le=1.0,
        description="Weight for revenue_impact dimension",
    )
    data_sensitivity: float = Field(
        default=0.30, ge=0.0, le=1.0,
        description="Weight for data_sensitivity dimension",
    )
    customer_impact: float = Field(
        default=0.20, ge=0.0, le=1.0,
        description="Weight for customer_impact_score dimension",
    )
    regulatory: float = Field(
        default=0.15, ge=0.0, le=1.0,
        description="Weight for regulatory contribution dimension",
    )
    regulatory_per_framework: float = Field(
        default=0.15, ge=0.0, le=1.0,
        description="Score added per compliance framework present",
    )
    regulatory_cap: float = Field(
        default=0.60, ge=0.0, le=1.0,
        description="Maximum regulatory sub-score before capping",
    )
    unknown_asset_default: float = Field(
        default=0.40, ge=0.0, le=1.0,
        description="Business impact score when no asset context is known",
    )


class BucketThresholds(BaseModel):
    """Operator-tunable composite-score thresholds for risk bucketing (scale 0-100)."""

    critical: float = Field(
        default=75.0, ge=0.0, le=100.0,
        description="Minimum score to be classified as CRITICAL",
    )
    high: float = Field(
        default=50.0, ge=0.0, le=100.0,
        description="Minimum score to be classified as HIGH",
    )
    medium: float = Field(
        default=20.0, ge=0.0, le=100.0,
        description="Minimum score to be classified as MEDIUM",
    )
    low: float = Field(
        default=5.0, ge=0.0, le=100.0,
        description="Minimum score to be classified as LOW (else INFO)",
    )


class ScoringConfig(BaseModel):
    """Full scoring configuration stored per org."""

    org_id: str = "default"
    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    thresholds: BucketThresholds = Field(default_factory=BucketThresholds)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# ENGINE
# ============================================================================


class VulnPrioritizer:
    """
    Vulnerability prioritization engine with EPSS + business context.

    SQLite-backed, thread-safe.

    Args:
        db_path: Path to SQLite database.
        org_id:  Default tenant org_id.
        epss_cache_ttl_hours: How long to cache EPSS scores locally.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        org_id: str = "default",
        epss_cache_ttl_hours: int = 24,
    ) -> None:
        self.db_path = db_path
        self.org_id = org_id
        self.epss_cache_ttl_hours = epss_cache_ttl_hours
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS epss_cache (
                    cve_id          TEXT PRIMARY KEY,
                    epss            REAL NOT NULL,
                    percentile      REAL NOT NULL DEFAULT 0.0,
                    model_version   TEXT NOT NULL DEFAULT 'v3',
                    score_date      TEXT NOT NULL,
                    fetched_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS business_context (
                    asset_id                TEXT PRIMARY KEY,
                    asset_name              TEXT NOT NULL,
                    revenue_impact          REAL NOT NULL DEFAULT 0.3,
                    data_sensitivity        REAL NOT NULL DEFAULT 0.3,
                    regulatory_frameworks   TEXT NOT NULL DEFAULT '[]',
                    customer_count          INTEGER NOT NULL DEFAULT 0,
                    customer_impact_score   REAL NOT NULL DEFAULT 0.0,
                    compensating_controls   REAL NOT NULL DEFAULT 0.0,
                    tier                    TEXT NOT NULL DEFAULT 'tier3',
                    org_id                  TEXT NOT NULL DEFAULT 'default',
                    updated_at              TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reachability (
                    finding_id  TEXT PRIMARY KEY,
                    level       TEXT NOT NULL DEFAULT 'unknown',
                    call_path   TEXT NOT NULL DEFAULT '[]',
                    evidence    TEXT NOT NULL DEFAULT '',
                    analyzer    TEXT NOT NULL DEFAULT 'static_analysis',
                    analyzed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS prioritized_vulns (
                    id                    TEXT PRIMARY KEY,
                    finding_id            TEXT NOT NULL UNIQUE,
                    cve_id                TEXT,
                    title                 TEXT NOT NULL,
                    asset_id              TEXT NOT NULL,
                    asset_name            TEXT NOT NULL,
                    epss_score            REAL NOT NULL DEFAULT 0.0,
                    reachability          TEXT NOT NULL DEFAULT 'unknown',
                    reachability_factor   REAL NOT NULL DEFAULT 0.5,
                    business_impact       REAL NOT NULL DEFAULT 0.5,
                    compensating_controls REAL NOT NULL DEFAULT 0.0,
                    composite_score       REAL NOT NULL DEFAULT 0.0,
                    risk_bucket           TEXT NOT NULL DEFAULT 'medium',
                    sla_deadline          TEXT,
                    sla_breached          INTEGER NOT NULL DEFAULT 0,
                    days_open             INTEGER NOT NULL DEFAULT 0,
                    assigned_team         TEXT,
                    group_id              TEXT,
                    recommendations       TEXT NOT NULL DEFAULT '[]',
                    discovered_at         TEXT NOT NULL,
                    last_prioritized      TEXT NOT NULL,
                    org_id                TEXT NOT NULL DEFAULT 'default'
                );

                CREATE INDEX IF NOT EXISTS idx_pv_org_bucket
                    ON prioritized_vulns (org_id, risk_bucket);
                CREATE INDEX IF NOT EXISTS idx_pv_org_cve
                    ON prioritized_vulns (org_id, cve_id);
                CREATE INDEX IF NOT EXISTS idx_pv_asset
                    ON prioritized_vulns (asset_id);

                CREATE TABLE IF NOT EXISTS scoring_config (
                    org_id      TEXT PRIMARY KEY,
                    weights     TEXT NOT NULL DEFAULT '{}',
                    thresholds  TEXT NOT NULL DEFAULT '{}',
                    updated_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vuln_groups (
                    id                  TEXT PRIMARY KEY,
                    group_type          TEXT NOT NULL,
                    label               TEXT NOT NULL,
                    finding_ids         TEXT NOT NULL DEFAULT '[]',
                    cve_id              TEXT,
                    library             TEXT,
                    pattern             TEXT,
                    max_composite_score REAL NOT NULL DEFAULT 0.0,
                    fix_once_count      INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL,
                    org_id              TEXT NOT NULL DEFAULT 'default'
                );
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # EPSS Integration
    # ------------------------------------------------------------------

    def get_epss_score(self, cve_id: str, force_refresh: bool = False) -> EPSSScore:
        """Return EPSS score for a CVE. Checks cache first, then FIRST.org API."""
        with self._lock:
            if not force_refresh:
                cached = self._get_epss_from_cache(cve_id)
                if cached:
                    return cached
            return self._fetch_epss_from_api(cve_id)

    def _get_epss_from_cache(self, cve_id: str) -> Optional[EPSSScore]:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=self.epss_cache_ttl_hours)
        ).isoformat()
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM epss_cache WHERE cve_id = ? AND fetched_at > ?",
                (cve_id.upper(), cutoff),
            ).fetchone()
        if not row:
            return None
        return EPSSScore(
            cve_id=row["cve_id"],
            epss=row["epss"],
            percentile=row["percentile"],
            model_version=row["model_version"],
            score_date=datetime.fromisoformat(row["score_date"]),
            cached=True,
        )

    def _fetch_epss_from_api(self, cve_id: str) -> EPSSScore:
        """Fetch EPSS from FIRST.org API and cache result. Falls back to 0.0 on error."""
        url = f"{_EPSS_API_BASE}?cve={cve_id.upper()}"
        try:
            with urlopen(url, timeout=5) as resp:  # noqa: S310  # nosec
                data = json.loads(resp.read().decode())
            items = data.get("data", [])
            if items:
                item = items[0]
                epss_val = float(item.get("epss", 0.0))
                pct_val = float(item.get("percentile", 0.0))
            else:
                epss_val, pct_val = 0.0, 0.0
        except (URLError, OSError, json.JSONDecodeError, KeyError) as exc:
            _logger.warning("EPSS API unavailable for %s: %s — using 0.0", cve_id, exc)
            epss_val, pct_val = 0.0, 0.0

        score = EPSSScore(
            cve_id=cve_id.upper(),
            epss=epss_val,
            percentile=pct_val,
            cached=False,
        )
        self._cache_epss(score)
        return score

    def _cache_epss(self, score: EPSSScore) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO epss_cache
                    (cve_id, epss, percentile, model_version, score_date, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    epss=excluded.epss,
                    percentile=excluded.percentile,
                    model_version=excluded.model_version,
                    score_date=excluded.score_date,
                    fetched_at=excluded.fetched_at
                """,
                (
                    score.cve_id,
                    score.epss,
                    score.percentile,
                    score.model_version,
                    score.score_date.isoformat(),
                    now,
                ),
            )

    # ------------------------------------------------------------------
    # Business Context
    # ------------------------------------------------------------------

    def upsert_business_context(self, ctx: BusinessContext) -> None:
        """Store or update business context for an asset."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO business_context
                        (asset_id, asset_name, revenue_impact, data_sensitivity,
                         regulatory_frameworks, customer_count, customer_impact_score,
                         compensating_controls, tier, org_id, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(asset_id) DO UPDATE SET
                        asset_name=excluded.asset_name,
                        revenue_impact=excluded.revenue_impact,
                        data_sensitivity=excluded.data_sensitivity,
                        regulatory_frameworks=excluded.regulatory_frameworks,
                        customer_count=excluded.customer_count,
                        customer_impact_score=excluded.customer_impact_score,
                        compensating_controls=excluded.compensating_controls,
                        tier=excluded.tier,
                        org_id=excluded.org_id,
                        updated_at=excluded.updated_at
                    """,
                    (
                        ctx.asset_id,
                        ctx.asset_name,
                        ctx.revenue_impact,
                        ctx.data_sensitivity,
                        json.dumps([f.value for f in ctx.regulatory_frameworks]),
                        ctx.customer_count,
                        ctx.customer_impact_score,
                        ctx.compensating_controls,
                        ctx.tier,
                        ctx.org_id,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

    def get_business_context(self, asset_id: str) -> Optional[BusinessContext]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM business_context WHERE asset_id = ?", (asset_id,)
            ).fetchone()
        if not row:
            return None
        valid_fw = {fw.value for fw in ComplianceFramework}
        return BusinessContext(
            asset_id=row["asset_id"],
            asset_name=row["asset_name"],
            revenue_impact=row["revenue_impact"],
            data_sensitivity=row["data_sensitivity"],
            regulatory_frameworks=[
                ComplianceFramework(f)
                for f in json.loads(row["regulatory_frameworks"])
                if f in valid_fw
            ],
            customer_count=row["customer_count"],
            customer_impact_score=row["customer_impact_score"],
            compensating_controls=row["compensating_controls"],
            tier=row["tier"],
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # Scoring Configuration
    # ------------------------------------------------------------------

    def get_scoring_config(self, org_id: Optional[str] = None) -> "ScoringConfig":
        """Return operator-tuned scoring config for the org (falls back to defaults)."""
        _org = org_id or self.org_id
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT weights, thresholds FROM scoring_config WHERE org_id = ?",
                (_org,),
            ).fetchone()
        if not row:
            return ScoringConfig(org_id=_org)
        return ScoringConfig(
            org_id=_org,
            weights=ScoringWeights(**json.loads(row["weights"])),
            thresholds=BucketThresholds(**json.loads(row["thresholds"])),
        )

    def upsert_scoring_config(self, config: "ScoringConfig") -> "ScoringConfig":
        """Persist operator-tuned scoring config for the org."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scoring_config (org_id, weights, thresholds, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(org_id) DO UPDATE SET
                        weights=excluded.weights,
                        thresholds=excluded.thresholds,
                        updated_at=excluded.updated_at
                    """,
                    (
                        config.org_id,
                        config.weights.model_dump_json(),
                        config.thresholds.model_dump_json(),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
        config.updated_at = datetime.now(timezone.utc)
        return config

    def _compute_business_impact(
        self,
        ctx: Optional[BusinessContext],
        weights: Optional["ScoringWeights"] = None,
    ) -> float:
        """Aggregate business impact 0.0–1.0 using operator-tunable weights."""
        w = weights or ScoringWeights()
        if ctx is None:
            return w.unknown_asset_default

        regulatory_weight = min(len(ctx.regulatory_frameworks) * w.regulatory_per_framework, w.regulatory_cap)
        impact = (
            ctx.revenue_impact * w.revenue_impact
            + ctx.data_sensitivity * w.data_sensitivity
            + ctx.customer_impact_score * w.customer_impact
            + regulatory_weight * w.regulatory
        )
        tier_mult = {"tier1": 1.2, "tier2": 1.1, "tier3": 1.0, "tier4": 0.8}.get(ctx.tier, 1.0)
        return min(impact * tier_mult, 1.0)

    # ------------------------------------------------------------------
    # Reachability Analysis
    # ------------------------------------------------------------------

    def upsert_reachability(self, result: ReachabilityResult) -> None:
        """Store or update reachability analysis for a finding."""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO reachability
                        (finding_id, level, call_path, evidence, analyzer, analyzed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        level=excluded.level,
                        call_path=excluded.call_path,
                        evidence=excluded.evidence,
                        analyzer=excluded.analyzer,
                        analyzed_at=excluded.analyzed_at
                    """,
                    (
                        result.finding_id,
                        result.level.value,
                        json.dumps(result.call_path),
                        result.evidence,
                        result.analyzer,
                        result.analyzed_at.isoformat(),
                    ),
                )

    def get_reachability(self, finding_id: str) -> Optional[ReachabilityResult]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM reachability WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if not row:
            return None
        return ReachabilityResult(
            finding_id=row["finding_id"],
            level=ReachabilityLevel(row["level"]),
            call_path=json.loads(row["call_path"]),
            evidence=row["evidence"],
            analyzer=row["analyzer"],
            analyzed_at=datetime.fromisoformat(row["analyzed_at"]),
        )

    # ------------------------------------------------------------------
    # Composite Score
    # ------------------------------------------------------------------

    def compute_composite_score(
        self,
        epss: float,
        reachability: ReachabilityLevel,
        business_impact: float,
        compensating_controls: float,
        thresholds: Optional["BucketThresholds"] = None,
    ) -> Tuple[float, RiskBucket]:
        """
        risk = EPSS × reachability_factor × business_impact × (1 - compensating_controls)
        Scaled to 0-100 and bucketed using operator-tunable thresholds.
        """
        t = thresholds or BucketThresholds()
        r_factor = _REACHABILITY_FACTOR.get(reachability.value, 0.5)
        raw = epss * r_factor * business_impact * (1.0 - compensating_controls)
        score = min(raw * 100.0, 100.0)

        if score >= t.critical:
            bucket = RiskBucket.CRITICAL
        elif score >= t.high:
            bucket = RiskBucket.HIGH
        elif score >= t.medium:
            bucket = RiskBucket.MEDIUM
        elif score >= t.low:
            bucket = RiskBucket.LOW
        else:
            bucket = RiskBucket.INFO

        return round(score, 2), bucket

    def _compute_sla_deadline(
        self, discovered_at: datetime, bucket: RiskBucket
    ) -> datetime:
        hours = _SLA_HOURS.get(bucket.value, 8760)
        return discovered_at + timedelta(hours=hours)

    # ------------------------------------------------------------------
    # Remediation Recommendations
    # ------------------------------------------------------------------

    def _build_recommendations(
        self,
        cve_id: Optional[str],
        title: str,
        epss: float,
        bucket: RiskBucket,
    ) -> List[RemediationRecommendation]:
        recs: List[RemediationRecommendation] = []

        if cve_id:
            recs.append(
                RemediationRecommendation(
                    action=RemediationAction.UPGRADE,
                    description=(
                        f"Upgrade the affected package to a version that resolves {cve_id}. "
                        "Check the vendor advisory for the minimum fixed version."
                    ),
                    effort_hours=2.0,
                    confidence=0.9,
                )
            )

        if bucket in (RiskBucket.CRITICAL, RiskBucket.HIGH) and cve_id:
            recs.append(
                RemediationRecommendation(
                    action=RemediationAction.WORKAROUND,
                    description=(
                        f"Deploy a WAF virtual patch for {cve_id} to block exploitation "
                        "while the permanent fix is applied."
                    ),
                    workaround_detail=(
                        "Add a WAF rule matching the known exploitation payload pattern. "
                        "Consult ModSecurity / AWS WAF managed rule sets for pre-built rules."
                    ),
                    effort_hours=1.0,
                    confidence=0.7,
                )
            )

        if bucket == RiskBucket.CRITICAL:
            recs.append(
                RemediationRecommendation(
                    action=RemediationAction.MITIGATE,
                    description=(
                        "Immediately restrict network access to the affected asset. "
                        "Apply zero-trust micro-segmentation until patched."
                    ),
                    effort_hours=0.5,
                    confidence=0.85,
                )
            )

        if bucket in (RiskBucket.LOW, RiskBucket.INFO) and epss < 0.05:
            template = (
                "RISK ACCEPTANCE JUSTIFICATION\n"
                f"CVE: {cve_id or 'N/A'}\n"
                f"Finding: {title}\n"
                f"EPSS Score: {epss:.4f} (low exploitation probability)\n"
                "Rationale: Low business impact + low exploitation probability "
                "justifies accepting this risk until the next scheduled maintenance window.\n"
                "Approved by: [CISO name]\n"
                "Review date: [DATE + 90 days]\n"
            )
            recs.append(
                RemediationRecommendation(
                    action=RemediationAction.ACCEPT_RISK,
                    description="Accept risk with formal justification and scheduled review.",
                    accept_risk_template=template,
                    effort_hours=0.5,
                    confidence=0.6,
                )
            )

        return recs

    # ------------------------------------------------------------------
    # Prioritize / Upsert
    # ------------------------------------------------------------------

    def upsert_vuln(
        self,
        finding_id: str,
        title: str,
        asset_id: str,
        asset_name: str,
        cve_id: Optional[str] = None,
        discovered_at: Optional[datetime] = None,
        assigned_team: Optional[str] = None,
        force_epss_refresh: bool = False,
        org_id: Optional[str] = None,
    ) -> PrioritizedVuln:
        """
        Ingest a finding, compute composite score, persist, and return full result.
        All components (EPSS, reachability, business context) are looked up automatically.
        """
        with self._lock:
            _org = org_id or self.org_id
            _discovered = discovered_at or datetime.now(timezone.utc)

            # 0. Load operator-tunable scoring config
            scoring_cfg = self.get_scoring_config(_org)

            # 1. EPSS
            epss_val = 0.0
            if cve_id:
                try:
                    epss_val = self.get_epss_score(
                        cve_id, force_refresh=force_epss_refresh
                    ).epss
                except Exception:
                    _logger.warning("EPSS lookup failed for %s", cve_id)

            # 2. Reachability
            reach_result = self.get_reachability(finding_id)
            reach_level = reach_result.level if reach_result else ReachabilityLevel.UNKNOWN
            reach_factor = _REACHABILITY_FACTOR.get(reach_level.value, 0.5)

            # 3. Business context
            ctx = self.get_business_context(asset_id)
            biz_impact = self._compute_business_impact(ctx, weights=scoring_cfg.weights)
            controls = ctx.compensating_controls if ctx else 0.0

            # 4. Composite score
            score, bucket = self.compute_composite_score(
                epss_val, reach_level, biz_impact, controls,
                thresholds=scoring_cfg.thresholds,
            )

            # 5. SLA deadline
            sla_deadline = self._compute_sla_deadline(_discovered, bucket)
            now = datetime.now(timezone.utc)
            sla_breached = now > sla_deadline
            days_open = (now - _discovered).days

            # 6. Recommendations
            recs = self._build_recommendations(cve_id, title, epss_val, bucket)

            vuln = PrioritizedVuln(
                finding_id=finding_id,
                cve_id=cve_id,
                title=title,
                asset_id=asset_id,
                asset_name=asset_name,
                epss_score=epss_val,
                reachability=reach_level,
                reachability_factor=reach_factor,
                business_impact=biz_impact,
                compensating_controls=controls,
                composite_score=score,
                risk_bucket=bucket,
                sla_deadline=sla_deadline,
                sla_breached=sla_breached,
                days_open=days_open,
                assigned_team=assigned_team,
                recommendations=recs,
                discovered_at=_discovered,
                last_prioritized=now,
                org_id=_org,
            )

            self._persist_vuln(vuln)

            if _get_tg_bus is not None:
                try:
                    _get_tg_bus().emit("vuln_prioritizer.vuln_upserted", {
                        "finding_id": finding_id,
                        "asset_id": asset_id,
                        "cve_id": cve_id,
                        "risk_bucket": bucket.value,
                        "composite_score": score,
                        "org_id": _org,
                    })
                except Exception:  # noqa: BLE001
                    pass

            return vuln

    def _persist_vuln(self, v: PrioritizedVuln) -> None:
        with self._get_conn() as conn:
            existing = conn.execute(
                "SELECT id FROM prioritized_vulns WHERE finding_id = ?", (v.finding_id,)
            ).fetchone()
            vuln_id = existing["id"] if existing else v.id

            conn.execute(
                """
                INSERT INTO prioritized_vulns
                    (id, finding_id, cve_id, title, asset_id, asset_name,
                     epss_score, reachability, reachability_factor, business_impact,
                     compensating_controls, composite_score, risk_bucket,
                     sla_deadline, sla_breached, days_open, assigned_team,
                     group_id, recommendations, discovered_at, last_prioritized, org_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    cve_id=excluded.cve_id,
                    title=excluded.title,
                    asset_id=excluded.asset_id,
                    asset_name=excluded.asset_name,
                    epss_score=excluded.epss_score,
                    reachability=excluded.reachability,
                    reachability_factor=excluded.reachability_factor,
                    business_impact=excluded.business_impact,
                    compensating_controls=excluded.compensating_controls,
                    composite_score=excluded.composite_score,
                    risk_bucket=excluded.risk_bucket,
                    sla_deadline=excluded.sla_deadline,
                    sla_breached=excluded.sla_breached,
                    days_open=excluded.days_open,
                    assigned_team=excluded.assigned_team,
                    group_id=excluded.group_id,
                    recommendations=excluded.recommendations,
                    last_prioritized=excluded.last_prioritized
                """,
                (
                    vuln_id,
                    v.finding_id,
                    v.cve_id,
                    v.title,
                    v.asset_id,
                    v.asset_name,
                    v.epss_score,
                    v.reachability.value,
                    v.reachability_factor,
                    v.business_impact,
                    v.compensating_controls,
                    v.composite_score,
                    v.risk_bucket.value,
                    v.sla_deadline.isoformat() if v.sla_deadline else None,
                    int(v.sla_breached),
                    v.days_open,
                    v.assigned_team,
                    v.group_id,
                    json.dumps([r.model_dump() for r in v.recommendations]),
                    v.discovered_at.isoformat(),
                    v.last_prioritized.isoformat(),
                    v.org_id,
                ),
            )

    # ------------------------------------------------------------------
    # Query — Prioritized List
    # ------------------------------------------------------------------

    def list_prioritized(
        self,
        org_id: Optional[str] = None,
        bucket: Optional[RiskBucket] = None,
        asset_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PrioritizedVuln]:
        """Return prioritized vulns sorted by composite_score desc."""
        _org = org_id or self.org_id
        clauses = ["org_id = ?"]
        params: List[Any] = [_org]

        if bucket:
            clauses.append("risk_bucket = ?")
            params.append(bucket.value)
        if asset_id:
            clauses.append("asset_id = ?")
            params.append(asset_id)

        where = " AND ".join(clauses)
        params.extend([limit, offset])

        with self._get_conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM prioritized_vulns WHERE {where} "  # nosec B608
                f"ORDER BY composite_score DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()

        return [self._row_to_vuln(r) for r in rows]

    def _row_to_vuln(self, row: sqlite3.Row) -> PrioritizedVuln:
        recs_raw = json.loads(row["recommendations"] or "[]")
        recs = [RemediationRecommendation(**r) for r in recs_raw]
        return PrioritizedVuln(
            id=row["id"],
            finding_id=row["finding_id"],
            cve_id=row["cve_id"],
            title=row["title"],
            asset_id=row["asset_id"],
            asset_name=row["asset_name"],
            epss_score=row["epss_score"],
            reachability=ReachabilityLevel(row["reachability"]),
            reachability_factor=row["reachability_factor"],
            business_impact=row["business_impact"],
            compensating_controls=row["compensating_controls"],
            composite_score=row["composite_score"],
            risk_bucket=RiskBucket(row["risk_bucket"]),
            sla_deadline=(
                datetime.fromisoformat(row["sla_deadline"]) if row["sla_deadline"] else None
            ),
            sla_breached=bool(row["sla_breached"]),
            days_open=row["days_open"],
            assigned_team=row["assigned_team"],
            group_id=row["group_id"],
            recommendations=recs,
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
            last_prioritized=datetime.fromisoformat(row["last_prioritized"]),
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # SLA Status
    # ------------------------------------------------------------------

    def get_sla_status(
        self, org_id: Optional[str] = None, team: Optional[str] = None
    ) -> SLAStatus:
        _org = org_id or self.org_id
        clauses = ["org_id = ?"]
        params: List[Any] = [_org]
        if team:
            clauses.append("assigned_team = ?")
            params.append(team)
        where = " AND ".join(clauses)

        with self._get_conn() as conn:
            rows = conn.execute(
                f"SELECT risk_bucket, sla_breached FROM prioritized_vulns WHERE {where}",  # nosec B608
                params,
            ).fetchall()

        total = len(rows)
        breached = sum(1 for r in rows if r["sla_breached"])
        within_sla = total - breached

        by_bucket: Dict[str, int] = {}
        breached_by_bucket: Dict[str, int] = {}
        for r in rows:
            b = r["risk_bucket"]
            by_bucket[b] = by_bucket.get(b, 0) + 1
            if r["sla_breached"]:
                breached_by_bucket[b] = breached_by_bucket.get(b, 0) + 1

        return SLAStatus(
            org_id=_org,
            team=team,
            total_open=total,
            within_sla=within_sla,
            breached=breached,
            breach_rate=round(breached / total, 4) if total > 0 else 0.0,
            by_bucket=by_bucket,
            breached_by_bucket=breached_by_bucket,
        )

    # ------------------------------------------------------------------
    # Trend Analysis
    # ------------------------------------------------------------------

    def compute_trend(
        self,
        org_id: Optional[str] = None,
        days: int = 30,
    ) -> VulnTrend:
        """Compute trend statistics for the last N days."""
        _org = org_id or self.org_id
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(days=days)

        with self._get_conn() as conn:
            new_count = conn.execute(
                "SELECT COUNT(*) FROM prioritized_vulns WHERE org_id=? AND discovered_at >= ?",
                (_org, period_start.isoformat()),
            ).fetchone()[0]

            total_open = conn.execute(
                "SELECT COUNT(*) FROM prioritized_vulns WHERE org_id=?", (_org,)
            ).fetchone()[0]

            bucket_rows = conn.execute(
                "SELECT risk_bucket, COUNT(*) as cnt FROM prioritized_vulns "
                "WHERE org_id=? GROUP BY risk_bucket",
                (_org,),
            ).fetchall()

            debt_row = conn.execute(
                "SELECT COALESCE(SUM(composite_score), 0) FROM prioritized_vulns WHERE org_id=?",
                (_org,),
            ).fetchone()

        bucket_map: Dict[str, int] = {r["risk_bucket"]: r["cnt"] for r in bucket_rows}
        risk_debt = float(debt_row[0])
        sla_status = self.get_sla_status(_org)

        return VulnTrend(
            org_id=_org,
            period_start=period_start,
            period_end=now,
            new_vulns=new_count,
            resolved_vulns=0,
            total_open=total_open,
            mean_time_to_remediate_hours=None,
            sla_breach_rate=sla_status.breach_rate,
            risk_debt_score=round(risk_debt, 2),
            critical_count=bucket_map.get("critical", 0),
            high_count=bucket_map.get("high", 0),
            medium_count=bucket_map.get("medium", 0),
            low_count=bucket_map.get("low", 0),
        )

    # ------------------------------------------------------------------
    # Auto-Grouping
    # ------------------------------------------------------------------

    def rebuild_groups(self, org_id: Optional[str] = None) -> List[VulnGroup]:
        """
        Rebuild auto-groups for the org:
        - same_cve: multiple assets hit by the same CVE
        - same_library: same library (first title token) across findings
        - same_pattern: misconfiguration patterns (first 3 title words)
        """
        _org = org_id or self.org_id
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT finding_id, cve_id, title, composite_score "
                    "FROM prioritized_vulns WHERE org_id=?",
                    (_org,),
                ).fetchall()

            # Group by CVE
            cve_map: Dict[str, List[Tuple[str, float]]] = {}
            lib_map: Dict[str, List[Tuple[str, float]]] = {}
            pattern_map: Dict[str, List[Tuple[str, float]]] = {}

            for r in rows:
                fid = r["finding_id"]
                score = r["composite_score"]

                if r["cve_id"]:
                    cve_map.setdefault(r["cve_id"], []).append((fid, score))
                else:
                    parts = r["title"].split()
                    if parts:
                        lib_key = parts[0].lower().rstrip(":")
                        lib_map.setdefault(lib_key, []).append((fid, score))

                words = r["title"].lower().split()
                if len(words) >= 3:
                    key = " ".join(words[:3])
                    pattern_map.setdefault(key, []).append((fid, score))

            # Clear old groups
            with self._get_conn() as conn:
                conn.execute("DELETE FROM vuln_groups WHERE org_id=?", (_org,))
                conn.execute(
                    "UPDATE prioritized_vulns SET group_id=NULL WHERE org_id=?", (_org,)
                )

            groups: List[VulnGroup] = []
            now_ts = datetime.now(timezone.utc)

            def _persist_group(grp: VulnGroup) -> None:
                with self._get_conn() as conn:
                    conn.execute(
                        """
                        INSERT INTO vuln_groups
                            (id, group_type, label, finding_ids, cve_id, library, pattern,
                             max_composite_score, fix_once_count, created_at, org_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            grp.id,
                            grp.group_type,
                            grp.label,
                            json.dumps(grp.finding_ids),
                            grp.cve_id,
                            grp.library,
                            grp.pattern,
                            grp.max_composite_score,
                            grp.fix_once_count,
                            grp.created_at.isoformat(),
                            grp.org_id,
                        ),
                    )
                    for fid in grp.finding_ids:
                        conn.execute(
                            "UPDATE prioritized_vulns SET group_id=? WHERE finding_id=?",
                            (grp.id, fid),
                        )

            for cve_id, items in cve_map.items():
                if len(items) < 2:
                    continue
                grp = VulnGroup(
                    group_type="same_cve",
                    label=f"CVE: {cve_id} ({len(items)} assets)",
                    finding_ids=[i[0] for i in items],
                    cve_id=cve_id,
                    max_composite_score=max(i[1] for i in items),
                    fix_once_count=len(items),
                    created_at=now_ts,
                    org_id=_org,
                )
                _persist_group(grp)
                groups.append(grp)

            for lib, items in lib_map.items():
                if len(items) < 2:
                    continue
                grp = VulnGroup(
                    group_type="same_library",
                    label=f"Library: {lib} ({len(items)} findings)",
                    finding_ids=[i[0] for i in items],
                    library=lib,
                    max_composite_score=max(i[1] for i in items),
                    fix_once_count=len(items),
                    created_at=now_ts,
                    org_id=_org,
                )
                _persist_group(grp)
                groups.append(grp)

            for pat, items in pattern_map.items():
                if len(items) < 2:
                    continue
                grp = VulnGroup(
                    group_type="same_pattern",
                    label=f"Pattern: {pat!r} ({len(items)} findings)",
                    finding_ids=[i[0] for i in items],
                    pattern=pat,
                    max_composite_score=max(i[1] for i in items),
                    fix_once_count=len(items),
                    created_at=now_ts,
                    org_id=_org,
                )
                _persist_group(grp)
                groups.append(grp)

        _logger.info("rebuilt_groups org=%s groups=%d", _org, len(groups))
        return groups

    def list_groups(self, org_id: Optional[str] = None) -> List[VulnGroup]:
        _org = org_id or self.org_id
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM vuln_groups WHERE org_id=? "
                "ORDER BY max_composite_score DESC",
                (_org,),
            ).fetchall()
        return [
            VulnGroup(
                id=r["id"],
                group_type=r["group_type"],
                label=r["label"],
                finding_ids=json.loads(r["finding_ids"]),
                cve_id=r["cve_id"],
                library=r["library"],
                pattern=r["pattern"],
                max_composite_score=r["max_composite_score"],
                fix_once_count=r["fix_once_count"],
                created_at=datetime.fromisoformat(r["created_at"]),
                org_id=r["org_id"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Bulk Re-prioritization
    # ------------------------------------------------------------------

    def run_prioritization(
        self,
        org_id: Optional[str] = None,
        asset_ids: Optional[List[str]] = None,
        force_epss_refresh: bool = False,
    ) -> PrioritizationSummary:
        """Re-compute scores for all stored vulns (or a filtered subset)."""
        import time as _time

        _org = org_id or self.org_id
        t0 = _time.monotonic()

        clauses = ["org_id = ?"]
        params: List[Any] = [_org]
        if asset_ids:
            placeholders = ",".join("?" * len(asset_ids))
            clauses.append(f"asset_id IN ({placeholders})")
            params.extend(asset_ids)

        with self._get_conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM prioritized_vulns WHERE {' AND '.join(clauses)}",  # nosec B608
                params,
            ).fetchall()

        # Load operator-tunable scoring config once for the whole run
        scoring_cfg = self.get_scoring_config(_org)

        epss_refreshed = 0
        for row in rows:
            fid = row["finding_id"]
            try:
                epss_val = 0.0
                if row["cve_id"]:
                    score_obj = self.get_epss_score(
                        row["cve_id"], force_refresh=force_epss_refresh
                    )
                    epss_val = score_obj.epss
                    if not score_obj.cached:
                        epss_refreshed += 1

                reach_level = ReachabilityLevel(row["reachability"])
                ctx = self.get_business_context(row["asset_id"])
                biz_impact = self._compute_business_impact(ctx, weights=scoring_cfg.weights)
                controls = ctx.compensating_controls if ctx else 0.0
                score, bucket = self.compute_composite_score(
                    epss_val, reach_level, biz_impact, controls,
                    thresholds=scoring_cfg.thresholds,
                )
                discovered = datetime.fromisoformat(row["discovered_at"])
                sla_deadline = self._compute_sla_deadline(discovered, bucket)
                now = datetime.now(timezone.utc)

                with self._get_conn() as conn2:
                    conn2.execute(
                        """
                        UPDATE prioritized_vulns SET
                            epss_score=?, composite_score=?, risk_bucket=?,
                            business_impact=?, compensating_controls=?,
                            sla_deadline=?, sla_breached=?, days_open=?,
                            last_prioritized=?
                        WHERE finding_id=?
                        """,
                        (
                            epss_val,
                            score,
                            bucket.value,
                            biz_impact,
                            controls,
                            sla_deadline.isoformat(),
                            int(now > sla_deadline),
                            (now - discovered).days,
                            now.isoformat(),
                            fid,
                        ),
                    )
            except Exception:
                _logger.warning(
                    "Re-prioritization failed for finding_id=%s", fid, exc_info=True
                )

        elapsed_ms = (_time.monotonic() - t0) * 1000.0

        with self._get_conn() as conn:
            bucket_rows = conn.execute(
                "SELECT risk_bucket, COUNT(*) FROM prioritized_vulns "
                "WHERE org_id=? GROUP BY risk_bucket",
                (_org,),
            ).fetchall()
        counts = {r[0]: r[1] for r in bucket_rows}

        return PrioritizationSummary(
            org_id=_org,
            vulns_evaluated=len(rows),
            epss_refreshed=epss_refreshed,
            duration_ms=round(elapsed_ms, 2),
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            info_count=counts.get("info", 0),
        )


# Compatibility aliases
RiskFactor = BusinessContext
PrioritizedFinding = PrioritizedVuln
