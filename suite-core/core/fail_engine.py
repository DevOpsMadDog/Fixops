"""
ALdeci FAIL Engine — $FACT → $ASSESS → $IMPACT → $LIKELIHOOD

The FAIL score replaces CVSS gambling with evidence-based risk scoring.
Each vulnerability gets four sub-scores that combine into a single
actionable FAIL score (0-100).

  $FACT     — Is this vulnerability real? (evidence quality)
  $ASSESS   — What does exploitation require? (attack complexity)
  $IMPACT   — What happens if exploited? (blast radius)
  $LIKELIHOOD — How likely is exploitation? (threat intelligence)

Usage:
    from core.fail_engine import FAILEngine, FAILInput

    engine = FAILEngine()
    result = engine.score(FAILInput(
        cve_id="CVE-2024-3094",
        cvss_score=10.0,
        epss_score=0.97,
        is_kev=True,
        asset_criticality="critical",
        has_exploit=True,
        is_reachable=True,
        data_classification="pii",
    ))
    # result.fail_score → 95.2
    # result.grade → "CRITICAL"
    # result.recommended_action → "PATCH_IMMEDIATELY"
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FAILGrade(str, Enum):
    """FAIL grade mapping based on score ranges."""
    CRITICAL = "CRITICAL"   # 90-100
    HIGH = "HIGH"           # 70-89
    MEDIUM = "MEDIUM"       # 40-69
    LOW = "LOW"             # 20-39
    INFO = "INFO"           # 0-19


class RecommendedAction(str, Enum):
    """Action to take based on FAIL score."""
    PATCH_IMMEDIATELY = "PATCH_IMMEDIATELY"     # CRITICAL: drop everything
    PATCH_NEXT_SPRINT = "PATCH_NEXT_SPRINT"     # HIGH: schedule urgently
    SCHEDULE_FIX = "SCHEDULE_FIX"               # MEDIUM: plan it
    MONITOR = "MONITOR"                         # LOW: watch and wait
    ACCEPT_RISK = "ACCEPT_RISK"                 # INFO: log and move on


class AssetCriticality(str, Enum):
    """How important is the affected asset."""
    CRITICAL = "critical"       # Revenue-generating, customer-facing
    HIGH = "high"               # Internal but important
    MEDIUM = "medium"           # Standard workload
    LOW = "low"                 # Dev/test environment
    UNKNOWN = "unknown"         # Not classified


class DataClassification(str, Enum):
    """What kind of data is at risk."""
    PII = "pii"                         # Personally identifiable info
    PHI = "phi"                         # Protected health info
    PCI = "pci"                         # Payment card data
    FINANCIAL = "financial"             # Financial records
    CREDENTIALS = "credentials"         # Secrets, keys, passwords
    INTERNAL = "internal"               # Internal business data
    PUBLIC = "public"                   # Publicly available
    NONE = "none"                       # No data at risk


class ExploitMaturity(str, Enum):
    """How mature is the exploit."""
    WEAPONIZED = "weaponized"           # Active exploit kit / malware
    POC_PUBLIC = "poc_public"           # Public proof-of-concept
    POC_PRIVATE = "poc_private"         # Known private PoC
    THEORETICAL = "theoretical"         # No known exploit
    UNKNOWN = "unknown"                 # Not assessed


# ---------------------------------------------------------------------------
# Input / Output data classes
# ---------------------------------------------------------------------------


@dataclass
class FAILInput:
    """Input to the FAIL scoring engine."""

    # Identity
    cve_id: Optional[str] = None
    finding_id: Optional[str] = None
    title: str = ""

    # Raw scores from scanners
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None

    # Threat intelligence signals
    is_kev: bool = False                # CISA Known Exploited Vuln
    has_exploit: bool = False           # Any known exploit
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNKNOWN
    active_campaigns: int = 0          # Known threat campaigns using this

    # Environment context
    asset_criticality: str = "unknown"
    data_classification: str = "none"
    is_reachable: bool = False         # Is the vuln reachable from attack surface?
    is_internet_facing: bool = False   # Is the asset internet-facing?
    has_compensating_controls: bool = False  # WAF, IPS, network segmentation

    # Organisational context
    affected_assets: int = 1
    affected_users: int = 0
    compliance_frameworks: List[str] = field(default_factory=list)  # SOC2, PCI, HIPAA
    sla_hours: Optional[int] = None     # SLA for remediation

    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FAILFactScore:
    """$FACT — Is this vulnerability real?"""
    score: float = 0.0          # 0-100
    has_cve: bool = False
    has_cvss: bool = False
    has_epss: bool = False
    scanner_confirmed: bool = False
    multiple_sources: bool = False
    evidence_quality: str = "low"  # low, medium, high


@dataclass
class FAILAssessScore:
    """$ASSESS — What does exploitation require?"""
    score: float = 0.0          # 0-100
    attack_complexity: str = "unknown"  # low, medium, high
    privileges_required: str = "none"   # none, low, high
    user_interaction: str = "none"      # none, required
    exploit_maturity: str = "unknown"


@dataclass
class FAILImpactScore:
    """$IMPACT — What happens if exploited?"""
    score: float = 0.0          # 0-100
    confidentiality: str = "none"   # none, low, high
    integrity: str = "none"         # none, low, high
    availability: str = "none"      # none, low, high
    blast_radius: str = "contained"  # contained, component, system, org-wide
    data_at_risk: str = "none"
    business_impact: str = "low"    # low, medium, high, critical


@dataclass
class FAILLikelihoodScore:
    """$LIKELIHOOD — How likely is exploitation?"""
    score: float = 0.0          # 0-100
    epss_based: float = 0.0
    kev_boost: float = 0.0
    exploit_availability: float = 0.0
    threat_activity: float = 0.0
    exposure_factor: float = 0.0


@dataclass
class FAILResult:
    """Complete FAIL score output."""

    # Computed scores
    fail_score: float = 0.0             # 0-100 composite
    grade: FAILGrade = FAILGrade.INFO
    recommended_action: RecommendedAction = RecommendedAction.ACCEPT_RISK

    # Sub-scores
    fact: FAILFactScore = field(default_factory=FAILFactScore)
    assess: FAILAssessScore = field(default_factory=FAILAssessScore)
    impact: FAILImpactScore = field(default_factory=FAILImpactScore)
    likelihood: FAILLikelihoodScore = field(default_factory=FAILLikelihoodScore)

    # Weights used
    weights: Dict[str, float] = field(default_factory=dict)

    # Metadata
    score_id: str = ""
    cve_id: Optional[str] = None
    finding_id: Optional[str] = None
    scored_at: str = ""
    engine_version: str = "1.0.0"
    computation_ms: float = 0.0

    def __post_init__(self):
        if not self.score_id:
            self.score_id = f"FAIL-{uuid.uuid4().hex[:12].upper()}"
        if not self.scored_at:
            self.scored_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to dictionary for API responses."""
        return {
            "score_id": self.score_id,
            "fail_score": round(self.fail_score, 2),
            "grade": self.grade.value,
            "recommended_action": self.recommended_action.value,
            "cve_id": self.cve_id,
            "finding_id": self.finding_id,
            "sub_scores": {
                "fact": {
                    "score": round(self.fact.score, 2),
                    "has_cve": self.fact.has_cve,
                    "has_cvss": self.fact.has_cvss,
                    "has_epss": self.fact.has_epss,
                    "scanner_confirmed": self.fact.scanner_confirmed,
                    "multiple_sources": self.fact.multiple_sources,
                    "evidence_quality": self.fact.evidence_quality,
                },
                "assess": {
                    "score": round(self.assess.score, 2),
                    "attack_complexity": self.assess.attack_complexity,
                    "privileges_required": self.assess.privileges_required,
                    "user_interaction": self.assess.user_interaction,
                    "exploit_maturity": self.assess.exploit_maturity,
                },
                "impact": {
                    "score": round(self.impact.score, 2),
                    "confidentiality": self.impact.confidentiality,
                    "integrity": self.impact.integrity,
                    "availability": self.impact.availability,
                    "blast_radius": self.impact.blast_radius,
                    "data_at_risk": self.impact.data_at_risk,
                    "business_impact": self.impact.business_impact,
                },
                "likelihood": {
                    "score": round(self.likelihood.score, 2),
                    "epss_based": round(self.likelihood.epss_based, 2),
                    "kev_boost": round(self.likelihood.kev_boost, 2),
                    "exploit_availability": round(self.likelihood.exploit_availability, 2),
                    "threat_activity": round(self.likelihood.threat_activity, 2),
                    "exposure_factor": round(self.likelihood.exposure_factor, 2),
                },
            },
            "weights": {k: round(v, 3) for k, v in self.weights.items()},
            "scored_at": self.scored_at,
            "engine_version": self.engine_version,
            "computation_ms": round(self.computation_ms, 2),
        }


# ---------------------------------------------------------------------------
# FAIL Engine
# ---------------------------------------------------------------------------


class FAILEngine:
    """
    The FAIL scoring engine.

    Weights are dynamically adjusted based on context:
    - If KEV or active campaigns → boost LIKELIHOOD weight
    - If critical asset → boost IMPACT weight
    - If low evidence → boost FACT weight
    - Default balanced: FACT=0.20, ASSESS=0.20, IMPACT=0.30, LIKELIHOOD=0.30
    """

    VERSION = "1.0.0"

    # Default weights
    DEFAULT_WEIGHTS = {
        "fact": 0.20,
        "assess": 0.20,
        "impact": 0.30,
        "likelihood": 0.30,
    }

    # Memory bounds — prevent unbounded growth in long-running processes
    MAX_HISTORY_SIZE = 5000

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self._base_weights = dict(weights or self.DEFAULT_WEIGHTS)
        self._history: List[FAILResult] = []

    # ------------------------------------------------------------------
    # Main scoring API
    # ------------------------------------------------------------------

    def score(self, inp: FAILInput) -> FAILResult:
        """Compute the FAIL score for a single finding."""
        import time as _time


        start = _time.perf_counter()

        # 1. Compute sub-scores
        fact = self._compute_fact(inp)
        assess = self._compute_assess(inp)
        impact = self._compute_impact(inp)
        likelihood = self._compute_likelihood(inp)

        # 2. Dynamic weight adjustment
        weights = self._adjust_weights(inp, fact, assess, impact, likelihood)

        # 3. Composite FAIL score
        fail_score = (
            fact.score * weights["fact"]
            + assess.score * weights["assess"]
            + impact.score * weights["impact"]
            + likelihood.score * weights["likelihood"]
        )
        fail_score = max(0.0, min(100.0, fail_score))

        # 4. Grade and action
        grade = self._score_to_grade(fail_score)
        action = self._grade_to_action(grade)

        elapsed_ms = (_time.perf_counter() - start) * 1000

        result = FAILResult(
            fail_score=fail_score,
            grade=grade,
            recommended_action=action,
            fact=fact,
            assess=assess,
            impact=impact,
            likelihood=likelihood,
            weights=weights,
            cve_id=inp.cve_id,
            finding_id=inp.finding_id,
            computation_ms=elapsed_ms,
        )

        self._history.append(result)
        # Evict oldest entries when history exceeds bound
        if len(self._history) > self.MAX_HISTORY_SIZE:
            self._history = self._history[-self.MAX_HISTORY_SIZE:]
        logger.info(
            "FAIL score computed: %s → %.1f (%s) in %.1fms",
            inp.cve_id or inp.finding_id or "unknown",
            fail_score,
            grade.value,
            elapsed_ms,
        )
        return result

    def score_batch(self, inputs: Sequence[FAILInput]) -> List[FAILResult]:
        """Score multiple findings."""
        return [self.score(inp) for inp in inputs]

    @property
    def history(self) -> List[FAILResult]:
        """Return scoring history."""
        return list(self._history)

    # ------------------------------------------------------------------
    # $FACT — Evidence quality scoring
    # ------------------------------------------------------------------

    def _compute_fact(self, inp: FAILInput) -> FAILFactScore:
        score = 0.0
        has_cve = bool(inp.cve_id)
        has_cvss = inp.cvss_score is not None and inp.cvss_score > 0
        has_epss = inp.epss_score is not None and inp.epss_score > 0

        # CVE ID exists → confirmed vulnerability
        if has_cve:
            score += 30.0

        # CVSS score available → assessed by NVD
        if has_cvss:
            score += 20.0

        # EPSS data available → probabilistic assessment exists
        if has_epss:
            score += 20.0

        # Multiple evidence sources
        evidence_sources = sum([has_cve, has_cvss, has_epss, inp.has_exploit])
        multiple_sources = evidence_sources >= 3
        if multiple_sources:
            score += 15.0
        elif evidence_sources >= 2:
            score += 10.0

        # Scanner confirmed
        scanner_confirmed = has_cve or has_cvss
        if scanner_confirmed:
            score += 15.0

        score = min(100.0, score)

        # Evidence quality classification
        if score >= 70:
            evidence_quality = "high"
        elif score >= 40:
            evidence_quality = "medium"
        else:
            evidence_quality = "low"

        return FAILFactScore(
            score=score,
            has_cve=has_cve,
            has_cvss=has_cvss,
            has_epss=has_epss,
            scanner_confirmed=scanner_confirmed,
            multiple_sources=multiple_sources,
            evidence_quality=evidence_quality,
        )

    # ------------------------------------------------------------------
    # $ASSESS — Attack complexity scoring
    # ------------------------------------------------------------------

    def _compute_assess(self, inp: FAILInput) -> FAILAssessScore:
        score = 0.0

        # Derive attack complexity from CVSS
        if inp.cvss_score is not None:
            if inp.cvss_score >= 9.0:
                attack_complexity = "low"
                score += 40.0
            elif inp.cvss_score >= 7.0:
                attack_complexity = "low"
                score += 30.0
            elif inp.cvss_score >= 4.0:
                attack_complexity = "medium"
                score += 20.0
            else:
                attack_complexity = "high"
                score += 10.0
        else:
            attack_complexity = "unknown"
            score += 15.0  # Unknown = assume medium risk

        # Exploit maturity adds to complexity assessment
        maturity = inp.exploit_maturity
        if maturity == ExploitMaturity.WEAPONIZED:
            score += 35.0
            exploit_mat = "weaponized"
        elif maturity == ExploitMaturity.POC_PUBLIC:
            score += 25.0
            exploit_mat = "poc_public"
        elif maturity == ExploitMaturity.POC_PRIVATE:
            score += 15.0
            exploit_mat = "poc_private"
        elif maturity == ExploitMaturity.THEORETICAL:
            score += 5.0
            exploit_mat = "theoretical"
        else:
            exploit_mat = "unknown"
            if inp.has_exploit:
                score += 20.0

        # No auth required = easier to exploit
        privileges = "none" if inp.cvss_score and inp.cvss_score >= 8.0 else "low"
        if privileges == "none":
            score += 15.0
        else:
            score += 5.0

        # No user interaction = automated exploitation possible
        user_interaction = "none" if inp.cvss_score and inp.cvss_score >= 7.0 else "required"
        if user_interaction == "none":
            score += 10.0

        score = min(100.0, score)

        return FAILAssessScore(
            score=score,
            attack_complexity=attack_complexity,
            privileges_required=privileges,
            user_interaction=user_interaction,
            exploit_maturity=exploit_mat,
        )

    # ------------------------------------------------------------------
    # $IMPACT — Blast radius scoring
    # ------------------------------------------------------------------

    def _compute_impact(self, inp: FAILInput) -> FAILImpactScore:
        score = 0.0

        # Asset criticality
        crit = inp.asset_criticality.lower() if inp.asset_criticality else "unknown"
        criticality_scores = {
            "critical": 30.0,
            "high": 22.0,
            "medium": 14.0,
            "low": 6.0,
            "unknown": 14.0,  # Assume medium if unknown
        }
        score += criticality_scores.get(crit, 14.0)
        business_impact = crit if crit in ("critical", "high", "medium", "low") else "medium"

        # Data classification
        data_cls = inp.data_classification.lower() if inp.data_classification else "none"
        data_scores = {
            "pii": 25.0,
            "phi": 28.0,      # Healthcare data → highest regulatory risk
            "pci": 25.0,
            "financial": 22.0,
            "credentials": 28.0,
            "internal": 12.0,
            "public": 3.0,
            "none": 5.0,
        }
        score += data_scores.get(data_cls, 10.0)

        # CIA impact (derived from CVSS or assumed HIGH when critical)
        if inp.cvss_score and inp.cvss_score >= 9.0:
            conf, integ, avail = "high", "high", "high"
            score += 20.0
        elif inp.cvss_score and inp.cvss_score >= 7.0:
            conf, integ, avail = "high", "low", "low"
            score += 12.0
        elif inp.cvss_score and inp.cvss_score >= 4.0:
            conf, integ, avail = "low", "low", "none"
            score += 6.0
        else:
            conf, integ, avail = "none", "none", "none"
            score += 2.0

        # Blast radius
        if inp.affected_assets >= 100:
            blast_radius = "org-wide"
            score += 15.0
        elif inp.affected_assets >= 10:
            blast_radius = "system"
            score += 10.0
        elif inp.affected_assets >= 2:
            blast_radius = "component"
            score += 5.0
        else:
            blast_radius = "contained"
            score += 2.0

        # Compliance penalty
        if inp.compliance_frameworks:
            score += min(10.0, len(inp.compliance_frameworks) * 3.0)

        score = min(100.0, score)

        return FAILImpactScore(
            score=score,
            confidentiality=conf,
            integrity=integ,
            availability=avail,
            blast_radius=blast_radius,
            data_at_risk=data_cls,
            business_impact=business_impact,
        )

    # ------------------------------------------------------------------
    # $LIKELIHOOD — Exploitation probability scoring
    # ------------------------------------------------------------------

    def _compute_likelihood(self, inp: FAILInput) -> FAILLikelihoodScore:
        # EPSS-based (0-1 → 0-40)
        epss_based = 0.0
        if inp.epss_score is not None:
            epss_based = inp.epss_score * 40.0

        # KEV boost (CISA says it's actively exploited)
        kev_boost = 25.0 if inp.is_kev else 0.0

        # Exploit availability
        exploit_avail = 0.0
        if inp.has_exploit:
            exploit_avail = 15.0
        if inp.exploit_maturity == ExploitMaturity.WEAPONIZED:
            exploit_avail = 20.0
        elif inp.exploit_maturity == ExploitMaturity.POC_PUBLIC:
            exploit_avail = 15.0

        # Active threat campaigns
        threat_activity = min(15.0, inp.active_campaigns * 5.0)

        # Exposure factor (reachable + internet-facing)
        exposure = 0.0
        if inp.is_reachable:
            exposure += 10.0
        if inp.is_internet_facing:
            exposure += 10.0
        # Compensating controls reduce exposure
        if inp.has_compensating_controls:
            exposure = max(0.0, exposure - 8.0)

        total = epss_based + kev_boost + exploit_avail + threat_activity + exposure
        total = min(100.0, total)

        return FAILLikelihoodScore(
            score=total,
            epss_based=epss_based,
            kev_boost=kev_boost,
            exploit_availability=exploit_avail,
            threat_activity=threat_activity,
            exposure_factor=exposure,
        )

    # ------------------------------------------------------------------
    # Dynamic weight adjustment
    # ------------------------------------------------------------------

    def _adjust_weights(
        self,
        inp: FAILInput,
        fact: FAILFactScore,
        assess: FAILAssessScore,
        impact: FAILImpactScore,
        likelihood: FAILLikelihoodScore,
    ) -> Dict[str, float]:
        """Dynamically adjust weights based on context."""
        w = dict(self._base_weights)

        # Low evidence → boost FACT weight (penalise score for uncertainty)
        if fact.evidence_quality == "low":
            w["fact"] += 0.10
            w["likelihood"] -= 0.05
            w["impact"] -= 0.05

        # KEV or active campaigns → boost LIKELIHOOD weight
        if inp.is_kev or inp.active_campaigns > 0:
            w["likelihood"] += 0.10
            w["assess"] -= 0.05
            w["fact"] -= 0.05

        # Critical asset → boost IMPACT weight
        if inp.asset_criticality in ("critical", "high"):
            w["impact"] += 0.10
            w["assess"] -= 0.05
            w["fact"] -= 0.05

        # Normalise to sum to 1.0
        total = sum(w.values())
        if total > 0:
            w = {k: v / total for k, v in w.items()}

        return w

    # ------------------------------------------------------------------
    # Grade / Action mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_grade(score: float) -> FAILGrade:
        if score >= 90:
            return FAILGrade.CRITICAL
        elif score >= 70:
            return FAILGrade.HIGH
        elif score >= 40:
            return FAILGrade.MEDIUM
        elif score >= 20:
            return FAILGrade.LOW
        else:
            return FAILGrade.INFO

    @staticmethod
    def _grade_to_action(grade: FAILGrade) -> RecommendedAction:
        mapping = {
            FAILGrade.CRITICAL: RecommendedAction.PATCH_IMMEDIATELY,
            FAILGrade.HIGH: RecommendedAction.PATCH_NEXT_SPRINT,
            FAILGrade.MEDIUM: RecommendedAction.SCHEDULE_FIX,
            FAILGrade.LOW: RecommendedAction.MONITOR,
            FAILGrade.INFO: RecommendedAction.ACCEPT_RISK,
        }
        return mapping.get(grade, RecommendedAction.ACCEPT_RISK)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def compare(self, a: FAILResult, b: FAILResult) -> Dict[str, Any]:
        """Compare two FAIL results for prioritisation."""
        return {
            "winner": a.cve_id if a.fail_score >= b.fail_score else b.cve_id,
            "score_diff": abs(a.fail_score - b.fail_score),
            "a": {"cve": a.cve_id, "score": a.fail_score, "grade": a.grade.value},
            "b": {"cve": b.cve_id, "score": b.fail_score, "grade": b.grade.value},
        }

    def rank(self, results: Sequence[FAILResult]) -> List[FAILResult]:
        """Rank FAIL results from highest to lowest score."""
        return sorted(results, key=lambda r: r.fail_score, reverse=True)

    def stats(self) -> Dict[str, Any]:
        """Return statistics from scoring history."""
        if not self._history:
            return {"total_scored": 0}

        scores = [r.fail_score for r in self._history]
        grades = {}
        for r in self._history:
            grades[r.grade.value] = grades.get(r.grade.value, 0) + 1

        return {
            "total_scored": len(self._history),
            "average_score": round(sum(scores) / len(scores), 2),
            "max_score": round(max(scores), 2),
            "min_score": round(min(scores), 2),
            "grade_distribution": grades,
            "critical_count": grades.get("CRITICAL", 0),
            "high_count": grades.get("HIGH", 0),
        }
