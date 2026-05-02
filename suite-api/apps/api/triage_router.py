"""
Unified Triage API — enrichment, analyst feedback, queue prioritization.

Returns EVERYTHING about a finding in one call: attack paths, compliance
impact, SLA deadlines, and self-learning confidence adjustments.  No
competitor offers this depth of single-call enrichment.

Graceful degradation: every optional dependency (knowledge graph,
compliance mapping, self-learning engine) is imported inside
try/except so the endpoint never fails — it simply returns less data
when a subsystem is unavailable.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency imports — the router MUST work without any of these.
# ---------------------------------------------------------------------------

# 1. Attack path engine (knowledge graph)
_HAS_ATTACK_PATH = False
_attack_path_engine = None
try:
    from core.attack_path_engine import AttackPathEngine, get_attack_path_engine

    _HAS_ATTACK_PATH = True
except ImportError:
    pass

# 2. Compliance mapping
_HAS_COMPLIANCE = False
_DEFAULT_CWE_MAPPINGS: Dict[str, Any] = {}
_ComplianceMappingResult: Any = None
try:
    from compliance.mapping import (
        DEFAULT_CWE_MAPPINGS as _DEFAULT_CWE_MAPPINGS,  # type: ignore[assignment]
    )
    from compliance.mapping import ComplianceMappingResult as _ComplianceMappingResult

    _HAS_COMPLIANCE = True
except ImportError:
    pass

# 3. Self-learning engine
_HAS_SELF_LEARNING = False
_SelfLearningEngine: Any = None
try:
    from core.self_learning import SelfLearningEngine as _SelfLearningEngine

    _HAS_SELF_LEARNING = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# SLA hours by severity (industry-standard targets)
SLA_HOURS: Dict[str, int] = {
    "critical": 24,
    "high": 72,
    "medium": 168,
    "low": 720,
    "info": 2160,
}

_VALID_SEVERITIES = frozenset(SLA_HOURS.keys())
_VALID_VERDICTS = frozenset({"accept", "reject", "escalate", "false_positive"})

# Input size limits
_MAX_FINDINGS_PER_REQUEST = 200
_MAX_TITLE_LEN = 1024
_MAX_REASON_LEN = 4096
_MAX_ID_LEN = 256
_MAX_CWE_IDS = 50
_MAX_SOURCE_LEN = 256
_MAX_ASSET_LEN = 512

# Database
_DB_DIR = os.getenv("FIXOPS_DATA_DIR", "data")
_DB_PATH = os.path.join(_DB_DIR, "analytics.db")

# ---------------------------------------------------------------------------
# Pydantic models — request / response
# ---------------------------------------------------------------------------


class TriageFindingInput(BaseModel):
    """A single finding to enrich."""

    finding_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN, description="Unique finding identifier")
    title: str = Field(..., min_length=1, max_length=_MAX_TITLE_LEN, description="Finding title")
    severity: str = Field(..., description="Severity: critical, high, medium, low, info")
    cve_id: Optional[str] = Field(None, max_length=64, description="CVE identifier (e.g. CVE-2024-1234)")
    cwe_ids: Optional[List[str]] = Field(default=None, description="CWE identifiers")
    asset_name: Optional[str] = Field(None, max_length=_MAX_ASSET_LEN, description="Affected asset")
    source: Optional[str] = Field(None, max_length=_MAX_SOURCE_LEN, description="Scanner source")
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0, description="Numeric risk score 0-100")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_VALID_SEVERITIES)}")
        return normalized

    @field_validator("cwe_ids")
    @classmethod
    def validate_cwe_ids(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None and len(v) > _MAX_CWE_IDS:
            raise ValueError(f"at most {_MAX_CWE_IDS} CWE IDs allowed")
        return v


class TriageEnrichRequest(BaseModel):
    """Request body for /enrich — single finding or batch."""

    findings: List[TriageFindingInput] = Field(
        ..., min_length=1, max_length=_MAX_FINDINGS_PER_REQUEST,
        description="One or more findings to enrich",
    )


class AttackPathSummary(BaseModel):
    """Summarized attack path information for a finding."""

    path_count: int = 0
    max_depth: int = 0
    internet_reachable: bool = False
    highest_score: float = 0.0
    paths: List[Dict[str, Any]] = Field(default_factory=list)


class ComplianceImpact(BaseModel):
    """Compliance framework impact for a finding."""

    frameworks_affected: List[str] = Field(default_factory=list)
    control_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_gaps: List[str] = Field(default_factory=list)


class TriageEnrichedFinding(BaseModel):
    """Enriched finding returned from /enrich."""

    finding: Dict[str, Any]
    attack_paths: AttackPathSummary
    compliance_impact: ComplianceImpact
    sla_deadline: str
    sla_hours_remaining: float
    confidence_adjustment: Optional[float] = None
    recommended_action: str
    enrichment_sources: List[str] = Field(default_factory=list)


class TriageEnrichResponse(BaseModel):
    """Response for /enrich."""

    enriched: List[TriageEnrichedFinding]
    total: int
    enrichment_available: Dict[str, bool]
    timestamp: str


class TriageFeedbackRequest(BaseModel):
    """Analyst feedback on a triaged finding."""

    finding_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN)
    analyst_verdict: str = Field(..., description="accept, reject, escalate, or false_positive")
    reason: Optional[str] = Field(None, max_length=_MAX_REASON_LEN)
    analyst_id: Optional[str] = Field(None, max_length=_MAX_ID_LEN)

    @field_validator("analyst_verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in _VALID_VERDICTS:
            raise ValueError(f"analyst_verdict must be one of {sorted(_VALID_VERDICTS)}")
        return normalized


class TriageFeedbackResponse(BaseModel):
    """Response after recording analyst feedback."""

    feedback_id: str
    finding_id: str
    verdict: str
    recorded_at: str
    confidence_updated: bool = False
    updated_confidence: Optional[float] = None


class TriageQueueItem(BaseModel):
    """A single item in the smart triage queue."""

    finding_id: str
    title: str
    severity: str
    priority_score: float
    sla_deadline: str
    sla_urgency: float
    attack_path_count: int = 0
    bucket: str  # requires_immediate_action, high_priority, standard, can_wait


class TriageQueueResponse(BaseModel):
    """Response for /queue."""

    queue: List[TriageQueueItem]
    total: int
    buckets: Dict[str, int]
    timestamp: str


class TriageStatsResponse(BaseModel):
    """Response for /stats."""

    total_triaged: int
    analyst_agreement_rate: float
    average_triage_time_hours: Optional[float]
    false_positive_rate: float
    verdict_breakdown: Dict[str, int]
    trending: Dict[str, Any]
    timestamp: str


# ---------------------------------------------------------------------------
# Database helpers — triage_feedback table
# ---------------------------------------------------------------------------

_db_lock = threading.Lock()


def _get_db() -> sqlite3.Connection:
    """Return a connection to analytics.db with triage tables created."""
    os.makedirs(os.path.dirname(_DB_PATH) if os.path.dirname(_DB_PATH) else ".", exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS triage_feedback (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            analyst_verdict TEXT NOT NULL,
            reason TEXT,
            analyst_id TEXT,
            recorded_at TEXT NOT NULL,
            ai_confidence REAL,
            ai_recommended_action TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_triage_fb_finding
            ON triage_feedback(finding_id);
        CREATE INDEX IF NOT EXISTS idx_triage_fb_recorded
            ON triage_feedback(recorded_at);
    """)
    return conn


# ---------------------------------------------------------------------------
# Enrichment helpers
# ---------------------------------------------------------------------------


def _enrich_attack_paths(finding: TriageFindingInput) -> Tuple[AttackPathSummary, bool]:
    """Query the knowledge graph for attack paths related to this finding.

    Returns (summary, was_available).
    """
    if not _HAS_ATTACK_PATH:
        return AttackPathSummary(), False

    try:
        engine = get_attack_path_engine()
        if engine is None:
            return AttackPathSummary(), False

        # Use CVE ID or finding ID as graph node identifier
        node_id = finding.cve_id or finding.finding_id
        chains = engine.discover_attack_paths(
            entry_point=None,
            target=node_id,
            max_depth=8,
            max_paths=5,
        )

        if not chains:
            return AttackPathSummary(path_count=0), True

        # Summarize paths
        path_dicts: List[Dict[str, Any]] = []
        max_depth = 0
        highest_score = 0.0
        internet_reachable = False

        for chain in chains:
            score = getattr(chain, "score", None)
            total_score = getattr(score, "total_score", 0.0) if score else 0.0
            depth = getattr(chain, "depth", 0) if hasattr(chain, "depth") else len(getattr(chain, "steps", []))
            is_internet = getattr(chain, "internet_reachable", False)

            if total_score > highest_score:
                highest_score = total_score
            if depth > max_depth:
                max_depth = depth
            if is_internet:
                internet_reachable = True

            path_dicts.append({
                "id": getattr(chain, "chain_id", str(uuid.uuid4())),
                "score": round(total_score, 2),
                "depth": depth,
                "internet_reachable": is_internet,
            })

        return AttackPathSummary(
            path_count=len(path_dicts),
            max_depth=max_depth,
            internet_reachable=internet_reachable,
            highest_score=round(highest_score, 2),
            paths=path_dicts,
        ), True

    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError, OSError) as exc:
        logger.warning("Attack path enrichment unavailable: %s", type(exc).__name__)
        return AttackPathSummary(), False


def _enrich_compliance(finding: TriageFindingInput) -> Tuple[ComplianceImpact, bool]:
    """Map CWE IDs to compliance frameworks.

    Returns (impact, was_available).
    """
    if not _HAS_COMPLIANCE or not _DEFAULT_CWE_MAPPINGS:
        # Provide a built-in minimal mapping if the compliance module is absent
        return _fallback_compliance(finding), False

    try:
        cwe_ids = finding.cwe_ids or []
        if not cwe_ids:
            return ComplianceImpact(), True

        frameworks: set = set()
        mappings: List[Dict[str, Any]] = []
        gaps: List[str] = []

        for cwe_id in cwe_ids:
            normalized_cwe = cwe_id.upper()
            if not normalized_cwe.startswith("CWE-"):
                normalized_cwe = f"CWE-{normalized_cwe}"

            ctrl = _DEFAULT_CWE_MAPPINGS.get(normalized_cwe)
            if ctrl is None:
                gaps.append(f"No mapping for {normalized_cwe}")
                continue

            mapping_dict = ctrl.to_dict() if hasattr(ctrl, "to_dict") else dict(ctrl)
            mappings.append(mapping_dict)

            # Collect affected frameworks
            if mapping_dict.get("nist_800_53"):
                frameworks.add("NIST 800-53")
            if mapping_dict.get("nist_ssdf"):
                frameworks.add("NIST SSDF")
            if mapping_dict.get("pci_dss"):
                frameworks.add("PCI DSS")
            if mapping_dict.get("iso_27001"):
                frameworks.add("ISO 27001")
            if mapping_dict.get("owasp_category"):
                frameworks.add("OWASP Top 10")

        return ComplianceImpact(
            frameworks_affected=sorted(frameworks),
            control_mappings=mappings,
            compliance_gaps=gaps,
        ), True

    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        logger.warning("Compliance enrichment error: %s", type(exc).__name__)
        return _fallback_compliance(finding), False


def _fallback_compliance(finding: TriageFindingInput) -> ComplianceImpact:
    """Built-in minimal compliance mapping when the compliance module is absent."""
    # Provide basic framework indication based on severity alone so the
    # response is always useful even without the full compliance engine.
    if finding.severity in ("critical", "high"):
        return ComplianceImpact(
            frameworks_affected=["NIST 800-53", "PCI DSS", "OWASP Top 10"],
            control_mappings=[],
            compliance_gaps=["Full compliance mapping unavailable — install compliance module"],
        )
    return ComplianceImpact(
        frameworks_affected=[],
        control_mappings=[],
        compliance_gaps=["Full compliance mapping unavailable — install compliance module"],
    )


def _compute_sla_deadline(severity: str) -> Tuple[str, float]:
    """Compute the SLA deadline ISO string and remaining hours.

    Returns (deadline_iso, hours_remaining).
    """
    now = datetime.now(timezone.utc)
    hours = SLA_HOURS.get(severity, 168)
    deadline = now + timedelta(hours=hours)
    return deadline.isoformat(), float(hours)


def _compute_sla_urgency(severity: str) -> float:
    """Return urgency multiplier: higher for tighter SLAs."""
    hours = SLA_HOURS.get(severity, 168)
    if hours <= 24:
        return 1.0
    if hours <= 72:
        return 0.7
    if hours <= 168:
        return 0.4
    return 0.1


def _enrich_self_learning(finding: TriageFindingInput) -> Tuple[Optional[float], bool]:
    """Get confidence adjustment from the self-learning engine.

    Returns (adjustment_value_or_None, was_available).
    """
    if not _HAS_SELF_LEARNING or _SelfLearningEngine is None:
        return None, False

    try:
        engine = _SelfLearningEngine()
        analysis = engine.fp_loop.analyze(days=90)
        fp_rate = analysis.get("overall_fp_rate", 0)

        # Adjust confidence based on scanner false-positive rate
        source = finding.source or "unknown"
        by_scanner = analysis.get("by_scanner", {})
        scanner_data = by_scanner.get(source, {})
        scanner_fp = scanner_data.get("fp", 0)
        scanner_total = scanner_fp + scanner_data.get("tp", 0)

        if scanner_total > 0:
            scanner_fp_rate = scanner_fp / scanner_total
            # Negative adjustment = lower confidence if scanner has high FP rate
            adjustment = -round(scanner_fp_rate * 0.3, 3)
        else:
            # Not enough data — slight negative for unknown scanners
            adjustment = -round(fp_rate * 0.1, 3) if fp_rate > 0 else 0.0

        return adjustment, True

    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        logger.warning("Self-learning enrichment unavailable: %s", type(exc).__name__)
        return None, False


def _recommended_action(finding: TriageFindingInput, attack_paths: AttackPathSummary) -> str:
    """Determine recommended action based on enrichment data."""
    sev = finding.severity

    # Internet-reachable critical/high findings require immediate action
    if attack_paths.internet_reachable and sev in ("critical", "high"):
        return "fix_immediately"

    # Multiple attack paths amplify urgency
    if attack_paths.path_count >= 3 and sev in ("critical", "high", "medium"):
        return "fix_immediately"

    # Standard severity-based recommendation
    action_map = {
        "critical": "fix_immediately",
        "high": "fix_in_sprint",
        "medium": "schedule_fix",
        "low": "backlog",
        "info": "accept_risk",
    }
    return action_map.get(sev, "schedule_fix")


def _priority_bucket(score: float, severity: str) -> str:
    """Assign a finding to a priority bucket."""
    if severity == "critical" or score >= 80:
        return "requires_immediate_action"
    if severity == "high" or score >= 50:
        return "high_priority"
    if severity == "medium" or score >= 20:
        return "standard"
    return "can_wait"


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/triage", tags=["triage"])


@router.get("/health")
async def triage_health() -> Dict[str, Any]:
    """Health check for triage subsystem."""
    return await triage_status()


@router.get("/status")
async def triage_status() -> Dict[str, Any]:
    """Status of the triage enrichment subsystem."""
    return {
        "status": "ok",
        "engine": "triage-enrichment",
        "version": "1.0.0",
        "subsystems": {
            "attack_paths": _HAS_ATTACK_PATH,
            "compliance_mapping": _HAS_COMPLIANCE,
            "self_learning": _HAS_SELF_LEARNING,
        },
        "sla_targets": SLA_HOURS,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# POST /enrich — the crown jewel
# ---------------------------------------------------------------------------


@router.post("/enrich", response_model=TriageEnrichResponse)
async def enrich_findings(
    body: TriageEnrichRequest,
    org_id: str = Depends(get_org_id),
) -> TriageEnrichResponse:
    """Enrich one or more findings with attack paths, compliance impact,
    SLA deadlines, and self-learning confidence adjustments.

    This is the unified triage endpoint: one call, everything you need to
    make a triage decision.  Subsystems that are unavailable are gracefully
    skipped and indicated in ``enrichment_available``.
    """
    enriched: List[TriageEnrichedFinding] = []

    for finding in body.findings:
        # 1. Attack paths
        ap_summary, ap_available = _enrich_attack_paths(finding)

        # 2. Compliance impact
        comp_impact, comp_available = _enrich_compliance(finding)

        # 3. SLA deadline
        sla_iso, sla_hours = _compute_sla_deadline(finding.severity)

        # 4. Self-learning confidence
        confidence_adj, sl_available = _enrich_self_learning(finding)

        # 5. Recommended action
        action = _recommended_action(finding, ap_summary)

        # Track which enrichment sources contributed
        sources: List[str] = ["sla"]
        if ap_available:
            sources.append("attack_paths")
        if comp_available:
            sources.append("compliance")
        if sl_available:
            sources.append("self_learning")

        enriched.append(
            TriageEnrichedFinding(
                finding=finding.model_dump(),
                attack_paths=ap_summary,
                compliance_impact=comp_impact,
                sla_deadline=sla_iso,
                sla_hours_remaining=sla_hours,
                confidence_adjustment=confidence_adj,
                recommended_action=action,
                enrichment_sources=sources,
            )
        )

    return TriageEnrichResponse(
        enriched=enriched,
        total=len(enriched),
        enrichment_available={
            "attack_paths": _HAS_ATTACK_PATH,
            "compliance_mapping": _HAS_COMPLIANCE,
            "self_learning": _HAS_SELF_LEARNING,
            "sla": True,  # always available
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# POST /feedback — analyst feedback loop
# ---------------------------------------------------------------------------


@router.post("/feedback", response_model=TriageFeedbackResponse)
async def submit_feedback(
    body: TriageFeedbackRequest,
    org_id: str = Depends(get_org_id),
) -> TriageFeedbackResponse:
    """Record analyst feedback on a triaged finding.

    Stores verdict in ``triage_feedback`` table and, if the self-learning
    engine is available, records a decision-outcome feedback event so the
    platform learns from analyst corrections over time.
    """
    now = datetime.now(timezone.utc)
    feedback_id = f"tf-{uuid.uuid4().hex[:16]}"

    # Persist to database
    with _db_lock:
        conn = _get_db()
        try:
            conn.execute(
                """
                INSERT INTO triage_feedback
                    (id, finding_id, analyst_verdict, reason, analyst_id, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    feedback_id,
                    body.finding_id,
                    body.analyst_verdict,
                    body.reason,
                    body.analyst_id,
                    now.isoformat(),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409,
                detail="Duplicate feedback ID — please retry",
            )
        finally:
            conn.close()

    # If self-learning engine available, record the decision outcome
    confidence_updated = False
    updated_confidence: Optional[float] = None

    if _HAS_SELF_LEARNING and _SelfLearningEngine is not None:
        try:
            engine = _SelfLearningEngine()
            # Map analyst verdict to predicted vs actual for learning loop
            predicted_action = "FIX"  # AI default recommendation
            actual_map = {
                "accept": "FIX",
                "reject": "ACCEPT_RISK",
                "escalate": "ESCALATE",
                "false_positive": "FALSE_POSITIVE",
            }
            actual_outcome = actual_map.get(body.analyst_verdict, "FIX")

            engine.decision_loop.record(
                decision_id=feedback_id,
                finding_id=body.finding_id,
                predicted_action=predicted_action,
                actual_outcome=actual_outcome,
                confidence=0.5,
                context={
                    "analyst_id": body.analyst_id or "unknown",
                    "reason": (body.reason or "")[:500],  # truncate for storage
                    "source": "triage_feedback",
                },
            )

            # Re-analyze to get updated accuracy
            analysis = engine.decision_loop.analyze(days=30)
            updated_confidence = analysis.get("weighted_accuracy")
            if updated_confidence is not None:
                updated_confidence = round(updated_confidence, 4)
                confidence_updated = True

        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError, OSError) as exc:
            logger.warning("Self-learning feedback recording failed: %s", type(exc).__name__)

    return TriageFeedbackResponse(
        feedback_id=feedback_id,
        finding_id=body.finding_id,
        verdict=body.analyst_verdict,
        recorded_at=now.isoformat(),
        confidence_updated=confidence_updated,
        updated_confidence=updated_confidence,
    )


# ---------------------------------------------------------------------------
# GET /stats — triage performance metrics
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=TriageStatsResponse)
async def triage_stats(
    org_id: str = Depends(get_org_id),
    days: int = Query(30, ge=1, le=365),
) -> TriageStatsResponse:
    """Triage performance statistics.

    Returns analyst agreement rate, false-positive trending, and verdict
    breakdown computed from the ``triage_feedback`` table.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    with _db_lock:
        conn = _get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM triage_feedback WHERE recorded_at >= ? ORDER BY recorded_at DESC",
                (cutoff,),
            ).fetchall()
        finally:
            conn.close()

    total_triaged = len(rows)

    # Verdict breakdown
    verdict_counts: Dict[str, int] = defaultdict(int)
    for row in rows:
        verdict_counts[row["analyst_verdict"]] += 1

    # False positive rate
    fp_count = verdict_counts.get("false_positive", 0)
    fp_rate = round(fp_count / max(total_triaged, 1) * 100, 2)

    # Analyst agreement rate: percentage of "accept" verdicts (AI was correct)
    accept_count = verdict_counts.get("accept", 0)
    agreement_rate = round(accept_count / max(total_triaged, 1) * 100, 2)

    # Average triage time (time between consecutive feedbacks — proxy metric)
    avg_triage_hours: Optional[float] = None
    if total_triaged >= 2:
        timestamps = []
        for row in rows:
            try:
                ts = datetime.fromisoformat(row["recorded_at"])
                timestamps.append(ts)
            except (ValueError, TypeError):
                continue
        if len(timestamps) >= 2:
            timestamps.sort()
            deltas = [
                (timestamps[i + 1] - timestamps[i]).total_seconds() / 3600
                for i in range(len(timestamps) - 1)
            ]
            avg_triage_hours = round(sum(deltas) / len(deltas), 2)

    # Trending: compare current half of period to previous half
    midpoint = (datetime.now(timezone.utc) - timedelta(days=days / 2)).isoformat()
    recent_fp = sum(1 for r in rows if r["analyst_verdict"] == "false_positive" and r["recorded_at"] >= midpoint)
    older_fp = fp_count - recent_fp
    recent_total = sum(1 for r in rows if r["recorded_at"] >= midpoint)
    older_total = total_triaged - recent_total

    trending = {
        "recent_period_fp_rate": round(recent_fp / max(recent_total, 1) * 100, 2),
        "older_period_fp_rate": round(older_fp / max(older_total, 1) * 100, 2),
        "direction": (
            "improving"
            if (recent_fp / max(recent_total, 1)) < (older_fp / max(older_total, 1))
            else "worsening"
            if (recent_fp / max(recent_total, 1)) > (older_fp / max(older_total, 1))
            else "stable"
        ),
    }

    return TriageStatsResponse(
        total_triaged=total_triaged,
        analyst_agreement_rate=agreement_rate,
        average_triage_time_hours=avg_triage_hours,
        false_positive_rate=fp_rate,
        verdict_breakdown=dict(verdict_counts),
        trending=trending,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# GET /queue — smart triage queue
# ---------------------------------------------------------------------------


@router.get("/queue", response_model=TriageQueueResponse)
async def triage_queue(
    org_id: str = Depends(get_org_id),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    include_demo: bool = Query(False, description="Include demo/seeded findings"),
) -> TriageQueueResponse:
    """Smart triage queue.

    Returns untriaged findings ordered by a composite priority score:
        ``risk_score * (1 + sla_urgency) * (1 + attack_path_count * 0.1)``

    Findings that already have analyst feedback are excluded.  Results
    are bucketed into four groups: ``requires_immediate_action``,
    ``high_priority``, ``standard``, and ``can_wait``.

    By default, pre-seeded demo findings are excluded. Pass
    ``include_demo=true`` to show them.
    """
    # Load already-triaged finding IDs
    triaged_ids: set = set()
    with _db_lock:
        conn = _get_db()
        try:
            rows = conn.execute("SELECT DISTINCT finding_id FROM triage_feedback").fetchall()
            triaged_ids = {r["finding_id"] for r in rows}
        finally:
            conn.close()

    # Load findings from analytics DB
    try:
        from core.analytics_db import AnalyticsDB

        db = AnalyticsDB()
        all_findings = db.list_findings(limit=10000)
    except ImportError:
        all_findings = []

    # Filter out already-triaged
    untriaged = [f for f in all_findings if f.id not in triaged_ids]

    # Filter out demo/seeded findings unless explicitly requested
    if not include_demo:
        def _is_seeded(f) -> bool:
            meta = getattr(f, "metadata", None)
            if isinstance(meta, dict):
                return meta.get("seeded", False) is True
            return False
        untriaged = [f for f in untriaged if not _is_seeded(f)]

    # Score and rank
    queue_items: List[TriageQueueItem] = []
    for f in untriaged:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_lower = sev.lower()

        # Base risk score
        risk_score = getattr(f, "risk_score", None)
        if risk_score is None:
            severity_scores = {"critical": 95, "high": 75, "medium": 50, "low": 25, "info": 5}
            risk_score = severity_scores.get(sev_lower, 50)

        sla_urgency = _compute_sla_urgency(sev_lower)
        sla_iso, _hours = _compute_sla_deadline(sev_lower)

        # Attack path count (expensive — only if engine available)
        ap_count = 0
        if _HAS_ATTACK_PATH:
            try:
                engine = get_attack_path_engine()
                if engine is not None:
                    node_id = getattr(f, "cve_id", None) or f.id
                    paths = engine.discover_attack_paths(target=node_id, max_paths=5)
                    ap_count = len(paths)
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError, OSError):
                pass

        # Composite score
        priority_score = round(
            risk_score * (1 + sla_urgency) * (1 + ap_count * 0.1),
            2,
        )

        bucket = _priority_bucket(priority_score, sev_lower)

        queue_items.append(
            TriageQueueItem(
                finding_id=f.id,
                title=getattr(f, "title", "Unknown"),
                severity=sev_lower,
                priority_score=priority_score,
                sla_deadline=sla_iso,
                sla_urgency=sla_urgency,
                attack_path_count=ap_count,
                bucket=bucket,
            )
        )

    # Sort descending by priority score
    queue_items.sort(key=lambda x: x.priority_score, reverse=True)

    # Paginate
    paginated = queue_items[offset : offset + limit]

    # Bucket counts (over ALL untriaged, not just the page)
    bucket_counts: Dict[str, int] = defaultdict(int)
    for item in queue_items:
        bucket_counts[item.bucket] += 1

    return TriageQueueResponse(
        queue=paginated,
        total=len(queue_items),
        buckets=dict(bucket_counts),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
