"""
FixOps FAIL Engine API Router — /api/v1/fail/*
suite-attack edition

Exposes the Fault & Attack Injection Layer (FAIL Engine) via REST API.
This is the chaos engineering system for security teams — inject synthetic
vulnerabilities, measure team response, grade performance, detect neglect zones.

Endpoints:
    POST   /api/v1/fail/inject              — Inject synthetic vulnerability (create drill)
    GET    /api/v1/fail/drills              — List active / historical drills
    GET    /api/v1/fail/drills/{id}         — Drill detail with timeline and score
    POST   /api/v1/fail/drills/{id}/detect  — Mark finding as detected
    POST   /api/v1/fail/drills/{id}/triage  — Mark finding as triaged
    POST   /api/v1/fail/drills/{id}/remediate — Mark finding as remediated
    POST   /api/v1/fail/drills/{id}/grade   — Grade team response
    DELETE /api/v1/fail/drills/{id}         — Cancel active drill
    GET    /api/v1/fail/neglect-zones       — Components with no recent security activity
    GET    /api/v1/fail/readiness-score     — Organisation readiness score
    GET    /api/v1/fail/comparison          — Industry benchmark comparison
    GET    /api/v1/fail/scenarios           — List available injection scenarios
    POST   /api/v1/fail/scenarios           — Create custom scenario
    GET    /api/v1/fail/training-data       — Export labeled training samples
    POST   /api/v1/fail/activity            — Log security activity (for neglect tracking)
    GET    /api/v1/fail/health              — Health check
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from attack.fail_engine import (
    DrillEngine,
    get_drill_engine,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/fail", tags=["fail-engine"])

# Module-level engine singleton
_engine: Optional[DrillEngine] = None


def _get_engine() -> DrillEngine:
    global _engine
    if _engine is None:
        _engine = get_drill_engine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class InjectRequest(BaseModel):
    """Request to inject a synthetic vulnerability (create a drill)."""

    scenario: str = Field(
        ...,
        description=(
            "Scenario ID to inject. One of: log4shell, sqli, ssrf, path_traversal, "
            "insecure_deserialization, hardcoded_credentials, broken_auth, xss, "
            "crypto_weakness, supply_chain — or a custom scenario ID."
        ),
        examples=["log4shell"],
    )
    target_component: str = Field(
        ...,
        description="The component / service to target with the synthetic finding",
        examples=["auth-service"],
    )
    org_id: str = Field(
        ...,
        description="Organisation identifier",
        examples=["org-acme-prod"],
    )
    notes: str = Field(
        "",
        description="Optional notes for this drill (not visible to the team being tested)",
    )
    injected_by: Optional[str] = Field(
        None,
        description="Identifier of the person / system injecting the drill",
    )


class InjectResponse(BaseModel):
    """Response after injecting a synthetic vulnerability."""

    drill_id: str
    scenario_id: str
    scenario_name: str
    target_component: str
    org_id: str
    status: str
    severity: str
    synthetic_finding_id: str
    injected_at: Optional[str] = None
    expires_at: str
    message: str


class DetectRequest(BaseModel):
    """Request to mark a drill finding as detected."""

    detected_by: Optional[str] = Field(None, description="Who detected the finding")
    detection_note: str = Field("", description="Notes about the detection")


class TriageRequest(BaseModel):
    """Request to mark a drill finding as triaged."""

    classification: str = Field(
        ...,
        description=(
            "Triage classification. One of: real_critical, real_high, real_medium, "
            "real_low, false_positive, synthetic, wont_fix"
        ),
        examples=["real_critical"],
    )
    triaged_by: Optional[str] = Field(None, description="Who performed triage")
    escalated: bool = Field(False, description="Was the finding escalated?")
    notified_teams: List[str] = Field(
        default_factory=list,
        description="Teams notified during triage",
    )
    triage_note: str = Field("", description="Notes from triage")


class RemediateRequest(BaseModel):
    """Request to mark a drill finding as remediated."""

    remediated_by: Optional[str] = Field(None, description="Who remediated the finding")
    remediation_note: str = Field("", description="Notes about remediation")


class GradeRequest(BaseModel):
    """
    Request to grade a drill's team response.

    Override fields allow manual override of auto-computed timings
    (e.g. when detection was reported verbally before the system was updated).
    """

    override_detection_minutes: Optional[int] = Field(
        None,
        ge=0,
        description="Override auto-computed detection time (minutes from injection)",
    )
    override_remediation_minutes: Optional[int] = Field(
        None,
        ge=0,
        description="Override auto-computed remediation time (minutes from injection)",
    )


class GradeResponse(BaseModel):
    """Drill score response."""

    drill_id: str
    detection_speed: float
    triage_accuracy: float
    remediation_speed: float
    communication: float
    overall: float
    grade: str
    detection_minutes_actual: Optional[int] = None
    detection_minutes_target: Optional[int] = None
    triage_classification_actual: Optional[str] = None
    triage_classification_expected: Optional[str] = None
    remediation_minutes_actual: Optional[int] = None
    escalated_correctly: bool
    team_notified: bool
    feedback: List[str]


class CreateScenarioRequest(BaseModel):
    """Request to create a custom injection scenario."""

    scenario_id: str = Field(
        ...,
        description="Unique identifier for the scenario (snake_case)",
        examples=["custom_log4j_variant"],
    )
    name: str = Field(..., description="Human-readable scenario name")
    description: str = Field(..., description="Scenario description")
    severity: str = Field(
        "high",
        description="Severity level: critical, high, medium, low, info",
    )
    synthetic_finding: Dict[str, Any] = Field(
        ...,
        description="The synthetic finding payload to inject",
    )
    cwe_ids: List[str] = Field(default_factory=list, description="CWE identifiers")
    mitre_techniques: List[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs"
    )
    mitre_tactics: List[str] = Field(
        default_factory=list, description="MITRE ATT&CK tactics"
    )
    expected_detection_minutes: int = Field(
        60, ge=1, description="Target detection time in minutes"
    )
    expected_triage_classification: str = Field(
        "real_high",
        description="Expected triage classification for scoring",
    )
    expected_remediation_approach: str = Field(
        "", description="Guidance on the expected fix"
    )
    cvss_score: float = Field(7.0, ge=0.0, le=10.0, description="CVSS base score")
    cve_id: Optional[str] = Field(None, description="Associated CVE identifier")
    tags: List[str] = Field(default_factory=list, description="Searchable tags")


class LogActivityRequest(BaseModel):
    """Request to log a security activity for neglect zone tracking."""

    org_id: str = Field(..., description="Organisation identifier")
    component: str = Field(..., description="Component / service name")
    activity_type: str = Field(
        ...,
        description="Type of activity: scan, review, drill, pentest, audit",
        examples=["scan"],
    )
    description: str = Field("", description="Activity description")
    actor: Optional[str] = Field(None, description="Who performed the activity")
    has_critical_data: bool = Field(
        False, description="Does this component hold critical data?"
    )


# ---------------------------------------------------------------------------
# Endpoint: Inject synthetic vulnerability
# ---------------------------------------------------------------------------


@router.post(
    "/inject",
    summary="Inject a synthetic vulnerability (create drill)",
    response_description="Created drill with injection metadata",
)
async def inject_vulnerability(req: InjectRequest, org_id: str = Depends(get_org_id)) -> InjectResponse:
    """
    Inject a synthetic vulnerability finding into the FixOps pipeline.

    This creates a FAIL Engine drill — the synthetic finding will appear
    in the normal finding feed for the target component, indistinguishable
    from a real finding. The clock starts ticking from injection time.

    Available scenarios: log4shell, sqli, ssrf, path_traversal,
    insecure_deserialization, hardcoded_credentials, broken_auth, xss,
    crypto_weakness, supply_chain.
    """
    try:
        engine = _get_engine()
        drill = engine.create_drill(
            scenario=req.scenario,
            target_component=req.target_component,
            org_id=org_id,
            notes=req.notes,
            injected_by=req.injected_by,
        )
        return InjectResponse(
            drill_id=drill.drill_id,
            scenario_id=drill.scenario_id,
            scenario_name=drill.scenario_name,
            target_component=drill.target_component,
            org_id=drill.org_id,
            status=drill.status.value,
            severity=drill.severity.value,
            synthetic_finding_id=drill.synthetic_finding_id,
            injected_at=drill.timeline.injected_at,
            expires_at=drill.expires_at,
            message=(
                f"Synthetic {drill.scenario_name} finding injected into "
                f"'{drill.target_component}'. Drill ID: {drill.drill_id}. "
                "Clock is running."
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Failed to inject FAIL drill: %s", exc)
        raise HTTPException(status_code=500, detail=f"Injection failed: {type(exc).__name__}")


# ---------------------------------------------------------------------------
# Endpoint: List drills
# ---------------------------------------------------------------------------


@router.get(
    "/drills",
    summary="List active / historical drills",
)
async def list_drills(
    org_id: str = Depends(get_org_id),
    history: bool = Query(False, description="Include historical (graded/cancelled) drills"),
    days: int = Query(90, ge=1, le=365, description="Days of history to include"),
) -> Dict[str, Any]:
    """
    List drills for an organisation.

    By default returns only active drills (pending, active, detected, triaged,
    remediated). Set history=true to include graded and cancelled drills.
    """
    engine = _get_engine()
    if history:
        drills = engine.get_drill_history(org_id=org_id, days=days)
    else:
        drills = engine.get_active_drills(org_id=org_id)

    return {
        "org_id": org_id,
        "total": len(drills),
        "drills": drills,
        "history_mode": history,
    }


# ---------------------------------------------------------------------------
# Endpoint: Drill detail
# ---------------------------------------------------------------------------


@router.get(
    "/drills/{drill_id}",
    summary="Drill detail with timeline and score",
)
async def get_drill(drill_id: str) -> Dict[str, Any]:
    """
    Get full detail for a drill including timeline events and score breakdown.
    """
    engine = _get_engine()
    drill = engine.get_drill(drill_id)
    if not drill:
        raise HTTPException(status_code=404, detail=f"Drill {drill_id} not found")
    return drill


# ---------------------------------------------------------------------------
# Endpoints: Drill lifecycle progression
# ---------------------------------------------------------------------------


@router.post(
    "/drills/{drill_id}/detect",
    summary="Mark drill finding as detected",
)
async def mark_detected(drill_id: str, req: DetectRequest) -> Dict[str, Any]:
    """
    Signal that the synthetic finding was detected by the security team.
    This records the detection timestamp and starts the triage clock.
    """
    try:
        engine = _get_engine()
        return engine.mark_detected(
            drill_id=drill_id,
            detected_by=req.detected_by,
            detection_note=req.detection_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("mark_detected failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


@router.post(
    "/drills/{drill_id}/triage",
    summary="Mark drill finding as triaged",
)
async def mark_triaged(drill_id: str, req: TriageRequest) -> Dict[str, Any]:
    """
    Record the triage outcome: classification, escalation, and teams notified.
    This is used by the scorer to assess triage accuracy and communication quality.
    """
    try:
        engine = _get_engine()
        return engine.mark_triaged(
            drill_id=drill_id,
            classification=req.classification,
            triaged_by=req.triaged_by,
            escalated=req.escalated,
            notified_teams=req.notified_teams,
            triage_note=req.triage_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("mark_triaged failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


@router.post(
    "/drills/{drill_id}/remediate",
    summary="Mark drill finding as remediated",
)
async def mark_remediated(drill_id: str, req: RemediateRequest) -> Dict[str, Any]:
    """
    Signal that the synthetic finding was remediated.
    This records the remediation timestamp for speed scoring.
    """
    try:
        engine = _get_engine()
        return engine.mark_remediated(
            drill_id=drill_id,
            remediated_by=req.remediated_by,
            remediation_note=req.remediation_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("mark_remediated failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


# ---------------------------------------------------------------------------
# Endpoint: Grade drill
# ---------------------------------------------------------------------------


@router.post(
    "/drills/{drill_id}/grade",
    summary="Grade team response to a drill",
    response_model=GradeResponse,
)
async def grade_drill(drill_id: str, req: GradeRequest) -> GradeResponse:
    """
    Compute and persist the 4-dimension drill score.

    Scoring dimensions:
    - **Detection Speed** (30%) — How fast was the synthetic finding noticed?
    - **Triage Accuracy** (25%) — Was it correctly classified as critical/real?
    - **Remediation Speed** (30%) — How fast was the fix applied?
    - **Communication** (15%) — Was the right team notified? Escalation followed?

    Overall = weighted average of all four dimensions (0-10 scale).
    """
    try:
        engine = _get_engine()
        score = engine.grade_drill(
            drill_id=drill_id,
            override_detection_minutes=req.override_detection_minutes,
            override_remediation_minutes=req.override_remediation_minutes,
        )
        return GradeResponse(
            drill_id=score.drill_id,
            detection_speed=score.detection_speed,
            triage_accuracy=score.triage_accuracy,
            remediation_speed=score.remediation_speed,
            communication=score.communication,
            overall=score.overall,
            grade=score.grade,
            detection_minutes_actual=score.detection_minutes_actual,
            detection_minutes_target=score.detection_minutes_target,
            triage_classification_actual=score.triage_classification_actual,
            triage_classification_expected=score.triage_classification_expected,
            remediation_minutes_actual=score.remediation_minutes_actual,
            escalated_correctly=score.escalated_correctly,
            team_notified=score.team_notified,
            feedback=score.feedback,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("grade_drill failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Grading failed: {type(exc).__name__}")


# ---------------------------------------------------------------------------
# Endpoint: Cancel drill
# ---------------------------------------------------------------------------


@router.delete(
    "/drills/{drill_id}",
    summary="Cancel an active drill",
)
async def cancel_drill(
    drill_id: str,
    cancelled_by: Optional[str] = Query(None, description="Who is cancelling the drill"),
    reason: str = Query("", description="Reason for cancellation"),
) -> Dict[str, Any]:
    """
    Cancel an active drill without grading it.

    The drill will be marked as cancelled and removed from the active list.
    Cancelled drills are excluded from readiness scoring.
    """
    try:
        engine = _get_engine()
        return engine.cancel_drill(
            drill_id=drill_id,
            cancelled_by=cancelled_by,
            reason=reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("cancel_drill failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


# ---------------------------------------------------------------------------
# Endpoint: Neglect zones
# ---------------------------------------------------------------------------


@router.get(
    "/neglect-zones",
    summary="Components with no recent security activity",
)
async def get_neglect_zones(
    org_id: str = Depends(get_org_id),
    threshold_days: int = Query(
        90, ge=1, le=365, description="Days of inactivity to flag as neglected"
    ),
) -> Dict[str, Any]:
    """
    Return all components that have had no security activity (scan, review, drill)
    within the threshold period.

    Risk amplification rules:
    - Component inactive 90+ days → flagged
    - Component inactive + holds critical data → **urgent**
    - Each neglect zone includes a suggested drill scenario

    Use this to proactively target under-tested components for FAIL drills.
    """
    engine = _get_engine()
    zones = engine.get_neglect_zones(org_id=org_id, threshold_days=threshold_days)
    urgent = [z for z in zones if z.risk_level == "urgent"]
    high = [z for z in zones if z.risk_level == "high"]

    return {
        "org_id": org_id,
        "threshold_days": threshold_days,
        "total_neglect_zones": len(zones),
        "urgent_count": len(urgent),
        "high_risk_count": len(high),
        "neglect_zones": [z.to_dict() for z in zones],
        "recommendation": (
            f"Found {len(zones)} neglected components. "
            + (f"{len(urgent)} are URGENT (critical data + no activity). " if urgent else "")
            + "Consider scheduling FAIL drills for the top-risk zones."
        ),
    }


# ---------------------------------------------------------------------------
# Endpoint: Readiness score
# ---------------------------------------------------------------------------


@router.get(
    "/readiness-score",
    summary="Organisation readiness score",
)
@router.get(
    "/readiness",
    summary="Organisation readiness score (alias)",
    include_in_schema=False,
)
async def get_readiness_score(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Compute the organisation's security readiness score based on drill history.

    Readiness = rolling average of the last 10 graded drill scores.

    Returns:
    - Overall score (0-10)
    - Per-dimension averages (detection, triage, remediation, communication)
    - Per-team breakdown
    - Trend (improving / declining / stable)
    - Industry benchmark comparison
    - Percentile ranking
    """
    engine = _get_engine()
    readiness = engine.get_readiness_score(org_id=org_id)
    return readiness.to_dict()


# ---------------------------------------------------------------------------
# Endpoint: Industry benchmark comparison
# ---------------------------------------------------------------------------


@router.get(
    "/comparison",
    summary="Industry benchmark comparison",
)
async def get_comparison(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Compare organisation readiness score against the industry benchmark.

    The default benchmark is 6.5/10 (configurable at engine init).
    Returns a delta, percentile estimate, and an assessment string.
    """
    engine = _get_engine()
    return engine.get_industry_comparison(org_id=org_id)


# ---------------------------------------------------------------------------
# Endpoints: Scenarios
# ---------------------------------------------------------------------------


@router.get(
    "/scenarios",
    summary="List available injection scenarios",
)
async def list_scenarios() -> Dict[str, Any]:
    """
    List all available FAIL injection scenarios (built-in and custom).

    Each scenario includes:
    - Synthetic finding payload (CVE, CVSS, evidence)
    - MITRE ATT&CK technique/tactic mapping
    - CWE identifiers
    - Expected detection timeline and triage classification
    - Recommended remediation approach
    """
    engine = _get_engine()
    scenarios = engine.list_scenarios()
    builtin = [s for s in scenarios if not s.get("is_custom")]
    custom = [s for s in scenarios if s.get("is_custom")]

    return {
        "total": len(scenarios),
        "builtin_count": len(builtin),
        "custom_count": len(custom),
        "scenarios": scenarios,
    }


@router.post(
    "/scenarios",
    summary="Create a custom injection scenario",
    status_code=201,
)
async def create_scenario(req: CreateScenarioRequest) -> Dict[str, Any]:
    """
    Create a custom FAIL injection scenario.

    Custom scenarios allow organisations to test detection of domain-specific
    vulnerabilities that are not covered by the 10 built-in scenarios.

    The synthetic_finding payload should mimic what a real scanner would report
    for this vulnerability class — the closer to reality, the more valid the test.
    """
    try:
        engine = _get_engine()
        scenario = engine.create_custom_scenario(
            scenario_id=req.scenario_id,
            name=req.name,
            description=req.description,
            severity=req.severity,
            synthetic_finding=req.synthetic_finding,
            cwe_ids=req.cwe_ids,
            mitre_techniques=req.mitre_techniques,
            mitre_tactics=req.mitre_tactics,
            expected_detection_minutes=req.expected_detection_minutes,
            expected_triage_classification=req.expected_triage_classification,
            expected_remediation_approach=req.expected_remediation_approach,
            cvss_score=req.cvss_score,
            cve_id=req.cve_id,
            tags=req.tags,
        )
        return {
            "created": True,
            "scenario": scenario.to_dict(),
            "message": f"Custom scenario '{req.scenario_id}' created successfully.",
        }
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("create_scenario failed: %s", exc)
        raise HTTPException(
            status_code=400, detail=f"Failed to create scenario: {exc}"
        )


# ---------------------------------------------------------------------------
# Endpoint: Training data export
# ---------------------------------------------------------------------------


@router.get(
    "/training-data",
    summary="Export labeled training samples",
)
async def get_training_data(
    org_id: str = Depends(get_org_id),
    scenario_id: Optional[str] = Query(None, description="Filter by scenario"),
    limit: int = Query(1000, ge=1, le=10000, description="Maximum samples to return"),
) -> Dict[str, Any]:
    """
    Export labeled training samples generated from completed drills.

    Each sample includes two labeled signals for ML feedback loops:
    - **Detection signal**: `detection_label` ∈ {fast, slow, very_slow, missed}
    - **Triage signal**: `triage_label` ∈ {correct, incorrect, skipped}

    These samples feed into the self-learning detection and triage loops:
    - Loop 1: Detection model — learns what "fast detection" looks like per scenario
    - Loop 2: Triage model — learns correct severity classification per finding type
    """
    engine = _get_engine()
    samples = engine.get_training_data(
        org_id=org_id,
        scenario_id=scenario_id,
        limit=limit,
    )
    detection_counts: Dict[str, int] = {}
    triage_counts: Dict[str, int] = {}
    for s in samples:
        dl = s.get("detection_label", "unknown")
        tl = s.get("triage_label", "unknown")
        detection_counts[dl] = detection_counts.get(dl, 0) + 1
        triage_counts[tl] = triage_counts.get(tl, 0) + 1

    return {
        "total": len(samples),
        "filters": {"org_id": org_id, "scenario_id": scenario_id},
        "label_distribution": {
            "detection": detection_counts,
            "triage": triage_counts,
        },
        "samples": samples,
    }


# ---------------------------------------------------------------------------
# Endpoint: Log security activity
# ---------------------------------------------------------------------------


@router.post(
    "/activity",
    summary="Log a security activity for neglect zone tracking",
    status_code=201,
)
async def log_activity(req: LogActivityRequest) -> Dict[str, Any]:
    """
    Log a security activity event for a component.

    This is used to track when components have been scanned, reviewed, or
    drilled, so the neglect zone detector can accurately identify blind spots.

    Activity types: scan, review, drill, pentest, audit
    """
    try:
        engine = _get_engine()
        activity_id = engine.log_security_activity(
            org_id=req.org_id,
            component=req.component,
            activity_type=req.activity_type,
            description=req.description,
            actor=req.actor,
            has_critical_data=req.has_critical_data,
        )
        return {
            "logged": True,
            "activity_id": activity_id,
            "org_id": req.org_id,
            "component": req.component,
            "activity_type": req.activity_type,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("log_activity failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to log activity")


# ---------------------------------------------------------------------------
# Endpoint: Health check
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    summary="FAIL Engine health check",
)
async def health_check() -> Dict[str, Any]:
    """
    Health check for the FAIL Engine (suite-attack edition).

    Returns engine version, scenario count, and database path.
    """
    try:
        engine = _get_engine()
        return engine.health()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Health check failed: %s", exc)
        return {
            "status": "degraded",
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Endpoints: FAIL Scoring (stats, scores, top-risks) — from legacy engine
# ---------------------------------------------------------------------------


@router.get("/scores", summary="List FAIL scores")
async def list_scores(
    org_id: str = Depends(get_org_id),
    grade: Optional[str] = Query(None, description="Filter by grade"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List FAIL scores (paginated, sorted by score DESC)."""
    try:
        from core.fail_db import FAILDB
        db = FAILDB()
        scores = db.get_scores_by_org(org_id=org_id, grade=grade, limit=limit, offset=offset)
        total = db.count(org_id=org_id)
        return {"total": total, "limit": limit, "offset": offset, "results": scores}
    except ImportError as exc:
        logger.warning("Failed to load FAIL scores: %s", exc)
        return {"total": 0, "limit": limit, "offset": offset, "results": []}


@router.get("/top-risks", summary="Top risks by FAIL score")
async def top_risks(
    org_id: str = Depends(get_org_id),
    limit: int = Query(20, ge=1, le=100),
):
    """Get the highest-risk findings by FAIL score."""
    try:
        from core.fail_db import FAILDB
        db = FAILDB()
        risks = db.get_top_risks(org_id=org_id, limit=limit)
        total = db.count(org_id=org_id)
        return {"risks": risks, "total": total}
    except ImportError as exc:
        logger.warning("Failed to load top risks: %s", exc)
        return {"risks": [], "total": 0}


@router.get("/stats", summary="FAIL score statistics")
async def fail_stats(org_id: str = Depends(get_org_id)):
    """Aggregate FAIL scoring statistics."""
    try:
        from core.fail_db import FAILDB
        db = FAILDB()
        stats = db.get_stats(org_id=org_id)
        return stats
    except ImportError as exc:
        logger.warning("Failed to load FAIL stats: %s", exc)
        return {
            "total_scored": 0,
            "grade_distribution": {},
            "avg_score": 0.0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        }



# ---------------------------------------------------------------------------
# Alias: /history — UI calls /fail/history, maps to drills with history=true
# ---------------------------------------------------------------------------


@router.get("/history", summary="Drill history (alias for drills?history=true)", include_in_schema=False)
async def get_fail_history(
    org_id: str = Depends(get_org_id),
    days: int = Query(90, ge=1, le=365, description="Days of history to include"),
) -> Dict[str, Any]:
    """Return drill history for an org — alias used by the UI."""
    return await list_drills(org_id=org_id, history=True, days=days)
