"""Self-Learning Feedback Loops Router (V8 — DEMO-012).

Exposes the 5 feedback loops: Decision Outcome, MPTE Result,
False Positive, Remediation Success, Policy Violation.
Each loop collects data → analyzes patterns → generates insights.

Demo endpoints:
- POST /demo/seed — Populate realistic feedback data for all 5 loops
- POST /demo/reset — Clear all learning data for fresh demo
- POST /score-with-learning — Score a finding showing before/after learning effect
- POST /compute-adjustments — Run the learning step (feedback → weight updates)
- GET  /weights — Show all learned weights
- PUT  /weights/{key} — Manually set a weight
- GET  /metrics/trends — Show learning improvement over time
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/self-learning", tags=["Self-Learning"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class DecisionFeedbackRequest(BaseModel):
    decision_id: str = Field(..., description="AI decision ID")
    finding_id: str = Field(..., description="Finding ID")
    predicted_action: str = Field(..., description="What AI decided")
    actual_outcome: str = Field(..., description="What actually happened")
    confidence: float = Field(0.0, ge=0, le=1)
    context: Dict[str, Any] = Field(default_factory=dict)


class MPTEFeedbackRequest(BaseModel):
    finding_id: str = Field(..., description="Finding ID")
    predicted_exploitable: bool = Field(..., description="Was it predicted exploitable?")
    actual_exploitable: bool = Field(..., description="Was it actually exploitable?")
    mpte_confidence: float = Field(0.0, ge=0, le=1)
    context: Dict[str, Any] = Field(default_factory=dict)


class FPFeedbackRequest(BaseModel):
    finding_id: str = Field(..., description="Finding ID")
    scanner: str = Field(..., description="Scanner name")
    rule_id: str = Field(..., description="Rule/check ID")
    is_false_positive: bool = Field(..., description="Analyst marked as FP?")
    context: Dict[str, Any] = Field(default_factory=dict)


class RemediationFeedbackRequest(BaseModel):
    finding_id: str = Field(..., description="Finding ID")
    fix_type: str = Field(..., description="Fix type (CODE_PATCH, CONFIG, etc.)")
    fix_applied: str = Field(..., description="Description of fix applied")
    resolved: bool = Field(..., description="Did the fix resolve the issue?")
    time_to_fix_hours: float = Field(0, ge=0)
    context: Dict[str, Any] = Field(default_factory=dict)


class PolicyFeedbackRequest(BaseModel):
    policy_id: str = Field(..., description="Policy ID")
    rule_id: str = Field(..., description="Rule ID within policy")
    violated: bool = Field(..., description="Was the policy violated?")
    was_justified: bool = Field(..., description="Was the action justified?")
    context: Dict[str, Any] = Field(default_factory=dict)


class ScoreWithLearningRequest(BaseModel):
    cvss_score: float = Field(7.5, ge=0, le=10, description="CVSS base score")
    epss_score: float = Field(0.3, ge=0, le=1, description="EPSS probability")
    in_kev: bool = Field(False, description="In CISA KEV catalog?")
    asset_criticality: float = Field(0.7, ge=0, le=1, description="Asset criticality")
    scanner: str = Field("semgrep", description="Scanner that found this")
    rule_id: str = Field("CWE-89-sql-injection", description="Rule/check ID")
    fix_type: str = Field("CODE_PATCH", description="Expected fix type")


class WeightUpdateRequest(BaseModel):
    value: float = Field(..., ge=0, le=2.0, description="Weight value")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/status")
async def self_learning_status() -> Dict[str, Any]:
    """Get self-learning engine status."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        return {
            "status": "operational",
            "engine": "self-learning",
            "version": "1.0.0",
            **engine.get_status(),
        }
    except Exception as e:
        return {
            "status": "degraded",
            "engine": "self-learning",
            "error": str(e),
        }


@router.post("/feedback/decision")
async def record_decision_feedback(req: DecisionFeedbackRequest) -> Dict[str, Any]:
    """Record a decision outcome feedback (Loop 1)."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        feedback_id = engine.decision_loop.record(
            decision_id=req.decision_id,
            finding_id=req.finding_id,
            predicted_action=req.predicted_action,
            actual_outcome=req.actual_outcome,
            confidence=req.confidence,
            context=req.context,
        )
        return {"recorded": True, "feedback_id": feedback_id, "loop": "decision_outcome"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback/mpte")
async def record_mpte_feedback(req: MPTEFeedbackRequest) -> Dict[str, Any]:
    """Record an MPTE result feedback (Loop 2)."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        feedback_id = engine.mpte_loop.record(
            finding_id=req.finding_id,
            predicted_exploitable=req.predicted_exploitable,
            actual_exploitable=req.actual_exploitable,
            mpte_confidence=req.mpte_confidence,
            context=req.context,
        )
        return {"recorded": True, "feedback_id": feedback_id, "loop": "mpte_result"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback/false-positive")
async def record_fp_feedback(req: FPFeedbackRequest) -> Dict[str, Any]:
    """Record a false positive feedback (Loop 3)."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        feedback_id = engine.fp_loop.record(
            finding_id=req.finding_id,
            scanner=req.scanner,
            rule_id=req.rule_id,
            is_false_positive=req.is_false_positive,
            context=req.context,
        )
        return {"recorded": True, "feedback_id": feedback_id, "loop": "false_positive"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback/remediation")
async def record_remediation_feedback(req: RemediationFeedbackRequest) -> Dict[str, Any]:
    """Record a remediation success feedback (Loop 4)."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        feedback_id = engine.remediation_loop.record(
            finding_id=req.finding_id,
            fix_type=req.fix_type,
            fix_applied=req.fix_applied,
            resolved=req.resolved,
            time_to_fix_hours=req.time_to_fix_hours,
            context=req.context,
        )
        return {"recorded": True, "feedback_id": feedback_id, "loop": "remediation_success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback/policy")
async def record_policy_feedback(req: PolicyFeedbackRequest) -> Dict[str, Any]:
    """Record a policy violation feedback (Loop 5)."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        feedback_id = engine.policy_loop.record(
            policy_id=req.policy_id,
            rule_id=req.rule_id,
            violated=req.violated,
            was_justified=req.was_justified,
            context=req.context,
        )
        return {"recorded": True, "feedback_id": feedback_id, "loop": "policy_violation"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analyze")
async def analyze_all(days: int = Query(90, ge=1, le=365)) -> Dict[str, Any]:
    """Run analysis on all 5 feedback loops."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        return engine.analyze_all(days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/insights")
async def get_insights() -> Dict[str, Any]:
    """Get actionable insights from self-learning analysis."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        return engine.get_insights()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analyze/{loop}")
async def analyze_loop(
    loop: str,
    days: int = Query(90, ge=1, le=365),
) -> Dict[str, Any]:
    """Analyze a specific feedback loop."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        loop_map = {
            "decision": engine.decision_loop,
            "mpte": engine.mpte_loop,
            "false-positive": engine.fp_loop,
            "remediation": engine.remediation_loop,
            "policy": engine.policy_loop,
        }
        if loop not in loop_map:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown loop: {loop}. Valid: {list(loop_map.keys())}",
            )
        return loop_map[loop].analyze(days)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/suppressed-rules")
async def get_suppressed_rules() -> Dict[str, Any]:
    """Get rules that should be suppressed based on FP learning."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        rules = engine.fp_loop.get_suppressed_rules()
        return {"suppressed_rules": rules, "count": len(rules)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Demo & Learning Endpoints (DEMO-012)
# ---------------------------------------------------------------------------
@router.post("/score-with-learning")
async def score_with_learning(req: ScoreWithLearningRequest) -> Dict[str, Any]:
    """Score a finding showing before/after learning effect.

    This is the key demo endpoint: it shows how the same vulnerability
    gets a different risk score after the system has learned from
    past decisions, FP feedback, MPTE verifications, and remediation outcomes.

    Returns:
        - baseline_score: Score without learning
        - adjusted_score: Score with learning adjustments
        - delta: The difference (negative = lower risk after learning)
        - adjustments: Detailed breakdown of each learning factor
    """
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        return engine.score_with_learning({
            "cvss_score": req.cvss_score,
            "epss_score": req.epss_score,
            "in_kev": req.in_kev,
            "asset_criticality": req.asset_criticality,
            "scanner": req.scanner,
            "rule_id": req.rule_id,
            "fix_type": req.fix_type,
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compute-adjustments")
async def compute_adjustments() -> Dict[str, Any]:
    """Run the learning step: analyze feedback → compute weight adjustments.

    This is the "brain learns" step. It analyzes all feedback data,
    identifies patterns, and adjusts internal weights that modify
    future risk scoring. Each adjustment is logged with reasoning.

    Returns:
        - adjustments: List of weight changes with old/new values and reasoning
        - count: Number of adjustments applied
    """
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        adjustments = engine.compute_adjustments()
        return {
            "adjustments": [
                {
                    "id": adj.adjustment_id,
                    "loop": adj.feedback_type.value,
                    "target": adj.target,
                    "metric": adj.metric,
                    "old_value": round(adj.old_value, 4),
                    "new_value": round(adj.new_value, 4),
                    "delta": round(adj.new_value - adj.old_value, 4),
                    "sample_count": adj.sample_count,
                    "confidence": round(adj.confidence, 2),
                    "reasoning": adj.reasoning,
                    "applied": adj.applied,
                }
                for adj in adjustments
            ],
            "count": len(adjustments),
            "computed_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/weights")
async def get_weights() -> Dict[str, Any]:
    """Get all learned weights.

    Shows every weight that the self-learning engine has computed.
    Weights modify risk scoring — values < 1.0 reduce risk scores,
    values > 1.0 increase them.
    """
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        weights = engine.get_all_weights()
        return {
            "weights": weights,
            "count": len(weights),
            "retrieved_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/weights/{key:path}")
async def set_weight(
    key: str = Path(..., description="Weight key (e.g., scanner:semgrep:accuracy)"),
    req: WeightUpdateRequest = ...,
) -> Dict[str, Any]:
    """Set a specific learned weight. For demo/calibration purposes."""
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        old_value = engine.get_weight(key, 1.0)
        engine.set_weight(key, req.value)
        return {
            "key": key,
            "old_value": round(old_value, 4),
            "new_value": round(req.value, 4),
            "updated": True,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/trends")
async def get_metrics_trends(
    days: int = Query(30, ge=1, le=365),
) -> Dict[str, Any]:
    """Get learning improvement trends over time.

    Shows how each loop's key metric has changed over the specified
    time period. Positive improvement = the system is learning.
    """
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        return engine.get_metrics_trends(days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/demo/seed")
async def seed_demo_data() -> Dict[str, Any]:
    """Seed realistic demo data for all 5 feedback loops.

    Populates the learning database with 98 realistic feedback records
    across all 5 loops, with distributions that demonstrate the learning
    effect (e.g., decision accuracy improves from 60% to 85%).

    Call this BEFORE running compute-adjustments and score-with-learning.
    """
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        return engine.seed_demo_data()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/demo/reset")
async def reset_demo_data() -> Dict[str, Any]:
    """Reset all learning data for a fresh demo.

    Clears all feedback records, weight adjustments, and metrics.
    Use this to start a clean demo.
    """
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()
        return engine.reset_learning()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/demo/full-loop")
async def demo_full_loop() -> Dict[str, Any]:
    """Execute a complete self-learning demo in one call.

    This endpoint demonstrates the FULL feedback loop:
    1. Reset any existing data
    2. Score a sample finding (baseline — no learning)
    3. Seed demo feedback data (98 records across 5 loops)
    4. Run learning step (compute weight adjustments)
    5. Score the SAME finding again (now with learning adjustments)
    6. Show the improvement (delta between baseline and adjusted)

    This is the demo that proves ALdeci gets smarter with every decision.
    """
    try:
        from core.self_learning import get_learning_engine
        engine = get_learning_engine()

        # Step 1: Reset
        reset_result = engine.reset_learning()

        # Step 2: Baseline score (no learning data)
        sample_finding = {
            "cvss_score": 7.5,
            "epss_score": 0.35,
            "in_kev": False,
            "asset_criticality": 0.7,
            "scanner": "zap",
            "rule_id": "10016-xss",
            "fix_type": "CODE_PATCH",
        }
        baseline = engine.score_with_learning(sample_finding)

        # Step 3: Seed demo data
        seed_result = engine.seed_demo_data()

        # Step 4: Compute adjustments (learning step)
        adjustments = engine.compute_adjustments()

        # Step 5: Re-score with learned weights
        after_learning = engine.score_with_learning(sample_finding)

        # Step 6: Compare
        improvement = round(baseline["baseline_score"] - after_learning["adjusted_score"], 4)
        improvement_pct = round(
            (improvement / baseline["baseline_score"] * 100) if baseline["baseline_score"] > 0 else 0,
            1,
        )

        # Step 7: Get analysis for context
        analysis = engine.analyze_all()
        insights = engine.get_insights()
        weights = engine.get_all_weights()

        return {
            "demo": "self-learning-full-loop",
            "story": (
                "ALdeci scored a ZAP XSS finding at baseline, then learned from "
                f"98 feedback records across 5 loops. After learning, the risk score "
                f"changed by {improvement_pct}% — proving the system adapts to reality."
            ),
            "steps": {
                "1_reset": {"status": "done", "cleared": reset_result["tables_cleared"]},
                "2_baseline_score": {
                    "status": "done",
                    "finding": sample_finding,
                    "score": baseline["baseline_score"],
                    "adjustments": baseline["adjustments_applied"],
                },
                "3_seed_data": {
                    "status": "done",
                    "records_seeded": seed_result["total_records"],
                    "by_loop": seed_result["seeded"],
                },
                "4_compute_adjustments": {
                    "status": "done",
                    "adjustments_applied": len(adjustments),
                    "adjustments": [
                        {
                            "loop": a.feedback_type.value,
                            "target": a.target,
                            "old": round(a.old_value, 4),
                            "new": round(a.new_value, 4),
                            "reasoning": a.reasoning,
                        }
                        for a in adjustments
                    ],
                },
                "5_adjusted_score": {
                    "status": "done",
                    "score": after_learning["adjusted_score"],
                    "delta": after_learning["delta"],
                    "adjustments": after_learning["adjustments_applied"],
                    "adjustments_detail": after_learning["adjustments"],
                },
                "6_improvement": {
                    "baseline": baseline["baseline_score"],
                    "after_learning": after_learning["adjusted_score"],
                    "absolute_change": improvement,
                    "percent_change": improvement_pct,
                    "direction": "risk_reduced" if improvement > 0 else "risk_increased" if improvement < 0 else "no_change",
                },
            },
            "analysis": analysis,
            "insights": insights,
            "learned_weights": weights,
            "loops_demonstrated": [
                "decision_outcome — tracks AI decision accuracy → adjusts scanner weights",
                "mpte_result — tracks exploitability prediction accuracy → adjusts MPTE confidence",
                "false_positive — tracks FP rates per scanner/rule → suppresses noisy rules",
                "remediation_success — tracks fix effectiveness by type → adjusts fix priority",
                "policy_violation — tracks justified violations → relaxes over-strict policies",
            ],
        }
    except Exception as e:
        logger.exception("Demo full loop failed")
        raise HTTPException(status_code=500, detail=str(e))
