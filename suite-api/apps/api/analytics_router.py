"""
Analytics and dashboard API endpoints.

Advanced analytics: trend analysis with moving averages, anomaly detection
via z-score, comparative metrics across periods, severity heatmaps,
real CSV export, and risk-velocity scoring.
"""
from __future__ import annotations

import csv
import io
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence

from apps.api.dependencies import get_org_id
from core.analytics_db import AnalyticsDB
from core.analytics_models import (
    Decision,
    DecisionOutcome,
    Finding,
    FindingSeverity,
    FindingStatus,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])
db = AnalyticsDB()


# ---------------------------------------------------------------------------
# Internal helpers — real statistical computation
# ---------------------------------------------------------------------------


def _moving_average(values: Sequence[float], window: int = 7) -> List[float]:
    """Compute simple moving average."""
    result: List[float] = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        result.append(sum(values[start : i + 1]) / (i - start + 1))
    return result


def _z_scores(values: Sequence[float]) -> List[float]:
    """Compute z-scores for anomaly detection (|z|>2 = anomaly)."""
    if len(values) < 3:
        return [0.0] * len(values)
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)
    if stdev == 0:
        return [0.0] * len(values)
    return [(v - mean) / stdev for v in values]


def _severity_weight(severity: str) -> float:
    """Convert severity to numeric weight for scoring."""
    return {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.5}.get(
        severity.lower() if isinstance(severity, str) else "medium", 4.0
    )


class FindingCreate(BaseModel):
    """Request model for creating a finding."""

    org_id: str = Field(
        ..., min_length=1, description="Organization ID for multi-tenancy"
    )
    application_id: Optional[str] = None
    service_id: Optional[str] = None
    rule_id: str = Field(..., min_length=1)
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.OPEN
    title: str = Field(..., min_length=1)
    description: str
    source: str = Field(..., min_length=1)
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    exploitable: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingUpdate(BaseModel):
    """Request model for updating a finding."""

    status: Optional[FindingStatus] = None
    metadata: Optional[Dict[str, Any]] = None


class FindingResponse(BaseModel):
    """Response model for a finding."""

    id: str
    org_id: Optional[str] = None
    application_id: Optional[str]
    service_id: Optional[str]
    rule_id: str
    severity: str
    status: str
    title: str
    description: str
    source: str
    cve_id: Optional[str]
    cvss_score: Optional[float]
    epss_score: Optional[float]
    exploitable: bool
    metadata: Dict[str, Any]
    created_at: str
    updated_at: str
    resolved_at: Optional[str]


class DecisionCreate(BaseModel):
    """Request model for creating a decision."""

    finding_id: str = Field(..., min_length=1)
    outcome: DecisionOutcome
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    llm_votes: Dict[str, Any] = Field(default_factory=dict)
    policy_matched: Optional[str] = None


class DecisionResponse(BaseModel):
    """Response model for a decision."""

    id: str
    finding_id: str
    outcome: str
    confidence: float
    reasoning: str
    llm_votes: Dict[str, Any]
    policy_matched: Optional[str]
    created_at: str


class MetricCreate(BaseModel):
    """Request model for creating a metric."""

    metric_type: str = Field(..., min_length=1)
    metric_name: str = Field(..., min_length=1)
    value: float
    unit: str = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MetricResponse(BaseModel):
    """Response model for a metric."""

    id: str
    metric_type: str
    metric_name: str
    value: float
    unit: str
    timestamp: str
    metadata: Dict[str, Any]


@router.get("/dashboard/overview")
async def get_dashboard_overview(
    org_id: str = Depends(get_org_id),
):
    """Get security posture overview for dashboard."""
    overview = db.get_dashboard_overview()
    overview["org_id"] = org_id
    return overview


@router.get("/dashboard/summary")
async def get_dashboard_summary(
    org_id: str = Depends(get_org_id),
):
    """Compact dashboard summary with key counts and risk score."""
    findings = db.list_findings(limit=5000)
    total = len(findings)
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_count = 0
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev.lower() in by_severity:
            by_severity[sev.lower()] += 1
        if (f.status.value if hasattr(f.status, "value") else str(f.status)).lower() == "open":
            open_count += 1

    risk_score = min(100, by_severity["critical"] * 25 + by_severity["high"] * 10 + by_severity["medium"] * 3)
    return {
        "org_id": org_id,
        "total_findings": total,
        "open_findings": open_count,
        "resolved_findings": total - open_count,
        "severity": by_severity,
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low",
        "scanners_active": len(set(
            getattr(f, "source", "unknown") for f in db.list_findings(limit=5000)
            if getattr(f, "source", None)
        )),
        "last_scan": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dashboard/severity")
async def get_dashboard_severity(
    org_id: str = Depends(get_org_id),
):
    """Severity breakdown for dashboard charts."""
    findings = db.list_findings(limit=5000)
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev.lower() in by_severity:
            by_severity[sev.lower()] += 1
    total = sum(by_severity.values())
    return {
        "org_id": org_id,
        "total": total,
        "severity": by_severity,
        "distribution": {k: round(v / max(total, 1) * 100, 1) for k, v in by_severity.items()},
    }


@router.get("/dashboard/scanners")
async def get_dashboard_scanners(
    org_id: str = Depends(get_org_id),
):
    """Scanner activity breakdown for dashboard."""
    findings = db.list_findings(limit=5000)
    by_scanner: Dict[str, int] = {}
    for f in findings:
        scanner = getattr(f, "source", None) or "unknown"
        by_scanner[scanner] = by_scanner.get(scanner, 0) + 1
    scanners = [
        {"name": name, "findings": count, "status": "active"}
        for name, count in sorted(by_scanner.items(), key=lambda x: -x[1])
    ]
    # Add native scanners that may not have findings yet
    native = ["SAST", "DAST", "Secrets", "Container", "CSPM", "API Fuzzer", "Malware", "LLM Monitor"]
    existing_names = {s["name"].lower() for s in scanners}
    for ns in native:
        if ns.lower() not in existing_names:
            scanners.append({"name": ns, "findings": 0, "status": "active"})
    return {"org_id": org_id, "scanners": scanners, "total": len(scanners)}


@router.get("/dashboard/executive")
async def get_dashboard_executive(
    request: Request,
    org_id: str = Depends(get_org_id),
):
    """Executive dashboard view — alias for /executive with org_id."""
    result = await executive_summary(request)
    result["org_id"] = org_id
    return result


@router.get("/overview")
async def get_analytics_overview(
    org_id: str = Depends(get_org_id),
):
    """High-level analytics overview across all compliance and risk domains."""
    findings = db.list_findings(limit=5000)
    total = len(findings)
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_status: Dict[str, int] = {"open": 0, "resolved": 0, "in_progress": 0, "false_positive": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev.lower() in by_severity:
            by_severity[sev.lower()] += 1
        st = f.status.value if hasattr(f.status, "value") else str(f.status)
        if st.lower() in by_status:
            by_status[st.lower()] += 1

    resolved = by_status.get("resolved", 0) + by_status.get("false_positive", 0)
    risk_score = min(100, by_severity["critical"] * 25 + by_severity["high"] * 10 + by_severity["medium"] * 3)
    return {
        "org_id": org_id,
        "total_findings": total,
        "severity_breakdown": by_severity,
        "status_breakdown": by_status,
        "risk_score": risk_score,
        "compliance_score": round(resolved / max(total, 1) * 100, 1),
        "frameworks_assessed": 0,
        "evidence_bundles": 0,
        "last_assessment": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dashboard/trends")
async def get_dashboard_trends(
    org_id: str = Depends(get_org_id),
    days: int = Query(30, ge=1, le=365),
):
    """Get trend data computed from ingested findings over the specified period."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)

    # First try the metrics table
    metrics = db.list_metrics(
        metric_type="trend",
        start_time=start_time,
        end_time=end_time,
        limit=1000,
    )

    if metrics:
        return {
            "org_id": org_id,
            "period_days": days,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "metrics": [m.to_dict() for m in metrics],
        }

    # Compute trends directly from findings table
    findings = db.list_findings(limit=50000)
    daily: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        if f.source == "test":
            continue
        ts = (
            f.created_at
            if isinstance(f.created_at, datetime)
            else datetime.fromisoformat(str(f.created_at))
        )
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        day_key = ts.strftime("%Y-%m-%d")
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        daily[day_key][sev] = daily[day_key].get(sev, 0) + 1
        daily[day_key]["total"] = daily[day_key].get("total", 0) + 1

    series = []
    for day in sorted(daily.keys()):
        entry = {"period": day}
        entry.update(dict(daily[day]))
        series.append(entry)

    # Severity breakdown across all findings
    severity_totals: Dict[str, int] = {}
    for f in findings:
        if f.source == "test":
            continue
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severity_totals[sev] = severity_totals.get(sev, 0) + 1

    return {
        "org_id": org_id,
        "period_days": days,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "total_findings": sum(severity_totals.values()),
        "severity_totals": severity_totals,
        "series": series,
        "metrics": [],
        "source": "computed_from_findings",
    }


@router.get("/dashboard/top-risks")
async def get_top_risks(
    org_id: str = Depends(get_org_id),
    limit: int = Query(10, ge=1, le=100),
):
    """Get top security risks by severity and exploitability."""
    risks = db.get_top_risks(limit=limit)
    return {"org_id": org_id, "risks": risks, "total": len(risks)}


@router.get("/dashboard/compliance-status")
async def get_compliance_status(
    org_id: str = Depends(get_org_id),
):
    """Get compliance framework status."""
    findings = db.list_findings(limit=1000)

    total = len(findings)
    open_count = sum(1 for f in findings if f.status == FindingStatus.OPEN)
    critical_count = sum(
        1
        for f in findings
        if f.severity == FindingSeverity.CRITICAL and f.status == FindingStatus.OPEN
    )

    compliance_score = 100.0
    if total > 0:
        compliance_score = max(0.0, 100.0 - (open_count / total * 100.0))

    return {
        "compliance_score": round(compliance_score, 2),
        "total_findings": total,
        "open_findings": open_count,
        "critical_findings": critical_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/findings", response_model=List[FindingResponse])
async def query_findings(
    org_id: str = Depends(get_org_id),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Query findings with filters. Returns real ingested findings."""
    findings = db.list_findings(
        severity=severity,
        status=status,
        limit=limit + 10,  # over-fetch to allow filtering
        offset=offset,
    )
    # Exclude synthetic test-only findings
    findings = [f for f in findings if getattr(f, "source", "") != "test"]
    return [FindingResponse(**f.to_dict()) for f in findings[:limit]]


@router.post("/findings", response_model=FindingResponse, status_code=201)
async def create_finding(finding_data: FindingCreate):
    """Create a new finding."""
    finding = Finding(
        id="",
        application_id=finding_data.application_id,
        service_id=finding_data.service_id,
        rule_id=finding_data.rule_id,
        severity=finding_data.severity,
        status=finding_data.status,
        title=finding_data.title,
        description=finding_data.description,
        source=finding_data.source,
        cve_id=finding_data.cve_id,
        cvss_score=finding_data.cvss_score,
        epss_score=finding_data.epss_score,
        exploitable=finding_data.exploitable,
        metadata=finding_data.metadata,
    )
    created_finding = db.create_finding(finding)
    return FindingResponse(**created_finding.to_dict())


@router.get("/findings/{id}", response_model=FindingResponse)
async def get_finding(id: str):
    """Get finding by ID."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse(**finding.to_dict())


@router.put("/findings/{id}", response_model=FindingResponse)
async def update_finding(id: str, finding_data: FindingUpdate):
    """Update a finding."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if finding_data.status is not None:
        finding.status = finding_data.status
        if finding_data.status in [
            FindingStatus.RESOLVED,
            FindingStatus.FALSE_POSITIVE,
        ]:
            finding.resolved_at = datetime.now(timezone.utc)

    if finding_data.metadata is not None:
        finding.metadata.update(finding_data.metadata)

    updated_finding = db.update_finding(finding)
    return FindingResponse(**updated_finding.to_dict())


@router.get("/decisions", response_model=List[DecisionResponse])
async def query_decisions(
    org_id: str = Depends(get_org_id),
    finding_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Query decision history."""
    decisions = db.list_decisions(
        finding_id=finding_id,
        limit=limit,
        offset=offset,
    )
    return [DecisionResponse(**d.to_dict()) for d in decisions]


@router.post("/decisions", response_model=DecisionResponse, status_code=201)
async def create_decision(decision_data: DecisionCreate):
    """Create a new decision record."""
    finding = db.get_finding(decision_data.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    decision = Decision(
        id="",
        finding_id=decision_data.finding_id,
        outcome=decision_data.outcome,
        confidence=decision_data.confidence,
        reasoning=decision_data.reasoning,
        llm_votes=decision_data.llm_votes,
        policy_matched=decision_data.policy_matched,
    )
    created_decision = db.create_decision(decision)
    return DecisionResponse(**created_decision.to_dict())


@router.get("/mttr")
async def get_mttr():
    """Get mean time to remediation metrics computed from findings and SLA data."""
    mttr_hours = db.calculate_mttr()

    if mttr_hours is not None:
        return {
            "mttr_hours": round(mttr_hours, 2),
            "mttr_days": round(mttr_hours / 24, 2),
            "resolved_count": len([f for f in db.list_findings(limit=10000) if getattr(f, "resolved_at", None)]),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "resolved_findings",
        }

    # No resolved findings — compute projected MTTR from SLA targets and finding severity
    findings = db.list_findings(limit=10000)
    real_findings = [f for f in findings if getattr(f, "source", "") != "test"]
    if not real_findings:
        return {
            "mttr_hours": None,
            "mttr_days": None,
            "message": "No findings available for MTTR calculation",
        }

    # SLA hours by severity (industry standard)
    sla_by_severity = {"critical": 24, "high": 72, "medium": 168, "low": 720, "info": 2160}
    severity_counts: Dict[str, int] = {}
    weighted_sla_total = 0.0
    for f in real_findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev = sev.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        weighted_sla_total += sla_by_severity.get(sev, 168)

    projected_mttr_hours = weighted_sla_total / len(real_findings) if real_findings else 0

    return {
        "mttr_hours": None,
        "mttr_days": None,
        "projected_mttr_hours": round(projected_mttr_hours, 1),
        "projected_mttr_days": round(projected_mttr_hours / 24, 1),
        "open_findings": len(real_findings),
        "severity_breakdown": severity_counts,
        "sla_targets_hours": sla_by_severity,
        "message": "No resolved findings yet. Projected MTTR based on SLA targets and finding severity.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "projected_from_sla",
    }


@router.get("/coverage")
async def get_coverage():
    """Get security coverage metrics."""
    findings = db.list_findings(limit=10000)

    total_findings = len(findings)
    scanned_apps = len(set(f.application_id for f in findings if f.application_id))
    scanned_services = len(set(f.service_id for f in findings if f.service_id))

    sources = {}
    for finding in findings:
        sources[finding.source] = sources.get(finding.source, 0) + 1

    return {
        "total_findings": total_findings,
        "scanned_applications": scanned_apps,
        "scanned_services": scanned_services,
        "sources": sources,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/roi")
async def get_roi():
    """Get ROI calculations."""
    findings = db.list_findings(limit=10000)

    total_findings = len(findings)
    critical_blocked = sum(
        1
        for f in findings
        if f.severity == FindingSeverity.CRITICAL and f.status == FindingStatus.RESOLVED
    )

    avg_breach_cost = 4_240_000
    critical_breach_probability = 0.15

    prevented_cost = critical_blocked * avg_breach_cost * critical_breach_probability

    return {
        "total_findings": total_findings,
        "critical_blocked": critical_blocked,
        "estimated_prevented_cost": round(prevented_cost, 2),
        "currency": "USD",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/noise-reduction")
async def get_noise_reduction():
    """Get noise reduction metrics."""
    findings = db.list_findings(limit=10000)
    decisions = db.list_decisions(limit=10000)

    total_findings = len(findings)
    false_positives = sum(
        1 for f in findings if f.status == FindingStatus.FALSE_POSITIVE
    )

    blocked_decisions = sum(1 for d in decisions if d.outcome == DecisionOutcome.BLOCK)
    alert_decisions = sum(1 for d in decisions if d.outcome == DecisionOutcome.ALERT)

    noise_reduction_pct = 0.0
    if total_findings > 0:
        noise_reduction_pct = (false_positives / total_findings) * 100

    return {
        "total_findings": total_findings,
        "false_positives": false_positives,
        "noise_reduction_percentage": round(noise_reduction_pct, 2),
        "blocked_decisions": blocked_decisions,
        "alert_decisions": alert_decisions,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/custom-query")
async def run_custom_query(query: Dict[str, Any]):
    """Run custom analytics query."""
    query_type = query.get("type", "findings")
    filters = query.get("filters", {})

    if query_type == "findings":
        findings = db.list_findings(
            severity=filters.get("severity"),
            status=filters.get("status"),
            limit=filters.get("limit", 100),
            offset=filters.get("offset", 0),
        )
        return {"results": [f.to_dict() for f in findings], "count": len(findings)}

    elif query_type == "decisions":
        decisions = db.list_decisions(
            finding_id=filters.get("finding_id"),
            limit=filters.get("limit", 100),
            offset=filters.get("offset", 0),
        )
        return {"results": [d.to_dict() for d in decisions], "count": len(decisions)}

    else:
        raise HTTPException(
            status_code=400, detail=f"Unsupported query type: {query_type}"
        )


@router.get("/export")
async def export_analytics(
    format: str = Query("json", pattern="^(json|csv)$"),
    data_type: str = Query("findings", pattern="^(findings|decisions|metrics)$"),
):
    """Export analytics data in specified format."""
    if data_type == "findings":
        findings = db.list_findings(limit=10000)
        data = [f.to_dict() for f in findings]
    elif data_type == "decisions":
        decisions = db.list_decisions(limit=10000)
        data = [d.to_dict() for d in decisions]
    elif data_type == "metrics":
        metrics = db.list_metrics(limit=10000)
        data = [m.to_dict() for m in metrics]
    else:
        raise HTTPException(
            status_code=400, detail=f"Unsupported data type: {data_type}"
        )

    if format == "json":
        return {"data": data, "count": len(data), "format": "json"}
    elif format == "csv":
        if not data:
            return {"data": [], "count": 0, "format": "csv"}
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(data[0].keys()))
        writer.writeheader()
        for row in data:
            writer.writerow({k: str(v) for k, v in row.items()})
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={data_type}.csv"},
        )

    raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


@router.get("/stats")
async def get_analytics_stats(org_id: str = Depends(get_org_id)):
    """Get aggregate analytics statistics."""
    findings = db.list_findings(limit=10000)
    decisions = db.list_decisions(limit=10000)

    severity_counts = {}
    status_counts = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        st = f.status.value if hasattr(f.status, "value") else str(f.status)
        status_counts[st] = status_counts.get(st, 0) + 1

    return {
        "org_id": org_id,
        "total_findings": len(findings),
        "total_decisions": len(decisions),
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/summary")
async def get_analytics_summary(org_id: str = Depends(get_org_id)):
    """Get analytics summary (alias for /stats)."""
    return await get_analytics_stats(org_id)


# ---------------------------------------------------------------------------
# Advanced analytics — trend analysis, anomaly detection, comparison
# ---------------------------------------------------------------------------


@router.get("/trends/severity-over-time")
async def severity_over_time(
    org_id: str = Depends(get_org_id),
    days: int = Query(30, ge=7, le=365),
    bucket: str = Query("day", pattern="^(day|week|month)$"),
):
    """Severity distribution over time with moving averages.

    Returns daily/weekly/monthly counts per severity with a 7-period
    moving average for trend analysis.
    """
    findings = db.list_findings(limit=50000)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    # Bucket findings by date
    buckets: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        ts = (
            f.created_at
            if isinstance(f.created_at, datetime)
            else datetime.fromisoformat(str(f.created_at))
        )
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < cutoff:
            continue
        if bucket == "day":
            key = ts.strftime("%Y-%m-%d")
        elif bucket == "week":
            key = f"{ts.isocalendar()[0]}-W{ts.isocalendar()[1]:02d}"
        else:
            key = ts.strftime("%Y-%m")
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        buckets[key][sev] += 1
        buckets[key]["total"] += 1

    sorted_keys = sorted(buckets.keys())
    totals = [buckets[k]["total"] for k in sorted_keys]
    ma = _moving_average(totals, window=7)

    series = []
    for i, k in enumerate(sorted_keys):
        series.append(
            {
                "period": k,
                **dict(buckets[k]),
                "moving_avg": round(ma[i], 2),
            }
        )

    return {"org_id": org_id, "bucket": bucket, "days": days, "series": series}


@router.get("/trends/anomalies")
async def detect_anomalies(
    org_id: str = Depends(get_org_id),
    days: int = Query(90, ge=14, le=365),
    threshold: float = Query(2.0, ge=1.0, le=5.0),
):
    """Anomaly detection on daily finding counts using z-score.

    Flags days where the z-score exceeds the given threshold (default 2σ).
    """
    findings = db.list_findings(limit=50000)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    daily: Dict[str, int] = defaultdict(int)
    for f in findings:
        ts = (
            f.created_at
            if isinstance(f.created_at, datetime)
            else datetime.fromisoformat(str(f.created_at))
        )
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < cutoff:
            continue
        daily[ts.strftime("%Y-%m-%d")] += 1

    sorted_dates = sorted(daily.keys())
    values = [daily[d] for d in sorted_dates]
    z = _z_scores(values)

    anomalies = []
    for i, d in enumerate(sorted_dates):
        if abs(z[i]) >= threshold:
            anomalies.append(
                {
                    "date": d,
                    "count": values[i],
                    "z_score": round(z[i], 3),
                    "direction": "spike" if z[i] > 0 else "drop",
                }
            )

    return {
        "org_id": org_id,
        "period_days": days,
        "threshold_sigma": threshold,
        "total_days_analysed": len(sorted_dates),
        "anomalies_detected": len(anomalies),
        "anomalies": anomalies,
    }


@router.get("/compare")
async def compare_periods(
    org_id: str = Depends(get_org_id),
    current_days: int = Query(30, ge=1, le=365),
):
    """Compare current period metrics against the previous equal-length period.

    Returns absolute and percentage change for key security KPIs.
    """
    findings = db.list_findings(limit=50000)
    now = datetime.now(timezone.utc)
    current_start = now - timedelta(days=current_days)
    prev_start = current_start - timedelta(days=current_days)

    current: List[Finding] = []
    previous: List[Finding] = []
    for f in findings:
        ts = (
            f.created_at
            if isinstance(f.created_at, datetime)
            else datetime.fromisoformat(str(f.created_at))
        )
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if current_start <= ts <= now:
            current.append(f)
        elif prev_start <= ts < current_start:
            previous.append(f)

    def _kpis(lst: List[Finding]) -> Dict[str, Any]:
        total = len(lst)
        crit = sum(
            1
            for f in lst
            if (f.severity.value if hasattr(f.severity, "value") else str(f.severity))
            == "critical"
        )
        high = sum(
            1
            for f in lst
            if (f.severity.value if hasattr(f.severity, "value") else str(f.severity))
            == "high"
        )
        resolved = sum(
            1
            for f in lst
            if (f.status.value if hasattr(f.status, "value") else str(f.status))
            in ("resolved", "false_positive")
        )
        risk_score = sum(
            _severity_weight(
                f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            )
            for f in lst
        )
        return {
            "total": total,
            "critical": crit,
            "high": high,
            "resolved": resolved,
            "risk_score": round(risk_score, 1),
        }

    cur = _kpis(current)
    prev = _kpis(previous)

    def _delta(c: float, p: float) -> Dict[str, Any]:
        diff = c - p
        pct = ((diff / p) * 100) if p else (100.0 if diff > 0 else 0.0)
        return {
            "current": c,
            "previous": p,
            "change": diff,
            "change_pct": round(pct, 1),
        }

    return {
        "org_id": org_id,
        "current_period": f"last {current_days} days",
        "previous_period": f"{current_days*2}-{current_days} days ago",
        "total_findings": _delta(cur["total"], prev["total"]),
        "critical_findings": _delta(cur["critical"], prev["critical"]),
        "high_findings": _delta(cur["high"], prev["high"]),
        "resolved_findings": _delta(cur["resolved"], prev["resolved"]),
        "risk_score": _delta(cur["risk_score"], prev["risk_score"]),
    }


@router.get("/triage-funnel")
async def triage_funnel(
    org_id: str = Depends(get_org_id),
):
    """Get triage funnel metrics showing finding reduction through ALdeci pipeline.

    Shows the progression: raw scanner findings → deduplicated → correlated →
    risk-prioritized exposure cases. All numbers are computed from real data.
    Returns zeros when no data exists rather than fabricated demo numbers.
    """
    findings = db.list_findings(limit=50000)

    total_raw = len(findings)

    if total_raw == 0:
        return {
            "org_id": org_id,
            "funnel": {
                "raw_findings": 0,
                "after_dedup": 0,
                "after_correlation": 0,
                "exposure_cases": 0,
            },
            "reduction_percentage": 0.0,
            "fail_distribution": {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            },
            "data_available": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Count unique (title, asset, severity) tuples — real dedup count
    seen_keys: set = set()
    for f in findings:
        title = getattr(f, "title", "") or ""
        asset = getattr(f, "asset_name", "") or getattr(f, "source", "") or ""
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        seen_keys.add((title, asset, sev))
    dedup_count = len(seen_keys)

    # Count findings with risk_score (correlated = have been scored)
    correlated_count = sum(
        1 for f in findings if getattr(f, "risk_score", None) is not None
    )
    if correlated_count == 0:
        correlated_count = dedup_count  # If no scoring done, equal to dedup

    # Count open non-info findings — real exposure cases
    prioritized_count = sum(
        1 for f in findings
        if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        not in ("info", "none")
        and (f.status.value if hasattr(f.status, "value") else str(f.status)).lower()
        in ("open", "confirmed", "in_progress")
    )

    reduction_pct = round(
        (1 - prioritized_count / max(total_raw, 1)) * 100, 1
    )

    # Real severity distribution
    severity_counts: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev.lower() in severity_counts:
            severity_counts[sev.lower()] += 1

    return {
        "org_id": org_id,
        "funnel": {
            "raw_findings": total_raw,
            "after_dedup": dedup_count,
            "after_correlation": correlated_count,
            "exposure_cases": prioritized_count,
        },
        "reduction_percentage": reduction_pct,
        "fail_distribution": severity_counts,
        "data_available": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/risk-velocity")
async def risk_velocity(
    org_id: str = Depends(get_org_id),
    days: int = Query(30, ge=7, le=365),
):
    """Compute risk velocity — rate of risk accumulation/reduction per day.

    Positive velocity = risk increasing. Negative = risk decreasing.
    """
    findings = db.list_findings(limit=50000)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    daily_risk: Dict[str, float] = defaultdict(float)
    for f in findings:
        if getattr(f, "source", "") == "test":
            continue
        ts = (
            f.created_at
            if isinstance(f.created_at, datetime)
            else datetime.fromisoformat(str(f.created_at))
        )
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < cutoff:
            continue
        day = ts.strftime("%Y-%m-%d")
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        weight = _severity_weight(sev)
        status = f.status.value if hasattr(f.status, "value") else str(f.status)
        if status in ("resolved", "false_positive"):
            daily_risk[day] -= weight
        else:
            daily_risk[day] += weight

    sorted_days = sorted(daily_risk.keys())
    values = [daily_risk[d] for d in sorted_days]
    cumulative = []
    running = 0.0
    for v in values:
        running += v
        cumulative.append(round(running, 2))

    velocity = round(sum(values) / max(len(values), 1), 3)

    return {
        "org_id": org_id,
        "period_days": days,
        "daily_risk_velocity": velocity,
        "direction": "increasing"
        if velocity > 0
        else "decreasing"
        if velocity < 0
        else "stable",
        "cumulative_risk": cumulative[-1] if cumulative else 0.0,
        "series": [
            {"date": d, "delta": round(daily_risk[d], 2), "cumulative": c}
            for d, c in zip(sorted_days, cumulative)
        ],
    }


@router.get("/executive")
async def executive_summary(request: Request) -> Dict[str, Any]:
    """Executive summary — CISO/CTO-level KPIs, risk posture, compliance."""
    findings = db.list_findings(limit=5000)

    total = len(findings)
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_status: Dict[str, int] = {"open": 0, "resolved": 0, "in_progress": 0, "false_positive": 0}
    by_scanner: Dict[str, int] = {}

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev.lower() in by_severity:
            by_severity[sev.lower()] += 1
        st = f.status.value if hasattr(f.status, "value") else str(f.status)
        if st.lower() in by_status:
            by_status[st.lower()] += 1
        scanner = getattr(f, "source", None) or "unknown"
        by_scanner[scanner] = by_scanner.get(scanner, 0) + 1

    resolved = by_status.get("resolved", 0) + by_status.get("false_positive", 0)
    resolution_rate = round(resolved / max(total, 1) * 100, 1)
    risk_score = min(100, by_severity["critical"] * 25 + by_severity["high"] * 10 + by_severity["medium"] * 3)

    return {
        "status": "ok",
        "total_findings": total,
        "severity_breakdown": by_severity,
        "status_breakdown": by_status,
        "scanner_breakdown": dict(sorted(by_scanner.items(), key=lambda x: -x[1])[:10]),
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low",
        "resolution_rate": resolution_rate,
        "kpis": {
            "mttr_hours": 0,
            "false_positive_rate": round(by_status.get("false_positive", 0) / max(total, 1) * 100, 1),
            "sla_compliance": round(resolution_rate, 1),
            "scanner_coverage": len(by_scanner),
        },
    }


@router.get("/risk-overview")
async def analytics_risk_overview(request: Request) -> Dict[str, Any]:
    """Risk overview from analytics data."""
    findings = db.list_findings(limit=2000)

    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev.lower() in by_severity:
            by_severity[sev.lower()] += 1

    total = sum(by_severity.values())
    risk_score = min(100, by_severity["critical"] * 25 + by_severity["high"] * 10 + by_severity["medium"] * 3)

    return {
        "status": "ok",
        "risk_score": risk_score,
        "total_findings": total,
        "severity_breakdown": by_severity,
        "risk_level": "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low",
    }


@router.get("/sla")
async def analytics_sla(request: Request) -> Dict[str, Any]:
    """SLA compliance analytics from findings data."""
    findings = db.list_findings(limit=2000)

    total = len(findings)
    resolved = sum(1 for f in findings if (f.status.value if hasattr(f.status, "value") else str(f.status)).lower() in ("resolved", "false_positive"))

    return {
        "status": "ok",
        "total_findings": total,
        "resolved": resolved,
        "open": total - resolved,
        "compliance_rate": round(resolved / max(total, 1) * 100, 1),
    }


@router.get("/live-feed")
async def analytics_live_feed(request: Request) -> Dict[str, Any]:
    """Live feed of recent findings/events."""
    findings = db.list_findings(limit=50)

    events = []
    for f in findings[:30]:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        events.append({
            "id": f.id,
            "type": "finding",
            "title": getattr(f, "title", "Unknown"),
            "severity": sev,
            "source": getattr(f, "source", "unknown"),
            "timestamp": f.created_at.isoformat() if hasattr(f, "created_at") and f.created_at else None,
            "status": f.status.value if hasattr(f.status, "value") else str(f.status),
        })

    return {
        "status": "ok",
        "events": events,
        "total": len(events),
    }


# ---------------------------------------------------------------------------
# TIER 3.2: False-Positive Rate Analytics
# ---------------------------------------------------------------------------


@router.get("/false-positive-rate")
async def false_positive_rate(
    scanner: Optional[str] = Query(None),
    cwe_id: Optional[str] = Query(None),
    app_id: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """[V3] Get false-positive rate from analyst feedback.

    Breaks down FP rate by scanner, CWE, and overall. Supports
    filtering by scanner, CWE, app_id, or org_id.

    Query params:
        scanner: Filter by scanner name (e.g. 'semgrep')
        cwe_id: Filter by CWE (e.g. 'CWE-79')
        app_id: Filter by application
        org_id: Filter by organization
    """
    try:
        from core.brain_pipeline import get_fp_feedback_store

        store = get_fp_feedback_store()
        return store.get_fp_rate(
            scanner=scanner,
            cwe_id=cwe_id,
            app_id=app_id,
            org_id=org_id,
        )
    except (OSError, ValueError, RuntimeError) as e:
        return {
            "error": type(e).__name__,
            "total_feedback": 0,
            "false_positives": 0,
            "true_positives": 0,
            "fp_rate": 0.0,
            "by_scanner": [],
            "by_cwe": [],
        }


@router.get("/", summary="Analytics index", tags=["analytics"])
async def analytics_root_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return analytics overview for the org from the live AnalyticsDB."""
    try:
        overview = db.get_dashboard_overview()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"analytics overview failed: {exc}") from exc
    return {
        "router": "analytics",
        "org_id": org_id,
        **overview,
    }
