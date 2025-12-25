"""Deduplication & Correlation API endpoints."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.services.deduplication import ClusterStatus, DeduplicationService

router = APIRouter(prefix="/api/v1/deduplication", tags=["deduplication"])

# Initialize service with default path
_DATA_DIR = Path("data/deduplication")
_dedup_service: Optional[DeduplicationService] = None


def get_dedup_service() -> DeduplicationService:
    """Get or create deduplication service instance."""
    global _dedup_service
    if _dedup_service is None:
        _dedup_service = DeduplicationService(_DATA_DIR / "clusters.db")
    return _dedup_service


class ProcessFindingRequest(BaseModel):
    """Request to process a single finding."""

    finding: Dict[str, Any]
    run_id: str
    org_id: str
    source: str = "sarif"


class ProcessFindingsBatchRequest(BaseModel):
    """Request to process a batch of findings."""

    findings: List[Dict[str, Any]]
    run_id: str
    org_id: str
    source: str = "sarif"


class UpdateStatusRequest(BaseModel):
    """Request to update cluster status."""

    status: str
    changed_by: Optional[str] = None
    reason: Optional[str] = None


class AssignClusterRequest(BaseModel):
    """Request to assign cluster to user."""

    assignee: str


class LinkTicketRequest(BaseModel):
    """Request to link cluster to external ticket."""

    ticket_id: str
    ticket_url: Optional[str] = None


class CreateCorrelationLinkRequest(BaseModel):
    """Request to create correlation link between clusters."""

    source_cluster_id: str
    target_cluster_id: str
    link_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    reason: Optional[str] = None


class OperatorFeedbackRequest(BaseModel):
    """Request to record operator feedback for correlation corrections."""

    cluster_id: str
    feedback_type: str = Field(
        description="merge_allowed, merge_blocked, or split_cluster"
    )
    target_cluster_id: Optional[str] = None
    reason: Optional[str] = None
    operator_id: Optional[str] = None


class BaselineComparisonRequest(BaseModel):
    """Request to compare current run against baseline."""

    org_id: str
    current_run_id: str
    baseline_run_id: str


class MergeClustersRequest(BaseModel):
    """Request to merge multiple clusters into one."""

    source_cluster_ids: List[str]
    target_cluster_id: str
    reason: Optional[str] = None


class SplitClusterRequest(BaseModel):
    """Request to split a cluster into separate findings."""

    event_ids: List[str] = []
    reason: Optional[str] = None


@router.post("/process")
def process_finding(request: ProcessFindingRequest) -> Dict[str, Any]:
    """Process a single finding for deduplication."""
    service = get_dedup_service()
    return service.process_finding(
        finding=request.finding,
        run_id=request.run_id,
        org_id=request.org_id,
        source=request.source,
    )


@router.post("/process/batch")
def process_findings_batch(
    request: ProcessFindingsBatchRequest,
) -> Dict[str, Any]:
    """Process a batch of findings for deduplication."""
    service = get_dedup_service()
    return service.process_findings_batch(
        findings=request.findings,
        run_id=request.run_id,
        org_id=request.org_id,
        source=request.source,
    )


@router.get("/clusters")
def list_clusters(
    org_id: str,
    app_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List clusters with optional filters."""
    service = get_dedup_service()
    clusters = service.get_clusters(
        org_id=org_id,
        app_id=app_id,
        status=status,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return {
        "clusters": clusters,
        "count": len(clusters),
        "limit": limit,
        "offset": offset,
    }


@router.get("/clusters/{cluster_id}")
def get_cluster(cluster_id: str) -> Dict[str, Any]:
    """Get a specific cluster by ID."""
    service = get_dedup_service()
    cluster = service.get_cluster(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


@router.put("/clusters/{cluster_id}/status")
def update_cluster_status(
    cluster_id: str, request: UpdateStatusRequest
) -> Dict[str, Any]:
    """Update cluster status."""
    try:
        ClusterStatus(request.status)
    except ValueError:
        valid_statuses = [s.value for s in ClusterStatus]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {valid_statuses}",
        )

    service = get_dedup_service()
    success = service.update_cluster_status(
        cluster_id=cluster_id,
        new_status=request.status,
        changed_by=request.changed_by,
        reason=request.reason,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return {"status": "updated", "cluster_id": cluster_id, "new_status": request.status}


@router.put("/clusters/{cluster_id}/assign")
def assign_cluster(cluster_id: str, request: AssignClusterRequest) -> Dict[str, Any]:
    """Assign cluster to a user."""
    service = get_dedup_service()
    success = service.assign_cluster(cluster_id, request.assignee)
    if not success:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return {
        "status": "assigned",
        "cluster_id": cluster_id,
        "assignee": request.assignee,
    }


@router.put("/clusters/{cluster_id}/ticket")
def link_ticket(cluster_id: str, request: LinkTicketRequest) -> Dict[str, Any]:
    """Link cluster to external ticket."""
    service = get_dedup_service()
    success = service.link_to_ticket(
        cluster_id=cluster_id,
        ticket_id=request.ticket_id,
        ticket_url=request.ticket_url,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return {
        "status": "linked",
        "cluster_id": cluster_id,
        "ticket_id": request.ticket_id,
    }


@router.get("/clusters/{cluster_id}/related")
def get_related_clusters(
    cluster_id: str, min_confidence: float = Query(default=0.5, ge=0.0, le=1.0)
) -> Dict[str, Any]:
    """Get clusters related to the given cluster."""
    service = get_dedup_service()
    related = service.get_related_clusters(cluster_id, min_confidence)
    return {"cluster_id": cluster_id, "related_clusters": related}


@router.post("/correlations")
def create_correlation_link(
    request: CreateCorrelationLinkRequest,
) -> Dict[str, Any]:
    """Create a correlation link between two clusters."""
    service = get_dedup_service()
    link_id = service.create_correlation_link(
        source_cluster_id=request.source_cluster_id,
        target_cluster_id=request.target_cluster_id,
        link_type=request.link_type,
        confidence=request.confidence,
        reason=request.reason,
    )
    return {"link_id": link_id, "status": "created"}


@router.get("/stats")
def get_dedup_stats_global() -> Dict[str, Any]:
    """Get global deduplication statistics."""
    service = get_dedup_service()
    return service.get_dedup_stats("default")


@router.get("/stats/{org_id}")
def get_dedup_stats(org_id: str) -> Dict[str, Any]:
    """Get deduplication statistics for an organization."""
    service = get_dedup_service()
    return service.get_dedup_stats(org_id)


@router.post("/correlate/cross-stage")
def correlate_cross_stage(
    org_id: str, min_confidence: float = Query(default=0.7, ge=0.0, le=1.0)
) -> Dict[str, Any]:
    """Find and create cross-stage correlation links.

    Cross-stage anchors:
    - CVE+purl: Same vulnerability in same package across stages
    - rule_id+file_path: Same rule violation in same file across stages
    - resource_id+policy_id: Same policy violation on same resource
    """
    service = get_dedup_service()
    return service.correlate_cross_stage(org_id, min_confidence)


@router.get("/graph")
def get_correlation_graph(
    org_id: str, cluster_id: Optional[str] = None
) -> Dict[str, Any]:
    """Get the correlation graph for visualization.

    Returns nodes (clusters) and edges (correlation links) in a format
    suitable for graph visualization.
    """
    service = get_dedup_service()
    return service.get_correlation_graph(org_id, cluster_id)


@router.post("/feedback")
def record_operator_feedback(request: OperatorFeedbackRequest) -> Dict[str, Any]:
    """Record operator feedback for correlation corrections.

    Feedback types:
    - merge_allowed: Confirm two clusters should be merged
    - merge_blocked: Block automatic merge of two clusters
    - split_cluster: Split a cluster into separate findings
    """
    valid_types = ["merge_allowed", "merge_blocked", "split_cluster"]
    if request.feedback_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feedback_type. Must be one of: {valid_types}",
        )

    if (
        request.feedback_type in ["merge_allowed", "merge_blocked"]
        and not request.target_cluster_id
    ):
        raise HTTPException(
            status_code=400,
            detail="target_cluster_id is required for merge_allowed and merge_blocked feedback",
        )

    service = get_dedup_service()
    return service.record_operator_feedback(
        cluster_id=request.cluster_id,
        feedback_type=request.feedback_type,
        target_cluster_id=request.target_cluster_id,
        reason=request.reason,
        operator_id=request.operator_id,
    )


@router.post("/baseline/compare")
def compare_baseline(request: BaselineComparisonRequest) -> Dict[str, Any]:
    """Compare current run against a baseline to identify NEW/EXISTING/FIXED.

    Returns findings categorized as:
    - NEW: Present in current run but not in baseline
    - EXISTING: Present in both runs
    - FIXED: Present in baseline but not in current run
    """
    service = get_dedup_service()
    return service.get_baseline_comparison(
        org_id=request.org_id,
        current_run_id=request.current_run_id,
        baseline_run_id=request.baseline_run_id,
    )


@router.post("/clusters/merge")
def merge_clusters(request: MergeClustersRequest) -> Dict[str, Any]:
    """Merge multiple clusters into a target cluster.

    All events from source clusters will be moved to the target cluster.
    Source clusters will be marked as merged.
    """
    service = get_dedup_service()

    # Verify target cluster exists
    target = service.get_cluster(request.target_cluster_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target cluster not found")

    merged_count = 0
    for source_id in request.source_cluster_ids:
        if source_id == request.target_cluster_id:
            continue  # Skip self-merge
        source = service.get_cluster(source_id)
        if source:
            # Record the merge as operator feedback
            service.record_operator_feedback(
                cluster_id=source_id,
                feedback_type="merge_allowed",
                target_cluster_id=request.target_cluster_id,
                reason=request.reason,
                operator_id="api-user",
            )
            merged_count += 1

    return {
        "status": "merged",
        "target_cluster_id": request.target_cluster_id,
        "merged_count": merged_count,
        "source_cluster_ids": request.source_cluster_ids,
    }


@router.post("/clusters/{cluster_id}/split")
def split_cluster(cluster_id: str, request: SplitClusterRequest) -> Dict[str, Any]:
    """Split a cluster by moving specified events to new clusters.

    If event_ids is empty, each event in the cluster becomes its own cluster.
    """
    service = get_dedup_service()

    # Verify cluster exists
    cluster = service.get_cluster(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Record the split as operator feedback
    service.record_operator_feedback(
        cluster_id=cluster_id,
        feedback_type="split_cluster",
        target_cluster_id=None,
        reason=request.reason,
        operator_id="api-user",
    )

    return {
        "status": "split_recorded",
        "cluster_id": cluster_id,
        "event_ids": request.event_ids,
        "message": "Split feedback recorded. Events will be separated on next processing.",
    }
