from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/pentagi", tags=["pentagi"])


class PentestRequest(BaseModel):
    name: str
    target: str
    type: str
    scope: str
    requested_by: str


class PentestUpdate(BaseModel):
    status: Optional[str] = None
    severity_found: Optional[str] = None
    findings_count: Optional[int] = None


_pentest_requests = [
    {
        "id": "1",
        "name": "Payment API Security Assessment",
        "target": "payment-api.fixops.com",
        "type": "web_application",
        "scope": "Full API endpoints, authentication, authorization",
        "status": "completed",
        "severity_found": "high",
        "findings_count": 12,
        "created_at": "2024-11-15T10:00:00Z",
        "started_at": "2024-11-16T09:00:00Z",
        "completed_at": "2024-11-18T17:00:00Z",
        "requested_by": "sarah.chen@fixops.io",
    },
    {
        "id": "2",
        "name": "Infrastructure Penetration Test",
        "target": "prod-cluster.fixops.com",
        "type": "infrastructure",
        "scope": "Network segmentation, firewall rules, cloud IAM",
        "status": "in_progress",
        "severity_found": None,
        "findings_count": 0,
        "created_at": "2024-11-20T14:30:00Z",
        "started_at": "2024-11-21T08:00:00Z",
        "completed_at": None,
        "requested_by": "mike.johnson@fixops.io",
    },
    {
        "id": "3",
        "name": "Mobile App Security Review",
        "target": "FixOps Mobile v2.1",
        "type": "mobile_application",
        "scope": "iOS and Android apps, API communication, data storage",
        "status": "pending",
        "severity_found": None,
        "findings_count": 0,
        "created_at": "2024-11-22T09:15:00Z",
        "started_at": None,
        "completed_at": None,
        "requested_by": "lisa.wong@fixops.io",
    },
    {
        "id": "4",
        "name": "Admin Panel Security Audit",
        "target": "admin.fixops.com",
        "type": "web_application",
        "scope": "Authentication, authorization, RBAC, audit logging",
        "status": "completed",
        "severity_found": "critical",
        "findings_count": 8,
        "created_at": "2024-11-10T11:00:00Z",
        "started_at": "2024-11-11T09:00:00Z",
        "completed_at": "2024-11-13T16:00:00Z",
        "requested_by": "david.kim@fixops.io",
    },
    {
        "id": "5",
        "name": "API Gateway Security Assessment",
        "target": "gateway.fixops.com",
        "type": "api",
        "scope": "Rate limiting, authentication, input validation",
        "status": "scheduled",
        "severity_found": None,
        "findings_count": 0,
        "created_at": "2024-11-23T15:45:00Z",
        "started_at": None,
        "completed_at": None,
        "requested_by": "emma.davis@fixops.io",
    },
]


@router.get("/requests")
async def list_pentest_requests() -> dict[str, Any]:
    """List all penetration testing requests."""
    return {
        "requests": _pentest_requests,
        "summary": {
            "total": len(_pentest_requests),
            "pending": sum(1 for r in _pentest_requests if r["status"] == "pending"),
            "in_progress": sum(
                1 for r in _pentest_requests if r["status"] == "in_progress"
            ),
            "completed": sum(
                1 for r in _pentest_requests if r["status"] == "completed"
            ),
            "scheduled": sum(
                1 for r in _pentest_requests if r["status"] == "scheduled"
            ),
        },
    }


@router.get("/requests/{request_id}")
async def get_pentest_request(request_id: str) -> dict[str, Any]:
    """Get a specific penetration testing request."""
    for req in _pentest_requests:
        if req["id"] == request_id:
            return req
    raise HTTPException(status_code=404, detail="Pentest request not found")


@router.post("/requests")
async def create_pentest_request(request: PentestRequest) -> dict[str, Any]:
    """Create a new penetration testing request."""
    new_request = {
        "id": str(len(_pentest_requests) + 1),
        "name": request.name,
        "target": request.target,
        "type": request.type,
        "scope": request.scope,
        "status": "pending",
        "severity_found": None,
        "findings_count": 0,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "started_at": None,
        "completed_at": None,
        "requested_by": request.requested_by,
    }
    _pentest_requests.append(new_request)
    return new_request


@router.patch("/requests/{request_id}")
async def update_pentest_request(
    request_id: str, update: PentestUpdate
) -> dict[str, Any]:
    """Update a penetration testing request."""
    for req in _pentest_requests:
        if req["id"] == request_id:
            if update.status:
                req["status"] = update.status
                if update.status == "in_progress" and not req["started_at"]:
                    req["started_at"] = datetime.utcnow().isoformat() + "Z"
                elif update.status == "completed" and not req["completed_at"]:
                    req["completed_at"] = datetime.utcnow().isoformat() + "Z"
            if update.severity_found:
                req["severity_found"] = update.severity_found
            if update.findings_count is not None:
                req["findings_count"] = update.findings_count
            return req
    raise HTTPException(status_code=404, detail="Pentest request not found")


@router.delete("/requests/{request_id}")
async def delete_pentest_request(request_id: str) -> dict[str, Any]:
    """Delete a penetration testing request."""
    for i, req in enumerate(_pentest_requests):
        if req["id"] == request_id:
            deleted = _pentest_requests.pop(i)
            return {"message": "Pentest request deleted", "request": deleted}
    raise HTTPException(status_code=404, detail="Pentest request not found")


__all__ = ["router"]
