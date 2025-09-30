"""
Incidents API endpoints with performance optimization
Security incident management with hot path optimization
"""

import time
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from src.db.session import get_db
from src.core.security import get_current_user, require_permission
from src.models.security_sqlite import SecurityIncident, SecurityFinding, Service, IncidentStatus
from src.services.correlation_engine import correlation_engine
from src.services.policy_engine import policy_engine, PolicyContext
from src.services.fix_engine import fix_engine
from src.utils.logger import log_security_event, PerformanceLogger

logger = structlog.get_logger()
router = APIRouter()


@router.get("/", tags=["hot-path"])
async def list_incidents(
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    service_id: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None)
) -> Dict[str, Any]:
    """
    List security incidents with advanced filtering
    Hot path optimized for dashboard queries
    """
    start_time = time.perf_counter()
    
    try:
        # Build query with filters
        query = select(SecurityIncident).where(SecurityIncident.is_active == True)
        
        if status:
            query = query.where(SecurityIncident.status == status)
        if severity:
            query = query.where(SecurityIncident.severity == severity)
        if service_id:
            query = query.where(SecurityIncident.service_id == service_id)
        if assigned_to:
            query = query.where(SecurityIncident.assigned_to == assigned_to)
        
        # Add pagination
        query = query.offset(skip).limit(limit).order_by(SecurityIncident.created_at.desc())
        
        # Execute query
        result = await db.execute(query)
        incidents = result.scalars().all()
        
        # Get total count for pagination
        count_query = select(func.count(SecurityIncident.id)).where(SecurityIncident.is_active == True)
        if status:
            count_query = count_query.where(SecurityIncident.status == status)
        if severity:
            count_query = count_query.where(SecurityIncident.severity == severity)
        if service_id:
            count_query = count_query.where(SecurityIncident.service_id == service_id)
        if assigned_to:
            count_query = count_query.where(SecurityIncident.assigned_to == assigned_to)
        
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0
        
        # Convert to dict for response
        incident_dicts = [incident.to_dict() for incident in incidents]
        
        # Log performance
        latency_us = (time.perf_counter() - start_time) * 1_000_000
        PerformanceLogger.log_hot_path_performance(
            "incidents_list",
            latency_us,
            user_id=current_user.get("sub"),
            additional_context={"incident_count": len(incidents), "total": total}
        )
        
        return {
            "incidents": incident_dicts,
            "total": total,
            "page": skip // limit + 1,
            "size": limit,
            "pages": (total + limit - 1) // limit
        }
        
    except Exception as e:
        logger.error(f"Failed to list incidents: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve incidents")


@router.post("/", tags=["hot-path"])
async def create_incident(
    incident_data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("incident.create"))
) -> Dict[str, Any]:
    """
    Create new security incident with automated workflow
    Hot path optimized for rapid incident creation
    """
    start_time = time.perf_counter()
    
    try:
        # Create incident
        incident = SecurityIncident(
            title=incident_data["title"],
            description=incident_data["description"],
            severity=incident_data["severity"],
            incident_type=incident_data.get("incident_type", "security"),
            service_id=incident_data.get("service_id"),
            business_impact=incident_data.get("business_impact"),
            reporter=current_user.get("email"),
            detected_at=datetime.utcnow(),
            related_findings=incident_data.get("related_findings", []),
            created_by=current_user.get("sub")
        )
        
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        
        # Background processing for performance
        background_tasks.add_task(
            process_incident_creation,
            incident.id,
            current_user.get("sub")
        )
        
        # Log security event
        await log_security_event(
            action="incident_created",
            user_id=current_user.get("sub"),
            resource="incident",
            resource_id=incident.id,
            details={
                "severity": incident.severity,
                "type": incident.incident_type,
                "service_id": incident.service_id
            }
        )
        
        # Log performance
        latency_us = (time.perf_counter() - start_time) * 1_000_000
        PerformanceLogger.log_hot_path_performance(
            "incident_creation",
            latency_us,
            user_id=current_user.get("sub"),
            additional_context={"incident_id": incident.id}
        )
        
        return incident.to_dict()
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to create incident: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create incident")


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("incident.read"))
) -> Dict[str, Any]:
    """Get incident details with related findings and fix suggestions"""
    
    try:
        # Get incident
        result = await db.execute(
            select(SecurityIncident).where(
                and_(
                    SecurityIncident.id == incident_id,
                    SecurityIncident.is_active == True
                )
            )
        )
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        incident_dict = incident.to_dict()
        
        # Get related findings if any
        if incident.related_findings:
            findings_result = await db.execute(
                select(SecurityFinding).where(
                    SecurityFinding.id.in_(incident.related_findings)
                )
            )
            findings = findings_result.scalars().all()
            incident_dict["related_findings_details"] = [f.to_dict() for f in findings]
        
        # Get service details if service_id exists
        if incident.service_id:
            service_result = await db.execute(
                select(Service).where(Service.id == incident.service_id)
            )
            service = service_result.scalar_one_or_none()
            if service:
                incident_dict["service_details"] = service.to_dict()
        
        return incident_dict
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve incident")


@router.put("/{incident_id}")
async def update_incident(
    incident_id: str,
    incident_data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("incident.update"))
) -> Dict[str, Any]:
    """Update incident with workflow automation"""
    
    try:
        # Get existing incident
        result = await db.execute(
            select(SecurityIncident).where(
                and_(
                    SecurityIncident.id == incident_id,
                    SecurityIncident.is_active == True
                )
            )
        )
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Track status changes for workflow
        old_status = incident.status
        
        # Update fields
        update_fields = [
            "title", "description", "severity", "status", "business_impact",
            "assigned_to", "resolution_summary", "root_cause", "lessons_learned"
        ]
        
        for field in update_fields:
            if field in incident_data:
                setattr(incident, field, incident_data[field])
        
        # Set resolution timestamp if status changed to resolved
        if (old_status != "resolved" and 
            incident_data.get("status") == "resolved"):
            incident.resolved_at = datetime.utcnow()
        
        incident.modified_by = current_user.get("sub")
        
        await db.commit()
        
        # Background workflow processing
        if old_status != incident.status:
            background_tasks.add_task(
                process_incident_status_change,
                incident.id,
                old_status,
                incident.status,
                current_user.get("sub")
            )
        
        # Log security event
        await log_security_event(
            action="incident_updated",
            user_id=current_user.get("sub"),
            resource="incident",
            resource_id=incident.id,
            details={
                "old_status": old_status,
                "new_status": incident.status,
                "changes": list(incident_data.keys())
            }
        )
        
        return incident.to_dict()
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to update incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update incident")


@router.post("/{incident_id}/assign")
async def assign_incident(
    incident_id: str,
    assignee_data: Dict[str, str],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("incident.update"))
) -> Dict[str, Any]:
    """Assign incident to user"""
    
    try:
        # Get incident
        result = await db.execute(
            select(SecurityIncident).where(
                and_(
                    SecurityIncident.id == incident_id,
                    SecurityIncident.is_active == True
                )
            )
        )
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        old_assignee = incident.assigned_to
        incident.assigned_to = assignee_data["assignee_email"]
        incident.status = "investigating"
        incident.modified_by = current_user.get("sub")
        
        await db.commit()
        
        # Background notification
        background_tasks.add_task(
            notify_incident_assignment,
            incident.id,
            old_assignee,
            incident.assigned_to,
            current_user.get("email")
        )
        
        # Log security event
        await log_security_event(
            action="incident_assigned",
            user_id=current_user.get("sub"),
            resource="incident",
            resource_id=incident.id,
            details={
                "old_assignee": old_assignee,
                "new_assignee": incident.assigned_to
            }
        )
        
        return {"message": "Incident assigned successfully", "incident": incident.to_dict()}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to assign incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to assign incident")


@router.post("/{incident_id}/resolve")
async def resolve_incident(
    incident_id: str,
    resolution_data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("incident.update"))
) -> Dict[str, Any]:
    """Resolve incident with resolution details"""
    
    try:
        # Get incident
        result = await db.execute(
            select(SecurityIncident).where(
                and_(
                    SecurityIncident.id == incident_id,
                    SecurityIncident.is_active == True
                )
            )
        )
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Update incident
        incident.status = "resolved"
        incident.resolved_at = datetime.utcnow()
        incident.resolution_summary = resolution_data.get("resolution_summary")
        incident.root_cause = resolution_data.get("root_cause")
        incident.lessons_learned = resolution_data.get("lessons_learned")
        incident.modified_by = current_user.get("sub")
        
        await db.commit()
        
        # Background processing
        background_tasks.add_task(
            process_incident_resolution,
            incident.id,
            current_user.get("sub")
        )
        
        # Log security event
        await log_security_event(
            action="incident_resolved",
            user_id=current_user.get("sub"),
            resource="incident",
            resource_id=incident.id,
            details={
                "resolution_summary": resolution_data.get("resolution_summary"),
                "root_cause": resolution_data.get("root_cause")
            }
        )
        
        return {"message": "Incident resolved successfully", "incident": incident.to_dict()}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to resolve incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to resolve incident")


@router.post("/{incident_id}/escalate")
async def escalate_incident(
    incident_id: str,
    escalation_data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("incident.update"))
) -> Dict[str, Any]:
    """Escalate incident to higher severity or management"""
    
    try:
        # Get incident
        result = await db.execute(
            select(SecurityIncident).where(
                and_(
                    SecurityIncident.id == incident_id,
                    SecurityIncident.is_active == True
                )
            )
        )
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Update incident severity and status
        old_severity = incident.severity
        escalation_level = escalation_data.get("level", "management")
        
        if escalation_level == "critical":
            incident.severity = "critical"
        
        incident.status = "investigating"
        incident.business_impact = escalation_data.get("business_impact", incident.business_impact)
        incident.modified_by = current_user.get("sub")
        
        await db.commit()
        
        # Background escalation processing
        background_tasks.add_task(
            process_incident_escalation,
            incident.id,
            escalation_level,
            escalation_data.get("reason"),
            current_user.get("sub")
        )
        
        # Log security event
        await log_security_event(
            action="incident_escalated",
            user_id=current_user.get("sub"),
            resource="incident",
            resource_id=incident.id,
            details={
                "old_severity": old_severity,
                "new_severity": incident.severity,
                "escalation_level": escalation_level,
                "reason": escalation_data.get("reason")
            }
        )
        
        return {"message": "Incident escalated successfully", "incident": incident.to_dict()}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to escalate incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to escalate incident")


@router.get("/{incident_id}/fixes")
async def get_incident_fixes(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("incident.read"))
) -> Dict[str, Any]:
    """Get automated fix suggestions for incident"""
    
    try:
        # Get incident with related findings
        result = await db.execute(
            select(SecurityIncident).where(
                and_(
                    SecurityIncident.id == incident_id,
                    SecurityIncident.is_active == True
                )
            )
        )
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        fix_suggestions = []
        
        # Get fix suggestions for related findings
        if incident.related_findings:
            findings_result = await db.execute(
                select(SecurityFinding).where(
                    SecurityFinding.id.in_(incident.related_findings)
                )
            )
            findings = findings_result.scalars().all()
            
            # Get service details for context
            service = None
            if incident.service_id:
                service_result = await db.execute(
                    select(Service).where(Service.id == incident.service_id)
                )
                service = service_result.scalar_one_or_none()
            
            # Generate fix suggestions for each finding
            for finding in findings:
                suggestions = await fix_engine.generate_fix_suggestions(finding, service)
                for suggestion in suggestions:
                    fix_suggestions.append({
                        "finding_id": finding.id,
                        "finding_title": finding.title,
                        **suggestion.__dict__
                    })
        
        return {
            "incident_id": incident_id,
            "fix_suggestions": fix_suggestions,
            "total_suggestions": len(fix_suggestions)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get fixes for incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve fix suggestions")


# Background task functions
async def process_incident_creation(incident_id: str, user_id: str):
    """Background processing for new incident creation"""
    try:
        # Auto-correlation with existing incidents
        # Auto-assignment based on rules
        # Notification to relevant teams
        logger.info(f"Processing incident creation: {incident_id}")
    except Exception as e:
        logger.error(f"Failed to process incident creation {incident_id}: {str(e)}")


async def process_incident_status_change(incident_id: str, old_status: str, new_status: str, user_id: str):
    """Background processing for incident status changes"""
    try:
        # Workflow automation
        # Notifications
        # Metrics updates
        logger.info(f"Processing status change for incident {incident_id}: {old_status} -> {new_status}")
    except Exception as e:
        logger.error(f"Failed to process status change for incident {incident_id}: {str(e)}")


async def notify_incident_assignment(incident_id: str, old_assignee: Optional[str], new_assignee: str, assigner: str):
    """Notify users of incident assignment"""
    try:
        # Send notifications
        logger.info(f"Notifying assignment for incident {incident_id}: {new_assignee}")
    except Exception as e:
        logger.error(f"Failed to notify assignment for incident {incident_id}: {str(e)}")


async def process_incident_resolution(incident_id: str, user_id: str):
    """Process incident resolution"""
    try:
        # Update metrics
        # Generate reports
        # Close related findings if applicable
        logger.info(f"Processing resolution for incident {incident_id}")
    except Exception as e:
        logger.error(f"Failed to process resolution for incident {incident_id}: {str(e)}")


async def process_incident_escalation(incident_id: str, level: str, reason: Optional[str], user_id: str):
    """Process incident escalation"""
    try:
        # Notify management
        # Update priority
        # Trigger additional monitoring
        logger.info(f"Processing escalation for incident {incident_id}: {level}")
    except Exception as e:
        logger.error(f"Failed to process escalation for incident {incident_id}: {str(e)}")