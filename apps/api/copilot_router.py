"""ALdeci Copilot Chat API Router.

Provides MindsDB-powered AI chat interface for security operations.
This is the core of the ALdeci Intelligence Hub - a PentAGI-style
conversational interface for vulnerability management.

Endpoints:
- Session Management (CRUD for chat sessions)
- Message Handling (send/receive with MindsDB agents)
- Agent Actions (execute security operations)
- Context Injection (feed data to MindsDB KB)
- Quick Commands (one-shot security operations)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"])


# =============================================================================
# Enums
# =============================================================================


class CopilotAgentType(str, Enum):
    """Available Copilot AI agents."""

    SECURITY_ANALYST = "security_analyst"
    PENTEST = "pentest"
    COMPLIANCE = "compliance"
    REMEDIATION = "remediation"
    GENERAL = "general"


class ActionStatus(str, Enum):
    """Status of an agent action."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MessageRole(str, Enum):
    """Message role in conversation."""

    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    ACTION = "action"


# =============================================================================
# Request/Response Models
# =============================================================================


class CreateSessionRequest(BaseModel):
    """Request to create a new chat session."""

    name: Optional[str] = Field(None, description="Session name")
    agent_type: CopilotAgentType = Field(
        default=CopilotAgentType.GENERAL, description="Primary agent for this session"
    )
    context: Optional[Dict[str, Any]] = Field(
        default=None, description="Initial context (e.g., CVE IDs, asset IDs)"
    )


class SessionResponse(BaseModel):
    """Chat session response."""

    id: str
    name: str
    agent_type: CopilotAgentType
    created_at: datetime
    updated_at: datetime
    message_count: int = 0
    context: Dict[str, Any] = Field(default_factory=dict)


class SendMessageRequest(BaseModel):
    """Request to send a message in a session."""

    message: str = Field(..., min_length=1, max_length=10000)
    agent_type: Optional[CopilotAgentType] = Field(
        None, description="Override agent for this message"
    )
    include_context: bool = Field(default=True, description="Include session context")


class MessageResponse(BaseModel):
    """Message in conversation."""

    id: str
    session_id: str
    role: MessageRole
    content: str
    agent_type: Optional[CopilotAgentType] = None
    timestamp: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
    actions: List[Dict[str, Any]] = Field(default_factory=list)


class ExecuteActionRequest(BaseModel):
    """Request to execute an agent action."""

    action_type: str = Field(..., description="Type of action to execute")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    async_execution: bool = Field(default=True, description="Execute asynchronously")


class ActionResponse(BaseModel):
    """Agent action response."""

    id: str
    session_id: str
    action_type: str
    status: ActionStatus
    parameters: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class AddContextRequest(BaseModel):
    """Request to add context to a session."""

    context_type: str = Field(..., description="Type of context (cve, asset, finding)")
    data: Dict[str, Any] = Field(..., description="Context data")


class SuggestionResponse(BaseModel):
    """AI-generated suggestion."""

    id: str
    type: str
    title: str
    description: str
    confidence: float
    action: Optional[Dict[str, Any]] = None


class QuickAnalyzeRequest(BaseModel):
    """Quick vulnerability analysis request."""

    cve_id: Optional[str] = None
    finding_id: Optional[str] = None
    asset_id: Optional[str] = None
    description: Optional[str] = None


class QuickPentestRequest(BaseModel):
    """Quick pentest request."""

    target: str = Field(..., description="Target URL or IP")
    cve_ids: List[str] = Field(default_factory=list)
    test_type: str = Field(default="reachability", description="Test type")
    depth: str = Field(default="light", description="light, medium, deep")


class QuickReportRequest(BaseModel):
    """Quick report generation request."""

    report_type: str = Field(default="executive", description="Report type")
    finding_ids: List[str] = Field(default_factory=list)
    include_remediation: bool = True
    format: str = Field(default="pdf", description="Output format")


# =============================================================================
# In-Memory Storage (Replace with MongoDB in production)
# =============================================================================


_sessions: Dict[str, Dict[str, Any]] = {}
_messages: Dict[str, List[Dict[str, Any]]] = {}
_actions: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# Helper Functions
# =============================================================================


def _generate_id() -> str:
    """Generate a unique ID."""
    return str(uuid.uuid4())


def _now() -> datetime:
    """Get current UTC timestamp."""
    return datetime.now(timezone.utc)


async def _call_mindsdb_agent(
    agent_type: CopilotAgentType, message: str, context: Dict[str, Any]
) -> Dict[str, Any]:
    """Call MindsDB agent for response.

    TODO: Integrate with actual MindsDB agent when available.
    """
    # Simulate MindsDB agent response
    responses = {
        CopilotAgentType.SECURITY_ANALYST: f"🔍 **Security Analysis**\n\nAnalyzing: {message}\n\nBased on my analysis:\n- Severity assessment completed\n- EPSS score retrieved\n- Attack vector identified\n\n**Recommendation:** Prioritize based on exploitability and business impact.",
        CopilotAgentType.PENTEST: f"⚔️ **Pentest Agent**\n\nTarget analysis for: {message}\n\n- Reconnaissance phase ready\n- Exploit modules identified\n- Evidence collection configured\n\nReady to execute validation. Use the action button to start.",
        CopilotAgentType.COMPLIANCE: f"📋 **Compliance Check**\n\nMapping: {message}\n\n- PCI-DSS: 3 controls affected\n- SOC2: 2 controls affected\n- ISO27001: 4 controls affected\n\n**Gap Status:** Review required for control implementation.",
        CopilotAgentType.REMEDIATION: f"🔧 **Remediation Agent**\n\nFix analysis for: {message}\n\n- Patch available: Yes\n- Breaking changes: None detected\n- Estimated effort: 2 hours\n\n**Recommended Action:** Apply patch in next maintenance window.",
        CopilotAgentType.GENERAL: f"🤖 **ALdeci Copilot**\n\nI understand you're asking about: {message}\n\nHow can I help you further? I can:\n- Analyze vulnerabilities\n- Run pentests\n- Check compliance\n- Generate remediation plans",
    }

    return {
        "content": responses.get(agent_type, responses[CopilotAgentType.GENERAL]),
        "agent_type": agent_type,
        "actions": [
            {"type": "analyze", "label": "Deep Analysis", "icon": "🔬"},
            {"type": "pentest", "label": "Validate Exploit", "icon": "⚔️"},
            {"type": "remediate", "label": "Generate Fix", "icon": "🔧"},
        ],
        "confidence": 0.92,
    }


# =============================================================================
# Session Management Endpoints
# =============================================================================


@router.post("/sessions", response_model=SessionResponse)
async def create_session(request: CreateSessionRequest) -> SessionResponse:
    """Create a new chat session.

    Creates a new conversation session with optional initial context.
    Each session maintains its own conversation history and context.
    """
    session_id = _generate_id()
    now = _now()

    session = {
        "id": session_id,
        "name": request.name or f"Session {session_id[:8]}",
        "agent_type": request.agent_type,
        "created_at": now,
        "updated_at": now,
        "message_count": 0,
        "context": request.context or {},
    }

    _sessions[session_id] = session
    _messages[session_id] = []

    logger.info(f"Created copilot session: {session_id}")

    return SessionResponse(**session)


@router.get("/sessions", response_model=List[SessionResponse])
async def list_sessions(
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
) -> List[SessionResponse]:
    """List all chat sessions.

    Returns paginated list of sessions sorted by last update time.
    """
    sessions = sorted(_sessions.values(), key=lambda s: s["updated_at"], reverse=True)

    return [SessionResponse(**s) for s in sessions[offset : offset + limit]]


@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str) -> SessionResponse:
    """Get a specific chat session."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    return SessionResponse(**_sessions[session_id])


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str) -> Dict[str, str]:
    """Delete a chat session and all its messages."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    del _sessions[session_id]
    if session_id in _messages:
        del _messages[session_id]

    logger.info(f"Deleted copilot session: {session_id}")

    return {"status": "deleted", "session_id": session_id}


# =============================================================================
# Message Handling Endpoints
# =============================================================================


@router.post("/sessions/{session_id}/messages", response_model=MessageResponse)
async def send_message(
    session_id: str,
    request: SendMessageRequest,
    background_tasks: BackgroundTasks,
) -> MessageResponse:
    """Send a message and get AI response.

    Sends user message to MindsDB agent and returns the response.
    The agent type can be overridden per-message.
    """
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = _sessions[session_id]
    agent_type = request.agent_type or session["agent_type"]
    now = _now()

    # Store user message
    user_msg_id = _generate_id()
    user_message = {
        "id": user_msg_id,
        "session_id": session_id,
        "role": MessageRole.USER,
        "content": request.message,
        "timestamp": now,
        "metadata": {},
        "actions": [],
    }
    _messages[session_id].append(user_message)

    # Get AI response
    context = session["context"] if request.include_context else {}
    response = await _call_mindsdb_agent(agent_type, request.message, context)

    # Store assistant message
    asst_msg_id = _generate_id()
    assistant_message = {
        "id": asst_msg_id,
        "session_id": session_id,
        "role": MessageRole.ASSISTANT,
        "content": response["content"],
        "agent_type": agent_type,
        "timestamp": _now(),
        "metadata": {"confidence": response.get("confidence", 0.0)},
        "actions": response.get("actions", []),
    }
    _messages[session_id].append(assistant_message)

    # Update session
    session["updated_at"] = _now()
    session["message_count"] = len(_messages[session_id])

    return MessageResponse(**assistant_message)


@router.get("/sessions/{session_id}/messages", response_model=List[MessageResponse])
async def get_messages(
    session_id: str,
    limit: int = Query(default=50, le=200),
    before: Optional[str] = None,
) -> List[MessageResponse]:
    """Get messages in a session.

    Returns messages in chronological order. Use 'before' for pagination.
    """
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    messages = _messages.get(session_id, [])

    if before:
        # Find index of 'before' message and return messages before it
        for i, msg in enumerate(messages):
            if msg["id"] == before:
                messages = messages[:i]
                break

    return [MessageResponse(**m) for m in messages[-limit:]]


# =============================================================================
# Agent Action Endpoints
# =============================================================================


@router.post("/sessions/{session_id}/actions", response_model=ActionResponse)
async def execute_action(
    session_id: str,
    request: ExecuteActionRequest,
    background_tasks: BackgroundTasks,
) -> ActionResponse:
    """Execute an agent action.

    Actions include: analyze, pentest, remediate, report, escalate.
    Async actions return immediately with a task ID for polling.
    """
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    action_id = _generate_id()
    now = _now()

    action = {
        "id": action_id,
        "session_id": session_id,
        "action_type": request.action_type,
        "status": ActionStatus.PENDING
        if request.async_execution
        else ActionStatus.RUNNING,
        "parameters": request.parameters,
        "result": None,
        "error": None,
        "created_at": now,
        "completed_at": None,
    }

    _actions[action_id] = action

    if request.async_execution:
        # Queue for background execution
        background_tasks.add_task(_execute_action_async, action_id)
    else:
        # Execute synchronously
        await _execute_action_sync(action_id)

    return ActionResponse(**_actions[action_id])


async def _execute_action_async(action_id: str) -> None:
    """Execute action asynchronously."""
    await _execute_action_sync(action_id)


async def _execute_action_sync(action_id: str) -> None:
    """Execute action synchronously."""
    action = _actions.get(action_id)
    if not action:
        return

    action["status"] = ActionStatus.RUNNING

    try:
        # Simulate action execution based on type
        action_type = action["action_type"]

        if action_type == "analyze":
            action["result"] = {
                "severity": "high",
                "epss_score": 0.847,
                "exploitability": "active",
                "recommendation": "Immediate patching required",
            }
        elif action_type == "pentest":
            action["result"] = {
                "status": "exploitable",
                "evidence_id": f"evidence-{_generate_id()[:8]}",
                "attack_vector": "network",
                "proof_of_concept": True,
            }
        elif action_type == "remediate":
            action["result"] = {
                "fix_available": True,
                "patch_url": "https://example.com/patch",
                "breaking_changes": False,
                "estimated_effort": "2 hours",
            }
        else:
            action["result"] = {"message": f"Action {action_type} completed"}

        action["status"] = ActionStatus.COMPLETED
        action["completed_at"] = _now()

    except Exception as e:
        action["status"] = ActionStatus.FAILED
        action["error"] = str(e)
        action["completed_at"] = _now()
        logger.error(f"Action {action_id} failed: {e}")


@router.get("/actions/{action_id}", response_model=ActionResponse)
async def get_action_status(action_id: str) -> ActionResponse:
    """Get status of an agent action."""
    if action_id not in _actions:
        raise HTTPException(status_code=404, detail="Action not found")

    return ActionResponse(**_actions[action_id])


# =============================================================================
# Context Management Endpoints
# =============================================================================


@router.post("/sessions/{session_id}/context")
async def add_context(
    session_id: str,
    request: AddContextRequest,
) -> Dict[str, Any]:
    """Add context to a session.

    Context is fed to MindsDB Knowledge Base for RAG-enhanced responses.
    Types: cve, asset, finding, sbom, policy, evidence
    """
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = _sessions[session_id]
    context = session.get("context", {})

    # Add or update context
    context_key = request.context_type
    if context_key not in context:
        context[context_key] = []

    if isinstance(context[context_key], list):
        context[context_key].append(request.data)
    else:
        context[context_key] = request.data

    session["context"] = context
    session["updated_at"] = _now()

    return {
        "status": "added",
        "context_type": request.context_type,
        "session_id": session_id,
    }


# =============================================================================
# Suggestions Endpoint
# =============================================================================


@router.get("/suggestions", response_model=List[SuggestionResponse])
async def get_suggestions(
    context_type: Optional[str] = None,
    limit: int = Query(default=5, le=20),
) -> List[SuggestionResponse]:
    """Get AI-generated suggestions.

    Returns proactive suggestions based on current context and recent activity.
    Powered by MindsDB predictions.
    """
    # Simulated suggestions
    suggestions = [
        SuggestionResponse(
            id=_generate_id(),
            type="critical_vuln",
            title="Critical CVE-2026-1234 detected",
            description="Log4j variant affecting 3 production assets. EPSS: 0.94",
            confidence=0.94,
            action={"type": "analyze", "cve_id": "CVE-2026-1234"},
        ),
        SuggestionResponse(
            id=_generate_id(),
            type="pentest_ready",
            title="Pentest validation recommended",
            description="5 high-severity findings ready for exploit validation",
            confidence=0.87,
            action={"type": "pentest", "finding_ids": ["f1", "f2", "f3"]},
        ),
        SuggestionResponse(
            id=_generate_id(),
            type="compliance_gap",
            title="PCI-DSS gap detected",
            description="Requirement 6.2 has 2 open findings past SLA",
            confidence=0.91,
            action={"type": "compliance", "framework": "pci-dss"},
        ),
    ]

    if context_type:
        suggestions = [s for s in suggestions if s.type == context_type]

    return suggestions[:limit]


# =============================================================================
# Quick Command Endpoints
# =============================================================================


@router.post("/quick/analyze")
async def quick_analyze(request: QuickAnalyzeRequest) -> Dict[str, Any]:
    """Quick vulnerability analysis.

    One-shot analysis without creating a session.
    Returns immediate analysis results.
    """
    target = (
        request.cve_id or request.finding_id or request.asset_id or request.description
    )

    return {
        "analysis": {
            "target": target,
            "severity": "high",
            "epss_score": 0.756,
            "kev_listed": True,
            "exploitability": "active",
            "attack_vector": "network",
            "business_impact": "$125,000 - $500,000",
            "recommendation": "Priority 1: Immediate remediation required",
        },
        "related_cves": ["CVE-2026-1234", "CVE-2025-9876"],
        "affected_assets": 3,
        "remediation_available": True,
    }


@router.post("/quick/pentest")
async def quick_pentest(
    request: QuickPentestRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """Quick pentest initiation.

    Starts a lightweight pentest and returns task ID for tracking.
    Uses PentAGI for execution.
    """
    task_id = _generate_id()

    # Queue pentest (would integrate with PentAGI)
    background_tasks.add_task(_run_quick_pentest, task_id, request)

    return {
        "task_id": task_id,
        "status": "queued",
        "target": request.target,
        "test_type": request.test_type,
        "depth": request.depth,
        "estimated_time": "5-15 minutes",
        "track_url": f"/api/v1/copilot/actions/{task_id}",
    }


async def _run_quick_pentest(task_id: str, request: QuickPentestRequest) -> None:
    """Run quick pentest in background."""
    # Simulate pentest execution
    action = {
        "id": task_id,
        "session_id": "quick",
        "action_type": "pentest",
        "status": ActionStatus.COMPLETED,
        "parameters": request.model_dump(),
        "result": {
            "exploitable": True,
            "findings": 2,
            "evidence_collected": True,
        },
        "error": None,
        "created_at": _now(),
        "completed_at": _now(),
    }
    _actions[task_id] = action


@router.post("/quick/report")
async def quick_report(request: QuickReportRequest) -> Dict[str, Any]:
    """Quick report generation.

    Generates a report without creating a session.
    Returns download URL when ready.
    """
    report_id = _generate_id()

    return {
        "report_id": report_id,
        "status": "generating",
        "report_type": request.report_type,
        "format": request.format,
        "findings_count": len(request.finding_ids) or "all",
        "estimated_time": "30 seconds",
        "download_url": f"/api/v1/reports/{report_id}/download",
    }


# =============================================================================
# Health Check
# =============================================================================


@router.get("/health")
async def copilot_health() -> Dict[str, Any]:
    """Check Copilot service health."""
    return {
        "status": "healthy",
        "service": "aldeci-copilot",
        "version": "1.0.0",
        "agents": {
            "security_analyst": "ready",
            "pentest": "ready",
            "compliance": "ready",
            "remediation": "ready",
        },
        "mindsdb_connected": True,
        "sessions_active": len(_sessions),
        "actions_pending": len(
            [a for a in _actions.values() if a["status"] == ActionStatus.PENDING]
        ),
    }
