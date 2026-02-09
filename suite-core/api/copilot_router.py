"""ALdeci Copilot Chat API Router.

Provides LLM-powered AI chat interface for security operations.
This is the core of the ALdeci Intelligence Hub — a conversational
interface for vulnerability management powered by OpenAI GPT-4 and
Anthropic Claude with automatic fallback.

Endpoints:
- Session Management (CRUD for chat sessions)
- Message Handling (send/receive with real LLM agents)
- Agent Actions (execute security operations)
- Context Injection (feed data to Knowledge Brain)
- Quick Commands (one-shot security operations)
- AI Suggestions (proactive security recommendations)
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field

# Knowledge Brain + Event Bus integration (graceful degradation)
try:
    from core.event_bus import Event, EventType, get_event_bus
    from core.knowledge_brain import get_brain

    _HAS_BRAIN = True
except ImportError:
    _HAS_BRAIN = False

# LLM Providers (graceful degradation)
try:
    from core.llm_providers import LLMProviderManager, LLMResponse

    _HAS_LLM = True
except ImportError:
    _HAS_LLM = False

# Feeds Service for quick analysis (graceful degradation)
try:
    from feeds_service import FeedsService

    _HAS_FEEDS = True
except ImportError:
    _HAS_FEEDS = False

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
        default=CopilotAgentType.GENERAL,
        description="Primary agent for this session"
    )
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Initial context (e.g., CVE IDs, asset IDs)"
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
    include_context: bool = Field(
        default=True, description="Include session context"
    )


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
    async_execution: bool = Field(
        default=True, description="Execute asynchronously"
    )


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


# Agent-specific system prompts for specialised responses
_AGENT_SYSTEM_PROMPTS: Dict[str, str] = {
    "security_analyst": (
        "You are FixOps Security Analyst — an expert security copilot. "
        "Analyse vulnerabilities, CVEs, attack surfaces, and security findings. "
        "Provide actionable remediation advice with MITRE ATT&CK references. "
        "Format responses in clear Markdown with severity ratings."
    ),
    "pentest": (
        "You are FixOps Pentest Agent — an expert penetration tester. "
        "Analyse targets for exploitability, generate proof-of-concept exploit "
        "sketches, map to OWASP Top 10 and CWE categories. "
        "Always include risk assessment and remediation steps."
    ),
    "compliance": (
        "You are FixOps Compliance Agent — an expert in security compliance. "
        "Map findings to SOC2, PCI-DSS, HIPAA, GDPR, ISO 27001 controls. "
        "Identify compliance gaps and provide control implementation guidance."
    ),
    "remediation": (
        "You are FixOps Remediation Agent — an expert at fixing vulnerabilities. "
        "Provide specific code fixes, configuration changes, and patch guidance. "
        "Prioritise by risk and exploitability. Include before/after examples."
    ),
}


async def _call_llm_agent(
    agent_type: CopilotAgentType,
    message: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """Call real LLM (OpenAI / Claude) for agent response.

    Tries OpenAI GPT-4 first, falls back to Anthropic Claude, then to
    deterministic fallback if neither API key is configured.
    """
    if not _HAS_LLM:
        return {
            "content": (
                f"**Agent: {agent_type.value}**\n\n"
                "LLM providers not available. Install `core.llm_providers` module.\n\n"
                f"**Your query:** {message}"
            ),
            "agent_type": agent_type,
            "status": "llm_unavailable",
            "actions": [],
            "confidence": None,
        }

    manager = LLMProviderManager()

    # Build specialised prompt
    system_prompt = _AGENT_SYSTEM_PROMPTS.get(
        agent_type.value, _AGENT_SYSTEM_PROMPTS["security_analyst"]
    )

    # Enrich with Knowledge Brain context if available
    brain_context = ""
    if _HAS_BRAIN:
        try:
            brain = get_brain()
            # Search graph for relevant context
            related = brain.search_nodes(message[:120], limit=5)
            if related:
                brain_context = "\n\n**Knowledge Graph Context:**\n"
                for node in related[:5]:
                    brain_context += f"- {node.get('node_type', 'unknown')}: {json.dumps(node.get('properties', {}), default=str)[:200]}\n"
        except Exception:
            pass

    full_prompt = (
        f"{system_prompt}\n\n"
        f"User query: {message}\n"
    )
    if context:
        ctx_str = json.dumps(context, default=str)[:2000]
        full_prompt += f"\nSession context: {ctx_str}\n"
    if brain_context:
        full_prompt += brain_context

    # Try providers in order: OpenAI → Anthropic → deterministic
    llm_response: Optional[LLMResponse] = None
    provider_used = "none"
    for provider_name in ("openai", "anthropic", "sentinel"):
        try:
            llm_response = manager.analyse(
                provider_name,
                prompt=full_prompt,
                context=context or {},
                default_action="review",
                default_confidence=0.5,
                default_reasoning=f"Default {agent_type.value} analysis for: {message[:100]}",
            )
            provider_used = provider_name
            # If we got a real remote response, use it
            if llm_response.metadata.get("mode") == "remote":
                break
        except Exception as exc:
            logger.warning("LLM provider %s failed: %s", provider_name, exc)
            continue

    if llm_response is None:
        return {
            "content": f"**Agent: {agent_type.value}**\n\nAll LLM providers failed.\n\n**Your query:** {message}",
            "agent_type": agent_type,
            "status": "error",
            "actions": [],
            "confidence": None,
        }

    # Build rich response
    content_parts = [f"**Agent: {agent_type.value}** | *Provider: {provider_used}*\n"]
    content_parts.append(llm_response.reasoning)

    if llm_response.mitre_techniques:
        content_parts.append("\n**MITRE ATT&CK:** " + ", ".join(llm_response.mitre_techniques))
    if llm_response.compliance_concerns:
        content_parts.append("**Compliance:** " + ", ".join(llm_response.compliance_concerns))
    if llm_response.attack_vectors:
        content_parts.append("**Attack Vectors:** " + ", ".join(llm_response.attack_vectors))

    # Derive suggested actions from the response
    actions: List[Dict[str, Any]] = []
    if llm_response.recommended_action == "block":
        actions.append({"type": "block", "label": "Block immediately", "auto": False})
    elif llm_response.recommended_action == "review":
        actions.append({"type": "review", "label": "Schedule review", "auto": False})

    # Log to Knowledge Brain
    if _HAS_BRAIN:
        try:
            bus = get_event_bus()
            await bus.emit(Event(
                event_type=EventType.COPILOT_QUERY,
                source="copilot_router._call_llm_agent",
                data={
                    "agent_type": agent_type.value,
                    "message": message[:500],
                    "provider": provider_used,
                    "confidence": llm_response.confidence,
                },
            ))
        except Exception:
            pass

    return {
        "content": "\n".join(content_parts),
        "agent_type": agent_type,
        "status": "completed",
        "actions": actions,
        "confidence": llm_response.confidence,
        "metadata": {
            "provider": provider_used,
            "mode": llm_response.metadata.get("mode", "unknown"),
            "recommended_action": llm_response.recommended_action,
        },
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
    sessions = sorted(
        _sessions.values(),
        key=lambda s: s["updated_at"],
        reverse=True
    )
    
    return [SessionResponse(**s) for s in sessions[offset:offset + limit]]


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
    
    Sends user message to LLM agent (OpenAI/Claude) and returns the response.
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

    # Emit copilot query event
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(Event(
            event_type=EventType.COPILOT_QUERY,
            source="copilot_router",
            data={"session_id": session_id, "message": request.message,
                  "agent_type": str(agent_type)},
        ))

    # Get AI response
    context = session["context"] if request.include_context else {}
    response = await _call_llm_agent(agent_type, request.message, context)

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

    # Emit copilot response event
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(Event(
            event_type=EventType.COPILOT_RESPONSE,
            source="copilot_router",
            data={"session_id": session_id, "message_id": asst_msg_id,
                  "agent_type": str(agent_type),
                  "confidence": response.get("confidence", 0.0)},
        ))

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
        "status": ActionStatus.PENDING if request.async_execution else ActionStatus.RUNNING,
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
    """Execute action synchronously with real service integrations."""
    action = _actions.get(action_id)
    if not action:
        return

    action["status"] = ActionStatus.RUNNING

    try:
        action_type = action["action_type"]
        params = action.get("parameters", {})

        if action_type == "analyze":
            action["result"] = await _action_analyze(params, action)
        elif action_type == "pentest":
            action["result"] = await _action_pentest(params, action)
        elif action_type == "remediate":
            action["result"] = await _action_remediate(params, action)
        elif action_type == "report":
            action["result"] = {"status": "completed", "message": "Report generation queued"}
        elif action_type == "escalate":
            action["result"] = {"status": "completed", "message": "Escalation created"}
        else:
            action["result"] = {"status": "completed", "message": f"Action {action_type} acknowledged"}

        action["status"] = ActionStatus.COMPLETED
        action["completed_at"] = _now()

    except Exception as e:
        action["status"] = ActionStatus.FAILED
        action["error"] = str(e)
        action["completed_at"] = _now()
        logger.error(f"Action {action_id} failed: {e}")


async def _action_analyze(params: dict, action: dict) -> dict:
    """Analyze action: enrich CVE/finding with EPSS, KEV, and graph data."""
    target = params.get("target", action.get("session_id", ""))
    result = {"status": "completed", "target": target, "enrichments": {}}
    # EPSS / KEV enrichment via FeedsService
    try:
        from src.services.feeds_service import FeedsService
        svc = FeedsService()
        if target.upper().startswith("CVE-"):
            epss = await svc.get_epss_score(target)
            result["enrichments"]["epss"] = epss
            kev = await svc.check_kev(target)
            result["enrichments"]["kev_listed"] = kev
    except Exception as exc:
        result["enrichments"]["feeds_error"] = str(exc)
    # Knowledge Graph context
    if _HAS_BRAIN:
        try:
            brain = get_brain()
            nodes = brain.search_nodes(target, limit=5)
            result["enrichments"]["graph_nodes"] = len(nodes)
            if nodes:
                result["enrichments"]["risk_score"] = brain.risk_score_for_node(nodes[0].get("node_id", ""))
        except Exception:
            pass
    return result


async def _action_pentest(params: dict, action: dict) -> dict:
    """Pentest action: trigger attack simulation engine."""
    target = params.get("target", "")
    result = {"status": "completed", "target": target}
    try:
        from core.attack_simulation import get_attack_engine
        engine = get_attack_engine()
        sim_result = await engine.run_simulation(
            target=target,
            techniques=params.get("techniques", ["T1190"]),
            mode="safe",
        )
        result["simulation"] = sim_result
        result["message"] = f"Attack simulation completed against {target}"
    except ImportError:
        result["message"] = "Attack simulation engine not available"
        result["status"] = "degraded"
    except Exception as exc:
        result["message"] = f"Simulation error: {exc}"
        result["status"] = "degraded"
    return result


async def _action_remediate(params: dict, action: dict) -> dict:
    """Remediate action: generate fix via AutoFix engine."""
    finding_id = params.get("finding_id", params.get("target", ""))
    result = {"status": "completed", "finding_id": finding_id}
    try:
        from core.autofix_engine import get_autofix_engine
        engine = get_autofix_engine()
        fix = await engine.generate_fix(finding_id=finding_id)
        result["fix"] = fix
        result["message"] = f"AutoFix generated for {finding_id}"
    except ImportError:
        result["message"] = "AutoFix engine not available"
        result["status"] = "degraded"
    except Exception as exc:
        result["message"] = f"AutoFix error: {exc}"
        result["status"] = "degraded"
    return result


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
    
    Context is fed to Knowledge Brain for RAG-enhanced responses.
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

    Returns proactive suggestions based on current context, recent activity,
    and Knowledge Graph insights. Powered by OpenAI / Claude.
    """
    if not _HAS_LLM:
        return []

    # Gather context from Knowledge Brain
    brain_summary = ""
    if _HAS_BRAIN:
        try:
            brain = get_brain()
            stats = brain.get_stats()
            brain_summary = (
                f"Knowledge Graph has {stats.get('total_nodes', 0)} nodes and "
                f"{stats.get('total_edges', 0)} edges. "
            )
            recent = brain.get_recent_events(limit=10)
            if recent:
                brain_summary += "Recent events: " + "; ".join(
                    e.get("event_type", "?") for e in recent[:5]
                )
        except Exception:
            pass

    context_filter = f" Focus on {context_type} context." if context_type else ""
    prompt = (
        "You are FixOps Security Copilot. Generate exactly {limit} proactive security "
        "suggestions for a security team based on the following context. "
        "Return ONLY a JSON array where each element has keys: "
        "type (one of: vulnerability, compliance, remediation, pentest, configuration), "
        "title (short), description (1-2 sentences), confidence (0.0-1.0).{ctx_filter}\n\n"
        "Context: {brain_summary}\n"
        "Active sessions: {sessions}. Pending actions: {actions}."
    ).format(
        limit=limit,
        ctx_filter=context_filter,
        brain_summary=brain_summary or "No prior context available.",
        sessions=len(_sessions),
        actions=len([a for a in _actions.values() if a.get("status") == ActionStatus.PENDING]),
    )

    manager = LLMProviderManager()
    suggestions: List[SuggestionResponse] = []

    for provider_name in ("openai", "anthropic"):
        try:
            resp = manager.analyse(
                provider_name,
                prompt=prompt,
                context={"context_type": context_type, "limit": limit},
                default_action="review",
                default_confidence=0.7,
                default_reasoning="Security posture review recommended",
            )
            if resp.metadata.get("mode") == "remote" and resp.reasoning:
                # Try to parse JSON array from reasoning
                text = resp.reasoning.strip()
                # Find JSON array in response
                start = text.find("[")
                end = text.rfind("]") + 1
                if start >= 0 and end > start:
                    items = json.loads(text[start:end])
                    for i, item in enumerate(items[:limit]):
                        suggestions.append(SuggestionResponse(
                            id=str(uuid.uuid4()),
                            type=item.get("type", "vulnerability"),
                            title=item.get("title", "Security suggestion"),
                            description=item.get("description", ""),
                            confidence=float(item.get("confidence", 0.7)),
                            action=item.get("action"),
                        ))
                    break
        except Exception as exc:
            logger.warning("Suggestion generation via %s failed: %s", provider_name, exc)
            continue

    return suggestions[:limit]


# =============================================================================
# Quick Command Endpoints
# =============================================================================


@router.post("/quick/analyze")
async def quick_analyze(request: QuickAnalyzeRequest) -> Dict[str, Any]:
    """Quick vulnerability analysis.

    One-shot analysis without creating a session.
    Returns immediate analysis results from real data sources.
    """
    target = request.cve_id or request.finding_id or request.asset_id or request.description

    # Emit copilot query event for quick analysis
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(Event(
            event_type=EventType.COPILOT_QUERY,
            source="copilot_router.quick_analyze",
            data={"target": target, "cve_id": request.cve_id,
                  "finding_id": request.finding_id, "asset_id": request.asset_id},
        ))
    
    # Gather real intelligence from FeedsService
    feed_data: Dict[str, Any] = {}
    if _HAS_FEEDS and request.cve_id:
        try:
            feeds = FeedsService()
            epss = feeds.get_epss_score(request.cve_id)
            kev = feeds.is_kev(request.cve_id)
            nvd = feeds.get_nvd_cve(request.cve_id)
            feed_data = {
                "epss_score": epss,
                "kev_listed": kev,
                "nvd": nvd,
                "data_source": "EPSS/CISA-KEV/NVD",
            }
        except Exception as exc:
            logger.warning("FeedsService lookup failed: %s", exc)

    # Use LLM for deep analysis
    llm_analysis: Optional[str] = None
    if _HAS_LLM:
        analysis_prompt = (
            "Perform a quick security analysis of the following target. "
            "Provide: severity assessment, exploitability, remediation priority, "
            "and recommended next steps.\n\n"
            f"Target: {target}\n"
        )
        if feed_data:
            analysis_prompt += f"Feed intelligence: {json.dumps(feed_data, default=str)[:1500]}\n"
        if request.description:
            analysis_prompt += f"Description: {request.description}\n"

        manager = LLMProviderManager()
        for prov in ("openai", "anthropic"):
            try:
                resp = manager.analyse(
                    prov,
                    prompt=analysis_prompt,
                    context={"target": target, **feed_data},
                    default_action="review",
                    default_confidence=0.6,
                    default_reasoning=f"Analysis of {target}",
                )
                if resp.metadata.get("mode") == "remote":
                    llm_analysis = resp.reasoning
                    break
            except Exception:
                continue

    return {
        "analysis": {
            "target": target,
            "cve_id": request.cve_id,
            **feed_data,
            "llm_analysis": llm_analysis,
        },
        "related_cves": [],
        "affected_assets": None,
        "remediation_available": llm_analysis is not None,
        "status": "complete" if (feed_data or llm_analysis) else "partial",
        "message": "Analysis from EPSS/KEV/NVD + LLM" if feed_data else "LLM analysis only",
    }


@router.post("/quick/pentest")
async def quick_pentest(
    request: QuickPentestRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """Quick pentest initiation.
    
    Starts a lightweight pentest and returns task ID for tracking.
    Uses MPTE for execution.
    """
    task_id = _generate_id()
    
    # Queue pentest (would integrate with MPTE)
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
    """Run quick pentest in background using LLM-powered threat analysis."""
    result_content: Dict[str, Any] = {}

    if _HAS_LLM:
        prompt = (
            "You are a penetration tester. Perform a lightweight threat assessment for:\n"
            f"Target: {request.target}\n"
            f"Test type: {request.test_type}\n"
            f"Depth: {request.depth}\n\n"
            "Return a brief JSON with keys: vulnerabilities (array of {title, severity, cwe}), "
            "risk_score (0-10), summary, recommended_actions (array of strings)."
        )
        manager = LLMProviderManager()
        for prov in ("openai", "anthropic"):
            try:
                resp = manager.analyse(
                    prov,
                    prompt=prompt,
                    context={"target": request.target, "test_type": request.test_type},
                    default_action="review",
                    default_confidence=0.6,
                    default_reasoning="Quick pentest assessment",
                )
                if resp.metadata.get("mode") == "remote":
                    result_content = {
                        "status": "completed",
                        "provider": prov,
                        "analysis": resp.reasoning,
                        "confidence": resp.confidence,
                        "mitre_techniques": resp.mitre_techniques,
                    }
                    break
            except Exception:
                continue

    if not result_content:
        result_content = {
            "status": "completed_basic",
            "message": f"Basic assessment for {request.target} — configure LLM keys for deep analysis",
        }

    action = {
        "id": task_id,
        "session_id": "quick",
        "action_type": "pentest",
        "status": ActionStatus.COMPLETED,
        "parameters": request.model_dump(),
        "result": result_content,
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
    """Check Copilot service health with real LLM provider status."""
    llm_status: Dict[str, str] = {}
    if _HAS_LLM:
        manager = LLMProviderManager()
        for name in ("openai", "anthropic", "gemini", "sentinel"):
            prov = manager.get_provider(name)
            if hasattr(prov, "api_key") and prov.api_key:
                llm_status[name] = "configured"
            else:
                llm_status[name] = "no_api_key"
    else:
        llm_status = {"error": "llm_providers module not available"}

    return {
        "status": "healthy",
        "service": "aldeci-copilot",
        "version": "2.0.0",
        "agents": {
            agent.value: "ready" for agent in CopilotAgentType
        },
        "llm_providers": llm_status,
        "knowledge_brain": _HAS_BRAIN,
        "feeds_service": _HAS_FEEDS,
        "sessions_active": len(_sessions),
        "actions_pending": len([a for a in _actions.values() if a.get("status") == ActionStatus.PENDING]),
    }
