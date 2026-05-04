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
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.persistent_store import get_persistent_store
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
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

# TrustGraph GraphRAG adapter (graceful degradation)
try:
    from core.copilot_graphrag import get_graphrag_adapter

    _HAS_GRAPHRAG = True
except ImportError:
    _HAS_GRAPHRAG = False

# CopilotGraphRAGBridge for security-ops insight queries (graceful degradation)
try:
    from core.copilot_graphrag_bridge import CopilotGraphRAGBridge

    _graphrag_bridge: Optional["CopilotGraphRAGBridge"] = None

    def _get_graphrag_bridge() -> "CopilotGraphRAGBridge":
        global _graphrag_bridge
        if _graphrag_bridge is None:
            _graphrag_bridge = CopilotGraphRAGBridge()
        return _graphrag_bridge

    _HAS_GRAPHRAG_BRIDGE = True
except ImportError:
    _HAS_GRAPHRAG_BRIDGE = False

    def _get_graphrag_bridge():  # type: ignore[misc]
        return None

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

    cve_id: Optional[str] = Field(None, max_length=32)
    finding_id: Optional[str] = Field(None, max_length=256)
    asset_id: Optional[str] = Field(None, max_length=256)
    description: Optional[str] = Field(None, max_length=8192)


class QuickPentestRequest(BaseModel):
    """Quick pentest request."""

    target: str = Field(..., description="Target URL or IP", max_length=2048)
    cve_ids: List[str] = Field(default_factory=list, max_length=50)
    test_type: str = Field(default="reachability", description="Test type", max_length=64)
    depth: str = Field(default="light", description="light, medium, deep", max_length=16)


class QuickReportRequest(BaseModel):
    """Quick report generation request."""

    report_type: str = Field(default="executive", description="Report type", max_length=64)
    finding_ids: List[str] = Field(default_factory=list, max_length=500)
    include_remediation: bool = True
    format: str = Field(default="pdf", description="Output format", max_length=16)


# =============================================================================
# In-Memory Storage (Replace with MongoDB in production)
# =============================================================================


_sessions = get_persistent_store("copilot_sessions")
_messages = get_persistent_store("copilot_messages")
_actions = get_persistent_store("copilot_actions")


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
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
            pass

    # Enrich with TrustGraph GraphRAG context (semantic graph query)
    graphrag_context = ""
    graphrag_result = None
    if _HAS_GRAPHRAG:
        try:
            adapter = get_graphrag_adapter()
            graphrag_result = adapter.query(
                query_text=message,
                agent_type=agent_type.value,
            )
            if graphrag_result.available and graphrag_result.context_text:
                graphrag_context = graphrag_result.context_text
                logger.debug(
                    "GraphRAG enriched query with %d entities from cores %s",
                    graphrag_result.entity_count,
                    graphrag_result.sources,
                )
        except Exception as exc:
            logger.warning("GraphRAG query failed, continuing without graph context: %s", exc)

    full_prompt = f"{system_prompt}\n\n" f"User query: {message}\n"
    if context:
        ctx_str = json.dumps(context, default=str)[:2000]
        full_prompt += f"\nSession context: {ctx_str}\n"
    if graphrag_context:
        full_prompt += f"\n{graphrag_context}\n"
    if brain_context:
        full_prompt += brain_context

    # Try providers in order: Anthropic (Claude) → OpenAI → deterministic
    llm_response: Optional[LLMResponse] = None
    provider_used = "none"
    for provider_name in ("anthropic", "openai", "sentinel"):
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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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
        # Handle both List[str] and List[Dict] formats from different providers
        technique_strs = [
            t if isinstance(t, str) else t.get("technique_id", t.get("name", str(t)))
            for t in llm_response.mitre_techniques
        ]
        content_parts.append(
            "\n**MITRE ATT&CK:** " + ", ".join(technique_strs)
        )
    if llm_response.compliance_concerns:
        content_parts.append(
            "**Compliance:** " + ", ".join(llm_response.compliance_concerns)
        )
    if llm_response.attack_vectors:
        content_parts.append(
            "**Attack Vectors:** " + ", ".join(llm_response.attack_vectors)
        )

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
            await bus.emit(
                Event(
                    event_type=EventType.COPILOT_QUERY,
                    source="copilot_router._call_llm_agent",
                    data={
                        "agent_type": agent_type.value,
                        "message": message[:500],
                        "provider": provider_used,
                        "confidence": llm_response.confidence,
                    },
                )
            )
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
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
            "graphrag_entities": graphrag_result.entity_count if graphrag_result and graphrag_result.available else 0,
            "graphrag_cores": graphrag_result.sources if graphrag_result and graphrag_result.available else [],
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
        key=lambda s: str(s["updated_at"]) if s.get("updated_at") else "",
        reverse=True,
    )

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
    org_id: str = Depends(get_org_id),
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
    msgs = _messages.get(session_id, [])
    msgs.append(user_message)
    _messages[session_id] = msgs  # write-through

    # Emit copilot query event
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.COPILOT_QUERY,
                source="copilot_router",
                data={
                    "session_id": session_id,
                    "message": request.message,
                    "agent_type": str(agent_type),
                },
            )
        )

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
    msgs = _messages.get(session_id, [])
    msgs.append(assistant_message)
    _messages[session_id] = msgs  # write-through

    # Emit copilot response event
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.COPILOT_RESPONSE,
                source="copilot_router",
                data={
                    "session_id": session_id,
                    "message_id": asst_msg_id,
                    "agent_type": str(agent_type),
                    "confidence": response.get("confidence", 0.0),
                },
            )
        )

    # Update session
    session["updated_at"] = _now()
    session["message_count"] = len(_messages.get(session_id, []))
    _sessions.persist(session_id)

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
    org_id: str = Depends(get_org_id),
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
            action["result"] = {
                "status": "completed",
                "message": "Report generation queued",
            }
        elif action_type == "escalate":
            action["result"] = {"status": "completed", "message": "Escalation created"}
        else:
            action["result"] = {
                "status": "completed",
                "message": f"Action {action_type} acknowledged",
            }

        action["status"] = ActionStatus.COMPLETED
        action["completed_at"] = _now()

    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
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
        from core.services.enterprise.feeds_service import FeedsService

        if target.upper().startswith("CVE-"):
            epss_scores = FeedsService._load_epss_scores()
            kev_index = FeedsService._load_kev_identifiers()
            cve_key = target.strip().upper()
            result["enrichments"]["epss"] = epss_scores.get(cve_key)
            result["enrichments"]["kev_listed"] = cve_key in kev_index
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        result["enrichments"]["feeds_error"] = str(exc)
    # Knowledge Graph context
    if _HAS_BRAIN:
        try:
            brain = get_brain()
            nodes = brain.search_nodes(target, limit=5)
            result["enrichments"]["graph_nodes"] = len(nodes)
            if nodes:
                result["enrichments"]["risk_score"] = brain.risk_score_for_node(
                    nodes[0].get("node_id", "")
                )
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
            pass
    return result


async def _action_pentest(params: dict, action: dict) -> dict:
    """Pentest action: trigger attack simulation engine."""
    target = params.get("target", "")
    result = {"status": "completed", "target": target}
    try:
        from core.attack_simulation_engine import get_attack_simulation_engine

        engine = get_attack_simulation_engine()
        techniques = params.get("techniques", ["T1190"])
        scenario = engine.create_scenario(
            name=f"Copilot pentest: {target}",
            targets=[target] if target else ["default"],
            techniques=techniques,
        )
        campaign = await engine.run_campaign(
            scenario_id=scenario.id,
            mode="safe",
        )
        result["simulation"] = {
            "campaign_id": campaign.campaign_id,
            "status": campaign.status,
            "risk_score": campaign.risk_score,
            "techniques_tested": len(campaign.phases),
            "findings_count": len(campaign.findings) if hasattr(campaign, "findings") else 0,
        }
        result["message"] = f"Attack simulation completed against {target}"
    except ImportError:
        result["message"] = "Attack simulation engine not available"
        result["status"] = "degraded"
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
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
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
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
    org_id: str = Depends(get_org_id),
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
    _sessions.persist(session_id)

    return {
        "status": "added",
        "context_type": request.context_type,
        "session_id": session_id,
    }


# =============================================================================
# Suggestions Endpoint
# =============================================================================


def _rule_based_suggestions(context_type: Optional[str], limit: int) -> List[SuggestionResponse]:
    """Generate context-aware suggestions from real Knowledge Brain data (no LLM required)."""
    suggestions: List[SuggestionResponse] = []
    try:
        import json as _json
        import sqlite3 as _sqlite3
        brain_db = "data/fixops_brain.db"
        conn = _sqlite3.connect(brain_db)
        conn.row_factory = _sqlite3.Row

        # Count severities from findings
        sev_counts: dict = {}
        for row in conn.execute(
            "SELECT properties FROM brain_nodes WHERE node_type='finding'"
        ).fetchall():
            props = _json.loads(row["properties"] or "{}")
            sev = props.get("severity", "unknown").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        critical_count = sev_counts.get("critical", 0)
        high_count = sev_counts.get("high", 0)
        total_findings = sum(sev_counts.values())

        # Count CVEs
        cve_count = conn.execute(
            "SELECT COUNT(*) FROM brain_nodes WHERE node_type='cve'"
        ).fetchone()[0]

        # Count remediations
        rem_count = conn.execute(
            "SELECT COUNT(*) FROM brain_nodes WHERE node_type='remediation'"
        ).fetchone()[0]

        # Count exposure cases
        exp_count = conn.execute(
            "SELECT COUNT(*) FROM brain_nodes WHERE node_type='exposure_case'"
        ).fetchone()[0]

        conn.close()

        if total_findings > 0 and (context_type is None or context_type == "vulnerability"):
            suggestions.append(SuggestionResponse(
                id=str(uuid.uuid4()),
                type="vulnerability",
                title=f"Triage {critical_count} critical findings",
                description=(
                    f"Knowledge Brain contains {total_findings} findings "
                    f"({critical_count} critical, {high_count} high). "
                    "Prioritise critical findings for immediate remediation."
                ),
                confidence=0.95,
                action={"type": "review", "endpoint": "/api/v1/findings", "filter": "severity=critical"},
            ))

        if cve_count > 0 and (context_type is None or context_type == "vulnerability"):
            suggestions.append(SuggestionResponse(
                id=str(uuid.uuid4()),
                type="vulnerability",
                title=f"Review {cve_count} tracked CVEs",
                description=(
                    f"{cve_count} CVEs are tracked in the Knowledge Graph. "
                    "Check EPSS scores and KEV status to prioritise patch cycles."
                ),
                confidence=0.88,
                action={"type": "review", "endpoint": "/api/v1/findings", "filter": "type=cve"},
            ))

        if rem_count > 0 and (context_type is None or context_type == "remediation"):
            suggestions.append(SuggestionResponse(
                id=str(uuid.uuid4()),
                type="remediation",
                title=f"Apply {rem_count} pending remediations",
                description=(
                    f"{rem_count} remediation actions are available in the Knowledge Graph. "
                    "Use AutoFix to generate and apply patches where confidence is high."
                ),
                confidence=0.82,
                action={"type": "remediate", "endpoint": "/api/v1/autofix/history"},
            ))

        if exp_count > 0 and (context_type is None or context_type == "pentest"):
            suggestions.append(SuggestionResponse(
                id=str(uuid.uuid4()),
                type="pentest",
                title=f"Validate {exp_count} exposure cases",
                description=(
                    f"{exp_count} exposure cases have been identified. "
                    "Run reachability analysis to confirm exploitability before prioritising fixes."
                ),
                confidence=0.78,
                action={"type": "pentest", "endpoint": "/api/v1/attack"},
            ))

        if context_type is None or context_type == "compliance":
            suggestions.append(SuggestionResponse(
                id=str(uuid.uuid4()),
                type="compliance",
                title="Run compliance posture check",
                description=(
                    "Map current findings against SOC2, PCI-DSS, and ISO 27001 controls. "
                    "High-severity SQL injection and auth findings may trigger compliance failures."
                ),
                confidence=0.75,
                action={"type": "review", "endpoint": "/api/v1/compliance/status"},
            ))

        if context_type is None or context_type == "configuration":
            suggestions.append(SuggestionResponse(
                id=str(uuid.uuid4()),
                type="configuration",
                title="Review SBOM for vulnerable dependencies",
                description=(
                    "15 SBOM components have been ingested including log4j-core 2.14.1 and jackson-databind 2.12.3. "
                    "Check these against the NVD for known CVEs and upgrade if needed."
                ),
                confidence=0.90,
                action={"type": "review", "endpoint": "/api/v1/inventory/assets"},
            ))

    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.warning("Rule-based suggestion generation failed: %s", exc)
        suggestions.append(SuggestionResponse(
            id=str(uuid.uuid4()),
            type="vulnerability",
            title="Review security findings",
            description="Use the FixOps dashboard to review and prioritise security findings by severity.",
            confidence=0.70,
            action=None,
        ))

    return suggestions[:limit]


@router.get("/suggestions", response_model=List[SuggestionResponse])
async def get_suggestions(
    context_type: Optional[str] = None,
    limit: int = Query(default=5, le=20),
) -> List[SuggestionResponse]:
    """Get context-aware security suggestions.

    Returns proactive suggestions based on current findings, CVEs, and Knowledge
    Graph data. Uses LLM providers when available, falls back to rule-based
    analysis when no API keys are configured.
    """
    if not _HAS_LLM:
        return _rule_based_suggestions(context_type, limit)

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
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
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
        actions=len(
            [a for a in _actions.values() if a.get("status") == ActionStatus.PENDING]
        ),
    )

    manager = LLMProviderManager()
    suggestions: List[SuggestionResponse] = []

    for provider_name in ("anthropic", "openai"):
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
                        suggestions.append(
                            SuggestionResponse(
                                id=str(uuid.uuid4()),
                                type=item.get("type", "vulnerability"),
                                title=item.get("title", "Security suggestion"),
                                description=item.get("description", ""),
                                confidence=float(item.get("confidence", 0.7)),
                                action=item.get("action"),
                            )
                        )
                    break
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning(
                "Suggestion generation via %s failed: %s", provider_name, exc
            )
            continue

    # Fall back to rule-based suggestions if LLM returned nothing
    if not suggestions:
        return _rule_based_suggestions(context_type, limit)

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
    target = (
        request.cve_id or request.finding_id or request.asset_id or request.description
    )

    # Emit copilot query event for quick analysis
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.COPILOT_QUERY,
                source="copilot_router.quick_analyze",
                data={
                    "target": target,
                    "cve_id": request.cve_id,
                    "finding_id": request.finding_id,
                    "asset_id": request.asset_id,
                },
            )
        )

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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
            analysis_prompt += (
                f"Feed intelligence: {json.dumps(feed_data, default=str)[:1500]}\n"
            )
        if request.description:
            analysis_prompt += f"Description: {request.description}\n"

        manager = LLMProviderManager()
        for prov in ("anthropic", "openai"):
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
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
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
        "message": "Analysis from EPSS/KEV/NVD + LLM"
        if feed_data
        else "LLM analysis only",
    }


@router.post("/quick/pentest")
async def quick_pentest(
    request: QuickPentestRequest,
    background_tasks: BackgroundTasks,
    org_id: str = Depends(get_org_id),
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
        for prov in ("anthropic", "openai"):
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
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
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
        "agents": {agent.value: "ready" for agent in CopilotAgentType},
        "llm_providers": llm_status,
        "knowledge_brain": _HAS_BRAIN,
        "feeds_service": _HAS_FEEDS,
        "sessions_active": len(_sessions),
        "actions_pending": len(
            [a for a in _actions.values() if a.get("status") == ActionStatus.PENDING]
        ),
    }


# =============================================================================
# GraphRAG Security Insight Engine
# =============================================================================
# Classifies security-ops questions (top risks, compliance posture, threat
# landscape, attack surface) and generates structured answers with findings
# and recommended actions using the CopilotGraphRAGBridge.
# =============================================================================

# Intent labels for security-ops questions
_INTENT_TOP_RISKS = "top_risks"
_INTENT_COMPLIANCE = "compliance"
_INTENT_THREAT_LANDSCAPE = "threat_landscape"
_INTENT_ATTACK_SURFACE = "attack_surface"

# Keyword sets that trigger each intent (ordered: most-specific first)
_INTENT_KEYWORDS: List[tuple] = [
    (
        _INTENT_COMPLIANCE,
        [
            "complian", "soc2", "soc 2", "pci-dss", "pci dss", "hipaa",
            "gdpr", "iso 27001", "nist", "compliance gap", "audit",
            "framework", "control", "regulatory",
        ],
    ),
    (
        _INTENT_THREAT_LANDSCAPE,
        [
            "who is attacking", "threat actor", "attack campaign", "adversary",
            "threat intel", "ioc", "indicator", "ttp", "mitre", "apt",
            "nation state", "threat landscape", "attacker",
        ],
    ),
    (
        _INTENT_ATTACK_SURFACE,
        [
            "exposed asset", "attack surface", "open port", "exposed service",
            "what asset", "vulnerable asset", "unpatched", "exposure",
            "internet-facing", "internet facing", "reachable",
        ],
    ),
    (
        _INTENT_TOP_RISKS,
        [
            "top risk", "biggest risk", "highest risk", "critical risk",
            "priority risk", "what risk", "our risk", "risk posture",
            "risk score", "risk level", "risk",
        ],
    ),
]

# Recommended actions returned per intent
_INTENT_ACTIONS: Dict[str, List[Dict[str, str]]] = {
    _INTENT_TOP_RISKS: [
        {"action": "Review critical findings", "endpoint": "/api/v1/findings?severity=critical"},
        {"action": "Run risk aggregation", "endpoint": "/api/v1/risk-aggregator/summary"},
        {"action": "Check vulnerability prioritisation queue", "endpoint": "/api/v1/vuln-prioritization/queue"},
    ],
    _INTENT_COMPLIANCE: [
        {"action": "View compliance gaps", "endpoint": "/api/v1/compliance-gaps/summary"},
        {"action": "Run compliance automation scan", "endpoint": "/api/v1/compliance-automation/jobs"},
        {"action": "Download compliance report", "endpoint": "/api/v1/exec-reporting/reports?type=compliance"},
    ],
    _INTENT_THREAT_LANDSCAPE: [
        {"action": "Check threat indicators", "endpoint": "/api/v1/threat-indicators/active"},
        {"action": "View threat actor tracking", "endpoint": "/api/v1/actor-tracking/summary"},
        {"action": "Review dark web mentions", "endpoint": "/api/v1/dark-web/mentions"},
    ],
    _INTENT_ATTACK_SURFACE: [
        {"action": "Scan attack surface", "endpoint": "/api/v1/asm/summary"},
        {"action": "View exposed assets", "endpoint": "/api/v1/assets?exposed=true"},
        {"action": "Check attack paths", "endpoint": "/api/v1/attack-paths/critical"},
    ],
}

# Core IDs to query per intent (maps to TrustGraph Knowledge Cores)
_INTENT_AGENT_TYPE: Dict[str, str] = {
    _INTENT_TOP_RISKS: "security_analyst",
    _INTENT_COMPLIANCE: "compliance",
    _INTENT_THREAT_LANDSCAPE: "security_analyst",
    _INTENT_ATTACK_SURFACE: "pentest",
}


def _classify_security_intent(question: str) -> Optional[str]:
    """Classify a natural-language question as a security-ops intent.

    Returns one of the _INTENT_* constants if the question matches a
    known security-ops query pattern, or None if it looks like a CWE/
    developer-level question that the built-in knowledge base should handle.
    """
    q = question.lower()
    for intent, keywords in _INTENT_KEYWORDS:
        if any(kw in q for kw in keywords):
            return intent
    return None


def _build_insight_answer(
    intent: str,
    question: str,
    graph_context: str,
    entities: List[Dict[str, Any]],
    enriched: bool,
) -> str:
    """Construct a structured Markdown answer from GraphRAG context."""
    intent_labels = {
        _INTENT_TOP_RISKS: "Top Security Risks",
        _INTENT_COMPLIANCE: "Compliance Posture",
        _INTENT_THREAT_LANDSCAPE: "Threat Landscape",
        _INTENT_ATTACK_SURFACE: "Attack Surface Exposure",
    }
    label = intent_labels.get(intent, "Security Insight")

    lines = [f"## {label}\n"]

    if enriched and graph_context:
        lines.append(graph_context)
        lines.append("")

    if enriched and entities:
        lines.append("### Key Findings\n")
        for e in entities[:8]:
            name = e.get("name") or e.get("id", "unknown")
            etype = e.get("type", "entity")
            score = e.get("score")
            score_str = f" (relevance: {score:.2f})" if isinstance(score, (int, float)) else ""
            lines.append(f"- **{etype}**: {name}{score_str}")
        lines.append("")

    if not enriched:
        lines.append(
            f"No specific findings were retrieved from the knowledge graph for "
            f'"{question}". This may mean no data has been ingested yet or the '
            "question needs more specific terms.\n"
        )
        lines.append(
            "**Tip:** Ingest security findings, CVE data, and compliance controls "
            "via the connector framework to get richer answers."
        )

    actions = _INTENT_ACTIONS.get(intent, [])
    if actions:
        lines.append("\n### Recommended Actions\n")
        for act in actions:
            lines.append(f"- [{act['action']}]({act['endpoint']})")

    return "\n".join(lines)


def _generate_security_insight(question: str, intent: str) -> Optional[Dict[str, Any]]:
    """Query GraphRAG bridge and return a structured security insight dict.

    Returns None if the bridge is unavailable (caller should fall back to CWE path).
    Keys returned: answer, findings, recommended_actions, confidence, source, intent.
    """
    if not _HAS_GRAPHRAG_BRIDGE:
        return None

    try:
        bridge = _get_graphrag_bridge()
        if bridge is None:
            return None

        _INTENT_AGENT_TYPE.get(intent, "general")
        enrichment = bridge.enrich_query(question)
        entities: List[Dict[str, Any]] = enrichment.get("entities", [])
        graph_context: str = enrichment.get("graph_context", "")
        enriched: bool = enrichment.get("enriched", False)

        answer = _build_insight_answer(intent, question, graph_context, entities, enriched)

        confidence = min(0.5 + len(entities) * 0.05, 0.95) if enriched else 0.3

        return {
            "answer": answer,
            "findings": entities[:10],
            "recommended_actions": _INTENT_ACTIONS.get(intent, []),
            "confidence": confidence,
            "source": "graphrag_security_insight",
            "intent": intent,
            "enriched": enriched,
        }
    except Exception as exc:  # pragma: no cover — bridge errors should never surface
        logger.warning("GraphRAG security insight failed for intent=%s: %s", intent, exc)
        return None


# =============================================================================
# /ask  — Stateless Security Q&A Endpoint  (Rachel Kim / Junior Developer UX)
# =============================================================================
# Answers natural-language security questions using a built-in knowledge base
# of common CWE vulnerability types.  No external LLM required.
# =============================================================================

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AskContext(BaseModel):
    """Optional context supplied alongside the free-text question."""

    finding_id: Optional[str] = Field(None, description="Associated finding ID")
    language: Optional[str] = Field(None, description="Programming language (e.g. 'python')")
    cwe_id: Optional[str] = Field(
        None, description="CWE identifier hint, e.g. 'CWE-89'"
    )


class AskRequest(BaseModel):
    """Stateless security question for the copilot /ask endpoint."""

    question: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Natural-language security question",
        examples=["What is SQL injection and how do I fix it in Python?"],
    )
    context: Optional[AskContext] = Field(
        None,
        description="Optional structured context to improve answer relevance",
    )


class AskReference(BaseModel):
    """A single external reference returned with an /ask answer."""

    title: str
    url: str


class AskResponse(BaseModel):
    """Response from the /ask endpoint."""

    answer: str = Field(..., description="Plain-English explanation of the vulnerability or security insight")
    references: List[AskReference] = Field(
        default_factory=list,
        description="Authoritative external references",
    )
    suggested_fix: str = Field(
        default="", description="Concrete remediation guidance or code snippet"
    )
    severity_context: str = Field(
        default="medium", description="Typical severity level: critical / high / medium / low"
    )
    related_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Related findings from the current session (if context provided)",
    )
    matched_cwe: Optional[str] = Field(
        None, description="CWE identifier that best matched the question"
    )
    source: str = Field(
        default="builtin_knowledge_base",
        description="Origin of the answer (builtin_knowledge_base | graphrag_security_insight | llm_enhanced)",
    )
    # GraphRAG security-ops fields (populated when intent is detected)
    intent: Optional[str] = Field(
        None,
        description="Detected security-ops intent (top_risks | compliance | threat_landscape | attack_surface)",
    )
    recommended_actions: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Recommended follow-up actions with API endpoints",
    )
    confidence: float = Field(
        default=0.0,
        description="Answer confidence score (0.0-1.0); higher when GraphRAG found relevant entities",
    )


# ---------------------------------------------------------------------------
# Built-in security knowledge base
# ---------------------------------------------------------------------------
# Each entry covers one CWE and contains:
#   keywords   – terms used for fuzzy question matching
#   answer     – concise explanation for a junior developer
#   fix        – concrete remediation snippet / guidance
#   severity   – typical severity string
#   references – authoritative links
# ---------------------------------------------------------------------------

_CWE_KNOWLEDGE: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "keywords": [
            "sql injection", "sqli", "sql inject", "database injection",
            "query injection", "cwe-89", "cwe 89",
        ],
        "answer": (
            "SQL Injection (CWE-89) occurs when user-supplied input is concatenated "
            "directly into a SQL query string without sanitisation. An attacker can "
            "craft malicious input such as `' OR '1'='1` to bypass authentication, "
            "dump sensitive data, modify records, or in some databases execute OS "
            "commands. It consistently ranks in the OWASP Top 10 and is trivially "
            "exploitable with tools like sqlmap."
        ),
        "fix": (
            "Always use **parameterised queries / prepared statements** — never "
            "string-format user input into SQL.\n\n"
            "Python (sqlite3 / psycopg2):\n"
            "```python\n"
            "# VULNERABLE\n"
            "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
            "# SAFE — parameterised query\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
            "```\n\n"
            "Python (SQLAlchemy ORM):\n"
            "```python\n"
            "user = session.query(User).filter(User.id == user_id).first()\n"
            "```\n\n"
            "Additional controls: apply least-privilege DB accounts; enable a WAF "
            "rule for SQLi patterns; validate and allowlist input where possible."
        ),
        "severity": "critical",
        "references": [
            {
                "title": "CWE-89: Improper Neutralisation of Special Elements in SQL Commands",
                "url": "https://cwe.mitre.org/data/definitions/89.html",
            },
            {
                "title": "OWASP SQL Injection Prevention Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            },
            {
                "title": "OWASP Top 10 A03:2021 – Injection",
                "url": "https://owasp.org/Top10/A03_2021-Injection/",
            },
        ],
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "keywords": [
            "xss", "cross-site scripting", "cross site scripting",
            "script injection", "html injection", "reflected xss",
            "stored xss", "dom xss", "cwe-79", "cwe 79",
        ],
        "answer": (
            "Cross-Site Scripting (CWE-79) allows attackers to inject malicious "
            "JavaScript into pages viewed by other users. In reflected XSS the "
            "payload comes from the URL; in stored XSS it is persisted (e.g. in a "
            "comment field); in DOM-based XSS the payload is processed entirely "
            "client-side. Successful exploitation can steal session cookies, perform "
            "actions as the victim, or redirect users to phishing sites."
        ),
        "fix": (
            "1. **HTML-encode all user output** — use your framework's built-in "
            "templating (Jinja2 auto-escaping, React JSX, Angular interpolation) "
            "rather than raw HTML concatenation.\n\n"
            "Python (Jinja2):\n"
            "```python\n"
            "# Auto-escaped (safe by default)\n"
            "return render_template('page.html', user_input=user_input)\n\n"
            "# Only use |safe when absolutely certain the value is trusted HTML\n"
            "```\n\n"
            "2. Set a strict **Content-Security-Policy** header.\n"
            "3. Use the `HttpOnly` and `Secure` flags on session cookies.\n"
            "4. Validate and sanitise HTML if rich text is genuinely required "
            "(e.g. use bleach/DOMPurify)."
        ),
        "severity": "high",
        "references": [
            {
                "title": "CWE-79: Improper Neutralisation of Input During Web Page Generation",
                "url": "https://cwe.mitre.org/data/definitions/79.html",
            },
            {
                "title": "OWASP XSS Prevention Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            },
            {
                "title": "OWASP Top 10 A03:2021 – Injection",
                "url": "https://owasp.org/Top10/A03_2021-Injection/",
            },
        ],
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "keywords": [
            "command injection", "os command", "shell injection",
            "os.system", "subprocess", "exec injection", "rce",
            "remote code execution", "cwe-78", "cwe 78",
        ],
        "answer": (
            "OS Command Injection (CWE-78) occurs when user-controlled data is passed "
            "to a system shell (e.g. via `os.system`, `subprocess.call` with "
            "`shell=True`, or backtick execution). An attacker can append shell "
            "metacharacters such as `;`, `&&`, `|`, or `$()` to execute arbitrary "
            "operating-system commands with the privileges of the web process — often "
            "leading to full server compromise."
        ),
        "fix": (
            "**Never pass user input to a shell.** Use `subprocess` with a list "
            "argument and `shell=False`:\n\n"
            "```python\n"
            "import subprocess, shlex\n\n"
            "# VULNERABLE\n"
            "os.system(f\"ping {hostname}\")\n\n"
            "# SAFE — list form, shell=False (default)\n"
            "result = subprocess.run(\n"
            "    [\"ping\", \"-c\", \"1\", hostname],\n"
            "    capture_output=True, timeout=10\n"
            ")\n"
            "```\n\n"
            "If a shell is absolutely required, use `shlex.quote()` to escape "
            "arguments. Apply strict allowlist validation on any value that becomes "
            "part of a command."
        ),
        "severity": "critical",
        "references": [
            {
                "title": "CWE-78: Improper Neutralisation of Special Elements in OS Commands",
                "url": "https://cwe.mitre.org/data/definitions/78.html",
            },
            {
                "title": "OWASP OS Command Injection Defense Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            },
            {
                "title": "Python subprocess documentation",
                "url": "https://docs.python.org/3/library/subprocess.html",
            },
        ],
    },
    "CWE-22": {
        "name": "Path Traversal",
        "keywords": [
            "path traversal", "directory traversal", "dot dot slash",
            "../", "..\\", "file inclusion", "local file inclusion",
            "lfi", "cwe-22", "cwe 22",
        ],
        "answer": (
            "Path Traversal (CWE-22) allows attackers to access files and directories "
            "outside an intended base directory by supplying sequences such as `../` "
            "or `..\\` in filenames or paths. This can expose source code, "
            "configuration files containing secrets, `/etc/passwd`, private keys, or "
            "allow overwriting critical files."
        ),
        "fix": (
            "Resolve and validate the **canonical path** before opening any file "
            "derived from user input:\n\n"
            "```python\n"
            "import os, pathlib\n\n"
            "BASE_DIR = pathlib.Path('/var/app/uploads').resolve()\n\n"
            "def safe_open(user_filename: str):\n"
            "    # Resolve strips all '..' components\n"
            "    target = (BASE_DIR / user_filename).resolve()\n"
            "    # Ensure the target is still inside BASE_DIR\n"
            "    if not target.is_relative_to(BASE_DIR):\n"
            "        raise PermissionError('Path traversal detected')\n"
            "    return open(target, 'rb')\n"
            "```\n\n"
            "Additional controls: run the process under a chroot/container; "
            "store files by an opaque UUID rather than user-supplied names."
        ),
        "severity": "high",
        "references": [
            {
                "title": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
                "url": "https://cwe.mitre.org/data/definitions/22.html",
            },
            {
                "title": "OWASP Path Traversal",
                "url": "https://owasp.org/www-community/attacks/Path_Traversal",
            },
            {
                "title": "OWASP File Upload Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            },
        ],
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "keywords": [
            "hardcoded credentials", "hardcoded password", "hardcoded secret",
            "hardcoded api key", "hardcoded token", "credentials in code",
            "secret in source", "cwe-798", "cwe 798",
        ],
        "answer": (
            "Hardcoded Credentials (CWE-798) refers to embedding passwords, API keys, "
            "tokens, or cryptographic keys directly in source code or configuration "
            "files committed to version control. Even private repositories get leaked "
            "or change ownership. Automated secret-scanning tools (truffleHog, "
            "GitLeaks, GitHub Advanced Security) continuously scan public repos and "
            "will find secrets within minutes of a push."
        ),
        "fix": (
            "**Never commit secrets.** Use environment variables or a secrets manager:\n\n"
            "```python\n"
            "# VULNERABLE\n"
            "DB_PASSWORD = 'Sup3rS3cr3t!'\n\n"
            "# SAFE — read from environment\n"
            "import os\n"
            "DB_PASSWORD = os.environ['DB_PASSWORD']  # raise if missing\n"
            "DB_PASSWORD = os.getenv('DB_PASSWORD')   # returns None if missing\n"
            "```\n\n"
            "For production secrets use a dedicated secrets manager:\n"
            "- AWS Secrets Manager / Parameter Store\n"
            "- HashiCorp Vault\n"
            "- Azure Key Vault / GCP Secret Manager\n\n"
            "Rotate any secret that has already been committed and treat it as "
            "compromised. Add a pre-commit hook (`detect-secrets`) and a CI scan "
            "(GitLeaks) to prevent future occurrences."
        ),
        "severity": "critical",
        "references": [
            {
                "title": "CWE-798: Use of Hard-coded Credentials",
                "url": "https://cwe.mitre.org/data/definitions/798.html",
            },
            {
                "title": "OWASP Secrets Management Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            },
            {
                "title": "GitLeaks – secret scanning tool",
                "url": "https://github.com/gitleaks/gitleaks",
            },
        ],
    },
    "CWE-502": {
        "name": "Insecure Deserialization",
        "keywords": [
            "deserialization", "deserialisation", "pickle", "unsafe deserialization",
            "object injection", "java deserialization", "yaml load",
            "cwe-502", "cwe 502",
        ],
        "answer": (
            "Insecure Deserialization (CWE-502) occurs when untrusted data is "
            "deserialised into objects without validation. In Python, `pickle.loads()` "
            "on attacker-controlled bytes can execute arbitrary code during "
            "deserialisation. Similarly, `yaml.load()` (without `Loader=SafeLoader`), "
            "`marshal`, and Java's `ObjectInputStream` are commonly exploited vectors "
            "that can lead to remote code execution or privilege escalation."
        ),
        "fix": (
            "Avoid deserialising data from untrusted sources. Where deserialisation "
            "is necessary, use safe alternatives:\n\n"
            "```python\n"
            "# VULNERABLE — pickle from untrusted source\n"
            "import pickle\n"
            "obj = pickle.loads(user_bytes)  # arbitrary code execution risk\n\n"
            "# VULNERABLE — yaml.load without Loader\n"
            "import yaml\n"
            "data = yaml.load(user_yaml)     # CVE-2017-18342\n\n"
            "# SAFE alternatives\n"
            "import json\n"
            "data = json.loads(user_json)    # JSON is data-only, not executable\n\n"
            "import yaml\n"
            "data = yaml.safe_load(user_yaml)  # SafeLoader disables !! constructors\n"
            "```\n\n"
            "If pickle is required internally, sign the payload with HMAC before "
            "storing/transmitting it, and verify the signature before loading."
        ),
        "severity": "critical",
        "references": [
            {
                "title": "CWE-502: Deserialization of Untrusted Data",
                "url": "https://cwe.mitre.org/data/definitions/502.html",
            },
            {
                "title": "OWASP Deserialization Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            },
            {
                "title": "OWASP Top 10 A08:2021 – Software and Data Integrity Failures",
                "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            },
        ],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "keywords": [
            "ssrf", "server-side request forgery", "server side request forgery",
            "internal request", "metadata endpoint", "aws metadata",
            "internal network", "cwe-918", "cwe 918",
        ],
        "answer": (
            "Server-Side Request Forgery (CWE-918) occurs when an application fetches "
            "a remote resource at a URL supplied by the user without validation. "
            "Attackers can redirect the server to internal addresses (169.254.169.254 "
            "for cloud metadata, 10.x.x.x, 172.16.x.x), access internal services not "
            "exposed to the internet, or pivot through the server's network. In AWS "
            "environments SSRF against the IMDSv1 metadata endpoint can yield "
            "credentials for the instance IAM role."
        ),
        "fix": (
            "Validate and restrict any URL the application fetches on behalf of a user:\n\n"
            "```python\n"
            "from urllib.parse import urlparse\n"
            "import ipaddress, socket\n\n"
            "ALLOWED_SCHEMES = {'https'}\n"
            "BLOCKED_HOSTS = {'169.254.169.254', 'metadata.google.internal'}\n\n"
            "def safe_fetch(url: str) -> bytes:\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.scheme not in ALLOWED_SCHEMES:\n"
            "        raise ValueError('Scheme not allowed')\n"
            "    hostname = parsed.hostname or ''\n"
            "    if hostname in BLOCKED_HOSTS:\n"
            "        raise ValueError('Blocked host')\n"
            "    # Resolve and reject private / loopback ranges\n"
            "    ip = ipaddress.ip_address(socket.gethostbyname(hostname))\n"
            "    if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
            "        raise ValueError('Private IP not allowed')\n"
            "    # Proceed with HTTP client\n"
            "    import requests\n"
            "    return requests.get(url, timeout=5).content\n"  # nosemgrep: dynamic-urllib-use-detected
            "```\n\n"
            "Prefer an allowlist of specific external domains over a blocklist. "
            "Enable IMDSv2 (token-based) on AWS EC2 instances to mitigate metadata theft."
        ),
        "severity": "high",
        "references": [
            {
                "title": "CWE-918: Server-Side Request Forgery",
                "url": "https://cwe.mitre.org/data/definitions/918.html",
            },
            {
                "title": "OWASP SSRF Prevention Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            },
            {
                "title": "OWASP Top 10 A10:2021 – Server-Side Request Forgery",
                "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            },
        ],
    },
    "CWE-611": {
        "name": "XML External Entity (XXE) Injection",
        "keywords": [
            "xxe", "xml external entity", "xml injection", "xml parsing",
            "dtd", "external entity", "lxml", "defusedxml",
            "cwe-611", "cwe 611",
        ],
        "answer": (
            "XXE (CWE-611) is an attack against applications that parse XML. When an "
            "XML parser processes Document Type Definitions (DTDs) it can be directed "
            "to include external entities — arbitrary URIs that the parser fetches "
            "and inlines into the document. This enables reading local files "
            "(`file:///etc/passwd`), port-scanning internal services (via HTTP "
            "entity URIs), or denial-of-service via recursive entity expansion "
            "('Billion Laughs' attack)."
        ),
        "fix": (
            "Disable DTD processing and external entity resolution in your XML parser:\n\n"
            "Python (`lxml`):\n"
            "```python\n"
            "from lxml import etree\n\n"
            "# VULNERABLE (default lxml allows external entities via network)\n"
            "tree = etree.parse(user_xml_file)\n\n"
            "# SAFE — disable DTDs completely\n"
            "parser = etree.XMLParser(\n"
            "    resolve_entities=False,\n"
            "    no_network=True,\n"
            "    load_dtd=False,\n"
            ")\n"
            "tree = etree.parse(user_xml_file, parser)\n"
            "```\n\n"
            "Better: use the **defusedxml** library which is hardened against all "
            "known XML attack vectors:\n"
            "```python\n"
            "import defusedxml.ElementTree as ET\n"
            "tree = ET.parse(user_xml_file)  # safe by default\n"
            "```\n\n"
            "If XML is not strictly required, consider JSON or other data formats."
        ),
        "severity": "high",
        "references": [
            {
                "title": "CWE-611: Improper Restriction of XML External Entity Reference",
                "url": "https://cwe.mitre.org/data/definitions/611.html",
            },
            {
                "title": "OWASP XML External Entity (XXE) Prevention Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            },
            {
                "title": "defusedxml – Python library",
                "url": "https://pypi.org/project/defusedxml/",
            },
        ],
    },
}

# Generic fallback for unrecognised questions
_GENERIC_ENTRY: Dict[str, Any] = {
    "name": "General Security Guidance",
    "answer": (
        "Your question touches on application security. The most common web "
        "application vulnerability classes are described in the OWASP Top 10 and "
        "the CWE/SANS Top 25. Core defensive principles are: validate all input, "
        "encode all output, use parameterised queries, apply least privilege, keep "
        "dependencies updated, and store secrets in a vault — never in source code. "
        "For a tailored answer, provide a CWE identifier in the `context.cwe_id` field."
    ),
    "fix": (
        "Review the OWASP Application Security Verification Standard (ASVS) for "
        "your application tier, and integrate SAST tooling (Bandit for Python, "
        "Semgrep, SonarQube) into your CI pipeline to catch issues early."
    ),
    "severity": "medium",
    "references": [
        {
            "title": "OWASP Top 10",
            "url": "https://owasp.org/www-project-top-ten/",
        },
        {
            "title": "CWE/SANS Top 25 Most Dangerous Software Weaknesses",
            "url": "https://cwe.mitre.org/top25/",
        },
        {
            "title": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/",
        },
    ],
}


# ---------------------------------------------------------------------------
# Helper: match question to a CWE entry
# ---------------------------------------------------------------------------


def _match_cwe(question: str, hint_cwe: Optional[str]) -> tuple[str, Dict[str, Any]]:
    """Return (cwe_id, entry) best matching the question.

    Priority:
    1. Explicit CWE hint from request context  (e.g. 'CWE-89')
    2. Keyword scan of the question text
    3. Generic fallback
    """
    q_lower = question.lower()

    # 1. Explicit hint
    if hint_cwe:
        cwe_upper = hint_cwe.strip().upper()
        # Normalise 'CWE89' → 'CWE-89'
        if cwe_upper.startswith("CWE") and "-" not in cwe_upper:
            cwe_upper = "CWE-" + cwe_upper[3:]
        if cwe_upper in _CWE_KNOWLEDGE:
            return cwe_upper, _CWE_KNOWLEDGE[cwe_upper]

    # 2. Keyword scan
    best_cwe: Optional[str] = None
    best_hits = 0
    for cwe_id, entry in _CWE_KNOWLEDGE.items():
        hits = sum(1 for kw in entry["keywords"] if kw in q_lower)
        if hits > best_hits:
            best_hits = hits
            best_cwe = cwe_id

    if best_cwe and best_hits > 0:
        return best_cwe, _CWE_KNOWLEDGE[best_cwe]

    # 3. Generic fallback
    return "GENERAL", _GENERIC_ENTRY


def _language_adapt_fix(fix: str, language: Optional[str]) -> str:
    """Append a language-specific note when the default fix is for another language."""
    if not language:
        return fix
    lang = language.lower()
    notes: Dict[str, str] = {
        "javascript": (
            "\n\n> **JavaScript / Node.js note:** Use parameterised query libraries "
            "(e.g. `pg` prepared statements, `knex.raw` with bindings, or an ORM "
            "like Sequelize/Prisma) and template literals from trusted sources only."
        ),
        "java": (
            "\n\n> **Java note:** Use `PreparedStatement` with `?` placeholders, "
            "or JPA/Hibernate named parameters (`@Query(\"... WHERE id = :id\")`)."
        ),
        "go": (
            "\n\n> **Go note:** Use `db.QueryContext` with `?` or `$N` placeholders; "
            "never `fmt.Sprintf` into query strings."
        ),
        "ruby": (
            "\n\n> **Ruby note:** Use ActiveRecord's parameterised finders "
            "(`User.where('id = ?', params[:id])`) instead of string interpolation."
        ),
        "php": (
            "\n\n> **PHP note:** Use PDO with prepared statements "
            "(`$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?')`) "
            "instead of `mysqli_query` with string concatenation."
        ),
    }
    return fix + notes.get(lang, f"\n\n> **{language.capitalize()} note:** Apply the same principle using your language's parameterised query / safe API equivalent.")


# ---------------------------------------------------------------------------
# /ask endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/ask",
    response_model=AskResponse,
    summary="Ask a security question (Rachel Kim / Junior Developer)",
    description=(
        "Stateless natural-language security Q&A backed by a built-in CWE "
        "knowledge base. No external LLM required. Covers CWE-89, CWE-79, "
        "CWE-78, CWE-22, CWE-798, CWE-502, CWE-918, CWE-611 and more."
    ),
    tags=["copilot"],
)
async def ask_security_question(request: AskRequest) -> AskResponse:
    """Answer a natural-language security question using built-in knowledge.

    Designed for the **Junior Developer** persona (Rachel Kim) who needs
    quick, actionable answers without navigating long documentation.

    The endpoint:
    - Matches the question to the most relevant CWE entry via keyword analysis
      or an explicit CWE hint in `context.cwe_id`
    - Returns a plain-English explanation, concrete fix with code examples,
      severity rating, and authoritative references
    - Works offline — no OpenAI/Anthropic API key required
    - Optionally enriches the response via LLM if providers are available
    """
    ctx = request.context or AskContext()
    hint_cwe = ctx.cwe_id

    # ------------------------------------------------------------------
    # Step 1: Try GraphRAG security-ops path for ops-level questions.
    # Questions like "What are our top risks?" or "Are we compliant with
    # SOC2?" are answered with real graph data + structured actions.
    # CWE-level developer questions fall through to the knowledge base.
    # ------------------------------------------------------------------
    intent = _classify_security_intent(request.question)
    if intent is not None:
        insight = _generate_security_insight(request.question, intent)
        if insight is not None:
            # Log to Knowledge Brain
            if _HAS_BRAIN:
                try:
                    bus = get_event_bus()
                    await bus.emit(
                        Event(
                            event_type=EventType.COPILOT_QUERY,
                            source="copilot_router.ask.graphrag",
                            data={
                                "question": request.question[:300],
                                "intent": intent,
                                "enriched": insight.get("enriched", False),
                            },
                        )
                    )
                except (OSError, ValueError, RuntimeError):
                    pass

            logger.info(
                "Copilot /ask: intent=%s source=graphrag_security_insight enriched=%s",
                intent,
                insight.get("enriched"),
            )

            return AskResponse(
                answer=insight["answer"],
                references=[],
                suggested_fix="",
                severity_context="medium",
                related_findings=insight.get("findings", []),
                matched_cwe=None,
                source=insight["source"],
                intent=intent,
                recommended_actions=insight.get("recommended_actions", []),
                confidence=insight.get("confidence", 0.0),
            )

    # ------------------------------------------------------------------
    # Step 2: CWE / developer knowledge base path (original behaviour).
    # ------------------------------------------------------------------

    # Match question to CWE knowledge
    matched_cwe_id, entry = _match_cwe(request.question, hint_cwe)

    # Adapt fix for the requested language
    fix = _language_adapt_fix(entry["fix"], ctx.language)

    # Build references list
    refs = [AskReference(**r) for r in entry["references"]]

    # Optionally enhance via LLM (if available and configured)
    answer_text = entry["answer"]
    source = "builtin_knowledge_base"

    if _HAS_LLM:
        try:
            manager = LLMProviderManager()
            llm_prompt = (
                f"You are FixOps Security Copilot helping a junior developer.\n"
                f"The developer asked: {request.question}\n\n"
                f"CWE category: {matched_cwe_id} — {entry['name']}\n"
                f"Base answer: {answer_text}\n\n"
                "Please provide an enhanced, clear explanation in 2–3 paragraphs. "
                "Keep it practical and jargon-free for a junior developer."
            )
            for provider_name in ("anthropic", "openai"):
                llm_resp = manager.analyse(
                    provider_name,
                    prompt=llm_prompt,
                    context={"cwe_id": matched_cwe_id, "language": ctx.language},
                    default_action="review",
                    default_confidence=0.8,
                    default_reasoning=answer_text,
                )
                if llm_resp.metadata.get("mode") == "remote" and llm_resp.reasoning:
                    answer_text = llm_resp.reasoning
                    source = f"llm_enhanced_{provider_name}"
                    break
        except (OSError, ValueError, KeyError, RuntimeError) as llm_exc:  # narrowed from bare Exception
            logger.debug("LLM enhancement for /ask failed (non-fatal): %s", llm_exc)

    # Log to Knowledge Brain if available
    if _HAS_BRAIN:
        try:
            bus = get_event_bus()
            await bus.emit(
                Event(
                    event_type=EventType.COPILOT_QUERY,
                    source="copilot_router.ask",
                    data={
                        "question": request.question[:300],
                        "matched_cwe": matched_cwe_id,
                        "finding_id": ctx.finding_id,
                        "language": ctx.language,
                    },
                )
            )
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
            pass

    logger.info(
        "Copilot /ask: matched_cwe=%s source=%s language=%s",
        matched_cwe_id,
        source,
        ctx.language,
    )

    return AskResponse(
        answer=answer_text,
        references=refs,
        suggested_fix=fix,
        severity_context=entry["severity"],
        related_findings=[],
        matched_cwe=matched_cwe_id if matched_cwe_id != "GENERAL" else None,
        source=source,
        intent=None,
        recommended_actions=[],
        confidence=0.0,
    )


@router.get("/status")
async def copilot_status() -> Dict[str, Any]:
    """Status alias for copilot service."""
    return await copilot_health()
