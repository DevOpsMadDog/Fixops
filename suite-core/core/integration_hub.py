"""Integration Hub — unified delivery engine for Slack, Jira, PagerDuty, ServiceNow, Teams.

Features:
    - Connector registry (add / remove / list integrations with credential masking)
    - Webhook management (inbound + outbound hooks with signature verification)
    - Event routing (finding.created → Jira, incident.critical → PagerDuty, etc.)
    - Message templates per integration with Jinja2-style variable substitution
    - Retry with exponential backoff + circuit-breaker for failed deliveries
    - Bidirectional sync stubs (Jira status → ALDECI finding status)
    - Integration health monitoring (last sync, error count, latency p50/p95)

Design principles:
    - Pure Python — no new heavyweight dependencies beyond what exists in connectors.py
    - Pydantic v2 models, structlog-compatible logging
    - Thread-safe in-process state (suitable for single-process FastAPI workers)
    - All credentials masked in logs / API responses
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import random
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock, RLock
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mask_secret(value: Optional[str]) -> Optional[str]:
    """Return a masked version of a secret for safe logging/display."""
    if not value:
        return value
    if len(value) <= 6:
        return "***"
    return value[:3] + "***" + value[-3:]


def _substitute(template: str, context: Dict[str, Any]) -> str:
    """Simple {{ key }} variable substitution — no Jinja2 dependency needed."""
    result = template
    for k, v in context.items():
        result = result.replace("{{" + k + "}}", str(v))
        result = result.replace("{{ " + k + " }}", str(v))
    return result


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IntegrationType(str, Enum):
    slack = "slack"
    jira = "jira"
    pagerduty = "pagerduty"
    servicenow = "servicenow"
    teams = "teams"
    webhook = "webhook"  # generic outbound webhook


class CircuitState(str, Enum):
    closed = "closed"
    open = "open"
    half_open = "half_open"


class EventType(str, Enum):
    finding_created = "finding.created"
    finding_updated = "finding.updated"
    finding_resolved = "finding.resolved"
    incident_critical = "incident.critical"
    incident_high = "incident.high"
    compliance_breach = "compliance.breach"
    compliance_passed = "compliance.passed"
    asset_discovered = "asset.discovered"
    scan_completed = "scan.completed"
    generic = "generic"


class SyncDirection(str, Enum):
    outbound = "outbound"   # ALDECI → integration
    inbound = "inbound"     # integration → ALDECI
    bidirectional = "bidirectional"


# ---------------------------------------------------------------------------
# Pydantic config models
# ---------------------------------------------------------------------------

class SlackConfig(BaseModel):
    webhook_url: str = Field(..., description="Slack Incoming Webhook URL")
    channel: str = Field("#security", description="Default channel (e.g. #security)")
    bot_token: Optional[str] = Field(None, description="Bot OAuth token for API calls")
    signing_secret: Optional[str] = Field(None, description="For verifying inbound events")

    @field_validator("webhook_url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://hooks.slack.com/"):
            raise ValueError("webhook_url must be a Slack hooks URL")
        return v


class JiraConfig(BaseModel):
    base_url: str = Field(..., description="Jira instance URL")
    email: str = Field(..., description="Jira user email")
    api_token: str = Field(..., description="Jira API token")
    project_key: str = Field(..., description="Default project key (e.g. SEC)")
    issue_type: str = Field("Bug", description="Default issue type")
    sync_direction: SyncDirection = SyncDirection.bidirectional

    @field_validator("base_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.strip().rstrip("/")

    @field_validator("project_key")
    @classmethod
    def _upper_project(cls, v: str) -> str:
        return v.strip().upper()


class PagerDutyConfig(BaseModel):
    integration_key: str = Field(..., description="PagerDuty Events API v2 routing key")
    api_token: Optional[str] = Field(None, description="REST API token for read-back")
    escalation_policy_id: Optional[str] = None
    severity_map: Dict[str, str] = Field(
        default_factory=lambda: {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
        }
    )


class ServiceNowConfig(BaseModel):
    instance_url: str = Field(..., description="ServiceNow instance URL")
    username: str = Field(..., description="ServiceNow username")
    password: str = Field(..., description="ServiceNow password")
    table: str = Field("incident", description="Target table (incident, problem, change_request)")
    sync_direction: SyncDirection = SyncDirection.bidirectional

    @field_validator("instance_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.strip().rstrip("/")


class TeamsConfig(BaseModel):
    webhook_url: str = Field(..., description="MS Teams Incoming Webhook URL")
    channel_name: Optional[str] = Field(None, description="Channel display name (cosmetic)")

    @field_validator("webhook_url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://"):
            raise ValueError("webhook_url must be https://")
        return v


class WebhookConfig(BaseModel):
    url: str = Field(..., description="Generic outbound webhook URL")
    secret: Optional[str] = Field(None, description="HMAC-SHA256 signing secret")
    headers: Dict[str, str] = Field(default_factory=dict)
    method: str = Field("POST", description="HTTP method")

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return v


# Union discriminated by integration_type — stored as raw dict in registry
IntegrationConfig = SlackConfig | JiraConfig | PagerDutyConfig | ServiceNowConfig | TeamsConfig | WebhookConfig


# ---------------------------------------------------------------------------
# Registration / descriptor model
# ---------------------------------------------------------------------------

class IntegrationRegistration(BaseModel):
    """Descriptor stored in the connector registry."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Unique human-readable name (slug)")
    integration_type: IntegrationType
    config: Dict[str, Any] = Field(..., description="Raw config dict (credentials masked on read)")
    enabled: bool = True
    created_at: str = Field(default_factory=_now_iso)
    updated_at: str = Field(default_factory=_now_iso)
    tags: List[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _slug_name(cls, v: str) -> str:
        import re
        v = v.strip().lower()
        if not re.match(r"^[a-z0-9][a-z0-9_-]{0,62}$", v):
            raise ValueError("name must be lowercase alphanumeric slug (max 63 chars)")
        return v


class IntegrationRegistrationResponse(BaseModel):
    """Safe API response — secrets masked."""

    id: str
    name: str
    integration_type: IntegrationType
    enabled: bool
    created_at: str
    updated_at: str
    tags: List[str]
    config_summary: Dict[str, Any]  # safe subset, no raw secrets


# ---------------------------------------------------------------------------
# Webhook models
# ---------------------------------------------------------------------------

class WebhookRegistration(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    integration_id: str
    direction: SyncDirection
    path: str = Field(..., description="Inbound path suffix or outbound URL")
    secret: Optional[str] = Field(None, description="HMAC signing secret for verification")
    event_types: List[EventType] = Field(default_factory=list)
    created_at: str = Field(default_factory=_now_iso)
    active: bool = True


class WebhookRegistrationResponse(BaseModel):
    id: str
    integration_id: str
    direction: SyncDirection
    path: str
    event_types: List[EventType]
    created_at: str
    active: bool
    secret_hint: Optional[str]  # masked


# ---------------------------------------------------------------------------
# Event routing
# ---------------------------------------------------------------------------

class RoutingRule(BaseModel):
    """Maps an EventType to one or more integration targets."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    integration_ids: List[str] = Field(..., min_length=1)
    filter_expr: Optional[str] = Field(
        None, description="Optional jmespath-like filter (e.g. severity==critical)"
    )
    template_name: Optional[str] = Field(None, description="Named template override")
    enabled: bool = True
    created_at: str = Field(default_factory=_now_iso)


class DeliveryAttempt(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    integration_id: str
    event_type: EventType
    payload: Dict[str, Any]
    attempt_number: int = 1
    success: bool = False
    status_code: Optional[int] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    timestamp: str = Field(default_factory=_now_iso)


# ---------------------------------------------------------------------------
# Message templates
# ---------------------------------------------------------------------------

_DEFAULT_TEMPLATES: Dict[str, Dict[str, str]] = {
    IntegrationType.slack: {
        EventType.finding_created: (
            ":red_circle: *New Finding* — *{{ severity }}*\n"
            ">*{{ title }}*\n"
            ">Asset: {{ asset_name }}  |  Source: {{ source }}\n"
            ">ID: `{{ id }}`"
        ),
        EventType.incident_critical: (
            ":rotating_light: *CRITICAL INCIDENT*\n"
            ">{{ title }}\n"
            ">{{ description }}"
        ),
        EventType.compliance_breach: (
            ":warning: *Compliance Breach — {{ framework }}*\n"
            ">Control: {{ control_id }}  |  Org: {{ org_id }}"
        ),
        "default": ":bell: *ALDECI Event* — {{ event_type }}\n>{{ title }}",
    },
    IntegrationType.jira: {
        EventType.finding_created: (
            "h3. {{ title }}\n\n"
            "*Severity*: {{ severity }}\n"
            "*Asset*: {{ asset_name }}\n"
            "*Source*: {{ source }}\n"
            "*Finding ID*: {{ id }}\n\n"
            "{{ description }}"
        ),
        "default": "ALDECI {{ event_type }}: {{ title }}\n{{ description }}",
    },
    IntegrationType.pagerduty: {
        EventType.incident_critical: "{{ title }}: {{ description }}",
        EventType.finding_created: "Finding {{ id }}: {{ title }} ({{ severity }})",
        "default": "{{ event_type }}: {{ title }}",
    },
    IntegrationType.servicenow: {
        EventType.finding_created: "{{ title }} — Severity: {{ severity }} — Asset: {{ asset_name }}",
        EventType.compliance_breach: "Compliance breach: {{ framework }} / {{ control_id }}",
        "default": "ALDECI {{ event_type }}: {{ title }}",
    },
    IntegrationType.teams: {
        EventType.finding_created: "**New Finding ({{ severity }})**: {{ title }} on {{ asset_name }}",
        EventType.incident_critical: "CRITICAL: {{ title }}\n{{ description }}",
        EventType.compliance_breach: "Compliance Breach — {{ framework }}: {{ control_id }}",
        "default": "ALDECI Event: {{ event_type }} — {{ title }}",
    },
    IntegrationType.webhook: {
        "default": "{{ event_type }}: {{ title }}",
    },
}


class TemplateStore:
    """In-memory registry of named message templates."""

    def __init__(self) -> None:
        self._lock = RLock()
        # {name: {integration_type: {event_type: template_str}}}
        self._custom: Dict[str, Dict[str, Dict[str, str]]] = {}

    def register(
        self,
        name: str,
        integration_type: IntegrationType,
        event_type: str,
        template: str,
    ) -> None:
        with self._lock:
            self._custom.setdefault(name, {}).setdefault(integration_type, {})[event_type] = template

    def resolve(
        self,
        integration_type: IntegrationType,
        event_type: EventType,
        template_name: Optional[str] = None,
    ) -> str:
        with self._lock:
            if template_name and template_name in self._custom:
                tmap = self._custom[template_name].get(integration_type, {})
                if event_type in tmap:
                    return tmap[event_type]
                if "default" in tmap:
                    return tmap["default"]
            # Fall back to built-in defaults
            tmap = _DEFAULT_TEMPLATES.get(integration_type, {})
            return tmap.get(event_type, tmap.get("default", "{{ event_type }}: {{ title }}"))

    def render(
        self,
        integration_type: IntegrationType,
        event_type: EventType,
        context: Dict[str, Any],
        template_name: Optional[str] = None,
    ) -> str:
        template = self.resolve(integration_type, event_type, template_name)
        ctx = {"event_type": event_type, **context}
        return _substitute(template, ctx)

    def list_templates(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._custom)


# ---------------------------------------------------------------------------
# Circuit breaker (per integration)
# ---------------------------------------------------------------------------

@dataclass
class _CircuitBreaker:
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3

    _state: CircuitState = field(default=CircuitState.closed, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: Optional[float] = field(default=None, init=False)
    _half_open_calls: int = field(default=0, init=False)
    _lock: Lock = field(default_factory=Lock, init=False)

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.open:
                if (
                    self._last_failure_time is not None
                    and time.monotonic() - self._last_failure_time >= self.recovery_timeout
                ):
                    self._state = CircuitState.half_open
                    self._half_open_calls = 0
            return self._state

    def allow_request(self) -> bool:
        return self.state in (CircuitState.closed, CircuitState.half_open)

    def record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.half_open:
                self._half_open_calls += 1
                if self._half_open_calls >= self.half_open_max_calls:
                    self._state = CircuitState.closed
                    self._failure_count = 0
            elif self._state == CircuitState.closed:
                self._failure_count = 0

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state == CircuitState.half_open:
                self._state = CircuitState.open
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.open


# ---------------------------------------------------------------------------
# Health tracking (per integration)
# ---------------------------------------------------------------------------

@dataclass
class IntegrationHealth:
    integration_id: str
    integration_name: str
    integration_type: IntegrationType
    enabled: bool = True
    circuit_state: CircuitState = CircuitState.closed

    total_deliveries: int = 0
    successful_deliveries: int = 0
    failed_deliveries: int = 0
    consecutive_failures: int = 0
    error_count: int = 0

    last_success_at: Optional[str] = None
    last_failure_at: Optional[str] = None
    last_sync_at: Optional[str] = None
    last_error: Optional[str] = None

    # Rolling latency samples (last 100)
    _latencies: Deque[float] = field(default_factory=lambda: deque(maxlen=100), repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def record_delivery(self, success: bool, latency_ms: float, error: Optional[str] = None) -> None:
        with self._lock:
            self.total_deliveries += 1
            self._latencies.append(latency_ms)
            ts = _now_iso()
            if success:
                self.successful_deliveries += 1
                self.consecutive_failures = 0
                self.last_success_at = ts
                self.last_sync_at = ts
            else:
                self.failed_deliveries += 1
                self.consecutive_failures += 1
                self.error_count += 1
                self.last_failure_at = ts
                self.last_error = error

    @property
    def success_rate(self) -> float:
        if self.total_deliveries == 0:
            return 1.0
        return self.successful_deliveries / self.total_deliveries

    @property
    def latency_p50(self) -> Optional[float]:
        if not self._latencies:
            return None
        srt = sorted(self._latencies)
        return srt[int(len(srt) * 0.50)]

    @property
    def latency_p95(self) -> Optional[float]:
        if not self._latencies:
            return None
        srt = sorted(self._latencies)
        return srt[min(int(len(srt) * 0.95), len(srt) - 1)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "integration_name": self.integration_name,
            "integration_type": self.integration_type,
            "enabled": self.enabled,
            "circuit_state": self.circuit_state,
            "total_deliveries": self.total_deliveries,
            "successful_deliveries": self.successful_deliveries,
            "failed_deliveries": self.failed_deliveries,
            "consecutive_failures": self.consecutive_failures,
            "error_count": self.error_count,
            "success_rate": round(self.success_rate, 4),
            "latency_p50_ms": self.latency_p50,
            "latency_p95_ms": self.latency_p95,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "last_sync_at": self.last_sync_at,
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------------
# Delivery result
# ---------------------------------------------------------------------------

class DeliveryResult(BaseModel):
    success: bool
    integration_id: str
    integration_name: str
    event_type: EventType
    attempt: int
    latency_ms: float
    status_code: Optional[int] = None
    error: Optional[str] = None
    external_id: Optional[str] = None  # Jira issue key, PD incident id, etc.
    timestamp: str = Field(default_factory=_now_iso)


# ---------------------------------------------------------------------------
# Bidirectional sync stub
# ---------------------------------------------------------------------------

class SyncRecord(BaseModel):
    """Represents an inbound status sync from an external integration."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    integration_id: str
    external_id: str         # e.g. Jira issue key "SEC-42"
    external_status: str     # e.g. "Done", "In Progress"
    aldeci_finding_id: Optional[str] = None
    aldeci_status: Optional[str] = None  # mapped ALDECI status
    synced_at: str = Field(default_factory=_now_iso)
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


# Jira status → ALDECI finding status mapping
_JIRA_STATUS_MAP: Dict[str, str] = {
    "To Do": "open",
    "In Progress": "in_remediation",
    "In Review": "in_remediation",
    "Done": "resolved",
    "Closed": "resolved",
    "Resolved": "resolved",
    "Cancelled": "risk_accepted",
    "Won't Do": "risk_accepted",
    "Backlog": "open",
}

# ServiceNow state → ALDECI status
_SNOW_STATE_MAP: Dict[str, str] = {
    "1": "open",        # New
    "2": "in_remediation",  # In Progress
    "3": "in_remediation",  # On Hold
    "6": "resolved",    # Resolved
    "7": "resolved",    # Closed
}


def map_jira_status(jira_status: str) -> str:
    return _JIRA_STATUS_MAP.get(jira_status, "open")


def map_servicenow_state(snow_state: str) -> str:
    return _SNOW_STATE_MAP.get(snow_state, "open")


# ---------------------------------------------------------------------------
# Connector registry
# ---------------------------------------------------------------------------

class ConnectorRegistry:
    """Thread-safe in-memory registry of integration connectors."""

    def __init__(self) -> None:
        self._lock = RLock()
        # name → IntegrationRegistration
        self._integrations: Dict[str, IntegrationRegistration] = {}
        # integration_id → _CircuitBreaker
        self._circuit_breakers: Dict[str, _CircuitBreaker] = {}
        # integration_id → IntegrationHealth
        self._health: Dict[str, IntegrationHealth] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, registration: IntegrationRegistration) -> IntegrationRegistration:
        with self._lock:
            if registration.name in self._integrations:
                raise ValueError(f"Integration '{registration.name}' already exists")
            self._integrations[registration.name] = registration
            self._circuit_breakers[registration.id] = _CircuitBreaker()
            self._health[registration.id] = IntegrationHealth(
                integration_id=registration.id,
                integration_name=registration.name,
                integration_type=registration.integration_type,
                enabled=registration.enabled,
            )
            logger.info(
                "integration_registered",
                extra={"name": registration.name, "type": registration.integration_type},
            )
            _emit_event("integration.registered", {"id": registration.id, "name": registration.name, "type": registration.integration_type})
            return registration

    def remove(self, name: str) -> bool:
        with self._lock:
            reg = self._integrations.pop(name, None)
            if reg is None:
                return False
            self._circuit_breakers.pop(reg.id, None)
            self._health.pop(reg.id, None)
            logger.info("integration_removed", extra={"name": name})
            return True

    def get(self, name: str) -> Optional[IntegrationRegistration]:
        with self._lock:
            return self._integrations.get(name)

    def get_by_id(self, integration_id: str) -> Optional[IntegrationRegistration]:
        with self._lock:
            for reg in self._integrations.values():
                if reg.id == integration_id:
                    return reg
            return None

    def list_all(self, enabled_only: bool = False) -> List[IntegrationRegistration]:
        with self._lock:
            regs = list(self._integrations.values())
        if enabled_only:
            regs = [r for r in regs if r.enabled]
        return regs

    def enable(self, name: str) -> bool:
        return self._set_enabled(name, True)

    def disable(self, name: str) -> bool:
        return self._set_enabled(name, False)

    def _set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            reg = self._integrations.get(name)
            if reg is None:
                return False
            self._integrations[name] = reg.model_copy(
                update={"enabled": enabled, "updated_at": _now_iso()}
            )
            hlth = self._health.get(reg.id)
            if hlth:
                hlth.enabled = enabled
            return True

    # ------------------------------------------------------------------
    # Circuit breaker access
    # ------------------------------------------------------------------

    def circuit_breaker(self, integration_id: str) -> Optional[_CircuitBreaker]:
        with self._lock:
            return self._circuit_breakers.get(integration_id)

    # ------------------------------------------------------------------
    # Health access
    # ------------------------------------------------------------------

    def health(self, integration_id: str) -> Optional[IntegrationHealth]:
        with self._lock:
            return self._health.get(integration_id)

    def all_health(self) -> List[IntegrationHealth]:
        with self._lock:
            return list(self._health.values())

    def reset_circuit_breaker(self, name: str) -> bool:
        with self._lock:
            reg = self._integrations.get(name)
            if reg is None:
                return False
            cb = self._circuit_breakers.get(reg.id)
            if cb is None:
                return False
            with cb._lock:
                cb._state = CircuitState.closed
                cb._failure_count = 0
                cb._last_failure_time = None
                cb._half_open_calls = 0
            logger.info("circuit_breaker_reset", extra={"name": name})
            return True


# ---------------------------------------------------------------------------
# Webhook registry
# ---------------------------------------------------------------------------

class WebhookRegistry:
    """Manages inbound and outbound webhook registrations."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._hooks: Dict[str, WebhookRegistration] = {}  # id → hook

    def register(self, hook: WebhookRegistration) -> WebhookRegistration:
        with self._lock:
            self._hooks[hook.id] = hook
            logger.info(
                "webhook_registered",
                extra={"id": hook.id, "direction": hook.direction, "path": hook.path},
            )
            return hook

    def remove(self, hook_id: str) -> bool:
        with self._lock:
            existed = hook_id in self._hooks
            self._hooks.pop(hook_id, None)
            return existed

    def get(self, hook_id: str) -> Optional[WebhookRegistration]:
        with self._lock:
            return self._hooks.get(hook_id)

    def list_for_integration(self, integration_id: str) -> List[WebhookRegistration]:
        with self._lock:
            return [h for h in self._hooks.values() if h.integration_id == integration_id]

    def list_all(self) -> List[WebhookRegistration]:
        with self._lock:
            return list(self._hooks.values())

    def verify_signature(self, hook_id: str, payload: bytes, signature: str) -> bool:
        """Verify HMAC-SHA256 signature for an inbound webhook."""
        hook = self.get(hook_id)
        if hook is None or not hook.secret:
            return False
        expected = hmac.new(
            hook.secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature.lstrip("sha256="))


# ---------------------------------------------------------------------------
# Event router
# ---------------------------------------------------------------------------

class EventRouter:
    """Routes ALDECI events to the appropriate integration targets."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._rules: Dict[str, RoutingRule] = {}  # id → rule

    def add_rule(self, rule: RoutingRule) -> RoutingRule:
        with self._lock:
            self._rules[rule.id] = rule
            logger.info(
                "routing_rule_added",
                extra={"event_type": rule.event_type, "targets": rule.integration_ids},
            )
            return rule

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            existed = rule_id in self._rules
            self._rules.pop(rule_id, None)
            return existed

    def get_rule(self, rule_id: str) -> Optional[RoutingRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self) -> List[RoutingRule]:
        with self._lock:
            return list(self._rules.values())

    def resolve(
        self,
        event_type: EventType,
        event_payload: Dict[str, Any],
    ) -> List[Tuple[str, Optional[str]]]:
        """Return list of (integration_id, template_name) tuples for this event."""
        with self._lock:
            rules = [r for r in self._rules.values() if r.enabled and r.event_type == event_type]

        targets: List[Tuple[str, Optional[str]]] = []
        for rule in rules:
            if rule.filter_expr and not self._evaluate_filter(rule.filter_expr, event_payload):
                continue
            for iid in rule.integration_ids:
                targets.append((iid, rule.template_name))
        return targets

    def _evaluate_filter(self, expr: str, payload: Dict[str, Any]) -> bool:
        """Evaluate simple key==value filter expression."""
        try:
            if "==" in expr:
                lhs, rhs = expr.split("==", 1)
                lhs, rhs = lhs.strip(), rhs.strip().strip("'\"")
                return str(payload.get(lhs, "")) == rhs
            if "!=" in expr:
                lhs, rhs = expr.split("!=", 1)
                lhs, rhs = lhs.strip(), rhs.strip().strip("'\"")
                return str(payload.get(lhs, "")) != rhs
        except Exception:
            pass
        return True  # pass-through on unparseable expression


# ---------------------------------------------------------------------------
# Delivery engine (retry + circuit breaker)
# ---------------------------------------------------------------------------

class DeliveryEngine:
    """Delivers events to integration endpoints with retry and circuit breaker.

    This class is a pure orchestration layer — actual HTTP calls are delegated
    to integration-specific adapter functions so the engine itself stays
    framework-agnostic and easily unit-testable via mock adapters.
    """

    def __init__(
        self,
        registry: ConnectorRegistry,
        template_store: TemplateStore,
        max_retries: int = 3,
        base_backoff: float = 1.0,
        max_backoff: float = 30.0,
    ) -> None:
        self._registry = registry
        self._template_store = template_store
        self._max_retries = max_retries
        self._base_backoff = base_backoff
        self._max_backoff = max_backoff
        # integration_type → adapter callable
        self._adapters: Dict[IntegrationType, Callable[..., Dict[str, Any]]] = {}
        # Delivery history (last 1000)
        self._history: Deque[DeliveryAttempt] = deque(maxlen=1000)
        self._history_lock = Lock()

    def register_adapter(
        self,
        integration_type: IntegrationType,
        adapter: Callable[..., Dict[str, Any]],
    ) -> None:
        """Register an HTTP adapter for an integration type.

        Adapter signature:
            adapter(config: dict, payload: dict) -> {"success": bool, "status_code": int, "external_id": str, "error": str}
        """
        self._adapters[integration_type] = adapter

    def deliver(
        self,
        integration_id: str,
        event_type: EventType,
        event_payload: Dict[str, Any],
        template_name: Optional[str] = None,
    ) -> DeliveryResult:
        """Deliver a single event to one integration, with retry + circuit breaker."""
        reg = self._registry.get_by_id(integration_id)
        if reg is None:
            return DeliveryResult(
                success=False,
                integration_id=integration_id,
                integration_name="unknown",
                event_type=event_type,
                attempt=0,
                latency_ms=0.0,
                error=f"Integration {integration_id!r} not found",
            )

        if not reg.enabled:
            return DeliveryResult(
                success=False,
                integration_id=integration_id,
                integration_name=reg.name,
                event_type=event_type,
                attempt=0,
                latency_ms=0.0,
                error="Integration disabled",
            )

        cb = self._registry.circuit_breaker(integration_id)
        if cb and not cb.allow_request():
            return DeliveryResult(
                success=False,
                integration_id=integration_id,
                integration_name=reg.name,
                event_type=event_type,
                attempt=0,
                latency_ms=0.0,
                error="Circuit breaker open — delivery blocked",
            )

        message = self._template_store.render(
            reg.integration_type, event_type, event_payload, template_name
        )

        adapter = self._adapters.get(reg.integration_type, _noop_adapter)
        last_result: Optional[Dict[str, Any]] = None
        attempt = 0

        for attempt in range(1, self._max_retries + 1):
            t0 = time.monotonic()
            try:
                result = adapter(
                    config=reg.config,
                    payload={"message": message, "event": event_payload, "event_type": event_type},
                )
                latency_ms = (time.monotonic() - t0) * 1000
                last_result = result
            except Exception as exc:
                latency_ms = (time.monotonic() - t0) * 1000
                last_result = {"success": False, "error": str(exc)}

            success = bool(last_result.get("success"))
            hlth = self._registry.health(integration_id)
            if hlth:
                hlth.record_delivery(success, latency_ms, last_result.get("error"))
            if cb:
                cb.record_success() if success else cb.record_failure()

            attempt_record = DeliveryAttempt(
                integration_id=integration_id,
                event_type=event_type,
                payload=event_payload,
                attempt_number=attempt,
                success=success,
                status_code=last_result.get("status_code"),
                error=last_result.get("error"),
                latency_ms=latency_ms,
            )
            with self._history_lock:
                self._history.append(attempt_record)

            if success:
                logger.info(
                    "delivery_success",
                    extra={"integration": reg.name, "event_type": event_type, "attempt": attempt},
                )
                return DeliveryResult(
                    success=True,
                    integration_id=integration_id,
                    integration_name=reg.name,
                    event_type=event_type,
                    attempt=attempt,
                    latency_ms=latency_ms,
                    status_code=last_result.get("status_code"),
                    external_id=last_result.get("external_id"),
                )

            if attempt < self._max_retries:
                backoff = min(
                    self._base_backoff * (2 ** (attempt - 1)) + random.uniform(0, 0.5),
                    self._max_backoff,
                )
                logger.warning(
                    "delivery_retry",
                    extra={
                        "integration": reg.name,
                        "event_type": event_type,
                        "attempt": attempt,
                        "backoff_s": round(backoff, 2),
                        "error": last_result.get("error"),
                    },
                )
                time.sleep(backoff)

        error_msg = (last_result or {}).get("error", "unknown error")
        logger.error(
            "delivery_failed",
            extra={"integration": reg.name, "event_type": event_type, "attempts": attempt},
        )
        return DeliveryResult(
            success=False,
            integration_id=integration_id,
            integration_name=reg.name,
            event_type=event_type,
            attempt=attempt,
            latency_ms=0.0,
            error=error_msg,
        )

    def get_history(self, limit: int = 100) -> List[DeliveryAttempt]:
        with self._history_lock:
            items = list(self._history)
        return items[-limit:]


def _noop_adapter(config: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """No-op adapter used when no real adapter is registered (e.g. in tests)."""
    return {"success": True, "status_code": 200, "external_id": None, "error": None}


# ---------------------------------------------------------------------------
# Bidirectional sync manager
# ---------------------------------------------------------------------------

class BidirectionalSyncManager:
    """Manages inbound status syncs from external integrations into ALDECI.

    In production, inbound webhooks call `process_inbound_sync()`. This manager
    maps external statuses to ALDECI finding statuses and stores the sync record.
    Actual ALDECI DB writes are injected via `finding_status_callback`.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: Dict[str, SyncRecord] = {}  # id → record
        self._finding_status_callback: Optional[Callable[[str, str], bool]] = None

    def set_finding_status_callback(self, cb: Callable[[str, str], bool]) -> None:
        """Register a callback: cb(finding_id, new_status) → bool."""
        self._finding_status_callback = cb

    def process_inbound_sync(
        self,
        integration_id: str,
        integration_type: IntegrationType,
        external_id: str,
        external_status: str,
        aldeci_finding_id: Optional[str],
        raw_payload: Dict[str, Any],
    ) -> SyncRecord:
        """Process a status update arriving from an external integration."""
        if integration_type == IntegrationType.jira:
            aldeci_status = map_jira_status(external_status)
        elif integration_type == IntegrationType.servicenow:
            aldeci_status = map_servicenow_state(external_status)
        else:
            aldeci_status = external_status.lower()

        record = SyncRecord(
            integration_id=integration_id,
            external_id=external_id,
            external_status=external_status,
            aldeci_finding_id=aldeci_finding_id,
            aldeci_status=aldeci_status,
            raw_payload=raw_payload,
        )

        with self._lock:
            self._records[record.id] = record

        if aldeci_finding_id and self._finding_status_callback:
            try:
                self._finding_status_callback(aldeci_finding_id, aldeci_status)
            except Exception as exc:
                logger.warning(
                    "finding_status_callback_failed",
                    extra={"finding_id": aldeci_finding_id, "error": str(exc)},
                )

        logger.info(
            "inbound_sync_processed",
            extra={
                "integration_id": integration_id,
                "external_id": external_id,
                "external_status": external_status,
                "aldeci_status": aldeci_status,
            },
        )
        return record

    def get_sync_records(
        self,
        integration_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[SyncRecord]:
        with self._lock:
            records = list(self._records.values())
        if integration_id:
            records = [r for r in records if r.integration_id == integration_id]
        return records[-limit:]


# ---------------------------------------------------------------------------
# Integration Hub — top-level facade
# ---------------------------------------------------------------------------

class IntegrationHub:
    """Facade coordinating all Integration Hub subsystems.

    Usage::

        hub = IntegrationHub()

        # Register a Slack integration
        hub.add_integration("slack-security", IntegrationType.slack, {
            "webhook_url": "https://hooks.slack.com/...",
            "channel": "#security",
        })

        # Add routing rule: finding.created → slack-security
        reg = hub.registry.get("slack-security")
        hub.add_routing_rule(EventType.finding_created, [reg.id])

        # Route an event
        results = hub.route_event(EventType.finding_created, {
            "id": "F-001", "title": "SQL Injection", "severity": "critical",
            "asset_name": "api-gateway", "source": "semgrep",
        })
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_backoff: float = 1.0,
        max_backoff: float = 30.0,
    ) -> None:
        self.registry = ConnectorRegistry()
        self.webhook_registry = WebhookRegistry()
        self.event_router = EventRouter()
        self.template_store = TemplateStore()
        self.sync_manager = BidirectionalSyncManager()
        self.delivery_engine = DeliveryEngine(
            registry=self.registry,
            template_store=self.template_store,
            max_retries=max_retries,
            base_backoff=base_backoff,
            max_backoff=max_backoff,
        )

    # ------------------------------------------------------------------
    # Connector management
    # ------------------------------------------------------------------

    def add_integration(
        self,
        name: str,
        integration_type: IntegrationType,
        config: Dict[str, Any],
        tags: Optional[List[str]] = None,
    ) -> IntegrationRegistration:
        reg = IntegrationRegistration(
            name=name,
            integration_type=integration_type,
            config=config,
            tags=tags or [],
        )
        return self.registry.register(reg)

    def remove_integration(self, name: str) -> bool:
        return self.registry.remove(name)

    def list_integrations(self, enabled_only: bool = False) -> List[IntegrationRegistrationResponse]:
        regs = self.registry.list_all(enabled_only=enabled_only)
        return [_to_response(r) for r in regs]

    def get_integration(self, name: str) -> Optional[IntegrationRegistrationResponse]:
        reg = self.registry.get(name)
        if reg is None:
            return None
        return _to_response(reg)

    # ------------------------------------------------------------------
    # Webhook management
    # ------------------------------------------------------------------

    def add_webhook(
        self,
        integration_id: str,
        direction: SyncDirection,
        path: str,
        event_types: Optional[List[EventType]] = None,
        secret: Optional[str] = None,
    ) -> WebhookRegistration:
        hook = WebhookRegistration(
            integration_id=integration_id,
            direction=direction,
            path=path,
            event_types=event_types or [],
            secret=secret,
        )
        return self.webhook_registry.register(hook)

    def remove_webhook(self, hook_id: str) -> bool:
        return self.webhook_registry.remove(hook_id)

    def list_webhooks(self, integration_id: Optional[str] = None) -> List[WebhookRegistrationResponse]:
        if integration_id:
            hooks = self.webhook_registry.list_for_integration(integration_id)
        else:
            hooks = self.webhook_registry.list_all()
        return [_to_webhook_response(h) for h in hooks]

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def add_routing_rule(
        self,
        event_type: EventType,
        integration_ids: List[str],
        filter_expr: Optional[str] = None,
        template_name: Optional[str] = None,
    ) -> RoutingRule:
        rule = RoutingRule(
            event_type=event_type,
            integration_ids=integration_ids,
            filter_expr=filter_expr,
            template_name=template_name,
        )
        return self.event_router.add_rule(rule)

    def remove_routing_rule(self, rule_id: str) -> bool:
        return self.event_router.remove_rule(rule_id)

    def route_event(
        self,
        event_type: EventType,
        event_payload: Dict[str, Any],
    ) -> List[DeliveryResult]:
        """Route an event to all matching integrations per registered rules."""
        targets = self.event_router.resolve(event_type, event_payload)
        if not targets:
            logger.debug("no_routing_targets", extra={"event_type": event_type})
            return []

        results: List[DeliveryResult] = []
        for integration_id, template_name in targets:
            result = self.delivery_engine.deliver(
                integration_id=integration_id,
                event_type=event_type,
                event_payload=event_payload,
                template_name=template_name,
            )
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Bidirectional sync
    # ------------------------------------------------------------------

    def process_inbound_sync(
        self,
        integration_id: str,
        external_id: str,
        external_status: str,
        aldeci_finding_id: Optional[str] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
    ) -> SyncRecord:
        reg = self.registry.get_by_id(integration_id)
        itype = reg.integration_type if reg else IntegrationType.webhook
        return self.sync_manager.process_inbound_sync(
            integration_id=integration_id,
            integration_type=itype,
            external_id=external_id,
            external_status=external_status,
            aldeci_finding_id=aldeci_finding_id,
            raw_payload=raw_payload or {},
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_summary(self) -> List[Dict[str, Any]]:
        return [h.to_dict() for h in self.registry.all_health()]

    def integration_health(self, name: str) -> Optional[Dict[str, Any]]:
        reg = self.registry.get(name)
        if reg is None:
            return None
        hlth = self.registry.health(reg.id)
        if hlth is None:
            return None
        d = hlth.to_dict()
        cb = self.registry.circuit_breaker(reg.id)
        if cb:
            d["circuit_state"] = cb.state
        return d

    def reset_circuit_breaker(self, name: str) -> bool:
        return self.registry.reset_circuit_breaker(name)

    # ------------------------------------------------------------------
    # Delivery history
    # ------------------------------------------------------------------

    def delivery_history(self, limit: int = 100) -> List[DeliveryAttempt]:
        return self.delivery_engine.get_history(limit=limit)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MASKED_KEYS = {
    "api_token", "token", "password", "secret", "integration_key",
    "webhook_url", "bot_token", "signing_secret",
}


def _mask_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return config dict with credential values masked."""
    out: Dict[str, Any] = {}
    for k, v in config.items():
        if k in _MASKED_KEYS and isinstance(v, str):
            out[k] = _mask_secret(v)
        else:
            out[k] = v
    return out


def _to_response(reg: IntegrationRegistration) -> IntegrationRegistrationResponse:
    return IntegrationRegistrationResponse(
        id=reg.id,
        name=reg.name,
        integration_type=reg.integration_type,
        enabled=reg.enabled,
        created_at=reg.created_at,
        updated_at=reg.updated_at,
        tags=reg.tags,
        config_summary=_mask_config(reg.config),
    )


def _to_webhook_response(hook: WebhookRegistration) -> WebhookRegistrationResponse:
    return WebhookRegistrationResponse(
        id=hook.id,
        integration_id=hook.integration_id,
        direction=hook.direction,
        path=hook.path,
        event_types=hook.event_types,
        created_at=hook.created_at,
        active=hook.active,
        secret_hint=_mask_secret(hook.secret) if hook.secret else None,
    )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_hub_instance: Optional[IntegrationHub] = None
_hub_lock = Lock()


def get_hub() -> IntegrationHub:
    """Return the module-level IntegrationHub singleton."""
    global _hub_instance
    if _hub_instance is None:
        with _hub_lock:
            if _hub_instance is None:
                _hub_instance = IntegrationHub()
    return _hub_instance
