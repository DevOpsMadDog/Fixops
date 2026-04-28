"""Deep Slack Integration for ALDECI.

Provides enterprise-grade Slack integration with:
- Channel management (create, archive, list, configure)
- Thread-based finding discussions (post, reply, resolve)
- Interactive approval workflows via BlockKit (approve, reject, escalate)
- Scheduled digests (daily, weekly summaries by severity/team)
- Finding-to-channel routing rules (severity, asset, tag, team-based)
- Mock-safe design (all HTTP calls behind injectable transport)

Environment variables:
    SLACK_BOT_TOKEN       — xoxb-... Slack bot OAuth token
    SLACK_SIGNING_SECRET  — used for request signature verification
    SLACK_DEFAULT_CHANNEL — fallback channel ID (default: #security-alerts)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import structlog

_logger = structlog.get_logger(__name__)

# TrustGraph event bus — optional, never blocks on failure
try:  # pragma: no cover - bus is optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit an event to the TrustGraph event bus. Never raises."""
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
            import asyncio
            import inspect
            if inspect.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# ============================================================================
# Enums
# ============================================================================


class DigestFrequency(str, Enum):
    """How often a digest is sent."""

    DAILY = "daily"
    WEEKLY = "weekly"
    HOURLY = "hourly"


class RoutingCondition(str, Enum):
    """Dimension used to route findings to channels."""

    SEVERITY = "severity"
    ASSET_TAG = "asset_tag"
    TEAM = "team"
    CONNECTOR = "connector"
    CVE_PRESENT = "cve_present"


class ApprovalStatus(str, Enum):
    """State of an interactive approval workflow."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


# ============================================================================
# Data models
# ============================================================================


@dataclass
class ChannelConfig:
    """Configuration for a managed Slack channel."""

    channel_id: str
    channel_name: str
    purpose: str = ""
    topic: str = ""
    is_private: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    archived: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "channel_id": self.channel_id,
            "channel_name": self.channel_name,
            "purpose": self.purpose,
            "topic": self.topic,
            "is_private": self.is_private,
            "created_at": self.created_at,
            "archived": self.archived,
            "metadata": self.metadata,
        }


@dataclass
class FindingThread:
    """Tracks a Slack thread associated with a security finding."""

    thread_id: str
    finding_id: str
    channel_id: str
    ts: str  # Slack message timestamp (thread root)
    replies: List[Dict[str, Any]] = field(default_factory=list)
    resolved: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "thread_id": self.thread_id,
            "finding_id": self.finding_id,
            "channel_id": self.channel_id,
            "ts": self.ts,
            "replies": self.replies,
            "resolved": self.resolved,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }


@dataclass
class ApprovalWorkflow:
    """Interactive BlockKit approval workflow for a finding action."""

    workflow_id: str
    finding_id: str
    action: str  # e.g. "remediate", "accept_risk", "escalate"
    requested_by: str
    channel_id: str
    ts: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None
    rejected_by: Optional[str] = None
    reason: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "finding_id": self.finding_id,
            "action": self.action,
            "requested_by": self.requested_by,
            "channel_id": self.channel_id,
            "ts": self.ts,
            "status": self.status.value,
            "approved_by": self.approved_by,
            "rejected_by": self.rejected_by,
            "reason": self.reason,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }


@dataclass
class RoutingRule:
    """Rule that maps findings matching certain conditions to a Slack channel."""

    rule_id: str
    name: str
    condition: RoutingCondition
    condition_value: str  # e.g. "critical", "team-infra", "CVE-"
    channel_id: str
    priority: int = 100  # lower = higher priority
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def matches(self, finding: Dict[str, Any]) -> bool:
        """Return True if this rule matches the given finding dict."""
        if not self.enabled:
            return False
        v = self.condition_value.lower()
        if self.condition == RoutingCondition.SEVERITY:
            return str(finding.get("severity", "")).lower() == v
        if self.condition == RoutingCondition.ASSET_TAG:
            tags = [t.lower() for t in finding.get("tags", [])]
            return v in tags
        if self.condition == RoutingCondition.TEAM:
            return str(finding.get("team", "")).lower() == v
        if self.condition == RoutingCondition.CONNECTOR:
            return str(finding.get("connector", "")).lower() == v
        if self.condition == RoutingCondition.CVE_PRESENT:
            has_cve = bool(finding.get("cve_id"))
            return has_cve if v in ("true", "1", "yes") else not has_cve
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "condition": self.condition.value,
            "condition_value": self.condition_value,
            "channel_id": self.channel_id,
            "priority": self.priority,
            "enabled": self.enabled,
            "created_at": self.created_at,
        }


@dataclass
class DigestSchedule:
    """Configuration for a scheduled Slack digest message."""

    schedule_id: str
    name: str
    channel_id: str
    frequency: DigestFrequency
    filters: Dict[str, Any] = field(default_factory=dict)  # severity, team, etc.
    enabled: bool = True
    last_sent_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "name": self.name,
            "channel_id": self.channel_id,
            "frequency": self.frequency.value,
            "filters": self.filters,
            "enabled": self.enabled,
            "last_sent_at": self.last_sent_at,
            "created_at": self.created_at,
        }


# ============================================================================
# BlockKit builders
# ============================================================================


def _build_finding_blocks(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build BlockKit blocks for a security finding notification."""
    severity = finding.get("severity", "unknown").upper()
    title = finding.get("title", "Untitled Finding")
    finding_id = finding.get("id", "n/a")
    connector = finding.get("connector", "unknown")
    cve = finding.get("cve_id", "")
    description = finding.get("description", "")[:300]

    severity_emoji = {
        "CRITICAL": ":red_circle:",
        "HIGH": ":orange_circle:",
        "MEDIUM": ":yellow_circle:",
        "LOW": ":white_circle:",
    }.get(severity, ":white_circle:")

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{severity_emoji} [{severity}] {title}",
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Finding ID:*\n`{finding_id}`"},
                {"type": "mrkdwn", "text": f"*Source:*\n{connector}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                {"type": "mrkdwn", "text": f"*CVE:*\n{cve or 'N/A'}"},
            ],
        },
    ]
    if description:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description:*\n{description}"},
            }
        )
    return blocks


def _build_approval_blocks(
    workflow_id: str,
    finding: Dict[str, Any],
    action: str,
    requested_by: str,
) -> List[Dict[str, Any]]:
    """Build BlockKit blocks for an interactive approval workflow."""
    title = finding.get("title", "Untitled Finding")
    severity = finding.get("severity", "unknown").upper()
    finding_id = finding.get("id", "n/a")

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f":shield: Approval Required: {action.replace('_', ' ').title()}",
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Finding:*\n{title}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                {"type": "mrkdwn", "text": f"*Finding ID:*\n`{finding_id}`"},
                {"type": "mrkdwn", "text": f"*Requested by:*\n<@{requested_by}>"},
                {"type": "mrkdwn", "text": f"*Action:*\n`{action}`"},
                {"type": "mrkdwn", "text": f"*Workflow ID:*\n`{workflow_id}`"},
            ],
        },
        {"type": "divider"},
        {
            "type": "actions",
            "block_id": f"approval_{workflow_id}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": ":white_check_mark: Approve", "emoji": True},
                    "style": "primary",
                    "action_id": "approval_approve",
                    "value": workflow_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": ":x: Reject", "emoji": True},
                    "style": "danger",
                    "action_id": "approval_reject",
                    "value": workflow_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": ":arrow_up: Escalate", "emoji": True},
                    "action_id": "approval_escalate",
                    "value": workflow_id,
                },
            ],
        },
    ]
    return blocks


def _build_digest_blocks(
    findings: List[Dict[str, Any]],
    period: str,
    filters: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Build BlockKit blocks for a scheduled digest message."""
    total = len(findings)
    critical = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    medium = sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")
    low = sum(1 for f in findings if str(f.get("severity", "")).lower() == "low")

    filter_desc = ", ".join(f"{k}={v}" for k, v in filters.items()) if filters else "all findings"

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f":bar_chart: ALDECI Security Digest — {period}",
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Filter:* {filter_desc}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Total Findings:*\n{total}"},
                {"type": "mrkdwn", "text": f":red_circle: *Critical:*\n{critical}"},
                {"type": "mrkdwn", "text": f":orange_circle: *High:*\n{high}"},
                {"type": "mrkdwn", "text": f":yellow_circle: *Medium:*\n{medium}"},
                {"type": "mrkdwn", "text": f":white_circle: *Low:*\n{low}"},
            ],
        },
    ]

    # Top 5 critical/high findings
    top = [f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")][:5]
    if top:
        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Top Critical/High Findings:*"},
            }
        )
        for f in top:
            sev = f.get("severity", "unknown").upper()
            fid = f.get("id", "n/a")
            title = f.get("title", "Untitled")[:80]
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"• [`{fid}`] *{sev}* — {title}"},
                }
            )

    blocks.append({"type": "divider"})
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Generated by ALDECI at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                }
            ],
        }
    )
    return blocks


# ============================================================================
# HTTP transport (mock-safe)
# ============================================================================


class SlackTransport:
    """Thin HTTP wrapper around the Slack Web API.

    Swappable for testing: pass a custom ``_call`` callable that accepts
    (method, payload) and returns a dict.
    """

    API_BASE = "https://slack.com/api"

    def __init__(
        self,
        bot_token: Optional[str] = None,
        _call: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        self._token = bot_token or os.environ.get("SLACK_BOT_TOKEN", "")
        self._call = _call  # injectable for tests

    def post(self, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Call a Slack Web API method and return the response dict."""
        if self._call is not None:
            return self._call(method, payload)
        if not self._token:
            _logger.warning("slack.transport: no bot token — returning mock ok")
            return {"ok": True, "ts": str(time.time()), "channel": payload.get("channel", "")}
        try:
            import requests  # type: ignore[import-untyped]

            resp = requests.post(  # nosemgrep: dynamic-urllib-use-detected
                f"{self.API_BASE}/{method}",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json; charset=utf-8",
                },
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            _logger.error("slack.transport.error", method=method, error=str(exc))
            return {"ok": False, "error": str(exc)}


# ============================================================================
# SlackIntegration — main class
# ============================================================================


class SlackIntegration:
    """Deep Slack integration for ALDECI security operations.

    Args:
        bot_token: Slack bot OAuth token (xoxb-...). Falls back to
            ``SLACK_BOT_TOKEN`` env var. If absent, all API calls return
            mock-safe ``{"ok": True}`` responses.
        signing_secret: Slack signing secret for verifying inbound webhooks.
            Falls back to ``SLACK_SIGNING_SECRET`` env var.
        default_channel: Fallback channel ID when no routing rule matches.
            Falls back to ``SLACK_DEFAULT_CHANNEL`` env var.
        transport: Optional ``SlackTransport`` override (e.g. for tests).
    """

    def __init__(
        self,
        bot_token: Optional[str] = None,
        signing_secret: Optional[str] = None,
        default_channel: Optional[str] = None,
        transport: Optional[SlackTransport] = None,
    ) -> None:
        self._token = bot_token or os.environ.get("SLACK_BOT_TOKEN", "")
        self._signing_secret = signing_secret or os.environ.get("SLACK_SIGNING_SECRET", "")
        self._default_channel = (
            default_channel
            or os.environ.get("SLACK_DEFAULT_CHANNEL", "C_DEFAULT")
        )
        self._transport = transport or SlackTransport(bot_token=self._token)

        # In-memory stores (production would use PersistentDict / SQLite)
        self._channels: Dict[str, ChannelConfig] = {}
        self._threads: Dict[str, FindingThread] = {}  # keyed by thread_id
        self._finding_threads: Dict[str, List[str]] = {}  # finding_id -> [thread_id]
        self._workflows: Dict[str, ApprovalWorkflow] = {}
        self._routing_rules: Dict[str, RoutingRule] = {}
        self._digest_schedules: Dict[str, DigestSchedule] = {}

    # -------------------------------------------------------------------------
    # Signature verification
    # -------------------------------------------------------------------------

    def verify_signature(self, timestamp: str, body: str, signature: str) -> bool:
        """Verify an inbound Slack request signature (HMAC-SHA256)."""
        if not self._signing_secret:
            return True
        sig_base = f"v0:{timestamp}:{body}"
        computed = (
            "v0="
            + hmac.new(
                self._signing_secret.encode(),
                sig_base.encode(),
                hashlib.sha256,
            ).hexdigest()
        )
        return hmac.compare_digest(computed, signature)

    # -------------------------------------------------------------------------
    # Channel management
    # -------------------------------------------------------------------------

    def create_channel(
        self,
        name: str,
        purpose: str = "",
        topic: str = "",
        is_private: bool = False,
    ) -> ChannelConfig:
        """Create a Slack channel and register it internally."""
        payload: Dict[str, Any] = {"name": name, "is_private": is_private}
        resp = self._transport.post("conversations.create", payload)

        channel_id = (
            resp.get("channel", {}).get("id")
            if isinstance(resp.get("channel"), dict)
            else f"C_{uuid.uuid4().hex[:8].upper()}"
        )

        if purpose:
            self._transport.post(
                "conversations.setPurpose",
                {"channel": channel_id, "purpose": purpose},
            )
        if topic:
            self._transport.post(
                "conversations.setTopic",
                {"channel": channel_id, "topic": topic},
            )

        config = ChannelConfig(
            channel_id=channel_id,
            channel_name=name,
            purpose=purpose,
            topic=topic,
            is_private=is_private,
        )
        self._channels[channel_id] = config
        _logger.info("slack.channel.created", channel_id=channel_id, name=name)
        return config

    def list_channels(self, include_archived: bool = False) -> List[ChannelConfig]:
        """Return all managed channels, optionally including archived ones."""
        channels = list(self._channels.values())
        if not include_archived:
            channels = [c for c in channels if not c.archived]
        return channels

    def get_channel(self, channel_id: str) -> Optional[ChannelConfig]:
        """Return channel config by ID or None."""
        return self._channels.get(channel_id)

    def archive_channel(self, channel_id: str) -> bool:
        """Archive a channel by ID. Returns True on success."""
        if channel_id not in self._channels:
            return False
        resp = self._transport.post("conversations.archive", {"channel": channel_id})
        if resp.get("ok"):
            self._channels[channel_id].archived = True
            _logger.info("slack.channel.archived", channel_id=channel_id)
        return bool(resp.get("ok"))

    def update_channel(
        self,
        channel_id: str,
        purpose: Optional[str] = None,
        topic: Optional[str] = None,
    ) -> Optional[ChannelConfig]:
        """Update channel purpose/topic. Returns updated config or None."""
        config = self._channels.get(channel_id)
        if not config:
            return None
        if purpose is not None:
            self._transport.post(
                "conversations.setPurpose",
                {"channel": channel_id, "purpose": purpose},
            )
            config.purpose = purpose
        if topic is not None:
            self._transport.post(
                "conversations.setTopic",
                {"channel": channel_id, "topic": topic},
            )
            config.topic = topic
        return config

    # -------------------------------------------------------------------------
    # Finding thread discussions
    # -------------------------------------------------------------------------

    def post_finding(
        self,
        finding: Dict[str, Any],
        channel_id: Optional[str] = None,
    ) -> FindingThread:
        """Post a finding notification and open a discussion thread."""
        target_channel = channel_id or self._route_finding(finding)
        blocks = _build_finding_blocks(finding)
        resp = self._transport.post(
            "chat.postMessage",
            {
                "channel": target_channel,
                "blocks": blocks,
                "text": f"[{finding.get('severity','unknown').upper()}] {finding.get('title','Finding')}",
            },
        )
        ts = resp.get("ts", str(time.time()))
        thread = FindingThread(
            thread_id=str(uuid.uuid4()),
            finding_id=finding.get("id", str(uuid.uuid4())),
            channel_id=target_channel,
            ts=ts,
        )
        self._threads[thread.thread_id] = thread
        fid = thread.finding_id
        self._finding_threads.setdefault(fid, []).append(thread.thread_id)
        _logger.info(
            "slack.finding.posted",
            thread_id=thread.thread_id,
            finding_id=fid,
            channel_id=target_channel,
        )
        _emit_event(
            "slack.finding.posted",
            {
                "thread_id": thread.thread_id,
                "finding_id": fid,
                "channel_id": target_channel,
                "severity": finding.get("severity"),
            },
        )
        return thread

    def reply_to_thread(
        self,
        thread_id: str,
        text: str,
        user: str = "system",
    ) -> Optional[Dict[str, Any]]:
        """Post a reply into an existing finding thread."""
        thread = self._threads.get(thread_id)
        if not thread:
            return None
        resp = self._transport.post(
            "chat.postMessage",
            {
                "channel": thread.channel_id,
                "thread_ts": thread.ts,
                "text": text,
            },
        )
        reply = {"user": user, "text": text, "ts": resp.get("ts", str(time.time()))}
        thread.replies.append(reply)
        return reply

    def resolve_thread(self, thread_id: str) -> bool:
        """Mark a finding thread as resolved."""
        thread = self._threads.get(thread_id)
        if not thread:
            return False
        thread.resolved = True
        thread.resolved_at = datetime.now(timezone.utc).isoformat()
        self._transport.post(
            "chat.postMessage",
            {
                "channel": thread.channel_id,
                "thread_ts": thread.ts,
                "text": ":white_check_mark: This finding has been resolved.",
            },
        )
        _logger.info("slack.thread.resolved", thread_id=thread_id)
        return True

    def get_threads_for_finding(self, finding_id: str) -> List[FindingThread]:
        """Return all threads associated with a finding ID."""
        thread_ids = self._finding_threads.get(finding_id, [])
        return [self._threads[tid] for tid in thread_ids if tid in self._threads]

    # -------------------------------------------------------------------------
    # Interactive approval workflows
    # -------------------------------------------------------------------------

    def request_approval(
        self,
        finding: Dict[str, Any],
        action: str,
        requested_by: str,
        channel_id: Optional[str] = None,
    ) -> ApprovalWorkflow:
        """Post an interactive approval request via BlockKit."""
        workflow_id = str(uuid.uuid4())
        target_channel = channel_id or self._route_finding(finding)
        blocks = _build_approval_blocks(workflow_id, finding, action, requested_by)
        resp = self._transport.post(
            "chat.postMessage",
            {
                "channel": target_channel,
                "blocks": blocks,
                "text": f"Approval required: {action} for finding {finding.get('id','n/a')}",
            },
        )
        ts = resp.get("ts", str(time.time()))
        workflow = ApprovalWorkflow(
            workflow_id=workflow_id,
            finding_id=finding.get("id", str(uuid.uuid4())),
            action=action,
            requested_by=requested_by,
            channel_id=target_channel,
            ts=ts,
        )
        self._workflows[workflow_id] = workflow
        _logger.info(
            "slack.approval.requested",
            workflow_id=workflow_id,
            action=action,
            finding_id=workflow.finding_id,
        )
        return workflow

    def resolve_approval(
        self,
        workflow_id: str,
        resolution: ApprovalStatus,
        resolved_by: str,
        reason: Optional[str] = None,
    ) -> Optional[ApprovalWorkflow]:
        """Resolve an approval workflow (approve / reject / escalate)."""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return None
        if workflow.status != ApprovalStatus.PENDING:
            return workflow  # already resolved

        workflow.status = resolution
        workflow.resolved_at = datetime.now(timezone.utc).isoformat()
        workflow.reason = reason
        if resolution == ApprovalStatus.APPROVED:
            workflow.approved_by = resolved_by
        elif resolution == ApprovalStatus.REJECTED:
            workflow.rejected_by = resolved_by

        status_emoji = {
            ApprovalStatus.APPROVED: ":white_check_mark:",
            ApprovalStatus.REJECTED: ":x:",
            ApprovalStatus.ESCALATED: ":arrow_up:",
        }.get(resolution, ":grey_question:")
        msg = f"{status_emoji} *{resolution.value.title()}* by <@{resolved_by}>"
        if reason:
            msg += f"\n_Reason: {reason}_"

        self._transport.post(
            "chat.postMessage",
            {
                "channel": workflow.channel_id,
                "thread_ts": workflow.ts,
                "text": msg,
            },
        )
        _logger.info(
            "slack.approval.resolved",
            workflow_id=workflow_id,
            resolution=resolution.value,
            resolved_by=resolved_by,
        )
        return workflow

    def get_workflow(self, workflow_id: str) -> Optional[ApprovalWorkflow]:
        """Return an approval workflow by ID."""
        return self._workflows.get(workflow_id)

    def list_pending_approvals(self) -> List[ApprovalWorkflow]:
        """Return all pending approval workflows."""
        return [w for w in self._workflows.values() if w.status == ApprovalStatus.PENDING]

    # -------------------------------------------------------------------------
    # Finding-to-channel routing rules
    # -------------------------------------------------------------------------

    def add_routing_rule(
        self,
        name: str,
        condition: RoutingCondition,
        condition_value: str,
        channel_id: str,
        priority: int = 100,
    ) -> RoutingRule:
        """Add a finding-to-channel routing rule."""
        rule = RoutingRule(
            rule_id=str(uuid.uuid4()),
            name=name,
            condition=condition,
            condition_value=condition_value,
            channel_id=channel_id,
            priority=priority,
        )
        self._routing_rules[rule.rule_id] = rule
        _logger.info("slack.routing.rule.added", rule_id=rule.rule_id, name=name)
        return rule

    def remove_routing_rule(self, rule_id: str) -> bool:
        """Remove a routing rule by ID."""
        if rule_id in self._routing_rules:
            del self._routing_rules[rule_id]
            return True
        return False

    def list_routing_rules(self) -> List[RoutingRule]:
        """Return all routing rules ordered by priority."""
        return sorted(self._routing_rules.values(), key=lambda r: r.priority)

    def _route_finding(self, finding: Dict[str, Any]) -> str:
        """Return the best matching channel ID for a finding."""
        for rule in self.list_routing_rules():
            if rule.matches(finding):
                return rule.channel_id
        return self._default_channel

    # -------------------------------------------------------------------------
    # Scheduled digests
    # -------------------------------------------------------------------------

    def add_digest_schedule(
        self,
        name: str,
        channel_id: str,
        frequency: DigestFrequency,
        filters: Optional[Dict[str, Any]] = None,
    ) -> DigestSchedule:
        """Register a scheduled digest."""
        schedule = DigestSchedule(
            schedule_id=str(uuid.uuid4()),
            name=name,
            channel_id=channel_id,
            frequency=frequency,
            filters=filters or {},
        )
        self._digest_schedules[schedule.schedule_id] = schedule
        _logger.info(
            "slack.digest.schedule.added",
            schedule_id=schedule.schedule_id,
            frequency=frequency.value,
        )
        return schedule

    def remove_digest_schedule(self, schedule_id: str) -> bool:
        """Remove a digest schedule by ID."""
        if schedule_id in self._digest_schedules:
            del self._digest_schedules[schedule_id]
            return True
        return False

    def list_digest_schedules(self) -> List[DigestSchedule]:
        """Return all digest schedules."""
        return list(self._digest_schedules.values())

    def send_digest(
        self,
        schedule_id: str,
        findings: List[Dict[str, Any]],
        period: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Send a digest for a given schedule ID and findings list."""
        schedule = self._digest_schedules.get(schedule_id)
        if not schedule or not schedule.enabled:
            return None

        # Apply schedule filters to findings
        filtered = findings
        if schedule.filters.get("severity"):
            target_sev = schedule.filters["severity"].lower()
            filtered = [f for f in filtered if str(f.get("severity", "")).lower() == target_sev]
        if schedule.filters.get("team"):
            target_team = schedule.filters["team"].lower()
            filtered = [f for f in filtered if str(f.get("team", "")).lower() == target_team]

        period_label = period or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        blocks = _build_digest_blocks(filtered, period_label, schedule.filters)

        resp = self._transport.post(
            "chat.postMessage",
            {
                "channel": schedule.channel_id,
                "blocks": blocks,
                "text": f"ALDECI Security Digest — {period_label}",
            },
        )
        schedule.last_sent_at = datetime.now(timezone.utc).isoformat()
        _logger.info(
            "slack.digest.sent",
            schedule_id=schedule_id,
            findings_count=len(filtered),
        )
        return resp
