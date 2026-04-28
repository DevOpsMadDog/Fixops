"""Slack Security Bot for ALDECI.

Provides slash command handling and interactive button processing for security
operations via Slack. Produces BlockKit-formatted responses for rich messaging.

Supported slash commands:
  /status   — overall posture score + top risks
  /findings — recent critical/high findings with severity filter
  /sla      — SLA breaches and at-risk items
  /triage   — finding detail with action buttons
  /score    — repository security score
  /help     — list available commands

Interactive actions: acknowledge, escalate, dismiss, comment
"""

from __future__ import annotations

import hashlib
import hmac
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger(__name__)


# ============================================================================
# Enums
# ============================================================================


class SlashCommand(str, Enum):
    """Supported Slack slash commands."""

    STATUS = "/status"
    FINDINGS = "/findings"
    SLA = "/sla"
    HELP = "/help"
    TRIAGE = "/triage"
    SCORE = "/score"


class InteractionAction(str, Enum):
    """Button actions in interactive messages."""

    ACKNOWLEDGE = "acknowledge"
    ESCALATE = "escalate"
    DISMISS = "dismiss"
    COMMENT = "comment"


# ============================================================================
# SlackBot
# ============================================================================


class SlackBot:
    """Handles Slack slash commands and interactive button callbacks.

    Args:
        posture_scorer: Optional PostureScorer instance. If None, a default
            instance is created on first use.
        sla_manager: Optional SLAManager instance. If None, a default
            instance is created on first use.
        signing_secret: Slack signing secret for request verification.
            If None, signature verification is disabled.
        org_id: Organisation identifier used for posture/SLA queries.
    """

    def __init__(
        self,
        posture_scorer: Optional[Any] = None,
        sla_manager: Optional[Any] = None,
        signing_secret: Optional[str] = None,
        org_id: str = "default",
    ) -> None:
        self._posture_scorer = posture_scorer
        self._sla_manager = sla_manager
        self._signing_secret = signing_secret
        self._org_id = org_id

    # ------------------------------------------------------------------
    # Lazy dependency resolution
    # ------------------------------------------------------------------

    def _get_posture_scorer(self) -> Any:
        if self._posture_scorer is None:
            from core.posture_scoring import get_posture_scorer  # type: ignore[import]
            self._posture_scorer = get_posture_scorer()
        return self._posture_scorer

    def _get_sla_manager(self) -> Any:
        if self._sla_manager is None:
            from core.sla_manager import SLAManager  # type: ignore[import]
            self._sla_manager = SLAManager()
        return self._sla_manager

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def verify_signature(
        self,
        timestamp: str,
        body: str,
        signature: str,
    ) -> bool:
        """Verify Slack request signature.

        Returns True when signing secret is not configured (disabled mode).
        """
        if not self._signing_secret:
            return True
        base = f"v0:{timestamp}:{body}"
        mac = hmac.new(
            self._signing_secret.encode(),
            base.encode(),
            hashlib.sha256,
        ).hexdigest()
        expected = f"v0={mac}"
        return hmac.compare_digest(expected, signature)

    # ------------------------------------------------------------------
    # Slash command router
    # ------------------------------------------------------------------

    def handle_slash_command(
        self,
        command: str,
        text: str,
        user_id: str,
        channel_id: str,
    ) -> Dict[str, Any]:
        """Route a Slack slash command to the appropriate handler.

        Args:
            command: The slash command string (e.g. "/status").
            text: Additional text supplied after the command.
            user_id: Slack user ID who invoked the command.
            channel_id: Slack channel ID where command was invoked.

        Returns:
            A Slack response payload dict (response_type + blocks).
        """
        _logger.info(
            "slack_bot.slash_command",
            command=command,
            user_id=user_id,
            channel_id=channel_id,
        )

        cmd = command.strip().lower()

        if cmd == SlashCommand.STATUS:
            return self.handle_status()
        if cmd == SlashCommand.FINDINGS:
            return self.handle_findings(filters={"text": text})
        if cmd == SlashCommand.SLA:
            return self.handle_sla()
        if cmd == SlashCommand.TRIAGE:
            finding_id = text.strip()
            return self.handle_triage(finding_id=finding_id)
        if cmd == SlashCommand.SCORE:
            repo_name = text.strip()
            return self.handle_score(repo_name=repo_name)
        if cmd == SlashCommand.HELP:
            return self.handle_help()

        return self._error_response(f"Unknown command: `{command}`. Try `/help`.")

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    def handle_status(self) -> Dict[str, Any]:
        """Return overall posture score, grade, and top risk components.

        Returns:
            Slack response payload with BlockKit blocks.
        """
        try:
            scorer = self._get_posture_scorer()
            posture = scorer.calculate_score(self._org_id)
            blocks = self._build_status_blocks(posture)
        except Exception as exc:
            _logger.warning("slack_bot.handle_status.error", error=str(exc))
            blocks = self._fallback_status_blocks()

        return {
            "response_type": "in_channel",
            "blocks": blocks,
        }

    def handle_findings(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return recent critical/high findings with optional filters.

        Args:
            filters: Optional dict with keys like ``severity``, ``limit``, ``text``.

        Returns:
            Slack response payload with BlockKit blocks.
        """
        filters = filters or {}
        severity_filter = filters.get("severity", "").lower()
        limit = int(filters.get("limit", 5))

        # Build sample findings — in production these come from the findings DB
        sample_findings = self._get_sample_findings(severity_filter, limit)

        if not sample_findings:
            return {
                "response_type": "ephemeral",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":white_check_mark: No findings match the current filter.",
                        },
                    }
                ],
            }

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Recent Findings",
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ]
        for finding in sample_findings:
            blocks.append(self._build_finding_block(finding))
            blocks.append({"type": "divider"})

        return {
            "response_type": "in_channel",
            "blocks": blocks,
        }

    def handle_sla(self) -> Dict[str, Any]:
        """Return SLA breaches and at-risk findings.

        Returns:
            Slack response payload with BlockKit blocks.
        """
        try:
            manager = self._get_sla_manager()
            breached = manager.get_breached(self._org_id)
            at_risk = manager.get_at_risk(self._org_id)
        except Exception as exc:
            _logger.warning("slack_bot.handle_sla.error", error=str(exc))
            breached = []
            at_risk = []

        breached_count = len(breached)
        at_risk_count = len(at_risk)

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "SLA Status",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f":red_circle: *Breached*\n{breached_count} finding(s)",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f":warning: *At Risk*\n{at_risk_count} finding(s)",
                    },
                ],
            },
        ]

        if breached:
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Breached SLA Items:*",
                    },
                }
            )
            for record in breached[:5]:
                finding_id = getattr(record, "finding_id", str(record))
                severity = getattr(record, "severity", "unknown")
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"{self.format_severity_emoji(severity)} "
                                f"`{finding_id}` — *{severity.upper()}* — SLA breached"
                            ),
                        },
                    }
                )

        if at_risk:
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*At-Risk Items (approaching deadline):*",
                    },
                }
            )
            for record in at_risk[:5]:
                finding_id = getattr(record, "finding_id", str(record))
                severity = getattr(record, "severity", "unknown")
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"{self.format_severity_emoji(severity)} "
                                f"`{finding_id}` — *{severity.upper()}* — approaching deadline"
                            ),
                        },
                    }
                )

        return {
            "response_type": "in_channel",
            "blocks": blocks,
        }

    def handle_triage(self, finding_id: str) -> Dict[str, Any]:
        """Return finding detail with interactive action buttons.

        Args:
            finding_id: The finding ID to look up.

        Returns:
            Slack response payload with BlockKit blocks including action buttons.
        """
        if not finding_id:
            return self._error_response(
                "Please supply a finding ID: `/triage <finding_id>`"
            )

        finding = self._lookup_finding(finding_id)

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Finding Triage",
                    "emoji": True,
                },
            },
            self._build_finding_block(finding),
            {"type": "divider"},
            self._build_action_buttons(finding_id),
        ]

        return {
            "response_type": "in_channel",
            "blocks": blocks,
        }

    def handle_score(self, repo_name: str) -> Dict[str, Any]:
        """Return security score for a repository.

        Args:
            repo_name: Repository name or identifier.

        Returns:
            Slack response payload with repo score details.
        """
        if not repo_name:
            return self._error_response(
                "Please supply a repo name: `/score <repo_name>`"
            )

        # Placeholder score — in production queries the scanner results DB
        score = self._get_repo_score(repo_name)

        grade = self._score_to_grade(score)
        emoji = ":white_check_mark:" if score >= 70 else (":warning:" if score >= 50 else ":x:")

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Security Score: {repo_name}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Score*\n{emoji} {score}/100",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Grade*\n{grade}",
                    },
                ],
            },
        ]

        return {
            "response_type": "in_channel",
            "blocks": blocks,
        }

    def handle_help(self) -> Dict[str, Any]:
        """Return a list of available commands.

        Returns:
            Slack response payload listing all slash commands.
        """
        commands = [
            (SlashCommand.STATUS, "Overall security posture score and top risks"),
            (SlashCommand.FINDINGS, "Recent critical/high findings (optional: severity=<level>)"),
            (SlashCommand.SLA, "SLA breaches and at-risk findings"),
            (SlashCommand.TRIAGE, "<finding_id> — Finding detail with action buttons"),
            (SlashCommand.SCORE, "<repo_name> — Repository security score"),
            (SlashCommand.HELP, "Show this help message"),
        ]

        lines = ["*ALDECI Security Bot — Available Commands*\n"]
        for cmd, description in commands:
            lines.append(f"`{cmd.value}` — {description}")

        blocks: List[Dict[str, Any]] = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n".join(lines),
                },
            }
        ]

        return {
            "response_type": "ephemeral",
            "blocks": blocks,
        }

    def handle_interaction(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process an interactive component callback (button click).

        Args:
            payload: Slack interaction payload dict.

        Returns:
            Acknowledgement response dict.
        """
        actions = payload.get("actions", [])
        user = payload.get("user", {})
        user_id = user.get("id", "unknown")

        if not actions:
            return {"ok": True, "message": "No actions in payload"}

        action = actions[0]
        action_id = action.get("action_id", "")
        value = action.get("value", "")

        _logger.info(
            "slack_bot.interaction",
            action_id=action_id,
            value=value,
            user_id=user_id,
        )

        if action_id == InteractionAction.ACKNOWLEDGE:
            return self._handle_acknowledge(value, user_id)
        if action_id == InteractionAction.ESCALATE:
            return self._handle_escalate(value, user_id)
        if action_id == InteractionAction.DISMISS:
            return self._handle_dismiss(value, user_id)
        if action_id == InteractionAction.COMMENT:
            return self._handle_comment(value, user_id)

        return {
            "ok": True,
            "message": f"Unknown action: {action_id}",
        }

    # ------------------------------------------------------------------
    # Block builders
    # ------------------------------------------------------------------

    def _build_finding_block(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Build a BlockKit section for a single finding.

        Args:
            finding: Dict with keys: id, title, severity, source, description.

        Returns:
            BlockKit section dict.
        """
        finding_id = finding.get("id", "unknown")
        title = finding.get("title", "Untitled Finding")
        severity = finding.get("severity", "unknown")
        source = finding.get("source", "unknown")
        description = finding.get("description", "No description available.")

        emoji = self.format_severity_emoji(severity)

        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *{title}*\n"
                    f"ID: `{finding_id}` | Severity: *{severity.upper()}* | Source: _{source}_\n"
                    f"{description}"
                ),
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Triage",
                    "emoji": True,
                },
                "action_id": "triage_finding",
                "value": finding_id,
            },
        }

    def _build_status_blocks(self, posture: Any) -> List[Dict[str, Any]]:
        """Build BlockKit blocks for the status command.

        Args:
            posture: PostureScore instance with overall_score, grade, components.

        Returns:
            List of BlockKit block dicts.
        """
        overall = getattr(posture, "overall_score", 0.0)
        grade = getattr(posture, "grade", "?")
        components = getattr(posture, "components", [])

        score_emoji = (
            ":large_green_circle:"
            if overall >= 70
            else (":large_yellow_circle:" if overall >= 50 else ":red_circle:")
        )

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Security Posture Status",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Overall Score*\n{score_emoji} {overall:.1f}/100",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Grade*\n{grade}",
                    },
                ],
            },
        ]

        if components:
            blocks.append({"type": "divider"})
            component_lines = ["*Component Scores:*"]
            for comp in components:
                comp_name = getattr(comp, "name", "unknown").replace("_", " ").title()
                comp_score = getattr(comp, "score", 0.0)
                comp_weight = getattr(comp, "weight", 0.0)
                bar = self._score_bar(comp_score)
                component_lines.append(
                    f"`{comp_name}` {bar} {comp_score:.0f}/100 (weight: {comp_weight:.0%})"
                )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(component_lines),
                    },
                }
            )

        return blocks

    def _build_action_buttons(self, finding_id: str) -> Dict[str, Any]:
        """Build interactive action buttons for a finding.

        Args:
            finding_id: The finding ID to attach to button values.

        Returns:
            BlockKit actions dict with acknowledge/escalate/dismiss buttons.
        """
        return {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Acknowledge",
                        "emoji": True,
                    },
                    "action_id": InteractionAction.ACKNOWLEDGE,
                    "value": finding_id,
                    "style": "primary",
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Escalate",
                        "emoji": True,
                    },
                    "action_id": InteractionAction.ESCALATE,
                    "value": finding_id,
                    "style": "danger",
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Dismiss",
                        "emoji": True,
                    },
                    "action_id": InteractionAction.DISMISS,
                    "value": finding_id,
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Comment",
                        "emoji": True,
                    },
                    "action_id": InteractionAction.COMMENT,
                    "value": finding_id,
                },
            ],
        }

    # ------------------------------------------------------------------
    # Severity formatting
    # ------------------------------------------------------------------

    def format_severity_emoji(self, severity: str) -> str:
        """Map severity string to a coloured circle emoji.

        Args:
            severity: Severity label (critical, high, medium, low, or info).

        Returns:
            Emoji string.
        """
        mapping: Dict[str, str] = {
            "critical": ":red_circle:",
            "high": ":large_orange_circle:",
            "medium": ":large_yellow_circle:",
            "low": ":large_blue_circle:",
            "info": ":white_circle:",
        }
        return mapping.get(severity.lower(), ":white_circle:")

    # ------------------------------------------------------------------
    # Interaction sub-handlers
    # ------------------------------------------------------------------

    def _handle_acknowledge(self, finding_id: str, user_id: str) -> Dict[str, Any]:
        _logger.info("slack_bot.acknowledge", finding_id=finding_id, user_id=user_id)
        return {
            "ok": True,
            "action": InteractionAction.ACKNOWLEDGE,
            "finding_id": finding_id,
            "user_id": user_id,
            "message": f"Finding `{finding_id}` acknowledged by <@{user_id}>.",
        }

    def _handle_escalate(self, finding_id: str, user_id: str) -> Dict[str, Any]:
        _logger.info("slack_bot.escalate", finding_id=finding_id, user_id=user_id)
        return {
            "ok": True,
            "action": InteractionAction.ESCALATE,
            "finding_id": finding_id,
            "user_id": user_id,
            "message": f"Finding `{finding_id}` escalated by <@{user_id}>.",
        }

    def _handle_dismiss(self, finding_id: str, user_id: str) -> Dict[str, Any]:
        _logger.info("slack_bot.dismiss", finding_id=finding_id, user_id=user_id)
        return {
            "ok": True,
            "action": InteractionAction.DISMISS,
            "finding_id": finding_id,
            "user_id": user_id,
            "message": f"Finding `{finding_id}` dismissed by <@{user_id}>.",
        }

    def _handle_comment(self, finding_id: str, user_id: str) -> Dict[str, Any]:
        _logger.info("slack_bot.comment", finding_id=finding_id, user_id=user_id)
        return {
            "ok": True,
            "action": InteractionAction.COMMENT,
            "finding_id": finding_id,
            "user_id": user_id,
            "message": f"Comment requested for finding `{finding_id}` by <@{user_id}>.",
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _error_response(self, message: str) -> Dict[str, Any]:
        return {
            "response_type": "ephemeral",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f":x: {message}",
                    },
                }
            ],
        }

    def _fallback_status_blocks(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ":warning: Unable to retrieve posture score at this time.",
                },
            }
        ]

    def _get_sample_findings(
        self, severity_filter: str, limit: int
    ) -> List[Dict[str, Any]]:
        """Return placeholder findings (production: query findings DB)."""
        all_findings = [
            {
                "id": "FIND-001",
                "title": "SQL Injection in login endpoint",
                "severity": "critical",
                "source": "SAST",
                "description": "User-controlled input concatenated into SQL query without sanitization.",
            },
            {
                "id": "FIND-002",
                "title": "Exposed secrets in environment variables",
                "severity": "high",
                "source": "Secrets Scanner",
                "description": "AWS credentials detected in .env file committed to repository.",
            },
            {
                "id": "FIND-003",
                "title": "Outdated dependency with known CVE",
                "severity": "high",
                "source": "SCA",
                "description": "lodash 4.17.19 is vulnerable to CVE-2021-23337 (prototype pollution).",
            },
            {
                "id": "FIND-004",
                "title": "Missing HTTPS enforcement",
                "severity": "medium",
                "source": "DAST",
                "description": "HTTP traffic is not redirected to HTTPS on the public endpoint.",
            },
            {
                "id": "FIND-005",
                "title": "Verbose error messages in production",
                "severity": "low",
                "source": "DAST",
                "description": "Stack traces are returned in HTTP 500 responses.",
            },
        ]
        if severity_filter:
            all_findings = [f for f in all_findings if f["severity"] == severity_filter]
        return all_findings[:limit]

    def _lookup_finding(self, finding_id: str) -> Dict[str, Any]:
        """Look up a finding by ID (production: query findings DB)."""
        return {
            "id": finding_id,
            "title": f"Finding {finding_id}",
            "severity": "high",
            "source": "ALDECI",
            "description": f"Security finding identified as {finding_id}. Review required.",
        }

    def _get_repo_score(self, repo_name: str) -> float:
        """Return a repo security score (production: query scanner results DB)."""
        # Deterministic placeholder based on repo name length
        return max(0.0, min(100.0, 60.0 + (len(repo_name) % 40)))

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    @staticmethod
    def _score_bar(score: float) -> str:
        """Return a simple ASCII progress bar for a 0-100 score."""
        filled = int(score / 10)
        return "█" * filled + "░" * (10 - filled)
