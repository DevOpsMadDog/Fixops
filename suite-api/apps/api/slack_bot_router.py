"""Slack Bot API Router for ALDECI.

Handles incoming requests from Slack:
  POST /api/v1/slack/commands     — slash command handler
  POST /api/v1/slack/interactions — interactive component handler (button clicks)
  POST /api/v1/slack/events       — Slack Events API (mentions, DMs)

Slack signature verification is optional: when SLACK_SIGNING_SECRET is not
configured, verification is skipped so the bot works without credentials.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

from core.slack_bot import SlackBot
from fastapi import APIRouter, Form, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/slack", tags=["Slack"])

# Module-level singleton — created once, reused across requests
_bot: Optional[SlackBot] = None


def _get_bot() -> SlackBot:
    global _bot
    if _bot is None:
        signing_secret = os.environ.get("SLACK_SIGNING_SECRET") or None
        org_id = os.environ.get("FIXOPS_DEFAULT_ORG", "default")
        _bot = SlackBot(signing_secret=signing_secret, org_id=org_id)
    return _bot


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class SlackCommandResponse(BaseModel):
    """Response returned to Slack after a slash command."""

    response_type: str = Field("ephemeral", description="'in_channel' or 'ephemeral'")
    blocks: list = Field(default_factory=list)
    text: Optional[str] = None


class SlackEventPayload(BaseModel):
    """Minimal Slack Events API payload."""

    type: str
    challenge: Optional[str] = None
    event: Optional[Dict[str, Any]] = None
    team_id: Optional[str] = None
    api_app_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Signature verification helper
# ---------------------------------------------------------------------------


def _verify_slack_request(
    bot: SlackBot,
    request_body: str,
    timestamp: Optional[str],
    signature: Optional[str],
) -> None:
    """Raise HTTP 401 if signature verification fails.

    When no signing secret is configured the check is skipped.
    """
    if not timestamp or not signature:
        # If there is no signing secret configured, allow through
        if bot._signing_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Slack signature headers",
            )
        return

    if not bot.verify_signature(timestamp, request_body, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Slack request signature",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/commands",
    summary="Slack slash command handler",
    response_model=SlackCommandResponse,
)
async def handle_slash_command(
    request: Request,
    command: str = Form(...),
    text: str = Form(default=""),
    user_id: str = Form(...),
    channel_id: str = Form(...),
    x_slack_request_timestamp: Optional[str] = Header(None),
    x_slack_signature: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Handle a Slack slash command (e.g. /status, /findings, /sla).

    Slack sends form-encoded data; this endpoint decodes it, optionally
    verifies the HMAC signature, and returns a BlockKit response.
    """
    bot = _get_bot()

    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8")

    _verify_slack_request(
        bot,
        body_str,
        x_slack_request_timestamp,
        x_slack_signature,
    )

    result = bot.handle_slash_command(
        command=command,
        text=text,
        user_id=user_id,
        channel_id=channel_id,
    )
    return result


@router.post(
    "/interactions",
    summary="Slack interactive component handler",
)
async def handle_interaction(
    request: Request,
    payload: str = Form(...),
    x_slack_request_timestamp: Optional[str] = Header(None),
    x_slack_signature: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Handle Slack interactive component callbacks (button clicks, menus).

    Slack sends a form-encoded ``payload`` field containing JSON.
    """
    bot = _get_bot()

    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8")

    _verify_slack_request(
        bot,
        body_str,
        x_slack_request_timestamp,
        x_slack_signature,
    )

    try:
        interaction_payload = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON in payload: {exc}",
        ) from exc

    result = bot.handle_interaction(interaction_payload)
    return result


@router.post(
    "/events",
    summary="Slack Events API handler",
)
async def handle_event(
    request: Request,
    x_slack_request_timestamp: Optional[str] = Header(None),
    x_slack_signature: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Handle Slack Events API payloads (mentions, DMs, app_mention).

    Responds to the URL verification challenge automatically.
    """
    bot = _get_bot()

    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8")

    _verify_slack_request(
        bot,
        body_str,
        x_slack_request_timestamp,
        x_slack_signature,
    )

    try:
        event_payload = json.loads(body_str)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON body: {exc}",
        ) from exc

    # Slack URL verification challenge
    if event_payload.get("type") == "url_verification":
        return {"challenge": event_payload.get("challenge", "")}

    event = event_payload.get("event", {})
    event_type = event.get("type", "")

    logger.info("slack_event received type=%s", event_type)

    # Handle app_mention — respond with help
    if event_type == "app_mention":
        channel = event.get("channel", "")
        help_response = bot.handle_help()
        logger.info("slack_event.app_mention channel=%s", channel)
        return {"ok": True, "response": help_response}

    return {"ok": True}
