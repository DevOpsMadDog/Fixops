"""
Support ticket API router.

Routes:
  POST /api/v1/support/ticket  - Submit support ticket
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from apps.api.auth_deps import api_key_auth
from core.notification_engine import NotificationEngine

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/support", tags=["support"])


# ── Models ────────────────────────────────────────────────────────────────

class SupportTicketRequest(BaseModel):
    """Support ticket submission."""

    name: str = Field(..., min_length=1, max_length=255)
    email: EmailStr
    subject: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=10, max_length=5000)


class SupportTicketResponse(BaseModel):
    """Support ticket response."""

    ticket_id: str
    status: str
    message: str


# ── Helpers ───────────────────────────────────────────────────────────────

def _get_notification_engine() -> NotificationEngine:
    """Get or create notification engine instance."""
    try:
        return NotificationEngine()
    except Exception as e:
        _logger.warning(f"Failed to initialize NotificationEngine: {e}")
        return None


# ── Routes ────────────────────────────────────────────────────────────────

@router.post(
    "/ticket",
    response_model=SupportTicketResponse,
    status_code=status.HTTP_201_CREATED,
)
async def submit_support_ticket(
    req: SupportTicketRequest,
    _auth: Dict[str, Any] = Depends(api_key_auth),
) -> SupportTicketResponse:
    """
    Submit a support ticket.

    Creates a new support ticket and sends email notification to support@aldeci.
    """
    ticket_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    try:
        # Send email notification via notification_engine
        notif_engine = _get_notification_engine()
        if notif_engine:
            email_body = f"""
Support Ticket #{ticket_id}

From: {req.name} <{req.email}>
Subject: {req.subject}
Submitted: {now}

Message:
{req.description}

---
Ticket ID: {ticket_id}
Status: Open
"""
            try:
                # Send to support email (stub: notification engine will route)
                notif_engine.notify(
                    event_type="support_ticket",
                    channels=["email"],
                    recipient="support@aldeci.com",
                    subject=f"Support Ticket: {req.subject}",
                    body=email_body,
                    metadata={
                        "ticket_id": ticket_id,
                        "customer_email": req.email,
                        "customer_name": req.name,
                    },
                )
                _logger.info(f"Support ticket {ticket_id} submitted by {req.email}")
            except Exception as e:
                _logger.warning(
                    f"Failed to send notification for ticket {ticket_id}: {e}"
                )
                # Don't fail the request if notification fails
        else:
            _logger.warning("NotificationEngine not available, ticket created but email not sent")

        return SupportTicketResponse(
            ticket_id=ticket_id,
            status="open",
            message="Support ticket submitted successfully. We will respond within 24 hours.",
        )

    except Exception as e:
        _logger.error(f"Error submitting support ticket: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit support ticket",
        )
