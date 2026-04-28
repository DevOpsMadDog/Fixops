"""
Remediation Board Router — Kanban-style security fix tracking.

10 endpoints:
  POST   /api/v1/remediation-board/cards                      create_card
  GET    /api/v1/remediation-board/board                      get_board
  GET    /api/v1/remediation-board/cards/{card_id}            get_card
  PATCH  /api/v1/remediation-board/cards/{card_id}/move       move_card
  PATCH  /api/v1/remediation-board/cards/{card_id}/assign     assign_card
  POST   /api/v1/remediation-board/cards/{card_id}/comments   add_comment
  GET    /api/v1/remediation-board/workload                   get_assignee_workload
  GET    /api/v1/remediation-board/metrics                    get_board_metrics
  GET    /api/v1/remediation-board/overdue                    get_overdue
  POST   /api/v1/remediation-board/cards/bulk                 auto_create_from_findings
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "remediation_board_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.remediation_board import (
    BoardColumn,
    CardComment,
    RemediationBoard,
    RemediationCard,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/remediation-board",
    tags=["remediation-board"],
    dependencies=_AUTH_DEP,
)

# Shared board instance (file-backed, shared across requests)
_board: Optional[RemediationBoard] = None


def _get_board() -> RemediationBoard:
    global _board
    if _board is None:
        _board = RemediationBoard("data/remediation_board/board.db")
    return _board


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class CreateCardRequest(BaseModel):
    finding_id: str = Field(..., description="ID of the security finding")
    title: str = Field(..., description="Short card title")
    description: str = Field("", description="Full description of what needs fixing")
    assignee: Optional[str] = Field(None, description="Assignee email or username")
    priority: str = Field("medium", description="critical|high|medium|low|informational")
    org_id: str = Field("default", description="Organisation ID")
    labels: List[str] = Field(default_factory=list, description="Optional labels/tags")
    due_date: Optional[str] = Field(None, description="ISO 8601 due date, e.g. 2026-05-01T00:00:00Z")


class MoveCardRequest(BaseModel):
    to_column: str = Field(..., description="Target column: backlog|todo|in_progress|in_review|testing|done")


class AssignCardRequest(BaseModel):
    assignee: str = Field(..., description="Assignee email or username")


class AddCommentRequest(BaseModel):
    author: str = Field(..., description="Comment author email or username")
    text: str = Field(..., description="Comment text")


class BulkFindingItem(BaseModel):
    finding_id: Optional[str] = None
    id: Optional[str] = None
    title: str
    description: str = ""
    severity: Optional[str] = None
    priority: Optional[str] = None
    assignee: Optional[str] = None
    labels: List[str] = Field(default_factory=list)


class BulkCreateRequest(BaseModel):
    findings: List[BulkFindingItem]
    org_id: str = Field("default", description="Organisation ID")


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/cards", response_model=RemediationCard, status_code=201)
def create_card(body: CreateCardRequest) -> RemediationCard:
    """Create a new remediation card in BACKLOG."""
    from datetime import datetime

    due_date = None
    if body.due_date:
        try:
            due_date = datetime.fromisoformat(body.due_date.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid due_date format: {exc}") from exc

    try:
        card = _get_board().create_card(
            finding_id=body.finding_id,
            title=body.title,
            description=body.description,
            assignee=body.assignee,
            priority=body.priority,
            org_id=body.org_id,
            labels=body.labels,
            due_date=due_date,
        )
    except Exception as exc:
        logger.exception("remediation_board_router: create_card failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return card


@router.get("/board")
def get_board(org_id: str = Query("default", description="Organisation ID")) -> Dict[str, Any]:
    """Return all cards grouped by Kanban column."""
    try:
        board = _get_board().get_board(org_id)
    except Exception as exc:
        logger.exception("remediation_board_router: get_board failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    # Serialize cards to dicts for JSON response
    return {col: [c.model_dump(mode="json") for c in cards] for col, cards in board.items()}


@router.get("/cards/{card_id}", response_model=RemediationCard)
def get_card(card_id: str) -> RemediationCard:
    """Return full card details with comments."""
    card = _get_board().get_card(card_id)
    if card is None:
        raise HTTPException(status_code=404, detail=f"Card not found: {card_id}")
    return card


@router.patch("/cards/{card_id}/move", response_model=RemediationCard)
def move_card(card_id: str, body: MoveCardRequest) -> RemediationCard:
    """Move a card to a different Kanban column."""
    try:
        col = BoardColumn(body.to_column)
    except ValueError:
        valid = [c.value for c in BoardColumn]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid column '{body.to_column}'. Valid: {valid}",
        )
    try:
        return _get_board().move_card(card_id, col)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("remediation_board_router: move_card failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.patch("/cards/{card_id}/assign", response_model=RemediationCard)
def assign_card(card_id: str, body: AssignCardRequest) -> RemediationCard:
    """Reassign a card to a different person."""
    try:
        return _get_board().assign_card(card_id, body.assignee)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("remediation_board_router: assign_card failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/cards/{card_id}/comments", response_model=CardComment, status_code=201)
def add_comment(card_id: str, body: AddCommentRequest) -> CardComment:
    """Add a comment to a card."""
    try:
        return _get_board().add_comment(card_id, body.author, body.text)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("remediation_board_router: add_comment failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/workload")
def get_assignee_workload(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, int]:
    """Return active card count per assignee (excluding DONE)."""
    try:
        return _get_board().get_assignee_workload(org_id)
    except Exception as exc:
        logger.exception("remediation_board_router: get_assignee_workload failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/metrics")
def get_board_metrics(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return board metrics: cycle time, throughput, WIP per column."""
    try:
        return _get_board().get_board_metrics(org_id)
    except Exception as exc:
        logger.exception("remediation_board_router: get_board_metrics failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/overdue", response_model=List[RemediationCard])
def get_overdue(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[RemediationCard]:
    """Return all cards past their due date that are not yet DONE."""
    try:
        return _get_board().get_overdue(org_id)
    except Exception as exc:
        logger.exception("remediation_board_router: get_overdue failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/cards/bulk", response_model=List[RemediationCard], status_code=201)
def auto_create_from_findings(body: BulkCreateRequest) -> List[RemediationCard]:
    """Bulk-create remediation cards from a list of security findings."""
    findings_dicts = [f.model_dump() for f in body.findings]
    try:
        return _get_board().auto_create_from_findings(findings_dicts, org_id=body.org_id)
    except Exception as exc:
        logger.exception("remediation_board_router: auto_create_from_findings failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
