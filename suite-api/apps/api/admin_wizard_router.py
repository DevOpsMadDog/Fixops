"""Admin First-Login Wizard router — ALDECI onboarding bug fix 2026-04-27.

Surfaced by 4-app non-tech customer playbook (commit 682a7437): a freshly
installed admin lands on the empty Command hero with no prompts, has no idea
that Step 1 is Admin -> Organizations -> Create New, and assumes ALDECI is
broken. This router backs the FirstLoginWizard React component with a tiny,
real SQLite-backed state store -- no localStorage-only fakes.

Endpoints
---------
GET  /api/v1/admin/wizard-state
    Returns ``{completed, completed_at, completed_steps, first_seen_at}``.
    On the very first GET (no row exists) the row is INSERTed with
    completed=false and first_seen_at=now -- this captures "first admin
    login" deterministically per-install. Subsequent GETs are pure reads.

POST /api/v1/admin/wizard-state
    Body: ``{step: str | None, completed: bool | None}``.
    If ``step`` is given, appends it to ``completed_steps`` (idempotent).
    If ``completed=True`` is given, marks the wizard fully complete with
    completed_at=now. Returns the updated row.

POST /api/v1/admin/wizard-state/reset
    Engineer hatch -- clears all state so the wizard re-fires on next GET.
    Useful for QA, demos, and customer success replays.

Storage
-------
``data/admin_wizard.db`` (SQLite). Single ``wizard_state`` row per install
(id=1 is the only row). The DB lives outside the repo so it survives
container restarts but resets on fresh installs -- which is correct: a
fresh install IS a first login.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# Repo-relative path so dev + container both find it. The data/ dir is the
# canonical home for per-install SQLite stores in this repo.
_DB_PATH = Path(__file__).resolve().parents[3] / "data" / "admin_wizard.db"
_DB_LOCK = threading.RLock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    """Open the wizard-state DB, creating schema on first call."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wizard_state (
            id              INTEGER PRIMARY KEY CHECK (id = 1),
            completed       INTEGER NOT NULL DEFAULT 0,
            first_seen_at   TEXT,
            completed_at    TEXT,
            completed_steps TEXT NOT NULL DEFAULT '[]'
        )
        """
    )
    conn.commit()
    return conn


def _row_to_dict(row: Optional[sqlite3.Row]) -> Dict[str, Any]:
    if row is None:
        return {
            "completed": False,
            "first_seen_at": None,
            "completed_at": None,
            "completed_steps": [],
        }
    try:
        steps = json.loads(row["completed_steps"]) if row["completed_steps"] else []
    except (json.JSONDecodeError, TypeError):
        steps = []
    return {
        "completed": bool(row["completed"]),
        "first_seen_at": row["first_seen_at"],
        "completed_at": row["completed_at"],
        "completed_steps": steps,
    }


def _get_or_create_row(conn: sqlite3.Connection) -> sqlite3.Row:
    """Return the singleton row, INSERTing first_seen_at on the first call."""
    row = conn.execute("SELECT * FROM wizard_state WHERE id = 1").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO wizard_state (id, completed, first_seen_at, completed_steps) "
            "VALUES (1, 0, ?, '[]')",
            (_now_iso(),),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM wizard_state WHERE id = 1").fetchone()
    return row


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class WizardStateUpdate(BaseModel):
    """Body for POST /api/v1/admin/wizard-state."""

    step: Optional[str] = Field(
        None,
        description="Wizard step just completed (e.g. 'create_org'). Appended idempotently.",
        max_length=64,
    )
    completed: Optional[bool] = Field(
        None,
        description="Set true to mark the whole wizard complete (sets completed_at).",
    )


class WizardStateResponse(BaseModel):
    completed: bool
    first_seen_at: Optional[str]
    completed_at: Optional[str]
    completed_steps: List[str]


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


router = APIRouter(
    prefix="/api/v1/admin",
    tags=["Admin Wizard"],
)


@router.get(
    "/wizard-state",
    response_model=WizardStateResponse,
    summary="First-login wizard state (first GET initialises the install)",
)
def get_wizard_state() -> Dict[str, Any]:
    """Return the wizard-state row, creating it on first call.

    The first GET captures ``first_seen_at`` so the FirstLoginWizard React
    component can render exactly once for the very first admin to log in
    on this install. Subsequent admins on the same install see no wizard
    (because completed=true once any admin finishes it).
    """
    with _DB_LOCK:
        try:
            conn = _connect()
            try:
                row = _get_or_create_row(conn)
                return _row_to_dict(row)
            finally:
                conn.close()
        except sqlite3.Error as exc:
            _logger.exception("admin_wizard: get_wizard_state failed")
            raise HTTPException(
                status_code=500,
                detail=f"wizard_state_get_failed: {type(exc).__name__}",
            ) from exc


@router.post(
    "/wizard-state",
    response_model=WizardStateResponse,
    summary="Mark a wizard step or the whole wizard as complete",
)
def update_wizard_state(payload: WizardStateUpdate) -> Dict[str, Any]:
    """Append a completed step and/or mark the wizard fully done.

    Both ``step`` and ``completed`` are optional. Sending neither just returns
    the current state (no-op). Steps are deduped on insert so the React
    component can safely retry on network glitches.
    """
    with _DB_LOCK:
        try:
            conn = _connect()
            try:
                row = _get_or_create_row(conn)
                state = _row_to_dict(row)
                steps = list(state["completed_steps"])

                if payload.step and payload.step not in steps:
                    steps.append(payload.step)

                completed_flag = (
                    1 if payload.completed else (1 if state["completed"] else 0)
                )
                completed_at = (
                    _now_iso()
                    if payload.completed and not state["completed"]
                    else state["completed_at"]
                )

                conn.execute(
                    "UPDATE wizard_state SET completed = ?, completed_at = ?, "
                    "completed_steps = ? WHERE id = 1",
                    (completed_flag, completed_at, json.dumps(steps)),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM wizard_state WHERE id = 1"
                ).fetchone()
                return _row_to_dict(row)
            finally:
                conn.close()
        except sqlite3.Error as exc:
            _logger.exception("admin_wizard: update_wizard_state failed")
            raise HTTPException(
                status_code=500,
                detail=f"wizard_state_update_failed: {type(exc).__name__}",
            ) from exc


@router.post(
    "/wizard-state/reset",
    response_model=WizardStateResponse,
    summary="Reset wizard state (QA / demo / customer-success replay)",
)
def reset_wizard_state() -> Dict[str, Any]:
    """Clear all wizard state so the next GET starts a fresh first-login flow."""
    with _DB_LOCK:
        try:
            conn = _connect()
            try:
                conn.execute("DELETE FROM wizard_state WHERE id = 1")
                conn.commit()
                # Re-create a fresh first-seen row immediately so callers
                # never see a 404 on the very next GET.
                row = _get_or_create_row(conn)
                return _row_to_dict(row)
            finally:
                conn.close()
        except sqlite3.Error as exc:
            _logger.exception("admin_wizard: reset_wizard_state failed")
            raise HTTPException(
                status_code=500,
                detail=f"wizard_state_reset_failed: {type(exc).__name__}",
            ) from exc
