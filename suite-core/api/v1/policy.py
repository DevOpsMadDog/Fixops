"""Policy evaluation endpoint — gate verdicts with KEV waiver enforcement.

Provides:
- ``GateRequest`` / ``GateResponse`` Pydantic models
- ``WaiverCreate`` schema for creating KEV waivers
- ``evaluate_gate()`` — async gate evaluation with OPA integration
- ``create_waiver()`` — persist a KEV waiver record

This module is intentionally decoupled from FastAPI routers so it can be
imported and tested directly.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.enterprise.settings import get_settings
from core.models.enterprise.security_sqlite import KevFindingWaiver

# ---------------------------------------------------------------------------
# Settings singleton (module-level so tests can monkeypatch)
# ---------------------------------------------------------------------------
settings = get_settings()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class GateRequest(BaseModel):
    """Incoming gate evaluation request."""

    decision: str = Field(description="Proposed decision (ALLOW / BLOCK)")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    signals: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class GateResponse(BaseModel):
    """Gate evaluation result."""

    allow: bool
    reason: str
    required_actions: List[str] = Field(default_factory=list)


class WaiverCreate(BaseModel):
    """Schema for creating a KEV waiver."""

    cve_id: str
    service_name: str
    justification: str
    approved_by: str
    expires_at: datetime
    requested_by: str = "unknown"


class WaiverRecord(BaseModel):
    """Returned after a waiver is persisted."""

    id: str
    cve_id: str
    service_name: str
    status: str = "active"


# ---------------------------------------------------------------------------
# OPA engine helper
# ---------------------------------------------------------------------------

async def get_opa_engine() -> Any:
    """Return the configured OPA engine (production or local).

    Imports lazily to avoid circular dependencies.
    """
    from core.services.enterprise.real_opa_engine import (
        LocalOPAEngine,
        ProductionOPAEngine,
    )

    opa_url = getattr(settings, "OPA_SERVER_URL", None)
    if opa_url:
        return ProductionOPAEngine(server_url=opa_url)
    return LocalOPAEngine()


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

async def evaluate_gate(
    request: GateRequest,
    *,
    db: AsyncSession,
) -> GateResponse:
    """Evaluate a gate request against KEV waivers and optional OPA policy."""

    # 1. KEV enforcement — any finding with kev=True must have an active waiver
    kev_findings = [f for f in request.findings if f.get("kev")]
    service_name = request.signals.get("service_name")

    for finding in kev_findings:
        cve_id = finding.get("cve_id", "")
        stmt = select(KevFindingWaiver).where(KevFindingWaiver.cve_id == cve_id)
        result = await db.execute(stmt)
        waiver = result.scalars().first()

        if waiver is None or not waiver.is_active_for(
            service_name=service_name
        ):
            return GateResponse(
                allow=False,
                reason=f"KEV finding {cve_id} has no active waiver",
                required_actions=[
                    f"Create a waiver for {cve_id} or remediate the vulnerability"
                ],
            )

    # 2. OPA policy evaluation (if configured and not in demo mode)
    demo_mode = getattr(settings, "DEMO_MODE", True)
    opa_url = getattr(settings, "OPA_SERVER_URL", None)

    if not demo_mode and opa_url:
        engine = await get_opa_engine()
        opa_payload = {
            "decision": request.decision,
            "confidence": request.confidence,
            "signals": request.signals,
            "findings": request.findings,
        }
        opa_result = await engine.evaluate_policy("vulnerability", opa_payload)
        opa_decision = opa_result.get("decision", "allow")
        if opa_decision == "block":
            rationale = opa_result.get("rationale", "policy violation")
            return GateResponse(
                allow=False,
                reason=f"OPA policy blocked: {rationale}",
                required_actions=["Review OPA policy and remediate findings"],
            )

    return GateResponse(allow=True, reason="Policy checks passed")


async def create_waiver(
    payload: WaiverCreate,
    *,
    db: AsyncSession,
) -> WaiverRecord:
    """Persist a KEV waiver and return a record."""

    waiver = KevFindingWaiver(
        id=str(uuid.uuid4()),
        cve_id=payload.cve_id,
        service_name=payload.service_name,
        justification=payload.justification,
        approved_by=payload.approved_by,
        approved_at=datetime.now(timezone.utc),
        expires_at=payload.expires_at,
    )
    db.add(waiver)
    await db.commit()
    await db.refresh(waiver)

    return WaiverRecord(
        id=waiver.id,
        cve_id=waiver.cve_id,
        service_name=waiver.service_name,
        status="active",
    )
