"""Minimal policy gate implementation covering KEV waivers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from src.models.waivers import KevWaiver

router = APIRouter(prefix="/policy", tags=["policy-gates"])


class GateRequest(BaseModel):
    decision: str
    confidence: float
    signals: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class GateResponse(BaseModel):
    allow: bool
    reason: str
    required_actions: List[str]


class WaiverCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    cve_id: str = Field(..., min_length=5)
    service_name: Optional[str] = Field(default=None, max_length=255)
    justification: str = Field(..., min_length=10)
    approved_by: str = Field(..., max_length=255)
    expires_at: datetime
    change_ticket: Optional[str] = Field(default=None, max_length=255)
    finding_id: Optional[str] = Field(default=None, max_length=64)
    requested_by: Optional[str] = Field(default=None, max_length=255)

    @field_validator("cve_id")
    @classmethod
    def _normalize_cve(cls, value: str) -> str:
        candidate = value.strip().upper()
        if not candidate.startswith("CVE-"):
            raise ValueError("cve_id must resemble CVE-2024-12345")
        return candidate

    @field_validator("expires_at")
    @classmethod
    def _future_date(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if value <= now:
            raise ValueError("expires_at must be in the future")
        return value.astimezone(timezone.utc).replace(tzinfo=None)


class WaiverResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    cve_id: str
    service_name: Optional[str]
    finding_id: Optional[str]
    justification: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    change_ticket: Optional[str]
    requested_by: Optional[str]
    created_by: Optional[str]
    modified_by: Optional[str]
    created_at: datetime
    updated_at: datetime
    is_active: bool

    @computed_field(return_type=str)
    def status(self) -> str:
        if not self.is_active:
            return "revoked"
        now = datetime.now(timezone.utc)
        expires = self.expires_at.replace(tzinfo=timezone.utc)
        return "active" if expires >= now else "expired"


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=None)
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _extract_service_name(signals: Dict[str, Any]) -> Optional[str]:
    for key in ("service_name", "service", "application"):
        value = signals.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _coerce_iterable(value: Any) -> Iterable[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return value
    return [value]


def _extract_kev_cves(
    signals: Dict[str, Any], findings: Sequence[Dict[str, Any]]
) -> Set[str]:
    kev_ids: Set[str] = set()
    for key in ("kev_cves", "kev_ids"):
        for entry in _coerce_iterable(signals.get(key)):
            if isinstance(entry, str) and entry.strip():
                kev_ids.add(entry.strip().upper())
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        cve = (
            finding.get("cve_id") or finding.get("cve") or finding.get("kev_reference")
        )
        is_kev = bool(
            finding.get("kev") or finding.get("is_kev") or finding.get("kev_reference")
        )
        if cve and is_kev:
            kev_ids.add(str(cve).strip().upper())
    return kev_ids


async def create_waiver(payload: WaiverCreate, db: AsyncSession) -> WaiverResponse:
    waiver = KevWaiver(
        id=str(uuid.uuid4()),
        cve_id=payload.cve_id,
        service_name=payload.service_name.strip() if payload.service_name else None,
        justification=payload.justification,
        approved_by=payload.approved_by,
        approved_at=_normalize_datetime(datetime.now(timezone.utc)),
        expires_at=_normalize_datetime(payload.expires_at),
        change_ticket=payload.change_ticket,
        finding_id=payload.finding_id,
        requested_by=payload.requested_by,
        created_by=payload.requested_by,
        modified_by=payload.approved_by,
        created_at=_normalize_datetime(datetime.now(timezone.utc)),
        updated_at=_normalize_datetime(datetime.now(timezone.utc)),
        is_active=True,
    )
    db.add(waiver)
    await db.commit()
    await db.refresh(waiver)
    return WaiverResponse.model_validate(waiver)


async def evaluate_gate(request: GateRequest, db: AsyncSession) -> GateResponse:
    kev_cves = _extract_kev_cves(request.signals, request.findings)
    if not kev_cves:
        return GateResponse(
            allow=True,
            reason="Policy checks passed",
            required_actions=[],
        )

    service_name = _extract_service_name(request.signals)
    now = _normalize_datetime(datetime.now(timezone.utc))

    stmt = select(KevWaiver).where(
        KevWaiver.cve_id.in_(list(kev_cves)),
        KevWaiver.is_active.is_(True),
        KevWaiver.expires_at >= now,
    )
    if service_name:
        stmt = stmt.where(
            or_(
                KevWaiver.service_name.is_(None), KevWaiver.service_name == service_name
            )
        )

    result = await db.execute(stmt)
    matching = result.scalars().all()

    covered_cves = {waiver.cve_id for waiver in matching}
    uncovered = sorted(cve for cve in kev_cves if cve not in covered_cves)

    if not uncovered:
        return GateResponse(
            allow=True,
            reason="Policy checks passed",
            required_actions=[],
        )

    actions = [f"Submit waiver for {cve}" for cve in uncovered]
    return GateResponse(
        allow=False,
        reason=f"KEV findings without waivers: {', '.join(uncovered)}",
        required_actions=actions,
    )


__all__ = [
    "router",
    "GateRequest",
    "GateResponse",
    "WaiverCreate",
    "WaiverResponse",
    "create_waiver",
    "evaluate_gate",
]
