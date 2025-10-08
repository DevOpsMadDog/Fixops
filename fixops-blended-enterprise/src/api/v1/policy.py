"""Policy evaluation endpoints for CI/CD gates (SSVC-aware)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import get_settings
from src.db.session import get_db
from src.models.waivers import get_kev_waiver_model
from src.services.real_opa_engine import get_opa_engine

logger = structlog.get_logger()
router = APIRouter(prefix="/policy", tags=["policy-gates"])
settings = get_settings()


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
KevWaiverModel = get_kev_waiver_model()

if KevWaiverModel is None:  # pragma: no cover - misconfiguration safeguard
    raise RuntimeError("KEV waiver model is unavailable for the configured database")


def _normalize_datetime(value: datetime) -> datetime:
    """Return a timezone-naive UTC datetime for persistence and comparison."""

    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


class GateRequest(BaseModel):
    """Payload accepted by the policy gate evaluation endpoint."""

    decision: str  # ALLOW/BLOCK/DEFER
    confidence: float
    signals: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class GateResponse(BaseModel):
    """Structured response for policy evaluation requests."""

    allow: bool
    reason: str
    required_actions: List[str]


class WaiverCreate(BaseModel):
    """Schema for creating or updating a KEV waiver."""

    model_config = ConfigDict(str_strip_whitespace=True)

    cve_id: str = Field(..., description="CVE identifier for the KEV finding", min_length=5)
    service_name: Optional[str] = Field(
        default=None,
        description="Optional service scope; omit for platform-wide waivers",
        max_length=255,
    )
    justification: str = Field(..., description="Business justification for the waiver", min_length=10)
    approved_by: str = Field(..., description="Approver recorded for audit", max_length=255)
    expires_at: datetime = Field(..., description="UTC expiration timestamp")
    change_ticket: Optional[str] = Field(
        default=None,
        description="Change, risk, or exception ticket tracking the waiver",
        max_length=255,
    )
    finding_id: Optional[str] = Field(
        default=None,
        description="Specific finding identifier when the waiver is scoped narrowly",
        max_length=36,
    )
    requested_by: Optional[str] = Field(
        default=None,
        description="Security user requesting the waiver for audit attribution",
        max_length=255,
    )

    @field_validator("cve_id")
    @classmethod
    def _normalize_cve(cls, value: str) -> str:
        normalized = value.upper().strip()
        if not normalized.startswith("CVE-"):
            raise ValueError("cve_id must be a valid CVE identifier (e.g. CVE-2024-12345)")
        return normalized

    @field_validator("expires_at")
    @classmethod
    def _validate_expiry(cls, value: datetime) -> datetime:
        normalized = _normalize_datetime(value)
        if normalized <= _normalize_datetime(datetime.now(timezone.utc)):
            raise ValueError("expires_at must be in the future")
        return normalized


class WaiverResponse(BaseModel):
    """Serialized KEV waiver returned to clients."""

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
    is_active: bool
    created_by: Optional[str]
    created_at: datetime
    modified_by: Optional[str]
    updated_at: datetime

    @computed_field(return_type=str)
    def status(self) -> str:
        """Return the current lifecycle state for observability and UI badges."""

        if not self.is_active:
            return "revoked"

        expires = _normalize_datetime(self.expires_at)
        now = _normalize_datetime(datetime.now(timezone.utc))
        return "active" if expires >= now else "expired"


def _extract_service_name(signals: Dict[str, Any]) -> Optional[str]:
    """Resolve a service identifier from heterogeneous payloads."""

    candidate_keys = ("service_name", "service", "serviceId", "service_id", "application")
    for key in candidate_keys:
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


def _extract_kev_cves(signals: Dict[str, Any], findings: Sequence[Dict[str, Any]]) -> Set[str]:
    """Collect CVE identifiers for KEV findings from signals and finding payloads."""

    kev_ids: Set[str] = set()

    for key in ("kev_cves", "kev_ids", "kev_findings"):
        for entry in _coerce_iterable(signals.get(key)):
            if isinstance(entry, str):
                if entry.strip():
                    kev_ids.add(entry.strip().upper())
            elif isinstance(entry, dict):
                candidate = entry.get("cve") or entry.get("cve_id") or entry.get("id")
                if isinstance(candidate, str) and candidate.strip():
                    kev_ids.add(candidate.strip().upper())

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        cve = finding.get("cve_id") or finding.get("cve") or finding.get("kev_reference")
        is_kev = bool(finding.get("kev") or finding.get("is_kev") or finding.get("kev_reference"))
        if cve and isinstance(cve, str):
            cve_upper = cve.strip().upper()
            if is_kev or cve_upper in kev_ids:
                kev_ids.add(cve_upper)

    return {cve for cve in kev_ids if cve.startswith("CVE-")}


def _extract_environment(signals: Dict[str, Any]) -> Optional[str]:
    """Resolve an environment label from the provided signals."""

    for key in ("environment", "env", "deployment_environment", "target_env"):
        value = signals.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "enabled"}:
            return True
        if lowered in {"false", "0", "no", "n", "disabled"}:
            return False
    return False


def _as_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip().upper()
    return normalized or None


def _collect_vulnerabilities(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalise finding payloads so remote OPA policies receive consistent input."""

    entries: List[Dict[str, Any]] = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        fix_available = finding.get("fix_available")
        if fix_available is None:
            fix_available = finding.get("fixAvailable")

        entry = {
            "id": finding.get("id")
            or finding.get("finding_id")
            or finding.get("uuid"),
            "cve_id": (
                finding.get("cve_id")
                or finding.get("cve")
                or finding.get("cveId")
                or finding.get("kev_id")
            ),
            "kev": _as_bool(finding.get("kev") or finding.get("is_kev")),
            "severity": _normalize_severity(
                finding.get("severity")
                or finding.get("severity_label")
                or finding.get("severity_level"),
            ),
            "fix_available": _as_bool(fix_available),
            "cvss_score": _as_float(
                finding.get("cvss_score")
                or finding.get("cvss")
                or finding.get("cvss_v3"),
            ),
            "epss": _as_float(finding.get("epss") or finding.get("epss_score")),
            "title": finding.get("title") or finding.get("name"),
        }
        entries.append(entry)

    return entries


def _build_sbom_payload(signals: Dict[str, Any]) -> Dict[str, Any]:
    sbom_data = signals.get("sbom") if isinstance(signals.get("sbom"), dict) else None
    components = signals.get("sbom_components")
    payload: Dict[str, Any] = {
        "sbom_present": _as_bool(signals.get("sbom_present")) or bool(sbom_data),
        "sbom_valid": _as_bool(signals.get("sbom_valid")),
    }
    if sbom_data is not None:
        payload["sbom"] = sbom_data
    if isinstance(components, list):
        payload["components"] = components
    if signals.get("sbom_required") is not None:
        payload["sbom_required"] = _as_bool(signals.get("sbom_required"))
    return payload


async def _evaluate_remote_policies(
    request: GateRequest, service_name: Optional[str]
) -> List[Tuple[str, Dict[str, Any]]]:
    """Evaluate remote OPA policies when running in enterprise mode."""

    if settings.DEMO_MODE or not getattr(settings, "OPA_SERVER_URL", None):
        return []

    vulnerabilities = _collect_vulnerabilities(request.findings)
    sbom_payload = _build_sbom_payload(request.signals)
    environment = _extract_environment(request.signals)

    policy_inputs: List[Tuple[str, Dict[str, Any]]] = []

    if vulnerabilities:
        vuln_payload: Dict[str, Any] = {"vulnerabilities": vulnerabilities}
        if service_name:
            vuln_payload["service_name"] = service_name
        if environment:
            vuln_payload["environment"] = environment
        vuln_payload["kev_findings"] = [entry for entry in vulnerabilities if entry.get("kev")]
        policy_inputs.append(("vulnerability", vuln_payload))

    if sbom_payload:
        if service_name:
            sbom_payload.setdefault("service_name", service_name)
        if environment:
            sbom_payload.setdefault("environment", environment)
        policy_inputs.append(("sbom", sbom_payload))

    if not policy_inputs:
        return []

    try:
        engine = await get_opa_engine()
        if not await engine.health_check():
            logger.warning("OPA engine health check failed; skipping remote enforcement")
            return []

        decisions: List[Tuple[str, Dict[str, Any]]] = []
        for policy_name, payload in policy_inputs:
            try:
                decision = await engine.evaluate_policy(policy_name, payload)
            except Exception as exc:  # pragma: no cover - network/transient failure guard
                logger.warning(
                    "OPA policy evaluation failed", policy=policy_name, error=str(exc)
                )
                decisions.append(
                    (
                        policy_name,
                        {
                            "decision": "error",
                            "rationale": f"OPA evaluation error: {exc}",
                            "error": True,
                        },
                    )
                )
            else:
                decisions.append((policy_name, decision))
        return decisions
    except Exception as exc:  # pragma: no cover - defensive guardrail
        logger.warning("OPA enforcement aborted", error=str(exc))
        return []


def _map_opa_results(results: List[Tuple[str, Dict[str, Any]]]) -> Optional[GateResponse]:
    """Translate OPA policy decisions into gate responses."""

    for policy_name, decision in results:
        outcome = str(decision.get("decision", "")).lower()
        rationale = decision.get("rationale") or decision.get("details") or ""

        if outcome == "allow":
            continue

        if outcome == "block":
            reason = (
                f"OPA policy '{policy_name}' blocked the request: {rationale}".strip()
                or f"OPA policy '{policy_name}' blocked the request"
            )
            return GateResponse(
                allow=False,
                reason=reason,
                required_actions=[
                    "Review OPA policy findings",
                    "Apply required remediations",
                    "Re-run policy evaluation",
                ],
            )

        if outcome in {"defer", "error"} or decision.get("error"):
            reason = (
                f"OPA policy '{policy_name}' requires manual review: {rationale}".strip()
                or f"OPA policy '{policy_name}' requires manual review"
            )
            return GateResponse(
                allow=False,
                reason=reason,
                required_actions=[
                    "Investigate OPA policy status",
                    "Resolve bundle discrepancies",
                    "Re-run policy evaluation",
                ],
            )

    return None


async def _get_active_waivers(
    db: AsyncSession,
    cve_ids: Set[str],
    service_name: Optional[str],
) -> Dict[str, List[Any]]:
    """Fetch active waivers matching the provided CVE identifiers."""

    if not cve_ids:
        return {}

    now = _normalize_datetime(datetime.now(timezone.utc))

    stmt = (
        select(KevWaiverModel)
        .where(
            KevWaiverModel.cve_id.in_(list(cve_ids)),
            KevWaiverModel.is_active.is_(True),
            KevWaiverModel.expires_at >= now,
        )
    )

    if service_name:
        stmt = stmt.where(
            or_(
                KevWaiverModel.service_name.is_(None),
                KevWaiverModel.service_name == service_name,
            )
        )

    result = await db.execute(stmt)
    rows = result.scalars().all()

    waivers: Dict[str, List[Any]] = {}
    for row in rows:
        waivers.setdefault(row.cve_id, []).append(row)
    return waivers


def _kev_block_response(unwaived: Set[str]) -> GateResponse:
    sorted_ids = ", ".join(sorted(unwaived)) if unwaived else "KEV finding"
    return GateResponse(
        allow=False,
        reason=f"KEV findings ({sorted_ids}) require remediation or an approved waiver",
        required_actions=[
            "Patch affected KEV vulnerabilities",
            "Request and approve a waiver if deferral is required",
            "Re-run policy evaluation",
        ],
    )


@router.post("/evaluate", response_model=GateResponse)
async def evaluate_gate(req: GateRequest, db: AsyncSession = Depends(get_db)) -> GateResponse:
    """Evaluate policy gating rules with KEV hard-block enforcement."""

    try:
        kev_count = int(req.signals.get("kev_count", 0) or 0)
        consensus_threshold = _coerce_float(getattr(settings, "LLM_CONSENSUS_THRESHOLD", 0.75), 0.75)
        low_confidence = req.confidence < max(consensus_threshold, 0.75)

        if req.decision == "BLOCK":
            return GateResponse(
                allow=False,
                reason="Engine decided BLOCK",
                required_actions=["Fix blocking issues", "Request re-evaluation"],
            )

        service_name = _extract_service_name(req.signals)
        kev_cves = _extract_kev_cves(req.signals, req.findings)

        if kev_count or kev_cves:
            if not kev_cves and kev_count:
                return _kev_block_response(set())

            waivers = await _get_active_waivers(db, kev_cves, service_name)
            unwaived = {cve for cve in kev_cves if not waivers.get(cve)}
            if unwaived or (kev_count and not kev_cves):
                return _kev_block_response(unwaived or kev_cves or {"KEV"})

        if low_confidence:
            return GateResponse(
                allow=False,
                reason=f"Consensus confidence too low ({req.confidence:.0%})",
                required_actions=["Manual review", "Add business context"],
            )

        opa_results = await _evaluate_remote_policies(req, service_name)
        opa_response = _map_opa_results(opa_results)
        if opa_response is not None:
            return opa_response

        return GateResponse(
            allow=True,
            reason="Policy checks passed",
            required_actions=["Proceed with deployment"],
        )
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Policy evaluate failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/waivers", response_model=WaiverResponse, status_code=status.HTTP_201_CREATED)
async def create_waiver(
    waiver: WaiverCreate,
    db: AsyncSession = Depends(get_db),
) -> WaiverResponse:
    """Create or update a KEV waiver with auditable metadata."""

    try:
        normalized_expiry = _normalize_datetime(waiver.expires_at)

        existing_stmt = select(KevWaiverModel).where(
            KevWaiverModel.cve_id == waiver.cve_id,
            KevWaiverModel.is_active.is_(True),
        )
        if waiver.service_name:
            existing_stmt = existing_stmt.where(KevWaiverModel.service_name == waiver.service_name)
        if waiver.finding_id:
            existing_stmt = existing_stmt.where(KevWaiverModel.finding_id == waiver.finding_id)

        result = await db.execute(existing_stmt.limit(1))
        record = result.scalars().first()

        now = _normalize_datetime(datetime.now(timezone.utc))
        approved_at = now

        if record:
            record.justification = waiver.justification
            record.approved_by = waiver.approved_by
            record.approved_at = approved_at
            record.expires_at = normalized_expiry
            record.change_ticket = waiver.change_ticket
            record.modified_by = waiver.approved_by
            await db.flush()
            await db.commit()
            await db.refresh(record)
            return WaiverResponse.model_validate(record)

        payload = KevWaiverModel(
            cve_id=waiver.cve_id,
            service_name=waiver.service_name,
            finding_id=waiver.finding_id,
            justification=waiver.justification,
            approved_by=waiver.approved_by,
            approved_at=approved_at,
            expires_at=normalized_expiry,
            change_ticket=waiver.change_ticket,
            created_by=waiver.requested_by or waiver.approved_by,
            modified_by=waiver.approved_by,
        )

        db.add(payload)
        await db.flush()
        await db.commit()
        await db.refresh(payload)
        return WaiverResponse.model_validate(payload)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Failed to create waiver", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/waivers", response_model=List[WaiverResponse])
async def list_waivers(
    db: AsyncSession = Depends(get_db),
    cve_id: Optional[str] = Query(default=None, description="Filter waivers by CVE identifier"),
    service_name: Optional[str] = Query(default=None, description="Filter waivers by service scope"),
    include_expired: bool = Query(default=False, description="Include expired waivers in the response"),
) -> List[WaiverResponse]:
    """Return waivers, optionally filtered by CVE or service."""

    stmt = select(KevWaiverModel)

    if cve_id:
        stmt = stmt.where(KevWaiverModel.cve_id == cve_id.upper())
    if service_name:
        stmt = stmt.where(KevWaiverModel.service_name == service_name)
    if not include_expired:
        now = _normalize_datetime(datetime.now(timezone.utc))
        stmt = stmt.where(
            KevWaiverModel.is_active.is_(True),
            KevWaiverModel.expires_at >= now,
        )

    stmt = stmt.order_by(KevWaiverModel.expires_at.desc())

    result = await db.execute(stmt)
    waivers = result.scalars().all()
    return [WaiverResponse.model_validate(item) for item in waivers]
