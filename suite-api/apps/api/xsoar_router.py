"""Palo Alto Cortex XSOAR (Demisto) Router — ALDECI.

Wraps Cortex XSOAR's REST surface under prefix ``/api/v1/xsoar``:

  - GET  /                              capability summary
  - POST /incidents/search              filter+page+sort incidents
  - GET  /incidents/{incident_id}       single incident with full payload
  - POST /incidents/{incident_id}/run   trigger playbook on incident
  - POST /entry                         add markdown/text/html note to incident
  - POST /playbooks/search              filter+page playbooks
  - POST /settings/integration/search   list integration instances
  - POST /settings/integration/test     test integration credentials

NO MOCKS rule
-------------
* When XSOAR_BASE_URL or XSOAR_API_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/xsoar",
    tags=["Cortex XSOAR"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor
# ---------------------------------------------------------------------------


def _engine():
    from core.xsoar_engine import get_xsoar_engine

    return get_xsoar_engine()


def _serve(callable_):
    """Run an XSOAR call, translating engine errors to HTTP responses.

    XsoarUnavailableError -> 503
    ValueError            -> 422
    """
    from core.xsoar_engine import XsoarUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except XsoarUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class IncidentSearchFilter(BaseModel):
    query: Optional[str] = Field(default=None)
    page: int = Field(default=0, ge=0)
    size: int = Field(default=50, ge=1, le=1000)
    fromDate: Optional[str] = Field(default=None)
    toDate: Optional[str] = Field(default=None)
    status: Optional[List[int]] = Field(default=None)
    severity: Optional[List[int]] = Field(default=None)


class SortClause(BaseModel):
    field: str = Field(..., min_length=1)
    asc: bool = Field(default=True)


class IncidentSearchRequest(BaseModel):
    filter: IncidentSearchFilter = Field(default_factory=IncidentSearchFilter)
    ascending: Optional[bool] = Field(default=False)
    sort: Optional[List[SortClause]] = Field(default=None)


class RunPlaybookRequest(BaseModel):
    playbookId: str = Field(..., min_length=1)


class AddEntryRequest(BaseModel):
    investigationId: str = Field(..., min_length=1)
    data: str = Field(..., min_length=0)
    format: Optional[str] = Field(default=None, pattern="^(text|markdown|html|json|table)$")


class PlaybookSearchRequest(BaseModel):
    query: Optional[str] = Field(default=None)
    page: int = Field(default=0, ge=0)
    size: int = Field(default=50, ge=1, le=1000)


class IntegrationSearchRequest(BaseModel):
    query: Optional[str] = Field(default=None)
    page: int = Field(default=0, ge=0)
    size: int = Field(default=50, ge=1, le=1000)


class IntegrationConfigEntry(BaseModel):
    name: str = Field(..., min_length=1)
    value: Any


class IntegrationTestRequest(BaseModel):
    name: str = Field(..., min_length=1)
    brand: str = Field(..., min_length=1)
    configuration: List[IntegrationConfigEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Cortex XSOAR capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    base_ok = eng.base_url_present()
    key_ok = eng.api_key_present()
    return {
        "service": "Palo Alto Cortex XSOAR",
        "endpoints": [
            "/incidents/search",
            "/incidents/{id}",
            "/incidents/{id}/run",
            "/playbooks/search",
            "/settings/integration/search",
        ],
        "xsoar_base_url_present": base_ok,
        "xsoar_api_key_present": key_ok,
        "status": "ok" if (base_ok and key_ok) else "unavailable",
    }


# ---------------------------------------------------------------------------
# Incident endpoints
# ---------------------------------------------------------------------------


@router.post("/incidents/search", summary="Search/filter incidents")
def incidents_search(body: IncidentSearchRequest = Body(...)) -> Dict[str, Any]:
    flt = body.filter
    sort_dump: Optional[List[Dict[str, Any]]] = None
    if body.sort is not None:
        sort_dump = [s.model_dump() for s in body.sort]
    return _serve(
        lambda: _engine().search_incidents(
            query=flt.query,
            page=flt.page,
            size=flt.size,
            from_date=flt.fromDate,
            to_date=flt.toDate,
            status=flt.status,
            severity=flt.severity,
            ascending=bool(body.ascending) if body.ascending is not None else False,
            sort=sort_dump,
        )
    )


@router.get("/incidents/{incident_id}", summary="Fetch single incident")
def incidents_get(
    incident_id: str = Path(..., min_length=1, description="XSOAR incident id"),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().get_incident(incident_id))


@router.post("/incidents/{incident_id}/run", status_code=204, summary="Run playbook on incident")
def incidents_run(
    incident_id: str = Path(..., min_length=1),
    body: RunPlaybookRequest = Body(...),
):
    _serve(
        lambda: _engine().run_playbook(
            incident_id=incident_id,
            playbook_id=body.playbookId,
        )
    )
    # Returning None with status_code=204 yields an empty body
    return None


@router.post("/entry", summary="Add a war-room entry to an incident")
def add_entry(body: AddEntryRequest = Body(...)) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().add_entry(
            investigation_id=body.investigationId,
            data=body.data,
            format=body.format,
        )
    )


# ---------------------------------------------------------------------------
# Playbook + Integration endpoints
# ---------------------------------------------------------------------------


@router.post("/playbooks/search", summary="Search/filter playbooks")
def playbooks_search(body: PlaybookSearchRequest = Body(...)) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().search_playbooks(
            query=body.query, page=body.page, size=body.size
        )
    )


@router.post("/settings/integration/search", summary="Search integration instances")
def integrations_search(body: IntegrationSearchRequest = Body(...)) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().search_integrations(
            query=body.query, page=body.page, size=body.size
        )
    )


@router.post("/settings/integration/test", summary="Test integration credentials")
def integrations_test(body: IntegrationTestRequest = Body(...)) -> Dict[str, Any]:
    config = [c.model_dump() for c in body.configuration]
    return _serve(
        lambda: _engine().test_integration(
            name=body.name,
            brand=body.brand,
            configuration=config,
        )
    )


__all__ = ["router"]
