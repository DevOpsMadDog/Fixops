"""Syft Router — ALDECI.

Wraps :mod:`core.syft_sbom_engine` and exposes a thin HTTP surface for SBOM
generation using Syft conventions (CycloneDX / SPDX / Syft / GitHub formats).

Prefix: ``/api/v1/syft``
Auth: API-key dependency injected by the parent app at ``include_router`` time.

Routes
------
GET  /api/v1/syft/                    capability summary
POST /api/v1/syft/sbom                queue SBOM generation
GET  /api/v1/syft/sbom/{sbom_id}      retrieve generated SBOM (with packages)
GET  /api/v1/syft/sbom                list recent SBOMs (debug / discovery)
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/syft", tags=["syft", "sbom"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class SyftSBOMRequest(BaseModel):
    input_type: str = Field(..., description="One of: image, dir, file, registry")
    target: str = Field(..., min_length=1, description="Reference to scan")
    output_format: Optional[str] = Field(
        default="cyclonedx-json",
        description=(
            "One of: cyclonedx-json, cyclonedx-xml, spdx-json, "
            "spdx-tag-value, syft-json, syft-table, github-json"
        ),
    )
    scope: Optional[str] = Field(
        default="Squashed",
        description="Layer scope: Squashed (default) or AllLayers",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/")
def syft_overview():
    """Service capability summary — returns input types, output formats, scope options."""
    from core.syft_sbom_engine import get_syft_sbom_engine  # noqa: PLC0415

    return get_syft_sbom_engine().capabilities()


@router.post("/sbom", status_code=202)
def generate_sbom(body: SyftSBOMRequest):
    """Queue a Syft SBOM generation job (executed inline; returns receipt)."""
    from core.syft_sbom_engine import (  # noqa: PLC0415
        DEFAULT_OUTPUT_FORMAT,
        DEFAULT_SCOPE,
        get_syft_sbom_engine,
    )

    try:
        return get_syft_sbom_engine().generate_sbom(
            input_type=body.input_type,
            target=body.target,
            output_format=body.output_format or DEFAULT_OUTPUT_FORMAT,
            scope=body.scope or DEFAULT_SCOPE,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/sbom")
def list_sboms(limit: int = Query(default=50, ge=1, le=1000)):
    """List recently generated SBOMs (most recent first)."""
    from core.syft_sbom_engine import get_syft_sbom_engine  # noqa: PLC0415

    return {"sboms": get_syft_sbom_engine().list_sboms(limit=limit), "count_returned": None}


@router.get("/sbom/{sbom_id}")
def get_sbom(sbom_id: str):
    """Fetch a previously generated SBOM by id (includes parsed packages)."""
    from core.syft_sbom_engine import get_syft_sbom_engine  # noqa: PLC0415

    sbom = get_syft_sbom_engine().get_sbom(sbom_id)
    if sbom is None:
        raise HTTPException(status_code=404, detail=f"SBOM not found: {sbom_id}")
    return sbom


__all__ = ["router"]
