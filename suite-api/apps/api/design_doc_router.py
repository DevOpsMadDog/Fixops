"""Design Doc Ingest Router — ALDECI (GAP-056).

Unifies design-doc ingestion and STRIDE extraction across three threat-modeling
engines:

  * ``threat_modeling_engine``            — parses the doc, extracts STRIDE
    threats via keyword heuristics.
  * ``threat_modeling_pipeline_engine``   — auto-creates a draft STRIDE model
    from the ingest.
  * ``cyber_threat_modeling_engine``      — stores traceability links from a
    doc ingest to an attack-tree-based model.

Prefix: ``/api/v1/design-doc``
Auth:   ``api_key_auth`` (X-API-Key / Bearer / ?api_key).

Endpoints:
  POST /api/v1/design-doc/ingest      — parse + persist a design doc
  POST /api/v1/design-doc/extract     — run STRIDE heuristics on an ingest
  GET  /api/v1/design-doc/ingests     — list ingests for an org
  POST /api/v1/design-doc/auto-model  — draft a pipeline model from the ingest
  GET  /api/v1/design-doc/stride      — list extracted STRIDE threats
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/design-doc",
    tags=["Design Doc Ingest"],
    dependencies=[Depends(api_key_auth)],
)

_tme = None
_pipeline = None
_cyber = None


def _get_tme():
    global _tme
    if _tme is None:
        from core.threat_modeling_engine import ThreatModelingEngine
        _tme = ThreatModelingEngine()
    return _tme


def _get_pipeline():
    global _pipeline
    if _pipeline is None:
        from core.threat_modeling_pipeline_engine import ThreatModelingPipelineEngine
        _pipeline = ThreatModelingPipelineEngine()
    return _pipeline


def _get_cyber():
    global _cyber
    if _cyber is None:
        from core.cyber_threat_modeling_engine import CyberThreatModelingEngine
        _cyber = CyberThreatModelingEngine()
    return _cyber


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class IngestRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    doc_source: str = Field(..., description="Where the doc came from (URL / path)")
    doc_content: str = Field(..., description="Raw doc text (markdown or plain)")
    doc_format: str = Field(default="markdown", description="markdown|text|rst")


class ExtractRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    doc_ingest_id: str = Field(..., description="Design-doc ingest id")


class AutoModelRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    doc_ingest_id: str = Field(..., description="Design-doc ingest id")
    model_name: Optional[str] = Field(
        default=None, description="Override auto-generated model name"
    )
    created_by: str = Field(default="auto-ingest", description="Creator id / username")
    link_cyber_model_id: Optional[str] = Field(
        default=None,
        description="If provided, also write traceability link to this cyber model",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/ingest", response_model=Dict[str, Any])
async def ingest_design_doc(req: IngestRequest) -> Dict[str, Any]:
    try:
        return _get_tme().ingest_design_doc(
            org_id=req.org_id,
            doc_source=req.doc_source,
            doc_content=req.doc_content,
            doc_format=req.doc_format,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        _logger.exception("design_doc.ingest.failed")
        raise HTTPException(status_code=500, detail="design_doc ingest failed")


@router.post("/extract", response_model=Dict[str, Any])
async def extract_stride(req: ExtractRequest) -> Dict[str, Any]:
    try:
        threats = _get_tme().extract_stride_elements(
            org_id=req.org_id, doc_ingest_id=req.doc_ingest_id
        )
        return {
            "org_id": req.org_id,
            "doc_ingest_id": req.doc_ingest_id,
            "threat_count": len(threats),
            "threats": threats,
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception:
        _logger.exception("design_doc.extract.failed")
        raise HTTPException(status_code=500, detail="stride extraction failed")


@router.get("/ingests", response_model=List[Dict[str, Any]])
async def list_ingests(org_id: str = Query(..., description="Org id")) -> List[Dict[str, Any]]:
    try:
        return _get_tme().list_ingested_docs(org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        _logger.exception("design_doc.list.failed")
        raise HTTPException(status_code=500, detail="failed to list ingests")


@router.post("/auto-model", response_model=Dict[str, Any])
async def auto_model(req: AutoModelRequest) -> Dict[str, Any]:
    try:
        result = _get_pipeline().auto_threat_model_from_doc(
            org_id=req.org_id,
            doc_ingest_id=req.doc_ingest_id,
            model_name=req.model_name,
            created_by=req.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception:
        _logger.exception("design_doc.auto_model.failed")
        raise HTTPException(status_code=500, detail="auto-model generation failed")

    if req.link_cyber_model_id:
        try:
            link = _get_cyber().link_design_doc_to_model(
                org_id=req.org_id,
                doc_ingest_id=req.doc_ingest_id,
                model_id=req.link_cyber_model_id,
            )
            result["cyber_link"] = link
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except Exception:
            _logger.exception("design_doc.auto_model.cyber_link.failed")
    return result


@router.get("/stride", response_model=List[Dict[str, Any]])
async def list_stride(
    org_id: str = Query(..., description="Org id"),
    doc_ingest_id: Optional[str] = Query(None, description="Filter by ingest id"),
) -> List[Dict[str, Any]]:
    try:
        return _get_tme().list_extracted_stride_threats(
            org_id=org_id, doc_ingest_id=doc_ingest_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        _logger.exception("design_doc.stride.list.failed")
        raise HTTPException(status_code=500, detail="failed to list STRIDE threats")
