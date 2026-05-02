"""Semantic Analyzer Router — ALDECI (NEW-G070).

Prefix: /api/v1/semantic
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/semantic/detect-languages     detect languages in a root dir
  POST  /api/v1/semantic/parse-repo           parse repo for one language
  GET   /api/v1/semantic/symbols              list symbols (filter by symbol_type)
  POST  /api/v1/semantic/references           find references for an fqn
  POST  /api/v1/semantic/orm-schema           parse an ORM schema (sqla/django/prisma)
  GET   /api/v1/semantic/erd/{repo_ref}       generate ERD from orm models
  GET   /api/v1/semantic/stats                engine stats for org
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/semantic",
    tags=["Semantic Analyzer"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.semantic_analyzer_engine import SemanticAnalyzerEngine
        _engine = SemanticAnalyzerEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DetectLanguagesRequest(BaseModel):
    repo_ref: str
    root_path: str
    org_id: Optional[str] = None


class ParseRepoRequest(BaseModel):
    org_id: str
    repo_ref: str
    root_path: str
    language: str  # python/typescript/java/go


class ReferenceLookupRequest(BaseModel):
    org_id: str
    repo_ref: str
    fqn: str


class OrmParseRequest(BaseModel):
    org_id: str
    repo_ref: str
    root_path: str  # for prisma, this is the schema file path
    orm_framework: str  # sqlalchemy / django_orm / prisma / drizzle


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/detect-languages")
def detect_languages(req: DetectLanguagesRequest) -> Dict[str, Any]:
    eng = _get_engine()
    try:
        out = eng.detect_languages(req.root_path)
    except Exception as exc:
        _logger.exception("detect_languages failed")
        raise HTTPException(status_code=500, detail=str(exc))
    out["repo_ref"] = req.repo_ref
    return out


@router.post("/parse-repo")
def parse_repo(req: ParseRepoRequest) -> Dict[str, Any]:
    eng = _get_engine()
    try:
        return eng.parse_repo(
            org_id=req.org_id,
            repo_ref=req.repo_ref,
            root_path=req.root_path,
            language=req.language,
        )
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("parse_repo failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/symbols")
def list_symbols(
    org_id: str = Query(...),
    repo_ref: str = Query(...),
    symbol_type: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=5000),
) -> Dict[str, Any]:
    eng = _get_engine()
    repo = eng.get_repo(org_id, repo_ref)
    if not repo:
        raise HTTPException(status_code=404, detail="repo not found")
    try:
        symbols = eng.list_symbols(
            repo_id=repo["id"], symbol_type=symbol_type, limit=limit
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "org_id": org_id,
        "repo_ref": repo_ref,
        "symbol_type": symbol_type,
        "count": len(symbols),
        "symbols": symbols,
    }


@router.post("/references")
def find_references(req: ReferenceLookupRequest) -> Dict[str, Any]:
    eng = _get_engine()
    repo = eng.get_repo(req.org_id, req.repo_ref)
    if not repo:
        raise HTTPException(status_code=404, detail="repo not found")
    refs = eng.find_references(repo_id=repo["id"], fqn=req.fqn)
    return {
        "org_id": req.org_id,
        "repo_ref": req.repo_ref,
        "fqn": req.fqn,
        "count": len(refs),
        "references": refs,
    }


@router.post("/orm-schema")
def parse_orm_schema(req: OrmParseRequest) -> Dict[str, Any]:
    eng = _get_engine()
    try:
        return eng.parse_orm(
            org_id=req.org_id,
            repo_ref=req.repo_ref,
            root_path=req.root_path,
            orm_framework=req.orm_framework,
        )
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("parse_orm_schema failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/erd/{repo_ref}")
def get_erd(repo_ref: str, org_id: str = Query(...)) -> Dict[str, Any]:
    eng = _get_engine()
    repo = eng.get_repo(org_id, repo_ref)
    if not repo:
        raise HTTPException(status_code=404, detail="repo not found")
    return eng.generate_erd(repo_id=repo["id"])


@router.get("/stats")
def get_stats(org_id: str = Query(...)) -> Dict[str, Any]:
    eng = _get_engine()
    return eng.stats(org_id=org_id)
