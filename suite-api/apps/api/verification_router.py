"""Verification Router — exposes the multi-stage VerificationEngine.

Endpoints
---------
GET  /api/v1/verification/signatures              List built-in product signatures.
POST /api/v1/verification/run                     Execute the 4-stage pipeline.
GET  /api/v1/verification/health                  Liveness probe.
GET  /api/v1/verification/status                  Status alias.

The engine itself takes an httpx.AsyncClient + a target URL; this router
constructs a temporary client per request so calls are isolated.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

try:
    from apps.api.auth_deps import api_key_auth
except Exception:  # pragma: no cover
    def api_key_auth() -> None:  # type: ignore
        return None

logger = structlog.get_logger(__name__)
_stdlib_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/verification",
    tags=["Multi-Stage Verification"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ProductSignatureModel(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    header_patterns: Dict[str, str] = Field(default_factory=dict)
    body_patterns: List[str] = Field(default_factory=list, max_length=64)
    url_paths: List[str] = Field(default_factory=list, max_length=64)
    cookie_patterns: List[str] = Field(default_factory=list, max_length=32)
    status_code_hints: Dict[str, int] = Field(default_factory=dict)


class VersionRangeModel(BaseModel):
    product: str = Field(..., min_length=1, max_length=256)
    min_version: Optional[str] = Field(default=None, max_length=64)
    max_version: Optional[str] = Field(default=None, max_length=64)
    fixed_version: Optional[str] = Field(default=None, max_length=64)
    version_regex: str = Field(default="", max_length=512)
    extract_from: str = Field(default="header", max_length=16)


class ExploitPayloadModel(BaseModel):
    method: str = Field(default="GET", max_length=16)
    path: str = Field(default="/", max_length=2048)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = Field(default=None, max_length=65536)
    success_indicators: List[str] = Field(default_factory=list, max_length=32)
    failure_indicators: List[str] = Field(default_factory=list, max_length=32)
    timeout_is_success: bool = False


class DifferentialRequestModel(BaseModel):
    method: str = Field(default="GET", max_length=16)
    path: str = Field(default="/", max_length=2048)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = Field(default=None, max_length=65536)


class VerificationRunRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    target_url: str = Field(..., min_length=8, max_length=2048)
    signature: ProductSignatureModel
    version_range: Optional[VersionRangeModel] = None
    exploit_payloads: List[ExploitPayloadModel] = Field(default_factory=list, max_length=16)
    differential_benign: Optional[DifferentialRequestModel] = None
    differential_malicious: Optional[DifferentialRequestModel] = None
    timeout: float = Field(default=15.0, ge=1.0, le=120.0)

    @field_validator("target_url")
    @classmethod
    def _check_url(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/signatures")
def signatures() -> List[Dict[str, Any]]:
    from core.verification_engine import PRODUCT_SIGNATURES

    out = []
    for key, sig in PRODUCT_SIGNATURES.items():
        out.append(
            {
                "id": key,
                "name": sig.name,
                "header_patterns": dict(sig.header_patterns),
                "body_patterns": list(sig.body_patterns),
                "url_paths": list(sig.url_paths),
                "cookie_patterns": list(sig.cookie_patterns),
                "status_code_hints": dict(sig.status_code_hints),
            }
        )
    return out


@router.post("/run")
async def run_pipeline(body: VerificationRunRequest) -> Dict[str, Any]:
    from core.verification_engine import (
        ProductSignature,
        VerificationEngine,
        VersionRange,
    )

    sig = ProductSignature(
        name=body.signature.name,
        header_patterns=body.signature.header_patterns,
        body_patterns=body.signature.body_patterns,
        url_paths=body.signature.url_paths,
        cookie_patterns=body.signature.cookie_patterns,
        status_code_hints=body.signature.status_code_hints,
    )

    try:
        async with httpx.AsyncClient(timeout=body.timeout, follow_redirects=True) as client:
            engine = VerificationEngine(client=client, target_url=body.target_url)
            await engine.run_stage_1_product_detection(sig)

            if body.version_range:
                vr = VersionRange(
                    product=body.version_range.product,
                    min_version=body.version_range.min_version,
                    max_version=body.version_range.max_version,
                    fixed_version=body.version_range.fixed_version,
                    version_regex=body.version_range.version_regex,
                    extract_from=body.version_range.extract_from,
                )
                await engine.run_stage_2_version_fingerprint(vr)

            if body.exploit_payloads:
                payloads = [p.model_dump() for p in body.exploit_payloads]
                await engine.run_stage_3_exploit_verification(payloads)

            if body.differential_benign and body.differential_malicious:
                await engine.run_stage_4_differential_confirmation(
                    benign_request=body.differential_benign.model_dump(),
                    malicious_request=body.differential_malicious.model_dump(),
                )

            result = engine.finalize()
            return {
                "org_id": body.org_id,
                "target_url": body.target_url,
                "vulnerable": result.vulnerable,
                "confidence": result.confidence,
                "verification_chain": result.verification_chain,
                "stages": [
                    {
                        "stage": s.stage.value,
                        "passed": s.passed,
                        "confidence_contribution": s.confidence_contribution,
                        "evidence": s.evidence,
                        "detail": s.detail,
                    }
                    for s in result.stages
                ],
                "evidence": result.evidence,
            }
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"upstream_http_error: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("verification.run_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"run_failure: {exc}")


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "engine": "verification"}


@router.get("/status")
def status() -> Dict[str, Any]:
    from core.verification_engine import (
        MINIMUM_CONFIDENCE_THRESHOLD,
        PRODUCT_SIGNATURES,
    )

    return {
        "status": "ok",
        "engine": "verification",
        "ready": True,
        "signature_count": len(PRODUCT_SIGNATURES),
        "min_confidence": MINIMUM_CONFIDENCE_THRESHOLD,
    }


__all__ = ["router"]
