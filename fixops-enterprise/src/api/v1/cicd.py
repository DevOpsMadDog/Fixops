"""CI/CD integration routes."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from src.api.dependencies import authenticated_payload
from src.services.ci_adapters import GitHubCIAdapter, JenkinsCIAdapter, SonarQubeAdapter
from src.services.runtime import DECISION_ENGINE
from src.utils.crypto import rsa_verify

router = APIRouter(tags=["cicd"])

_github_adapter = GitHubCIAdapter(DECISION_ENGINE)
_jenkins_adapter = JenkinsCIAdapter(DECISION_ENGINE)
_sonarqube_adapter = SonarQubeAdapter(DECISION_ENGINE)


class SignatureVerificationRequest(BaseModel):
    """Request body for verifying signed evidence artefacts."""

    evidence_id: str
    payload: Dict[str, Any]
    signature: str
    fingerprint: str


@router.post("/github/webhook")
async def github_webhook(
    request: Request, payload=Depends(authenticated_payload)
) -> dict:
    event = request.headers.get("X-GitHub-Event", "").lower()
    if event not in {"pull_request", "check_suite"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported GitHub event"
        )
    try:
        result = _github_adapter.handle_webhook(event, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {"status": "ok", "data": result}


@router.post("/jenkins/ingest")
async def jenkins_ingest(payload=Depends(authenticated_payload)) -> dict:
    result = _jenkins_adapter.ingest(payload)
    return {"status": "ok", "data": result}


@router.post("/sonarqube/ingest")
async def sonarqube_ingest(payload=Depends(authenticated_payload)) -> dict:
    result = _sonarqube_adapter.ingest(payload)
    return {"status": "ok", "data": result}


@router.post("/verify-signature")
async def verify_signature(
    request: SignatureVerificationRequest,
) -> Dict[str, Any]:
    """Verify signed payloads pushed from CI/CD tooling."""

    try:
        signature_bytes = base64.b64decode(request.signature)
    except Exception as exc:  # pragma: no cover - defensive guardrail
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature encoding",
        ) from exc

    payload_bytes = json.dumps(request.payload, sort_keys=True).encode("utf-8")
    if not rsa_verify(payload_bytes, signature_bytes, request.fingerprint):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Signature verification failed",
        )

    return {
        "status": "success",
        "evidence_id": request.evidence_id,
        "verified": True,
    }
