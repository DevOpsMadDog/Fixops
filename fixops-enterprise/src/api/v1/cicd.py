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

# Import new adapters
try:
    from integrations.gitlab.adapter import GitLabCIAdapter
    from integrations.azure_devops.adapter import AzureDevOpsAdapter
    from integrations.snyk.adapter import SnykAdapter
    from integrations.defectdojo.adapter import DefectDojoAdapter
except ImportError:
    GitLabCIAdapter = None  # type: ignore
    AzureDevOpsAdapter = None  # type: ignore
    SnykAdapter = None  # type: ignore
    DefectDojoAdapter = None  # type: ignore

router = APIRouter(tags=["cicd"])

_github_adapter = GitHubCIAdapter(DECISION_ENGINE)
_jenkins_adapter = JenkinsCIAdapter(DECISION_ENGINE)
_sonarqube_adapter = SonarQubeAdapter(DECISION_ENGINE)
_gitlab_adapter = GitLabCIAdapter(DECISION_ENGINE) if GitLabCIAdapter else None
_azure_devops_adapter = AzureDevOpsAdapter(DECISION_ENGINE) if AzureDevOpsAdapter else None
_snyk_adapter = SnykAdapter(DECISION_ENGINE) if SnykAdapter else None
_defectdojo_adapter = DefectDojoAdapter(DECISION_ENGINE) if DefectDojoAdapter else None


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


@router.post("/gitlab/webhook")
async def gitlab_webhook(
    request: Request, payload=Depends(authenticated_payload)
) -> dict:
    """Handle GitLab merge request and pipeline webhooks."""
    if _gitlab_adapter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitLab integration not available",
        )

    event = request.headers.get("X-Gitlab-Event", "").lower().replace(" ", "_")
    if event not in {"merge_request_hook", "pipeline_hook", "merge_request", "pipeline"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported GitLab event",
        )

    # Normalize event name
    event_type = "merge_request" if "merge_request" in event else "pipeline"

    try:
        result = _gitlab_adapter.handle_webhook(event_type, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {"status": "ok", "data": result}


@router.post("/azure-devops/webhook")
async def azure_devops_webhook(payload=Depends(authenticated_payload)) -> dict:
    """Handle Azure DevOps build and pull request webhooks."""
    if _azure_devops_adapter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Azure DevOps integration not available",
        )

    event_type = payload.get("eventType", "build.complete")

    try:
        result = _azure_devops_adapter.handle_webhook(event_type, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {"status": "ok", "data": result}


@router.post("/snyk/ingest")
async def snyk_ingest(payload=Depends(authenticated_payload)) -> dict:
    """Ingest Snyk vulnerability scan results."""
    if _snyk_adapter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Snyk integration not available",
        )

    result = _snyk_adapter.ingest(payload)
    return {"status": "ok", "data": result}


@router.post("/defectdojo/sync")
async def defectdojo_sync(payload=Depends(authenticated_payload)) -> dict:
    """Sync findings with DefectDojo."""
    if _defectdojo_adapter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DefectDojo integration not available",
        )

    direction = payload.get("direction", "pull")

    if direction == "pull":
        result = await _defectdojo_adapter.pull_findings(
            product_id=payload.get("product_id"),
            engagement_id=payload.get("engagement_id"),
            active_only=payload.get("active_only", True),
        )
    elif direction == "push":
        findings = payload.get("findings", [])
        product_id = payload.get("product_id")
        if not product_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="product_id required for push sync",
            )
        result = await _defectdojo_adapter.push_findings(
            findings=findings,
            product_id=product_id,
            engagement_id=payload.get("engagement_id"),
        )
    else:
        # Ingest findings from DefectDojo format
        result = _defectdojo_adapter.ingest(payload)

    return {"status": "ok", "data": result}


@router.get("/integrations")
async def list_integrations() -> dict:
    """List available CI/CD integrations and their status."""
    return {
        "integrations": [
            {"name": "github", "status": "available", "type": "scm/ci"},
            {"name": "gitlab", "status": "available" if _gitlab_adapter else "unavailable", "type": "scm/ci"},
            {"name": "azure_devops", "status": "available" if _azure_devops_adapter else "unavailable", "type": "ci"},
            {"name": "jenkins", "status": "available", "type": "ci"},
            {"name": "sonarqube", "status": "available", "type": "scanner"},
            {"name": "snyk", "status": "available" if _snyk_adapter else "unavailable", "type": "scanner"},
            {"name": "defectdojo", "status": "available" if _defectdojo_adapter else "unavailable", "type": "vuln_mgmt"},
        ]
    }
