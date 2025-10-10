"""CI/CD integration routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from src.api.dependencies import authenticated_payload
from src.services.ci_adapters import GitHubCIAdapter, JenkinsCIAdapter, SonarQubeAdapter
from src.services.runtime import DECISION_ENGINE

router = APIRouter(tags=["cicd"])

_github_adapter = GitHubCIAdapter(DECISION_ENGINE)
_jenkins_adapter = JenkinsCIAdapter(DECISION_ENGINE)
_sonarqube_adapter = SonarQubeAdapter(DECISION_ENGINE)


@router.post("/github/webhook")
async def github_webhook(request: Request, payload=Depends(authenticated_payload)) -> dict:
    event = request.headers.get("X-GitHub-Event", "").lower()
    if event not in {"pull_request", "check_suite"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported GitHub event")
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

