"""FastAPI application for decision engine endpoints."""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field


_TOKEN_ENV_VARS = (
    "DECISION_ENGINE_API_TOKEN",
    "DECISION_ENGINE_API_TOKENS",
    "FIXOPS_DECISION_ENGINE_TOKEN",
    "FIXOPS_DECISION_ENGINE_TOKENS",
)
_HEADER_ENV = "DECISION_ENGINE_API_HEADER"
_DEFAULT_HEADER = "X-API-Key"


def _load_tokens() -> tuple[str, ...]:
    tokens: list[str] = []
    for env_var in _TOKEN_ENV_VARS:
        raw = os.getenv(env_var)
        if not raw:
            continue
        if "TOKENS" in env_var:
            parts: Iterable[str] = (part.strip() for part in raw.split(","))
        else:
            parts = (raw.strip(),)
        for part in parts:
            if not part:
                continue
            if part.lower().startswith("demo-"):
                raise RuntimeError(
                    "Demo decision engine tokens cannot be used for authenticated endpoints"
                )
            tokens.append(part)

    unique = tuple(dict.fromkeys(tokens))
    if not unique:
        raise RuntimeError(
            "Decision engine API tokens are not configured. Set one of "
            + ", ".join(_TOKEN_ENV_VARS)
        )
    return unique


class DecisionRequest(BaseModel):
    """Input model for requesting a decision from the engine."""

    service_name: str = Field(..., min_length=1, description="Name of the service under review")
    environment: str = Field(..., min_length=1, description="Deployment environment, e.g. production")
    risk_score: float = Field(
        ..., ge=0.0, le=1.0, description="Normalized risk score (0 is safe, 1 is highest risk)"
    )
    metadata: Dict[str, Any] | None = Field(
        default=None,
        description="Optional metadata supplied by the caller",
    )


class FeedbackRequest(BaseModel):
    """Input model for recording feedback on a previously issued decision."""

    decision_id: str = Field(..., min_length=1, description="Identifier returned by the decision endpoint")
    accepted: bool = Field(..., description="Whether the caller accepted the automated decision")
    comments: str | None = Field(
        default=None,
        max_length=1_000,
        description="Optional free-form feedback for auditing or tuning the engine",
    )


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(title="FixOps Decision Engine", version="1.0.0")

    tokens = _load_tokens()
    header_name = (os.getenv(_HEADER_ENV) or _DEFAULT_HEADER).strip() or _DEFAULT_HEADER

    def _require_token(api_key: Optional[str]) -> None:
        if api_key is None or api_key not in tokens:
            raise HTTPException(status_code=401, detail="Invalid or missing API token")

    @app.post(
        "/decisions",
        summary="Issue a decision for a service change",
    )
    def make_decision(
        request: DecisionRequest, api_key: Optional[str] = Header(default=None, alias=header_name)
    ) -> Dict[str, Any]:
        _require_token(api_key)
        """Return a decision based on the provided risk score."""

        if request.risk_score >= 0.85:
            decision = "reject"
        elif request.risk_score >= 0.6:
            decision = "review"
        else:
            decision = "approve"

        decision_payload = {
            "decision": decision,
            "service_name": request.service_name,
            "environment": request.environment,
            "metadata": request.metadata or {},
        }
        decision_payload["decision_id"] = f"{request.service_name}-{request.environment}".lower()

        return decision_payload

    @app.post(
        "/decisions/{decision_id}/feedback",
        summary="Submit feedback for a prior decision",
    )
    def submit_feedback(
        decision_id: str,
        feedback: FeedbackRequest,
        api_key: Optional[str] = Header(default=None, alias=header_name),
    ) -> Dict[str, Any]:
        _require_token(api_key)
        """Record feedback and guard against mismatched identifiers."""

        if decision_id != feedback.decision_id:
            raise HTTPException(status_code=400, detail="Decision identifier mismatch")

        return {
            "status": "received",
            "decision_id": decision_id,
            "accepted": feedback.accepted,
            "comments": feedback.comments,
        }

    @app.get("/health", summary="Simple health probe")
    def healthcheck() -> Dict[str, str]:
        """Return an OK status for monitoring systems."""

        return {"status": "ok"}

    return app


__all__ = ["create_app", "DecisionRequest", "FeedbackRequest"]
