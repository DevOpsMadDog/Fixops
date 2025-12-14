"""Lightweight FastAPI application for decision validation tests."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Path
from pydantic import BaseModel, Field, model_validator


class DecisionRequest(BaseModel):
    service_name: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DecisionResponse(BaseModel):
    decision: str
    decision_id: str
    confidence: float


class FeedbackRequest(BaseModel):
    decision_id: str = Field(min_length=1)
    accepted: bool
    comments: str | None = None

    @model_validator(mode="before")
    @classmethod
    def normalize_comments(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        comment = values.get("comments")
        if comment is not None:
            values["comments"] = comment.strip()
        return values


def create_app() -> FastAPI:
    app = FastAPI(title="FixOps Backend API", version="0.1.0")

    @app.post("/decisions", response_model=DecisionResponse)
    def make_decision(request: DecisionRequest) -> DecisionResponse:
        if request.risk_score >= 0.85:
            decision = "block"
        elif request.risk_score >= 0.6:
            decision = "review"
        else:
            decision = "allow"
        decision_id = f"{request.service_name}-{request.environment}"
        return DecisionResponse(
            decision=decision,
            decision_id=decision_id,
            confidence=round(request.risk_score, 3),
        )

    @app.post("/decisions/{decision_id}/feedback")
    def submit_feedback(
        decision_id: str = Path(..., min_length=1),
        request: FeedbackRequest = None,
    ) -> Dict[str, Any]:
        if request is None:
            raise HTTPException(status_code=400, detail="Feedback payload required")
        if request.decision_id != decision_id:
            raise HTTPException(status_code=400, detail="Decision identifier mismatch")
        return {
            "status": "received",
            "decision_id": decision_id,
            "accepted": request.accepted,
            "comments": request.comments,
        }

    @app.get("/health")
    def healthcheck() -> Dict[str, str]:
        return {"status": "ok"}

    return app


__all__ = ["create_app"]
