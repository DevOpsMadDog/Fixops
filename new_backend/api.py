"""FastAPI application for the lightweight FixOps backend."""

from __future__ import annotations

from typing import List, Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ConfigDict

SeverityLevel = Literal["low", "medium", "high", "critical"]
EnvironmentName = Literal["dev", "staging", "prod"]
TriggerSource = Literal["commit", "manual", "schedule", "pull_request"]


class ContextModel(BaseModel):
    """Metadata describing the CI/CD request invoking the service."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., min_length=1, description="Unique identifier for the pipeline request")
    pipeline_id: str = Field(..., min_length=1, description="CI/CD pipeline identifier")
    environment: EnvironmentName = Field(..., description="Target deployment environment")
    triggered_by: TriggerSource = Field(..., description="How the pipeline was triggered")


class VulnerabilityModel(BaseModel):
    """Represents a security finding that needs triage."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, description="Identifier of the security rule")
    description: str = Field(..., min_length=1, description="Human readable description of the finding")
    severity: SeverityLevel = Field(..., description="Normalized severity for the finding")
    component: Optional[str] = Field(
        None,
        min_length=1,
        description="Component or package affected by the finding",
    )
    fix_available: bool = Field(
        default=False,
        description="Indicates whether an automated fix is available",
    )


class DecisionModel(BaseModel):
    """Decision returned by the backend after evaluating the request."""

    model_config = ConfigDict(extra="forbid")

    context: ContextModel
    decision: Literal["approve", "reject"] = Field(..., description="Final deployment decision")
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score between 0 (low) and 1 (high)"
    )
    rationale: str = Field(..., min_length=1, description="Summary of how the decision was reached")
    vulnerabilities: List[VulnerabilityModel] = Field(
        default_factory=list, description="Security findings considered in the decision"
    )


class PipelineRequest(BaseModel):
    """Input payload expected by the decision endpoint."""

    model_config = ConfigDict(extra="forbid")

    context: ContextModel
    vulnerabilities: List[VulnerabilityModel] = Field(
        ..., min_length=1, description="Collection of security findings to review"
    )
    change_summary: Optional[str] = Field(
        None,
        description="Short description of the change that triggered the pipeline",
    )


def create_app() -> FastAPI:
    """Create the FastAPI application instance used in tests."""

    app = FastAPI(title="FixOps API", version="1.0.0")

    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        """Lightweight probe used by tests and monitoring."""

        return {"status": "ok"}

    @app.post("/api/v1/pipeline/decision", response_model=DecisionModel)
    async def make_decision(payload: PipelineRequest) -> DecisionModel:
        """Compute a mock deployment decision for the provided pipeline payload."""

        if payload.context.environment == "prod" and not payload.change_summary:
            raise HTTPException(
                status_code=400,
                detail="A change_summary is required when evaluating production deployments.",
            )

        # Highest severity finding determines whether to approve or reject the deployment.
        highest = max(payload.vulnerabilities, key=lambda finding: severity_rank[finding.severity])
        decision = "reject" if severity_rank[highest.severity] >= severity_rank["high"] else "approve"

        rationale = (
            "Blocking vulnerabilities detected." if decision == "reject" else "All findings are informational."
        )

        confidence = 0.25 if decision == "reject" else 0.9

        return DecisionModel(
            context=payload.context,
            decision=decision,
            confidence_score=confidence,
            rationale=rationale,
            vulnerabilities=payload.vulnerabilities,
        )

    return app
