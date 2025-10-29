"""
FixOps CI/CD Integration API
Optimized endpoints for CI/CD pipeline integration
"""

import base64
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from src.config.settings import get_settings
from src.services.decision_engine import DecisionContext, decision_engine
from src.utils.crypto import rsa_verify

logger = structlog.get_logger()
router = APIRouter(prefix="/cicd", tags=["ci-cd-integration"])


class CICDDecisionRequest(BaseModel):
    """Optimized request format for CI/CD pipelines"""

    service_name: str
    environment: str = "production"
    repository_url: Optional[str] = None
    commit_sha: Optional[str] = None
    branch_name: Optional[str] = None
    pull_request_id: Optional[str] = None

    # Security scan results (from existing tools)
    sarif_results: Optional[Dict[str, Any]] = None
    sbom_data: Optional[Dict[str, Any]] = None
    sca_results: Optional[Dict[str, Any]] = None  # Snyk, etc.
    dast_results: Optional[Dict[str, Any]] = None

    # Business context
    jira_ticket_id: Optional[str] = None
    business_criticality: Optional[str] = None
    compliance_requirements: List[str] = []


class CICDDecisionResponse(BaseModel):
    """Optimized response format for CI/CD pipelines"""

    # Core decision
    decision: str  # ALLOW, BLOCK, DEFER
    confidence_score: float
    exit_code: int  # 0=ALLOW, 1=BLOCK, 2=DEFER

    # CI/CD integration fields
    deployment_approved: bool
    security_gate_passed: bool
    manual_review_required: bool

    # Evidence and audit
    evidence_id: str
    decision_timestamp: str
    processing_time_ms: float

    # Action guidance for CI/CD
    recommended_actions: List[str]
    blocking_issues: List[str]
    compliance_status: Dict[str, str]

    # Notification data
    notification_required: bool
    notification_channels: List[str]
    stakeholders_to_notify: List[str]


class SignatureVerificationRequest(BaseModel):
    """Request body for verifying signed evidence artefacts."""

    evidence_id: str
    payload: Dict[str, Any]
    signature: str
    fingerprint: str


@router.post("/decision", response_model=CICDDecisionResponse)
async def make_cicd_decision(
    request: CICDDecisionRequest,
    x_pipeline_id: Optional[str] = None,
    x_correlation_id: Optional[str] = None,
):
    """
    Make security decision for CI/CD pipeline
    Optimized for bank CI/CD integration with existing security tools
    """
    start_time = time.time()

    try:
        # Prepare security findings from various sources
        security_findings = []

        # Process SARIF results (from SonarQube, CodeQL, etc.)
        if request.sarif_results:
            security_findings.extend(_extract_sarif_findings(request.sarif_results))

        # Process SCA results (from Snyk, etc.)
        if request.sca_results:
            security_findings.extend(_extract_sca_findings(request.sca_results))

        # Process DAST results
        if request.dast_results:
            security_findings.extend(_extract_dast_findings(request.dast_results))

        # Prepare business context
        business_context = {
            "jira_ticket_id": request.jira_ticket_id,
            "business_criticality": request.business_criticality or "medium",
            "compliance_requirements": request.compliance_requirements,
            "repository_url": request.repository_url,
            "commit_sha": request.commit_sha,
            "branch_name": request.branch_name,
            "pull_request_id": request.pull_request_id,
            "pipeline_id": x_pipeline_id,
            "correlation_id": x_correlation_id,
        }

        # Create decision context
        context = DecisionContext(
            service_name=request.service_name,
            environment=request.environment,
            business_context=business_context,
            security_findings=security_findings,
            sbom_data=request.sbom_data,
        )

        # Make decision using decision engine
        decision_result = await decision_engine.make_decision(context)

        # Prepare CI/CD optimized response
        processing_time_ms = (time.time() - start_time) * 1000

        # Determine recommended actions
        recommended_actions = _get_recommended_actions(decision_result)
        blocking_issues = _get_blocking_issues(decision_result, security_findings)
        compliance_status = _get_compliance_status(decision_result)

        # Determine notification requirements
        notification_data = _get_notification_requirements(decision_result, request)

        response = CICDDecisionResponse(
            # Core decision
            decision=decision_result.decision.value,
            confidence_score=decision_result.confidence_score,
            exit_code=0
            if decision_result.decision.value == "ALLOW"
            else 1
            if decision_result.decision.value == "BLOCK"
            else 2,
            # CI/CD integration
            deployment_approved=decision_result.decision.value == "ALLOW",
            security_gate_passed=decision_result.confidence_score >= 0.85,
            manual_review_required=decision_result.decision.value == "DEFER",
            # Evidence and audit
            evidence_id=decision_result.evidence_id,
            decision_timestamp=datetime.now().isoformat(),
            processing_time_ms=processing_time_ms,
            # Action guidance
            recommended_actions=recommended_actions,
            blocking_issues=blocking_issues,
            compliance_status=compliance_status,
            # Notifications
            notification_required=notification_data["required"],
            notification_channels=notification_data["channels"],
            stakeholders_to_notify=notification_data["stakeholders"],
        )

        # Log for audit trail
        logger.info(
            "CI/CD decision made",
            service=request.service_name,
            decision=decision_result.decision.value,
            confidence=decision_result.confidence_score,
            evidence_id=decision_result.evidence_id,
            pipeline_id=x_pipeline_id,
            correlation_id=x_correlation_id,
        )

        return response

    except Exception as e:
        logger.error(f"CI/CD decision failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Decision engine failure",
                "message": str(e),
                "exit_code": 2,
                "recommended_action": "DEFER - Manual review required due to system error",
            },
        )


@router.post("/verify-signature")
async def verify_signature(request: SignatureVerificationRequest) -> Dict[str, Any]:
    """Verify a signed evidence payload using the configured key provider."""

    try:
        signature_bytes = base64.b64decode(request.signature)
    except Exception as exc:  # pragma: no cover - defensive guardrail
        raise HTTPException(
            status_code=400, detail="Invalid signature encoding"
        ) from exc

    payload_bytes = json.dumps(request.payload, sort_keys=True).encode("utf-8")
    if not rsa_verify(payload_bytes, signature_bytes, request.fingerprint):
        raise HTTPException(status_code=400, detail="Signature verification failed")

    return {
        "status": "success",
        "evidence_id": request.evidence_id,
        "verified": True,
    }


def _extract_sarif_findings(sarif_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract security findings from SARIF format"""
    findings = []

    for run in sarif_data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")

        for result in run.get("results", []):
            findings.append(
                {
                    "source": "sarif",
                    "tool": tool_name,
                    "rule_id": result.get("ruleId", "unknown"),
                    "severity": _map_sarif_severity(result.get("level", "note")),
                    "title": result.get("message", {}).get("text", "Unknown issue"),
                    "category": "sast",
                    "file_path": _extract_sarif_location(result),
                }
            )

    return findings


def _extract_sca_findings(sca_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract findings from SCA tools (Snyk, etc.)"""
    findings = []

    # Handle Snyk format
    if "vulnerabilities" in sca_data:
        for vuln in sca_data["vulnerabilities"]:
            findings.append(
                {
                    "source": "sca",
                    "tool": "snyk",
                    "rule_id": vuln.get("id", "unknown"),
                    "severity": vuln.get("severity", "medium").lower(),
                    "title": vuln.get("title", "Dependency vulnerability"),
                    "category": "dependency",
                    "package": vuln.get("packageName", "unknown"),
                }
            )

    return findings


def _extract_dast_findings(dast_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract findings from DAST tools"""
    findings = []

    # Handle common DAST formats
    for alert in dast_data.get("alerts", []):
        findings.append(
            {
                "source": "dast",
                "tool": dast_data.get("tool", "unknown"),
                "rule_id": alert.get("alertRef", "unknown"),
                "severity": _map_dast_severity(alert.get("riskdesc", "Medium")),
                "title": alert.get("alert", "Runtime vulnerability"),
                "category": "runtime",
                "url": alert.get("url", ""),
            }
        )

    return findings


def _map_sarif_severity(level: str) -> str:
    """Map SARIF severity levels"""
    mapping = {"error": "high", "warning": "medium", "note": "low", "info": "info"}
    return mapping.get(level, "medium")


def _map_dast_severity(risk_desc: str) -> str:
    """Map DAST risk levels"""
    if "High" in risk_desc:
        return "high"
    elif "Medium" in risk_desc:
        return "medium"
    elif "Low" in risk_desc:
        return "low"
    else:
        return "medium"


def _extract_sarif_location(result: Dict[str, Any]) -> str:
    """Extract file location from SARIF result"""
    locations = result.get("locations", [])
    if locations:
        physical_location = locations[0].get("physicalLocation", {})
        artifact_location = physical_location.get("artifactLocation", {})
        return artifact_location.get("uri", "unknown")
    return "unknown"


def _get_recommended_actions(decision_result) -> List[str]:
    """Get CI/CD recommended actions based on decision"""
    if decision_result.decision.value == "ALLOW":
        return [
            "Proceed with deployment",
            "Update deployment status in monitoring",
            "Archive security scan results",
        ]
    elif decision_result.decision.value == "BLOCK":
        return [
            "Stop deployment pipeline",
            "Create security incident ticket",
            "Notify development team",
            "Block merge to main branch",
        ]
    else:  # DEFER
        return [
            "Pause deployment pipeline",
            "Request security team review",
            "Assign to security analyst",
            "Set deployment hold status",
        ]


def _get_blocking_issues(decision_result, security_findings: List[Dict]) -> List[str]:
    """Get specific issues that caused blocking"""
    if decision_result.decision.value != "BLOCK":
        return []

    blocking_issues = []

    # Identify critical/high severity issues
    for finding in security_findings:
        if finding.get("severity") in ["critical", "high"]:
            blocking_issues.append(
                f"{finding.get('category', 'security').upper()}: {finding.get('title', 'Unknown issue')}"
            )

    # Add consensus/validation failures
    if decision_result.consensus_details.get("threshold_met") == False:
        blocking_issues.append(
            f"Consensus threshold not met ({decision_result.confidence_score:.1%} < 85%)"
        )

    return blocking_issues


def _get_compliance_status(decision_result) -> Dict[str, str]:
    """Get compliance status for bank requirements"""
    return {
        "pci_dss": "compliant"
        if decision_result.confidence_score >= 0.85
        else "review_required",
        "sox": "compliant"
        if decision_result.decision.value != "BLOCK"
        else "non_compliant",
        "nist_ssdf": "compliant",
        "internal_policies": "compliant"
        if decision_result.confidence_score >= 0.85
        else "review_required",
    }


def _get_notification_requirements(decision_result, request) -> Dict[str, Any]:
    """Determine notification requirements"""
    notification_required = decision_result.decision.value in ["BLOCK", "DEFER"]

    stakeholders = ["engineering"]
    channels = ["pipeline"]

    if decision_result.decision.value == "BLOCK":
        stakeholders.extend(["security", "compliance"])
        channels.extend(["email", "slack", "jira"])

    if request.business_criticality == "critical":
        stakeholders.extend(["management", "risk"])

    return {
        "required": notification_required,
        "channels": channels,
        "stakeholders": stakeholders,
    }
