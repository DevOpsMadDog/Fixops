"""Auto-Fix Verification API Router.

Exposes the Find → Fix → Verify loop via REST API.
Enterprise-grade verification that no fix introduces new vulnerabilities.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from core.autofix_verifier import AutoFixVerifier
from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/autofix/verify", tags=["autofix-verification"])

_verifier = AutoFixVerifier(config={"strict_mode": True})


class FixVerifyRequest(BaseModel):
    """Request to verify a proposed auto-fix."""
    original_code: str = Field(..., description="Original vulnerable code", max_length=500_000)
    fixed_code: str = Field(..., description="Proposed fixed code", max_length=500_000)
    language: str = Field(..., description="Programming language (python, javascript, java, go)", max_length=50)
    finding_id: Optional[str] = Field(None, description="ID of the finding being fixed", max_length=256)
    finding_title: Optional[str] = Field(None, description="Title of the finding", max_length=1024)


class BatchFixVerifyRequest(BaseModel):
    """Batch verification request."""
    fixes: list[FixVerifyRequest] = Field(..., max_length=50, description="Up to 50 fixes to verify")


@router.post("")
async def verify_autofix(request: FixVerifyRequest) -> Dict[str, Any]:
    """Verify a proposed auto-fix before applying.
    
    Runs comprehensive checks to ensure the fix:
    - Doesn't introduce new vulnerabilities
    - Has valid syntax
    - Doesn't remove existing security controls
    - Doesn't contain hardcoded secrets
    - Meets compliance requirements
    
    Returns a verification result with pass/fail status,
    risk level, individual check results, and compliance evidence.
    """
    result = _verifier.verify_fix(
        original_code=request.original_code,
        fixed_code=request.fixed_code,
        language=request.language,
        finding_id=request.finding_id or "",
        finding_title=request.finding_title or "",
    )
    
    return {
        "finding_id": result.finding_id,
        "fix_id": result.fix_id,
        "status": result.status.value,
        "risk_level": result.risk_level.value,
        "safe_to_apply": result.safe_to_apply,
        "recommendation": result.recommendation,
        "verification_time_ms": result.verification_time_ms,
        "checks": [
            {
                "name": c.name,
                "status": c.status.value,
                "description": c.description,
                "details": c.details,
                "severity": c.severity,
            }
            for c in result.checks
        ],
        "new_vulnerabilities": result.new_vulnerabilities,
        "compliance_evidence": result.compliance_evidence,
        "timestamp": result.timestamp,
    }


@router.post("/batch")
async def batch_verify_autofixes(request: BatchFixVerifyRequest) -> Dict[str, Any]:
    """Batch verify multiple auto-fixes.
    
    Verifies up to 50 fixes in a single request. Returns individual
    results for each fix plus an aggregate summary.
    """
    results = []
    for fix in request.fixes:
        result = _verifier.verify_fix(
            original_code=fix.original_code,
            fixed_code=fix.fixed_code,
            language=fix.language,
            finding_id=fix.finding_id or "",
            finding_title=fix.finding_title or "",
        )
        results.append({
            "finding_id": result.finding_id,
            "fix_id": result.fix_id,
            "status": result.status.value,
            "risk_level": result.risk_level.value,
            "safe_to_apply": result.safe_to_apply,
            "recommendation": result.recommendation,
            "verification_time_ms": result.verification_time_ms,
            "new_vulnerabilities_count": len(result.new_vulnerabilities),
        })
    
    safe_count = sum(1 for r in results if r["safe_to_apply"])
    
    return {
        "total": len(results),
        "safe": safe_count,
        "rejected": len(results) - safe_count,
        "batch_safe_rate": round(safe_count / max(len(results), 1) * 100, 1),
        "results": results,
    }


@router.get("/stats")
async def get_verification_stats() -> Dict[str, Any]:
    """Get auto-fix verification engine statistics."""
    return {
        "engine": "autofix-verifier",
        "version": "1.0.0",
        **_verifier.get_stats(),
        "supported_languages": ["python", "javascript", "java", "go", "c", "cpp"],
        "verification_checks": [
            "syntax_validation",
            "dangerous_pattern_detection",
            "security_regression_analysis",
            "code_complexity_check",
            "import_safety_check",
            "secrets_detection",
        ],
        "compliance_frameworks": ["NIST 800-53 SI-10", "NIST 800-53 SA-11", "SOC2 CC8.1", "PCI DSS 6.3.2"],
    }
