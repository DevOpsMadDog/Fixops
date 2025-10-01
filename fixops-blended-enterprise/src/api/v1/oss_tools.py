"""
OSS Tools Integration API Endpoints
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
import structlog

from src.services.oss_integrations import OSSIntegrationService

logger = structlog.get_logger()
router = APIRouter(prefix="/oss", tags=["oss-tools"])

# Initialize OSS integration service
oss_service = OSSIntegrationService()

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "image"  # image, filesystem, repository
    
class PolicyEvalRequest(BaseModel):
    policy_name: str
    input_data: Dict[str, Any]

@router.get("/status")
async def get_oss_status():
    """Get status of all OSS tools"""
    try:
        status = oss_service.get_status()
        return {
            "status": "success",
            "tools": status,
            "summary": {
                "total_tools": len(status),
                "available_tools": len([t for t in status.values() if t["available"]]),
                "missing_tools": [name for name, info in status.items() if not info["available"]]
            }
        }
    except Exception as e:
        logger.error(f"Failed to get OSS status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/comprehensive")
async def run_comprehensive_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Run comprehensive security scan using multiple OSS tools"""
    try:
        # Run scan in background for long-running operations
        results = await oss_service.comprehensive_scan(
            target=request.target,
            image_type=(request.scan_type == "image")
        )
        
        return {
            "status": "success",
            "scan_id": f"scan_{request.target.replace(':', '_').replace('/', '_')}",
            "results": results
        }
    except Exception as e:
        logger.error(f"Comprehensive scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/trivy")
async def run_trivy_scan(request: ScanRequest):
    """Run Trivy vulnerability scan"""
    try:
        if oss_service.trivy.version == "not-installed":
            raise HTTPException(status_code=404, detail="Trivy not installed")
            
        results = await oss_service.trivy.scan_image(request.target)
        return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Trivy scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/grype")  
async def run_grype_scan(request: ScanRequest):
    """Run Grype vulnerability scan"""
    try:
        if oss_service.grype.version == "not-installed":
            raise HTTPException(status_code=404, detail="Grype not installed")
            
        results = await oss_service.grype.scan_target(request.target)
        return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Grype scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/verify/sigstore")
async def verify_sigstore_signature(request: ScanRequest, public_key: Optional[str] = None):
    """Verify container signatures using Sigstore"""
    try:
        if oss_service.sigstore.version == "not-installed":
            raise HTTPException(status_code=404, detail="Cosign/Sigstore not installed")
            
        results = await oss_service.sigstore.verify_signature(request.target, public_key)
        return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Sigstore verification failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/policy/evaluate")
async def evaluate_policy(request: PolicyEvalRequest):
    """Evaluate security policy using OPA"""
    try:
        if oss_service.opa.version == "not-installed":
            raise HTTPException(status_code=404, detail="OPA not installed")
            
        results = await oss_service.opa.evaluate_policy(
            policy_name=request.policy_name,
            input_data=request.input_data
        )
        return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Policy evaluation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/policies")
async def list_policies():
    """List available OPA policies"""
    try:
        policies_dir = oss_service.opa.policies_dir
        policies = []
        
        for policy_file in policies_dir.glob("*.rego"):
            policies.append({
                "name": policy_file.stem,
                "file": policy_file.name,
                "path": str(policy_file)
            })
        
        return {
            "status": "success",
            "policies": policies,
            "count": len(policies)
        }
    except Exception as e:
        logger.error(f"Failed to list policies: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/tools")
async def list_supported_tools():
    """List all supported OSS tools and their capabilities"""
    return {
        "status": "success",
        "tools": {
            "trivy": {
                "name": "Trivy",
                "type": "vulnerability_scanner",
                "description": "Container and filesystem vulnerability scanner",
                "capabilities": ["image_scan", "filesystem_scan", "sarif_output"],
                "installation": "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            },
            "grype": {
                "name": "Grype", 
                "type": "vulnerability_scanner",
                "description": "Container and filesystem vulnerability scanner",
                "capabilities": ["image_scan", "filesystem_scan", "sbom_scan"],
                "installation": "https://github.com/anchore/grype#installation"
            },
            "opa": {
                "name": "Open Policy Agent",
                "type": "policy_engine", 
                "description": "General-purpose policy engine",
                "capabilities": ["policy_evaluation", "rego_policies", "decision_engine"],
                "installation": "https://www.openpolicyagent.org/docs/latest/"
            },
            "cosign": {
                "name": "Cosign/Sigstore",
                "type": "supply_chain_security",
                "description": "Container signature verification",
                "capabilities": ["signature_verification", "attestation", "keyless_signing"], 
                "installation": "https://docs.sigstore.dev/cosign/installation/"
            }
        }
    }