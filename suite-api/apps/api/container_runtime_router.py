"""Container Runtime Security Router — image analysis, policy, drift, CIS Benchmark.

8 endpoints under /api/v1/containers covering:
  - Image analysis without pulling
  - Runtime policy management and evaluation
  - Drift detection for running containers
  - Vulnerability mapping across workloads
  - CIS Docker Benchmark compliance
  - Image signing verification
  - Registry security scanning
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/containers", tags=["Container Runtime Security"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ImageAnalysisRequest(BaseModel):
    """POST /images/analyse — analyse a container image from manifest/config blobs."""
    image_ref: str
    manifest: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None


class PolicyCreateRequest(BaseModel):
    """POST /policies — create a runtime security policy."""
    name: str
    approved_base_images: List[str] = Field(default_factory=list)
    approved_registries: List[str] = Field(default_factory=list)
    required_labels: List[str] = Field(default_factory=list)
    max_image_size_mb: int = 2048
    allow_root_user: bool = False
    require_healthcheck: bool = True
    require_signed_images: bool = False
    allowed_capabilities: List[str] = Field(default_factory=list)
    blocked_capabilities: List[str] = Field(default_factory=list)
    max_layer_count: int = 127


class PolicyEvaluateRequest(BaseModel):
    """POST /policies/evaluate — evaluate image against runtime policies."""
    image_ref: str
    manifest: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    policy_id: Optional[str] = None


class DriftDetectRequest(BaseModel):
    """POST /drift/detect — compare running container against image baseline."""
    container_id: str
    image_ref: str
    manifest: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    runtime_state: Dict[str, Any] = Field(
        default_factory=dict,
        description="Keys: files (Dict[path,sha256]), processes (List[str]), env_vars (List[str]), network_connections (List[str])",
    )


class VulnMapRequest(BaseModel):
    """POST /vulnerabilities/map — map CVEs to running containers."""
    image_ref: str
    cve_list: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Each item: {id, cvss_score, severity}",
    )
    running_containers: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Each item: {container_id, image_ref, pod_name?, namespace?, service?}",
    )


class CISBenchmarkRequest(BaseModel):
    """POST /compliance/cis — run CIS Docker Benchmark checks."""
    target: str = "docker-host"
    config_snapshot: Dict[str, Any] = Field(
        default_factory=dict,
        description="Keys: docker_daemon, container_opts, host_info, image_analysis",
    )
    section_filter: Optional[str] = None


class SignatureVerifyRequest(BaseModel):
    """POST /images/verify-signature — verify image signing."""
    image_ref: str
    signature_data: Optional[Dict[str, Any]] = None
    scheme: str = "cosign"


class RegistryScanRequest(BaseModel):
    """POST /registries/scan — assess registry security posture."""
    registry_url: str
    registry_metadata: Optional[Dict[str, Any]] = None
    images: Optional[List[Dict[str, Any]]] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/")
async def container_runtime_index() -> Dict[str, Any]:
    """Return container runtime security service capabilities + live engine stats."""
    try:
        from core.container_runtime import get_container_runtime_engine
        engine = get_container_runtime_engine()
        policies = engine.policy_engine.list_policies()
        policy_count = len(policies)
        engine_available = True
    except Exception as exc:
        _logger.warning("container_runtime_index: engine unavailable: %s", exc)
        policy_count = 0
        engine_available = False

    return {
        "service": "container-runtime-security",
        "version": "1.0.0",
        "engine_available": engine_available,
        "policies_configured": policy_count,
        "capabilities": [
            "image-analysis",
            "runtime-policy",
            "drift-detection",
            "vuln-mapping",
            "cis-benchmark",
            "image-signing",
            "registry-scan",
        ],
        "endpoints": [
            "POST /images/analyse",
            "POST /policies",
            "GET  /policies",
            "POST /policies/evaluate",
            "POST /drift/detect",
            "POST /vulnerabilities/map",
            "POST /compliance/cis",
            "POST /images/verify-signature",
            "POST /registries/scan",
        ],
        "status": "operational",
    }


@router.post("/images/analyse")
async def analyse_image(req: ImageAnalysisRequest) -> Dict[str, Any]:
    """Analyse a container image without pulling it.

    Inspects layers, detects OS/base image, identifies multi-stage builds,
    squash opportunities, exposed ports, user, healthcheck, and more.
    """
    if not req.image_ref:
        raise HTTPException(status_code=422, detail="image_ref is required")

    from core.container_runtime import get_container_runtime_engine

    engine = get_container_runtime_engine()
    try:
        result = engine.analyse_image(req.image_ref, req.manifest, req.config)
    except Exception as exc:
        _logger.exception("image_analyse_error")
        raise HTTPException(status_code=500, detail=f"Image analysis failed: {exc}") from exc

    return result.to_dict()


@router.post("/policies")
async def create_policy(req: PolicyCreateRequest) -> Dict[str, Any]:
    """Create a runtime security policy.

    Policies define allowed behaviors: approved base images, required labels,
    max image size, root user prohibition, healthcheck requirements, etc.
    """
    from core.container_runtime import RuntimePolicy, get_container_runtime_engine

    engine = get_container_runtime_engine()
    try:
        policy = RuntimePolicy(
            name=req.name,
            approved_base_images=req.approved_base_images,
            approved_registries=req.approved_registries,
            required_labels=req.required_labels,
            max_image_size_mb=req.max_image_size_mb,
            allow_root_user=req.allow_root_user,
            require_healthcheck=req.require_healthcheck,
            require_signed_images=req.require_signed_images,
            allowed_capabilities=req.allowed_capabilities,
            blocked_capabilities=req.blocked_capabilities,
            max_layer_count=req.max_layer_count,
        )
        engine.policy_engine.add_policy(policy)
    except Exception as exc:
        _logger.exception("policy_create_error")
        raise HTTPException(status_code=500, detail=f"Policy creation failed: {exc}") from exc

    return {
        "status": "created",
        "policy": policy.to_dict(),
    }


@router.get("/policies")
async def list_policies() -> Dict[str, Any]:
    """List all configured runtime security policies."""
    from core.container_runtime import get_container_runtime_engine

    engine = get_container_runtime_engine()
    policies = engine.policy_engine.list_policies()
    return {
        "total": len(policies),
        "policies": [p.to_dict() for p in policies],
    }


@router.post("/policies/evaluate")
async def evaluate_policy(req: PolicyEvaluateRequest) -> Dict[str, Any]:
    """Evaluate an image against runtime policies.

    Performs image analysis then checks all (or a specific) policy for
    violations: approved base images, required labels, size limits,
    root user, healthcheck, approved registries.
    """
    if not req.image_ref:
        raise HTTPException(status_code=422, detail="image_ref is required")

    from core.container_runtime import get_container_runtime_engine

    engine = get_container_runtime_engine()
    try:
        analysis = engine.analyse_image(req.image_ref, req.manifest, req.config)
        results = engine.evaluate_policy(req.image_ref, analysis, req.policy_id)
    except Exception as exc:
        _logger.exception("policy_evaluate_error")
        raise HTTPException(status_code=500, detail=f"Policy evaluation failed: {exc}") from exc

    overall_passed = all(r.passed for r in results)
    return {
        "image_ref": req.image_ref,
        "overall_passed": overall_passed,
        "policies_checked": len(results),
        "results": [r.to_dict() for r in results],
    }


@router.post("/drift/detect")
async def detect_drift(req: DriftDetectRequest) -> Dict[str, Any]:
    """Detect runtime drift between a running container and its image baseline.

    Compares modified files, new processes, changed env vars, and unexpected
    network connections. Flags each deviation with severity.
    """
    if not req.container_id:
        raise HTTPException(status_code=422, detail="container_id is required")
    if not req.image_ref:
        raise HTTPException(status_code=422, detail="image_ref is required")

    from core.container_runtime import get_container_runtime_engine

    engine = get_container_runtime_engine()
    try:
        analysis = engine.analyse_image(req.image_ref, req.manifest, req.config)
        report = engine.detect_drift(
            req.container_id, req.image_ref, analysis, req.runtime_state
        )
    except Exception as exc:
        _logger.exception("drift_detect_error")
        raise HTTPException(status_code=500, detail=f"Drift detection failed: {exc}") from exc

    return report.to_dict()


@router.post("/vulnerabilities/map")
async def map_vulnerabilities(req: VulnMapRequest) -> Dict[str, Any]:
    """Map image CVEs to running containers across namespaces and services.

    Given a list of CVEs for an image, identifies which running containers,
    pods, namespaces, and services are affected.
    """
    if not req.image_ref:
        raise HTTPException(status_code=422, detail="image_ref is required")

    from core.container_runtime import get_container_runtime_engine

    engine = get_container_runtime_engine()
    try:
        result = engine.map_vulnerabilities(
            req.image_ref, req.cve_list, req.running_containers
        )
    except Exception as exc:
        _logger.exception("vuln_map_error")
        raise HTTPException(status_code=500, detail=f"Vulnerability mapping failed: {exc}") from exc

    return result.to_dict()


@router.post("/compliance/cis")
async def run_cis_benchmark(req: CISBenchmarkRequest) -> Dict[str, Any]:
    """Run CIS Docker Benchmark checks (80+ checks across 7 sections).

    Sections: host_configuration, docker_daemon, docker_daemon_files,
    container_images, container_runtime, security_operations, docker_swarm.
    Pass section_filter to limit to one section.
    """
    from core.container_runtime import CISBenchmarkSection, get_container_runtime_engine

    section_filter = None
    if req.section_filter:
        try:
            section_filter = CISBenchmarkSection(req.section_filter)
        except ValueError:
            valid = [s.value for s in CISBenchmarkSection]
            raise HTTPException(
                status_code=422,
                detail=f"Invalid section_filter '{req.section_filter}'. Valid: {valid}",
            )

    engine = get_container_runtime_engine()
    try:
        report = engine.run_cis_benchmark(req.target, req.config_snapshot, section_filter)
    except Exception as exc:
        _logger.exception("cis_benchmark_error")
        raise HTTPException(status_code=500, detail=f"CIS Benchmark failed: {exc}") from exc

    return report.to_dict()


@router.post("/images/verify-signature")
async def verify_image_signature(req: SignatureVerifyRequest) -> Dict[str, Any]:
    """Verify container image signature using cosign, Notary v2, or Docker Content Trust.

    Returns verification status, signer identity, signature digest, and policy compliance.
    """
    if not req.image_ref:
        raise HTTPException(status_code=422, detail="image_ref is required")

    from core.container_runtime import SignatureScheme, get_container_runtime_engine

    try:
        scheme = SignatureScheme(req.scheme)
    except ValueError:
        valid = [s.value for s in SignatureScheme]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid scheme '{req.scheme}'. Valid: {valid}",
        )

    engine = get_container_runtime_engine()
    try:
        result = engine.verify_signature(req.image_ref, req.signature_data, scheme)
    except Exception as exc:
        _logger.exception("signature_verify_error")
        raise HTTPException(status_code=500, detail=f"Signature verification failed: {exc}") from exc

    return result.to_dict()


@router.post("/registries/scan")
async def scan_registry(req: RegistryScanRequest) -> Dict[str, Any]:
    """Scan a container registry for security posture issues.

    Checks: public access, tag immutability, vulnerability scanning status,
    stale image detection (>180 days), authentication requirements.
    Returns a risk score (0-100) and list of issues.
    """
    if not req.registry_url:
        raise HTTPException(status_code=422, detail="registry_url is required")

    from core.container_runtime import get_container_runtime_engine

    engine = get_container_runtime_engine()
    try:
        report = engine.scan_registry(req.registry_url, req.registry_metadata, req.images)
    except Exception as exc:
        _logger.exception("registry_scan_error")
        raise HTTPException(status_code=500, detail=f"Registry scan failed: {exc}") from exc

    return report.to_dict()
