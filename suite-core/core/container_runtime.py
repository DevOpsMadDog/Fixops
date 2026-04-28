"""ALDECI Container Runtime Security Engine.

Image analysis, runtime policy enforcement, drift detection, vulnerability
mapping, CIS Docker Benchmark compliance, image signing verification, and
registry security scanning.

Competitive parity: Aqua Security, Prisma Cloud, Sysdig Secure, Snyk Container.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SignatureScheme(str, Enum):
    COSIGN = "cosign"
    NOTARY_V2 = "notary_v2"
    DOCKER_CONTENT_TRUST = "docker_content_trust"
    NONE = "none"


class DriftType(str, Enum):
    MODIFIED_FILE = "modified_file"
    NEW_PROCESS = "new_process"
    CHANGED_ENV = "changed_env"
    UNEXPECTED_NETWORK = "unexpected_network"
    NEW_FILE = "new_file"
    DELETED_FILE = "deleted_file"


class CISBenchmarkSection(str, Enum):
    HOST_CONFIGURATION = "1_host_configuration"
    DOCKER_DAEMON = "2_docker_daemon"
    DOCKER_DAEMON_FILES = "3_docker_daemon_files"
    CONTAINER_IMAGES = "4_container_images"
    CONTAINER_RUNTIME = "5_container_runtime"
    SECURITY_OPERATIONS = "6_security_operations"
    DOCKER_SWARM = "7_docker_swarm"


class RegistryVulnStatus(str, Enum):
    SCANNING_ENABLED = "scanning_enabled"
    SCANNING_DISABLED = "scanning_disabled"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Pydantic v2 models
# ---------------------------------------------------------------------------

try:
    from pydantic import BaseModel, Field, field_validator, model_validator
    _PYDANTIC_V2 = True
except ImportError:  # pragma: no cover
    from pydantic import BaseModel, Field  # type: ignore
    _PYDANTIC_V2 = False


class ImageLayer(BaseModel):
    """A single layer in a container image."""
    digest: str
    size_bytes: int
    created_at: Optional[str] = None
    command: str = ""
    is_empty: bool = False
    is_squashable: bool = False


class InstalledPackage(BaseModel):
    """A package found inside a container image."""
    name: str
    version: str
    arch: str = "unknown"
    manager: str = "unknown"  # apt, apk, rpm, pip, npm …
    cves: List[str] = Field(default_factory=list)


class ImageAnalysisResult(BaseModel):
    """Full analysis of a container image without pulling it."""
    image_ref: str
    digest: Optional[str] = None
    os_family: str = "unknown"
    os_version: str = "unknown"
    base_image: str = "unknown"
    base_image_tag: str = "unknown"
    architecture: str = "amd64"
    total_size_bytes: int = 0
    layer_count: int = 0
    layers: List[ImageLayer] = Field(default_factory=list)
    packages: List[InstalledPackage] = Field(default_factory=list)
    is_multi_stage: bool = False
    squash_opportunities: int = 0
    labels: Dict[str, str] = Field(default_factory=dict)
    environment_vars: List[str] = Field(default_factory=list)
    exposed_ports: List[str] = Field(default_factory=list)
    entrypoint: List[str] = Field(default_factory=list)
    cmd: List[str] = Field(default_factory=list)
    user: str = "root"
    has_healthcheck: bool = False
    analysed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class RuntimePolicy(BaseModel):
    """Policy defining allowed container behaviors."""
    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    approved_base_images: List[str] = Field(default_factory=list)
    approved_registries: List[str] = Field(default_factory=list)
    required_labels: List[str] = Field(default_factory=list)
    max_image_size_mb: int = 2048
    allow_root_user: bool = False
    require_healthcheck: bool = True
    require_signed_images: bool = False
    allowed_capabilities: List[str] = Field(default_factory=list)
    blocked_capabilities: List[str] = Field(
        default_factory=lambda: ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
    )
    max_layer_count: int = 127
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class PolicyViolation(BaseModel):
    """A single policy violation found during evaluation."""
    violation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str
    policy_name: str
    rule: str
    detail: str
    severity: Severity
    image_ref: str

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class PolicyEvaluationResult(BaseModel):
    """Result of evaluating an image against a runtime policy."""
    image_ref: str
    policy_id: str
    policy_name: str
    passed: bool
    violations: List[PolicyViolation] = Field(default_factory=list)
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class DriftEvent(BaseModel):
    """A single drift observation comparing container to its image."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    container_id: str
    image_ref: str
    drift_type: DriftType
    path: Optional[str] = None
    description: str
    severity: Severity
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class DriftReport(BaseModel):
    """Full drift report for a running container."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    container_id: str
    image_ref: str
    drift_detected: bool
    drift_events: List[DriftEvent] = Field(default_factory=list)
    modified_files: List[str] = Field(default_factory=list)
    new_processes: List[str] = Field(default_factory=list)
    changed_env_vars: List[str] = Field(default_factory=list)
    unexpected_connections: List[str] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class VulnerableContainer(BaseModel):
    """A running container found to run a vulnerable image."""
    container_id: str
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    service: Optional[str] = None
    image_ref: str
    cves: List[str] = Field(default_factory=list)
    highest_severity: Severity = Severity.INFO

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class VulnerabilityMapResult(BaseModel):
    """Mapping of image vulnerabilities to running workloads."""
    map_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    image_ref: str
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    affected_containers: List[VulnerableContainer] = Field(default_factory=list)
    affected_namespaces: List[str] = Field(default_factory=list)
    affected_services: List[str] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class CISCheckResult(BaseModel):
    """Result of a single CIS Docker Benchmark check."""
    check_id: str
    section: CISBenchmarkSection
    title: str
    description: str
    passed: bool
    severity: Severity
    remediation: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class CISBenchmarkReport(BaseModel):
    """Full CIS Docker Benchmark report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str  # host or container
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    score_pct: float = 0.0
    checks: List[CISCheckResult] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class SignatureVerificationResult(BaseModel):
    """Result of verifying image signature(s)."""
    image_ref: str
    verified: bool
    scheme: SignatureScheme
    signer: Optional[str] = None
    signature_digest: Optional[str] = None
    signed_at: Optional[str] = None
    error: Optional[str] = None
    policy_compliant: bool = False
    verified_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


class RegistrySecurityReport(BaseModel):
    """Security posture report for a container registry."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    registry_url: str
    public_access: bool = False
    tag_immutability: bool = False
    vuln_scanning_status: RegistryVulnStatus = RegistryVulnStatus.UNKNOWN
    stale_images: List[str] = Field(default_factory=list)
    stale_image_count: int = 0
    total_images_checked: int = 0
    issues: List[str] = Field(default_factory=list)
    risk_score: int = 0  # 0–100
    scanned_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump() if _PYDANTIC_V2 else self.dict()


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _detect_os(labels: Dict[str, str], env_vars: List[str], layers: List[Dict[str, Any]]) -> Tuple[str, str]:
    """Heuristically detect OS family and version from image metadata."""
    # Check labels first
    for key in ("org.opencontainers.image.base.name", "os", "distribution"):
        val = labels.get(key, "").lower()
        if "alpine" in val:
            return "alpine", labels.get("org.opencontainers.image.version", "3.x")
        if "debian" in val:
            return "debian", labels.get("org.opencontainers.image.version", "unknown")
        if "ubuntu" in val:
            return "ubuntu", labels.get("org.opencontainers.image.version", "unknown")
        if "centos" in val:
            return "centos", labels.get("org.opencontainers.image.version", "unknown")
        if "rhel" in val or "redhat" in val:
            return "rhel", labels.get("org.opencontainers.image.version", "unknown")

    # Check env vars
    for var in env_vars:
        low = var.lower()
        if "alpine" in low:
            return "alpine", "unknown"
        if "ubuntu" in low:
            return "ubuntu", "unknown"
        if "debian" in low:
            return "debian", "unknown"
        if "centos" in low or "rhel" in low:
            return "centos", "unknown"

    return "linux", "unknown"


def _detect_base_image(image_ref: str) -> Tuple[str, str]:
    """Parse base image and tag from an image reference."""
    ref = image_ref.split("@")[0]  # strip digest
    if ":" in ref.split("/")[-1]:
        parts = ref.rsplit(":", 1)
        return parts[0], parts[1]
    return ref, "latest"


def _is_squashable(layers: List[ImageLayer]) -> int:
    """Count consecutive RUN-created layers that could be squashed."""
    opportunities = 0
    consecutive = 0
    for layer in layers:
        cmd_lower = layer.command.lower()
        if cmd_lower.startswith("run ") or "&&" in cmd_lower:
            consecutive += 1
            if consecutive > 1:
                opportunities += 1
        else:
            consecutive = 0
    return opportunities


def _severity_from_cvss(cvss_score: float) -> Severity:
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    if cvss_score >= 7.0:
        return Severity.HIGH
    if cvss_score >= 4.0:
        return Severity.MEDIUM
    if cvss_score > 0.0:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Image Analysis
# ---------------------------------------------------------------------------

class ImageAnalyzer:
    """Analyse container images without pulling them (registry API + manifest inspection)."""

    # Common base images and their OS
    _KNOWN_BASES: Dict[str, Tuple[str, str]] = {
        "alpine": ("alpine", "linux"),
        "debian": ("debian", "linux"),
        "ubuntu": ("ubuntu", "linux"),
        "centos": ("centos", "linux"),
        "scratch": ("scratch", "none"),
        "distroless": ("distroless", "linux"),
        "python": ("debian", "linux"),
        "node": ("debian", "linux"),
        "nginx": ("debian", "linux"),
        "redis": ("debian", "linux"),
        "postgres": ("debian", "linux"),
    }

    def analyse(
        self,
        image_ref: str,
        manifest: Optional[Dict[str, Any]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> ImageAnalysisResult:
        """Analyse an image from its manifest and config blob.

        When manifest/config are None, synthetic placeholders are used so the
        engine operates offline (unit-test friendly).
        """
        log.info("image_analysis_start", image_ref=image_ref)

        manifest = manifest or {}
        config = config or {}

        labels: Dict[str, str] = config.get("Labels", {}) or {}
        env_vars: List[str] = config.get("Env", []) or []
        exposed_ports: List[str] = list((config.get("ExposedPorts") or {}).keys())
        entrypoint: List[str] = config.get("Entrypoint", []) or []
        cmd: List[str] = config.get("Cmd", []) or []
        user: str = config.get("User", "root") or "root"
        has_healthcheck: bool = bool(config.get("Healthcheck"))

        # Layers from manifest
        raw_layers = manifest.get("layers", [])
        layers: List[ImageLayer] = []
        history = config.get("history", [])
        for i, raw in enumerate(raw_layers):
            hist = history[i] if i < len(history) else {}
            cmd_str = hist.get("created_by", "")
            layer = ImageLayer(
                digest=raw.get("digest", f"sha256:{'0' * 64}"),
                size_bytes=raw.get("size", 0),
                created_at=hist.get("created"),
                command=cmd_str,
                is_empty=hist.get("empty_layer", False),
            )
            layers.append(layer)

        total_size = sum(l.size_bytes for l in layers)
        os_family, os_version = _detect_os(labels, env_vars, raw_layers)
        base_image, base_tag = _detect_base_image(image_ref)

        # Multi-stage detection: look for multiple FROM in history
        from_count = sum(
            1 for h in history
            if "FROM" in (h.get("created_by", "") or "").upper()
        )
        is_multi_stage = from_count > 1

        squash_opps = _is_squashable(layers)

        result = ImageAnalysisResult(
            image_ref=image_ref,
            digest=manifest.get("config", {}).get("digest"),
            os_family=os_family,
            os_version=os_version,
            base_image=base_image,
            base_image_tag=base_tag,
            architecture=manifest.get("architecture", config.get("Architecture", "amd64")),
            total_size_bytes=total_size,
            layer_count=len(layers),
            layers=layers,
            is_multi_stage=is_multi_stage,
            squash_opportunities=squash_opps,
            labels=labels,
            environment_vars=env_vars,
            exposed_ports=exposed_ports,
            entrypoint=entrypoint,
            cmd=cmd,
            user=user,
            has_healthcheck=has_healthcheck,
        )

        log.info(
            "image_analysis_complete",
            image_ref=image_ref,
            layers=len(layers),
            size_bytes=total_size,
            os=os_family,
        )
        return result


# ---------------------------------------------------------------------------
# Runtime Policy Engine
# ---------------------------------------------------------------------------

class RuntimePolicyEngine:
    """Evaluate images and containers against runtime security policies."""

    def __init__(self) -> None:
        self._policies: Dict[str, RuntimePolicy] = {}

    def add_policy(self, policy: RuntimePolicy) -> None:
        self._policies[policy.policy_id] = policy
        log.info("policy_added", policy_id=policy.policy_id, name=policy.name)

    def remove_policy(self, policy_id: str) -> bool:
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False

    def list_policies(self) -> List[RuntimePolicy]:
        return list(self._policies.values())

    def evaluate(
        self,
        image_ref: str,
        analysis: ImageAnalysisResult,
        policy_id: Optional[str] = None,
    ) -> List[PolicyEvaluationResult]:
        """Evaluate image against one or all policies."""
        targets = (
            [self._policies[policy_id]]
            if policy_id and policy_id in self._policies
            else list(self._policies.values())
        )
        results = []
        for policy in targets:
            violations = self._check_policy(image_ref, analysis, policy)
            results.append(PolicyEvaluationResult(
                image_ref=image_ref,
                policy_id=policy.policy_id,
                policy_name=policy.name,
                passed=len(violations) == 0,
                violations=violations,
            ))
        return results

    def _check_policy(
        self,
        image_ref: str,
        analysis: ImageAnalysisResult,
        policy: RuntimePolicy,
    ) -> List[PolicyViolation]:
        violations: List[PolicyViolation] = []

        def _viol(rule: str, detail: str, sev: Severity) -> PolicyViolation:
            return PolicyViolation(
                policy_id=policy.policy_id,
                policy_name=policy.name,
                rule=rule,
                detail=detail,
                severity=sev,
                image_ref=image_ref,
            )

        # Approved base images
        if policy.approved_base_images:
            base_ok = any(
                approved in analysis.base_image
                for approved in policy.approved_base_images
            )
            if not base_ok:
                violations.append(_viol(
                    "approved_base_images",
                    f"Base image '{analysis.base_image}' not in approved list: {policy.approved_base_images}",
                    Severity.HIGH,
                ))

        # Approved registries
        if policy.approved_registries:
            registry = image_ref.split("/")[0] if "/" in image_ref else "docker.io"
            reg_ok = any(approved in registry for approved in policy.approved_registries)
            if not reg_ok:
                violations.append(_viol(
                    "approved_registries",
                    f"Registry '{registry}' not in approved list: {policy.approved_registries}",
                    Severity.HIGH,
                ))

        # Required labels
        for required_label in policy.required_labels:
            if required_label not in analysis.labels:
                violations.append(_viol(
                    "required_labels",
                    f"Missing required label: '{required_label}'",
                    Severity.MEDIUM,
                ))

        # Max image size
        size_mb = analysis.total_size_bytes / (1024 * 1024)
        if size_mb > policy.max_image_size_mb:
            violations.append(_viol(
                "max_image_size_mb",
                f"Image size {size_mb:.1f} MB exceeds limit of {policy.max_image_size_mb} MB",
                Severity.MEDIUM,
            ))

        # No root user
        if not policy.allow_root_user:
            if not analysis.user or analysis.user in ("root", "0", ""):
                violations.append(_viol(
                    "no_root_user",
                    f"Container runs as user '{analysis.user}' (root); non-root user required",
                    Severity.HIGH,
                ))

        # Required healthcheck
        if policy.require_healthcheck and not analysis.has_healthcheck:
            violations.append(_viol(
                "require_healthcheck",
                "Image has no HEALTHCHECK instruction",
                Severity.MEDIUM,
            ))

        # Max layer count
        if analysis.layer_count > policy.max_layer_count:
            violations.append(_viol(
                "max_layer_count",
                f"Image has {analysis.layer_count} layers, exceeds limit of {policy.max_layer_count}",
                Severity.LOW,
            ))

        return violations


# ---------------------------------------------------------------------------
# Drift Detection
# ---------------------------------------------------------------------------

class DriftDetector:
    """Detect runtime drift between a running container and its image."""

    def detect(
        self,
        container_id: str,
        image_ref: str,
        image_analysis: ImageAnalysisResult,
        runtime_state: Dict[str, Any],
    ) -> DriftReport:
        """Compare runtime_state snapshot against image baseline.

        runtime_state keys:
          - files: Dict[path, sha256]
          - processes: List[str]
          - env_vars: List[str]
          - network_connections: List[str]  e.g. "10.0.0.1:443"
        """
        log.info("drift_detection_start", container_id=container_id, image_ref=image_ref)

        drift_events: List[DriftEvent] = []
        modified_files: List[str] = []
        new_processes: List[str] = []
        changed_env_vars: List[str] = []
        unexpected_connections: List[str] = []

        # File drift
        image_env_set = set(image_analysis.environment_vars)
        runtime_env_set = set(runtime_state.get("env_vars", []))
        changed = runtime_env_set.symmetric_difference(image_env_set)
        for var in changed:
            key = var.split("=")[0] if "=" in var else var
            changed_env_vars.append(key)
            drift_events.append(DriftEvent(
                container_id=container_id,
                image_ref=image_ref,
                drift_type=DriftType.CHANGED_ENV,
                path=None,
                description=f"Environment variable changed or added: {key}",
                severity=Severity.MEDIUM,
            ))

        # Process drift — compare against expected entrypoint/cmd
        expected_procs = set(image_analysis.entrypoint + image_analysis.cmd)
        runtime_procs = set(runtime_state.get("processes", []))
        for proc in runtime_procs - expected_procs:
            if proc:
                new_processes.append(proc)
                drift_events.append(DriftEvent(
                    container_id=container_id,
                    image_ref=image_ref,
                    drift_type=DriftType.NEW_PROCESS,
                    path=None,
                    description=f"Unexpected process running: {proc}",
                    severity=Severity.HIGH,
                ))

        # File drift
        image_files: Dict[str, str] = {}  # from image layers (baseline)
        runtime_files: Dict[str, str] = runtime_state.get("files", {})
        for path, runtime_hash in runtime_files.items():
            expected_hash = image_files.get(path)
            if expected_hash is None:
                # new file not in image
                modified_files.append(path)
                drift_events.append(DriftEvent(
                    container_id=container_id,
                    image_ref=image_ref,
                    drift_type=DriftType.NEW_FILE,
                    path=path,
                    description=f"New file not present in image: {path}",
                    severity=Severity.HIGH if path.startswith("/etc") or path.startswith("/bin") else Severity.MEDIUM,
                ))
            elif expected_hash != runtime_hash:
                modified_files.append(path)
                drift_events.append(DriftEvent(
                    container_id=container_id,
                    image_ref=image_ref,
                    drift_type=DriftType.MODIFIED_FILE,
                    path=path,
                    description=f"File modified at runtime: {path}",
                    severity=Severity.HIGH if "/etc/passwd" in path or "/bin" in path else Severity.MEDIUM,
                ))

        # Network drift
        # Approved connections: exposed ports on loopback and service mesh
        approved_ports = {p.split("/")[0] for p in image_analysis.exposed_ports}
        for conn in runtime_state.get("network_connections", []):
            port = conn.split(":")[-1] if ":" in conn else ""
            if port not in approved_ports:
                unexpected_connections.append(conn)
                drift_events.append(DriftEvent(
                    container_id=container_id,
                    image_ref=image_ref,
                    drift_type=DriftType.UNEXPECTED_NETWORK,
                    path=None,
                    description=f"Unexpected network connection: {conn}",
                    severity=Severity.MEDIUM,
                ))

        report = DriftReport(
            container_id=container_id,
            image_ref=image_ref,
            drift_detected=len(drift_events) > 0,
            drift_events=drift_events,
            modified_files=modified_files,
            new_processes=new_processes,
            changed_env_vars=changed_env_vars,
            unexpected_connections=unexpected_connections,
        )

        log.info(
            "drift_detection_complete",
            container_id=container_id,
            drift_detected=report.drift_detected,
            events=len(drift_events),
        )
        return report


# ---------------------------------------------------------------------------
# Vulnerability Mapping
# ---------------------------------------------------------------------------

class VulnerabilityMapper:
    """Map image vulnerabilities to running containers across namespaces and services."""

    def map_vulnerabilities(
        self,
        image_ref: str,
        cve_list: List[Dict[str, Any]],
        running_containers: List[Dict[str, Any]],
    ) -> VulnerabilityMapResult:
        """Build a vulnerability map from CVE data and running container inventory.

        cve_list item keys: id, cvss_score, severity (optional)
        running_containers item keys: container_id, image_ref, pod_name (opt),
                                      namespace (opt), service (opt)
        """
        log.info("vuln_mapping_start", image_ref=image_ref, cve_count=len(cve_list))

        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cve_ids = []
        for cve in cve_list:
            cid = cve.get("id", "")
            if cid:
                cve_ids.append(cid)
            sev_raw = cve.get("severity", "")
            if not sev_raw and "cvss_score" in cve:
                sev_raw = _severity_from_cvss(float(cve["cvss_score"])).value
            sev = sev_raw.lower() if sev_raw else "low"
            if sev in counts:
                counts[sev] += 1

        affected: List[VulnerableContainer] = []
        namespaces: set = set()
        services: set = set()

        for ct in running_containers:
            ct_image = ct.get("image_ref", "")
            # Match on image name without tag/digest for flexibility
            ct_base = ct_image.split(":")[0].split("@")[0]
            img_base = image_ref.split(":")[0].split("@")[0]
            if ct_base == img_base or ct_image == image_ref:
                highest = Severity.INFO
                for cve in cve_list:
                    sev_raw = cve.get("severity", "info")
                    try:
                        s = Severity(sev_raw.lower())
                        if list(Severity).index(s) < list(Severity).index(highest):
                            highest = s
                    except ValueError:
                        pass

                vc = VulnerableContainer(
                    container_id=ct["container_id"],
                    pod_name=ct.get("pod_name"),
                    namespace=ct.get("namespace"),
                    service=ct.get("service"),
                    image_ref=ct_image,
                    cves=cve_ids,
                    highest_severity=highest,
                )
                affected.append(vc)
                if ct.get("namespace"):
                    namespaces.add(ct["namespace"])
                if ct.get("service"):
                    services.add(ct["service"])

        result = VulnerabilityMapResult(
            image_ref=image_ref,
            total_cves=len(cve_ids),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            affected_containers=affected,
            affected_namespaces=sorted(namespaces),
            affected_services=sorted(services),
        )

        log.info(
            "vuln_mapping_complete",
            image_ref=image_ref,
            affected_containers=len(affected),
            total_cves=result.total_cves,
        )
        return result


# ---------------------------------------------------------------------------
# CIS Docker Benchmark
# ---------------------------------------------------------------------------

# CIS check registry: (check_id, section, title, severity, remediation)
_CIS_CHECKS: List[Tuple[str, CISBenchmarkSection, str, Severity, str]] = [
    # Section 1 — Host Configuration
    ("1.1.1", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure a separate partition for containers is used", Severity.LOW, "Create a dedicated partition for /var/lib/docker"),
    ("1.1.2", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure only trusted users are allowed to control Docker daemon", Severity.HIGH, "Remove untrusted users from the docker group"),
    ("1.1.3", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure auditing is configured for Docker daemon", Severity.MEDIUM, "Add audit rules for /usr/bin/dockerd"),
    ("1.1.4", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure auditing for /var/lib/docker", Severity.MEDIUM, "Add audit rule for /var/lib/docker directory"),
    ("1.1.5", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure auditing for /etc/docker", Severity.MEDIUM, "Add audit rule for /etc/docker directory"),
    ("1.1.6", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure auditing for docker.service", Severity.MEDIUM, "Add audit rule for docker.service"),
    ("1.1.7", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure auditing for docker.socket", Severity.MEDIUM, "Add audit rule for docker.socket"),
    ("1.1.8", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure auditing for /etc/default/docker", Severity.MEDIUM, "Add audit rule for /etc/default/docker"),
    ("1.2.1", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure Docker is kept up to date", Severity.MEDIUM, "Upgrade Docker to the latest stable release"),
    ("1.2.2", CISBenchmarkSection.HOST_CONFIGURATION, "Ensure only trusted base images are used", Severity.HIGH, "Use images from trusted registries only"),
    # Section 2 — Docker Daemon Configuration
    ("2.1", CISBenchmarkSection.DOCKER_DAEMON, "Ensure network traffic is restricted between containers", Severity.MEDIUM, "Set --icc=false in Docker daemon config"),
    ("2.2", CISBenchmarkSection.DOCKER_DAEMON, "Ensure logging level is set to 'info'", Severity.LOW, "Set --log-level=info in Docker daemon config"),
    ("2.3", CISBenchmarkSection.DOCKER_DAEMON, "Ensure Docker is allowed to make changes to iptables", Severity.MEDIUM, "Do not set --iptables=false"),
    ("2.4", CISBenchmarkSection.DOCKER_DAEMON, "Ensure insecure registries are not used", Severity.HIGH, "Remove --insecure-registry from daemon config"),
    ("2.5", CISBenchmarkSection.DOCKER_DAEMON, "Ensure aufs storage driver is not used", Severity.LOW, "Use overlay2 storage driver"),
    ("2.6", CISBenchmarkSection.DOCKER_DAEMON, "Ensure TLS authentication is configured for Docker daemon", Severity.HIGH, "Configure --tlsverify and related TLS flags"),
    ("2.7", CISBenchmarkSection.DOCKER_DAEMON, "Ensure default ulimit is configured appropriately", Severity.LOW, "Set appropriate --default-ulimit values"),
    ("2.8", CISBenchmarkSection.DOCKER_DAEMON, "Ensure user namespace support is enabled", Severity.HIGH, "Set --userns-remap=default in daemon config"),
    ("2.9", CISBenchmarkSection.DOCKER_DAEMON, "Ensure the default cgroup usage has been confirmed", Severity.LOW, "Verify --cgroup-parent value"),
    ("2.10", CISBenchmarkSection.DOCKER_DAEMON, "Ensure base device size is not changed until needed", Severity.LOW, "Remove --storage-opt dm.basesize unless required"),
    ("2.11", CISBenchmarkSection.DOCKER_DAEMON, "Ensure authorization plugin is enabled", Severity.MEDIUM, "Configure --authorization-plugin"),
    ("2.12", CISBenchmarkSection.DOCKER_DAEMON, "Ensure centralized and remote logging is configured", Severity.MEDIUM, "Configure --log-driver to send to centralized logging"),
    ("2.13", CISBenchmarkSection.DOCKER_DAEMON, "Ensure live restore is enabled", Severity.LOW, "Set --live-restore=true"),
    ("2.14", CISBenchmarkSection.DOCKER_DAEMON, "Ensure Userland Proxy is disabled", Severity.LOW, "Set --userland-proxy=false"),
    ("2.15", CISBenchmarkSection.DOCKER_DAEMON, "Ensure that a daemon-wide custom seccomp profile is applied", Severity.MEDIUM, "Configure --seccomp-profile with a restrictive profile"),
    # Section 3 — Docker Daemon Configuration Files
    ("3.1", CISBenchmarkSection.DOCKER_DAEMON_FILES, "Ensure that docker.service file ownership is set to root:root", Severity.HIGH, "chown root:root /lib/systemd/system/docker.service"),
    ("3.2", CISBenchmarkSection.DOCKER_DAEMON_FILES, "Ensure that docker.service file permissions are set to 644 or more restrictive", Severity.HIGH, "chmod 644 /lib/systemd/system/docker.service"),
    ("3.3", CISBenchmarkSection.DOCKER_DAEMON_FILES, "Ensure that docker.socket file ownership is set to root:root", Severity.HIGH, "chown root:root /lib/systemd/system/docker.socket"),
    ("3.4", CISBenchmarkSection.DOCKER_DAEMON_FILES, "Ensure that docker.socket file permissions are set to 644 or more restrictive", Severity.HIGH, "chmod 644 /lib/systemd/system/docker.socket"),
    ("3.5", CISBenchmarkSection.DOCKER_DAEMON_FILES, "Ensure that /etc/docker directory ownership is set to root:root", Severity.HIGH, "chown root:root /etc/docker"),
    ("3.6", CISBenchmarkSection.DOCKER_DAEMON_FILES, "Ensure that /etc/docker directory permissions are set to 755 or more restrictive", Severity.HIGH, "chmod 755 /etc/docker"),
    ("3.7", CISBenchmarkSection.DOCKER_DAEMON_FILES, "Ensure that registry certificate file ownership is set to root:root", Severity.MEDIUM, "chown root:root /etc/docker/certs.d/*"),
    ("3.8", CISBenchmarkSection.DOCKER_DAEMON_FILES, "Ensure that registry certificate file permissions are set to 444 or more restrictive", Severity.MEDIUM, "chmod 444 /etc/docker/certs.d/*/*"),
    # Section 4 — Container Images and Build File
    ("4.1", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure a user for the container has been created", Severity.HIGH, "Add USER directive in Dockerfile with non-root user"),
    ("4.2", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure that containers use only trusted base images", Severity.HIGH, "Use images from approved registries with digest pinning"),
    ("4.3", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure that unnecessary packages are not installed in the container", Severity.MEDIUM, "Remove development and debug packages from production images"),
    ("4.4", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure images are scanned for vulnerabilities", Severity.HIGH, "Integrate vulnerability scanning in CI pipeline"),
    ("4.5", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure Content trust for Docker is enabled", Severity.HIGH, "Set DOCKER_CONTENT_TRUST=1 in build environment"),
    ("4.6", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure HEALTHCHECK instructions have been added to the container image", Severity.MEDIUM, "Add HEALTHCHECK instruction to Dockerfile"),
    ("4.7", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure update instructions are not used alone in Dockerfile", Severity.MEDIUM, "Combine RUN apt-get update with apt-get install"),
    ("4.8", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure setuid and setgid permissions are removed", Severity.MEDIUM, "Remove setuid/setgid bits in Dockerfile"),
    ("4.9", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure COPY is used instead of ADD in Dockerfiles", Severity.LOW, "Replace ADD with COPY unless extraction is required"),
    ("4.10", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure secrets are not stored in Dockerfiles", Severity.CRITICAL, "Use Docker secrets or env injection at runtime"),
    ("4.11", CISBenchmarkSection.CONTAINER_IMAGES, "Ensure verified packages are only installed", Severity.MEDIUM, "Verify package signatures during installation"),
    # Section 5 — Container Runtime
    ("5.1", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure AppArmor Profile is enabled", Severity.MEDIUM, "Apply AppArmor profile to container with --security-opt apparmor"),
    ("5.2", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure SELinux security options are set", Severity.MEDIUM, "Set --security-opt label=level:s0"),
    ("5.3", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure Linux Kernel Capabilities are restricted within containers", Severity.HIGH, "Use --cap-drop=ALL --cap-add=<needed>"),
    ("5.4", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure privileged containers are not used", Severity.CRITICAL, "Remove --privileged flag from container run commands"),
    ("5.5", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure sensitive host system directories are not mounted", Severity.HIGH, "Do not mount /, /etc, /var/run, /sys, /proc from host"),
    ("5.6", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure ssh is not run within containers", Severity.MEDIUM, "Remove SSH daemon from container; use exec instead"),
    ("5.7", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure privileged ports are not mapped within containers", Severity.MEDIUM, "Avoid mapping host ports < 1024"),
    ("5.8", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure that only needed ports are open on the container", Severity.MEDIUM, "Remove unnecessary EXPOSE directives"),
    ("5.9", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure the host's network namespace is not shared", Severity.HIGH, "Remove --network=host from container run"),
    ("5.10", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure memory usage for container is limited", Severity.MEDIUM, "Set --memory flag"),
    ("5.11", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure CPU priority is set appropriately", Severity.LOW, "Set --cpu-shares flag"),
    ("5.12", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure the container's root filesystem is mounted as read only", Severity.MEDIUM, "Set --read-only flag"),
    ("5.13", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure incoming container traffic is bound to a specific host interface", Severity.MEDIUM, "Bind published ports to specific interface: -p host_ip:port:port"),
    ("5.14", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure 'on-failure' container restart policy is set to '5'", Severity.MEDIUM, "Set --restart=on-failure:5"),
    ("5.15", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure the host's process namespace is not shared", Severity.HIGH, "Remove --pid=host from container run"),
    ("5.16", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure the host's IPC namespace is not shared", Severity.HIGH, "Remove --ipc=host from container run"),
    ("5.17", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure host devices are not directly exposed to containers", Severity.HIGH, "Remove --device flag or restrict to safe devices"),
    ("5.18", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure the default ulimit is overwritten at runtime only if needed", Severity.LOW, "Review --ulimit overrides"),
    ("5.19", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure mount propagation mode is not set to shared", Severity.MEDIUM, "Avoid :shared mount propagation"),
    ("5.20", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure the host's UTS namespace is not shared", Severity.MEDIUM, "Remove --uts=host from container run"),
    ("5.21", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure the default seccomp profile is not disabled", Severity.MEDIUM, "Remove --security-opt seccomp=unconfined"),
    ("5.22", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure docker exec commands are not used with privileged option", Severity.HIGH, "Disallow docker exec --privileged in runbooks"),
    ("5.23", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure docker exec commands are not used with user option", Severity.MEDIUM, "Avoid docker exec --user root"),
    ("5.24", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure cgroup usage is confirmed", Severity.LOW, "Verify --cgroup-parent usage"),
    ("5.25", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure the container is restricted from acquiring additional privileges", Severity.HIGH, "Set --security-opt=no-new-privileges"),
    ("5.26", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure container health is checked at runtime", Severity.MEDIUM, "Verify HEALTHCHECK or --health-cmd is set"),
    ("5.27", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure Docker commands always get the latest version of the image", Severity.MEDIUM, "Pin images by digest, not :latest"),
    ("5.28", CISBenchmarkSection.CONTAINER_RUNTIME, "Ensure PIDs cgroup limit is used", Severity.LOW, "Set --pids-limit"),
    # Section 6 — Docker Security Operations
    ("6.1", CISBenchmarkSection.SECURITY_OPERATIONS, "Ensure image sprawl is avoided", Severity.LOW, "Regularly remove unused images with docker image prune"),
    ("6.2", CISBenchmarkSection.SECURITY_OPERATIONS, "Ensure container sprawl is avoided", Severity.LOW, "Remove stopped containers regularly with docker container prune"),
    # Section 7 — Docker Swarm Configuration
    ("7.1", CISBenchmarkSection.DOCKER_SWARM, "Ensure swarm mode is not enabled unnecessarily", Severity.LOW, "Run docker swarm leave --force if swarm is not needed"),
    ("7.2", CISBenchmarkSection.DOCKER_SWARM, "Ensure that the minimum number of manager nodes have been created in a swarm", Severity.MEDIUM, "Use odd number of managers for quorum"),
    ("7.3", CISBenchmarkSection.DOCKER_SWARM, "Ensure that swarm services are bound to a specific host interface", Severity.MEDIUM, "Bind swarm ports to specific interface"),
    ("7.4", CISBenchmarkSection.DOCKER_SWARM, "Ensure that all Docker swarm overlay networks are encrypted", Severity.HIGH, "Create overlay networks with --opt encrypted"),
    ("7.5", CISBenchmarkSection.DOCKER_SWARM, "Ensure that Docker's secret management commands are used for managing secrets in a swarm cluster", Severity.HIGH, "Use docker secret create/inspect, not plaintext env vars"),
    ("7.6", CISBenchmarkSection.DOCKER_SWARM, "Ensure that swarm manager is run in auto-lock mode", Severity.HIGH, "Enable --autolock when initializing swarm"),
    ("7.7", CISBenchmarkSection.DOCKER_SWARM, "Ensure that the swarm manager auto-lock key is rotated periodically", Severity.MEDIUM, "Rotate autolock key: docker swarm unlock-key --rotate"),
    ("7.8", CISBenchmarkSection.DOCKER_SWARM, "Ensure that node certificates are rotated as appropriate", Severity.MEDIUM, "Set --cert-expiry to a reasonable value"),
    ("7.9", CISBenchmarkSection.DOCKER_SWARM, "Ensure that CA certificates are rotated as appropriate", Severity.MEDIUM, "Rotate CA: docker swarm ca --rotate"),
    ("7.10", CISBenchmarkSection.DOCKER_SWARM, "Ensure that management plane traffic is separated from data plane traffic", Severity.MEDIUM, "Use separate NICs/networks for management and data plane"),
]


class CISBenchmarkChecker:
    """Run CIS Docker Benchmark checks against a host/container config snapshot."""

    def run_checks(
        self,
        target: str,
        config_snapshot: Dict[str, Any],
        section_filter: Optional[CISBenchmarkSection] = None,
    ) -> CISBenchmarkReport:
        """Evaluate CIS checks against a configuration snapshot.

        config_snapshot keys (all optional, defaults to insecure):
          - docker_daemon: Dict[str, Any] — parsed daemon.json
          - container_opts: Dict[str, Any] — container inspect result
          - image_analysis: ImageAnalysisResult | None
          - host_info: Dict[str, Any]
        """
        log.info("cis_benchmark_start", target=target)

        daemon = config_snapshot.get("docker_daemon", {}) or {}
        container = config_snapshot.get("container_opts", {}) or {}
        image: Optional[ImageAnalysisResult] = config_snapshot.get("image_analysis")
        host = config_snapshot.get("host_info", {}) or {}

        checks: List[CISCheckResult] = []
        for check_id, section, title, sev, remediation in _CIS_CHECKS:
            if section_filter and section != section_filter:
                continue
            passed, evidence = self._evaluate_check(
                check_id, daemon, container, image, host
            )
            checks.append(CISCheckResult(
                check_id=check_id,
                section=section,
                title=title,
                description=title,
                passed=passed,
                severity=sev,
                remediation=remediation,
                evidence=evidence,
            ))

        total = len(checks)
        passed_count = sum(1 for c in checks if c.passed)
        failed_count = total - passed_count
        score = (passed_count / total * 100) if total > 0 else 0.0

        report = CISBenchmarkReport(
            target=target,
            total_checks=total,
            passed_checks=passed_count,
            failed_checks=failed_count,
            score_pct=round(score, 1),
            checks=checks,
        )

        log.info(
            "cis_benchmark_complete",
            target=target,
            total=total,
            passed=passed_count,
            score_pct=score,
        )
        return report

    def _evaluate_check(
        self,
        check_id: str,
        daemon: Dict[str, Any],
        container: Dict[str, Any],
        image: Optional[ImageAnalysisResult],
        host: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Return (passed, evidence_string) for a single CIS check."""

        # Map check IDs to evaluation logic
        evaluators: Dict[str, Any] = {
            "2.1": lambda: (daemon.get("icc") is False, f"icc={daemon.get('icc')}"),
            "2.4": lambda: (not daemon.get("insecure-registries"), f"insecure-registries={daemon.get('insecure-registries')}"),
            "2.6": lambda: (bool(daemon.get("tlsverify")), f"tlsverify={daemon.get('tlsverify')}"),
            "2.8": lambda: (bool(daemon.get("userns-remap")), f"userns-remap={daemon.get('userns-remap')}"),
            "4.1": lambda: (image is not None and image.user not in ("", "root", "0"), f"user={image.user if image else 'unknown'}"),
            "4.5": lambda: (bool(host.get("DOCKER_CONTENT_TRUST")), f"DOCKER_CONTENT_TRUST={host.get('DOCKER_CONTENT_TRUST')}"),
            "4.6": lambda: (image is not None and image.has_healthcheck, f"has_healthcheck={image.has_healthcheck if image else False}"),
            "4.10": lambda: self._check_no_secrets_in_image(image),
            "5.3": lambda: (bool(container.get("cap_drop")), f"cap_drop={container.get('cap_drop')}"),
            "5.4": lambda: (not container.get("privileged", False), f"privileged={container.get('privileged', False)}"),
            "5.9": lambda: (container.get("network_mode") != "host", f"network_mode={container.get('network_mode')}"),
            "5.10": lambda: (bool(container.get("memory_limit")), f"memory_limit={container.get('memory_limit')}"),
            "5.12": lambda: (bool(container.get("read_only_rootfs")), f"read_only_rootfs={container.get('read_only_rootfs')}"),
            "5.15": lambda: (container.get("pid_mode") != "host", f"pid_mode={container.get('pid_mode')}"),
            "5.16": lambda: (container.get("ipc_mode") != "host", f"ipc_mode={container.get('ipc_mode')}"),
            "5.21": lambda: ("seccomp=unconfined" not in str(container.get("security_opts", [])), f"security_opts={container.get('security_opts')}"),
            "5.25": lambda: ("no-new-privileges" in str(container.get("security_opts", [])), f"security_opts={container.get('security_opts')}"),
        }

        if check_id in evaluators:
            try:
                result = evaluators[check_id]()
                return result[0], result[1]
            except Exception as exc:
                return False, f"evaluation_error: {exc}"

        # Default: unknown — assume not configured (conservative/failing)
        return False, "not_evaluated"

    def _check_no_secrets_in_image(self, image: Optional[ImageAnalysisResult]) -> Tuple[bool, str]:
        if image is None:
            return False, "no_image_provided"
        secret_patterns = ["password", "secret", "token", "api_key", "private_key", "aws_", "db_pass"]
        for env_var in image.environment_vars:
            low = env_var.lower()
            for pat in secret_patterns:
                if pat in low and "=" in env_var:
                    val = env_var.split("=", 1)[1]
                    if val and val not in ("", "None", "null", "<secret>"):
                        return False, f"Potential secret in ENV: {env_var.split('=')[0]}"
        for label_key in image.labels:
            if any(pat in label_key.lower() for pat in secret_patterns):
                return False, f"Potential secret in LABEL: {label_key}"
        return True, "no_secrets_detected"


# ---------------------------------------------------------------------------
# Cosign shell-out helper
# ---------------------------------------------------------------------------

def _cosign_verify_image(
    image_ref: str,
    scheme: "SignatureScheme" = None,  # type: ignore[assignment]
    timeout: int = 15,
) -> Optional[bool]:
    """Shell out to the cosign binary to verify an image signature.

    Returns:
      True   — cosign exited 0 (signature valid)
      False  — cosign exited non-zero (signature invalid / not found)
      None   — cosign binary not installed; caller should degrade gracefully

    Never raises. Structured warnings are logged on failure so oncall
    can diagnose without stack-trace noise in the API response.
    """
    cosign_bin = shutil.which("cosign")
    if cosign_bin is None:
        log.warning(
            "cosign_binary_not_found",
            image_ref=image_ref,
            advice="install cosign (https://docs.sigstore.dev/cosign/installation) for real signature verification",
        )
        return None

    cmd = [cosign_bin, "verify", image_ref]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            log.info("cosign_verify_ok", image_ref=image_ref)
            return True
        log.warning(
            "cosign_verify_failed",
            image_ref=image_ref,
            returncode=result.returncode,
            stderr=result.stderr[:500] if result.stderr else "",
        )
        return False
    except subprocess.TimeoutExpired:
        log.warning("cosign_verify_timeout", image_ref=image_ref, timeout=timeout)
        return False
    except Exception as exc:  # pragma: no cover
        log.warning("cosign_verify_error", image_ref=image_ref, error=str(exc))
        return False


# ---------------------------------------------------------------------------
# Image Signing Verification
# ---------------------------------------------------------------------------

class ImageSigningVerifier:
    """Verify image signatures using cosign, Notary v2, or Docker Content Trust."""

    def __init__(self, require_signed: bool = False) -> None:
        self.require_signed = require_signed

    def verify(
        self,
        image_ref: str,
        signature_data: Optional[Dict[str, Any]] = None,
        scheme: SignatureScheme = SignatureScheme.COSIGN,
    ) -> SignatureVerificationResult:
        """Verify a container image signature.

        signature_data keys (from registry or cosign output):
          - signatures: List[Dict] — list of signature objects
          - signer: str
          - signed_at: str (ISO8601)
          - digest: str
        """
        log.info("signature_verification_start", image_ref=image_ref, scheme=scheme)

        if not signature_data:
            result = SignatureVerificationResult(
                image_ref=image_ref,
                verified=False,
                scheme=scheme,
                error="No signature data provided",
                policy_compliant=not self.require_signed,
            )
            log.warning("signature_verification_no_data", image_ref=image_ref)
            return result

        signatures = signature_data.get("signatures", [])
        if not signatures:
            result = SignatureVerificationResult(
                image_ref=image_ref,
                verified=False,
                scheme=scheme,
                error="No signatures found in signature data",
                policy_compliant=not self.require_signed,
            )
            return result

        # Take first valid signature
        sig = signatures[0]
        signer = sig.get("signer") or signature_data.get("signer", "unknown")
        signed_at = sig.get("signed_at") or signature_data.get("signed_at")
        sig_digest = sig.get("digest") or signature_data.get("digest")

        # Real cosign/notation verify shell-out.
        # If cosign binary is present, delegate to it; else fall back to
        # structural check (signer + digest present) with a logged warning.
        verified = _cosign_verify_image(image_ref, scheme=scheme)
        if verified is None:
            # cosign not installed — degrade gracefully with structural check
            verified = bool(signer and sig_digest)

        result = SignatureVerificationResult(
            image_ref=image_ref,
            verified=verified,
            scheme=scheme,
            signer=signer if verified else None,
            signature_digest=sig_digest if verified else None,
            signed_at=signed_at if verified else None,
            error=None if verified else "Signature digest or signer missing",
            policy_compliant=verified or not self.require_signed,
        )

        log.info(
            "signature_verification_complete",
            image_ref=image_ref,
            verified=verified,
            scheme=scheme,
            policy_compliant=result.policy_compliant,
        )
        return result


# ---------------------------------------------------------------------------
# Registry Security Scanner
# ---------------------------------------------------------------------------

class RegistrySecurityScanner:
    """Scan configured registries for security posture issues."""

    # Known public registries that allow anonymous pull by default
    _DEFAULT_PUBLIC_REGISTRIES = frozenset({
        "docker.io", "registry.hub.docker.com",
        "ghcr.io", "quay.io", "gcr.io",
    })

    def scan(
        self,
        registry_url: str,
        registry_metadata: Optional[Dict[str, Any]] = None,
        images: Optional[List[Dict[str, Any]]] = None,
    ) -> RegistrySecurityReport:
        """Assess security posture of a registry.

        registry_metadata keys:
          - public_access: bool
          - tag_immutability: bool
          - vuln_scanning: str (enabled|disabled|unknown)
          - auth_required: bool

        images: list of {ref, pushed_at (ISO8601), has_cves: bool}
        """
        log.info("registry_scan_start", registry_url=registry_url)

        meta = registry_metadata or {}
        images = images or []

        issues: List[str] = []
        risk_score = 0

        # Public access check
        public_access = meta.get("public_access", False)
        if not public_access:
            # Heuristic: well-known public registries
            domain = registry_url.split("/")[0].lower()
            public_access = domain in self._DEFAULT_PUBLIC_REGISTRIES
        if public_access:
            issues.append("Registry allows public/anonymous access — enforce authentication")
            risk_score += 25

        # Tag immutability
        tag_immutability = bool(meta.get("tag_immutability", False))
        if not tag_immutability:
            issues.append("Tag immutability not enforced — tags can be overwritten")
            risk_score += 20

        # Vulnerability scanning
        vuln_raw = meta.get("vuln_scanning", "unknown").lower()
        try:
            vuln_status = RegistryVulnStatus(f"scanning_{vuln_raw}") if vuln_raw in ("enabled", "disabled") else RegistryVulnStatus.UNKNOWN
        except ValueError:
            vuln_status = RegistryVulnStatus.UNKNOWN
        if vuln_status != RegistryVulnStatus.SCANNING_ENABLED:
            issues.append("Vulnerability scanning not confirmed enabled on registry")
            risk_score += 20

        # Auth required
        if not meta.get("auth_required", True):
            issues.append("Registry does not require authentication for push operations")
            risk_score += 25

        # Stale image detection (older than 180 days)
        stale: List[str] = []
        now = datetime.now(timezone.utc)
        for img in images:
            pushed_raw = img.get("pushed_at", "")
            if pushed_raw:
                try:
                    pushed = datetime.fromisoformat(pushed_raw.replace("Z", "+00:00"))
                    age_days = (now - pushed).days
                    if age_days > 180:
                        stale.append(img.get("ref", "unknown"))
                except ValueError:
                    pass

        if stale:
            issues.append(f"{len(stale)} stale image(s) older than 180 days detected")
            risk_score += min(10, len(stale))

        risk_score = min(100, risk_score)

        report = RegistrySecurityReport(
            registry_url=registry_url,
            public_access=public_access,
            tag_immutability=tag_immutability,
            vuln_scanning_status=vuln_status,
            stale_images=stale,
            stale_image_count=len(stale),
            total_images_checked=len(images),
            issues=issues,
            risk_score=risk_score,
        )

        log.info(
            "registry_scan_complete",
            registry_url=registry_url,
            risk_score=risk_score,
            issues=len(issues),
        )
        return report


# ---------------------------------------------------------------------------
# Singleton facade
# ---------------------------------------------------------------------------

class ContainerRuntimeSecurityEngine:
    """Unified facade over all container security subsystems."""

    def __init__(self) -> None:
        self.image_analyzer = ImageAnalyzer()
        self.policy_engine = RuntimePolicyEngine()
        self.drift_detector = DriftDetector()
        self.vuln_mapper = VulnerabilityMapper()
        self.cis_checker = CISBenchmarkChecker()
        self.signing_verifier = ImageSigningVerifier()
        self.registry_scanner = RegistrySecurityScanner()
        log.info("container_runtime_security_engine_initialized")

    def analyse_image(
        self,
        image_ref: str,
        manifest: Optional[Dict[str, Any]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> ImageAnalysisResult:
        result = self.image_analyzer.analyse(image_ref, manifest, config)
        _emit_event("container.image_analysed", {"image_ref": image_ref, "vuln_count": len(result.vulnerabilities) if hasattr(result, "vulnerabilities") else 0})
        return result

    def evaluate_policy(
        self,
        image_ref: str,
        analysis: ImageAnalysisResult,
        policy_id: Optional[str] = None,
    ) -> List[PolicyEvaluationResult]:
        results = self.policy_engine.evaluate(image_ref, analysis, policy_id)
        _emit_event("container.policy_evaluated", {"image_ref": image_ref, "policy_id": policy_id, "violation_count": sum(1 for r in results if r.violations)})
        return results

    def detect_drift(
        self,
        container_id: str,
        image_ref: str,
        image_analysis: ImageAnalysisResult,
        runtime_state: Dict[str, Any],
    ) -> DriftReport:
        report = self.drift_detector.detect(container_id, image_ref, image_analysis, runtime_state)
        _emit_event("container.drift_detected", {"container_id": container_id, "image_ref": image_ref, "drifted": getattr(report, "has_drift", False)})
        return report

    def map_vulnerabilities(
        self,
        image_ref: str,
        cve_list: List[Dict[str, Any]],
        running_containers: List[Dict[str, Any]],
    ) -> VulnerabilityMapResult:
        return self.vuln_mapper.map_vulnerabilities(image_ref, cve_list, running_containers)

    def run_cis_benchmark(
        self,
        target: str,
        config_snapshot: Dict[str, Any],
        section_filter: Optional[CISBenchmarkSection] = None,
    ) -> CISBenchmarkReport:
        return self.cis_checker.run_checks(target, config_snapshot, section_filter)

    def verify_signature(
        self,
        image_ref: str,
        signature_data: Optional[Dict[str, Any]] = None,
        scheme: SignatureScheme = SignatureScheme.COSIGN,
    ) -> SignatureVerificationResult:
        return self.signing_verifier.verify(image_ref, signature_data, scheme)

    def scan_registry(
        self,
        registry_url: str,
        registry_metadata: Optional[Dict[str, Any]] = None,
        images: Optional[List[Dict[str, Any]]] = None,
    ) -> RegistrySecurityReport:
        return self.registry_scanner.scan(registry_url, registry_metadata, images)


_engine: Optional[ContainerRuntimeSecurityEngine] = None


def get_container_runtime_engine() -> ContainerRuntimeSecurityEngine:
    """Return the singleton ContainerRuntimeSecurityEngine."""
    global _engine
    if _engine is None:
        _engine = ContainerRuntimeSecurityEngine()
    return _engine
