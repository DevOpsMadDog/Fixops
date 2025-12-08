"""FixOps Container Runtime Security Analyzer

Proprietary container runtime analysis for Docker, Kubernetes, and cloud containers.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ContainerThreatType(Enum):
    """Container threat types."""
    
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNSAFE_CAPABILITIES = "unsafe_capabilities"
    ROOT_USER = "root_user"
    INSECURE_MOUNTS = "insecure_mounts"
    NETWORK_EXPOSURE = "network_exposure"
    SECRETS_IN_IMAGE = "secrets_in_image"
    VULNERABLE_BASE_IMAGE = "vulnerable_base_image"
    MISSING_SECURITY_CONTEXT = "missing_security_context"


@dataclass
class ContainerFinding:
    """Container security finding."""
    
    threat_type: ContainerThreatType
    severity: str  # critical, high, medium, low
    container_id: Optional[str] = None
    image_name: Optional[str] = None
    namespace: Optional[str] = None
    pod_name: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ContainerSecurityResult:
    """Container security analysis result."""
    
    findings: List[ContainerFinding]
    total_findings: int
    findings_by_type: Dict[str, int]
    findings_by_severity: Dict[str, int]
    containers_analyzed: int
    images_analyzed: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ContainerRuntimeAnalyzer:
    """FixOps Container Runtime Analyzer - Proprietary container security."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize container runtime analyzer."""
        self.config = config or {}
    
    def analyze_container(
        self, container_id: str, container_info: Optional[Dict[str, Any]] = None
    ) -> List[ContainerFinding]:
        """Analyze a single container for security issues."""
        findings = []
        
        # Get container information
        if not container_info:
            container_info = self._get_container_info(container_id)
        
        # Check for root user
        if self._is_running_as_root(container_info):
            findings.append(
                ContainerFinding(
                    threat_type=ContainerThreatType.ROOT_USER,
                    severity="high",
                    container_id=container_id,
                    image_name=container_info.get("image"),
                    description="Container is running as root user",
                    recommendation="Run container as non-root user",
                )
            )
        
        # Check for unsafe capabilities
        unsafe_caps = self._check_capabilities(container_info)
        if unsafe_caps:
            findings.append(
                ContainerFinding(
                    threat_type=ContainerThreatType.UNSAFE_CAPABILITIES,
                    severity="high",
                    container_id=container_id,
                    image_name=container_info.get("image"),
                    description=f"Container has unsafe capabilities: {', '.join(unsafe_caps)}",
                    recommendation="Remove unsafe capabilities or use drop capabilities",
                )
            )
        
        # Check for privilege escalation
        if self._check_privilege_escalation(container_info):
            findings.append(
                ContainerFinding(
                    threat_type=ContainerThreatType.PRIVILEGE_ESCALATION,
                    severity="critical",
                    container_id=container_id,
                    image_name=container_info.get("image"),
                    description="Container allows privilege escalation",
                    recommendation="Set allowPrivilegeEscalation: false",
                )
            )
        
        # Check for insecure mounts
        insecure_mounts = self._check_mounts(container_info)
        if insecure_mounts:
            findings.append(
                ContainerFinding(
                    threat_type=ContainerThreatType.INSECURE_MOUNTS,
                    severity="medium",
                    container_id=container_id,
                    image_name=container_info.get("image"),
                    description=f"Insecure mounts detected: {', '.join(insecure_mounts)}",
                    recommendation="Review and secure container mounts",
                )
            )
        
        # Check for network exposure
        if self._check_network_exposure(container_info):
            findings.append(
                ContainerFinding(
                    threat_type=ContainerThreatType.NETWORK_EXPOSURE,
                    severity="medium",
                    container_id=container_id,
                    image_name=container_info.get("image"),
                    description="Container has exposed network ports",
                    recommendation="Limit network exposure, use network policies",
                )
            )
        
        return findings
    
    def analyze_kubernetes_pod(
        self, namespace: str, pod_name: str, pod_spec: Optional[Dict[str, Any]] = None
    ) -> List[ContainerFinding]:
        """Analyze Kubernetes pod for security issues."""
        findings = []
        
        if not pod_spec:
            pod_spec = self._get_pod_spec(namespace, pod_name)
        
        # Check security context
        security_context = pod_spec.get("spec", {}).get("securityContext", {})
        containers = pod_spec.get("spec", {}).get("containers", [])
        
        # Check for missing security context
        if not security_context:
            findings.append(
                ContainerFinding(
                    threat_type=ContainerThreatType.MISSING_SECURITY_CONTEXT,
                    severity="high",
                    namespace=namespace,
                    pod_name=pod_name,
                    description="Pod is missing security context",
                    recommendation="Add security context with runAsNonRoot, readOnlyRootFilesystem",
                )
            )
        
        # Analyze each container in pod
        for container in containers:
            container_findings = self._analyze_container_spec(container, namespace, pod_name)
            findings.extend(container_findings)
        
        return findings
    
    def _analyze_container_spec(
        self, container_spec: Dict[str, Any], namespace: str, pod_name: str
    ) -> List[ContainerFinding]:
        """Analyze container spec for security issues."""
        findings = []
        
        security_context = container_spec.get("securityContext", {})
        
        # Check for root user
        if security_context.get("runAsUser") == 0:
            findings.append(
                ContainerFinding(
                    threat_type=ContainerThreatType.ROOT_USER,
                    severity="high",
                    namespace=namespace,
                    pod_name=pod_name,
                    image_name=container_spec.get("image"),
                    description="Container runs as root user",
                    recommendation="Set runAsUser to non-root UID",
                )
            )
        
        # Check for privilege escalation
        if security_context.get("allowPrivilegeEscalation", True):
            findings.append(
                ContainerFinding(
                    threat_type=ContainerThreatType.PRIVILEGE_ESCALATION,
                    severity="critical",
                    namespace=namespace,
                    pod_name=pod_name,
                    image_name=container_spec.get("image"),
                    description="Container allows privilege escalation",
                    recommendation="Set allowPrivilegeEscalation: false",
                )
            )
        
        return findings
    
    def _get_container_info(self, container_id: str) -> Dict[str, Any]:
        """Get container information."""
        # In production, this would use Docker API or container runtime API
        try:
            result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                import json
                return json.loads(result.stdout)[0]
        except Exception as e:
            logger.warning(f"Failed to get container info: {e}")
        
        return {}
    
    def _get_pod_spec(self, namespace: str, pod_name: str) -> Dict[str, Any]:
        """Get Kubernetes pod spec."""
        # In production, this would use Kubernetes API
        try:
            result = subprocess.run(
                ["kubectl", "get", "pod", pod_name, "-n", namespace, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                import json
                return json.loads(result.stdout)
        except Exception as e:
            logger.warning(f"Failed to get pod spec: {e}")
        
        return {}
    
    def _is_running_as_root(self, container_info: Dict[str, Any]) -> bool:
        """Check if container is running as root."""
        config = container_info.get("Config", {})
        user = config.get("User", "")
        return user == "" or user == "0" or user == "root"
    
    def _check_capabilities(self, container_info: Dict[str, Any]) -> List[str]:
        """Check for unsafe capabilities."""
        unsafe_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "DAC_OVERRIDE"]
        found_caps = []
        
        host_config = container_info.get("HostConfig", {})
        cap_add = host_config.get("CapAdd", [])
        
        for cap in cap_add:
            if cap in unsafe_caps:
                found_caps.append(cap)
        
        return found_caps
    
    def _check_privilege_escalation(self, container_info: Dict[str, Any]) -> bool:
        """Check if container allows privilege escalation."""
        host_config = container_info.get("HostConfig", {})
        return host_config.get("Privileged", False)
    
    def _check_mounts(self, container_info: Dict[str, Any]) -> List[str]:
        """Check for insecure mounts."""
        insecure_mounts = []
        
        mounts = container_info.get("Mounts", [])
        for mount in mounts:
            source = mount.get("Source", "")
            if "/proc" in source or "/sys" in source or "/dev" in source:
                insecure_mounts.append(source)
        
        return insecure_mounts
    
    def _check_network_exposure(self, container_info: Dict[str, Any]) -> bool:
        """Check if container has exposed network ports."""
        config = container_info.get("Config", {})
        exposed_ports = config.get("ExposedPorts", {})
        return len(exposed_ports) > 0
    
    def analyze_all_containers(self) -> ContainerSecurityResult:
        """Analyze all running containers."""
        findings = []
        
        # Get all containers (Docker)
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.ID}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                container_ids = result.stdout.strip().split("\n")
                for container_id in container_ids:
                    if container_id:
                        container_findings = self.analyze_container(container_id)
                        findings.extend(container_findings)
        except Exception as e:
            logger.warning(f"Failed to list containers: {e}")
        
        # Group findings
        findings_by_type: Dict[str, int] = {}
        findings_by_severity: Dict[str, int] = {}
        
        for finding in findings:
            threat_type = finding.threat_type.value
            findings_by_type[threat_type] = findings_by_type.get(threat_type, 0) + 1
            
            severity = finding.severity
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
        
        return ContainerSecurityResult(
            findings=findings,
            total_findings=len(findings),
            findings_by_type=findings_by_type,
            findings_by_severity=findings_by_severity,
            containers_analyzed=len(set(f.container_id for f in findings if f.container_id)),
            images_analyzed=len(set(f.image_name for f in findings if f.image_name)),
        )
