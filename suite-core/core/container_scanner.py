"""ALdeci Container Image Scanner.

Scans Docker/OCI images and Dockerfiles for:
- Vulnerable base images
- Dockerfile misconfigurations (running as root, no healthcheck, etc.)
- Layer analysis for secrets/sensitive files
- Helm chart security analysis
- Image layer secret detection
- Integration with Trivy/Grype when available
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


class ContainerSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ContainerFinding:
    finding_id: str
    title: str
    severity: ContainerSeverity
    category: str  # dockerfile, base_image, layer, runtime
    cwe_id: str
    description: str
    recommendation: str
    line_number: int = 0
    image_ref: str = ""
    confidence: float = 0.9
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "recommendation": self.recommendation,
            "line_number": self.line_number,
            "image_ref": self.image_ref,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


# ── Dockerfile Rules ───────────────────────────────────────────────
DOCKERFILE_RULES: List[Tuple[str, str, str, str, str, str, str]] = [
    (
        "CONT-001",
        "Running as Root",
        "high",
        "CWE-250",
        r"^USER\s+root",
        "Container runs as root user",
        "Add USER directive with non-root user",
    ),
    (
        "CONT-002",
        "No USER Directive",
        "high",
        "CWE-250",
        "__NO_USER__",
        "Dockerfile has no USER directive (defaults to root)",
        "Add 'USER nonroot' before CMD/ENTRYPOINT",
    ),
    (
        "CONT-003",
        "Latest Tag",
        "medium",
        "CWE-1104",
        r"FROM\s+\S+:latest",
        "Using :latest tag — unpinned base image",
        "Pin to specific version tag or SHA digest",
    ),
    (
        "CONT-004",
        "No HEALTHCHECK",
        "low",
        "CWE-693",
        "__NO_HEALTHCHECK__",
        "No HEALTHCHECK instruction",
        "Add HEALTHCHECK to enable container orchestrator health monitoring",
    ),
    (
        "CONT-005",
        "ADD Instead of COPY",
        "low",
        "CWE-829",
        r"^ADD\s+(?!https?://)",
        "ADD used instead of COPY for local files",
        "Use COPY for local files; ADD only for URLs or tar extraction",
    ),
    (
        "CONT-006",
        "Secrets in ENV",
        "critical",
        "CWE-798",
        r"ENV\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*\S+",
        "Secret value hardcoded in ENV directive",
        "Use build args with --secret or runtime env injection",
    ),
    (
        "CONT-007",
        "Privileged Port",
        "medium",
        "CWE-284",
        r"EXPOSE\s+([0-9]+)",
        "Exposing privileged port (<1024)",
        "Use non-privileged ports (>1024) when possible",
    ),
    (
        "CONT-008",
        "Curl Pipe to Shell",
        "critical",
        "CWE-829",
        r"(curl|wget)\s+.*\|\s*(sh|bash|zsh)",
        "Downloading and piping to shell — supply chain risk",
        "Download, verify checksum, then execute separately",
    ),
    (
        "CONT-009",
        "No Package Pinning",
        "medium",
        "CWE-1104",
        r"(apt-get install|apk add|yum install)\s+(?!.*=)",
        "Package installed without version pinning",
        "Pin package versions for reproducible builds",
    ),
    (
        "CONT-010",
        "Apt-get No Clean",
        "low",
        "CWE-400",
        r"apt-get install(?!.*&&\s*(apt-get clean|rm -rf /var/lib/apt))",
        "apt-get install without cleanup — bloated image",
        "Add '&& apt-get clean && rm -rf /var/lib/apt/lists/*'",
    ),
]

# ── Helm Chart Rules ───────────────────────────────────────────────
HELM_CHART_RULES: List[Dict[str, str]] = [
    {
        "id": "HELM-001", "title": "No Resource Limits in Template",
        "severity": "high", "cwe": "CWE-770",
        "pattern": r"containers:", "anti_pattern": r"resources:",
        "description": "Containers in Helm template have no resource limits — risk of resource exhaustion",
        "recommendation": "Add resources.limits.cpu and resources.limits.memory to every container spec",
    },
    {
        "id": "HELM-002", "title": "Privileged Container in Template",
        "severity": "critical", "cwe": "CWE-250",
        "pattern": r"privileged:\s*true",
        "description": "Helm template deploys privileged container — full host access",
        "recommendation": "Set securityContext.privileged to false",
    },
    {
        "id": "HELM-003", "title": "Run As Root in Template",
        "severity": "high", "cwe": "CWE-250",
        "pattern": r"runAsUser:\s*0",
        "description": "Helm template runs container as root (UID 0)",
        "recommendation": "Set runAsUser to a non-zero UID (e.g., 65534)",
    },
    {
        "id": "HELM-004", "title": "Host Network Enabled",
        "severity": "high", "cwe": "CWE-284",
        "pattern": r"hostNetwork:\s*true",
        "description": "Helm template uses host network namespace — container can sniff host traffic",
        "recommendation": "Set hostNetwork to false unless absolutely required",
    },
    {
        "id": "HELM-005", "title": "Host PID Enabled",
        "severity": "high", "cwe": "CWE-284",
        "pattern": r"hostPID:\s*true",
        "description": "Helm template shares host PID namespace — can see/kill host processes",
        "recommendation": "Set hostPID to false",
    },
    {
        "id": "HELM-006", "title": "No Security Context",
        "severity": "medium", "cwe": "CWE-250",
        "pattern": r"containers:", "anti_pattern": r"securityContext:",
        "description": "Helm template has no securityContext — defaults may be insecure",
        "recommendation": "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation: false",
    },
    {
        "id": "HELM-007", "title": "Latest Image Tag in Template",
        "severity": "medium", "cwe": "CWE-1104",
        "pattern": r"image:\s*['\"]?\S+:latest['\"]?",
        "description": "Helm template uses :latest tag — unpinned, non-reproducible deployments",
        "recommendation": "Pin image to a specific version tag or SHA digest",
    },
    {
        "id": "HELM-008", "title": "Writable Root Filesystem",
        "severity": "medium", "cwe": "CWE-732",
        "pattern": r"readOnlyRootFilesystem:\s*false",
        "description": "Container root filesystem is writable — attackers can modify binaries",
        "recommendation": "Set readOnlyRootFilesystem to true and use emptyDir for writable paths",
    },
    {
        "id": "HELM-009", "title": "Privilege Escalation Allowed",
        "severity": "high", "cwe": "CWE-250",
        "pattern": r"allowPrivilegeEscalation:\s*true",
        "description": "Container can escalate privileges via setuid/setgid binaries",
        "recommendation": "Set allowPrivilegeEscalation to false",
    },
    {
        "id": "HELM-010", "title": "Dangerous Capabilities",
        "severity": "critical", "cwe": "CWE-250",
        "pattern": r"add:\s*\[?\s*['\"]?(SYS_ADMIN|NET_ADMIN|ALL|SYS_PTRACE|NET_RAW)",
        "description": "Helm template adds dangerous Linux capabilities",
        "recommendation": "Drop all capabilities and add only the minimum required",
    },
    {
        "id": "HELM-011", "title": "No Liveness Probe",
        "severity": "low", "cwe": "CWE-693",
        "pattern": r"containers:", "anti_pattern": r"livenessProbe:",
        "description": "No liveness probe — Kubernetes cannot detect unhealthy containers",
        "recommendation": "Add livenessProbe with httpGet, tcpSocket, or exec check",
    },
    {
        "id": "HELM-012", "title": "No Readiness Probe",
        "severity": "low", "cwe": "CWE-693",
        "pattern": r"containers:", "anti_pattern": r"readinessProbe:",
        "description": "No readiness probe — traffic may be sent to unready pods",
        "recommendation": "Add readinessProbe to ensure traffic is only sent to ready pods",
    },
    {
        "id": "HELM-013", "title": "Hardcoded Secrets in Values",
        "severity": "critical", "cwe": "CWE-798",
        "pattern": r"(password|secret|token|apiKey|api_key|private_key):\s*['\"]?[a-zA-Z0-9+/=]{8,}",
        "description": "Hardcoded secret value detected in Helm values or templates",
        "recommendation": "Use Kubernetes Secrets or external secret management (Vault, sealed-secrets)",
    },
    {
        "id": "HELM-014", "title": "Default ServiceAccount Used",
        "severity": "medium", "cwe": "CWE-284",
        "pattern": r"serviceAccountName:\s*['\"]?default['\"]?",
        "description": "Using default ServiceAccount — may have excessive RBAC permissions",
        "recommendation": "Create a dedicated ServiceAccount with least-privilege RBAC bindings",
    },
    {
        "id": "HELM-015", "title": "No Network Policy",
        "severity": "medium", "cwe": "CWE-284",
        "pattern": r"kind:\s*Deployment", "anti_pattern": r"kind:\s*NetworkPolicy",
        "description": "Deployment found but no NetworkPolicy — pods accept all traffic by default",
        "recommendation": "Add a NetworkPolicy to restrict ingress/egress traffic",
    },
]

# ── Image Layer Secret Patterns ────────────────────────────────────
LAYER_SECRET_PATTERNS: List[Dict[str, str]] = [
    {"id": "SEC-001", "name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"id": "SEC-002", "name": "AWS Secret Key", "pattern": r"(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}", "severity": "critical"},
    {"id": "SEC-003", "name": "GitHub Token", "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}", "severity": "critical"},
    {"id": "SEC-004", "name": "Generic Private Key", "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical"},
    {"id": "SEC-005", "name": "Slack Token", "pattern": r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", "severity": "high"},
    {"id": "SEC-006", "name": "Google API Key", "pattern": r"AIza[0-9A-Za-z_-]{35}", "severity": "high"},
    {"id": "SEC-007", "name": "Stripe Secret Key", "pattern": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "critical"},
    {"id": "SEC-008", "name": "Database Connection String", "pattern": r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "severity": "critical"},
    {"id": "SEC-009", "name": "JWT Secret", "pattern": r"(?i)(jwt_secret|jwt_key|signing_key)\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{16,}", "severity": "high"},
    {"id": "SEC-010", "name": "Generic API Key in ENV", "pattern": r"(?i)ENV\s+\S*(API_KEY|APIKEY|ACCESS_KEY|AUTH_TOKEN)\s*=\s*['\"]?[A-Za-z0-9]{16,}", "severity": "high"},
    {"id": "SEC-011", "name": "Heroku API Key", "pattern": r"(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "severity": "high"},
    {"id": "SEC-012", "name": "SendGrid API Key", "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "severity": "high"},
    {"id": "SEC-013", "name": "Twilio Auth Token", "pattern": r"(?i)twilio.*[0-9a-f]{32}", "severity": "high"},
    {"id": "SEC-014", "name": "SSH Private Key Path", "pattern": r"(?i)(COPY|ADD)\s+.*id_(rsa|dsa|ecdsa|ed25519)", "severity": "critical"},
    {"id": "SEC-015", "name": "PFX/P12 Certificate", "pattern": r"(?i)(COPY|ADD)\s+.*\.(pfx|p12|jks|keystore)", "severity": "high"},
    {"id": "SEC-016", "name": "Environment File Copied", "pattern": r"(?i)(COPY|ADD)\s+\.env\b", "severity": "high"},
    {"id": "SEC-017", "name": "NPM Token", "pattern": r"(?i)npm_token\s*=\s*[a-f0-9-]{36}", "severity": "high"},
    {"id": "SEC-018", "name": "Azure Storage Key", "pattern": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "severity": "critical"},
    {"id": "SEC-019", "name": "GCP Service Account Key", "pattern": r"(?i)(COPY|ADD)\s+.*service[_-]?account.*\.json", "severity": "critical"},
    {"id": "SEC-020", "name": "Password in ARG/ENV", "pattern": r"(?i)(ARG|ENV)\s+\S*PASS(WORD)?\s*=\s*['\"]?[^\s'\"]{4,}", "severity": "high"},
]

KNOWN_VULNERABLE_IMAGES = {
    "python:2": ("critical", "Python 2 is EOL since Jan 2020"),
    "node:8": ("critical", "Node.js 8 is EOL"),
    "node:10": ("high", "Node.js 10 is EOL"),
    "ubuntu:14.04": ("critical", "Ubuntu 14.04 is EOL"),
    "ubuntu:16.04": ("high", "Ubuntu 16.04 is EOL"),
    "debian:jessie": ("critical", "Debian Jessie is EOL"),
    "debian:stretch": ("high", "Debian Stretch is EOL"),
    "alpine:3.8": ("high", "Alpine 3.8 is EOL"),
    "alpine:3.9": ("high", "Alpine 3.9 is EOL"),
    "centos:6": ("critical", "CentOS 6 is EOL"),
    "centos:7": ("high", "CentOS 7 is EOL since Jun 2024"),
    "php:7.2": ("critical", "PHP 7.2 is EOL"),
    "php:7.3": ("critical", "PHP 7.3 is EOL"),
    "ruby:2.5": ("high", "Ruby 2.5 is EOL"),
    "golang:1.16": ("medium", "Go 1.16 is EOL"),
}


@dataclass
class ContainerScanResult:
    scan_id: str
    target: str
    total_findings: int
    findings: List[ContainerFinding]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    trivy_available: bool = False
    grype_available: bool = False
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "trivy_available": self.trivy_available,
            "grype_available": self.grype_available,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
        }


class ContainerImageScanner:
    """Container image and Dockerfile scanner."""

    def __init__(self):
        self._trivy = shutil.which("trivy")
        self._grype = shutil.which("grype")

    @property
    def trivy_available(self) -> bool:
        return self._trivy is not None

    @property
    def grype_available(self) -> bool:
        return self._grype is not None

    def scan_dockerfile(
        self, content: str, filename: str = "Dockerfile"
    ) -> ContainerScanResult:
        """Scan Dockerfile content for misconfigurations."""
        import time

        t0 = time.time()
        findings: List[ContainerFinding] = []
        lines = content.split("\n")
        has_user = False
        has_healthcheck = False

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.upper().startswith("USER") and "root" not in stripped.lower():
                has_user = True
            if stripped.upper().startswith("HEALTHCHECK"):
                has_healthcheck = True

            # Check FROM for vulnerable base images
            from_match = re.match(r"^FROM\s+(\S+)", stripped, re.IGNORECASE)
            if from_match:
                image = from_match.group(1).lower()
                for vuln_img, (sev, desc) in KNOWN_VULNERABLE_IMAGES.items():
                    if image.startswith(vuln_img):
                        findings.append(
                            ContainerFinding(
                                finding_id=f"CONT-{uuid.uuid4().hex[:8]}",
                                title=f"Vulnerable Base Image: {image}",
                                severity=ContainerSeverity(sev),
                                category="base_image",
                                cwe_id="CWE-1104",
                                description=desc,
                                recommendation=f"Upgrade from {vuln_img} to a supported version",
                                line_number=line_num,
                                image_ref=image,
                            )
                        )

            # Check privileged port
            port_match = re.match(r"^EXPOSE\s+(\d+)", stripped, re.IGNORECASE)
            if port_match:
                port = int(port_match.group(1))
                if port < 1024:
                    findings.append(
                        ContainerFinding(
                            finding_id=f"CONT-{uuid.uuid4().hex[:8]}",
                            title=f"Privileged Port {port}",
                            severity=ContainerSeverity.MEDIUM,
                            category="dockerfile",
                            cwe_id="CWE-284",
                            description=f"Exposing privileged port {port}",
                            recommendation="Use non-privileged ports (>1024)",
                            line_number=line_num,
                        )
                    )
                continue

            # Pattern-based rules
            for rid, title, sev, cwe, pat, desc, rec in DOCKERFILE_RULES:
                if pat.startswith("__"):
                    continue
                if re.search(pat, stripped, re.IGNORECASE):
                    findings.append(
                        ContainerFinding(
                            finding_id=f"CONT-{uuid.uuid4().hex[:8]}",
                            title=title,
                            severity=ContainerSeverity(sev),
                            category="dockerfile",
                            cwe_id=cwe,
                            description=desc,
                            recommendation=rec,
                            line_number=line_num,
                        )
                    )

        # Meta-rules
        if not has_user:
            findings.append(
                ContainerFinding(
                    finding_id=f"CONT-{uuid.uuid4().hex[:8]}",
                    title="No USER Directive",
                    severity=ContainerSeverity.HIGH,
                    category="dockerfile",
                    cwe_id="CWE-250",
                    description="Dockerfile has no USER directive (defaults to root)",
                    recommendation="Add 'USER nonroot' before CMD/ENTRYPOINT",
                )
            )
        if not has_healthcheck:
            findings.append(
                ContainerFinding(
                    finding_id=f"CONT-{uuid.uuid4().hex[:8]}",
                    title="No HEALTHCHECK",
                    severity=ContainerSeverity.LOW,
                    category="dockerfile",
                    cwe_id="CWE-693",
                    description="No HEALTHCHECK instruction",
                    recommendation="Add HEALTHCHECK to enable health monitoring",
                )
            )

        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1

        elapsed = (time.time() - t0) * 1000
        return ContainerScanResult(
            scan_id=f"cont-{uuid.uuid4().hex[:12]}",
            target=filename,
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            trivy_available=self.trivy_available,
            grype_available=self.grype_available,
            duration_ms=round(elapsed, 2),
        )

    @staticmethod
    def _validate_image_ref(image_ref: str) -> str:
        """Validate container image reference to prevent shell injection.

        Blocks characters that could be used for command injection:
        ; | & $ ( ) { } ! > < ` \\n \\r
        """
        _BLOCKED_CHARS = set(';|&$(){}!><`\n\r\t\\')
        if not image_ref or not image_ref.strip():
            raise ValueError("Empty image reference")
        if len(image_ref) > 512:
            raise ValueError("Image reference too long (max 512 chars)")
        bad_chars = _BLOCKED_CHARS & set(image_ref)
        if bad_chars:
            raise ValueError(
                f"Blocked characters in image reference: {sorted(bad_chars)}"
            )
        # Validate format: registry/repo:tag or repo:tag@sha256:digest
        import re
        if not re.match(r'^[\w\.\-/:@]+$', image_ref):
            raise ValueError(f"Invalid image reference format: {image_ref!r}")
        return image_ref.strip()

    async def scan_image(self, image_ref: str) -> ContainerScanResult:
        """Scan a container image using Trivy/Grype if available."""
        import time

        # Validate image reference to prevent CLI injection
        image_ref = self._validate_image_ref(image_ref)

        t0 = time.time()
        findings: List[ContainerFinding] = []

        if self._trivy:
            try:
                proc = await asyncio.create_subprocess_exec(
                    self._trivy,
                    "image",
                    "--format",
                    "json",
                    "--quiet",
                    image_ref,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                data = json.loads(stdout.decode())
                for result in data.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        sev = vuln.get("Severity", "UNKNOWN").lower()
                        if sev not in ("critical", "high", "medium", "low"):
                            sev = "info"
                        findings.append(
                            ContainerFinding(
                                finding_id=f"CONT-{uuid.uuid4().hex[:8]}",
                                title=f"{vuln.get('VulnerabilityID', 'UNKNOWN')}: {vuln.get('PkgName', '')}",
                                severity=ContainerSeverity(sev),
                                category="image_vuln",
                                cwe_id=vuln.get("CweIDs", ["CWE-1104"])[0]
                                if vuln.get("CweIDs")
                                else "CWE-1104",
                                description=vuln.get("Description", "")[:300],
                                recommendation=f"Upgrade {vuln.get('PkgName', '')} to {vuln.get('FixedVersion', 'latest')}",
                                image_ref=image_ref,
                            )
                        )
            except asyncio.TimeoutError:
                logger.warning("Trivy scan timed out for %s", image_ref)
            except json.JSONDecodeError as e:
                logger.warning("Trivy returned invalid JSON for %s: %s", image_ref, e.msg)
            except FileNotFoundError:
                logger.debug("Trivy not found in PATH")
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("Trivy scan error for %s: %s", image_ref, type(e).__name__)

        # ── Grype scanning ──────────────────────────────────────────
        if self._grype:
            try:
                proc = await asyncio.create_subprocess_exec(
                    self._grype,
                    image_ref,
                    "-o", "json",
                    "--quiet",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                data = json.loads(stdout.decode())
                for match in data.get("matches", []):
                    vuln = match.get("vulnerability", {})
                    artifact = match.get("artifact", {})
                    sev = vuln.get("severity", "Unknown").lower()
                    if sev not in ("critical", "high", "medium", "low"):
                        sev = "info"
                    vuln_id = vuln.get("id", "UNKNOWN")
                    pkg_name = artifact.get("name", "")
                    # Deduplicate: skip if Trivy already found same CVE+package
                    existing_ids = {f.title for f in findings}
                    title = f"{vuln_id}: {pkg_name}"
                    if title in existing_ids:
                        continue
                    findings.append(
                        ContainerFinding(
                            finding_id=f"GRYPE-{uuid.uuid4().hex[:8]}",
                            title=title,
                            severity=ContainerSeverity(sev),
                            category="image_vuln",
                            cwe_id="CWE-1104",
                            description=vuln.get("description", "")[:300],
                            recommendation=f"Upgrade {pkg_name} to {vuln.get('fix', {}).get('versions', ['latest'])[0] if vuln.get('fix', {}).get('versions') else 'latest'}",
                            image_ref=image_ref,
                        )
                    )
            except asyncio.TimeoutError:
                logger.warning("Grype scan timed out for %s", image_ref)
            except json.JSONDecodeError as e:
                logger.warning("Grype returned invalid JSON for %s: %s", image_ref, e.msg)
            except FileNotFoundError:
                logger.debug("Grype not found in PATH")
            except (OSError, ValueError, KeyError, RuntimeError) as e:
                logger.warning("Grype scan error for %s: %s", image_ref, type(e).__name__)

        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1

        elapsed = (time.time() - t0) * 1000
        return ContainerScanResult(
            scan_id=f"cont-{uuid.uuid4().hex[:12]}",
            target=image_ref,
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            trivy_available=self.trivy_available,
            grype_available=self.grype_available,
            duration_ms=round(elapsed, 2),
        )

    def scan_helm_chart(
        self, content: str, filename: str = "Chart.yaml"
    ) -> ContainerScanResult:
        """Scan Helm chart content (values.yaml, templates, Chart.yaml) for security issues."""
        import time

        t0 = time.time()
        findings: List[ContainerFinding] = []
        full_text = content

        # ── Parse Chart.yaml metadata if present ──
        chart_meta: Dict[str, Any] = {}
        if _HAS_YAML:
            try:
                parsed = _yaml.safe_load(content)
                if isinstance(parsed, dict):
                    chart_meta = parsed
            except Exception:
                pass

        # Check for deprecated API versions in Chart.yaml
        api_version = chart_meta.get("apiVersion", "")
        if api_version == "v1":
            findings.append(
                ContainerFinding(
                    finding_id=f"HELM-{uuid.uuid4().hex[:8]}",
                    title="Deprecated Helm Chart API Version",
                    severity=ContainerSeverity.LOW,
                    category="helm",
                    cwe_id="CWE-1104",
                    description="Chart uses apiVersion v1 (deprecated) — use v2 for Helm 3+",
                    recommendation="Update apiVersion to 'v2' in Chart.yaml",
                )
            )

        # Check for missing appVersion
        if chart_meta and not chart_meta.get("appVersion"):
            findings.append(
                ContainerFinding(
                    finding_id=f"HELM-{uuid.uuid4().hex[:8]}",
                    title="Missing appVersion in Chart.yaml",
                    severity=ContainerSeverity.INFO,
                    category="helm",
                    cwe_id="CWE-1104",
                    description="Chart.yaml missing appVersion — makes tracking deployed versions difficult",
                    recommendation="Add appVersion field to Chart.yaml",
                )
            )

        # ── Pattern-based rules ──
        for rule in HELM_CHART_RULES:
            pattern = rule["pattern"]
            anti_pattern = rule.get("anti_pattern")

            if re.search(pattern, full_text, re.IGNORECASE | re.MULTILINE):
                # If anti_pattern is defined, only flag if anti_pattern is ABSENT
                if anti_pattern and re.search(anti_pattern, full_text, re.IGNORECASE | re.MULTILINE):
                    continue
                # Find line number of first match
                line_num = 0
                for i, line in enumerate(content.split("\n"), 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        line_num = i
                        break
                findings.append(
                    ContainerFinding(
                        finding_id=f"HELM-{uuid.uuid4().hex[:8]}",
                        title=rule["title"],
                        severity=ContainerSeverity(rule["severity"]),
                        category="helm",
                        cwe_id=rule["cwe"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        line_number=line_num,
                    )
                )

        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1

        elapsed = (time.time() - t0) * 1000
        return ContainerScanResult(
            scan_id=f"helm-{uuid.uuid4().hex[:12]}",
            target=filename,
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            trivy_available=self.trivy_available,
            grype_available=self.grype_available,
            duration_ms=round(elapsed, 2),
        )

    def scan_layer_secrets(
        self, content: str, filename: str = "Dockerfile"
    ) -> ContainerScanResult:
        """Scan Dockerfile/image layer content for hardcoded secrets and sensitive files."""
        import time

        t0 = time.time()
        findings: List[ContainerFinding] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for sp in LAYER_SECRET_PATTERNS:
                if re.search(sp["pattern"], stripped):
                    findings.append(
                        ContainerFinding(
                            finding_id=f"SEC-{uuid.uuid4().hex[:8]}",
                            title=f"Secret Detected: {sp['name']}",
                            severity=ContainerSeverity(sp["severity"]),
                            category="secrets",
                            cwe_id="CWE-798",
                            description=f"Potential {sp['name']} found in image layer at line {line_num}",
                            recommendation="Remove secret from Dockerfile. Use Docker secrets, Vault, or runtime environment injection.",
                            line_number=line_num,
                        )
                    )

        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1

        elapsed = (time.time() - t0) * 1000
        return ContainerScanResult(
            scan_id=f"sec-{uuid.uuid4().hex[:12]}",
            target=filename,
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            trivy_available=self.trivy_available,
            grype_available=self.grype_available,
            duration_ms=round(elapsed, 2),
        )


_scanner: Optional[ContainerImageScanner] = None


def get_container_scanner() -> ContainerImageScanner:
    global _scanner
    if _scanner is None:
        _scanner = ContainerImageScanner()
    return _scanner
