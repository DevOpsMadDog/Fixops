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


# Preserve reference to the dataclass before the Pydantic ContainerFinding
# redefinition (line ~904) shadows the name at module level.
_ContainerFindingDC = ContainerFinding


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

# ── Pre-compiled regex caches (module-load time, O(1) per scan call) ──────────
# DOCKERFILE_RULES: skip sentinel strings starting with "__"; compile the rest.
_DOCKERFILE_RULES_COMPILED: List[Tuple[str, str, str, str, "re.Pattern[str]", str, str]] = [
    (rid, title, sev, cwe, re.compile(pat, re.IGNORECASE), desc, rec)
    for rid, title, sev, cwe, pat, desc, rec in DOCKERFILE_RULES
    if not pat.startswith("__")
]

# HELM_CHART_RULES: compile pattern + optional anti_pattern per rule.
_HELM_RULES_COMPILED: List[Tuple[Dict[str, str], "re.Pattern[str]", "Optional[re.Pattern[str]]"]] = [
    (
        rule,
        re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE),
        re.compile(rule["anti_pattern"], re.IGNORECASE | re.MULTILINE)
        if rule.get("anti_pattern")
        else None,
    )
    for rule in HELM_CHART_RULES
]

# LAYER_SECRET_PATTERNS: compile pattern per entry.
_LAYER_SECRET_COMPILED: List[Tuple[Dict[str, str], "re.Pattern[str]"]] = [
    (sp, re.compile(sp["pattern"]))
    for sp in LAYER_SECRET_PATTERNS
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

            # Pattern-based rules (pre-compiled — no per-line recompilation)
            for rid, title, sev, cwe, pat, desc, rec in _DOCKERFILE_RULES_COMPILED:
                if pat.search(stripped):
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
        _emit_event("container.dockerfile_scanned", {"target": filename, "finding_count": len(findings), "elapsed_ms": round(elapsed, 1)})
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
        _emit_event("container.image_scanned", {"target": image_ref, "finding_count": len(findings), "elapsed_ms": round(elapsed, 1)})
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

        # ── Pattern-based rules (pre-compiled — no per-rule recompilation) ──
        for rule, pat_re, anti_re in _HELM_RULES_COMPILED:
            if pat_re.search(full_text):
                # If anti_pattern is defined, only flag if anti_pattern is ABSENT
                if anti_re and anti_re.search(full_text):
                    continue
                # Find line number of first match
                line_num = 0
                for i, line in enumerate(content.split("\n"), 1):
                    if pat_re.search(line):
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

            for sp, sp_re in _LAYER_SECRET_COMPILED:
                if sp_re.search(stripped):
                    findings.append(
                        _ContainerFindingDC(
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


# Forward-declare for get_security_scanner — resolved after ContainerSecurityScanner is defined
_security_scanner = None


def get_security_scanner():  # type: ignore[return]
    """Return singleton ContainerSecurityScanner (new Pydantic-based scanner)."""
    global _security_scanner
    if _security_scanner is None:
        _security_scanner = ContainerSecurityScanner()
    return _security_scanner


# =============================================================================
# ContainerSecurityScanner — structured Pydantic-based Dockerfile analysis
# Adds: Severity enum, CheckCategory enum, ContainerFinding (Pydantic),
#       DockerfileAnalysis, ContainerSecurityScanner with 20+ checks and
#       SQLite-backed history/stats.
# =============================================================================

import sqlite3
from pathlib import Path as _Path

from pydantic import BaseModel, Field

_SCANNER_DB_PATH = _Path(__file__).parent.parent.parent / "data" / "container_scanner.db"

_SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    2375: "Docker daemon (unencrypted)",
    2376: "Docker daemon (TLS)",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5601: "Kibana",
    8500: "Consul",
    2181: "ZooKeeper",
    4369: "Erlang Port Mapper",
}

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_\-]?key|private[_\-]?key|"
    r"access[_\-]?key|auth[_\-]?key|credential|passphrase|"
    r"db[_\-]?pass|database[_\-]?pass|jwt[_\-]?secret|oauth[_\-]?secret)",
    re.IGNORECASE,
)

_RISKY_PKGS = {
    "curl", "wget", "netcat", "nc", "ncat", "nmap", "telnet",
    "gcc", "g++", "make", "build-essential", "python3-dev",
    "openssh-server", "ftp", "rsh", "rlogin",
}

_TRUSTED_REGISTRIES = {
    "docker.io", "ghcr.io", "gcr.io", "quay.io", "mcr.microsoft.com",
    "registry.access.redhat.com", "registry.fedoraproject.org",
    "public.ecr.aws",
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckCategory(str, Enum):
    USER_PRIVILEGE = "user_privilege"
    SECRETS = "secrets"
    PACKAGES = "packages"
    BASE_IMAGE = "base_image"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    RUNTIME = "runtime"


class ContainerFinding(BaseModel):  # type: ignore[no-redef]  # shadows dataclass above intentionally
    """Pydantic finding model used by ContainerSecurityScanner."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    check_id: str
    title: str
    description: str
    severity: Severity
    category: CheckCategory
    line_number: Optional[int] = None
    remediation: str
    file_path: str = "Dockerfile"


class DockerfileAnalysis(BaseModel):
    """Full security analysis result for a Dockerfile."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str = "Dockerfile"
    findings: List[ContainerFinding] = Field(default_factory=list)
    base_image: str = ""
    user: str = "root"
    exposed_ports: List[int] = Field(default_factory=list)
    total_layers: int = 0
    score: float = Field(100.0, ge=0, le=100)
    org_id: str = "default"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ContainerSecurityScanner:
    """Analyse Dockerfiles for security misconfigurations (20+ checks)."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or str(_SCANNER_DB_PATH)
        self._init_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_dockerfile(
        self,
        content: str,
        file_path: str = "Dockerfile",
        org_id: str = "default",
    ) -> DockerfileAnalysis:
        """Parse *content* as a Dockerfile and return a full security analysis."""
        instructions = self._parse_dockerfile(content)

        findings: List[ContainerFinding] = []
        findings.extend(self._check_root_user(instructions, file_path))
        findings.extend(self._check_secrets(instructions, file_path))
        findings.extend(self._check_packages(instructions, file_path))
        findings.extend(self._check_base_image(instructions, file_path))
        findings.extend(self._check_network(instructions, file_path))
        findings.extend(self._check_filesystem(instructions, file_path))
        findings.extend(self._check_runtime(instructions, file_path, content))

        base_image = self._extract_base_image(instructions)
        user = self._extract_user(instructions)
        exposed_ports = self._extract_ports(instructions)
        total_layers = sum(1 for i in instructions if i["cmd"] in {"RUN", "COPY", "ADD"})
        score = self.score_analysis(findings)

        analysis = DockerfileAnalysis(
            file_path=file_path,
            findings=findings,
            base_image=base_image,
            user=user,
            exposed_ports=exposed_ports,
            total_layers=total_layers,
            score=score,
            org_id=org_id,
        )
        self._persist_analysis(analysis)
        return analysis

    def get_checks(self) -> List[Dict[str, Any]]:
        """Return metadata for all built-in checks."""
        return [
            {"id": "DKR-001", "category": CheckCategory.USER_PRIVILEGE, "severity": Severity.HIGH, "title": "Running as root (no USER directive)"},
            {"id": "DKR-002", "category": CheckCategory.USER_PRIVILEGE, "severity": Severity.HIGH, "title": "Explicit root USER directive"},
            {"id": "DKR-010", "category": CheckCategory.SECRETS, "severity": Severity.CRITICAL, "title": "Secret in ENV"},
            {"id": "DKR-011", "category": CheckCategory.SECRETS, "severity": Severity.CRITICAL, "title": "Secret in ARG"},
            {"id": "DKR-012", "category": CheckCategory.SECRETS, "severity": Severity.HIGH, "title": "Secret file copied into image"},
            {"id": "DKR-020", "category": CheckCategory.PACKAGES, "severity": Severity.MEDIUM, "title": "Risky package installed"},
            {"id": "DKR-021", "category": CheckCategory.PACKAGES, "severity": Severity.LOW, "title": "apt packages without version pins"},
            {"id": "DKR-022", "category": CheckCategory.PACKAGES, "severity": Severity.LOW, "title": "apt cache not cleaned"},
            {"id": "DKR-023", "category": CheckCategory.PACKAGES, "severity": Severity.LOW, "title": "apk add without --no-cache"},
            {"id": "DKR-030", "category": CheckCategory.BASE_IMAGE, "severity": Severity.HIGH, "title": "Base image uses :latest tag"},
            {"id": "DKR-031", "category": CheckCategory.BASE_IMAGE, "severity": Severity.MEDIUM, "title": "Base image not digest-pinned"},
            {"id": "DKR-032", "category": CheckCategory.BASE_IMAGE, "severity": Severity.MEDIUM, "title": "Untrusted base registry"},
            {"id": "DKR-033", "category": CheckCategory.BASE_IMAGE, "severity": Severity.LOW, "title": "Full OS base image"},
            {"id": "DKR-040", "category": CheckCategory.NETWORK, "severity": Severity.HIGH, "title": "Sensitive port exposed"},
            {"id": "DKR-041", "category": CheckCategory.NETWORK, "severity": Severity.MEDIUM, "title": "Privileged port exposed"},
            {"id": "DKR-050", "category": CheckCategory.FILESYSTEM, "severity": Severity.MEDIUM, "title": "Copying entire build context"},
            {"id": "DKR-051", "category": CheckCategory.FILESYSTEM, "severity": Severity.HIGH, "title": "Secret file added to image"},
            {"id": "DKR-052", "category": CheckCategory.FILESYSTEM, "severity": Severity.LOW, "title": "No read-only filesystem hint"},
            {"id": "DKR-060", "category": CheckCategory.RUNTIME, "severity": Severity.CRITICAL, "title": "Privileged mode hint"},
            {"id": "DKR-061", "category": CheckCategory.RUNTIME, "severity": Severity.HIGH, "title": "Dangerous capability hint"},
            {"id": "DKR-062", "category": CheckCategory.RUNTIME, "severity": Severity.MEDIUM, "title": "No HEALTHCHECK instruction"},
            {"id": "DKR-063", "category": CheckCategory.RUNTIME, "severity": Severity.INFO, "title": "No explicit SHELL instruction"},
        ]

    def score_analysis(self, findings: List[ContainerFinding]) -> float:
        """Return a 0-100 security score. 100 = no issues."""
        deductions: Dict[Severity, float] = {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 15.0,
            Severity.MEDIUM: 7.0,
            Severity.LOW: 3.0,
            Severity.INFO: 0.5,
        }
        total = sum(deductions.get(f.severity, 0) for f in findings)
        return max(0.0, round(100.0 - total, 1))

    def get_scan_history(self, org_id: str = "default") -> List[DockerfileAnalysis]:
        """Return all past analyses for *org_id*, most-recent first."""
        try:
            conn = sqlite3.connect(self._db_path)
            cur = conn.execute(
                "SELECT data FROM container_analyses WHERE org_id = ? ORDER BY scanned_at DESC",
                (org_id,),
            )
            rows = cur.fetchall()
            conn.close()
            return [DockerfileAnalysis.model_validate(json.loads(r[0])) for r in rows]
        except Exception as exc:
            logger.warning("get_scan_history failed: %s", exc)
            return []

    def get_scanner_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregate statistics for *org_id*."""
        history = self.get_scan_history(org_id)
        if not history:
            return {"total_scans": 0, "avg_score": 0.0, "total_findings": 0, "by_severity": {}, "by_category": {}}

        all_findings = [f for a in history for f in a.findings]
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for f in all_findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_category[f.category.value] = by_category.get(f.category.value, 0) + 1

        avg_score = round(sum(a.score for a in history) / len(history), 1)
        return {
            "total_scans": len(history),
            "avg_score": avg_score,
            "total_findings": len(all_findings),
            "by_severity": by_severity,
            "by_category": by_category,
        }

    # ------------------------------------------------------------------
    # Check methods
    # ------------------------------------------------------------------

    def _check_root_user(
        self, instructions: List[Dict[str, Any]], file_path: str
    ) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        user_instructions = [i for i in instructions if i["cmd"] == "USER"]

        if not user_instructions:
            findings.append(ContainerFinding(
                check_id="DKR-001",
                title="Container runs as root",
                description="No USER instruction found — container defaults to root.",
                severity=Severity.HIGH,
                category=CheckCategory.USER_PRIVILEGE,
                file_path=file_path,
                remediation="Add USER <nonroot> before CMD/ENTRYPOINT.",
            ))
        else:
            for instr in user_instructions:
                val = instr["value"].strip().lower()
                if val in {"root", "0", "0:0", "root:root"}:
                    findings.append(ContainerFinding(
                        check_id="DKR-002",
                        title="Explicit root USER directive",
                        description=f"USER is explicitly set to '{instr['value']}' on line {instr['line']}.",
                        severity=Severity.HIGH,
                        category=CheckCategory.USER_PRIVILEGE,
                        line_number=instr["line"],
                        file_path=file_path,
                        remediation="Change USER to a non-root user.",
                    ))
        return findings

    def _check_secrets(
        self, instructions: List[Dict[str, Any]], file_path: str
    ) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        for instr in instructions:
            cmd, value, line = instr["cmd"], instr["value"], instr["line"]

            if cmd == "ENV":
                pairs = re.findall(r"(\w+)\s*=\s*\S+", value)
                if not pairs:
                    parts = value.split(None, 1)
                    pairs = [parts[0]] if parts else []
                for key in pairs:
                    if _SECRET_KEY_RE.search(key):
                        findings.append(ContainerFinding(
                            check_id="DKR-010",
                            title=f"Secret-like ENV key: {key}",
                            description=f"ENV on line {line} contains key '{key}' — visible in docker inspect.",
                            severity=Severity.CRITICAL,
                            category=CheckCategory.SECRETS,
                            line_number=line,
                            file_path=file_path,
                            remediation="Use Docker secrets (--secret) or runtime env injection.",
                        ))

            elif cmd == "ARG":
                key = value.split("=")[0].split()[0] if value else ""
                if key and _SECRET_KEY_RE.search(key):
                    findings.append(ContainerFinding(
                        check_id="DKR-011",
                        title=f"Secret-like ARG key: {key}",
                        description=f"ARG on line {line} with key '{key}' is visible in image history.",
                        severity=Severity.CRITICAL,
                        category=CheckCategory.SECRETS,
                        line_number=line,
                        file_path=file_path,
                        remediation="Use --secret flag with BuildKit instead of ARG for secrets.",
                    ))

            elif cmd in {"COPY", "ADD"}:
                src_parts = value.split()
                for src in src_parts[:-1]:
                    fname = _Path(src).name.lower()
                    if _SECRET_KEY_RE.search(fname) or fname.endswith(
                        (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
                    ):
                        findings.append(ContainerFinding(
                            check_id="DKR-012",
                            title=f"Secret file copied: {src}",
                            description=f"Line {line}: COPY/ADD copies '{src}' which looks like a secret or key file.",
                            severity=Severity.HIGH,
                            category=CheckCategory.SECRETS,
                            line_number=line,
                            file_path=file_path,
                            remediation="Use BuildKit secret mounts (--mount=type=secret) instead.",
                        ))
        return findings

    def _check_packages(
        self, instructions: List[Dict[str, Any]], file_path: str
    ) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        for instr in instructions:
            if instr["cmd"] != "RUN":
                continue
            value, line = instr["value"], instr["line"]

            if re.search(r"apt-get\s+install|apt\s+install", value):
                for pkg in _RISKY_PKGS:
                    if re.search(rf"\b{re.escape(pkg)}\b", value):
                        findings.append(ContainerFinding(
                            check_id="DKR-020",
                            title=f"Risky package installed: {pkg}",
                            description=f"Line {line}: '{pkg}' increases attack surface in production images.",
                            severity=Severity.MEDIUM,
                            category=CheckCategory.PACKAGES,
                            line_number=line,
                            file_path=file_path,
                            remediation=f"Remove '{pkg}'. Use multi-stage builds to isolate build-time tools.",
                        ))
                pkgs_without_pin = re.findall(
                    r"apt(?:-get)?\s+install(?:\s+-\S+)*\s+((?:(?!\S+=\S+)\S+\s*)+)", value
                )
                if pkgs_without_pin:
                    findings.append(ContainerFinding(
                        check_id="DKR-021",
                        title="apt packages without version pins",
                        description=f"Line {line}: apt install without version pins produces non-reproducible builds.",
                        severity=Severity.LOW,
                        category=CheckCategory.PACKAGES,
                        line_number=line,
                        file_path=file_path,
                        remediation="Pin versions, e.g.: apt-get install -y curl=7.68.0-1",
                    ))
                if "rm -rf /var/lib/apt/lists" not in value:
                    findings.append(ContainerFinding(
                        check_id="DKR-022",
                        title="apt cache not cleaned",
                        description=f"Line {line}: apt-get install without cleaning cache bloats image layers.",
                        severity=Severity.LOW,
                        category=CheckCategory.PACKAGES,
                        line_number=line,
                        file_path=file_path,
                        remediation="Add '&& rm -rf /var/lib/apt/lists/*' after apt-get install.",
                    ))

            if re.search(r"apk\s+add", value):
                for pkg in _RISKY_PKGS:
                    if re.search(rf"\b{re.escape(pkg)}\b", value):
                        findings.append(ContainerFinding(
                            check_id="DKR-020",
                            title=f"Risky package installed: {pkg}",
                            description=f"Line {line}: Alpine package '{pkg}' is unnecessary in production.",
                            severity=Severity.MEDIUM,
                            category=CheckCategory.PACKAGES,
                            line_number=line,
                            file_path=file_path,
                            remediation=f"Remove '{pkg}' from the production image.",
                        ))
                if "--no-cache" not in value and "apk cache clean" not in value:
                    findings.append(ContainerFinding(
                        check_id="DKR-023",
                        title="apk add without --no-cache",
                        description=f"Line {line}: apk add without --no-cache leaves cache in image.",
                        severity=Severity.LOW,
                        category=CheckCategory.PACKAGES,
                        line_number=line,
                        file_path=file_path,
                        remediation="Use 'apk add --no-cache <package>'.",
                    ))
        return findings

    def _check_base_image(
        self, instructions: List[Dict[str, Any]], file_path: str
    ) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        for instr in [i for i in instructions if i["cmd"] == "FROM"]:
            raw_image = instr["value"].split()[0]
            line = instr["line"]
            if raw_image.upper() == "SCRATCH":
                continue

            if "@sha256:" in raw_image:
                pass  # pinned — no latest/digest findings
            elif ":" in raw_image:
                tag = raw_image.rsplit(":", 1)[1]
                if tag == "latest":
                    findings.append(ContainerFinding(
                        check_id="DKR-030",
                        title="Base image uses :latest tag",
                        description=f"Line {line}: FROM {raw_image} — :latest is non-deterministic.",
                        severity=Severity.HIGH,
                        category=CheckCategory.BASE_IMAGE,
                        line_number=line,
                        file_path=file_path,
                        remediation="Pin to a specific tag or @sha256 digest.",
                    ))
                else:
                    findings.append(ContainerFinding(
                        check_id="DKR-031",
                        title="Base image not digest-pinned",
                        description=f"Line {line}: '{raw_image}' has a tag but no @sha256 digest. Tags are mutable.",
                        severity=Severity.MEDIUM,
                        category=CheckCategory.BASE_IMAGE,
                        line_number=line,
                        file_path=file_path,
                        remediation="Append @sha256:<digest> for immutable pinning.",
                    ))
            else:
                findings.append(ContainerFinding(
                    check_id="DKR-030",
                    title="Base image uses implicit :latest tag",
                    description=f"Line {line}: FROM {raw_image} has no tag — defaults to :latest.",
                    severity=Severity.HIGH,
                    category=CheckCategory.BASE_IMAGE,
                    line_number=line,
                    file_path=file_path,
                    remediation="Pin to a specific version tag.",
                ))

            if "/" in raw_image:
                registry = raw_image.split("/")[0]
                if "." in registry and registry not in _TRUSTED_REGISTRIES:
                    findings.append(ContainerFinding(
                        check_id="DKR-032",
                        title=f"Untrusted registry: {registry}",
                        description=f"Line {line}: Registry '{registry}' is not in the trusted list.",
                        severity=Severity.MEDIUM,
                        category=CheckCategory.BASE_IMAGE,
                        line_number=line,
                        file_path=file_path,
                        remediation="Use images from trusted registries or mirror to your private registry.",
                    ))

            img_lower = raw_image.lower()
            base_name = img_lower.split("/")[-1].split(":")[0].split("@")[0]
            full_os = {"ubuntu", "debian", "centos", "fedora", "amazonlinux"}
            if base_name in full_os and "slim" not in img_lower and "alpine" not in img_lower:
                findings.append(ContainerFinding(
                    check_id="DKR-033",
                    title=f"Full OS base image: {base_name}",
                    description=f"Line {line}: Full OS base increases attack surface.",
                    severity=Severity.LOW,
                    category=CheckCategory.BASE_IMAGE,
                    line_number=line,
                    file_path=file_path,
                    remediation="Switch to a slim/alpine/distroless variant.",
                ))
        return findings

    def _check_network(
        self, instructions: List[Dict[str, Any]], file_path: str
    ) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        for instr in [i for i in instructions if i["cmd"] == "EXPOSE"]:
            line = instr["line"]
            for token in instr["value"].split():
                try:
                    port = int(token.split("/")[0])
                except ValueError:
                    continue
                if port in _SENSITIVE_PORTS:
                    findings.append(ContainerFinding(
                        check_id="DKR-040",
                        title=f"Sensitive port exposed: {port} ({_SENSITIVE_PORTS[port]})",
                        description=f"Line {line}: EXPOSE {port} exposes {_SENSITIVE_PORTS[port]}.",
                        severity=Severity.HIGH,
                        category=CheckCategory.NETWORK,
                        line_number=line,
                        file_path=file_path,
                        remediation=f"Remove EXPOSE {port} and restrict access via network policies.",
                    ))
                elif port < 1024:
                    findings.append(ContainerFinding(
                        check_id="DKR-041",
                        title=f"Privileged port exposed: {port}",
                        description=f"Line {line}: Ports below 1024 require elevated privileges.",
                        severity=Severity.MEDIUM,
                        category=CheckCategory.NETWORK,
                        line_number=line,
                        file_path=file_path,
                        remediation="Use a port >= 1024 or a reverse proxy.",
                    ))
        return findings

    def _check_filesystem(
        self, instructions: List[Dict[str, Any]], file_path: str
    ) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        for instr in instructions:
            cmd, value, line = instr["cmd"], instr["value"], instr["line"]
            if cmd not in {"COPY", "ADD"}:
                continue
            parts = value.split()
            if len(parts) >= 2:
                src = parts[0]
                if src in {".", "./"}:
                    findings.append(ContainerFinding(
                        check_id="DKR-050",
                        title="Copying entire build context",
                        description=f"Line {line}: 'COPY . .' risks including .env files and credentials.",
                        severity=Severity.MEDIUM,
                        category=CheckCategory.FILESYSTEM,
                        line_number=line,
                        file_path=file_path,
                        remediation="Use an explicit allowlist and maintain a .dockerignore file.",
                    ))
                fname = _Path(src).name.lower()
                if _SECRET_KEY_RE.search(fname) or fname.endswith(
                    (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".env")
                ):
                    findings.append(ContainerFinding(
                        check_id="DKR-051",
                        title=f"Secret file added to image: {src}",
                        description=f"Line {line}: '{src}' appears to be a credentials or key file.",
                        severity=Severity.HIGH,
                        category=CheckCategory.FILESYSTEM,
                        line_number=line,
                        file_path=file_path,
                        remediation="Use BuildKit secret mounts or inject secrets at runtime.",
                    ))

        findings.append(ContainerFinding(
            check_id="DKR-052",
            title="No read-only filesystem hint",
            description="No indication the container filesystem will be read-only at runtime.",
            severity=Severity.LOW,
            category=CheckCategory.FILESYSTEM,
            file_path=file_path,
            remediation="Run with --read-only and mount only required writable paths as tmpfs.",
        ))
        return findings

    def _check_runtime(
        self, instructions: List[Dict[str, Any]], file_path: str, raw_content: str = ""
    ) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        # Use raw content (includes comments/labels) so hints like `--privileged` in comments are caught
        full_text = (raw_content or "\n".join(f"{i['cmd']} {i['value']}" for i in instructions)).lower()

        if "--privileged" in full_text or "privileged=true" in full_text:
            findings.append(ContainerFinding(
                check_id="DKR-060",
                title="Privileged mode hint detected",
                description="Dockerfile references '--privileged' which disables all security boundaries.",
                severity=Severity.CRITICAL,
                category=CheckCategory.RUNTIME,
                file_path=file_path,
                remediation="Remove privileged mode. Use --cap-add for specific capabilities if needed.",
            ))

        dangerous_caps = ["cap_sys_admin", "sys_admin", "cap_net_admin", "net_admin", "cap_sys_ptrace", "sys_ptrace"]
        for cap in dangerous_caps:
            if cap in full_text:
                findings.append(ContainerFinding(
                    check_id="DKR-061",
                    title=f"Dangerous capability hint: {cap.upper()}",
                    description=f"Dockerfile references '{cap}' — grants elevated kernel privileges.",
                    severity=Severity.HIGH,
                    category=CheckCategory.RUNTIME,
                    file_path=file_path,
                    remediation="Avoid dangerous capabilities. Use least privilege and drop all unnecessary caps.",
                ))
                break

        if not any(i["cmd"] == "HEALTHCHECK" for i in instructions):
            findings.append(ContainerFinding(
                check_id="DKR-062",
                title="No HEALTHCHECK instruction",
                description="Without HEALTHCHECK, orchestrators cannot detect application-level failures.",
                severity=Severity.MEDIUM,
                category=CheckCategory.RUNTIME,
                file_path=file_path,
                remediation="Add: HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1",
            ))

        if not any(i["cmd"] == "SHELL" for i in instructions):
            findings.append(ContainerFinding(
                check_id="DKR-063",
                title="No explicit SHELL instruction",
                description="Container uses the default /bin/sh -c shell — less explicit and no pipefail.",
                severity=Severity.INFO,
                category=CheckCategory.RUNTIME,
                file_path=file_path,
                remediation='Add: SHELL ["/bin/bash", "-o", "pipefail", "-c"]',
            ))
        return findings

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_dockerfile(self, content: str) -> List[Dict[str, Any]]:
        """Parse Dockerfile content into instruction dicts with cmd, value, line keys."""
        instructions: List[Dict[str, Any]] = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            raw = lines[i].rstrip()
            line_num = i + 1
            stripped = raw.lstrip()
            if not stripped or stripped.startswith("#"):
                i += 1
                continue
            while raw.endswith("\\"):
                raw = raw[:-1].rstrip()
                i += 1
                if i < len(lines):
                    raw += " " + lines[i].lstrip()
            parts = raw.split(None, 1)
            if not parts:
                i += 1
                continue
            instructions.append({
                "cmd": parts[0].upper(),
                "value": parts[1].strip() if len(parts) > 1 else "",
                "line": line_num,
            })
            i += 1
        return instructions

    def _extract_base_image(self, instructions: List[Dict[str, Any]]) -> str:
        for i in instructions:
            if i["cmd"] == "FROM":
                return i["value"].split()[0]
        return ""

    def _extract_user(self, instructions: List[Dict[str, Any]]) -> str:
        user = "root"
        for i in instructions:
            if i["cmd"] == "USER":
                user = i["value"].strip()
        return user

    def _extract_ports(self, instructions: List[Dict[str, Any]]) -> List[int]:
        ports: List[int] = []
        for i in instructions:
            if i["cmd"] == "EXPOSE":
                for token in i["value"].split():
                    try:
                        ports.append(int(token.split("/")[0]))
                    except ValueError:
                        pass
        return ports

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        try:
            _Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS container_analyses (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    score REAL NOT NULL,
                    scanned_at TEXT NOT NULL,
                    data TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_org_scanned ON container_analyses (org_id, scanned_at)"
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("ContainerSecurityScanner DB init failed: %s", exc)

    def _persist_analysis(self, analysis: DockerfileAnalysis) -> None:
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT INTO container_analyses (id, org_id, file_path, score, scanned_at, data) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    analysis.id,
                    analysis.org_id,
                    analysis.file_path,
                    analysis.score,
                    analysis.scanned_at.isoformat(),
                    analysis.model_dump_json(),
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("ContainerSecurityScanner persist failed: %s", exc)
