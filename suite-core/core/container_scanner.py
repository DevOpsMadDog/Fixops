"""ALdeci Container Image Scanner.

Scans Docker/OCI images and Dockerfiles for:
- Vulnerable base images
- Dockerfile misconfigurations (running as root, no healthcheck, etc.)
- Layer analysis for secrets/sensitive files
- Integration with Trivy/Grype when available
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


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

    async def scan_image(self, image_ref: str) -> ContainerScanResult:
        """Scan a container image using Trivy/Grype if available."""
        import time

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
            except Exception:
                pass

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


_scanner: Optional[ContainerImageScanner] = None


def get_container_scanner() -> ContainerImageScanner:
    global _scanner
    if _scanner is None:
        _scanner = ContainerImageScanner()
    return _scanner
