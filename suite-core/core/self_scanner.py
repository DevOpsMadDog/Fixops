"""
Self-Scan Dogfooding Engine — ALDECI scans itself as its own test subject.

ALDECI uses its own security scanning capabilities against its own codebase,
dependencies, containers, config, and API surface. No demo data — real findings
from the actual source code, Dockerfiles, requirements.txt, and running API.

Features:
  1. SAST Self-Scan       — Python source: eval/exec, SQLi, secrets, unsafe ops
  2. Dependency Scan      — requirements.txt: offline CVE DB, licenses, depth
  3. Container Scan       — Dockerfiles: root user, secrets, missing HEALTHCHECK
  4. Config Audit         — debug flags, exposed keys, CORS, auth, encryption
  5. API Surface Audit    — unauthenticated endpoints, rate limits, validation
  6. Report Generation    — severity counts, risk score, compliance gaps
  7. CI Integration       — GitHub Actions workflow generator

Usage:
    from core.self_scanner import SelfScanEngine, get_self_scan_engine

    engine = get_self_scan_engine()
    report = engine.run_full_scan()
"""

from __future__ import annotations

import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum

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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = structlog.get_logger(__name__)

# Project root — two levels up from this file (suite-core/core/self_scanner.py)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Enums & constants
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanCategory(str, Enum):
    SAST = "sast"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    CONFIG = "config"
    API_SURFACE = "api_surface"


# Severity weights used for risk score calculation
_SEVERITY_WEIGHTS: Dict[str, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Maximum theoretical risk score (used to normalise to 0-100)
_MAX_RAW_SCORE = 400

# ---------------------------------------------------------------------------
# Offline CVE stub database (package -> list of (cve_id, severity, description))
# Real deployments would pull from NVD/OSV feeds; this is the offline fallback.
# ---------------------------------------------------------------------------
_OFFLINE_CVE_DB: Dict[str, List[Tuple[str, str, str]]] = {
    "pyyaml": [
        ("CVE-2017-18342", Severity.CRITICAL, "yaml.load() arbitrary code execution without Loader"),
        ("CVE-2020-14343", Severity.CRITICAL, "Full load of untrusted YAML can execute arbitrary code"),
    ],
    "requests": [
        ("CVE-2023-32681", Severity.MEDIUM, "Unintended leak of Proxy-Authorization header on redirect"),
    ],
    "cryptography": [
        ("CVE-2023-49083", Severity.HIGH, "NULL pointer dereference in PKCS12 parsing"),
        ("CVE-2024-26130", Severity.HIGH, "NULL dereference in PKCS12 serialize_key_and_certificates"),
    ],
    "pillow": [
        ("CVE-2023-50447", Severity.HIGH, "Arbitrary code execution via crafted image with ImageMath.eval"),
    ],
    "sqlalchemy": [
        ("CVE-2019-7164", Severity.HIGH, "SQL injection via order_by parameter"),
    ],
    "aiohttp": [
        ("CVE-2024-23334", Severity.HIGH, "Directory traversal via static file serving"),
        ("CVE-2024-23829", Severity.MEDIUM, "HTTP request smuggling via header parsing"),
    ],
    "reportlab": [
        ("CVE-2023-33733", Severity.CRITICAL, "Remote code execution via malicious PDF with RML injection"),
    ],
    "werkzeug": [
        ("CVE-2023-46136", Severity.HIGH, "DoS via large multipart upload"),
        ("CVE-2024-34069", Severity.HIGH, "Remote code execution in debug mode"),
    ],
    "jinja2": [
        ("CVE-2024-34064", Severity.MEDIUM, "XSS via xmlattr filter in Jinja2 templates"),
    ],
    "paramiko": [
        ("CVE-2023-48795", Severity.MEDIUM, "Terrapin attack prefix truncation via SSH protocol"),
    ],
    "urllib3": [
        ("CVE-2023-45803", Severity.MEDIUM, "Request body not stripped after 303 redirect"),
        ("CVE-2024-37891", Severity.MEDIUM, "Proxy-Authorization header leak on cross-origin redirect"),
    ],
}

# Packages considered abandoned (no meaningful update in 2+ years — stub list)
_ABANDONED_PACKAGES = {"sarif_om", "ssvc", "pgmpy"}

# License compatibility (permissive vs copyleft)
_COPYLEFT_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0", "EUPL-1.2"}
_LICENSE_MAP: Dict[str, str] = {
    "pyyaml": "MIT",
    "requests": "Apache-2.0",
    "cryptography": "Apache-2.0",
    "fastapi": "MIT",
    "uvicorn": "BSD-3-Clause",
    "sqlalchemy": "MIT",
    "aiohttp": "Apache-2.0",
    "reportlab": "BSD-3-Clause",
    "networkx": "BSD-3-Clause",
    "scikit_learn": "BSD-3-Clause",
    "pydantic": "MIT",
    "structlog": "Apache-2.0",
    "pgmpy": "MIT",
    "ssvc": "Apache-2.0",
    "sarif_om": "MIT",
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class SelfScanFinding(BaseModel):
    """A single finding produced by the self-scanner."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: ScanCategory
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp: Optional[str] = None
    recommendation: str
    confidence: float = Field(default=0.8)
    remediation_effort: str = "medium"  # low / medium / high
    tags: List[str] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class DependencyInfo(BaseModel):
    """Metadata for a single parsed dependency."""

    name: str
    version_spec: str
    cves: List[Dict[str, str]] = Field(default_factory=list)
    license: Optional[str] = None
    is_abandoned: bool = False
    transitive_depth: int = 0


class SelfScanReport(BaseModel):
    """Full self-scan report — ALDECI's own security posture."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    project_root: str
    duration_seconds: float = 0.0
    findings: List[SelfScanFinding] = Field(default_factory=list)
    dependencies: List[DependencyInfo] = Field(default_factory=list)
    risk_score: float = 0.0  # 0–100 (lower is better)
    grade: str = "A"  # A–F
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings_by_category: Dict[str, int] = Field(default_factory=dict)
    compliance_gaps: List[str] = Field(default_factory=list)
    remediation_priorities: List[str] = Field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    ci_workflow_yaml: Optional[str] = None

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})


# ---------------------------------------------------------------------------
# SAST scanner
# ---------------------------------------------------------------------------

# Patterns: (regex, title, severity, cwe, owasp, recommendation)
_SAST_PATTERNS: List[Tuple[re.Pattern, str, str, str, str, str]] = [
    (
        re.compile(r"\beval\s*\("),
        "Use of eval()",
        Severity.CRITICAL,
        "CWE-95",
        "A03:2021",
        "Replace eval() with safe alternatives (ast.literal_eval, json.loads). eval() executes arbitrary code.",
    ),
    (
        re.compile(r"\bexec\s*\("),
        "Use of exec()",
        Severity.HIGH,
        "CWE-95",
        "A03:2021",
        "Replace exec() with subprocess.run() with a fixed argument list and no shell=True.",
    ),
    (
        re.compile(r"""(?i)(?:password|passwd|secret|api[_-]?key|token|credential)\s*=\s*['"][^'"]{8,}['"]"""),
        "Hardcoded secret or credential",
        Severity.CRITICAL,
        "CWE-798",
        "A02:2021",
        "Store secrets in environment variables or a secrets manager. Never commit credentials to source.",
    ),
    (
        re.compile(r"""(?im)^[^\n]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^\n]*\+"""),
        "Potential SQL injection via string concatenation",
        Severity.HIGH,
        "CWE-89",
        "A03:2021",
        "Use parameterised queries (cursor.execute(query, params)) instead of string concatenation.",
    ),
    (
        re.compile(r"\bpickle\.load[s]?\s*\("),
        "Insecure deserialization via pickle",
        Severity.HIGH,
        "CWE-502",
        "A08:2021",
        "Avoid pickle for untrusted data. Use json.loads() or msgpack with schema validation.",
    ),
    (
        re.compile(r"\bexcept\s*:\s*$|except\s+Exception\s*:\s*$", re.MULTILINE),
        "Bare except block swallows all exceptions",
        Severity.MEDIUM,
        "CWE-390",
        "A05:2021",
        "Catch specific exceptions. Bare except hides bugs and makes debugging difficult.",
    ),
    (
        re.compile(r"""(?i)debug\s*=\s*True"""),
        "Debug mode enabled",
        Severity.HIGH,
        "CWE-215",
        "A05:2021",
        "Disable debug mode in production (DEBUG=False). Debug mode leaks stack traces and may enable code execution.",
    ),
    (
        re.compile(r"\bos\.system\s*\(|\bsubprocess\.call\s*\(.*shell\s*=\s*True|\bsubprocess\.run\s*\(.*shell\s*=\s*True"),
        "Unsafe shell command execution",
        Severity.HIGH,
        "CWE-78",
        "A03:2021",
        "Use subprocess.run() with a list of arguments and shell=False. Validate all inputs.",
    ),
    (
        re.compile(r"\bopen\s*\([^)]*['\"]w['\"]|Path\([^)]+\)\.write_text\("),
        "Unsafe file write — check path traversal",
        Severity.LOW,
        "CWE-22",
        "A01:2021",
        "Validate file paths against an allowed base directory before writing.",
    ),
    (
        re.compile(r"(?i)hashlib\.md5\s*\(|hashlib\.sha1\s*\("),
        "Weak cryptographic hash (MD5/SHA1)",
        Severity.MEDIUM,
        "CWE-327",
        "A02:2021",
        "Use SHA-256 or SHA-3 for security-sensitive hashing. MD5/SHA1 are cryptographically broken.",
    ),
    (
        re.compile(r"(?i)allow_origins\s*=\s*\[?\s*['\"]?\*['\"]?\s*\]?"),
        "Permissive CORS — wildcard origin",
        Severity.MEDIUM,
        "CWE-346",
        "A05:2021",
        "Restrict CORS origins to known domains. Wildcard origins allow cross-site requests from any origin.",
    ),
    (
        re.compile(r"(?i)verify\s*=\s*False"),
        "TLS certificate verification disabled",
        Severity.HIGH,
        "CWE-295",
        "A02:2021",
        "Never disable TLS certificate verification in production. Use proper CA bundle.",
    ),
    (
        re.compile(r"(?i)#\s*TODO|#\s*FIXME|#\s*HACK|#\s*XXX"),
        "Technical debt marker in production code",
        Severity.INFO,
        "CWE-1041",
        "A05:2021",
        "Resolve or ticket technical debt markers before shipping to production.",
    ),
    (
        re.compile(r"\bprint\s*\("),
        "Raw print() — use structured logging",
        Severity.INFO,
        "CWE-532",
        "A09:2021",
        "Replace print() with structlog logger calls to enable structured, level-aware logging.",
    ),
]


def _scan_python_file(file_path: Path, root: Path) -> List[SelfScanFinding]:
    """Run SAST pattern matching on a single Python file."""
    findings: List[SelfScanFinding] = []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    rel_path = str(file_path.relative_to(root))
    lines = source.splitlines()

    for pattern, title, severity, cwe, owasp, recommendation in _SAST_PATTERNS:
        for match in pattern.finditer(source):
            line_no = source[: match.start()].count("\n") + 1
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.SAST,
                    severity=severity,
                    title=title,
                    description=f"Detected in {rel_path}:{line_no} — {snippet[:120]}",
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=snippet[:200],
                    cwe_id=cwe,
                    owasp=owasp,
                    recommendation=recommendation,
                    confidence=0.75,
                    tags=["sast", "auto-detected"],
                )
            )

    return findings


def run_sast_scan(root: Path, max_files: int = 200) -> Tuple[List[SelfScanFinding], int, int]:
    """
    Walk all Python source files under root and apply SAST pattern checks.

    Returns (findings, files_scanned, lines_scanned).
    Skips test files, venv directories, __pycache__, and migration scripts.
    """
    findings: List[SelfScanFinding] = []
    files_scanned = 0
    lines_scanned = 0

    skip_dirs = {
        "__pycache__", ".venv", "venv", "env", "node_modules",
        ".git", "migrations", "alembic", "dist", "build",
        "site-packages", ".mypy_cache", ".pytest_cache",
    }
    skip_prefixes = ("test_", "_test", "conftest")

    py_files: List[Path] = []
    for py_file in root.rglob("*.py"):
        # Skip excluded directories
        if any(part in skip_dirs for part in py_file.parts):
            continue
        # Skip test/conftest files in the scan (they test the scanner itself)
        if py_file.name.startswith(skip_prefixes):
            continue
        py_files.append(py_file)
        if len(py_files) >= max_files:
            break

    for py_file in py_files:
        file_findings = _scan_python_file(py_file, root)
        findings.extend(file_findings)
        try:
            lines_scanned += py_file.read_text(encoding="utf-8", errors="replace").count("\n")
        except OSError:
            pass
        files_scanned += 1

    logger.info(
        "sast_scan_complete",
        files=files_scanned,
        lines=lines_scanned,
        findings=len(findings),
    )
    return findings, files_scanned, lines_scanned


# ---------------------------------------------------------------------------
# Dependency scanner
# ---------------------------------------------------------------------------

def _parse_requirements(req_path: Path) -> List[DependencyInfo]:
    """Parse requirements.txt into DependencyInfo objects."""
    deps: List[DependencyInfo] = []
    if not req_path.exists():
        return deps

    for raw_line in req_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip environment markers: package>=1.0; python_version >= "3.10"
        line = line.split(";")[0].strip()
        # Extract package name (before any version specifier)
        match = re.match(r"^([A-Za-z0-9_.\-]+)(.*)", line)
        if not match:
            continue
        name = match.group(1).lower().replace("-", "_").replace(".", "_")
        version_spec = match.group(2).strip() or "*"
        deps.append(
            DependencyInfo(
                name=name,
                version_spec=version_spec,
                license=_LICENSE_MAP.get(name),
                is_abandoned=name in _ABANDONED_PACKAGES,
            )
        )
    return deps


def run_dependency_scan(root: Path) -> Tuple[List[SelfScanFinding], List[DependencyInfo]]:
    """
    Scan requirements.txt for CVEs, license issues, and abandoned packages.

    Returns (findings, dependency_info_list).
    """
    findings: List[SelfScanFinding] = []
    req_path = root / "requirements.txt"
    deps = _parse_requirements(req_path)

    # Transitive depth heuristic — groups of packages by indirect dependency likelihood
    _transitive_heavy = {"requests", "httpx", "aiohttp", "sqlalchemy", "cryptography"}
    for dep in deps:
        canonical = dep.name.replace("_", "").lower()
        dep.transitive_depth = 3 if canonical in _transitive_heavy else 1

    # CVE check (offline database)
    for dep in deps:
        cve_entries = _OFFLINE_CVE_DB.get(dep.name.replace("_", ""), [])
        if not cve_entries:
            # Also try without underscores
            cve_entries = _OFFLINE_CVE_DB.get(dep.name, [])

        for cve_id, sev, description in cve_entries:
            dep.cves.append({"cve_id": cve_id, "severity": sev, "description": description})
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.DEPENDENCY,
                    severity=sev,
                    title=f"{cve_id} in {dep.name}",
                    description=description,
                    file_path="requirements.txt",
                    cwe_id="CWE-1104",
                    owasp="A06:2021",
                    recommendation=f"Upgrade {dep.name} to a patched version. Check https://osv.dev for fix versions.",
                    confidence=0.9,
                    tags=["dependency", "cve", cve_id.lower()],
                    remediation_effort="low",
                )
            )

    # License compatibility check
    for dep in deps:
        if dep.license in _COPYLEFT_LICENSES:
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.DEPENDENCY,
                    severity=Severity.MEDIUM,
                    title=f"Copyleft license: {dep.name} ({dep.license})",
                    description=f"Package {dep.name} uses {dep.license} which may require open-sourcing your code.",
                    file_path="requirements.txt",
                    owasp="A06:2021",
                    recommendation="Consult legal team on copyleft license obligations for commercial products.",
                    confidence=0.95,
                    tags=["dependency", "license"],
                    remediation_effort="high",
                )
            )

    # Abandoned package check
    for dep in deps:
        if dep.is_abandoned:
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.DEPENDENCY,
                    severity=Severity.MEDIUM,
                    title=f"Potentially abandoned package: {dep.name}",
                    description=f"Package {dep.name} shows no recent releases and may no longer be maintained.",
                    file_path="requirements.txt",
                    owasp="A06:2021",
                    recommendation="Replace with a maintained alternative or vendor the package internally.",
                    confidence=0.6,
                    tags=["dependency", "abandoned"],
                    remediation_effort="medium",
                )
            )

    # Deep transitive dependency warning
    deep_deps = [d for d in deps if d.transitive_depth >= 3]
    if deep_deps:
        names = ", ".join(d.name for d in deep_deps[:5])
        findings.append(
            SelfScanFinding(
                category=ScanCategory.DEPENDENCY,
                severity=Severity.LOW,
                title="Deep transitive dependency chain detected",
                description=f"Packages with deep transitive deps ({names}) increase supply-chain attack surface.",
                file_path="requirements.txt",
                owasp="A06:2021",
                recommendation="Pin all transitive dependencies. Use pip-compile or poetry.lock for reproducible builds.",
                confidence=0.7,
                tags=["dependency", "supply-chain"],
                remediation_effort="medium",
            )
        )

    logger.info("dependency_scan_complete", deps=len(deps), findings=len(findings))
    return findings, deps


# ---------------------------------------------------------------------------
# Container scanner
# ---------------------------------------------------------------------------

_DOCKERFILE_CHECKS: List[Tuple[re.Pattern, str, str, str, str, str]] = [
    (
        re.compile(r"^\s*USER\s+root\s*$", re.MULTILINE),
        "Container runs as root user",
        Severity.HIGH,
        "CWE-250",
        "A05:2021",
        "Add 'USER nonroot' or create a dedicated service user. Running as root grants full host access on escape.",
    ),
    (
        re.compile(r"^\s*COPY\s+.*(?:\.env|secret|credential|password|\.pem|\.key|id_rsa)\b", re.MULTILINE | re.IGNORECASE),
        "Potential secret file copied into image",
        Severity.CRITICAL,
        "CWE-538",
        "A02:2021",
        "Never COPY secrets into Docker images. Use Docker secrets, environment variables, or a secrets manager.",
    ),
    (
        re.compile(r"^\s*EXPOSE\s+(22|23|3389|5900)\s*$", re.MULTILINE),
        "Sensitive management port exposed",
        Severity.HIGH,
        "CWE-16",
        "A05:2021",
        "Do not expose SSH/RDP/VNC ports in production images. Use bastion hosts for administrative access.",
    ),
    (
        re.compile(r"^\s*FROM\s+\S+:latest\s*$", re.MULTILINE | re.IGNORECASE),
        "Unpinned base image (:latest tag)",
        Severity.MEDIUM,
        "CWE-1104",
        "A06:2021",
        "Pin base images to a specific digest or version tag for reproducible, auditable builds.",
    ),
    (
        re.compile(r"(?s)^(?!.*HEALTHCHECK).*$"),
        "No HEALTHCHECK instruction defined",
        Severity.LOW,
        "CWE-778",
        "A05:2021",
        "Add a HEALTHCHECK instruction so orchestrators can detect and restart unhealthy containers.",
    ),
    (
        re.compile(r"^\s*RUN\s+.*&&.*&&.*&&.*&&.*&&", re.MULTILINE),
        "Excessive RUN layer chaining — consider BuildKit cache mounts",
        Severity.INFO,
        "CWE-1041",
        "A05:2021",
        "Use BuildKit cache mounts (--mount=type=cache) to reduce layer count without sacrificing caching.",
    ),
    (
        re.compile(r"(?i)apt-get install(?!.*--no-install-recommends)"),
        "apt-get install without --no-install-recommends",
        Severity.LOW,
        "CWE-1041",
        "A05:2021",
        "Add --no-install-recommends to apt-get install to reduce image size and attack surface.",
    ),
    (
        re.compile(r"^\s*ADD\s+https?://", re.MULTILINE),
        "ADD with remote URL — use curl/wget + checksum instead",
        Severity.MEDIUM,
        "CWE-494",
        "A08:2021",
        "Replace ADD <url> with RUN curl ... | sha256sum -c to verify integrity of downloaded files.",
    ),
]


def run_container_scan(root: Path) -> List[SelfScanFinding]:
    """
    Scan all Dockerfiles under root for container security issues.

    Returns list of findings.
    """
    findings: List[SelfScanFinding] = []

    dockerfile_paths: List[Path] = list(root.rglob("Dockerfile*"))
    dockerfile_paths += list(root.rglob("*.dockerfile"))

    # Also check docker-compose files for hardcoded secrets
    compose_files: List[Path] = [
        p for p in root.rglob("docker-compose*.yml")
        if ".git" not in str(p) and "node_modules" not in str(p)
    ]

    for df_path in dockerfile_paths:
        if any(skip in str(df_path) for skip in (".git", "node_modules", ".venv")):
            continue
        try:
            content = df_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_path = str(df_path.relative_to(root))

        # Check for missing HEALTHCHECK by examining full file content
        if "HEALTHCHECK" not in content:
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.CONTAINER,
                    severity=Severity.LOW,
                    title="No HEALTHCHECK instruction defined",
                    description=f"Dockerfile {rel_path} has no HEALTHCHECK. Orchestrators cannot detect unhealthy containers.",
                    file_path=rel_path,
                    cwe_id="CWE-778",
                    owasp="A05:2021",
                    recommendation="Add a HEALTHCHECK instruction so orchestrators can detect and restart unhealthy containers.",
                    confidence=0.95,
                    tags=["container", "healthcheck"],
                    remediation_effort="low",
                )
            )

        for pattern, title, severity, cwe, owasp, recommendation in _DOCKERFILE_CHECKS:
            # Skip the HEALTHCHECK regex pattern — handled above
            if "HEALTHCHECK" in pattern.pattern:
                continue
            for match in pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                snippet = match.group(0).strip()[:150]
                findings.append(
                    SelfScanFinding(
                        category=ScanCategory.CONTAINER,
                        severity=severity,
                        title=title,
                        description=f"Detected in {rel_path}:{line_no}",
                        file_path=rel_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        cwe_id=cwe,
                        owasp=owasp,
                        recommendation=recommendation,
                        confidence=0.85,
                        tags=["container", "dockerfile"],
                        remediation_effort="low",
                    )
                )

    # Docker-compose secret leak check
    for compose_path in compose_files:
        try:
            compose_content = compose_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = str(compose_path.relative_to(root))
        secret_pattern = re.compile(
            r"""(?i)(?:password|secret|api[_-]?key|token)\s*:\s*['"]?[A-Za-z0-9+/=_\-]{12,}['"]?"""
        )
        for match in secret_pattern.finditer(compose_content):
            line_no = compose_content[: match.start()].count("\n") + 1
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.CONTAINER,
                    severity=Severity.HIGH,
                    title="Potential hardcoded secret in docker-compose",
                    description=f"Found possible hardcoded credential in {rel_path}:{line_no}",
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=match.group(0)[:100],
                    cwe_id="CWE-798",
                    owasp="A02:2021",
                    recommendation="Move secrets to .env file (excluded from git) or use Docker secrets.",
                    confidence=0.7,
                    tags=["container", "secrets", "docker-compose"],
                    remediation_effort="low",
                )
            )

    logger.info("container_scan_complete", dockerfiles=len(dockerfile_paths), findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# Config auditor
# ---------------------------------------------------------------------------

_CONFIG_PATTERNS: List[Tuple[re.Pattern, str, str, str, str, str]] = [
    (
        re.compile(r"(?i)debug\s*[=:]\s*(?:true|1|yes|on)"),
        "Debug mode enabled in configuration",
        Severity.HIGH,
        "CWE-215",
        "A05:2021",
        "Set DEBUG=False / debug=false in all production configurations.",
    ),
    (
        re.compile(r"""(?i)(?:api[_-]?key|secret|password|token)\s*[=:]\s*['"]?[A-Za-z0-9+/=_\-]{20,}['"]?"""),
        "API key or secret exposed in config file",
        Severity.CRITICAL,
        "CWE-798",
        "A02:2021",
        "Remove hardcoded secrets. Use environment variables and a secrets manager.",
    ),
    (
        re.compile(r"(?i)allow[_-]?origins?\s*[=:]\s*['\"]?\*['\"]?|\bCORS_ORIGINS?\s*[=:]\s*['\"]?\*['\"]?"),
        "Permissive CORS wildcard in config",
        Severity.MEDIUM,
        "CWE-346",
        "A05:2021",
        "Restrict CORS to specific trusted origins.",
    ),
    (
        re.compile(r"(?i)auth(?:entication)?\s*[=:]\s*(?:false|disabled|off|0|none)"),
        "Authentication disabled in config",
        Severity.CRITICAL,
        "CWE-306",
        "A07:2021",
        "Never disable authentication. Enable mandatory auth for all production environments.",
    ),
    (
        re.compile(r"(?i)(?:ssl|tls)[_-]?verify\s*[=:]\s*(?:false|0|no|off)"),
        "TLS verification disabled in config",
        Severity.HIGH,
        "CWE-295",
        "A02:2021",
        "Always verify TLS certificates. Use a valid CA bundle.",
    ),
    (
        re.compile(r"(?i)(?:aes[_-]?128|des3?|rc4|blowfish)\b"),
        "Weak encryption algorithm referenced in config",
        Severity.MEDIUM,
        "CWE-327",
        "A02:2021",
        "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption.",
    ),
    (
        re.compile(r"(?i)rate[_-]?limit\s*[=:]\s*(?:false|disabled|0|none|off)"),
        "Rate limiting disabled in config",
        Severity.MEDIUM,
        "CWE-770",
        "A05:2021",
        "Enable rate limiting to protect against brute force and DoS attacks.",
    ),
    (
        re.compile(r"(?i)log[_-]?level\s*[=:]\s*(?:debug|trace|verbose)"),
        "Verbose logging in production config",
        Severity.LOW,
        "CWE-532",
        "A09:2021",
        "Use INFO or WARNING log level in production to avoid leaking sensitive data in logs.",
    ),
]

_CONFIG_EXTENSIONS = {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".json"}
_CONFIG_SKIP = {"node_modules", ".git", "__pycache__", ".venv", "venv", "test", "tests"}


def run_config_audit(root: Path) -> List[SelfScanFinding]:
    """
    Audit configuration files for security misconfigurations.

    Returns list of findings.
    """
    findings: List[SelfScanFinding] = []

    config_files: List[Path] = []
    for ext in _CONFIG_EXTENSIONS:
        for p in root.rglob(f"*{ext}"):
            if any(skip in p.parts for skip in _CONFIG_SKIP):
                continue
            # Skip very large files (likely data files, not config)
            try:
                if p.stat().st_size > 500_000:
                    continue
            except OSError:
                continue
            config_files.append(p)

    for config_path in config_files:
        try:
            content = config_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = str(config_path.relative_to(root))

        for pattern, title, severity, cwe, owasp, recommendation in _CONFIG_PATTERNS:
            for match in pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                snippet = match.group(0).strip()[:100]
                findings.append(
                    SelfScanFinding(
                        category=ScanCategory.CONFIG,
                        severity=severity,
                        title=title,
                        description=f"Config issue in {rel_path}:{line_no} — {snippet}",
                        file_path=rel_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        cwe_id=cwe,
                        owasp=owasp,
                        recommendation=recommendation,
                        confidence=0.8,
                        tags=["config", "misconfiguration"],
                        remediation_effort="low",
                    )
                )

    logger.info("config_audit_complete", config_files=len(config_files), findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# API surface auditor
# ---------------------------------------------------------------------------

_AUTH_DEPS = re.compile(
    r"Depends\s*\(\s*(?:_verify_api_key|api_key_auth|require_auth|get_current_user|_require_scope)\b"
)
_ROUTE_DEF = re.compile(
    r"""@router\.(get|post|put|patch|delete|options)\s*\(\s*['"]([^'"]+)['"]"""
)
_RATE_LIMIT = re.compile(r"(?i)rate[_-]?limit|RateLimiter|slowapi|throttle")
_INPUT_VALIDATION = re.compile(r"(?:BaseModel|Pydantic|validator|field_validator|Query\(|Body\(|Path\()")
_VERBOSE_ERROR = re.compile(r"(?i)traceback|exc_info|str\(e\)|repr\(e\)|raise.*from|detail\s*=\s*str\(")


def run_api_surface_audit(root: Path) -> List[SelfScanFinding]:
    """
    Enumerate API endpoints from router files and audit for security gaps.

    Checks for: unauthenticated endpoints, missing rate limits, verbose errors,
    missing input validation, overly permissive scopes.

    Returns list of findings.
    """
    findings: List[SelfScanFinding] = []
    router_dir = root / "suite-api" / "apps" / "api"

    if not router_dir.exists():
        logger.warning("api_surface_audit_skipped", reason="router_dir_not_found")
        return findings

    router_files = list(router_dir.glob("*_router.py"))
    unauthenticated_routes: List[Dict[str, Any]] = []
    total_routes = 0

    for router_file in router_files:
        if router_file.name in ("auth_router.py", "auth_deps.py", "dependencies.py"):
            # Auth files are intentionally public
            continue
        try:
            content = router_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_path = str(router_file.relative_to(root))
        has_file_level_auth = bool(_AUTH_DEPS.search(content))
        has_rate_limit = bool(_RATE_LIMIT.search(content))
        has_input_validation = bool(_INPUT_VALIDATION.search(content))

        # Check for verbose error responses
        if _VERBOSE_ERROR.search(content):
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.API_SURFACE,
                    severity=Severity.MEDIUM,
                    title=f"Verbose error responses in {router_file.name}",
                    description=(
                        f"Router {rel_path} may return detailed exception info "
                        "to clients, leaking internal implementation details."
                    ),
                    file_path=rel_path,
                    cwe_id="CWE-209",
                    owasp="A05:2021",
                    recommendation="Return generic error messages to clients. Log full details server-side only.",
                    confidence=0.65,
                    tags=["api", "information-disclosure"],
                    remediation_effort="medium",
                )
            )

        # Per-endpoint check
        for match in _ROUTE_DEF.finditer(content):
            method = match.group(1).upper()
            path = match.group(2)
            total_routes += 1

            # Look for auth in the 5 lines after the decorator
            decorator_end = match.end()
            nearby = content[decorator_end: decorator_end + 300]
            endpoint_has_auth = has_file_level_auth or bool(_AUTH_DEPS.search(nearby))

            if not endpoint_has_auth:
                unauthenticated_routes.append(
                    {"method": method, "path": path, "file": rel_path}
                )

        if not has_rate_limit and has_file_level_auth:
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.API_SURFACE,
                    severity=Severity.MEDIUM,
                    title=f"Missing rate limiting in {router_file.name}",
                    description=f"Router {rel_path} has authentication but no visible rate limiting.",
                    file_path=rel_path,
                    cwe_id="CWE-770",
                    owasp="A05:2021",
                    recommendation="Add rate limiting via slowapi or middleware to prevent brute force attacks.",
                    confidence=0.7,
                    tags=["api", "rate-limit"],
                    remediation_effort="medium",
                )
            )

        if not has_input_validation:
            findings.append(
                SelfScanFinding(
                    category=ScanCategory.API_SURFACE,
                    severity=Severity.LOW,
                    title=f"No explicit input validation in {router_file.name}",
                    description=f"Router {rel_path} does not appear to use Pydantic models or FastAPI validators.",
                    file_path=rel_path,
                    cwe_id="CWE-20",
                    owasp="A03:2021",
                    recommendation="Use Pydantic BaseModel for request bodies and FastAPI Query/Path for parameters.",
                    confidence=0.6,
                    tags=["api", "input-validation"],
                    remediation_effort="medium",
                )
            )

    # Report unauthenticated endpoints (batch into one finding to avoid noise)
    if unauthenticated_routes:
        route_list = "; ".join(
            f"{r['method']} {r['path']}" for r in unauthenticated_routes[:10]
        )
        severity = Severity.HIGH if len(unauthenticated_routes) > 5 else Severity.MEDIUM
        findings.append(
            SelfScanFinding(
                category=ScanCategory.API_SURFACE,
                severity=severity,
                title=f"{len(unauthenticated_routes)} potentially unauthenticated API endpoints",
                description=f"Endpoints without detected auth dependency: {route_list}{'...' if len(unauthenticated_routes) > 10 else ''}",
                cwe_id="CWE-306",
                owasp="A07:2021",
                recommendation="Add Depends(api_key_auth) or Depends(_verify_api_key) to all protected endpoints.",
                confidence=0.6,
                tags=["api", "authentication", "unauthenticated"],
                remediation_effort="medium",
            )
        )

    logger.info(
        "api_surface_audit_complete",
        total_routes=total_routes,
        unauthenticated=len(unauthenticated_routes),
        findings=len(findings),
    )
    return findings


# ---------------------------------------------------------------------------
# Risk scoring & report generation
# ---------------------------------------------------------------------------

def _compute_risk_score(findings: List[SelfScanFinding]) -> Tuple[float, str]:
    """
    Compute a normalised risk score (0–100) and letter grade.

    Lower score = better security posture.
    """
    raw = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) * f.confidence for f in findings)
    score = min(100.0, round(raw / max(_MAX_RAW_SCORE, 1) * 100, 1))

    if score <= 10:
        grade = "A"
    elif score <= 25:
        grade = "B"
    elif score <= 45:
        grade = "C"
    elif score <= 65:
        grade = "D"
    else:
        grade = "F"

    return score, grade


def _compute_compliance_gaps(findings: List[SelfScanFinding]) -> List[str]:
    """Map findings to compliance control gaps."""
    gaps: set[str] = set()
    owasp_map = {f.owasp for f in findings if f.owasp}
    cwe_map = {f.cwe_id for f in findings if f.cwe_id}

    if "A02:2021" in owasp_map:
        gaps.add("SOC2 CC6.1 — Encryption of sensitive data at rest and in transit")
    if "A03:2021" in owasp_map:
        gaps.add("OWASP Top 10 A03 — Injection vulnerability remediation required")
    if "A06:2021" in owasp_map:
        gaps.add("NIST SP 800-53 SA-15 — Software and supply-chain vulnerability management")
    if "A07:2021" in owasp_map:
        gaps.add("ISO 27001 A.9 — Access control and authentication gaps identified")
    if "A05:2021" in owasp_map:
        gaps.add("CIS Benchmark Level 1 — Security misconfiguration remediation required")
    if "CWE-798" in cwe_map:
        gaps.add("PCI-DSS 3.4 — Hardcoded credentials violate cardholder data protection")
    if "CWE-502" in cwe_map:
        gaps.add("HIPAA 164.312(a)(2)(iv) — Insecure deserialization risk to PHI integrity")
    if any(sev == Severity.CRITICAL for sev, *_ in [(f.severity,) for f in findings]):
        gaps.add("FedRAMP Moderate — Critical findings must be remediated within 30 days")

    return sorted(gaps)


def _compute_remediation_priorities(findings: List[SelfScanFinding]) -> List[str]:
    """Generate ordered remediation priority list."""
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]
    medium = [f for f in findings if f.severity == Severity.MEDIUM]

    priorities: List[str] = []
    if critical:
        titles = ", ".join(dict.fromkeys(f.title for f in critical[:3]))
        priorities.append(f"[P0 — IMMEDIATE] Fix {len(critical)} critical finding(s): {titles}")
    if high:
        titles = ", ".join(dict.fromkeys(f.title for f in high[:3]))
        priorities.append(f"[P1 — THIS SPRINT] Resolve {len(high)} high-severity issue(s): {titles}")
    if medium:
        priorities.append(f"[P2 — NEXT SPRINT] Address {len(medium)} medium-severity findings")

    dep_cves = [f for f in findings if "cve" in f.tags and f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if dep_cves:
        priorities.append(f"[P1 — DEPENDENCY] Upgrade {len(dep_cves)} packages with known CVEs")

    priorities.append("[P3 — ONGOING] Integrate self-scan into CI pipeline (see ci_workflow_yaml)")
    return priorities


def generate_ci_workflow(project_root: Path) -> str:
    """Generate a GitHub Actions workflow YAML that runs self-scan on every push."""
    return """\
# .github/workflows/self-scan.yml
# ALDECI Self-Scan — runs on every push and PR.
# Fails CI if critical findings are introduced.
# Generated by ALDECI SelfScanEngine.

name: ALDECI Self-Scan

on:
  push:
    branches: ["**"]
  pull_request:
    branches: [main, "features/**"]
  schedule:
    # Nightly full scan at 02:00 UTC
    - cron: "0 2 * * *"

permissions:
  contents: read
  security-events: write

jobs:
  self-scan:
    name: ALDECI Self-Scan Dogfooding
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Run ALDECI self-scan
        id: self_scan
        env:
          SELF_SCAN_PROJECT_ROOT: ${{ github.workspace }}
          SELF_SCAN_MAX_SAST_FILES: "300"
          SELF_SCAN_FAIL_ON_CRITICAL: "true"
        run: |
          python -c "
          import json, sys, os
          sys.path.insert(0, 'suite-core')
          from core.self_scanner import get_self_scan_engine
          engine = get_self_scan_engine()
          report = engine.run_full_scan()
          print(json.dumps(report.model_dump(mode='json'), indent=2, default=str))
          criticals = report.findings_by_severity.get('critical', 0)
          print(f'Risk score: {report.risk_score} (Grade: {report.grade})', file=sys.stderr)
          print(f'Critical findings: {criticals}', file=sys.stderr)
          if os.getenv('SELF_SCAN_FAIL_ON_CRITICAL') == 'true' and criticals > 0:
              print(f'CI FAIL: {criticals} critical finding(s) detected', file=sys.stderr)
              sys.exit(1)
          " | tee self-scan-results.json

      - name: Upload self-scan results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: aldeci-self-scan-${{ github.sha }}
          path: self-scan-results.json
          retention-days: 30

      - name: Comment PR with scan summary
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('self-scan-results.json', 'utf8'));
            const body = [
              '## ALDECI Self-Scan Results',
              `**Risk Score:** ${report.risk_score} (Grade: ${report.grade})`,
              `**Findings:** Critical: ${report.findings_by_severity?.critical || 0} | High: ${report.findings_by_severity?.high || 0} | Medium: ${report.findings_by_severity?.medium || 0}`,
              '',
              '> Generated by ALDECI Self-Scan Dogfooding Engine'
            ].join('\\n');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body
            });
"""


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class SelfScanEngine:
    """
    ALDECI Self-Scan Dogfooding Engine.

    Orchestrates all scan modules (SAST, dependency, container, config,
    API surface) and produces a unified SelfScanReport.
    """

    def __init__(self, project_root: Optional[Path] = None, max_sast_files: int = 200) -> None:
        self.project_root = project_root or _PROJECT_ROOT
        self.max_sast_files = int(
            os.getenv("SELF_SCAN_MAX_SAST_FILES", str(max_sast_files))
        )
        self._lock = threading.Lock()
        self._latest_report: Optional[SelfScanReport] = None
        self._log = structlog.get_logger(__name__).bind(engine="SelfScanEngine")

    def run_full_scan(self) -> SelfScanReport:
        """
        Execute the complete self-scan pipeline.

        Runs SAST, dependency, container, config, and API surface audits,
        then computes risk score, compliance gaps, and remediation priorities.
        """
        t_start = time.monotonic()
        self._log.info("self_scan_started", root=str(self.project_root))

        all_findings: List[SelfScanFinding] = []

        # 1. SAST
        sast_findings, files_scanned, lines_scanned = run_sast_scan(
            self.project_root, max_files=self.max_sast_files
        )
        all_findings.extend(sast_findings)

        # 2. Dependency
        dep_findings, deps = run_dependency_scan(self.project_root)
        all_findings.extend(dep_findings)

        # 3. Container
        container_findings = run_container_scan(self.project_root)
        all_findings.extend(container_findings)

        # 4. Config
        config_findings = run_config_audit(self.project_root)
        all_findings.extend(config_findings)

        # 5. API Surface
        api_findings = run_api_surface_audit(self.project_root)
        all_findings.extend(api_findings)

        # Risk score & compliance
        risk_score, grade = _compute_risk_score(all_findings)
        compliance_gaps = _compute_compliance_gaps(all_findings)
        remediation_priorities = _compute_remediation_priorities(all_findings)

        # Counts
        findings_by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
        findings_by_category: Dict[str, int] = {c.value: 0 for c in ScanCategory}
        for f in all_findings:
            findings_by_severity[f.severity] = findings_by_severity.get(f.severity, 0) + 1
            findings_by_category[f.category] = findings_by_category.get(f.category, 0) + 1

        ci_yaml = generate_ci_workflow(self.project_root)

        report = SelfScanReport(
            project_root=str(self.project_root),
            duration_seconds=round(time.monotonic() - t_start, 2),
            findings=all_findings,
            dependencies=deps,
            risk_score=risk_score,
            grade=grade,
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
            compliance_gaps=compliance_gaps,
            remediation_priorities=remediation_priorities,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            ci_workflow_yaml=ci_yaml,
        )

        with self._lock:
            self._latest_report = report

        self._log.info(
            "self_scan_complete",
            scan_id=report.scan_id,
            duration=report.duration_seconds,
            total_findings=len(all_findings),
            risk_score=risk_score,
            grade=grade,
        )
        _emit_event("self_scan.completed", {"scan_id": report.scan_id, "total_findings": len(all_findings), "risk_score": risk_score, "grade": grade, "duration_seconds": report.duration_seconds})
        return report

    def get_latest_report(self) -> Optional[SelfScanReport]:
        """Return the most recently completed scan report, or None."""
        with self._lock:
            return self._latest_report

    def get_findings_by_category(self, category: Optional[ScanCategory] = None) -> List[SelfScanFinding]:
        """Return findings from the latest report, optionally filtered by category."""
        with self._lock:
            report = self._latest_report
        if report is None:
            return []
        if category is None:
            return report.findings
        return [f for f in report.findings if f.category == category]

    def get_security_score(self) -> Dict[str, Any]:
        """Return a concise score summary from the latest report."""
        with self._lock:
            report = self._latest_report
        if report is None:
            return {
                "score": None,
                "grade": None,
                "scanned_at": None,
                "message": "No scan has been run yet. POST /api/v1/self-scan/run to trigger.",
            }
        return {
            "scan_id": report.scan_id,
            "score": report.risk_score,
            "grade": report.grade,
            "scanned_at": report.scanned_at.isoformat(),
            "total_findings": len(report.findings),
            "findings_by_severity": report.findings_by_severity,
            "top_priorities": report.remediation_priorities[:3],
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[SelfScanEngine] = None
_engine_lock = threading.Lock()


def get_self_scan_engine() -> SelfScanEngine:
    """Return the shared SelfScanEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = SelfScanEngine()
    return _engine_instance
