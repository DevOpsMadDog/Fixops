"""
aldeci_scan.py — ALDECI Developer CLI Scanner (Snyk-style).

Run local security scans without a server connection.

Subcommands:
  secrets [path]          — Regex-based secret detection
  docker [Dockerfile]     — Dockerfile misconfiguration scan
  deps [manifest]         — Dependency vulnerability scan
  code [path]             — Pattern-based SAST scan
  full [path]             — Run all scan types
  report                  — Print combined report from last run

Options:
  --format table|json|sarif   Output format (default: table)
  --min-severity critical|high|medium|low|info
  --upload                    Upload findings to ALDECI server
  --server URL                Server URL for upload
  --api-key KEY               API key for upload
  --config PATH               Config file (default: .aldeci.yml)
  --output FILE               Write output to file instead of stdout

Exit codes: 0=clean, 1=findings above threshold, 2=error

Usage::

    python -m cli.aldeci_scan secrets ./src
    python -m cli.aldeci_scan docker Dockerfile --format json
    python -m cli.aldeci_scan full . --min-severity high --upload --server http://localhost:8000
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Optional dependencies (graceful degradation)
# ---------------------------------------------------------------------------
try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# Colour helpers (no external deps)
# ---------------------------------------------------------------------------
_NO_COLOUR = not sys.stdout.isatty() or os.getenv("NO_COLOR") or os.getenv("ALDECI_NO_COLOR")

_COLOURS: Dict[str, str] = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "red":     "\033[31m",
    "yellow":  "\033[33m",
    "green":   "\033[32m",
    "cyan":    "\033[36m",
    "magenta": "\033[35m",
    "dim":     "\033[2m",
}

_SEV_COLOURS: Dict[str, str] = {
    "critical": "\033[41m\033[1m",   # bold red background
    "high":     "\033[31m\033[1m",   # bold red
    "medium":   "\033[33m\033[1m",   # bold yellow
    "low":      "\033[36m",          # cyan
    "info":     "\033[2m",           # dim
}

_SEV_BADGES: Dict[str, str] = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]    ",
    "medium":   "[MEDIUM]  ",
    "low":      "[LOW]     ",
    "info":     "[INFO]    ",
}


def _c(colour: str, text: str) -> str:
    if _NO_COLOUR:
        return text
    return f"{_COLOURS.get(colour, '')}{text}{_COLOURS['reset']}"


def _sev_badge(severity: str) -> str:
    sev = severity.lower()
    badge = _SEV_BADGES.get(sev, f"[{sev.upper():<8}]")
    if _NO_COLOUR:
        return badge
    return f"{_SEV_COLOURS.get(sev, '')}{badge}{_COLOURS['reset']}"


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------
_SEV_ORDER: Dict[str, int] = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
}


def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.get(sev.lower(), 99)


def _passes_filter(finding_sev: str, min_severity: str) -> bool:
    return _sev_rank(finding_sev) <= _sev_rank(min_severity)


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------
def _progress(current: int, total: int, label: str = "") -> None:
    if _NO_COLOUR or total == 0:
        return
    width = 30
    filled = int(width * current / total)
    bar = "#" * filled + "-" * (width - filled)
    pct = int(100 * current / total)
    print(f"\r  [{bar}] {pct:3d}%  {label:<40}", end="", flush=True)
    if current >= total:
        print()  # newline when done


# ---------------------------------------------------------------------------
# Finding data class (plain dict-based for zero external deps)
# ---------------------------------------------------------------------------
class Finding:
    __slots__ = (
        "scan_type", "rule_id", "title", "severity",
        "file_path", "line_number", "description",
        "recommendation", "matched_text",
    )

    def __init__(
        self,
        scan_type: str,
        rule_id: str,
        title: str,
        severity: str,
        file_path: str,
        line_number: int,
        description: str,
        recommendation: str = "",
        matched_text: str = "",
    ) -> None:
        self.scan_type = scan_type
        self.rule_id = rule_id
        self.title = title
        self.severity = severity.lower()
        self.file_path = file_path
        self.line_number = line_number
        self.description = description
        self.recommendation = recommendation
        self.matched_text = matched_text

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_type": self.scan_type,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "recommendation": self.recommendation,
            "matched_text": self.matched_text,
        }


# ---------------------------------------------------------------------------
# Config loader (.aldeci.yml)
# ---------------------------------------------------------------------------
_DEFAULT_CONFIG: Dict[str, Any] = {
    "min_severity": "low",
    "format": "table",
    "exclude_paths": [],
    "exclude_rules": [],
    "server": None,
    "api_key": None,
}


def _load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    paths_to_try: List[Path] = []
    if config_path:
        paths_to_try.append(Path(config_path))
    else:
        paths_to_try = [
            Path(".aldeci.yml"),
            Path(".aldeci.yaml"),
            Path("aldeci.yml"),
        ]

    for p in paths_to_try:
        if p.exists():
            if not _HAS_YAML:
                # Try simple key: value parsing as fallback
                for line in p.read_text().splitlines():
                    if ":" in line and not line.strip().startswith("#"):
                        k, _, v = line.partition(":")
                        cfg[k.strip()] = v.strip().strip("\"'")
            else:
                try:
                    data = _yaml.safe_load(p.read_text()) or {}
                    cfg.update(data)
                except Exception:
                    pass
            break
    return cfg


# ---------------------------------------------------------------------------
# SAST patterns (code scan)
# ---------------------------------------------------------------------------
_SAST_RULES: List[Dict[str, Any]] = [
    {
        "id": "SAST-001",
        "title": "eval() with dynamic input",
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "description": "eval() executes arbitrary code — never use with user input",
        "recommendation": "Replace with safe alternatives (ast.literal_eval, json.loads)",
        "languages": [".py"],
    },
    {
        "id": "SAST-002",
        "title": "exec() usage",
        "pattern": r"\bexec\s*\(",
        "severity": "high",
        "description": "exec() executes arbitrary code at runtime",
        "recommendation": "Avoid exec(); use explicit function calls",
        "languages": [".py"],
    },
    {
        "id": "SAST-003",
        "title": "subprocess with shell=True",
        "pattern": r"subprocess\.\w+\(.*shell\s*=\s*True",
        "severity": "high",
        "description": "shell=True enables shell injection via unsanitized input",
        "recommendation": "Pass command as list, remove shell=True",
        "languages": [".py"],
    },
    {
        "id": "SAST-004",
        "title": "SQL string interpolation",
        "pattern": r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%[sd]|f["\'].*SELECT|f["\'].*INSERT|f["\'].*UPDATE|f["\'].*DELETE',
        "severity": "critical",
        "description": "SQL query built with string formatting — SQL injection risk",
        "recommendation": "Use parameterized queries with ? or %s placeholders",
        "languages": [".py", ".js", ".ts"],
    },
    {
        "id": "SAST-005",
        "title": "Hardcoded IP address",
        "pattern": r'(?:"|\'|\b)((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:"|\'|\b)',
        "severity": "low",
        "description": "Hardcoded IP address — use configuration instead",
        "recommendation": "Move IP to environment variable or config file",
        "languages": [],  # all languages
        "exclude_pattern": r"127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255",
    },
    {
        "id": "SAST-006",
        "title": "MD5 usage",
        "pattern": r"\bmd5\b|hashlib\.md5|MD5\(",
        "severity": "medium",
        "description": "MD5 is cryptographically broken — not suitable for security use",
        "recommendation": "Use SHA-256 or bcrypt for password hashing",
        "languages": [".py", ".js", ".ts", ".java"],
    },
    {
        "id": "SAST-007",
        "title": "assert used for security check",
        "pattern": r"\bassert\s+\w.*(?:auth|permission|role|admin|token|key)",
        "severity": "medium",
        "description": "assert is disabled with -O flag — never use for security checks",
        "recommendation": "Use explicit if/raise instead of assert for security",
        "languages": [".py"],
    },
    {
        "id": "SAST-008",
        "title": "Pickle deserialization",
        "pattern": r"\bpickle\.load[s]?\s*\(",
        "severity": "high",
        "description": "pickle.loads deserializes arbitrary objects — RCE risk with untrusted data",
        "recommendation": "Use JSON or message-pack for data exchange",
        "languages": [".py"],
    },
    {
        "id": "SAST-009",
        "title": "Unvalidated redirect",
        "pattern": r'(?:redirect|window\.location)\s*[=(].*(?:request\.|req\.|params\.|query\.)',
        "severity": "medium",
        "description": "Open redirect with user-controlled destination",
        "recommendation": "Validate redirect URLs against an allowlist",
        "languages": [".py", ".js", ".ts"],
    },
    {
        "id": "SAST-010",
        "title": "Bare except clause",
        "pattern": r"except\s*:\s*$|except\s+Exception\s*:\s*$",
        "severity": "low",
        "description": "Bare except swallows all errors including KeyboardInterrupt",
        "recommendation": "Catch specific exception types",
        "languages": [".py"],
    },
    {
        "id": "SAST-011",
        "title": "XSS via innerHTML",
        "pattern": r"\.innerHTML\s*=",
        "severity": "high",
        "description": "innerHTML assignment may execute injected scripts",
        "recommendation": "Use textContent, createElement, or DOMPurify sanitization",
        "languages": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "SAST-012",
        "title": "dangerouslySetInnerHTML",
        "pattern": r"dangerouslySetInnerHTML",
        "severity": "medium",
        "description": "React dangerouslySetInnerHTML can enable XSS",
        "recommendation": "Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML",
        "languages": [".jsx", ".tsx", ".js", ".ts"],
    },
]

_SKIP_DIRS_SAST = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "dist", "build", ".cache", ".mypy_cache", ".pytest_cache",
    ".tox",
}

_SKIP_EXTS_SAST = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".wasm",
    ".pyc", ".pyo", ".class", ".jar", ".lock",
    ".min.js", ".min.css",
}

_CODE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cpp", ".h", ".swift", ".kt",
    ".sh", ".bash", ".zsh",
}

# ---------------------------------------------------------------------------
# Dependency vulnerability patterns
# ---------------------------------------------------------------------------
_KNOWN_VULN_DEPS: List[Dict[str, Any]] = [
    {
        "pkg": "log4j", "max_version": "2.17.0",
        "cve": "CVE-2021-44228", "severity": "critical",
        "title": "Log4Shell — Log4j JNDI injection RCE",
        "recommendation": "Upgrade log4j to >= 2.17.1",
    },
    {
        "pkg": "django", "max_version": "4.1.0",
        "cve": "CVE-2023-23969", "severity": "high",
        "title": "Django DoS via multipart form parsing",
        "recommendation": "Upgrade Django to >= 4.1.10",
    },
    {
        "pkg": "flask", "max_version": "2.2.0",
        "cve": "CVE-2023-25577", "severity": "high",
        "title": "Werkzeug multipart DoS (Flask dependency)",
        "recommendation": "Upgrade flask to >= 2.3.3",
    },
    {
        "pkg": "requests", "max_version": "2.20.0",
        "cve": "CVE-2018-18074", "severity": "medium",
        "title": "Requests credentials forwarded on redirect",
        "recommendation": "Upgrade requests to >= 2.20.0",
    },
    {
        "pkg": "pillow", "max_version": "9.0.0",
        "cve": "CVE-2023-44271", "severity": "high",
        "title": "Pillow uncontrolled resource consumption",
        "recommendation": "Upgrade Pillow to >= 10.0.1",
    },
    {
        "pkg": "cryptography", "max_version": "41.0.0",
        "cve": "CVE-2023-49083", "severity": "medium",
        "title": "cryptography NULL pointer dereference",
        "recommendation": "Upgrade cryptography to >= 41.0.6",
    },
    {
        "pkg": "pyjwt", "max_version": "2.4.0",
        "cve": "CVE-2022-29217", "severity": "high",
        "title": "PyJWT algorithm confusion / key confusion attack",
        "recommendation": "Upgrade PyJWT to >= 2.4.0",
    },
    {
        "pkg": "lodash", "max_version": "4.17.21",
        "cve": "CVE-2021-23337", "severity": "high",
        "title": "Lodash prototype pollution via zipObjectDeep",
        "recommendation": "Upgrade lodash to >= 4.17.21",
    },
    {
        "pkg": "axios", "max_version": "1.6.0",
        "cve": "CVE-2023-45857", "severity": "medium",
        "title": "Axios CSRF token exposure via custom headers",
        "recommendation": "Upgrade axios to >= 1.6.0",
    },
    {
        "pkg": "express", "max_version": "4.18.0",
        "cve": "CVE-2022-24999", "severity": "medium",
        "title": "Express.js open redirect vulnerability",
        "recommendation": "Upgrade express to >= 4.18.0",
    },
    {
        "pkg": "numpy", "max_version": "1.24.0",
        "cve": "CVE-2023-47248", "severity": "critical",
        "title": "PyArrow deserialization RCE (numpy ecosystem)",
        "recommendation": "Upgrade numpy to >= 1.26.0",
    },
    {
        "pkg": "urllib3", "max_version": "2.0.0",
        "cve": "CVE-2023-45803", "severity": "medium",
        "title": "urllib3 request body not stripped on redirect",
        "recommendation": "Upgrade urllib3 to >= 2.0.7",
    },
]


def _parse_version(v: str) -> tuple:
    """Parse version string to comparable tuple, ignoring non-numeric parts."""
    parts = []
    for seg in re.split(r"[.\-]", v):
        m = re.match(r"(\d+)", seg)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts)


def _version_lte(ver: str, max_ver: str) -> bool:
    """Return True if ver <= max_ver."""
    try:
        return _parse_version(ver) <= _parse_version(max_ver)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Scan implementations
# ---------------------------------------------------------------------------

def _run_secrets_scan(path: str, cfg: Dict[str, Any]) -> List[Finding]:
    """Scan path for secrets using suite-core SecretScanner."""
    findings: List[Finding] = []
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from core.secret_scanner import SecretScanner
        scanner = SecretScanner(db_path=str(Path(path).parent / ".aldeci_secrets_scan.db"))
        p = Path(path)
        exclude = cfg.get("exclude_paths", [])
        if p.is_dir():
            all_files = [
                f for f in p.rglob("*")
                if f.is_file()
                and not any(part in _SKIP_DIRS_SAST for part in f.parts)
                and f.suffix.lower() not in {".png", ".jpg", ".jpeg", ".gif", ".bmp",
                                              ".ico", ".pdf", ".zip", ".tar", ".gz",
                                              ".bz2", ".7z", ".exe", ".dll", ".so",
                                              ".dylib", ".bin", ".wasm", ".pyc",
                                              ".pyo", ".class", ".jar", ".lock"}
            ]
            total = len(all_files)
            for i, file_path in enumerate(all_files):
                rel = str(file_path.relative_to(p))
                if any(ex and re.search(ex, rel) for ex in exclude):
                    continue
                _progress(i + 1, total, rel[:40])
                secrets = scanner.scan_file(str(file_path))
                for s in secrets:
                    findings.append(Finding(
                        scan_type="secrets",
                        rule_id=s.type.value,
                        title=f"Secret detected: {s.type.value}",
                        severity=s.severity,
                        file_path=s.file_path,
                        line_number=s.line_number,
                        description=f"Potential secret of type {s.type.value}",
                        matched_text=s.matched_text_masked,
                        recommendation="Remove from source, rotate immediately, use env vars or a secrets manager",
                    ))
        else:
            secrets = scanner.scan_file(str(p))
            for s in secrets:
                findings.append(Finding(
                    scan_type="secrets",
                    rule_id=s.type.value,
                    title=f"Secret detected: {s.type.value}",
                    severity=s.severity,
                    file_path=s.file_path,
                    line_number=s.line_number,
                    description=f"Potential secret of type {s.type.value}",
                    matched_text=s.matched_text_masked,
                    recommendation="Remove from source, rotate immediately, use env vars or a secrets manager",
                ))
    except ImportError:
        findings.append(Finding(
            scan_type="secrets",
            rule_id="SEC-ERR",
            title="Secret scanner unavailable",
            severity="info",
            file_path=path,
            line_number=0,
            description="suite-core not in path — cannot run secret scan",
        ))
    finally:
        # Clean up temp db
        tmp_db = Path(path if Path(path).is_dir() else Path(path).parent) / ".aldeci_secrets_scan.db"
        if tmp_db.exists():
            try:
                tmp_db.unlink()
            except Exception:
                pass
    return findings


def _run_docker_scan(dockerfile_path: str, cfg: Dict[str, Any]) -> List[Finding]:
    """Scan a Dockerfile for misconfigurations via suite-core ContainerScanner."""
    findings: List[Finding] = []
    p = Path(dockerfile_path)
    if not p.exists():
        findings.append(Finding(
            scan_type="docker",
            rule_id="DOCK-ERR",
            title="Dockerfile not found",
            severity="info",
            file_path=dockerfile_path,
            line_number=0,
            description=f"File does not exist: {dockerfile_path}",
        ))
        return findings

    content = p.read_text(encoding="utf-8", errors="replace")
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from core.container_scanner import ContainerScanner
        scanner = ContainerScanner()
        result = scanner.scan_dockerfile(content, filename=p.name)
        for f in result.findings:
            findings.append(Finding(
                scan_type="docker",
                rule_id=f.finding_id,
                title=f.title,
                severity=f.severity.value,
                file_path=dockerfile_path,
                line_number=f.line_number,
                description=f.description,
                recommendation=f.recommendation,
            ))
    except ImportError:
        # Fallback: inline Dockerfile checks
        findings.extend(_run_docker_scan_inline(content, dockerfile_path))
    return findings


def _run_docker_scan_inline(content: str, filepath: str) -> List[Finding]:
    """Inline Dockerfile scanner — used when ContainerScanner unavailable."""
    findings: List[Finding] = []
    lines = content.splitlines()
    has_user = False
    has_healthcheck = False

    _rules = [
        ("CONT-001", "Running as Root", "high", r"^USER\s+root",
         "Container runs as root user",
         "Add USER directive with non-root user"),
        ("CONT-003", "Latest Tag", "medium", r"FROM\s+\S+:latest",
         "Using :latest tag — unpinned base image",
         "Pin to specific version tag or SHA digest"),
        ("CONT-006", "Secrets in ENV", "critical",
         r"ENV\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*\S+",
         "Secret value hardcoded in ENV directive",
         "Use build args with --secret or runtime env injection"),
        ("CONT-008", "Curl Pipe to Shell", "critical",
         r"(curl|wget)\s+.*\|\s*(sh|bash|zsh)",
         "Downloading and piping to shell — supply chain risk",
         "Download, verify checksum, then execute separately"),
    ]

    compiled = [(r[0], r[1], r[2], re.compile(r[3], re.IGNORECASE), r[4], r[5]) for r in _rules]

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^USER\s+(?!root)", stripped, re.IGNORECASE):
            has_user = True
        if re.match(r"^HEALTHCHECK", stripped, re.IGNORECASE):
            has_healthcheck = True

        for rule_id, title, sev, pattern, desc, rec in compiled:
            if pattern.search(stripped):
                findings.append(Finding(
                    scan_type="docker",
                    rule_id=rule_id,
                    title=title,
                    severity=sev,
                    file_path=filepath,
                    line_number=line_num,
                    description=desc,
                    recommendation=rec,
                ))

    if not has_user:
        findings.append(Finding(
            scan_type="docker",
            rule_id="CONT-002",
            title="No USER Directive",
            severity="high",
            file_path=filepath,
            line_number=0,
            description="Dockerfile has no USER directive (defaults to root)",
            recommendation="Add 'USER nonroot' before CMD/ENTRYPOINT",
        ))
    if not has_healthcheck:
        findings.append(Finding(
            scan_type="docker",
            rule_id="CONT-004",
            title="No HEALTHCHECK",
            severity="low",
            file_path=filepath,
            line_number=0,
            description="No HEALTHCHECK instruction",
            recommendation="Add HEALTHCHECK to enable container orchestrator health monitoring",
        ))
    return findings


def _run_deps_scan(manifest_path: str, cfg: Dict[str, Any]) -> List[Finding]:
    """Scan requirements.txt or package.json for known vulnerable dependencies."""
    findings: List[Finding] = []
    p = Path(manifest_path)
    if not p.exists():
        findings.append(Finding(
            scan_type="deps",
            rule_id="DEP-ERR",
            title="Manifest file not found",
            severity="info",
            file_path=manifest_path,
            line_number=0,
            description=f"File does not exist: {manifest_path}",
        ))
        return findings

    content = p.read_text(encoding="utf-8", errors="replace")
    name_lower = p.name.lower()

    if name_lower in ("requirements.txt", "requirements-dev.txt") or name_lower.endswith(".txt"):
        findings.extend(_scan_requirements_txt(content, manifest_path))
    elif name_lower == "package.json":
        findings.extend(_scan_package_json(content, manifest_path))
    elif name_lower in ("pipfile", "pipfile.lock"):
        findings.extend(_scan_requirements_txt(content, manifest_path))
    else:
        # Try requirements.txt format first, then package.json
        try:
            json.loads(content)
            findings.extend(_scan_package_json(content, manifest_path))
        except (json.JSONDecodeError, ValueError):
            findings.extend(_scan_requirements_txt(content, manifest_path))

    return findings


def _scan_requirements_txt(content: str, filepath: str) -> List[Finding]:
    findings: List[Finding] = []
    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Parse: package==version, package>=version, package~=version
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=~><!\^]{1,2}\s*([0-9][A-Za-z0-9\.\-]*)", line)
        if not m:
            continue
        pkg_name = m.group(1).lower().replace("-", "_").replace(".", "_")
        version = m.group(2)

        for rule in _KNOWN_VULN_DEPS:
            rule_pkg = rule["pkg"].lower().replace("-", "_").replace(".", "_")
            if pkg_name == rule_pkg and _version_lte(version, rule["max_version"]):
                findings.append(Finding(
                    scan_type="deps",
                    rule_id=rule["cve"],
                    title=rule["title"],
                    severity=rule["severity"],
                    file_path=filepath,
                    line_number=line_num,
                    description=f"{rule['cve']}: {rule['title']} (installed: {version}, vulnerable <= {rule['max_version']})",
                    recommendation=rule["recommendation"],
                    matched_text=line,
                ))
    return findings


def _scan_package_json(content: str, filepath: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return findings

    all_deps: Dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        all_deps.update(data.get(section, {}))

    for pkg_name, version_spec in all_deps.items():
        pkg_lower = pkg_name.lower()
        # Strip semver range chars: ^, ~, >=, =
        version = re.sub(r"^[\^~>=<\s]+", "", version_spec)

        for rule in _KNOWN_VULN_DEPS:
            if pkg_lower == rule["pkg"].lower() and _version_lte(version, rule["max_version"]):
                findings.append(Finding(
                    scan_type="deps",
                    rule_id=rule["cve"],
                    title=rule["title"],
                    severity=rule["severity"],
                    file_path=filepath,
                    line_number=0,
                    description=f"{rule['cve']}: {rule['title']} (installed: {version}, vulnerable <= {rule['max_version']})",
                    recommendation=rule["recommendation"],
                    matched_text=f'"{pkg_name}": "{version_spec}"',
                ))
    return findings


def _run_code_scan(path: str, cfg: Dict[str, Any]) -> List[Finding]:
    """Pattern-based SAST scan over source files."""
    findings: List[Finding] = []
    p = Path(path)
    exclude = cfg.get("exclude_paths", [])
    exclude_rules = set(cfg.get("exclude_rules", []))

    if p.is_dir():
        all_files = [
            f for f in p.rglob("*")
            if f.is_file()
            and f.suffix.lower() in _CODE_EXTS
            and not any(part in _SKIP_DIRS_SAST for part in f.parts)
            and not str(f).endswith(".min.js")
        ]
        total = len(all_files)
        for i, file_path in enumerate(all_files):
            rel = str(file_path.relative_to(p))
            if any(ex and re.search(ex, rel) for ex in exclude):
                continue
            _progress(i + 1, total, rel[:40])
            findings.extend(_scan_code_file(file_path, exclude_rules))
    elif p.is_file():
        findings.extend(_scan_code_file(p, exclude_rules))
    else:
        findings.append(Finding(
            scan_type="code",
            rule_id="CODE-ERR",
            title="Path not found",
            severity="info",
            file_path=path,
            line_number=0,
            description=f"Path does not exist: {path}",
        ))
    return findings


def _scan_code_file(file_path: Path, exclude_rules: set) -> List[Finding]:
    findings: List[Finding] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    ext = file_path.suffix.lower()
    lines = content.splitlines()

    for rule in _SAST_RULES:
        if rule["id"] in exclude_rules:
            continue
        lang_filter = rule.get("languages", [])
        if lang_filter and ext not in lang_filter:
            continue

        compiled = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
        exclude_pat = rule.get("exclude_pattern")
        compiled_excl = re.compile(exclude_pat, re.IGNORECASE) if exclude_pat else None

        for m in compiled.finditer(content):
            if compiled_excl and compiled_excl.search(m.group(0)):
                continue
            line_num = content[:m.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip()[:80] if line_num <= len(lines) else ""
            findings.append(Finding(
                scan_type="code",
                rule_id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                file_path=str(file_path),
                line_number=line_num,
                description=rule["description"],
                recommendation=rule["recommendation"],
                matched_text=snippet,
            ))

    return findings


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _format_table(findings: List[Finding], min_severity: str) -> str:
    filtered = [f for f in findings if _passes_filter(f.severity, min_severity)]
    if not filtered:
        return _c("green", "  No findings above threshold. Clean scan.")

    lines: List[str] = []
    # Group by scan_type
    by_type: Dict[str, List[Finding]] = {}
    for f in filtered:
        by_type.setdefault(f.scan_type, []).append(f)

    for scan_type, type_findings in sorted(by_type.items()):
        lines.append(_c("bold", f"\n  {scan_type.upper()} SCAN FINDINGS"))
        lines.append(_c("dim", "  " + "─" * 70))
        for f in sorted(type_findings, key=lambda x: _sev_rank(x.severity)):
            badge = _sev_badge(f.severity)
            loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
            lines.append(f"  {badge} [{f.rule_id}] {f.title}")
            lines.append(_c("dim", f"    Location: {loc}"))
            lines.append(f"    {f.description}")
            if f.recommendation:
                lines.append(_c("cyan", f"    Fix: {f.recommendation}"))
            if f.matched_text:
                lines.append(_c("dim", f"    Code: {f.matched_text[:80]}"))
            lines.append("")

    # Summary
    counts: Dict[str, int] = {}
    for f in filtered:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            summary_parts.append(f"{counts[sev]} {sev}")
    lines.append(_c("bold", f"  Total: {len(filtered)} findings  ({', '.join(summary_parts)})"))
    return "\n".join(lines)


def _format_json(findings: List[Finding], min_severity: str) -> str:
    filtered = [f for f in findings if _passes_filter(f.severity, min_severity)]
    output = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total": len(filtered),
        "findings": [f.to_dict() for f in filtered],
        "summary": {
            sev: sum(1 for f in filtered if f.severity == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
    }
    return json.dumps(output, indent=2)


def _format_sarif(findings: List[Finding], min_severity: str) -> str:
    """Produce SARIF 2.1.0 output."""
    filtered = [f for f in findings if _passes_filter(f.severity, min_severity)]
    _sev_to_sarif = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }

    # Collect unique rules
    rules_seen: Dict[str, Dict[str, Any]] = {}
    for f in filtered:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": re.sub(r"\W+", "_", f.title),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {"level": _sev_to_sarif.get(f.severity, "warning")},
                "help": {"text": f.recommendation or f.description},
            }

    results = []
    for f in filtered:
        result: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _sev_to_sarif.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": max(f.line_number, 1)},
                    }
                }
            ],
            "properties": {"severity": f.severity, "scanType": f.scan_type},
        }
        if f.matched_text:
            result["message"]["text"] += f"\n\nSnippet: {f.matched_text[:200]}"
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aldeci-scan",
                        "version": "1.0.0",
                        "informationUri": "https://aldeci.dev/docs/cli",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

def _upload_findings(
    findings: List[Finding],
    server: str,
    api_key: str,
    min_severity: str,
) -> bool:
    """Upload findings to ALDECI server. Returns True on success."""
    if not _HAS_REQUESTS:
        print(_c("yellow", "  Warning: 'requests' not installed — cannot upload"))
        return False

    filtered = [f for f in findings if _passes_filter(f.severity, min_severity)]
    payload = {
        "source": "aldeci-scan-cli",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "findings": [f.to_dict() for f in filtered],
    }
    try:
        resp = _requests.post(  # nosemgrep: dynamic-urllib-use-detected
            f"{server.rstrip('/')}/api/v1/scan/ingest",
            json=payload,
            headers={"X-API-Key": api_key},
            timeout=30,
        )
        resp.raise_for_status()
        print(_c("green", f"  Uploaded {len(filtered)} findings to {server}"))
        return True
    except Exception as exc:
        print(_c("red", f"  Upload failed: {exc}"))
        return False


# ---------------------------------------------------------------------------
# Report command (session state via JSON file)
# ---------------------------------------------------------------------------
_REPORT_CACHE = Path(".aldeci_scan_report.json")


def _save_report(findings: List[Finding]) -> None:
    _REPORT_CACHE.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2),
        encoding="utf-8",
    )


def _load_report() -> List[Finding]:
    if not _REPORT_CACHE.exists():
        return []
    try:
        data = json.loads(_REPORT_CACHE.read_text())
        findings = []
        for d in data:
            findings.append(Finding(
                scan_type=d.get("scan_type", "unknown"),
                rule_id=d.get("rule_id", ""),
                title=d.get("title", ""),
                severity=d.get("severity", "info"),
                file_path=d.get("file_path", ""),
                line_number=d.get("line_number", 0),
                description=d.get("description", ""),
                recommendation=d.get("recommendation", ""),
                matched_text=d.get("matched_text", ""),
            ))
        return findings
    except Exception:
        return []


# ---------------------------------------------------------------------------
# CLI entry points
# ---------------------------------------------------------------------------

def _print_header(scan_type: str, target: str) -> None:
    print()
    print(_c("bold", f"  ALDECI Security Scanner — {scan_type.upper()}"))
    print(_c("dim", f"  Target: {target}"))
    print(_c("dim", f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(_c("dim", "  " + "─" * 60))
    print()


def _render_output(
    findings: List[Finding],
    fmt: str,
    min_severity: str,
    output_file: Optional[str],
) -> str:
    if fmt == "json":
        text = _format_json(findings, min_severity)
    elif fmt == "sarif":
        text = _format_sarif(findings, min_severity)
    else:
        text = _format_table(findings, min_severity)

    if output_file:
        Path(output_file).write_text(text, encoding="utf-8")
        print(_c("green", f"  Report written to {output_file}"))
    else:
        print(text)
    return text


def cmd_secrets(args: argparse.Namespace, cfg: Dict[str, Any]) -> int:
    path = args.path or "."
    _print_header("secrets", path)
    findings = _run_secrets_scan(path, cfg)
    _save_report(findings)
    _render_output(findings, args.format, args.min_severity, getattr(args, "output", None))
    if args.upload:
        _upload_findings(findings, args.server or cfg.get("server", ""), args.api_key or cfg.get("api_key", ""), args.min_severity)
    filtered = [f for f in findings if _passes_filter(f.severity, args.min_severity)]
    return 1 if filtered else 0


def cmd_docker(args: argparse.Namespace, cfg: Dict[str, Any]) -> int:
    path = args.path or "Dockerfile"
    _print_header("docker", path)
    findings = _run_docker_scan(path, cfg)
    _save_report(findings)
    _render_output(findings, args.format, args.min_severity, getattr(args, "output", None))
    if args.upload:
        _upload_findings(findings, args.server or cfg.get("server", ""), args.api_key or cfg.get("api_key", ""), args.min_severity)
    filtered = [f for f in findings if _passes_filter(f.severity, args.min_severity)]
    return 1 if filtered else 0


def cmd_deps(args: argparse.Namespace, cfg: Dict[str, Any]) -> int:
    path = args.path or "requirements.txt"
    _print_header("deps", path)
    findings = _run_deps_scan(path, cfg)
    _save_report(findings)
    _render_output(findings, args.format, args.min_severity, getattr(args, "output", None))
    if args.upload:
        _upload_findings(findings, args.server or cfg.get("server", ""), args.api_key or cfg.get("api_key", ""), args.min_severity)
    filtered = [f for f in findings if _passes_filter(f.severity, args.min_severity)]
    return 1 if filtered else 0


def cmd_code(args: argparse.Namespace, cfg: Dict[str, Any]) -> int:
    path = args.path or "."
    _print_header("code (SAST)", path)
    findings = _run_code_scan(path, cfg)
    _save_report(findings)
    _render_output(findings, args.format, args.min_severity, getattr(args, "output", None))
    if args.upload:
        _upload_findings(findings, args.server or cfg.get("server", ""), args.api_key or cfg.get("api_key", ""), args.min_severity)
    filtered = [f for f in findings if _passes_filter(f.severity, args.min_severity)]
    return 1 if filtered else 0


def cmd_full(args: argparse.Namespace, cfg: Dict[str, Any]) -> int:
    path = args.path or "."
    _print_header("full scan", path)
    all_findings: List[Finding] = []

    print(_c("cyan", "  [1/4] Scanning for secrets..."))
    all_findings.extend(_run_secrets_scan(path, cfg))

    # Look for Dockerfiles in path
    p = Path(path)
    dockerfiles = list(p.rglob("Dockerfile")) + list(p.rglob("Dockerfile.*")) if p.is_dir() else [p]
    if p.is_dir() and dockerfiles:
        print(_c("cyan", f"  [2/4] Scanning {len(dockerfiles)} Dockerfile(s)..."))
        for df in dockerfiles:
            all_findings.extend(_run_docker_scan(str(df), cfg))
    elif p.is_file() and p.name.startswith("Dockerfile"):
        print(_c("cyan", "  [2/4] Scanning Dockerfile..."))
        all_findings.extend(_run_docker_scan(path, cfg))
    else:
        print(_c("dim", "  [2/4] No Dockerfiles found — skipping docker scan"))

    # Look for dependency manifests
    manifests: List[Path] = []
    if p.is_dir():
        for name in ("requirements.txt", "requirements-dev.txt", "package.json", "Pipfile"):
            manifests.extend(p.rglob(name))
    elif p.is_file() and p.name.lower() in ("requirements.txt", "package.json", "pipfile"):
        manifests = [p]

    if manifests:
        print(_c("cyan", f"  [3/4] Scanning {len(manifests)} dependency manifest(s)..."))
        for m in manifests:
            all_findings.extend(_run_deps_scan(str(m), cfg))
    else:
        print(_c("dim", "  [3/4] No dependency manifests found — skipping deps scan"))

    print(_c("cyan", "  [4/4] Running SAST code scan..."))
    all_findings.extend(_run_code_scan(path, cfg))

    _save_report(all_findings)
    _render_output(all_findings, args.format, args.min_severity, getattr(args, "output", None))
    if args.upload:
        _upload_findings(all_findings, args.server or cfg.get("server", ""), args.api_key or cfg.get("api_key", ""), args.min_severity)
    filtered = [f for f in all_findings if _passes_filter(f.severity, args.min_severity)]
    return 1 if filtered else 0


def cmd_report(args: argparse.Namespace, cfg: Dict[str, Any]) -> int:
    findings = _load_report()
    if not findings:
        print(_c("dim", "  No cached report found. Run a scan first."))
        return 0
    print(_c("bold", f"\n  ALDECI Cached Report ({len(findings)} total findings)"))
    _render_output(findings, args.format, args.min_severity, getattr(args, "output", None))
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _add_common_args(p: argparse.ArgumentParser) -> None:
    """Add shared options to a parser or subparser."""
    p.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (default: table)",
    )
    p.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="low",
        dest="min_severity",
        help="Minimum severity to report (default: low)",
    )
    p.add_argument(
        "--upload",
        action="store_true",
        help="Upload findings to ALDECI server",
    )
    p.add_argument("--server", default=None, help="ALDECI server URL")
    p.add_argument("--api-key", default=None, dest="api_key", help="API key for upload")
    p.add_argument("--config", default=None, help="Config file path (default: .aldeci.yml)")
    p.add_argument("--output", default=None, help="Write output to file")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aldeci-scan",
        description="ALDECI Developer Security Scanner — find secrets, misconfigs, vulns, and SAST issues locally.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aldeci-scan secrets ./src
  aldeci-scan docker Dockerfile --format json
  aldeci-scan deps requirements.txt --min-severity high
  aldeci-scan code ./src --format sarif --output results.sarif
  aldeci-scan full . --min-severity medium --upload --server http://localhost:8000 --api-key KEY
  aldeci-scan report --format table
        """,
    )
    # Top-level options (allow before subcommand)
    _add_common_args(parser)

    sub = parser.add_subparsers(dest="command", required=True)

    # secrets
    p_secrets = sub.add_parser("secrets", help="Scan for hardcoded secrets and credentials")
    p_secrets.add_argument("path", nargs="?", default=".", help="Directory or file to scan (default: .)")
    _add_common_args(p_secrets)

    # docker
    p_docker = sub.add_parser("docker", help="Scan Dockerfile for misconfigurations")
    p_docker.add_argument("path", nargs="?", default="Dockerfile", help="Dockerfile path (default: ./Dockerfile)")
    _add_common_args(p_docker)

    # deps
    p_deps = sub.add_parser("deps", help="Scan dependency manifest for known vulnerabilities")
    p_deps.add_argument("path", nargs="?", default="requirements.txt", help="Manifest path (default: requirements.txt)")
    _add_common_args(p_deps)

    # code
    p_code = sub.add_parser("code", help="SAST pattern-based code scan")
    p_code.add_argument("path", nargs="?", default=".", help="Directory or file to scan (default: .)")
    _add_common_args(p_code)

    # full
    p_full = sub.add_parser("full", help="Run all scan types")
    p_full.add_argument("path", nargs="?", default=".", help="Root directory to scan (default: .)")
    _add_common_args(p_full)

    # report
    p_report = sub.add_parser("report", help="Print combined report from last scan")
    _add_common_args(p_report)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = _load_config(args.config)

    # CLI args override config file
    if args.format == "table" and cfg.get("format") and cfg["format"] != "table":
        args.format = cfg["format"]
    if args.min_severity == "low" and cfg.get("min_severity") and cfg["min_severity"] != "low":
        args.min_severity = cfg["min_severity"]

    dispatch = {
        "secrets": cmd_secrets,
        "docker":  cmd_docker,
        "deps":    cmd_deps,
        "code":    cmd_code,
        "full":    cmd_full,
        "report":  cmd_report,
    }

    try:
        handler = dispatch[args.command]
        return handler(args, cfg)
    except KeyboardInterrupt:
        print("\n  Scan interrupted.")
        return 2
    except Exception as exc:
        print(_c("red", f"  Error: {exc}"))
        return 2


if __name__ == "__main__":
    sys.exit(main())
