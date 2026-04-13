#!/usr/bin/env python3
"""
ALdeci Self-Scan Bootstrap — Real data from ALDECI's own security posture.

On first boot, ALDECI scans itself:
  - SAST: own Python source code
  - Secrets: own config files, env files, docker-compose
  - IaC/Dockerfile: own container configuration
  - SCA: own requirements.txt for vulnerable dependencies
  - SBOM: CycloneDX SBOM from own dependencies
  - License compliance: own dep licenses
  - Brain Pipeline: all findings ingested as real data
  - TrustGraph: indexed into Knowledge Core 2 (Threat Intelligence) +
                Core 5 (Self-Assessment)

This IS the demo — real security posture data, no mocked fixtures.

Usage:
    python scripts/self_scan.py
    ALDECI_BASE_URL=http://localhost:8000 python scripts/self_scan.py

Environment:
    ALDECI_BASE_URL      API base URL (default: http://localhost:8000)
    FIXOPS_API_TOKEN     API key
    SELF_SCAN_ORG_ID     Org ID for findings (default: aldeci-self)
    SELF_SCAN_MAX_FILES  Max source files to SAST scan (default: 20)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = os.getenv("ALDECI_BASE_URL", "http://localhost:8000")
API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
ORG_ID = os.getenv("SELF_SCAN_ORG_ID", "aldeci-self")
MAX_SAST_FILES = int(os.getenv("SELF_SCAN_MAX_FILES", "20"))
ROOT = Path(__file__).resolve().parent.parent

HEADERS = {"X-API-Key": API_TOKEN, "Content-Type": "application/json"}

# ANSI colours
G, R, Y, C, M, D, B, X = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m",
    "\033[95m", "\033[2m", "\033[1m", "\033[0m",
)

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
log = logging.getLogger("self_scan")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_pass = 0
_fail = 0
_total = 0
_step_open = False
_step_status: Optional[str] = None  # "passed" | "failed" | None

ALL_FINDINGS: List[Dict[str, Any]] = []
SCAN_SUMMARY: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _finalize_step() -> None:
    global _pass, _fail, _step_open, _step_status
    if not _step_open:
        return
    if _step_status == "passed":
        _pass += 1
    elif _step_status == "failed":
        _fail += 1
    _step_open = False
    _step_status = None


def _mark_passed() -> None:
    global _step_status
    if _step_open and _step_status is None:
        _step_status = "passed"


def _mark_failed() -> None:
    global _step_status
    if _step_open:
        _step_status = "failed"


def step(name: str) -> None:
    global _total, _step_open, _step_status
    _finalize_step()
    _total += 1
    _step_open = True
    _step_status = None
    print(f"\n  {B}{M}┌─ Step {_total}: {name}{X}")


def ok(msg: str) -> None:
    _mark_passed()
    print(f"  {G}│  ✓ {msg}{X}")


def warn(msg: str) -> None:
    print(f"  {Y}│  ⚠ {msg}{X}")


def fail_step(msg: str) -> None:
    _mark_failed()
    print(f"  {R}│  ✗ {msg}{X}")


def detail(msg: str) -> None:
    print(f"  {D}│    {msg}{X}")


def footer() -> None:
    print(f"  {M}└─────────────────────────────────{X}")


def section(title: str) -> None:
    print(f"\n{B}{'━' * 66}{X}")
    print(f"{B}  {title}{X}")
    print(f"{'━' * 66}")


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def api(method: str, path: str, body: Any = None, timeout: int = 60) -> Tuple[int, Any, float]:
    """Single HTTP call with 429 backoff."""
    for attempt in range(4):
        url = f"{BASE_URL}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in HEADERS.items():
            req.add_header(k, v)
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode()
                ms = (time.monotonic() - t0) * 1000
                try:
                    return resp.status, json.loads(raw), ms
                except json.JSONDecodeError:
                    return resp.status, {"raw": raw[:500]}, ms
        except urllib.error.HTTPError as e:
            ms = (time.monotonic() - t0) * 1000
            if e.code == 429 and attempt < 3:
                time.sleep((attempt + 1) * 2)
                continue
            try:
                return e.code, json.loads(e.read().decode()), ms
            except Exception:
                return e.code, {"error": str(e)}, ms
        except Exception as e:
            return 0, {"error": str(e)}, (time.monotonic() - t0) * 1000
    return 429, {"error": "rate limited"}, 0


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def read_file(rel_path: str) -> str:
    """Read a file relative to repo root; return empty string on failure."""
    try:
        return (ROOT / rel_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def resolve_path(*candidates: str) -> str:
    """Return first candidate that exists as a file, else first candidate."""
    for p in candidates:
        if (ROOT / p).is_file():
            return p
    return candidates[0] if candidates else ""


def collect_python_files(max_files: int = MAX_SAST_FILES) -> List[Path]:
    """Collect the most significant Python source files in the repo."""
    priority_dirs = [
        ROOT / "suite-core" / "core",
        ROOT / "suite-api" / "apps" / "api",
        ROOT / "suite-core" / "connectors",
        ROOT / "suite-core" / "trustgraph",
        ROOT / "suite-feeds",
        ROOT / "suite-attack",
        ROOT / "suite-evidence-risk",
    ]
    files: List[Path] = []
    seen: set = set()
    for d in priority_dirs:
        if not d.exists():
            continue
        for f in sorted(d.rglob("*.py")):
            if f.name.startswith("_") and f.name != "__init__.py":
                continue
            if str(f) not in seen:
                seen.add(str(f))
                files.append(f)
            if len(files) >= max_files:
                break
        if len(files) >= max_files:
            break
    return files[:max_files]


# ---------------------------------------------------------------------------
# Scanning helpers — pure Python, no external tools required
# ---------------------------------------------------------------------------

BANDIT_PATTERNS: List[Tuple[str, str, str, str]] = [
    # (pattern_substring, rule_id, title, severity)
    ("eval(", "B307", "Use of eval()", "high"),
    ("exec(", "B102", "Use of exec()", "high"),
    ("pickle.loads", "B301", "Pickle deserialization", "high"),
    ("subprocess.call", "B603", "Subprocess with shell=True risk", "medium"),
    ("shell=True", "B602", "subprocess with shell=True", "high"),
    ("os.system(", "B605", "os.system call", "medium"),
    ("hashlib.md5(", "B303", "Use of MD5", "medium"),
    ("hashlib.sha1(", "B303", "Use of SHA1", "medium"),
    ("random.random(", "B311", "Standard PRNG is not suitable for crypto", "low"),
    ("assert ", "B101", "Use of assert detected", "low"),
    ("except:", "B110", "Bare except clause", "low"),
    ("except Exception:", "B110", "Broad except clause", "low"),
    ("DEBUG = True", "B105", "Hardcoded DEBUG mode", "medium"),
    ("verify=False", "B501", "SSL verification disabled", "high"),
    ("ssl._create_unverified_context", "B507", "SSL unverified context", "high"),
    ("yaml.load(", "B506", "yaml.load without Loader", "medium"),
    ("input(", "B322", "Use of input()", "low"),
    ("tempfile.mktemp(", "B306", "Use of mktemp", "medium"),
    ("\"password\":", "B105", "Possible hardcoded password", "medium"),
    ("\"secret\":", "B105", "Possible hardcoded secret", "medium"),
]

SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    # (pattern_substring, secret_type, severity)
    ("AKIA", "aws_access_key_id", "critical"),
    ("sk-", "openai_api_key", "critical"),
    ("ghp_", "github_personal_token", "critical"),
    ("-----BEGIN RSA PRIVATE KEY-----", "rsa_private_key", "critical"),
    ("-----BEGIN EC PRIVATE KEY-----", "ec_private_key", "critical"),
    ("password = \"", "hardcoded_password", "high"),
    ("password=\"", "hardcoded_password", "high"),
    ("secret = \"", "hardcoded_secret", "high"),
    ("secret=\"", "hardcoded_secret", "high"),
    ("api_key = \"", "hardcoded_api_key", "high"),
    ("api_key=\"", "hardcoded_api_key", "high"),
    ("token = \"", "hardcoded_token", "medium"),
    ("POSTGRES_PASSWORD=", "db_password", "high"),
    ("MYSQL_ROOT_PASSWORD=", "db_password", "high"),
    ("REDIS_PASSWORD=", "db_password", "medium"),
]

DOCKERFILE_PATTERNS: List[Tuple[str, str, str, str]] = [
    # (pattern, rule_id, title, severity)
    ("USER root", "DL3002", "Last USER should not be root", "high"),
    (":latest", "DL3007", "Using latest tag", "medium"),
    ("ADD http", "DL3020", "Use COPY instead of ADD for remote URLs", "medium"),
    ("apt-get install", "DL3008", "Pin versions in apt-get install", "low"),
    ("--no-cache-dir", None, None, None),  # positive signal — skip
    ("RUN apt", "DL3009", "Delete apt cache after install", "low"),
    ("EXPOSE 22", "CIS-DK-1.4", "SSH port exposed", "high"),
    ("chmod 777", "SC2154", "Overly permissive file mode", "medium"),
    ("curl | sh", "DL3028", "Piping curl to shell", "high"),
    ("wget -O- | sh", "DL3028", "Piping wget to shell", "high"),
]

LICENSE_DB: Dict[str, str] = {
    # package_name_prefix → license category
    "gpl": "copyleft",
    "lgpl": "copyleft-weak",
    "agpl": "copyleft-strong",
    "mit": "permissive",
    "apache": "permissive",
    "bsd": "permissive",
    "isc": "permissive",
    "mpl": "weak-copyleft",
    "cc0": "public-domain",
    "unlicense": "public-domain",
}

KNOWN_VULNERABLE: Dict[str, Dict[str, Any]] = {
    # package → {vuln info}
    "pillow": {"cve": "CVE-2023-44271", "severity": "high", "fixed_in": "10.0.1",
               "desc": "Uncontrolled resource consumption in PIL.ImageFont"},
    "cryptography": {"cve": "CVE-2023-49083", "severity": "medium", "fixed_in": "41.0.6",
                     "desc": "NULL dereference in PKCS12 parsing"},
    "requests": {"cve": "CVE-2023-32681", "severity": "medium", "fixed_in": "2.31.0",
                 "desc": "Proxy-Authorization header leak on redirect"},
    "urllib3": {"cve": "CVE-2023-45803", "severity": "medium", "fixed_in": "2.0.7",
                "desc": "Cookie header leak on redirect"},
    "pydantic": {"cve": "CVE-2024-3772", "severity": "low", "fixed_in": "2.4.0",
                 "desc": "ReDoS vulnerability in email validator"},
    "starlette": {"cve": "CVE-2024-24762", "severity": "high", "fixed_in": "0.36.2",
                  "desc": "DoS via form data multipart parsing"},
    "fastapi": {"cve": "CVE-2024-24762", "severity": "high", "fixed_in": "0.109.1",
                "desc": "DoS via multipart form data (inherited from starlette)"},
    "werkzeug": {"cve": "CVE-2023-46136", "severity": "high", "fixed_in": "3.0.1",
                 "desc": "Multipart parsing DoS"},
    "sqlalchemy": {"cve": "CVE-2019-7164", "severity": "medium", "fixed_in": "1.3.0",
                   "desc": "SQL injection via order_by parameter"},
    "aiohttp": {"cve": "CVE-2024-23334", "severity": "medium", "fixed_in": "3.9.2",
                "desc": "Directory traversal via static file serving"},
    "paramiko": {"cve": "CVE-2023-48795", "severity": "medium", "fixed_in": "3.4.0",
                 "desc": "Terrapin SSH prefix truncation attack"},
    "pyyaml": {"cve": "CVE-2020-14343", "severity": "critical", "fixed_in": "6.0",
               "desc": "Arbitrary code execution via yaml.load()"},
    "lxml": {"cve": "CVE-2022-2309", "severity": "medium", "fixed_in": "4.9.1",
             "desc": "NULL pointer dereference in lxml"},
    "setuptools": {"cve": "CVE-2024-6345", "severity": "high", "fixed_in": "70.0.0",
                   "desc": "Remote code execution via malicious package URL"},
    "pip": {"cve": "CVE-2023-5752", "severity": "medium", "fixed_in": "23.3",
            "desc": "Mercurial config injection via VCS URL"},
}


def _sast_scan_file(content: str, filepath: str) -> List[Dict[str, Any]]:
    """Pure-Python SAST scan — looks for dangerous patterns line by line."""
    findings = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern, rule_id, title, severity in BANDIT_PATTERNS:
            if pattern in line:
                findings.append({
                    "finding_id": f"sast-{rule_id}-{filepath}-{lineno}",
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "file_path": filepath,
                    "line_number": lineno,
                    "message": f"{title} at line {lineno}: {line.strip()[:80]}",
                    "cwe_id": "CWE-676",
                    "source": "aldeci-sast",
                })
    return findings


def _secrets_scan_content(content: str, filepath: str) -> List[Dict[str, Any]]:
    """Scan content for secret patterns."""
    findings = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        for pattern, secret_type, severity in SECRET_PATTERNS:
            if pattern in line:
                findings.append({
                    "id": f"secret-{secret_type}-{filepath}-{lineno}",
                    "secret_type": secret_type,
                    "severity": severity,
                    "file_path": filepath,
                    "line_number": lineno,
                    "title": f"Potential {secret_type} in {filepath}",
                    "source": "aldeci-secrets",
                    "description": f"Secret pattern '{pattern}' matched at line {lineno}",
                })
    return findings


def _dockerfile_scan(content: str, filepath: str) -> List[Dict[str, Any]]:
    """Scan Dockerfile for misconfigurations."""
    findings = []
    lines = content.splitlines()
    has_no_cache = "--no-cache-dir" in content
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        for pattern, rule_id, title, severity in DOCKERFILE_PATTERNS:
            if rule_id is None:
                continue  # positive signal
            if pattern in line:
                # Suppress apt-get finding if no-cache is used elsewhere
                if rule_id == "DL3009" and has_no_cache:
                    continue
                findings.append({
                    "finding_id": f"iac-{rule_id}-{lineno}",
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "file_path": filepath,
                    "line_number": lineno,
                    "message": f"{title} at line {lineno}",
                    "source": "aldeci-iac",
                    "description": f"Dockerfile misconfiguration: {title}",
                })
    return findings


def _parse_requirements(content: str) -> List[Dict[str, str]]:
    """Parse requirements.txt into component list."""
    components = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        name, version = line, "unknown"
        for sep in ("==", ">=", "<=", "~=", "!="):
            if sep in line:
                parts = line.split(sep, 1)
                name = parts[0].strip()
                version = parts[1].strip().split(",")[0].strip()
                break
        components.append({"name": name, "version": version,
                            "purl": f"pkg:pypi/{name.lower()}@{version}"})
    return components


def _sca_scan(components: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Check components against known-vulnerable database."""
    findings = []
    for comp in components:
        name_lower = comp["name"].lower()
        if name_lower in KNOWN_VULNERABLE:
            vuln = KNOWN_VULNERABLE[name_lower]
            findings.append({
                "id": f"sca-{name_lower}-{vuln['cve']}",
                "title": f"{comp['name']} {comp['version']}: {vuln['cve']}",
                "severity": vuln["severity"],
                "cve_id": vuln["cve"],
                "package": comp["name"],
                "installed_version": comp["version"],
                "fixed_version": vuln["fixed_in"],
                "description": vuln["desc"],
                "source": "aldeci-sca",
                "purl": comp["purl"],
            })
    return findings


def _license_scan(components: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Detect license compliance issues for known problematic packages."""
    copyleft_packages = {
        "psutil": "BSD-3", "paramiko": "LGPL-2.1",
        "gpl-package": "GPL-3.0",
    }
    findings = []
    for comp in components:
        name_lower = comp["name"].lower()
        if name_lower in copyleft_packages:
            lic = copyleft_packages[name_lower]
            if "gpl" in lic.lower() and "lgpl" not in lic.lower():
                findings.append({
                    "id": f"license-{name_lower}",
                    "title": f"GPL license in dependency: {comp['name']}",
                    "severity": "medium",
                    "package": comp["name"],
                    "license": lic,
                    "description": f"{comp['name']} uses {lic} which may restrict commercial use",
                    "source": "aldeci-license",
                })
    return findings


def _build_sbom(components: List[Dict[str, str]]) -> Dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM from component list."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "ALdeci", "name": "self-scan", "version": "2.0.0"}],
            "component": {
                "type": "application",
                "name": "aldeci-platform",
                "version": "2.0.0",
                "purl": "pkg:github/DevOpsMadDog/Fixops@2.0.0",
                "description": "ALdeci ASPM+CTEM+CSPM platform",
            },
        },
        "components": [
            {
                "type": "library",
                "name": c["name"],
                "version": c["version"],
                "purl": c["purl"],
            }
            for c in components
        ],
    }


def _to_brain_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a raw scan finding to brain-pipeline shape."""
    return {
        "id": raw.get("id", raw.get("finding_id", str(uuid.uuid4()))),
        "title": raw.get("title", "Untitled finding"),
        "severity": raw.get("severity", "medium"),
        "source": raw.get("source", "aldeci-self-scan"),
        "description": raw.get("description", raw.get("message", "")),
        "cwe": raw.get("cwe_id", ""),
        "cve_id": raw.get("cve_id", ""),
        "file_path": raw.get("file_path", ""),
        "line_number": raw.get("line_number", 0),
        "asset_id": "aldeci-platform",
        "org_id": ORG_ID,
        "metadata": {
            "package": raw.get("package", ""),
            "purl": raw.get("purl", ""),
            "rule_id": raw.get("rule_id", ""),
            "secret_type": raw.get("secret_type", ""),
            "license": raw.get("license", ""),
            "fixed_version": raw.get("fixed_version", ""),
        },
    }


def _index_into_trustgraph(all_findings: List[Dict[str, Any]],
                            sbom: Dict[str, Any],
                            sca_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Index self-scan results into TrustGraph without requiring a running API.

    Uses KnowledgeStore directly (same as trustgraph_indexer.py).
    Returns stats dict.
    """
    try:
        from trustgraph import get_knowledge_store
        from trustgraph.knowledge_store import KnowledgeEntity, KnowledgeRelationship
    except ImportError:
        return {"error": "trustgraph not importable", "indexed": 0}

    store = get_knowledge_store()
    indexed = 0

    # Core 5 — Self-Assessment (findings)
    for finding in all_findings[:100]:
        fid = finding.get("id", str(uuid.uuid4()))
        ent = KnowledgeEntity(
            entity_id=f"self-finding-{fid}",
            core_id=5,
            entity_type="SelfScanFinding",
            name=finding.get("title", "Unknown"),
            properties={
                "severity": finding.get("severity", ""),
                "source": finding.get("source", ""),
                "file_path": finding.get("file_path", ""),
                "cve_id": finding.get("cve_id", ""),
                "cwe": finding.get("cwe", ""),
                "scan_date": datetime.now(timezone.utc).isoformat(),
            },
            org_id=ORG_ID,
        )
        try:
            store.ingest(ent)
            indexed += 1
        except Exception:
            pass

    # Core 2 — Threat Intelligence (CVEs found in self deps)
    for vuln in sca_findings:
        cve = vuln.get("cve_id", "")
        if not cve:
            continue
        ent = KnowledgeEntity(
            entity_id=f"cve-self-{cve}-{vuln.get('package', '')}",
            core_id=2,
            entity_type="CVE",
            name=cve,
            properties={
                "severity": vuln.get("severity", ""),
                "package": vuln.get("package", ""),
                "installed_version": vuln.get("installed_version", ""),
                "fixed_version": vuln.get("fixed_version", ""),
                "description": vuln.get("description", ""),
                "source": "aldeci-self-sca",
                "scan_date": datetime.now(timezone.utc).isoformat(),
            },
            org_id=ORG_ID,
        )
        try:
            store.ingest(ent)
            indexed += 1
        except Exception:
            pass

    # Core 1 — Customer Environment (SBOM components)
    for comp in sbom.get("components", [])[:50]:
        ent = KnowledgeEntity(
            entity_id=f"dep-{comp['name'].lower()}-{comp.get('version', '')}",
            core_id=1,
            entity_type="Dependency",
            name=comp["name"],
            properties={
                "version": comp.get("version", ""),
                "purl": comp.get("purl", ""),
                "asset": "aldeci-platform",
            },
            org_id=ORG_ID,
        )
        try:
            store.ingest(ent)
            indexed += 1
        except Exception:
            pass

    return {"indexed": indexed, "cores": [1, 2, 5]}


# ---------------------------------------------------------------------------
# Scan phases
# ---------------------------------------------------------------------------

def phase_sast() -> List[Dict[str, Any]]:
    """SAST — scan own Python source code."""
    section("SAST — Scan ALdeci Source Code")
    findings: List[Dict[str, Any]] = []
    files = collect_python_files()

    for pyfile in files:
        rel = str(pyfile.relative_to(ROOT))
        step(f"SAST: {rel}")
        content = pyfile.read_text(encoding="utf-8", errors="replace")

        # Try real API first; fall back to built-in scanner
        code, body, ms = api("POST", "/api/v1/sast/scan/code", {
            "code": content[:8000],
            "language": "python",
            "filename": rel,
            "scan_type": "security",
        })
        if code in (200, 201):
            api_findings = body.get("findings", [])
            for f in api_findings:
                f["file_path"] = rel
                f["source"] = "aldeci-sast-api"
            findings.extend(api_findings)
            ok(f"{len(api_findings)} findings via API ({ms:.0f}ms)")
        else:
            # Fallback: built-in scanner
            local_findings = _sast_scan_file(content, rel)
            findings.extend(local_findings)
            if local_findings:
                ok(f"{len(local_findings)} findings via built-in scanner")
                for f in local_findings[:2]:
                    detail(f"[{f['severity'].upper()}] {f['title']} L{f['line_number']}")
            else:
                ok("0 findings — clean")
        footer()

    SCAN_SUMMARY["sast_files_scanned"] = len(files)
    SCAN_SUMMARY["sast_findings"] = len(findings)
    return findings


def phase_secrets() -> List[Dict[str, Any]]:
    """Secrets — scan own config and env files."""
    section("SECRETS — Scan Configuration Files")
    findings: List[Dict[str, Any]] = []

    targets = [
        (resolve_path("docker-compose.yml", "docker/docker-compose.yml"), "Docker Compose"),
        (resolve_path(".env", ".env.example"), "Environment Variables"),
        (resolve_path("suite-core/config/fixops.overlay.yml"), "FixOps Config"),
        (resolve_path("docker-compose.connectors.yml"), "Connectors Compose"),
    ]

    for rel_path, label in targets:
        step(f"Secrets: {label}")
        content = read_file(rel_path)
        if not content:
            warn(f"Not found: {rel_path}")
            footer()
            continue

        # Try API
        code, body, ms = api("POST", "/api/v1/secrets/scan/content", {
            "content": content[:4000],
            "filename": rel_path,
        })
        if code in (200, 201):
            api_findings = body.get("findings", [])
            findings.extend(api_findings)
            ok(f"{len(api_findings)} via API ({ms:.0f}ms)")
        else:
            local = _secrets_scan_content(content, rel_path)
            findings.extend(local)
            if local:
                ok(f"{len(local)} potential secrets via built-in scanner")
                for f in local[:2]:
                    detail(f"[{f['severity'].upper()}] {f['secret_type']} L{f['line_number']}")
            else:
                ok("0 secrets detected — clean")
        footer()

    SCAN_SUMMARY["secrets_findings"] = len(findings)
    return findings


def phase_dockerfile() -> List[Dict[str, Any]]:
    """IaC — scan own Dockerfile for misconfigurations."""
    section("IaC/DOCKERFILE — Scan Container Configuration")
    findings: List[Dict[str, Any]] = []

    dockerfile_rel = resolve_path("Dockerfile", "docker/Dockerfile")
    step(f"Dockerfile: {dockerfile_rel}")
    content = read_file(dockerfile_rel)
    if not content:
        warn("Dockerfile not found")
        footer()
        SCAN_SUMMARY["dockerfile_findings"] = 0
        return findings

    # Try API
    code, body, ms = api("POST", "/api/v1/container/scan/dockerfile", {
        "content": content[:4000],
        "filename": dockerfile_rel,
    })
    if code in (200, 201):
        api_findings = body.get("findings", [])
        findings.extend(api_findings)
        ok(f"{len(api_findings)} via API ({ms:.0f}ms)")
    else:
        local = _dockerfile_scan(content, dockerfile_rel)
        findings.extend(local)
        if local:
            ok(f"{len(local)} misconfigurations via built-in scanner")
            for f in local[:3]:
                detail(f"[{f['severity'].upper()}] {f['title']} L{f['line_number']}")
        else:
            ok("0 misconfigurations found")
    footer()

    SCAN_SUMMARY["dockerfile_findings"] = len(findings)
    return findings


def phase_sbom_and_sca() -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """SBOM generation + SCA vulnerability check + License compliance."""
    section("SBOM + SCA + LICENSE — Dependency Analysis")

    requirements_content = read_file("requirements.txt")
    components = _parse_requirements(requirements_content) if requirements_content else []

    # --- SBOM ---
    step(f"SBOM: Generate CycloneDX from requirements.txt ({len(components)} deps)")
    sbom = _build_sbom(components)
    ok(f"Generated SBOM: {len(components)} components, format=CycloneDX-1.5")
    detail(f"Application: aldeci-platform v2.0.0")

    # Feed SBOM into API (multipart)
    boundary = f"----AldeciSelf{int(time.time())}"
    sbom_bytes = json.dumps(sbom, indent=2).encode()
    body_parts = [
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="file"; filename="sbom-aldeci-self.json"\r\n',
        b"Content-Type: application/json\r\n\r\n",
        sbom_bytes,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    data = b"".join(body_parts)
    url = f"{BASE_URL}/inputs/sbom"
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("X-API-Key", API_TOKEN)
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            ok(f"SBOM ingested via API: HTTP {resp.status}")
    except Exception as e:
        warn(f"SBOM API ingest skipped: {e} (SBOM saved locally)")
    footer()

    # --- SCA ---
    step(f"SCA: Check {len(components)} deps against vulnerability DB")
    sca_findings = _sca_scan(components)
    if sca_findings:
        ok(f"{len(sca_findings)} vulnerable dependencies")
        for f in sca_findings[:3]:
            detail(f"[{f['severity'].upper()}] {f['package']} → {f['cve_id']}")
    else:
        ok("No known-vulnerable packages detected")
    footer()

    # --- License ---
    step(f"License: Compliance check on {len(components)} packages")
    license_findings = _license_scan(components)
    if license_findings:
        ok(f"{len(license_findings)} license issues")
        for f in license_findings[:2]:
            detail(f"[{f['severity'].upper()}] {f['package']}: {f.get('license', '')}")
    else:
        ok("No license compliance issues detected")
    footer()

    SCAN_SUMMARY["sbom_components"] = len(components)
    SCAN_SUMMARY["sca_findings"] = len(sca_findings)
    SCAN_SUMMARY["license_findings"] = len(license_findings)
    return sbom, sca_findings, license_findings


def phase_brain_pipeline(findings: List[Dict[str, Any]]) -> None:
    """Feed all findings through Brain Pipeline."""
    section("BRAIN PIPELINE — Process Self-Scan Findings")
    step(f"Brain Pipeline: {len(findings)} findings → ingestion")

    if not findings:
        warn("No findings to process")
        footer()
        return

    brain_findings = [_to_brain_finding(f) for f in findings[:50]]
    code, body, ms = api("POST", "/api/v1/brain/pipeline/run", {
        "org_id": ORG_ID,
        "findings": brain_findings,
    }, timeout=120)

    if code in (200, 201):
        steps_run = body.get("steps", [])
        summary = body.get("summary", {})
        ingested = summary.get("findings_ingested", len(brain_findings))
        clusters = summary.get("clusters_created", 0)
        graph_nodes = summary.get("graph_nodes", 0)
        ok(f"Brain Pipeline: {len(steps_run)} steps, {ingested} ingested ({ms:.0f}ms)")
        detail(f"Clusters: {clusters} | Graph nodes: {graph_nodes}")
        SCAN_SUMMARY["brain_steps"] = len(steps_run)
        SCAN_SUMMARY["brain_clusters"] = clusters
    else:
        # Try alternate endpoint
        code2, body2, ms2 = api("POST", "/api/v1/pipeline/ingest", {
            "findings": brain_findings,
            "source": "aldeci-self-scan",
            "tags": ["self-scan", "bootstrap"],
        }, timeout=60)
        if code2 in (200, 201):
            ok(f"Pipeline ingest: {code2} ({ms2:.0f}ms)")
        else:
            warn(f"Brain Pipeline: {code} | Pipeline: {code2} (findings stored locally)")
    footer()


def phase_trustgraph(all_findings: List[Dict[str, Any]],
                     sbom: Dict[str, Any],
                     sca_findings: List[Dict[str, Any]]) -> None:
    """Index all results into TrustGraph Knowledge Cores."""
    section("TRUSTGRAPH — Index Self-Scan into Knowledge Cores")
    step(f"TrustGraph: Index {len(all_findings)} findings + {len(sbom.get('components', []))} deps")

    # Try API indexing first
    code, body, ms = api("POST", "/api/v1/trustgraph/index", {
        "entities": [
            {
                "entity_id": f"self-scan-{f.get('id', i)[:32]}",
                "core_id": 5,
                "entity_type": "SelfScanFinding",
                "name": f.get("title", "finding"),
                "properties": {
                    "severity": f.get("severity", ""),
                    "source": f.get("source", ""),
                    "cve_id": f.get("cve_id", ""),
                },
                "org_id": ORG_ID,
            }
            for i, f in enumerate(all_findings[:30])
        ]
    }, timeout=30)

    if code in (200, 201):
        ok(f"TrustGraph API: {code} ({ms:.0f}ms)")
        detail(f"Entities indexed: {body.get('indexed', len(all_findings[:30]))}")
    else:
        # Direct KnowledgeStore indexing
        tg_stats = _index_into_trustgraph(all_findings, sbom, sca_findings)
        if "error" not in tg_stats:
            ok(f"TrustGraph direct: {tg_stats['indexed']} entities → cores {tg_stats['cores']}")
        else:
            warn(f"TrustGraph: {tg_stats['error']} (results saved to local JSON)")
    footer()
    SCAN_SUMMARY["trustgraph_indexed"] = len(all_findings)


# ---------------------------------------------------------------------------
# Results persistence
# ---------------------------------------------------------------------------

def save_results(all_findings: List[Dict[str, Any]], sbom: Dict[str, Any]) -> Path:
    """Save scan results to data/self-scan/ directory."""
    out_dir = ROOT / "data" / "self-scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    results = {
        "scan_type": "aldeci-self-scan",
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "org_id": ORG_ID,
        "root": str(ROOT),
        "summary": SCAN_SUMMARY,
        "total_findings": len(all_findings),
        "findings_by_severity": {
            sev: sum(1 for f in all_findings if f.get("severity") == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
        "steps_total": _total,
        "steps_passed": _pass,
        "steps_failed": _fail,
        "pass_rate": round(_pass / _total * 100, 1) if _total > 0 else 0,
        "findings": all_findings,
    }
    results_path = out_dir / f"self-scan-{ts}.json"
    results_path.write_text(json.dumps(results, indent=2, default=str))

    # Also write SBOM
    sbom_path = out_dir / f"sbom-{ts}.json"
    sbom_path.write_text(json.dumps(sbom, indent=2, default=str))

    # Write a "latest" symlink-style file
    latest_path = out_dir / "latest.json"
    latest_path.write_text(json.dumps(results, indent=2, default=str))

    return results_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    t_start = time.monotonic()

    print(f"\n{B}{C}{'═' * 66}{X}")
    print(f"{B}{C}  ALdeci Self-Scan Bootstrap — Real Data, No Mocks{X}")
    print(f"{B}{C}  ALDECI scans itself on first boot{X}")
    print(f"{B}{C}{'═' * 66}{X}")
    print(f"  {D}API: {BASE_URL}  |  Root: {ROOT}  |  Org: {ORG_ID}{X}")

    # Pre-flight
    step("Pre-flight: API health check")
    code, body, ms = api("GET", "/api/v1/health")
    if code == 200:
        ok(f"API healthy ({ms:.0f}ms)")
    else:
        code2, _, ms2 = api("GET", "/health")
        if code2 == 200:
            ok(f"API healthy via /health ({ms2:.0f}ms)")
        else:
            warn(f"API not reachable ({code}/{code2}) — running offline scan only")
    footer()

    # Run all scan phases
    sast_findings = phase_sast()
    secret_findings = phase_secrets()
    dockerfile_findings = phase_dockerfile()
    sbom, sca_findings, license_findings = phase_sbom_and_sca()

    # Combine all findings
    all_findings: List[Dict[str, Any]] = (
        sast_findings + secret_findings + dockerfile_findings +
        sca_findings + license_findings
    )
    ALL_FINDINGS.extend(all_findings)

    # Feed into platform
    phase_brain_pipeline(all_findings)
    phase_trustgraph(all_findings, sbom, sca_findings)

    # Persist
    _finalize_step()
    results_path = save_results(all_findings, sbom)

    # Final summary
    elapsed = time.monotonic() - t_start
    pct = round(_pass / _total * 100, 1) if _total > 0 else 0

    severity_counts = {
        sev: sum(1 for f in all_findings if f.get("severity") == sev)
        for sev in ("critical", "high", "medium", "low")
    }

    print(f"\n{'═' * 66}")
    print(f"{B}  ALdeci Self-Scan — RESULTS{X}")
    print(f"{'═' * 66}")
    print(f"  SAST findings:      {SCAN_SUMMARY.get('sast_findings', 0)}")
    print(f"  Secret findings:    {SCAN_SUMMARY.get('secrets_findings', 0)}")
    print(f"  Dockerfile issues:  {SCAN_SUMMARY.get('dockerfile_findings', 0)}")
    print(f"  SCA vulns:          {SCAN_SUMMARY.get('sca_findings', 0)}")
    print(f"  License issues:     {SCAN_SUMMARY.get('license_findings', 0)}")
    print(f"  SBOM components:    {SCAN_SUMMARY.get('sbom_components', 0)}")
    print(f"  ─────────────────────────────────")
    print(f"  Total findings:     {len(all_findings)}")
    print(f"    Critical: {severity_counts['critical']}  High: {severity_counts['high']}  "
          f"Medium: {severity_counts['medium']}  Low: {severity_counts['low']}")
    print(f"  Duration:           {elapsed:.1f}s")
    print(f"  Results saved:      {results_path}")
    print(f"\n  Steps: {_total} | Passed: {G}{_pass}{X} | Failed: {R}{_fail}{X}")

    if pct >= 70:
        print(f"\n  {B}{G}SELF-SCAN COMPLETE — {_pass}/{_total} ({pct:.0f}%){X}")
        print(f"  {D}ALDECI security posture is now your demo data.{X}\n")
        return 0
    else:
        print(f"\n  {B}{Y}SELF-SCAN PARTIAL — {_pass}/{_total} ({pct:.0f}%){X}\n")
        return 0  # non-zero would block bootstrap; partial scan is still valid


if __name__ == "__main__":
    sys.exit(main())
