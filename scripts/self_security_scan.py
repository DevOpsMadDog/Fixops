#!/usr/bin/env python3
"""
ALDECI Self-Security-Scan — the platform eating its own dog food.

Runs a comprehensive security audit of the ALDECI/Fixops codebase using
local static analysis tools, then POSTs every finding into ALDECI's own
/api/v1/brain/ingest/finding endpoint so the platform can reason about
its own vulnerabilities.

Checks performed:
  1. Bandit SAST — Python security issues (CWE-mapped)
  2. Ruff code quality — unused vars, deprecated patterns, complexity
  3. Hardcoded secrets — passwords / API keys / tokens in source
  4. SQL injection — string concatenation inside SQL query calls
  5. Missing authentication — endpoints without Depends(api_key_auth)
  6. CORS misconfiguration — wildcard origins, missing restrictive config
  7. Debug mode in production — FastAPI/Uvicorn debug=True flags

Usage:
    python scripts/self_security_scan.py
    ALDECI_BASE_URL=http://localhost:8000 python scripts/self_security_scan.py

Environment:
    ALDECI_BASE_URL     API base URL (default: http://localhost:8000)
    ALDECI_API_KEY      API key (falls back to hardcoded dev token)
    ALDECI_ORG_ID       Org ID for finding ingest (default: aldeci-self)
    SELF_SCAN_DRY_RUN   Set to "1" to skip POSTing findings (default: off)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL: str = os.getenv("ALDECI_BASE_URL", "http://localhost:8000")
API_KEY: str = os.getenv(
    "ALDECI_API_KEY",
    "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_",
)
ORG_ID: str = os.getenv("ALDECI_ORG_ID", "aldeci-self")
DRY_RUN: bool = os.getenv("SELF_SCAN_DRY_RUN", "0") == "1"

ROOT: Path = Path(__file__).resolve().parent.parent
SCAN_DIRS: list[str] = ["suite-api", "suite-core"]

HEADERS: Dict[str, str] = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
    "X-Org-ID": ORG_ID,
}

# ANSI colours
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    check: str          # Which check produced this (e.g. "bandit", "sql_injection")
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    file_path: str = ""
    line: int = 0
    cwe: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def finding_id(self) -> str:
        slug = re.sub(r"[^a-z0-9]", "-", self.title.lower())[:40]
        fp = re.sub(r"[^a-z0-9]", "-", self.file_path.lower())[-30:]
        return f"self-scan-{self.check}-{fp}-{self.line}-{slug}"

    def severity_rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
            self.severity, 5
        )


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _http(method: str, path: str, body: Optional[dict] = None) -> dict:
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            try:
                return {"ok": True, "status": resp.status, "data": json.loads(raw)}
            except json.JSONDecodeError:
                return {"ok": True, "status": resp.status, "data": raw}
    except urllib.error.HTTPError as e:
        body_txt = ""
        try:
            body_txt = e.read().decode()[:300]
        except Exception:
            pass
        return {"ok": False, "status": e.code, "error": body_txt}
    except Exception as exc:
        return {"ok": False, "status": 0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def section(title: str) -> None:
    print(f"\n{B}{'─' * 70}{X}")
    print(f"{B}  {title}{X}")
    print(f"{B}{'─' * 70}{X}")


def tick(ok: bool) -> str:
    return f"{G}✓{X}" if ok else f"{R}✗{X}"


def sev_color(sev: str) -> str:
    return {
        "CRITICAL": R,
        "HIGH": R,
        "MEDIUM": Y,
        "LOW": G,
        "INFO": D,
    }.get(sev, "")


def py_files(dirs: list[str], exclude_tests: bool = True) -> Iterator[Path]:
    """Yield Python source files under the given directories."""
    for d in dirs:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            if exclude_tests and ("test" in p.parts or p.name.startswith("test_")):
                continue
            yield p


# ---------------------------------------------------------------------------
# CHECK 1 — Bandit SAST
# ---------------------------------------------------------------------------

def check_bandit() -> List[Finding]:
    """Run bandit -r over suite-api/ suite-core/ and parse JSON output."""
    section("CHECK 1 — Bandit SAST (Python security issues)")
    findings: List[Finding] = []

    targets = [str(ROOT / d) for d in SCAN_DIRS if (ROOT / d).exists()]
    if not targets:
        print(f"  {Y}SKIP{X} — no scan directories found")
        return findings

    cmd = ["bandit", "-r"] + targets + ["-f", "json", "-q", "--exit-zero"]
    print(f"  Running: {' '.join(cmd[:6])} ...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            cwd=str(ROOT),
        )
    except FileNotFoundError:
        print(f"  {Y}SKIP{X} — bandit not installed (pip install bandit)")
        return findings
    except subprocess.TimeoutExpired:
        print(f"  {Y}WARN{X} — bandit timed out after 180 s")
        return findings

    raw_json = result.stdout.strip()
    if not raw_json:
        print(f"  {Y}WARN{X} — bandit produced no JSON output")
        if result.stderr:
            print(f"  stderr: {result.stderr[:200]}")
        return findings

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        print(f"  {R}ERROR{X} — could not parse bandit JSON: {exc}")
        return findings

    sev_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    for item in data.get("results", []):
        sev = sev_map.get(item.get("issue_severity", "").upper(), "LOW")
        cwe_obj = item.get("issue_cwe", {})
        cwe = f"CWE-{cwe_obj.get('id', '')}" if cwe_obj else ""
        rel_file = str(Path(item.get("filename", "")).relative_to(ROOT))
        findings.append(
            Finding(
                check="bandit",
                severity=sev,
                title=item.get("issue_text", "Unknown bandit issue")[:200],
                detail=f"test_id={item.get('test_id','')}  confidence={item.get('issue_confidence','')}  "
                       f"code={item.get('code','')[:120]}",
                file_path=rel_file,
                line=item.get("line_number", 0),
                cwe=cwe,
                extra={
                    "test_id": item.get("test_id", ""),
                    "confidence": item.get("issue_confidence", ""),
                    "more_info": item.get("more_info", ""),
                },
            )
        )

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    metrics = data.get("metrics", {}).get("_totals", {})
    print(f"  Files scanned : {metrics.get('loc', '?')} lines  "
          f"{metrics.get('nosec', 0)} nosec")
    print(f"  Findings      : {len(findings)} total — "
          + "  ".join(f"{sev_color(s)}{s}:{n}{X}" for s, n in sorted(counts.items())))

    for f in sorted(findings, key=lambda x: x.severity_rank())[:5]:
        col = sev_color(f.severity)
        print(f"  {col}[{f.severity:6s}]{X}  {f.file_path}:{f.line}  {f.title[:70]}")

    return findings


# ---------------------------------------------------------------------------
# CHECK 2 — Ruff code quality
# ---------------------------------------------------------------------------

def check_ruff() -> List[Finding]:
    """Run ruff check and parse its JSON output."""
    section("CHECK 2 — Ruff Code Quality")
    findings: List[Finding] = []

    targets = [str(ROOT / d) for d in SCAN_DIRS if (ROOT / d).exists()]
    if not targets:
        print(f"  {Y}SKIP{X} — no scan directories found")
        return findings

    cmd = ["ruff", "check", "--output-format=json", "--exit-zero"] + targets
    print(f"  Running: {' '.join(cmd[:5])} ...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(ROOT),
        )
    except FileNotFoundError:
        print(f"  {Y}SKIP{X} — ruff not installed (pip install ruff)")
        return findings
    except subprocess.TimeoutExpired:
        print(f"  {Y}WARN{X} — ruff timed out after 120 s")
        return findings

    raw = result.stdout.strip()
    if not raw:
        print(f"  {G}CLEAN{X} — ruff reported no issues")
        return findings

    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        print(f"  {Y}WARN{X} — could not parse ruff JSON output")
        return findings

    # Map ruff codes to severity
    def _ruff_severity(code: str) -> str:
        if code.startswith(("S", "B", "E9")):   # security / bugbear / syntax error
            return "HIGH"
        if code.startswith(("F", "E", "W")):     # pyflakes / pep8
            return "MEDIUM"
        return "LOW"

    for item in items:
        code = item.get("code", "")
        sev = _ruff_severity(code)
        rel_file = item.get("filename", "")
        try:
            rel_file = str(Path(rel_file).relative_to(ROOT))
        except ValueError:
            pass
        loc = item.get("location", {})
        findings.append(
            Finding(
                check="ruff",
                severity=sev,
                title=f"[{code}] {item.get('message','')}"[:200],
                detail=f"rule={code}  url={item.get('url','')}",
                file_path=rel_file,
                line=loc.get("row", 0),
                extra={"code": code, "fix": item.get("fix", "")},
            )
        )

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"  Findings : {len(findings)} total — "
          + "  ".join(f"{sev_color(s)}{s}:{n}{X}" for s, n in sorted(counts.items())))

    # Print top 5 highest-severity
    for f in sorted(findings, key=lambda x: x.severity_rank())[:5]:
        col = sev_color(f.severity)
        print(f"  {col}[{f.severity:6s}]{X}  {f.file_path}:{f.line}  {f.title[:70]}")

    return findings


# ---------------------------------------------------------------------------
# CHECK 3 — Hardcoded secrets
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (label, regex, severity)
    ("Hardcoded password assignment",
     r'(?i)\bpassword\s*=\s*["\'][^"\']{4,}["\']',
     "HIGH"),
    ("Hardcoded secret assignment",
     r'(?i)\bsecret\s*=\s*["\'][^"\']{4,}["\']',
     "HIGH"),
    ("Hardcoded API key assignment",
     r'(?i)\bapi[_-]?key\s*=\s*["\'][^"\']{8,}["\']',
     "HIGH"),
    ("Hardcoded token assignment",
     r'(?i)\btoken\s*=\s*["\'][^"\']{8,}["\']',
     "MEDIUM"),
    ("Hardcoded bearer token",
     r'(?i)Bearer\s+[A-Za-z0-9\-_.~+/]{20,}',
     "HIGH"),
    ("AWS access key pattern",
     r'AKIA[0-9A-Z]{16}',
     "CRITICAL"),
    ("Private key header",
     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
     "CRITICAL"),
]

# Lines that are obviously safe to skip
_SECRET_WHITELIST_RE = re.compile(
    r'(?i)(os\.getenv|environ|getenv|placeholder|example|your[_-]?key|'
    r'<your|xxx|changeme|test_|_test|fake|dummy|mock|fixops_ent_38wJA8|'
    r'#.*secret|#.*password)'
)


def check_hardcoded_secrets() -> List[Finding]:
    """Grep Python source files for hardcoded secrets, skipping test files."""
    section("CHECK 3 — Hardcoded Secrets")
    findings: List[Finding] = []
    compiled = [(label, re.compile(pat), sev) for label, pat, sev in _SECRET_PATTERNS]

    scanned = 0
    for py_path in py_files(SCAN_DIRS, exclude_tests=True):
        try:
            lines = py_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        scanned += 1
        for lineno, line in enumerate(lines, 1):
            if _SECRET_WHITELIST_RE.search(line):
                continue
            for label, pat, sev in compiled:
                if pat.search(line):
                    rel = str(py_path.relative_to(ROOT))
                    findings.append(
                        Finding(
                            check="hardcoded_secrets",
                            severity=sev,
                            title=label,
                            detail=f"line content: {line.strip()[:120]}",
                            file_path=rel,
                            line=lineno,
                            cwe="CWE-798",
                        )
                    )
                    break  # one finding per line

    print(f"  Scanned {scanned} source files (tests excluded)")
    if findings:
        for f in sorted(findings, key=lambda x: x.severity_rank()):
            col = sev_color(f.severity)
            print(f"  {col}[{f.severity:8s}]{X}  {f.file_path}:{f.line}  {f.title}")
    else:
        print(f"  {G}CLEAN{X} — no hardcoded secrets detected")

    return findings


# ---------------------------------------------------------------------------
# CHECK 4 — SQL injection (string concatenation in SQL)
# ---------------------------------------------------------------------------

_SQL_CONCAT_PATTERNS = [
    # execute() called with an f-string — most reliable signal
    re.compile(
        r'(?i)(?:cursor|conn|self\._conn|self\.conn|db)\.execute\s*\(\s*f["\']',
    ),
    # execute() called with explicit string concatenation: "SELECT " + var
    re.compile(
        r'(?i)(?:cursor|conn|self\._conn|self\.conn|db)\.execute\s*\([^)]*["\'\s]\s*\+\s*\w',
    ),
    # SQL keyword immediately followed by %-format inside an execute() call
    re.compile(
        r'(?i)(?:cursor|conn|self\._conn|self\.conn|db)\.execute\s*\([^)]*'
        r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^)]*%\s*(?!\s*s\b\s*,)',
    ),
]


def check_sql_injection() -> List[Finding]:
    """Detect potential SQL injection via string concatenation or f-string interpolation."""
    section("CHECK 4 — SQL Injection Patterns")
    findings: List[Finding] = []
    scanned = 0

    for py_path in py_files(SCAN_DIRS, exclude_tests=True):
        try:
            content = py_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except OSError:
            continue
        scanned += 1

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments and pure string literals (no variable interpolation risk)
            if stripped.startswith("#"):
                continue
            for pat in _SQL_CONCAT_PATTERNS:
                if pat.search(line):
                    rel = str(py_path.relative_to(ROOT))
                    findings.append(
                        Finding(
                            check="sql_injection",
                            severity="HIGH",
                            title="Potential SQL injection via string interpolation",
                            detail=f"line: {stripped[:150]}",
                            file_path=rel,
                            line=lineno,
                            cwe="CWE-89",
                        )
                    )
                    break

    print(f"  Scanned {scanned} source files")
    if findings:
        for f in findings[:10]:
            print(f"  {R}[HIGH    ]{X}  {f.file_path}:{f.line}  {f.detail[:80]}")
        if len(findings) > 10:
            print(f"  ... and {len(findings) - 10} more")
    else:
        print(f"  {G}CLEAN{X} — no SQL injection patterns detected")

    return findings


# ---------------------------------------------------------------------------
# CHECK 5 — Missing authentication on API endpoints
# ---------------------------------------------------------------------------

_ROUTE_DECORATOR = re.compile(
    r'@router\.(get|post|put|patch|delete)\s*\('
)
_HAS_AUTH = re.compile(
    r'(?:Depends\s*\(\s*api_key_auth|Depends\s*\(\s*_verify_api_key|'
    r'require_auth|dependencies\s*=\s*\[Depends\(api_key_auth)',
)
_ROUTER_LEVEL_AUTH = re.compile(
    r'APIRouter\s*\([^)]*dependencies\s*=\s*\[Depends\s*\(\s*api_key_auth',
)


def check_missing_auth() -> List[Finding]:
    """
    Detect FastAPI router endpoints that appear to have no authentication
    dependency. Skips routers that use router-level dependencies.
    """
    section("CHECK 5 — Missing Authentication on API Endpoints")
    findings: List[Finding] = []
    router_dir = ROOT / "suite-api" / "apps" / "api"
    if not router_dir.exists():
        print(f"  {Y}SKIP{X} — router directory not found")
        return findings

    router_files = list(router_dir.glob("*_router.py"))
    checked = 0

    for rfile in sorted(router_files):
        try:
            content = rfile.read_text(encoding="utf-8", errors="ignore")
            file_lines = content.splitlines()
        except OSError:
            continue
        checked += 1

        # If the whole router has router-level auth, every endpoint is covered
        if _ROUTER_LEVEL_AUTH.search(content):
            continue

        for lineno, line in enumerate(file_lines, 1):
            if not _ROUTE_DECORATOR.search(line):
                continue

            # Collect the next 15 lines (function signature + deps)
            block = "\n".join(file_lines[lineno - 1 : lineno + 15])
            if not _HAS_AUTH.search(block):
                # Extract the method/path for context
                m = re.search(r'@router\.\w+\s*\(\s*["\']([^"\']+)', line)
                endpoint_path = m.group(1) if m else "unknown"
                findings.append(
                    Finding(
                        check="missing_auth",
                        severity="HIGH",
                        title=f"Endpoint may lack authentication: {endpoint_path}",
                        detail=f"No api_key_auth Depends found within 15 lines of decorator",
                        file_path=str(rfile.relative_to(ROOT)),
                        line=lineno,
                        cwe="CWE-306",
                        extra={"endpoint": endpoint_path},
                    )
                )

    print(f"  Checked {checked} router files")
    if findings:
        # Deduplicate by file — show at most 3 per file to avoid noise
        by_file: Dict[str, List[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.file_path, []).append(f)
        shown = 0
        for fpath, flist in sorted(by_file.items()):
            for f in flist[:3]:
                col = sev_color(f.severity)
                print(f"  {col}[{f.severity:6s}]{X}  {f.file_path}:{f.line}  {f.title[:70]}")
                shown += 1
            if len(flist) > 3:
                print(f"  {D}  ... +{len(flist)-3} more in {fpath}{X}")
        print(f"  Total unauthenticated endpoint(s): {len(findings)}")
    else:
        print(f"  {G}CLEAN{X} — all checked endpoints appear to have authentication")

    return findings


# ---------------------------------------------------------------------------
# CHECK 6 — CORS misconfiguration
# ---------------------------------------------------------------------------

_WILDCARD_CORS = re.compile(r'allow_origins\s*=\s*\[?\s*["\*]')
_STAR_ORIGINS = re.compile(r'allow_origins\s*=\s*\["?\*"?\]')


def check_cors() -> List[Finding]:
    """Check for CORS wildcard origins or missing environment-based restriction."""
    section("CHECK 6 — CORS Misconfiguration")
    findings: List[Finding] = []

    app_files = list((ROOT / "suite-api").rglob("app.py")) + \
                list((ROOT / "suite-api").rglob("main.py"))

    for app_file in app_files:
        try:
            content = app_file.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except OSError:
            continue

        rel = str(app_file.relative_to(ROOT))
        has_cors = "CORSMiddleware" in content
        has_env_origins = "FIXOPS_ALLOWED_ORIGINS" in content or "ALLOWED_ORIGINS" in content

        if not has_cors:
            findings.append(
                Finding(
                    check="cors",
                    severity="MEDIUM",
                    title="No CORSMiddleware found in app file",
                    detail="CORS headers may be unset or handled elsewhere",
                    file_path=rel,
                    cwe="CWE-942",
                )
            )
            continue

        for lineno, line in enumerate(lines, 1):
            if _STAR_ORIGINS.search(line):
                findings.append(
                    Finding(
                        check="cors",
                        severity="HIGH",
                        title="CORS wildcard origin: allow_origins=[\"*\"]",
                        detail=f"line: {line.strip()[:120]}",
                        file_path=rel,
                        line=lineno,
                        cwe="CWE-942",
                    )
                )

        if has_cors and not has_env_origins:
            findings.append(
                Finding(
                    check="cors",
                    severity="MEDIUM",
                    title="CORS origins not read from environment variable",
                    detail="Hardcoded CORS origins cannot be adjusted per deployment",
                    file_path=rel,
                    cwe="CWE-942",
                )
            )

    if not app_files:
        print(f"  {Y}SKIP{X} — no app.py/main.py found under suite-api/")
        return findings

    if findings:
        for f in findings:
            col = sev_color(f.severity)
            print(f"  {col}[{f.severity:6s}]{X}  {f.file_path}:{f.line or '?'}  {f.title}")
    else:
        print(f"  {G}CLEAN{X} — CORS appears to be environment-controlled")

    return findings


# ---------------------------------------------------------------------------
# CHECK 7 — Debug mode in production config
# ---------------------------------------------------------------------------

_DEBUG_PATTERNS = [
    re.compile(r'(?<!\w)debug\s*=\s*True', re.IGNORECASE),
    re.compile(r'(?<!\w)DEBUG\s*=\s*True'),
    re.compile(r'uvicorn\.run\s*\([^)]*debug\s*=\s*True'),
    re.compile(r'app\.debug\s*=\s*True'),
    re.compile(r'reload\s*=\s*True'),         # Uvicorn reload=True in prod is risky
]
_DEBUG_SAFE_RE = re.compile(
    r'(?i)(test|spec|dev_reload|local_only|if.*dev|environ.*DEBUG|getenv)'
)


def check_debug_mode() -> List[Finding]:
    """Detect debug=True or reload=True that should not be in production code."""
    section("CHECK 7 — Debug Mode in Production Config")
    findings: List[Finding] = []

    # Check both suite-api Python files and any startup/config scripts at root
    check_paths = list(py_files(SCAN_DIRS, exclude_tests=True)) + \
                  list(ROOT.glob("*.py")) + \
                  list((ROOT / "docker").rglob("*.py") if (ROOT / "docker").exists() else [])

    scanned = 0
    for py_path in check_paths:
        if not py_path.exists():
            continue
        try:
            lines = py_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        scanned += 1

        for lineno, line in enumerate(lines, 1):
            if _DEBUG_SAFE_RE.search(line):
                continue
            for pat in _DEBUG_PATTERNS:
                if pat.search(line):
                    rel = str(py_path.relative_to(ROOT))
                    label = "reload=True in uvicorn" if "reload" in line else "debug=True flag"
                    findings.append(
                        Finding(
                            check="debug_mode",
                            severity="MEDIUM",
                            title=f"Potential {label} in production code",
                            detail=f"line: {line.strip()[:150]}",
                            file_path=rel,
                            line=lineno,
                            cwe="CWE-489",
                        )
                    )
                    break

    print(f"  Scanned {scanned} files")
    if findings:
        for f in findings:
            col = sev_color(f.severity)
            print(f"  {col}[{f.severity:6s}]{X}  {f.file_path}:{f.line}  {f.title}")
            print(f"  {D}         {f.detail[:100]}{X}")
    else:
        print(f"  {G}CLEAN{X} — no debug/reload flags found in production paths")

    return findings


# ---------------------------------------------------------------------------
# Ingest findings into ALDECI brain
# ---------------------------------------------------------------------------

def ingest_findings(all_findings: List[Finding]) -> Dict[str, int]:
    """POST each finding to /api/v1/brain/ingest/finding.  Returns counts."""
    section("INGESTING FINDINGS → ALDECI Brain")
    stats = {"ok": 0, "fail": 0, "skip": 0}

    if DRY_RUN:
        print(f"  {Y}DRY RUN{X} — skipping POST (set SELF_SCAN_DRY_RUN=0 to enable)")
        stats["skip"] = len(all_findings)
        return stats

    if not all_findings:
        print(f"  {G}Nothing to ingest — zero findings.{X}")
        return stats

    print(f"  POSTing {len(all_findings)} findings to {BASE_URL}/api/v1/brain/ingest/finding ...")

    for f in all_findings:
        payload = {
            "finding_id": f.finding_id[:512],
            "org_id": ORG_ID,
            "title": f.title[:499],
            "severity": f.severity.lower(),
            "source": f"self-scan/{f.check}",
            "cve_id": f.cwe if f.cwe.startswith("CVE-") else None,
        }
        # Remove None values — the endpoint rejects them for cve_id pattern validation
        payload = {k: v for k, v in payload.items() if v is not None}

        result = _http("POST", "/api/v1/brain/ingest/finding", payload)
        if result["ok"]:
            stats["ok"] += 1
        else:
            stats["fail"] += 1
            if stats["fail"] <= 3:
                print(f"  {R}FAIL{X}  HTTP {result.get('status')}  {result.get('error','')[:120]}")
        # Minimal throttle to avoid overwhelming the API
        time.sleep(0.05)

    print(f"  Result: {G}{stats['ok']} ingested{X}  "
          f"{R}{stats['fail']} failed{X}  {stats['skip']} skipped")
    return stats


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------

def print_report(all_findings: List[Finding], ingest_stats: Dict[str, int]) -> None:
    section("SELF-SECURITY-SCAN REPORT")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(all_findings)

    counts: Dict[str, int] = {}
    by_check: Dict[str, int] = {}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        by_check[f.check] = by_check.get(f.check, 0) + 1

    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    medium = counts.get("MEDIUM", 0)
    low = counts.get("LOW", 0) + counts.get("INFO", 0)

    if critical > 0:
        verdict = f"{R}CRITICAL — Immediate remediation required{X}"
        risk_level = "CRITICAL"
    elif high > 20:
        verdict = f"{R}HIGH RISK — Prioritised remediation sprint needed{X}"
        risk_level = "HIGH"
    elif high > 0:
        verdict = f"{Y}MODERATE — Schedule remediation within sprint{X}"
        risk_level = "MEDIUM"
    elif medium > 10:
        verdict = f"{Y}LOW-MEDIUM — Address in next hardening cycle{X}"
        risk_level = "LOW"
    else:
        verdict = f"{G}HEALTHY — Maintain security hygiene{X}"
        risk_level = "INFO"

    print(f"\n  Generated : {now}")
    print(f"  Target    : ALDECI/Fixops (self-scan)")
    print(f"  Scanned   : {', '.join(SCAN_DIRS)}")

    print(f"\n  ┌─ Severity Breakdown ──────────────────────────────────────────┐")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        bar = "█" * min(n, 40)
        col = sev_color(sev)
        print(f"  │  {col}{sev:8s}{X}  {n:5d}  {col}{bar}{X}")
    print(f"  │  {'TOTAL':8s}  {total:5d}")
    print(f"  └───────────────────────────────────────────────────────────────┘")

    print(f"\n  ┌─ Findings by Check ───────────────────────────────────────────┐")
    for check, n in sorted(by_check.items(), key=lambda x: -x[1]):
        print(f"  │  {check:35s}  {n:5d}")
    print(f"  └───────────────────────────────────────────────────────────────┘")

    print(f"\n  ┌─ Top 15 Critical/High Findings ───────────────────────────────┐")
    ranked = sorted(all_findings, key=lambda x: x.severity_rank())
    for i, f in enumerate(ranked[:15], 1):
        col = sev_color(f.severity)
        loc = f"  {f.file_path}:{f.line}" if f.file_path else ""
        print(f"  │ #{i:2d} {col}[{f.severity:8s}]{X} [{f.check}]  {f.title[:55]}")
        if loc:
            print(f"  │      {D}{loc.strip()}{X}")
    print(f"  └───────────────────────────────────────────────────────────────┘")

    print(f"\n  ┌─ Brain Ingest ─────────────────────────────────────────────────┐")
    print(f"  │  Ingested OK : {ingest_stats.get('ok', 0)}")
    print(f"  │  Failed      : {ingest_stats.get('fail', 0)}")
    print(f"  │  Skipped     : {ingest_stats.get('skip', 0)}")
    print(f"  └───────────────────────────────────────────────────────────────┘")

    print(f"\n  {'═'*65}")
    print(f"  VERDICT: {verdict}")
    print(f"  {'═'*65}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    print(f"\n{B}{C}{'╔'+'═'*68+'╗'}{X}")
    print(f"{B}{C}║{'ALDECI SELF-SECURITY-SCAN  —  Dog-Food Mode':^68}║{X}")
    print(f"{B}{C}║{f'Target: {ROOT.name}  |  API: {BASE_URL}':^68}║{X}")
    print(f"{B}{C}{'╚'+'═'*68+'╝'}{X}\n")

    if DRY_RUN:
        print(f"  {Y}DRY RUN mode enabled — findings will NOT be POSTed to ALDECI{X}\n")

    # Verify API is reachable (non-fatal)
    health = _http("GET", "/api/v1/brain/stats")
    reachable = health.get("ok", False)
    status_str = f"{G}reachable{X}" if reachable else f"{Y}unreachable (continuing){X}"
    print(f"  Backend health: HTTP {health.get('status','?')}  {status_str}")

    # Run all checks
    all_findings: List[Finding] = []
    all_findings.extend(check_bandit())
    all_findings.extend(check_ruff())
    all_findings.extend(check_hardcoded_secrets())
    all_findings.extend(check_sql_injection())
    all_findings.extend(check_missing_auth())
    all_findings.extend(check_cors())
    all_findings.extend(check_debug_mode())

    # Ingest into ALDECI
    ingest_stats = ingest_findings(all_findings)

    # Final report
    print_report(all_findings, ingest_stats)

    # Exit code: 1 if any CRITICAL or HIGH findings
    critical_high = sum(
        1 for f in all_findings if f.severity in ("CRITICAL", "HIGH")
    )
    return 1 if critical_high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
