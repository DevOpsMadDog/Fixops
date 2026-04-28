"""ALDECI Container Security Connector — REAL OSS replacements for Aqua, Twistlock,
Snyk Container, Sysdig Secure, NeuVector.

Engines wrapped (all FOSS, all run locally — no SaaS / no API key required):

    OSS Tool      | Replaces                          | Source tool tag
    ------------- | --------------------------------- | --------------------------
    Trivy         | Aqua image scan / Twistlock CVE   | container_via_trivy
    Grype         | Twistlock vuln / Snyk Container   | container_via_grype
    Dockle        | Aqua image lint / NeuVector lint  | container_via_dockle
    kube-bench    | NeuVector cluster CIS benchmark   | container_via_kubebench

Pipeline per tenant repo:

    1. Locate Dockerfile in tenant_path. If absent, synthesise a minimal one
       (``FROM alpine:3.20`` + ``COPY . /app``).
    2. ``docker build -t fixops-test/<tenant>:scan <path>`` (uses local docker
       daemon; reuses cache so re-runs are cheap).
    3. Run trivy image, grype, dockle in parallel, JSON output, parse, mirror
       each finding to ``SecurityFindingsEngine.record_finding`` with the
       appropriate ``source_tool`` tag.
    4. (Optional) If a kind cluster is reachable, deploy the image and run
       kube-bench against the worker node.

Multi-tenant safe — every finding stamped with ``org_id`` and a stable
``correlation_key`` of ``"<source_tool>|<image>|<vuln_id>|<package>"`` so the
SecurityFindingsEngine de-dupes across consecutive scans.

Coordinates with the existing Snyk wave (``core/snyk_integration.py``):
when ``Snyk Container`` data is also present, both populate the same
SecurityFindingsEngine and dedup by correlation_key — no double counting.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import shutil
import subprocess  # nosec B404 — invoked with fixed argv lists, no shell=True
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

DEFAULT_BUILD_TIMEOUT = 600  # seconds
DEFAULT_SCAN_TIMEOUT = 600  # seconds per tool
DEFAULT_KUBEBENCH_TIMEOUT = 300  # seconds
DEFAULT_IMAGE_PREFIX = "fixops-test"

# Map raw severity strings (from any of the 4 tools) to ALDECI canonical levels.
_SEVERITY_MAP: Dict[str, str] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "moderate": "medium",
    "low":      "low",
    "negligible": "low",
    "info":     "informational",
    "informational": "informational",
    "unknown":  "informational",
    "warn":     "medium",
    "fatal":    "critical",
    "pass":     "informational",
    "skip":     "informational",
}

# Per-severity CVSS proxy when scanner does not emit an actual score.
_CVSS_PROXY: Dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "informational": 1.0,
}


def _norm_severity(raw: Optional[str]) -> str:
    if not raw:
        return "informational"
    return _SEVERITY_MAP.get(str(raw).strip().lower(), "informational")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Result of running a single OSS scanner against an image."""
    tool: str
    image: str
    available: bool = True
    success: bool = False
    elapsed_s: float = 0.0
    finding_count: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    raw_truncated: Optional[str] = None  # first 500 chars of stderr if failed


@dataclass
class TenantScanResult:
    """Aggregated result of scanning all tools against one tenant image."""
    scan_id: str
    org_id: str
    tenant: str
    image: str
    started_at: str
    completed_at: Optional[str] = None
    dockerfile_synthesised: bool = False
    build_seconds: float = 0.0
    tool_results: List[ToolResult] = field(default_factory=list)
    findings_recorded: int = 0
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "org_id": self.org_id,
            "tenant": self.tenant,
            "image": self.image,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "dockerfile_synthesised": self.dockerfile_synthesised,
            "build_seconds": round(self.build_seconds, 3),
            "findings_recorded": self.findings_recorded,
            "severity_breakdown": self.severity_breakdown,
            "error": self.error,
            "tools": [
                {
                    "tool": t.tool,
                    "available": t.available,
                    "success": t.success,
                    "elapsed_s": round(t.elapsed_s, 3),
                    "finding_count": t.finding_count,
                    "error": t.error,
                }
                for t in self.tool_results
            ],
        }


# ---------------------------------------------------------------------------
# In-memory scan history (per org)
# ---------------------------------------------------------------------------

_history: Dict[str, List[Dict[str, Any]]] = {}
_history_lock = threading.Lock()


def _record_history(org_id: str, entry: Dict[str, Any]) -> None:
    with _history_lock:
        bucket = _history.setdefault(org_id, [])
        bucket.append(entry)
        # cap at 200 most recent entries / org
        if len(bucket) > 200:
            del bucket[: len(bucket) - 200]


def get_scan_history(org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    with _history_lock:
        bucket = list(_history.get(org_id, []))
    return list(reversed(bucket))[: max(0, int(limit))]


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def _run(
    argv: List[str],
    timeout: int,
    cwd: Optional[str] = None,
    extra_env: Optional[Mapping[str, str]] = None,
) -> Tuple[int, bytes, bytes]:
    """Run a subprocess with hard timeout and captured stdout/stderr.

    Returns (returncode, stdout_bytes, stderr_bytes). Returncode -1 indicates
    timeout, -2 indicates the binary is missing.
    """
    if not argv or not isinstance(argv, list):
        raise ValueError("argv must be a non-empty list")
    binary = argv[0]
    if shutil.which(binary) is None and not Path(binary).is_file():
        return -2, b"", f"binary not found: {binary}".encode()

    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    try:
        proc = subprocess.run(  # nosec B603 — fixed argv list, no shell
            argv,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        return -1, exc.stdout or b"", exc.stderr or b""
    except (OSError, ValueError) as exc:  # pragma: no cover — defensive
        return -3, b"", str(exc).encode()


# ---------------------------------------------------------------------------
# Findings sink — pushes into SecurityFindingsEngine
# ---------------------------------------------------------------------------

_findings_engine = None  # lazy-init singleton


def _get_findings_engine():
    global _findings_engine
    if _findings_engine is not None:
        return _findings_engine
    try:
        from core.security_findings_engine import SecurityFindingsEngine
        _findings_engine = SecurityFindingsEngine()
    except Exception as exc:  # pragma: no cover
        logger.warning("SecurityFindingsEngine unavailable, findings will not be persisted: %s", exc)
        _findings_engine = None
    return _findings_engine


def _mirror_to_findings(
    org_id: str,
    image: str,
    scan_id: str,
    source_tool: str,
    findings: List[Dict[str, Any]],
) -> int:
    """Push normalised findings into the central SecurityFindingsEngine.

    Returns the number of findings successfully recorded.
    """
    engine = _get_findings_engine()
    if engine is None or not findings:
        return 0
    asset_id = image
    asset_type = "container_image"
    recorded = 0
    for f in findings:
        try:
            corr_key = f.get("correlation_key") or "|".join([
                source_tool,
                image,
                str(f.get("source_id") or f.get("title") or ""),
                str(f.get("package_name") or ""),
            ])
            engine.record_finding(
                org_id=org_id,
                title=str(f.get("title") or "container vulnerability")[:500],
                finding_type=f.get("finding_type") or "vulnerability",
                source_tool=source_tool,
                severity=f.get("severity") or "informational",
                cvss_score=float(f.get("cvss_score") or _CVSS_PROXY.get(f.get("severity") or "informational", 1.0)),
                asset_id=asset_id,
                asset_type=asset_type,
                description=str(f.get("description") or "")[:4000],
                remediation=str(f.get("remediation") or "")[:2000],
                correlation_key=corr_key,
                scan_id=scan_id,
            )
            recorded += 1
        except Exception as exc:  # pragma: no cover — never fail the scan
            logger.warning("record_finding failed for %s: %s", source_tool, exc)
    return recorded


# ---------------------------------------------------------------------------
# Per-tool runners (each returns a ToolResult)
# ---------------------------------------------------------------------------

def _run_trivy_image(image: str, timeout: int = DEFAULT_SCAN_TIMEOUT) -> ToolResult:
    started = time.monotonic()
    rc, stdout, stderr = _run(
        ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", image],
        timeout=timeout,
    )
    elapsed = time.monotonic() - started
    if rc == -2:
        return ToolResult(tool="trivy", image=image, available=False, elapsed_s=elapsed,
                          error="trivy binary not on PATH")
    if rc == -1:
        return ToolResult(tool="trivy", image=image, success=False, elapsed_s=elapsed,
                          error=f"trivy timed out after {timeout}s",
                          raw_truncated=stderr.decode("utf-8", errors="replace")[:500])
    if rc not in (0, 1):
        return ToolResult(tool="trivy", image=image, success=False, elapsed_s=elapsed,
                          error=f"trivy exit {rc}",
                          raw_truncated=stderr.decode("utf-8", errors="replace")[:500])
    try:
        payload = json.loads(stdout.decode("utf-8", errors="replace") or "{}")
    except json.JSONDecodeError as exc:
        return ToolResult(tool="trivy", image=image, success=False, elapsed_s=elapsed,
                          error=f"trivy returned invalid JSON: {exc}")
    findings = _parse_trivy(payload, image)
    return ToolResult(tool="trivy", image=image, success=True, elapsed_s=elapsed,
                      finding_count=len(findings), findings=findings)


def _parse_trivy(payload: Dict[str, Any], image: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for result in payload.get("Results") or []:
        target = result.get("Target") or image
        # Vulnerabilities (CVEs)
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or ""
            sev = _norm_severity(v.get("Severity"))
            cvss = 0.0
            cvss_obj = v.get("CVSS") or {}
            for vendor_cvss in cvss_obj.values():
                if isinstance(vendor_cvss, dict):
                    score = vendor_cvss.get("V3Score") or vendor_cvss.get("V2Score")
                    if isinstance(score, (int, float)):
                        cvss = max(cvss, float(score))
            out.append({
                "title": f"{vid}: {v.get('Title') or v.get('PkgName') or 'vulnerability'}"[:500],
                "description": (v.get("Description") or "")[:4000],
                "severity": sev,
                "cvss_score": cvss or _CVSS_PROXY.get(sev, 1.0),
                "source_id": vid,
                "package_name": v.get("PkgName"),
                "package_version": v.get("InstalledVersion"),
                "remediation": (
                    f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}"
                    if v.get("FixedVersion") else
                    f"Upgrade or patch package {v.get('PkgName') or ''}"
                ),
                "finding_type": "vulnerability",
                "target": target,
                "correlation_key": f"container_via_trivy|{image}|{vid}|{v.get('PkgName') or ''}",
            })
        # Misconfigurations
        for m in result.get("Misconfigurations") or []:
            mid = m.get("ID") or ""
            sev = _norm_severity(m.get("Severity"))
            out.append({
                "title": f"{mid}: {m.get('Title') or 'misconfiguration'}"[:500],
                "description": (m.get("Description") or "")[:4000],
                "severity": sev,
                "cvss_score": _CVSS_PROXY.get(sev, 1.0),
                "source_id": mid,
                "remediation": (m.get("Resolution") or "")[:2000],
                "finding_type": "misconfiguration",
                "target": target,
                "correlation_key": f"container_via_trivy|{image}|{mid}|misconfig",
            })
        # Secrets
        for s in result.get("Secrets") or []:
            sid = s.get("RuleID") or "trivy-secret"
            sev = _norm_severity(s.get("Severity"))
            out.append({
                "title": f"Secret leaked: {s.get('Title') or sid}"[:500],
                "description": (s.get("Match") or s.get("Title") or "")[:4000],
                "severity": sev,
                "cvss_score": _CVSS_PROXY.get(sev, 1.0),
                "source_id": sid,
                "finding_type": "secret-exposure",
                "remediation": "Remove secret from image and rotate credentials",
                "target": target,
                "correlation_key": f"container_via_trivy|{image}|{sid}|secret",
            })
    return out


def _run_grype(image: str, timeout: int = DEFAULT_SCAN_TIMEOUT) -> ToolResult:
    started = time.monotonic()
    rc, stdout, stderr = _run(["grype", image, "-o", "json", "-q"], timeout=timeout)
    elapsed = time.monotonic() - started
    if rc == -2:
        return ToolResult(tool="grype", image=image, available=False, elapsed_s=elapsed,
                          error="grype binary not on PATH")
    if rc == -1:
        return ToolResult(tool="grype", image=image, success=False, elapsed_s=elapsed,
                          error=f"grype timed out after {timeout}s",
                          raw_truncated=stderr.decode("utf-8", errors="replace")[:500])
    if rc != 0:
        return ToolResult(tool="grype", image=image, success=False, elapsed_s=elapsed,
                          error=f"grype exit {rc}",
                          raw_truncated=stderr.decode("utf-8", errors="replace")[:500])
    try:
        payload = json.loads(stdout.decode("utf-8", errors="replace") or "{}")
    except json.JSONDecodeError as exc:
        return ToolResult(tool="grype", image=image, success=False, elapsed_s=elapsed,
                          error=f"grype returned invalid JSON: {exc}")
    findings = _parse_grype(payload, image)
    return ToolResult(tool="grype", image=image, success=True, elapsed_s=elapsed,
                      finding_count=len(findings), findings=findings)


def _parse_grype(payload: Dict[str, Any], image: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for match in payload.get("matches") or []:
        v = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vid = v.get("id") or ""
        sev = _norm_severity(v.get("severity"))
        cvss_score = 0.0
        for c in v.get("cvss") or []:
            metrics = c.get("metrics") or {}
            score = metrics.get("baseScore")
            if isinstance(score, (int, float)):
                cvss_score = max(cvss_score, float(score))
        pkg_name = artifact.get("name") or ""
        pkg_ver = artifact.get("version") or ""
        fix = (v.get("fix") or {})
        fix_versions = fix.get("versions") or []
        out.append({
            "title": f"{vid}: {pkg_name} {pkg_ver}"[:500],
            "description": (v.get("description") or "")[:4000],
            "severity": sev,
            "cvss_score": cvss_score or _CVSS_PROXY.get(sev, 1.0),
            "source_id": vid,
            "package_name": pkg_name,
            "package_version": pkg_ver,
            "remediation": (
                f"Upgrade {pkg_name} to {fix_versions[0]}" if fix_versions else
                f"Upgrade or patch {pkg_name}"
            ),
            "finding_type": "vulnerability",
            "correlation_key": f"container_via_grype|{image}|{vid}|{pkg_name}",
        })
    return out


def _run_dockle(image: str, timeout: int = DEFAULT_SCAN_TIMEOUT) -> ToolResult:
    started = time.monotonic()
    rc, stdout, stderr = _run(
        # --exit-code 0 prevents non-zero exit from FATAL; we read JSON
        ["dockle", "-f", "json", "--exit-code", "0", image],
        timeout=timeout,
    )
    elapsed = time.monotonic() - started
    if rc == -2:
        return ToolResult(tool="dockle", image=image, available=False, elapsed_s=elapsed,
                          error="dockle binary not on PATH")
    if rc == -1:
        return ToolResult(tool="dockle", image=image, success=False, elapsed_s=elapsed,
                          error=f"dockle timed out after {timeout}s",
                          raw_truncated=stderr.decode("utf-8", errors="replace")[:500])
    # Dockle exits 0 with --exit-code 0; treat anything else as best-effort
    raw = stdout.decode("utf-8", errors="replace")
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        return ToolResult(tool="dockle", image=image, success=False, elapsed_s=elapsed,
                          error=f"dockle returned invalid JSON: {exc}",
                          raw_truncated=raw[:500])
    findings = _parse_dockle(payload, image)
    return ToolResult(tool="dockle", image=image, success=True, elapsed_s=elapsed,
                      finding_count=len(findings), findings=findings)


def _parse_dockle(payload: Dict[str, Any], image: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for d in payload.get("details") or []:
        code = d.get("code") or "DOCKLE"
        sev_raw = d.get("level") or "INFO"
        sev = _norm_severity(sev_raw)
        if sev == "informational" and sev_raw.upper() in {"PASS", "SKIP"}:
            # Don't push passing checks as findings
            continue
        title = d.get("title") or code
        alerts = d.get("alerts") or []
        description = "; ".join(str(a) for a in alerts)[:4000] or title
        out.append({
            "title": f"{code}: {title}"[:500],
            "description": description,
            "severity": sev,
            "cvss_score": _CVSS_PROXY.get(sev, 1.0),
            "source_id": code,
            "remediation": "See Dockle CIS-Docker rule documentation",
            "finding_type": "misconfiguration",
            "correlation_key": f"container_via_dockle|{image}|{code}|lint",
        })
    return out


def _run_kubebench(timeout: int = DEFAULT_KUBEBENCH_TIMEOUT) -> ToolResult:
    """Run kube-bench against the local cluster (must be reachable via kubectl).

    kube-bench can either be installed locally or run as a Job. We prefer
    the local binary path; if absent we return available=False.
    """
    image = "kubernetes-cluster"  # logical asset id for kube-bench findings
    started = time.monotonic()
    rc, stdout, stderr = _run(
        ["kube-bench", "run", "--json"],
        timeout=timeout,
    )
    elapsed = time.monotonic() - started
    if rc == -2:
        return ToolResult(tool="kube-bench", image=image, available=False, elapsed_s=elapsed,
                          error="kube-bench binary not on PATH")
    if rc == -1:
        return ToolResult(tool="kube-bench", image=image, success=False, elapsed_s=elapsed,
                          error=f"kube-bench timed out after {timeout}s")
    raw = stdout.decode("utf-8", errors="replace")
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        return ToolResult(tool="kube-bench", image=image, success=False, elapsed_s=elapsed,
                          error=f"kube-bench returned invalid JSON: {exc}",
                          raw_truncated=raw[:500])
    findings = _parse_kubebench(payload)
    return ToolResult(tool="kube-bench", image=image, success=True, elapsed_s=elapsed,
                      finding_count=len(findings), findings=findings)


def _parse_kubebench(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # kube-bench JSON structure: {"Controls": [{"tests": [{"results":[{"status":...}]}]}]}
    for control in payload.get("Controls") or []:
        for test in control.get("tests") or []:
            for r in test.get("results") or []:
                status = (r.get("status") or "").upper()
                if status not in {"FAIL", "WARN"}:
                    continue
                sev = "high" if status == "FAIL" else "medium"
                test_no = r.get("test_number") or "kbench"
                desc = r.get("test_desc") or r.get("test_info") or ""
                remediation = r.get("remediation") or ""
                out.append({
                    "title": f"CIS-K8S {test_no}: {desc[:400]}",
                    "description": (r.get("audit") or desc)[:4000],
                    "severity": sev,
                    "cvss_score": _CVSS_PROXY[sev],
                    "source_id": test_no,
                    "remediation": remediation[:2000],
                    "finding_type": "misconfiguration",
                    "correlation_key": f"container_via_kubebench|cluster|{test_no}|cis",
                })
    return out


# ---------------------------------------------------------------------------
# Dockerfile synthesis & docker build
# ---------------------------------------------------------------------------

_MIN_DOCKERFILE = """\
# fixops-test synthetic Dockerfile — used only for OSS container scanning
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY . /app
"""


def _find_dockerfile(repo_path: Path) -> Optional[Path]:
    """Return path to an existing Dockerfile within the first two levels."""
    for candidate in ("Dockerfile", "dockerfile", "build/Dockerfile", "docker/Dockerfile"):
        p = repo_path / candidate
        if p.is_file():
            return p
    # one-level glob
    for p in repo_path.glob("*/Dockerfile"):
        if p.is_file():
            return p
    return None


def _ensure_dockerfile(repo_path: Path) -> Tuple[Path, bool]:
    """Return (build_context, synthesised_flag).

    If repo lacks a Dockerfile we synthesise a minimal alpine-based one in a
    temp directory that contains a copy of the repo (small footprint via
    using the repo path as build context with a sibling tempfile)."""
    df = _find_dockerfile(repo_path)
    if df is not None:
        return repo_path, False
    # Place synthetic Dockerfile inside the repo (overwritten each call) under
    # a fixed name so docker build context can include the rest of the source.
    synth_path = repo_path / ".fixops-test.Dockerfile"
    try:
        synth_path.write_text(_MIN_DOCKERFILE, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"unable to write synthetic Dockerfile in {repo_path}: {exc}") from exc
    return repo_path, True


def _docker_build(repo_path: Path, image_tag: str, synthetic: bool, timeout: int) -> Tuple[bool, str, float]:
    started = time.monotonic()
    argv: List[str] = ["docker", "build", "-t", image_tag]
    if synthetic:
        argv += ["-f", str(repo_path / ".fixops-test.Dockerfile")]
    argv += [str(repo_path)]
    rc, stdout, stderr = _run(argv, timeout=timeout)
    elapsed = time.monotonic() - started
    if rc == -2:
        return False, "docker binary missing", elapsed
    if rc == -1:
        return False, f"docker build timed out after {timeout}s", elapsed
    if rc != 0:
        msg = (stderr or stdout).decode("utf-8", errors="replace")
        return False, f"docker build exit {rc}: {msg[-500:]}", elapsed
    return True, "", elapsed


# ---------------------------------------------------------------------------
# Public connector class
# ---------------------------------------------------------------------------

class ContainerSecurityConnector:
    """Real container security scanning across tenant images.

    Replaces stub implementations of Aqua / Twistlock / Snyk Container /
    Sysdig / NeuVector with the OSS quartet trivy + grype + dockle + kube-bench.

    Typical use::

        conn = ContainerSecurityConnector(
            tenants_root="/tmp/aspm-repos",
            image_prefix="fixops-test",
        )
        result = conn.scan_tenant("juice-shop", org_id="acme")
        results = conn.scan_all(org_id="acme")
    """

    def __init__(
        self,
        tenants_root: str = "/tmp/aspm-repos",
        image_prefix: str = DEFAULT_IMAGE_PREFIX,
        build_timeout: int = DEFAULT_BUILD_TIMEOUT,
        scan_timeout: int = DEFAULT_SCAN_TIMEOUT,
        kubebench_timeout: int = DEFAULT_KUBEBENCH_TIMEOUT,
        run_kubebench: bool = False,
        max_parallel_tools: int = 3,
    ) -> None:
        self.tenants_root = Path(tenants_root)
        self.image_prefix = image_prefix.strip().lower() or DEFAULT_IMAGE_PREFIX
        self.build_timeout = int(build_timeout)
        self.scan_timeout = int(scan_timeout)
        self.kubebench_timeout = int(kubebench_timeout)
        self.run_kubebench = bool(run_kubebench)
        self.max_parallel_tools = max(1, int(max_parallel_tools))

    # -------------------------------------------------------------- helpers
    def list_tenants(self) -> List[str]:
        if not self.tenants_root.is_dir():
            return []
        return sorted(
            p.name for p in self.tenants_root.iterdir()
            if p.is_dir() and not p.name.startswith(".")
        )

    def tool_status(self) -> Dict[str, bool]:
        return {
            "docker":     shutil.which("docker") is not None,
            "trivy":      shutil.which("trivy") is not None,
            "grype":      shutil.which("grype") is not None,
            "dockle":     shutil.which("dockle") is not None,
            "kube-bench": shutil.which("kube-bench") is not None,
        }

    # -------------------------------------------------------------- scan one
    def scan_tenant(self, tenant: str, org_id: str = "default") -> TenantScanResult:
        if not tenant or not isinstance(tenant, str):
            raise ValueError("tenant must be a non-empty string")
        tenant = tenant.strip()
        # Prevent path traversal: reject any tenant containing ../ or /
        if "/" in tenant or "\\" in tenant or ".." in tenant:
            raise ValueError("invalid tenant id")
        repo_path = self.tenants_root / tenant
        if not repo_path.is_dir():
            raise FileNotFoundError(f"tenant repo not found at {repo_path}")

        scan_id = str(uuid.uuid4())
        image_tag = f"{self.image_prefix}/{tenant.lower()}:scan"
        result = TenantScanResult(
            scan_id=scan_id,
            org_id=org_id,
            tenant=tenant,
            image=image_tag,
            started_at=_now_iso(),
        )

        # 1. Ensure Dockerfile
        try:
            ctx, synthetic = _ensure_dockerfile(repo_path)
            result.dockerfile_synthesised = synthetic
        except RuntimeError as exc:
            result.error = str(exc)
            result.completed_at = _now_iso()
            _record_history(org_id, result.to_dict())
            return result

        # 2. Build image (skip if docker not present — fall through to no-op tools)
        if shutil.which("docker") is not None:
            ok, err, elapsed = _docker_build(ctx, image_tag, synthetic, self.build_timeout)
            result.build_seconds = elapsed
            if not ok:
                result.error = err
                result.completed_at = _now_iso()
                _record_history(org_id, result.to_dict())
                return result
        else:
            result.error = "docker binary missing — cannot build tenant image"
            result.completed_at = _now_iso()
            _record_history(org_id, result.to_dict())
            return result

        # 3. Run scanners in parallel
        tool_runners = [
            ("trivy",  lambda: _run_trivy_image(image_tag, self.scan_timeout)),
            ("grype",  lambda: _run_grype(image_tag, self.scan_timeout)),
            ("dockle", lambda: _run_dockle(image_tag, self.scan_timeout)),
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_parallel_tools) as ex:
            future_map = {ex.submit(fn): name for name, fn in tool_runners}
            for fut in concurrent.futures.as_completed(future_map):
                name = future_map[fut]
                try:
                    tr = fut.result()
                except Exception as exc:  # pragma: no cover — defensive
                    tr = ToolResult(tool=name, image=image_tag, success=False,
                                    error=f"unhandled exception: {exc}")
                result.tool_results.append(tr)

        # 4. Mirror to SecurityFindingsEngine + tally
        sev_breakdown: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0
        }
        recorded_total = 0
        for tr in result.tool_results:
            if not tr.success or not tr.findings:
                continue
            source_tool = f"container_via_{tr.tool}"
            recorded_total += _mirror_to_findings(
                org_id=org_id,
                image=image_tag,
                scan_id=scan_id,
                source_tool=source_tool,
                findings=tr.findings,
            )
            for f in tr.findings:
                sev = (f.get("severity") or "informational").lower()
                sev_breakdown[sev] = sev_breakdown.get(sev, 0) + 1

        # 5. Optional kube-bench against currently-pointed cluster
        if self.run_kubebench:
            kbr = _run_kubebench(self.kubebench_timeout)
            result.tool_results.append(kbr)
            if kbr.success and kbr.findings:
                recorded_total += _mirror_to_findings(
                    org_id=org_id,
                    image="kubernetes-cluster",
                    scan_id=scan_id,
                    source_tool="container_via_kubebench",
                    findings=kbr.findings,
                )
                for f in kbr.findings:
                    sev = (f.get("severity") or "informational").lower()
                    sev_breakdown[sev] = sev_breakdown.get(sev, 0) + 1

        result.findings_recorded = recorded_total
        result.severity_breakdown = sev_breakdown
        result.completed_at = _now_iso()
        _record_history(org_id, result.to_dict())
        emit_connector_event(
            connector="ContainerSecurityConnector",
            org_id=org_id,
            source_kind="container",
            finding_count=recorded_total,
            correlation_id=scan_id,
            extra={
                "tenant": tenant,
                "image": image_tag,
                "scan_id": scan_id,
                "severity_breakdown": sev_breakdown,
            },
        )
        return result

    # -------------------------------------------------------------- scan all
    def scan_all(self, org_id: str = "default") -> List[TenantScanResult]:
        out: List[TenantScanResult] = []
        for tenant in self.list_tenants():
            try:
                out.append(self.scan_tenant(tenant, org_id=org_id))
            except Exception as exc:
                logger.error("scan_tenant(%s) failed: %s", tenant, exc, exc_info=True)
                out.append(TenantScanResult(
                    scan_id=str(uuid.uuid4()),
                    org_id=org_id,
                    tenant=tenant,
                    image=f"{self.image_prefix}/{tenant}:scan",
                    started_at=_now_iso(),
                    completed_at=_now_iso(),
                    error=str(exc),
                ))
        emit_connector_event(
            connector="ContainerSecurityConnector",
            org_id=org_id,
            source_kind="container",
            finding_count=sum(getattr(r, "findings_recorded", 0) for r in out),
            extra={"tenants_scanned": len(out)},
        )
        return out


# ---------------------------------------------------------------------------
# Module-level singleton (matches sibling connectors' pattern)
# ---------------------------------------------------------------------------

_DEFAULT_CONNECTOR: Optional[ContainerSecurityConnector] = None
_default_lock = threading.Lock()


def get_container_security_connector(
    tenants_root: Optional[str] = None,
    image_prefix: Optional[str] = None,
    run_kubebench: Optional[bool] = None,
) -> ContainerSecurityConnector:
    """Return a process-wide default ContainerSecurityConnector.

    Re-instantiates if any override argument is supplied.
    """
    global _DEFAULT_CONNECTOR
    with _default_lock:
        if (
            _DEFAULT_CONNECTOR is None
            or tenants_root is not None
            or image_prefix is not None
            or run_kubebench is not None
        ):
            _DEFAULT_CONNECTOR = ContainerSecurityConnector(
                tenants_root=tenants_root or os.environ.get(
                    "FIXOPS_CONTAINER_TENANTS_ROOT", "/tmp/aspm-repos"
                ),
                image_prefix=image_prefix or os.environ.get(
                    "FIXOPS_CONTAINER_IMAGE_PREFIX", DEFAULT_IMAGE_PREFIX
                ),
                run_kubebench=(
                    run_kubebench
                    if run_kubebench is not None
                    else os.environ.get("FIXOPS_RUN_KUBEBENCH", "0") == "1"
                ),
            )
        return _DEFAULT_CONNECTOR


__all__ = [
    "ContainerSecurityConnector",
    "TenantScanResult",
    "ToolResult",
    "get_container_security_connector",
    "get_scan_history",
]
