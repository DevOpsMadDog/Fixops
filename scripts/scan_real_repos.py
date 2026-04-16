#!/usr/bin/env python3
"""
scan_real_repos.py — Clone 3 real GitHub repos and run them through the
ALDECI security platform pipeline at http://localhost:8000.

Scanners used:
  - Bandit   (Python SAST)
  - Semgrep  (multi-language SAST)
  - Trivy    (filesystem vuln scan)
  - npm audit (JS dependency audit — juice-shop only)
  - pip-audit (Python dep audit — django/flask only)

Results are ingested into ALDECI via:
  POST /api/v1/brain/ingest/asset
  POST /api/v1/scanner-ingest/upload   (multipart with scanner_type)
  POST /api/v1/brain/ingest/finding    (top-N findings)
  GET  /api/v1/scanner-ingest/stats
  GET  /api/v1/risk/overview
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

import requests

# ── Configuration ────────────────────────────────────────────────────────────
API_BASE = "http://localhost:8000"
API_KEY = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
HEADERS = {"X-API-Key": API_KEY}
CALL_DELAY = 0.6        # seconds between API calls
MAX_FINDINGS_PER_SCAN = 20

BANDIT_BIN = "/Users/devops.ai/fixops/Fixops/.venv/bin/bandit"
SEMGREP_BIN = "/opt/homebrew/bin/semgrep"
TRIVY_BIN   = "/opt/homebrew/bin/trivy"
PIP_AUDIT_BIN = "/Users/devops.ai/fixops/Fixops/.venv/bin/pip-audit"

REPOS = [
    {
        "owner": "juice-shop",
        "repo":  "juice-shop",
        "path":  "/tmp/juice-shop",
        "lang":  "javascript",
        "url":   "https://github.com/juice-shop/juice-shop",
    },
    {
        "owner": "django",
        "repo":  "django",
        "path":  "/tmp/django",
        "lang":  "python",
        "url":   "https://github.com/django/django",
    },
    {
        "owner": "pallets",
        "repo":  "flask",
        "path":  "/tmp/flask",
        "lang":  "python",
        "url":   "https://github.com/pallets/flask",
    },
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list[str], cwd: Optional[str] = None, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a command, capturing stdout+stderr. Never raises on non-zero exit."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=timeout,
    )


def _write_json(path: str, data: Any) -> None:
    with open(path, "w") as fh:
        json.dump(data, fh)


def _load_json(path: str) -> Optional[Any]:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _request_with_retry(fn, path: str, max_retries: int = 3, **kwargs) -> Optional[dict]:
    """Execute a requests call with exponential backoff on 429."""
    delay = CALL_DELAY
    for attempt in range(max_retries):
        time.sleep(delay)
        try:
            r = fn(f"{API_BASE}{path}", headers=HEADERS, timeout=60, **kwargs)
            if r.status_code in (200, 201):
                return r.json()
            if r.status_code == 429:
                wait = min(30, delay * (2 ** attempt) + 5)
                print(f"    [RATE-LIMIT] {path} → 429, waiting {wait:.0f}s (attempt {attempt+1}/{max_retries})")
                time.sleep(wait)
                delay = wait
                continue
            # Non-retryable error
            print(f"    [WARN] {path} → {r.status_code}: {r.text[:180]}")
            return None
        except requests.RequestException as exc:
            print(f"    [ERROR] {path}: {exc}")
            return None
    print(f"    [FAIL] {path} — exhausted {max_retries} retries")
    return None


def _api_get(path: str) -> Optional[dict]:
    return _request_with_retry(requests.get, path)


def _api_post(path: str, json_body: dict) -> Optional[dict]:
    return _request_with_retry(requests.post, path, json=json_body)


def _api_upload(path: str, file_path: str, scanner_type: str, app_id: str = "") -> Optional[dict]:
    """Upload a scanner output file via multipart form."""
    try:
        with open(file_path, "rb") as fh:
            content = fh.read()
        files = {"file": (os.path.basename(file_path), content, "application/json")}
        data  = {"scanner_type": scanner_type, "app_id": app_id, "pipeline": "true"}
        return _request_with_retry(requests.post, path, files=files, data=data)
    except OSError as exc:
        print(f"    [ERROR] reading {file_path}: {exc}")
        return None


# ── Clone repos ───────────────────────────────────────────────────────────────

def clone_repos() -> None:
    for repo in REPOS:
        dest = Path(repo["path"])
        if dest.exists() and any(dest.iterdir()):
            print(f"  [SKIP] {repo['repo']} already at {dest}")
            continue
        print(f"  [CLONE] {repo['url']} → {dest}")
        dest.mkdir(parents=True, exist_ok=True)
        result = _run(
            ["git", "clone", "--depth", "1", repo["url"], str(dest)],
            timeout=300,
        )
        if result.returncode != 0:
            print(f"    [ERROR] clone failed: {result.stderr[:200]}")
        else:
            print(f"    [OK] cloned {repo['repo']}")


# ── Scanner wrappers ──────────────────────────────────────────────────────────

def run_bandit(repo_path: str, out_file: str) -> int:
    """Run Bandit SAST on a Python repo. Returns finding count."""
    if not Path(BANDIT_BIN).exists():
        print(f"    [SKIP] bandit not found at {BANDIT_BIN}")
        return 0
    print(f"    [SCAN] bandit on {repo_path}")
    result = _run(
        [BANDIT_BIN, "-r", repo_path, "-f", "json",
         "-o", out_file, "--severity-level", "medium"],
        timeout=180,
    )
    data = _load_json(out_file)
    if data:
        count = len(data.get("results", []))
        print(f"    [OK] bandit: {count} findings")
        return count
    print(f"    [WARN] bandit produced no output (rc={result.returncode})")
    return 0


def run_semgrep(repo_path: str, out_file: str) -> int:
    """Run Semgrep auto-config scan. Returns finding count."""
    if not Path(SEMGREP_BIN).exists():
        print(f"    [SKIP] semgrep not found at {SEMGREP_BIN}")
        return 0
    print(f"    [SCAN] semgrep on {repo_path}")
    result = _run(
        [SEMGREP_BIN, "scan", "--config", "auto",
         "--json", "--output", out_file, repo_path],
        timeout=300,
    )
    data = _load_json(out_file)
    if data:
        count = len(data.get("results", []))
        print(f"    [OK] semgrep: {count} findings")
        return count
    print(f"    [WARN] semgrep produced no output (rc={result.returncode})")
    return 0


def run_trivy(repo_path: str, out_file: str) -> int:
    """Run Trivy filesystem scan. Returns vuln count."""
    if not Path(TRIVY_BIN).exists():
        print(f"    [SKIP] trivy not found at {TRIVY_BIN}")
        return 0
    print(f"    [SCAN] trivy on {repo_path}")
    result = _run(
        [TRIVY_BIN, "fs", "--format", "json", "--output", out_file,
         "--scanners", "vuln,secret", repo_path],
        timeout=300,
    )
    data = _load_json(out_file)
    if data:
        count = sum(
            len(r.get("Vulnerabilities") or [])
            for r in data.get("Results", [])
        )
        print(f"    [OK] trivy: {count} vulns")
        return count
    print(f"    [WARN] trivy produced no output (rc={result.returncode})")
    return 0


def run_npm_audit(repo_path: str, out_file: str) -> int:
    """Run npm install + npm audit --json. Returns vuln count."""
    print(f"    [SCAN] npm audit on {repo_path}")
    npm_bin = "/usr/local/bin/npm"
    if not Path(npm_bin).exists():
        npm_bin = "npm"  # rely on PATH
    # npm install (ignore scripts to be safe)
    _run([npm_bin, "install", "--ignore-scripts", "--legacy-peer-deps"],
         cwd=repo_path, timeout=300)
    result = _run([npm_bin, "audit", "--json"], cwd=repo_path, timeout=120)
    data: Any = {}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # npm audit can mix text + JSON; try to extract JSON portion
        for line in result.stdout.splitlines():
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    pass
    if data:
        _write_json(out_file, data)
        # npm v7+ uses "vulnerabilities" dict; older uses "advisories"
        count = (
            len(data.get("vulnerabilities", {}))
            or len(data.get("advisories", {}))
        )
        print(f"    [OK] npm audit: {count} vuln packages")
        return count
    print(f"    [WARN] npm audit produced no parseable JSON")
    return 0


def run_pip_audit(repo_path: str, out_file: str) -> int:
    """Run pip-audit on a Python project's requirements. Returns vuln count."""
    if not Path(PIP_AUDIT_BIN).exists():
        print(f"    [SKIP] pip-audit not found at {PIP_AUDIT_BIN}")
        return 0
    # Find requirements file
    req_candidates = [
        "requirements.txt", "requirements/base.txt",
        "requirements/common.txt", "requirements-dev.txt",
    ]
    req_file = None
    for candidate in req_candidates:
        p = Path(repo_path) / candidate
        if p.exists():
            req_file = str(p)
            break
    if not req_file:
        print(f"    [SKIP] pip-audit: no requirements.txt found in {repo_path}")
        return 0
    print(f"    [SCAN] pip-audit on {req_file}")
    result = _run(
        [PIP_AUDIT_BIN, "-r", req_file, "--format", "json", "-o", out_file],
        timeout=180,
    )
    data = _load_json(out_file)
    if data:
        # pip-audit JSON: list of dicts with "vulns" key
        count = sum(len(pkg.get("vulns", [])) for pkg in (data if isinstance(data, list) else []))
        print(f"    [OK] pip-audit: {count} vulns")
        return count
    print(f"    [WARN] pip-audit produced no output (rc={result.returncode})")
    return 0


# ── ALDECI ingest ─────────────────────────────────────────────────────────────

def ingest_asset(asset_id: str, name: str) -> bool:
    """Register a repo as an asset node in the Knowledge Brain."""
    print(f"    [INGEST] asset: {asset_id}")
    result = _api_post("/api/v1/brain/ingest/asset", {
        "asset_id": asset_id,
        "name": name,
        "asset_type": "application",
    })
    return result is not None


def ingest_scanner_file(
    scanner_type: str,
    file_path: str,
    app_id: str,
) -> int:
    """Upload scanner output file. Returns number of findings parsed by ALDECI."""
    if not Path(file_path).exists() or Path(file_path).stat().st_size == 0:
        print(f"    [SKIP] {scanner_type}: output file missing or empty")
        return 0
    print(f"    [INGEST] {scanner_type} output → ALDECI scanner-ingest")
    result = _api_upload(
        "/api/v1/scanner-ingest/upload",
        file_path,
        scanner_type,
        app_id,
    )
    if result:
        count = result.get("findings_count", result.get("count", len(result.get("findings", []))))
        print(f"    [OK] ALDECI ingested {count} {scanner_type} findings")
        return count
    return 0


def ingest_top_findings(findings: list[dict], scanner: str, asset_id: str) -> int:
    """Ingest top-N findings individually into the Knowledge Brain."""
    ingested = 0
    for i, f in enumerate(findings[:MAX_FINDINGS_PER_SCAN]):
        fid = f.get("finding_id") or f"{asset_id}:{scanner}:{i}"
        title    = f.get("title") or f.get("issue_text") or f.get("check_id") or f.get("RuleId") or "finding"
        severity = (f.get("severity") or f.get("issue_severity") or "medium").lower()
        cve_id   = f.get("cve_id") or f.get("CVE") or None
        result = _api_post("/api/v1/brain/ingest/finding", {
            "finding_id": fid[:512],
            "title": str(title)[:500],
            "severity": severity[:20],
            "source": scanner,
            **({"cve_id": cve_id[:30]} if cve_id else {}),
        })
        if result:
            ingested += 1
    print(f"    [OK] brain ingested {ingested}/{min(len(findings), MAX_FINDINGS_PER_SCAN)} findings")
    return ingested


def extract_bandit_findings(data: Any) -> list[dict]:
    if not data:
        return []
    return [
        {
            "finding_id": f"bandit:{r.get('test_id','?')}:{r.get('filename','?')}:{r.get('line_number',0)}",
            "title": r.get("issue_text", ""),
            "severity": r.get("issue_severity", "medium"),
            "source": "bandit",
        }
        for r in data.get("results", [])
    ]


def extract_semgrep_findings(data: Any) -> list[dict]:
    if not data:
        return []
    return [
        {
            "finding_id": f"semgrep:{r.get('check_id','?')}:{r.get('path','?')}:{r.get('start',{}).get('line',0)}",
            "title": r.get("extra", {}).get("message", r.get("check_id", "")),
            "severity": r.get("extra", {}).get("severity", "medium"),
            "source": "semgrep",
        }
        for r in data.get("results", [])
    ]


def extract_trivy_findings(data: Any) -> list[dict]:
    if not data:
        return []
    findings = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            findings.append({
                "finding_id": f"trivy:{v.get('VulnerabilityID','?')}:{result.get('Target','?')}",
                "title": v.get("Title") or v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", "medium"),
                "cve_id": v.get("VulnerabilityID", "")[:30] if str(v.get("VulnerabilityID","")).startswith("CVE-") else None,
                "source": "trivy",
            })
    return findings


def extract_npm_findings(data: Any) -> list[dict]:
    if not data:
        return []
    findings = []
    # npm v7+ format
    for pkg_name, vuln in (data.get("vulnerabilities") or {}).items():
        findings.append({
            "finding_id": f"npm-audit:{pkg_name}:{vuln.get('severity','?')}",
            "title": f"{pkg_name}: {vuln.get('title', vuln.get('name', 'vulnerability'))}",
            "severity": vuln.get("severity", "medium"),
            "source": "npm-audit",
        })
    # npm v6 format
    for adv_id, adv in (data.get("advisories") or {}).items():
        findings.append({
            "finding_id": f"npm-audit:{adv_id}:{adv.get('module_name','?')}",
            "title": adv.get("title", ""),
            "severity": adv.get("severity", "medium"),
            "source": "npm-audit",
        })
    return findings


def extract_pip_audit_findings(data: Any) -> list[dict]:
    if not isinstance(data, list):
        return []
    findings = []
    for pkg in data:
        for v in pkg.get("vulns", []):
            cve = v.get("id", "")
            findings.append({
                "finding_id": f"pip-audit:{pkg.get('name','?')}:{cve}",
                "title": f"{pkg.get('name','?')} {pkg.get('version','?')}: {cve}",
                "severity": "high" if "CRITICAL" in cve.upper() else "medium",
                "cve_id": cve[:30] if cve.startswith("CVE-") else None,
                "source": "pip-audit",
            })
    return findings


# ── SBOM ingest ───────────────────────────────────────────────────────────────

def ingest_sbom_components(repo_path: str, asset_id: str) -> int:
    """Parse package manifest and ingest SBOM components as brain nodes."""
    components: list[dict] = []

    # package.json (JS)
    pkg_json = Path(repo_path) / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text())
            for name, version in {**data.get("dependencies", {}), **data.get("devDependencies", {})}.items():
                components.append({"name": name, "version": str(version), "type": "npm"})
        except (json.JSONDecodeError, OSError):
            pass

    # requirements.txt (Python)
    for req_file in ["requirements.txt", "requirements/base.txt"]:
        req_path = Path(repo_path) / req_file
        if req_path.exists():
            for line in req_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.replace("==", " ").replace(">=", " ").split()
                    name = parts[0]
                    version = parts[1] if len(parts) > 1 else "unknown"
                    components.append({"name": name, "version": version, "type": "pip"})
            break

    if not components:
        return 0

    print(f"    [SBOM] ingesting {len(components)} components for {asset_id}")
    ingested = 0
    for comp in components[:50]:  # cap at 50 to avoid flooding
        result = _api_post("/api/v1/brain/nodes", {
            "node_id": f"sbom:{asset_id}:{comp['name']}:{comp['version']}",
            "node_type": "component",
            "properties": {
                "name": comp["name"],
                "version": comp["version"],
                "package_type": comp["type"],
                "asset_id": asset_id,
            },
        })
        if result:
            ingested += 1
    print(f"    [OK] SBOM: {ingested} components ingested")
    return ingested


# ── Per-repo risk query ───────────────────────────────────────────────────────

def query_risk_level() -> str:
    """Query ALDECI risk overview and return a risk level string."""
    data = _api_get("/api/v1/risk/overview")
    if not data:
        return "UNKNOWN"
    # Handle various response shapes
    level = (
        data.get("risk_level")
        or data.get("overall_risk")
        or data.get("level")
        or data.get("status")
    )
    if level and str(level).upper() in ("HIGH", "MEDIUM", "LOW", "CRITICAL", "INFO"):
        return str(level).upper()
    score = data.get("risk_score") or data.get("score") or 0
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0
    if score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def _parse_stats(stats: Optional[dict]) -> dict:
    """Normalise the scanner-ingest/stats response into consistent fields."""
    if not stats:
        return {}
    # Session counters (per-process since restart)
    session = stats.get("in_session", {})
    return {
        "total_files_processed": session.get("files_processed", stats.get("total_files_processed", "?")),
        "total_findings_parsed": session.get("findings_parsed", stats.get("total_findings_ingested", "?")),
        "last_ingest_at": stats.get("last_ingest_at", "?"),
        "by_scanner": {
            src: {"findings": v.get("findings", 0), "files": v.get("files", 0)}
            for src, v in stats.get("by_source", stats.get("by_scanner", {})).items()
        },
    }


# ── Main pipeline ─────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 70)
    print("ALDECI Real-Repo Security Scan Pipeline")
    print("=" * 70)

    # Step 1: Clone repos
    print("\n[1] Cloning repos...")
    clone_repos()

    # Step 2-5: Per-repo scanning + ingestion
    report_lines: list[str] = []

    for repo in REPOS:
        owner     = repo["owner"]
        name      = repo["repo"]
        repo_path = repo["path"]
        lang      = repo["lang"]
        asset_id  = f"github:{owner}/{name}"
        tmp_prefix = f"/tmp/{name}"

        print(f"\n{'─'*60}")
        print(f"REPO: {owner}/{name}  ({lang})  →  {repo_path}")
        print(f"{'─'*60}")

        if not Path(repo_path).exists():
            print(f"  [ERROR] {repo_path} not found — skipping")
            report_lines.append(f"\nREPO: {owner}/{name}\n  ERROR: not cloned")
            continue

        # ── Run scanners ──────────────────────────────────────────────────
        scan_counts: dict[str, int] = {}
        scan_findings: dict[str, list] = {}

        # Bandit (Python only)
        if lang == "python":
            out = f"{tmp_prefix}_bandit.json"
            scan_counts["bandit"] = run_bandit(repo_path, out)
            scan_findings["bandit"] = extract_bandit_findings(_load_json(out))
        else:
            scan_counts["bandit"] = -1  # N/A

        # Semgrep (all)
        out = f"{tmp_prefix}_semgrep.json"
        scan_counts["semgrep"] = run_semgrep(repo_path, out)
        scan_findings["semgrep"] = extract_semgrep_findings(_load_json(out))

        # Trivy (all)
        out = f"{tmp_prefix}_trivy.json"
        scan_counts["trivy"] = run_trivy(repo_path, out)
        scan_findings["trivy"] = extract_trivy_findings(_load_json(out))

        # npm audit (JS only)
        if lang == "javascript":
            out = f"{tmp_prefix}_npm_audit.json"
            scan_counts["npm_audit"] = run_npm_audit(repo_path, out)
            scan_findings["npm_audit"] = extract_npm_findings(_load_json(out))
        else:
            scan_counts["npm_audit"] = -1  # N/A

        # pip-audit (Python only)
        if lang == "python":
            out = f"{tmp_prefix}_pip_audit.json"
            scan_counts["pip_audit"] = run_pip_audit(repo_path, out)
            scan_findings["pip_audit"] = extract_pip_audit_findings(_load_json(out))
        else:
            scan_counts["pip_audit"] = -1  # N/A

        # ── ALDECI ingest ─────────────────────────────────────────────────
        print(f"\n  [ALDECI] Ingesting {owner}/{name}...")

        # a) Register asset
        ingest_asset(asset_id, f"{owner}/{name}")

        # b) Upload scanner files
        total_aldeci_ingested = 0
        scanner_map = {
            "bandit":    (f"/tmp/{name}_bandit.json",    "bandit"),
            "semgrep":   (f"/tmp/{name}_semgrep.json",   "semgrep"),
            "trivy":     (f"/tmp/{name}_trivy.json",     "trivy"),
            "npm_audit": (f"/tmp/{name}_npm_audit.json", "npm"),
            "pip_audit": (f"/tmp/{name}_pip_audit.json", "pip-audit"),
        }
        for scanner_key, (file_path, scanner_type) in scanner_map.items():
            if scan_counts.get(scanner_key, -1) < 0:
                continue  # N/A for this lang
            ingested = ingest_scanner_file(scanner_type, file_path, asset_id)
            total_aldeci_ingested += ingested

        # c) Ingest top findings into brain
        all_findings: list[dict] = []
        for key, findings in scan_findings.items():
            if findings:
                all_findings.extend(findings)
        if all_findings:
            ingest_top_findings(all_findings, f"multi-scanner:{owner}/{name}", asset_id)

        # d) SBOM components
        ingest_sbom_components(repo_path, asset_id)

        # ── Query ALDECI stats ────────────────────────────────────────────
        print(f"\n  [QUERY] Querying ALDECI stats...")
        stats = _parse_stats(_api_get("/api/v1/scanner-ingest/stats"))
        risk_level = query_risk_level()

        # ── Build report lines ────────────────────────────────────────────
        lines = [f"\nREPO: {owner}/{name}"]
        if scan_counts.get("bandit", -1) >= 0:
            lines.append(f"  Bandit:     {scan_counts['bandit']} findings")
        else:
            lines.append("  Bandit:     N/A (not Python)")
        lines.append(f"  Semgrep:    {scan_counts.get('semgrep', 0)} findings")
        lines.append(f"  Trivy:      {scan_counts.get('trivy', 0)} vulns")
        if scan_counts.get("npm_audit", -1) >= 0:
            lines.append(f"  npm audit:  {scan_counts['npm_audit']} vuln packages")
        else:
            lines.append("  npm audit:  N/A (not JavaScript)")
        if scan_counts.get("pip_audit", -1) >= 0:
            lines.append(f"  pip-audit:  {scan_counts['pip_audit']} vulns")
        else:
            lines.append("  pip-audit:  N/A (not Python)")
        if stats:
            total_ever = stats.get("total_findings_parsed", "?")
            lines.append(f"  ALDECI total ingested (session): {total_ever}")
        lines.append(f"  ALDECI risk level: {risk_level}")
        report_lines.extend(lines)

    # Step 5: Final report
    print(f"\n{'='*70}")
    print("SECURITY SCAN REPORT")
    print("=" * 70)
    for line in report_lines:
        print(line)

    # Final global stats
    print(f"\n{'─'*60}")
    print("[ALDECI] Final platform stats:")
    stats = _parse_stats(_api_get("/api/v1/scanner-ingest/stats"))
    if stats:
        print(f"  Total files processed : {stats.get('total_files_processed', '?')}")
        print(f"  Total findings parsed : {stats.get('total_findings_parsed', '?')}")
        print(f"  Last ingest at        : {stats.get('last_ingest_at', '?')}")
        by_scanner = stats.get("by_scanner", {})
        if by_scanner:
            print("  By scanner:")
            for sc, sc_stats in by_scanner.items():
                print(f"    {sc:20s}: {sc_stats.get('findings', 0)} findings in {sc_stats.get('files', 0)} files")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
