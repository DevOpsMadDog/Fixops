#!/usr/bin/env python3
"""
ALDECI ASPM+CSPM Test Harness
==============================
Full pipeline: clone → scan → ingest → exercise engines → report.

Usage:
    python scripts/aspm_cspm_harness.py

Requires: trivy, syft, semgrep, checkov (optional), git, kubectl
Backend:  http://localhost:8000  (ALDECI)
Cluster:  kind-aldeci-lab
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
from typing import Any, Dict, List, Optional, Tuple

import urllib.request
import urllib.error

# ── Config ─────────────────────────────────────────────────────────────────
BASE_URL   = "http://localhost:8000"
API_TOKEN  = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
ORG_ID     = "aspm-test"
REPOS_DIR  = Path("/tmp/aspm-repos")
ARTIFACTS  = Path("/tmp/aspm-artifacts")
API_DELAY  = 0.3   # seconds between API calls
SCAN_TIMEOUT = 300  # seconds per scan tool
CLONE_TIMEOUT = 120

HEADERS = {
    "X-API-Key": API_TOKEN,
    "Content-Type": "application/json",
}

# ── Repo definitions ────────────────────────────────────────────────────────
@dataclass
class RepoConfig:
    name: str
    url: str
    kind: str   # "application" | "infrastructure" | "kubernetes"
    desc: str

REPOS: List[RepoConfig] = [
    RepoConfig("microservices-demo",               "https://github.com/GoogleCloudPlatform/microservices-demo",         "application",    "Google microservices demo (k8s + app)"),
    RepoConfig("podinfo",                          "https://github.com/stefanprodan/podinfo",                           "application",    "Stefanprodan podinfo Go app"),
    RepoConfig("spring-petclinic",                 "https://github.com/spring-projects/spring-petclinic",               "application",    "Spring Boot petclinic Java app"),
    RepoConfig("terraform-aws-eks",                "https://github.com/terraform-aws-modules/terraform-aws-eks",        "infrastructure", "Terraform AWS EKS module"),
    RepoConfig("terraform-azurerm-caf-enterprise-scale", "https://github.com/Azure/terraform-azurerm-caf-enterprise-scale", "infrastructure", "Azure CAF enterprise scale"),
    RepoConfig("argocd-example-apps",              "https://github.com/argoproj/argocd-example-apps",                  "kubernetes",     "ArgoCD example apps / k8s manifests"),
    RepoConfig("terragoat",                        "https://github.com/bridgecrewio/terragoat",                         "infrastructure", "Intentionally vulnerable Terraform (validation)"),
    RepoConfig("kubernetes-goat",                  "https://github.com/madhuakula/kubernetes-goat",                     "kubernetes",     "Intentionally vulnerable k8s (validation)"),
]

# ── Result containers ───────────────────────────────────────────────────────
@dataclass
class ScanResult:
    trivy_vulns:       Dict[str, int] = field(default_factory=lambda: {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0})
    trivy_misconfigs:  Dict[str, int] = field(default_factory=lambda: {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0})
    semgrep_findings:  int = 0
    sbom_components:   int = 0
    sbom_licenses:     List[str] = field(default_factory=list)
    checkov_passed:    int = 0
    checkov_failed:    int = 0
    top_findings:      List[Dict] = field(default_factory=list)
    scan_errors:       List[str] = field(default_factory=list)

@dataclass
class IngestResult:
    asset_id:       str = ""
    findings_sent:  int = 0
    tickets_created:int = 0
    sbom_ingested:  bool = False
    errors:         List[str] = field(default_factory=list)

@dataclass
class RepoResult:
    repo:    RepoConfig = None
    cloned:  bool = False
    scan:    ScanResult = field(default_factory=ScanResult)
    ingest:  IngestResult = field(default_factory=IngestResult)
    aldeci_risk:  str = "unknown"

# ── HTTP helpers ────────────────────────────────────────────────────────────
def api_get(path: str, params: Dict[str, str] = None) -> Optional[Dict]:
    """GET request returning parsed JSON or None on error."""
    url = f"{BASE_URL}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    try:
        req = urllib.request.Request(url, headers={k: v for k, v in HEADERS.items() if k != "Content-Type"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return None


def api_post(path: str, body: Dict, params: Dict[str, str] = None, retries: int = 3) -> Optional[Dict]:
    """POST request returning parsed JSON or None on error. Retries on 429 with backoff."""
    url = f"{BASE_URL}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    data = json.dumps(body).encode()
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=HEADERS, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode()[:200]
            except Exception:
                detail = str(e)
            if e.code == 429:
                wait = 2 ** attempt  # 1s, 2s, 4s
                time.sleep(wait)
                continue
            print(f"    [HTTP {e.code}] POST {path}: {detail[:120]}")
            return None
        except Exception as e:
            print(f"    [ERR] POST {path}: {e}")
            return None
    return None


def run_cmd(cmd: List[str], timeout: int = SCAN_TIMEOUT, capture: bool = True) -> Tuple[int, str, str]:
    """Run subprocess, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


# ── Phase 1: Clone repos ────────────────────────────────────────────────────
def phase1_clone() -> List[RepoConfig]:
    """Clone all repos to /tmp/aspm-repos/. Returns list of successfully cloned."""
    print("\n" + "="*70)
    print("PHASE 1: Cloning repositories")
    print("="*70)
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    cloned = []
    for repo in REPOS:
        dest = REPOS_DIR / repo.name
        if dest.exists() and (dest / ".git").exists():
            print(f"  [SKIP] {repo.name} already cloned")
            cloned.append(repo)
            continue
        print(f"  [GIT]  Cloning {repo.name} ...", end=" ", flush=True)
        rc, _, err = run_cmd(
            ["git", "clone", "--depth", "1", "--single-branch", repo.url, str(dest)],
            timeout=CLONE_TIMEOUT,
        )
        if rc == 0:
            print("OK")
            cloned.append(repo)
        else:
            print(f"FAILED: {err[:80]}")
    print(f"\n  Cloned {len(cloned)}/{len(REPOS)} repos")
    return cloned


# ── Phase 2: Scan repos ─────────────────────────────────────────────────────
def _parse_trivy_json(path: Path) -> Tuple[Dict[str, int], List[Dict]]:
    """Parse trivy JSON output, return severity counts + top findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    findings = []
    if not path.exists():
        return counts, findings
    try:
        data = json.loads(path.read_text())
        results = data.get("Results", [])
        for r in results:
            for v in r.get("Vulnerabilities", []) or []:
                sev = v.get("Severity", "UNKNOWN").upper()
                counts[sev] = counts.get(sev, 0) + 1
                if sev in ("CRITICAL", "HIGH") and len(findings) < 20:
                    findings.append({
                        "cve_id":      v.get("VulnerabilityID", ""),
                        "title":       v.get("Title", v.get("VulnerabilityID", "Unknown")),
                        "severity":    sev.lower(),
                        "cvss_score":  float(v.get("CVSS", {}).get("nvd", {}).get("V3Score", 0) or
                                            v.get("CVSS", {}).get("ghsa", {}).get("V3Score", 0) or 0),
                        "pkg":         v.get("PkgName", ""),
                        "fixed_ver":   v.get("FixedVersion", ""),
                        "description": (v.get("Description", "")[:200] if v.get("Description") else ""),
                    })
            # Also parse misconfigs (IaC scan)
            for m in r.get("Misconfigurations", []) or []:
                sev = m.get("Severity", "UNKNOWN").upper()
                counts[sev] = counts.get(sev, 0) + 1
                if sev in ("CRITICAL", "HIGH") and len(findings) < 20:
                    findings.append({
                        "cve_id":      m.get("ID", ""),
                        "title":       m.get("Title", m.get("ID", "Misconfiguration")),
                        "severity":    sev.lower(),
                        "cvss_score":  7.5 if sev == "CRITICAL" else 5.0,
                        "pkg":         m.get("Type", "iac"),
                        "fixed_ver":   "",
                        "description": (m.get("Description", "")[:200] if m.get("Description") else ""),
                    })
    except Exception as e:
        pass
    return counts, findings


def _parse_semgrep_json(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text())
        return len(data.get("results", []))
    except Exception:
        return 0


def _parse_sbom_json(path: Path) -> Tuple[int, List[str]]:
    """Parse CycloneDX SBOM JSON, return (component_count, license_list)."""
    if not path.exists():
        return 0, []
    try:
        data = json.loads(path.read_text())
        components = data.get("components", [])
        licenses = []
        for c in components:
            for lic in c.get("licenses", []) or []:
                lid = (lic.get("license", {}) or {}).get("id", "")
                if lid and lid not in licenses:
                    licenses.append(lid)
        return len(components), licenses
    except Exception:
        return 0, []


def _parse_checkov_json(artifacts_dir: Path, repo_name: str) -> Tuple[int, int]:
    """Parse checkov JSON output."""
    # checkov writes to a directory; look for results_*.json
    passed = failed = 0
    for p in artifacts_dir.glob(f"results_*.json"):
        try:
            data = json.loads(p.read_text())
            summary = data.get("summary", {})
            passed += summary.get("passed", 0)
            failed += summary.get("failed", 0)
        except Exception:
            pass
    # Also check repo-specific file
    ck_file = artifacts_dir / f"{repo_name}_checkov.json"
    if ck_file.exists():
        try:
            data = json.loads(ck_file.read_text())
            summary = data.get("summary", {})
            passed += summary.get("passed", 0)
            failed += summary.get("failed", 0)
        except Exception:
            pass
    return passed, failed


def phase2_scan(repos: List[RepoConfig]) -> Dict[str, ScanResult]:
    """Run all scans. Returns {repo_name: ScanResult}."""
    print("\n" + "="*70)
    print("PHASE 2: Scanning repositories")
    print("="*70)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    results: Dict[str, ScanResult] = {}

    for repo in repos:
        src = REPOS_DIR / repo.name
        sr = ScanResult()
        print(f"\n  [{repo.kind.upper()}] {repo.name}")

        if repo.kind == "application":
            # --- Trivy filesystem scan ---
            trivy_out = ARTIFACTS / f"{repo.name}_trivy.json"
            print(f"    trivy fs ...", end=" ", flush=True)
            rc, _, err = run_cmd([
                "trivy", "fs",
                "--format", "json",
                "--output", str(trivy_out),
                "--scanners", "vuln,secret",
                "--timeout", "5m",
                str(src),
            ])
            if rc in (0, 1):  # trivy returns 1 when vulns found
                counts, findings = _parse_trivy_json(trivy_out)
                sr.trivy_vulns = counts
                sr.top_findings.extend(findings[:20])
                total = sum(counts.values())
                print(f"OK ({total} vulns: {counts['CRITICAL']}C/{counts['HIGH']}H/{counts['MEDIUM']}M/{counts['LOW']}L)")
            else:
                sr.scan_errors.append(f"trivy-fs: rc={rc}")
                print(f"FAIL rc={rc}")

            # --- Semgrep ---
            semgrep_out = ARTIFACTS / f"{repo.name}_semgrep.json"
            print(f"    semgrep ...", end=" ", flush=True)
            rc, out, err = run_cmd([
                "semgrep", "scan",
                "--config", "auto",
                "--json",
                "--output", str(semgrep_out),
                str(src),
            ], timeout=180)
            sr.semgrep_findings = _parse_semgrep_json(semgrep_out)
            if rc in (0, 1):
                print(f"OK ({sr.semgrep_findings} findings)")
            else:
                sr.scan_errors.append(f"semgrep: rc={rc}")
                print(f"FAIL rc={rc} ({sr.semgrep_findings} findings parsed)")

            # --- Syft SBOM ---
            sbom_out = ARTIFACTS / f"{repo.name}_sbom.json"
            print(f"    syft ...", end=" ", flush=True)
            rc, _, err = run_cmd([
                "syft",
                f"dir:{src}",
                "-o", f"cyclonedx-json={sbom_out}",
                "--quiet",
            ], timeout=120)
            sr.sbom_components, sr.sbom_licenses = _parse_sbom_json(sbom_out)
            if rc == 0:
                print(f"OK ({sr.sbom_components} components, {len(sr.sbom_licenses)} licenses)")
            else:
                sr.scan_errors.append(f"syft: rc={rc}")
                print(f"FAIL rc={rc} ({sr.sbom_components} components parsed)")

        elif repo.kind == "infrastructure":
            # --- Trivy IaC config scan ---
            trivy_iac_out = ARTIFACTS / f"{repo.name}_trivy_iac.json"
            print(f"    trivy config ...", end=" ", flush=True)
            rc, _, err = run_cmd([
                "trivy", "config",
                "--format", "json",
                "--output", str(trivy_iac_out),
                "--timeout", "5m",
                str(src),
            ])
            if rc in (0, 1):
                counts, findings = _parse_trivy_json(trivy_iac_out)
                sr.trivy_misconfigs = {k: v for k, v in counts.items() if k != "UNKNOWN"}
                sr.top_findings.extend(findings[:20])
                total = sum(counts.values())
                print(f"OK ({total} misconfigs)")
            else:
                sr.scan_errors.append(f"trivy-config: rc={rc}")
                print(f"FAIL rc={rc}")

            # --- Checkov ---
            ck_out_dir = str(ARTIFACTS)
            print(f"    checkov ...", end=" ", flush=True)
            rc, out, err = run_cmd([
                "checkov",
                "-d", str(src),
                "--output", "json",
                "--output-file-path", ck_out_dir,
                "--quiet",
            ], timeout=180)
            # checkov writes results_*.json to the output dir
            p, f_ = _parse_checkov_json(ARTIFACTS, repo.name)
            sr.checkov_passed = p
            sr.checkov_failed = f_
            if rc in (0, 1):
                print(f"OK ({p} passed / {f_} failed)")
            else:
                sr.scan_errors.append(f"checkov: rc={rc}")
                print(f"FAIL rc={rc} ({p}p/{f_}f parsed)")

            # Also do syft on infra repos for package detection
            sbom_out = ARTIFACTS / f"{repo.name}_sbom.json"
            rc, _, _ = run_cmd([
                "syft", f"dir:{src}",
                "-o", f"cyclonedx-json={sbom_out}",
                "--quiet",
            ], timeout=90)
            sr.sbom_components, sr.sbom_licenses = _parse_sbom_json(sbom_out)

        elif repo.kind == "kubernetes":
            # --- Trivy k8s manifest config scan ---
            trivy_k8s_out = ARTIFACTS / f"{repo.name}_trivy_k8s.json"
            print(f"    trivy config (k8s) ...", end=" ", flush=True)
            rc, _, err = run_cmd([
                "trivy", "config",
                "--format", "json",
                "--output", str(trivy_k8s_out),
                "--timeout", "5m",
                str(src),
            ])
            if rc in (0, 1):
                counts, findings = _parse_trivy_json(trivy_k8s_out)
                sr.trivy_misconfigs = {k: v for k, v in counts.items() if k != "UNKNOWN"}
                sr.top_findings.extend(findings[:20])
                total = sum(counts.values())
                print(f"OK ({total} misconfigs)")
            else:
                sr.scan_errors.append(f"trivy-k8s: rc={rc}")
                print(f"FAIL rc={rc}")

            # Also trivy fs for any app code
            trivy_fs_out = ARTIFACTS / f"{repo.name}_trivy_fs.json"
            rc, _, _ = run_cmd([
                "trivy", "fs",
                "--format", "json",
                "--output", str(trivy_fs_out),
                "--scanners", "vuln",
                "--timeout", "3m",
                str(src),
            ], timeout=180)
            if rc in (0, 1):
                counts2, findings2 = _parse_trivy_json(trivy_fs_out)
                for k in sr.trivy_vulns:
                    sr.trivy_vulns[k] += counts2.get(k, 0)
                sr.top_findings.extend([f for f in findings2 if f not in sr.top_findings][:10])

        results[repo.name] = sr

    return results


# ── Phase 3: Ingest into ALDECI ─────────────────────────────────────────────
def _severity_to_priority(sev: str) -> str:
    return {"critical": "p1", "high": "p2", "medium": "p3", "low": "p4"}.get(sev.lower(), "p3")


def phase3_ingest(repos: List[RepoConfig], scan_results: Dict[str, ScanResult]) -> Dict[str, IngestResult]:
    """Ingest all scan data into ALDECI. Returns {repo_name: IngestResult}."""
    print("\n" + "="*70)
    print("PHASE 3: Ingesting data into ALDECI")
    print("="*70)
    ingest_results: Dict[str, IngestResult] = {}

    for repo in repos:
        sr = scan_results.get(repo.name, ScanResult())
        ir = IngestResult()
        print(f"\n  {repo.name}")

        # a) Register asset
        asset_id = f"aspm-{repo.name}-{ORG_ID}"
        ir.asset_id = asset_id
        payload = {
            "asset_id": asset_id,
            "org_id":   ORG_ID,
            "name":     repo.name,
            "asset_type": repo.kind,
        }
        resp = api_post("/api/v1/brain/ingest/asset", payload)
        time.sleep(API_DELAY)
        if resp:
            print(f"    [OK] asset registered: {asset_id}")
        else:
            ir.errors.append("asset-register-failed")
            print(f"    [WARN] asset register returned None (may already exist)")

        # b) Upload trivy scan result via scanner-ingest/webhook
        trivy_file = None
        if repo.kind == "application":
            trivy_file = ARTIFACTS / f"{repo.name}_trivy.json"
            scanner_type = "trivy"
        else:
            trivy_file = (ARTIFACTS / f"{repo.name}_trivy_iac.json"
                          if repo.kind == "infrastructure"
                          else ARTIFACTS / f"{repo.name}_trivy_k8s.json")
            scanner_type = "trivy"

        if trivy_file and trivy_file.exists():
            raw = trivy_file.read_bytes()
            # Use multipart upload
            boundary = f"----boundary{uuid.uuid4().hex}"
            body_parts = [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="file"; filename="{trivy_file.name}"\r\n'.encode(),
                b"Content-Type: application/json\r\n\r\n",
                raw,
                f"\r\n--{boundary}\r\n".encode(),
                b'Content-Disposition: form-data; name="scanner_type"\r\n\r\n',
                scanner_type.encode(),
                f"\r\n--{boundary}--\r\n".encode(),
            ]
            body = b"".join(body_parts)
            try:
                upload_headers = {
                    "X-API-Key": API_TOKEN,
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                }
                req = urllib.request.Request(
                    f"{BASE_URL}/api/v1/scanner-ingest/upload",
                    data=body,
                    headers=upload_headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    result = json.loads(resp.read())
                    print(f"    [OK] trivy upload: {result.get('findings_parsed', '?')} findings parsed")
            except Exception as e:
                print(f"    [WARN] trivy upload: {e}")
                ir.errors.append(f"trivy-upload: {e}")
            time.sleep(API_DELAY)

        # c) Ingest SBOM components into brain
        sbom_file = ARTIFACTS / f"{repo.name}_sbom.json"
        if sbom_file.exists() and sr.sbom_components > 0:
            try:
                sbom_data = json.loads(sbom_file.read_text())
                components = sbom_data.get("components", [])
                ingested = 0
                for comp in components[:50]:  # top 50 components
                    cname = comp.get("name", "unknown")
                    cver  = comp.get("version", "")
                    node_payload = {
                        "node_id":   f"sbom-{repo.name}-{cname}-{cver}"[:256],
                        "node_type": "software_component",
                        "org_id":    ORG_ID,
                        "properties": {
                            "name":    cname,
                            "version": cver,
                            "type":    comp.get("type", "library"),
                            "repo":    repo.name,
                            "licenses": [
                                (lic.get("license", {}) or {}).get("id", "")
                                for lic in comp.get("licenses", []) or []
                            ],
                        },
                    }
                    api_post("/api/v1/brain/nodes", node_payload)
                    ingested += 1
                    time.sleep(1.2)  # stay under rate limit
                ir.sbom_ingested = True
                print(f"    [OK] SBOM: {ingested} components ingested to brain graph")
            except Exception as e:
                ir.errors.append(f"sbom-ingest: {e}")
                print(f"    [WARN] SBOM ingest: {e}")
            time.sleep(API_DELAY)

        # d) Ingest top findings
        findings = sr.top_findings[:20]
        sent = 0
        for i, f in enumerate(findings):
            fid = f"finding-{repo.name}-{i}-{f.get('cve_id','unk')}"[:400]
            payload = {
                "finding_id": fid,
                "org_id":     ORG_ID,
                "cve_id":     f.get("cve_id", ""),
                "title":      f.get("title", "Security Finding")[:500],
                "severity":   f.get("severity", "medium"),
                "source":     f"trivy-{repo.kind}",
            }
            resp = api_post("/api/v1/brain/ingest/finding", payload)
            if resp:
                sent += 1
            time.sleep(1.0)  # stay under rate limit
        ir.findings_sent = sent
        if sent:
            print(f"    [OK] {sent} findings ingested to brain")

        ingest_results[repo.name] = ir

    return ingest_results


# ── Phase 4: Exercise ALDECI engines ────────────────────────────────────────
def phase4_exercise(repos: List[RepoConfig], scan_results: Dict[str, ScanResult],
                    ingest_results: Dict[str, IngestResult]) -> Dict[str, Any]:
    """Exercise ALDECI engines with real data. Returns engine output dict."""
    print("\n" + "="*70)
    print("PHASE 4: Exercising ALDECI ASPM/CSPM engines")
    print("="*70)
    engine_data: Dict[str, Any] = {}

    # a) Risk scoring
    print("  [a] Risk scoring: GET /api/v1/risk/overview")
    resp = api_get("/api/v1/risk/overview", {"org_id": ORG_ID})
    engine_data["risk_overview"] = resp
    if resp:
        print(f"      Risk score: {resp.get('risk_score',0)} | Level: {resp.get('risk_level','?')} | "
              f"Findings: {resp.get('total_findings',0)} | CVEs: {resp.get('total_cves',0)}")
    time.sleep(API_DELAY)

    # b) Compliance status
    print("  [b] Compliance: GET /api/v1/compliance/status")
    resp = api_get("/api/v1/compliance/status", {"org_id": ORG_ID})
    engine_data["compliance_status"] = resp
    if resp:
        score = resp.get("overall_score", 0)
        fw_count = len(resp.get("frameworks", []))
        print(f"      Overall: {score:.1f}% | Frameworks: {fw_count}")
    time.sleep(API_DELAY)

    # c) Create vuln-workflow tickets for critical findings
    print("  [c] Creating vuln-workflow tickets for CRITICAL findings")
    tickets_created = 0
    all_findings = []
    for repo in repos:
        sr = scan_results.get(repo.name, ScanResult())
        for f in sr.top_findings:
            if f.get("severity") in ("critical", "high"):
                all_findings.append((repo.name, f))

    for repo_name, f in all_findings[:10]:  # cap at 10 tickets
        ticket_payload = {
            "title":          f"[ASPM] {f.get('cve_id','Finding')} in {repo_name}: {f.get('title','')[:80]}",
            "cve_id":         f.get("cve_id", ""),
            "severity":       f.get("severity", "high"),
            "cvss_score":     float(f.get("cvss_score", 0)),
            "affected_assets":[f"aspm-{repo_name}-{ORG_ID}"],
            "priority":       _severity_to_priority(f.get("severity", "high")),
            "source_engine":  "aspm-cspm-harness",
            "tags":           ["aspm", "automated", repo_name, f.get("severity","")],
        }
        resp = api_post("/api/v1/vuln-workflow/tickets", ticket_payload,
                        params={"org_id": ORG_ID})
        if resp and resp.get("ticket_id"):
            tickets_created += 1
            if ingest_results.get(repo_name):
                ingest_results[repo_name].tickets_created += 1
        time.sleep(API_DELAY)
    engine_data["tickets_created"] = tickets_created
    print(f"      Created {tickets_created} tickets")

    # d) Cross-app analytics
    print("  [d] Cross-app analytics: GET /api/v1/analytics/summary")
    resp = api_get("/api/v1/analytics/summary", {"org_id": ORG_ID})
    engine_data["analytics_summary"] = resp
    if resp:
        total = resp.get("total_findings", 0)
        sev = resp.get("severity_breakdown", {})
        print(f"      Total findings: {total} | Crit: {sev.get('critical',0)} | High: {sev.get('high',0)}")
    time.sleep(API_DELAY)

    # e) Security scoreboard
    print("  [e] Security scoreboard: GET /api/v1/security-scoreboard/leaderboard")
    resp = api_get("/api/v1/security-scoreboard/leaderboard", {"org_id": ORG_ID})
    engine_data["scoreboard"] = resp
    if resp:
        entries = resp if isinstance(resp, list) else resp.get("leaderboard", resp.get("entries", []))
        print(f"      Leaderboard entries: {len(entries) if isinstance(entries, list) else '?'}")
    time.sleep(API_DELAY)

    # f) SBOM licenses
    print("  [f] SBOM licensing: GET /api/v1/sbom/licenses")
    resp = api_get("/api/v1/sbom/licenses", {"org_id": ORG_ID})
    engine_data["sbom_licenses"] = resp
    if resp:
        lcount = resp.get("total", 0)
        hrisk  = resp.get("high_risk_count", 0)
        print(f"      License types: {lcount} | High-risk: {hrisk}")
    time.sleep(API_DELAY)

    # g) Attack surface (ASM)
    print("  [g] Attack surface: GET /api/v1/asm/exposures")
    resp = api_get("/api/v1/asm/exposures", {"org_id": ORG_ID})
    if not resp:
        resp = api_get("/api/v1/attack-surface/summary", {"org_id": ORG_ID})
    if not resp:
        resp = api_get("/api/v1/asm/assets", {"org_id": ORG_ID})
    engine_data["attack_surface"] = resp
    if resp:
        items = resp if isinstance(resp, list) else resp.get("exposures", resp.get("assets", resp.get("data", [])))
        count = len(items) if isinstance(items, list) else resp.get("total", "?")
        print(f"      ASM entries: {count}")
    else:
        print("      (no ASM data yet — assets registered, scan in progress)")
    time.sleep(API_DELAY)

    # h) Threat intel correlation — check KEV/EPSS for top CVEs
    print("  [h] Threat intel correlation: KEV/EPSS checks")
    # Collect unique CVE IDs from all findings
    cve_ids = list({
        f.get("cve_id", "")
        for repo in repos
        for f in scan_results.get(repo.name, ScanResult()).top_findings
        if f.get("cve_id", "").startswith("CVE-")
    })[:5]
    kev_matches = []
    for cve_id in cve_ids:
        resp = api_get("/api/v1/cve/search", {"org_id": ORG_ID, "q": cve_id})
        if resp:
            items = resp if isinstance(resp, list) else resp.get("results", resp.get("cves", []))
            for item in (items if isinstance(items, list) else []):
                if item.get("kev") or item.get("in_kev") or item.get("is_kev"):
                    kev_matches.append(cve_id)
        time.sleep(API_DELAY * 0.5)
    engine_data["kev_matches"] = kev_matches
    print(f"      Checked {len(cve_ids)} CVEs | KEV matches: {len(kev_matches)}: {kev_matches[:5]}")

    # Also check risk/overview for brain-enriched data
    time.sleep(API_DELAY)
    resp2 = api_get("/api/v1/risk/overview", {"org_id": ORG_ID})
    engine_data["risk_overview_post"] = resp2

    return engine_data


# ── Phase 5: Report ─────────────────────────────────────────────────────────
def phase5_report(
    repos: List[RepoConfig],
    scan_results: Dict[str, ScanResult],
    ingest_results: Dict[str, IngestResult],
    engine_data: Dict[str, Any],
) -> None:
    """Print comprehensive ASPM/CSPM report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("\n\n" + "="*70)
    print("=== ALDECI ASPM/CSPM TEST HARNESS REPORT ===")
    print(f"    Generated: {ts}  |  Org: {ORG_ID}  |  Backend: {BASE_URL}")
    print("="*70)

    total_vulns   = 0
    total_misconf = 0
    total_semgrep = 0
    total_sbom    = 0
    total_tickets = 0
    all_top_findings: List[Tuple[str, Dict]] = []

    for repo in repos:
        sr = scan_results.get(repo.name, ScanResult())
        ir = ingest_results.get(repo.name, IngestResult())
        risk_resp = engine_data.get("risk_overview_post") or {}

        print(f"\nREPO: {repo.name}  ({repo.kind.upper()})")
        print(f"  Description : {repo.desc}")
        print(f"  ALDECI Asset: {ir.asset_id or 'not registered'}")

        if repo.kind == "application":
            vc = sr.trivy_vulns
            tv = sum(vc.values())
            total_vulns += tv
            print(f"  Trivy Vulns : {tv} total  "
                  f"[CRIT={vc['CRITICAL']} HIGH={vc['HIGH']} MED={vc['MEDIUM']} LOW={vc['LOW']}]")
            print(f"  Semgrep     : {sr.semgrep_findings} SAST findings")
            print(f"  SBOM        : {sr.sbom_components} components  |  "
                  f"Licenses: {', '.join(sr.sbom_licenses[:8]) or 'none'}")
        elif repo.kind == "infrastructure":
            mc = sr.trivy_misconfigs
            tm = sum(mc.values())
            total_misconf += tm
            print(f"  Trivy IaC   : {tm} misconfigs  "
                  f"[CRIT={mc.get('CRITICAL',0)} HIGH={mc.get('HIGH',0)} MED={mc.get('MEDIUM',0)} LOW={mc.get('LOW',0)}]")
            print(f"  Checkov     : {sr.checkov_passed} passed / {sr.checkov_failed} failed")
            if repo.name == "terragoat":
                severity_note = "HIGH (intentionally vulnerable)" if tm > 0 else "check scan"
                print(f"  Validation  : {severity_note}")
        elif repo.kind == "kubernetes":
            mc = sr.trivy_misconfigs
            tm = sum(mc.values())
            total_misconf += tm
            vc = sr.trivy_vulns
            tv = sum(vc.values())
            total_vulns += tv
            print(f"  Trivy K8s   : {tm} manifest misconfigs  "
                  f"[CRIT={mc.get('CRITICAL',0)} HIGH={mc.get('HIGH',0)} MED={mc.get('MEDIUM',0)} LOW={mc.get('LOW',0)}]")
            if tv:
                print(f"  Trivy FS    : {tv} vulns  "
                      f"[CRIT={vc.get('CRITICAL',0)} HIGH={vc.get('HIGH',0)}]")
            if repo.name == "kubernetes-goat":
                print(f"  Validation  : HIGH (intentionally vulnerable)")

        total_semgrep += sr.semgrep_findings
        total_sbom    += sr.sbom_components
        total_tickets += ir.tickets_created

        if sr.scan_errors:
            print(f"  Scan errors : {', '.join(sr.scan_errors)}")

        print(f"  ALDECI Ingest: {ir.findings_sent} findings | "
              f"SBOM={'yes' if ir.sbom_ingested else 'no'} | "
              f"Tickets={ir.tickets_created}")

        for f in sr.top_findings[:3]:
            sev = f.get("severity","?").upper()
            cve = f.get("cve_id","")
            title = f.get("title","")[:60]
            print(f"    [{sev}] {cve or title}")
        all_top_findings.extend([(repo.name, f) for f in sr.top_findings])

    # Cross-repo intelligence
    print("\n" + "-"*70)
    print("CROSS-REPO INTELLIGENCE")
    print("-"*70)

    risk_data       = engine_data.get("risk_overview_post") or engine_data.get("risk_overview") or {}
    compliance_data = engine_data.get("compliance_status") or {}
    analytics_data  = engine_data.get("analytics_summary") or {}
    sbom_data       = engine_data.get("sbom_licenses") or {}
    kev_matches     = engine_data.get("kev_matches", [])

    print(f"  Total trivy vulns       : {total_vulns}")
    print(f"  Total IaC misconfigs    : {total_misconf}")
    print(f"  Total semgrep findings  : {total_semgrep}")
    print(f"  Total SBOM components   : {total_sbom}")
    print(f"  Vuln tickets created    : {engine_data.get('tickets_created', total_tickets)}")

    print(f"\n  ALDECI Risk Score       : {risk_data.get('risk_score', 'N/A')} ({risk_data.get('risk_level','?')})")
    print(f"  ALDECI Total Findings   : {risk_data.get('total_findings', analytics_data.get('total_findings','?'))}")
    print(f"  ALDECI CVEs tracked     : {risk_data.get('total_cves','?')}")

    print(f"\n  Compliance Score        : {compliance_data.get('overall_score','?')}%")
    fws = compliance_data.get("frameworks", [])
    for fw in fws[:6]:
        print(f"    {fw.get('name','?'):40s}  {fw.get('score',0):5.1f}%")

    print(f"\n  SBOM License types      : {sbom_data.get('total','?')}")
    print(f"  High-risk licenses      : {sbom_data.get('high_risk_count','?')}")
    print(f"  KEV-matched CVEs        : {len(kev_matches)}  {kev_matches[:5] if kev_matches else ''}")

    # Top 10 critical findings across all repos
    crit_findings = sorted(
        [(rn, f) for rn, f in all_top_findings if f.get("severity") in ("critical","high")],
        key=lambda x: x[1].get("cvss_score", 0),
        reverse=True,
    )[:10]

    if crit_findings:
        print(f"\n  TOP {len(crit_findings)} CRITICAL/HIGH FINDINGS ACROSS ALL REPOS:")
        for rn, f in crit_findings:
            sev   = f.get("severity","?").upper()
            cve   = f.get("cve_id","FINDING")
            title = f.get("title","")[:55]
            cvss  = f.get("cvss_score", 0)
            pkg   = f.get("pkg","")
            print(f"    [{sev:8s}] CVSS={cvss:.1f}  {cve:20s}  {rn:30s}  {pkg:20s}  {title}")

    # Cluster check
    print("\n" + "-"*70)
    print("KUBERNETES CLUSTER (kind-aldeci-lab)")
    print("-"*70)
    rc, out, _ = run_cmd(["kubectl", "get", "nodes", "--context", "kind-aldeci-lab",
                          "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type,VERSION:.status.nodeInfo.kubeletVersion"],
                         timeout=15)
    if rc == 0:
        for line in out.strip().splitlines():
            print(f"  {line}")
    rc, out, _ = run_cmd(["kubectl", "get", "pods", "--all-namespaces", "--context", "kind-aldeci-lab",
                          "--field-selector=status.phase=Running",
                          "-o", "custom-columns=NS:.metadata.namespace,NAME:.metadata.name,STATUS:.status.phase"],
                         timeout=15)
    if rc == 0:
        lines = out.strip().splitlines()
        print(f"  Running pods: {len(lines)-1}")

    print("\n" + "="*70)
    print("=== END REPORT ===")
    print("="*70)


# ── Main ────────────────────────────────────────────────────────────────────
def main() -> None:
    print("ALDECI ASPM+CSPM Test Harness")
    print(f"Backend : {BASE_URL}")
    print(f"Org     : {ORG_ID}")
    print(f"Repos   : {REPOS_DIR}")
    print(f"Artifacts: {ARTIFACTS}")

    # Verify backend connectivity
    resp = api_get("/health")
    if not resp:
        resp = api_get("/api/v1/brain/health")
    if resp:
        print(f"Backend : CONNECTED  status={resp.get('status','ok')}")
    else:
        print("Backend : WARNING — cannot reach health endpoint, continuing anyway")

    cloned_repos = phase1_clone()
    if not cloned_repos:
        print("ERROR: No repos cloned. Exiting.")
        sys.exit(1)

    scan_results   = phase2_scan(cloned_repos)
    ingest_results = phase3_ingest(cloned_repos, scan_results)
    engine_data    = phase4_exercise(cloned_repos, scan_results, ingest_results)
    phase5_report(cloned_repos, scan_results, ingest_results, engine_data)


if __name__ == "__main__":
    main()
