"""
ALDECI Real E2E GitHub Scanner
================================
Clones real public repos (shallow, depth=1) into a temp directory and
runs every ALDECI security engine against them.  Produces a structured
report at reports/e2e_real_scan_results.json.

Usage:
    python scripts/e2e_real_github_scan.py [--repos nanoGPT fastapi ...]
    python scripts/e2e_real_github_scan.py --list-repos

Each repo scan runs:
  1. SAST engine     — real vulnerability pattern matching
  2. Secrets scanner — 200+ regex patterns for leaked credentials
  3. IaC scanner     — Dockerfiles, Kubernetes YAML, Terraform
  4. Dependency scanner — requirements.txt / setup.py / pyproject.toml
  5. License checker — SPDX risk classification per dependency
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path bootstrap — mirrors how every other test/script in this repo works
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "suite-core"))

from core.sast_engine import SASTEngine, get_sast_engine
from core.secrets_manager import SecretsManager, get_manager, _scan_content, ScanType
from core.iac_scanner_engine import IaCScannerEngine, get_iac_scanner
from core.supply_chain_security import (
    DependencyRiskScorer,
    LicenseRisk,
    ProvenanceLevel,
    RiskLevel,
    SBOMComponent,
    SupplyChainEngine,
)
from core.license_compliance import get_engine as get_license_engine

# ---------------------------------------------------------------------------
# Repos catalogue
# ---------------------------------------------------------------------------
REPOS: Dict[str, str] = {
    "nanoGPT":  "https://github.com/karpathy/nanoGPT.git",
    "fastapi":  "https://github.com/tiangolo/fastapi.git",
    "flask":    "https://github.com/pallets/flask.git",
    "requests": "https://github.com/psf/requests.git",
    "django":   "https://github.com/django/django.git",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_network() -> bool:
    """Return True if github.com is reachable."""
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--exit-code", "https://github.com/karpathy/nanoGPT.git", "HEAD"],
            capture_output=True,
            timeout=15,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def clone_repo(url: str, target: Path, timeout: int = 120) -> Tuple[bool, str]:
    """Shallow-clone *url* into *target*.  Returns (success, error_message)."""
    cmd = ["git", "clone", "--depth", "1", "--single-branch", url, str(target)]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, f"Clone timed out after {timeout}s"
    except OSError as exc:
        return False, str(exc)


def _parse_requirements(req_file: Path) -> List[Tuple[str, str]]:
    """Return list of (package_name, version_spec) from a requirements.txt."""
    deps: List[Tuple[str, str]] = []
    try:
        for raw_line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip extras and env markers
            line = re.split(r"[;#\[]", line)[0].strip()
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([>=<!~^].*)?$", line)
            if match:
                name = match.group(1).strip()
                version_spec = (match.group(2) or "unknown").strip() or "unknown"
                deps.append((name, version_spec))
    except OSError:
        pass
    return deps


def _parse_pyproject(pyproject_file: Path) -> List[Tuple[str, str]]:
    """Extract dependencies from pyproject.toml using regex (no toml dep needed)."""
    deps: List[Tuple[str, str]] = []
    try:
        content = pyproject_file.read_text(encoding="utf-8", errors="replace")
        # Match lines inside [project] dependencies or [tool.poetry.dependencies]
        dep_pattern = re.compile(
            r"""["']([A-Za-z0-9_\-\.]+)\s*([>=<!~^][^"']*)?["']"""
        )
        for match in dep_pattern.finditer(content):
            name = match.group(1).strip()
            version_spec = (match.group(2) or "unknown").strip() or "unknown"
            if name.lower() not in ("python", "pip", "setuptools"):
                deps.append((name, version_spec))
    except OSError:
        pass
    return deps


def _collect_dependencies(repo_root: Path) -> List[Tuple[str, str]]:
    """Collect all Python dependencies from the repo."""
    deps: List[Tuple[str, str]] = []
    for req_file in repo_root.rglob("requirements*.txt"):
        deps.extend(_parse_requirements(req_file))
    for pyproject in repo_root.rglob("pyproject.toml"):
        deps.extend(_parse_pyproject(pyproject))
    # De-duplicate by package name
    seen: dict = {}
    for name, version_spec in deps:
        key = name.lower()
        if key not in seen:
            seen[key] = (name, version_spec)
    return list(seen.values())


# ---------------------------------------------------------------------------
# Per-engine scan functions
# ---------------------------------------------------------------------------

def run_sast(repo_root: Path, sast: SASTEngine) -> Dict[str, Any]:
    """Run SAST engine against repo_root.  Returns summary dict."""
    t0 = time.monotonic()
    try:
        result = sast.scan_path(str(repo_root))
        elapsed = time.monotonic() - t0
        by_sev: Dict[str, int] = defaultdict(int)
        cwes: List[str] = []
        for finding in result.findings:
            by_sev[finding.severity.value] += 1
            if finding.cwe_id not in cwes:
                cwes.append(finding.cwe_id)
        return {
            "engine": "sast",
            "files_scanned": result.files_scanned,
            "total_findings": result.total_findings,
            "by_severity": dict(by_sev),
            "cwe_ids_found": sorted(set(cwes)),
            "duration_s": round(elapsed, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "engine": "sast",
            "files_scanned": 0,
            "total_findings": 0,
            "by_severity": {},
            "cwe_ids_found": [],
            "duration_s": round(time.monotonic() - t0, 2),
            "error": str(exc),
        }


def run_secrets(repo_root: Path, manager: SecretsManager) -> Dict[str, Any]:
    """Run secrets scanner (filesystem mode) against repo_root."""
    t0 = time.monotonic()
    try:
        result = manager.scan_filesystem(str(repo_root))
        elapsed = time.monotonic() - t0
        by_sev: Dict[str, int] = defaultdict(int)
        categories: List[str] = []
        for finding in result.findings:
            by_sev[finding.severity.value] += 1
            cat = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
            if cat not in categories:
                categories.append(cat)
        return {
            "engine": "secrets",
            "files_scanned": result.files_scanned,
            "total_findings": len(result.findings),
            "by_severity": dict(by_sev),
            "categories_found": sorted(categories),
            "duration_s": round(elapsed, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "engine": "secrets",
            "files_scanned": 0,
            "total_findings": 0,
            "by_severity": {},
            "categories_found": [],
            "duration_s": round(time.monotonic() - t0, 2),
            "error": str(exc),
        }


def run_iac(repo_root: Path, iac: IaCScannerEngine) -> Dict[str, Any]:
    """Run IaC scanner against all Dockerfiles/YAML/Terraform in repo_root."""
    t0 = time.monotonic()
    try:
        results = iac.scan_path(str(repo_root))
        elapsed = time.monotonic() - t0
        by_sev: Dict[str, int] = defaultdict(int)
        formats_seen: List[str] = []
        total_findings = 0
        for scan_result in results:
            for finding in scan_result.findings:
                by_sev[finding.severity.value] += 1
                total_findings += 1
            fmt = scan_result.format.value if hasattr(scan_result.format, "value") else str(scan_result.format)
            if fmt not in formats_seen:
                formats_seen.append(fmt)
        return {
            "engine": "iac",
            "files_scanned": len(results),
            "total_findings": total_findings,
            "by_severity": dict(by_sev),
            "formats_found": sorted(formats_seen),
            "duration_s": round(elapsed, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "engine": "iac",
            "files_scanned": 0,
            "total_findings": 0,
            "by_severity": {},
            "formats_found": [],
            "duration_s": round(time.monotonic() - t0, 2),
            "error": str(exc),
        }


def run_dependency(repo_root: Path, scorer: DependencyRiskScorer) -> Dict[str, Any]:
    """Parse real dependency files and risk-score each package."""
    t0 = time.monotonic()
    try:
        raw_deps = _collect_dependencies(repo_root)
        sbom_id = str(uuid.uuid4())
        components: List[SBOMComponent] = []
        for name, version_spec in raw_deps:
            comp = SBOMComponent(
                name=name,
                version=version_spec,
                ecosystem="pypi",
                purl=f"pkg:pypi/{name.lower()}@{version_spec}",
                sbom_id=sbom_id,
            )
            components.append(comp)

        risk_by_level: Dict[str, int] = defaultdict(int)
        high_risk: List[str] = []
        for comp in components:
            score = scorer.score(comp)
            risk_by_level[score.risk_level.value] += 1
            if score.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                high_risk.append(f"{comp.name}@{comp.version} ({score.overall_score:.0f}/100)")

        elapsed = time.monotonic() - t0
        return {
            "engine": "dependency",
            "dependencies_found": len(components),
            "risk_by_level": dict(risk_by_level),
            "high_risk_packages": high_risk[:20],
            "duration_s": round(elapsed, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "engine": "dependency",
            "dependencies_found": 0,
            "risk_by_level": {},
            "high_risk_packages": [],
            "duration_s": round(time.monotonic() - t0, 2),
            "error": str(exc),
        }


def run_license(repo_root: Path) -> Dict[str, Any]:
    """Detect license files in the repo and classify risk."""
    t0 = time.monotonic()
    try:
        license_engine = get_license_engine()
        # Collect actual LICENSE file content
        license_files = list(repo_root.glob("LICENSE*")) + list(repo_root.glob("LICENCE*"))
        licenses_found: List[str] = []
        violations: List[str] = []

        for lf in license_files:
            content = lf.read_text(encoding="utf-8", errors="replace")
            # Heuristic SPDX detection from common license text
            spdx_id = _detect_license_spdx(content)
            if spdx_id:
                licenses_found.append(spdx_id)
                info = license_engine.lookup_license(spdx_id)
                if info and hasattr(info, "category"):
                    cat = info.category.value if hasattr(info.category, "value") else str(info.category)
                    if cat in ("strong_copyleft", "non_commercial", "proprietary"):
                        violations.append(f"{spdx_id}: {cat}")

        elapsed = time.monotonic() - t0
        return {
            "engine": "license",
            "license_files_found": len(license_files),
            "spdx_ids_detected": licenses_found,
            "violations": violations,
            "compliant": len(violations) == 0,
            "duration_s": round(elapsed, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "engine": "license",
            "license_files_found": 0,
            "spdx_ids_detected": [],
            "violations": [],
            "compliant": True,
            "duration_s": round(time.monotonic() - t0, 2),
            "error": str(exc),
        }


def _detect_license_spdx(content: str) -> Optional[str]:
    """Heuristic: map common license text fragments to SPDX identifiers."""
    c = content.lower()
    if "apache license" in c and "version 2" in c:
        return "Apache-2.0"
    if "mit license" in c or "permission is hereby granted, free of charge" in c:
        return "MIT"
    if "gnu general public license" in c and "version 3" in c:
        return "GPL-3.0"
    if "gnu general public license" in c and "version 2" in c:
        return "GPL-2.0"
    if "bsd 3-clause" in c or "redistribution and use in source and binary" in c:
        return "BSD-3-Clause"
    if "bsd 2-clause" in c:
        return "BSD-2-Clause"
    if "mozilla public license" in c:
        return "MPL-2.0"
    if "gnu lesser general public license" in c and "version 3" in c:
        return "LGPL-3.0"
    if "isc license" in c or ("permission to use, copy, modify" in c and "isc" in c):
        return "ISC"
    if "creative commons" in c:
        return "CC-BY-4.0"
    if "unlicense" in c:
        return "Unlicense"
    return None


# ---------------------------------------------------------------------------
# Risk score aggregation
# ---------------------------------------------------------------------------

def _compute_risk_score(
    sast: Dict[str, Any],
    secrets: Dict[str, Any],
    iac: Dict[str, Any],
    dependency: Dict[str, Any],
    license_result: Dict[str, Any],
) -> float:
    """Return a 0–100 composite risk score."""
    score = 0.0

    # SAST contribution (max 40 pts)
    sev = sast.get("by_severity", {})
    score += min(40.0, (
        sev.get("critical", 0) * 10 +
        sev.get("high", 0) * 5 +
        sev.get("medium", 0) * 2 +
        sev.get("low", 0) * 0.5
    ))

    # Secrets contribution (max 30 pts)
    sec_sev = secrets.get("by_severity", {})
    score += min(30.0, (
        sec_sev.get("critical", 0) * 15 +
        sec_sev.get("high", 0) * 8 +
        sec_sev.get("medium", 0) * 3
    ))

    # IaC contribution (max 15 pts)
    iac_sev = iac.get("by_severity", {})
    score += min(15.0, (
        iac_sev.get("critical", 0) * 5 +
        iac_sev.get("high", 0) * 3 +
        iac_sev.get("medium", 0) * 1
    ))

    # Dependency contribution (max 10 pts)
    dep_risk = dependency.get("risk_by_level", {})
    score += min(10.0, (
        dep_risk.get("critical", 0) * 5 +
        dep_risk.get("high", 0) * 2
    ))

    # License contribution (max 5 pts)
    if not license_result.get("compliant", True):
        score += 5.0

    return round(min(score, 100.0), 1)


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------

def scan_repo(
    name: str,
    url: str,
    sast: SASTEngine,
    secrets_manager: SecretsManager,
    iac_scanner: IaCScannerEngine,
    risk_scorer: DependencyRiskScorer,
    tmpdir: Path,
) -> Dict[str, Any]:
    """Clone one repo, run all engines, return structured result."""
    repo_dir = tmpdir / name
    print(f"\n[{name}] Cloning {url} ...", flush=True)
    clone_ok, clone_err = clone_repo(url, repo_dir)
    if not clone_ok:
        print(f"[{name}] Clone FAILED: {clone_err}", flush=True)
        return {
            "repo": name,
            "url": url,
            "clone_ok": False,
            "clone_error": clone_err,
            "scanned_at": _now_iso(),
            "scanners": {},
            "risk_score": None,
        }

    print(f"[{name}] Running SAST ...", flush=True)
    sast_result = run_sast(repo_dir, sast)
    print(f"[{name}]   SAST: {sast_result['total_findings']} findings", flush=True)

    print(f"[{name}] Running secrets scanner ...", flush=True)
    secrets_result = run_secrets(repo_dir, secrets_manager)
    print(f"[{name}]   Secrets: {secrets_result['total_findings']} findings", flush=True)

    print(f"[{name}] Running IaC scanner ...", flush=True)
    iac_result = run_iac(repo_dir, iac_scanner)
    print(f"[{name}]   IaC: {iac_result['total_findings']} findings in {iac_result['files_scanned']} files", flush=True)

    print(f"[{name}] Running dependency scanner ...", flush=True)
    dep_result = run_dependency(repo_dir, risk_scorer)
    print(f"[{name}]   Dependencies: {dep_result['dependencies_found']} found", flush=True)

    print(f"[{name}] Running license checker ...", flush=True)
    license_result = run_license(repo_dir)
    print(f"[{name}]   Licenses: {license_result['spdx_ids_detected']}", flush=True)

    risk_score = _compute_risk_score(sast_result, secrets_result, iac_result, dep_result, license_result)
    print(f"[{name}] Risk score: {risk_score}/100", flush=True)

    return {
        "repo": name,
        "url": url,
        "clone_ok": True,
        "clone_error": None,
        "scanned_at": _now_iso(),
        "scanners": {
            "sast": sast_result,
            "secrets": secrets_result,
            "iac": iac_result,
            "dependency": dep_result,
            "license": license_result,
        },
        "risk_score": risk_score,
    }


def run_scan(repo_names: List[str]) -> Dict[str, Any]:
    """Run scans for the given repo names.  Returns full report dict."""
    print("=== ALDECI Real E2E GitHub Scanner ===")
    print(f"Repos to scan: {repo_names}")
    print("Checking network connectivity ...", flush=True)

    if not _check_network():
        print("ERROR: Cannot reach github.com — aborting.", flush=True)
        sys.exit(1)

    # Initialise engines once (shared across repo scans)
    sast = get_sast_engine()
    secrets_manager = get_manager()
    iac_scanner = get_iac_scanner()
    risk_scorer = DependencyRiskScorer()

    results: List[Dict[str, Any]] = []
    tmpdir = Path(tempfile.mkdtemp(prefix="aldeci_e2e_"))
    print(f"Temp dir: {tmpdir}", flush=True)

    try:
        for name in repo_names:
            url = REPOS.get(name)
            if url is None:
                print(f"[{name}] Unknown repo — skipping.", flush=True)
                continue
            result = scan_repo(name, url, sast, secrets_manager, iac_scanner, risk_scorer, tmpdir)
            results.append(result)
    finally:
        print(f"\nCleaning up {tmpdir} ...", flush=True)
        shutil.rmtree(tmpdir, ignore_errors=True)

    report = {
        "aldeci_version": "beast-mode-v6",
        "scan_run_id": str(uuid.uuid4()),
        "generated_at": _now_iso(),
        "repos_requested": repo_names,
        "repos_scanned": len([r for r in results if r.get("clone_ok")]),
        "results": results,
    }
    return report


def save_report(report: Dict[str, Any]) -> Path:
    """Write report JSON to reports/e2e_real_scan_results.json."""
    reports_dir = _REPO_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / "e2e_real_scan_results.json"
    out_path.write_text(json.dumps(report, indent=2, default=str))
    return out_path


def print_summary(report: Dict[str, Any]) -> None:
    """Print a human-readable summary table."""
    print("\n" + "=" * 70)
    print("ALDECI E2E REAL SCAN — SUMMARY")
    print("=" * 70)
    print(f"{'Repo':<12} {'SAST':>6} {'Secrets':>8} {'IaC':>5} {'Deps':>5} {'Score':>7}")
    print("-" * 70)
    for r in report["results"]:
        if not r.get("clone_ok"):
            print(f"{r['repo']:<12}  [CLONE FAILED: {r.get('clone_error', '')[:40]}]")
            continue
        s = r["scanners"]
        sast_n = s["sast"]["total_findings"]
        sec_n = s["secrets"]["total_findings"]
        iac_n = s["iac"]["total_findings"]
        dep_n = s["dependency"]["dependencies_found"]
        score = r["risk_score"]
        print(f"{r['repo']:<12} {sast_n:>6} {sec_n:>8} {iac_n:>5} {dep_n:>5} {score:>6.1f}")
    print("=" * 70)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ALDECI Real E2E GitHub Scanner — clones real repos, runs all scanners"
    )
    parser.add_argument(
        "--repos",
        nargs="+",
        default=list(REPOS.keys()),
        choices=list(REPOS.keys()),
        metavar="REPO",
        help=f"Repos to scan (default: all). Choices: {', '.join(REPOS.keys())}",
    )
    parser.add_argument(
        "--list-repos",
        action="store_true",
        help="List available repos and exit",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save results to reports/",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.list_repos:
        print("Available repos:")
        for name, url in REPOS.items():
            print(f"  {name:<12}  {url}")
        return

    report = run_scan(args.repos)

    if not args.no_save:
        out_path = save_report(report)
        print(f"\nReport saved to: {out_path}")

    print_summary(report)


if __name__ == "__main__":
    main()
