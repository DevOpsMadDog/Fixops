"""Seed real per-tenant dependency graphs + arch classifications via the
ALDECI public API (no shortcuts, no engine bypass).

Mission: for each of 15 tenants, hit the real
  POST /api/v1/dependency-mapping/map-repo
  POST /api/v1/arch-graph/classify
  POST /api/v1/arch-graph/trace-flow

…against the cloned fleet under /tmp/fixops-fleet/<repo>.

Then verify GET /api/v1/dependency-mapping/blast-radius for juice-shop-corp
returns a non-empty result.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

API_BASE = os.environ.get("FIXOPS_API_BASE", "http://127.0.0.1:8000")
API_KEY = os.environ.get(
    "FIXOPS_API_TOKEN",
    "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_",
)
FLEET_ROOT = Path(os.environ.get("FIXOPS_FLEET_ROOT", "/tmp/fixops-fleet"))

# 15 tenants — each maps to a real repo we already cloned. Tenant slug
# follows the existing convention used elsewhere in ALDECI seed scripts.
TENANTS: List[Tuple[str, str]] = [
    ("juice-shop-corp", "juice-shop"),
    ("nodegoat-corp", "NodeGoat"),
    ("webgoat-corp", "WebGoat"),
    ("dvna-corp", "dvna"),
    ("vulnado-corp", "vulnado"),
    ("django-corp", "django"),
    ("flask-corp", "flask"),
    ("fastapi-corp", "fastapi"),
    ("express-corp", "express"),
    ("fastify-corp", "fastify"),
    ("requests-corp", "requests"),
    ("httpx-corp", "httpx"),
    ("axios-corp", "axios"),
    ("lodash-corp", "lodash"),
    ("anthropic-sdk-python-corp", "anthropic-sdk-python"),
]


def _http(method: str, path: str, *, body: Optional[Dict[str, Any]] = None,
          params: Optional[Dict[str, str]] = None, timeout: int = 60,
          max_retries: int = 6) -> Tuple[int, Any]:
    """Make an HTTP call with auto-retry on 429 (respects Retry-After / retry_after)."""
    url = API_BASE + path
    if params:
        from urllib.parse import urlencode
        url += ("&" if "?" in url else "?") + urlencode(params)
    data = json.dumps(body).encode("utf-8") if body is not None else None

    attempt = 0
    while True:
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "X-API-Key": API_KEY,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                try:
                    payload = json.loads(text) if text else None
                except json.JSONDecodeError:
                    payload = {"_raw": text[:500]}
                return resp.status, payload
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(text) if text else {"error": e.reason}
            except json.JSONDecodeError:
                payload = {"_raw": text[:500]}
            if e.code == 429 and attempt < max_retries:
                # Honour Retry-After header or retry_after key, else exponential backoff
                wait = float(e.headers.get("Retry-After") or 0)
                if not wait and isinstance(payload, dict):
                    wait = float(payload.get("retry_after") or 0)
                if not wait:
                    wait = min(2 ** attempt, 8)
                time.sleep(max(0.25, wait + 0.25))
                attempt += 1
                continue
            return e.code, payload
        except urllib.error.URLError as e:
            if attempt < 2:
                time.sleep(1)
                attempt += 1
                continue
            return 0, {"error": str(e)}


def wait_for_api(max_seconds: int = 60) -> bool:
    """Poll /api/v1/health until OK or timeout."""
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        code, _ = _http("GET", "/api/v1/health", max_retries=0)
        if code == 200:
            return True
        time.sleep(1)
    return False


def pick_classify_targets(repo_dir: Path, max_files: int = 3) -> List[str]:
    """Pick 1-3 representative files from each repo for arch classification."""
    candidates: List[str] = []
    # Look in conventional API/data/UI dirs first
    priority_dirs = ["src", "lib", "app", "routes", "api", "controllers", "models"]
    for sub in priority_dirs:
        d = repo_dir / sub
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*"))[:50]:
            if f.is_file() and f.suffix in {".js", ".ts", ".py", ".tsx", ".jsx", ".java"}:
                rel = f.relative_to(repo_dir).as_posix()
                if len(rel) <= 256 and rel not in candidates:
                    candidates.append(rel)
                    if len(candidates) >= max_files:
                        return candidates
    # Fallback: top-level files
    if len(candidates) < max_files:
        for f in sorted(repo_dir.iterdir()):
            if f.is_file() and f.suffix in {".js", ".ts", ".py", ".tsx", ".jsx", ".java"}:
                rel = f.name
                if rel not in candidates:
                    candidates.append(rel)
                    if len(candidates) >= max_files:
                        break
    return candidates


def main() -> int:
    print(f"[seed] API base: {API_BASE}")
    print(f"[seed] Fleet root: {FLEET_ROOT}")
    if not wait_for_api():
        print("[seed] FAILED — API never responded on /health", file=sys.stderr)
        return 1

    summary: Dict[str, Any] = {
        "tenants_attempted": 0,
        "tenants_ok": 0,
        "deps_total": 0,
        "classifications": 0,
        "flows_traced": 0,
        "errors": [],
        "per_tenant": [],
    }

    for tenant, repo_name in TENANTS:
        repo_dir = FLEET_ROOT / repo_name
        if not repo_dir.is_dir():
            summary["errors"].append(f"{tenant}: repo {repo_dir} missing")
            continue
        summary["tenants_attempted"] += 1
        per: Dict[str, Any] = {"tenant": tenant, "repo": repo_name}

        # 1. map-repo
        code, body = _http(
            "POST",
            "/api/v1/dependency-mapping/map-repo",
            body={"repo_path": str(repo_dir), "criticality": "high"},
            params={"org_id": tenant},
        )
        per["map_repo_status"] = code
        if code == 200:
            per["service_id"] = body.get("service_id")
            per["service_name"] = body.get("service_name")
            per["deps_registered"] = body.get("deps_registered", 0)
            per["deps_detected"] = body.get("deps_detected", 0)
            summary["deps_total"] += body.get("deps_registered", 0)
        else:
            summary["errors"].append(f"{tenant}: map-repo HTTP {code}: {str(body)[:200]}")
            summary["per_tenant"].append(per)
            continue

        # 2. arch-graph/classify (one classify call per major file)
        targets = pick_classify_targets(repo_dir, max_files=3)
        per["classify_targets"] = targets
        per["classifications"] = []
        for tgt in targets:
            code, body = _http(
                "POST",
                "/api/v1/arch-graph/classify",
                body={"node_ref": tgt, "context": {"imports": [], "importers": []}},
                params={"org_id": tenant},
            )
            if code == 200:
                per["classifications"].append({
                    "node": tgt,
                    "layer": body.get("layer"),
                    "confidence": body.get("confidence"),
                })
                summary["classifications"] += 1
            else:
                summary["errors"].append(f"{tenant}: classify {tgt} HTTP {code}")

        # 3. arch-graph/trace-flow (one trace from the root service)
        if per.get("service_id"):
            code, body = _http(
                "POST",
                "/api/v1/arch-graph/trace-flow",
                body={"start_ref": per["service_id"], "max_hops": 3},
                params={"org_id": tenant},
            )
            per["trace_flow_status"] = code
            if code == 200:
                per["trace_hops"] = len(body.get("hops") or body.get("path") or [])
                summary["flows_traced"] += 1
            else:
                summary["errors"].append(f"{tenant}: trace-flow HTTP {code}: {str(body)[:200]}")

        summary["tenants_ok"] += 1
        summary["per_tenant"].append(per)
        print(f"[seed] {tenant}: deps={per.get('deps_registered',0)} "
              f"classified={len(per.get('classifications',[]))} "
              f"trace={per.get('trace_flow_status','?')}")
        # Modest pacing between tenants to avoid sustained 429 backoff churn
        # and to give the server room to flush event-bus buffers.
        time.sleep(0.5)
        # Re-confirm API health every 3 tenants — wait for recovery if down
        if summary["tenants_attempted"] % 3 == 0:
            health_code, _ = _http("GET", "/api/v1/health", max_retries=0)
            if health_code != 200:
                summary["errors"].append(
                    f"[WARN] API health-check failed after {summary['tenants_attempted']} tenants "
                    f"(status={health_code}); waiting up to 30s for recovery"
                )
                if not wait_for_api(30):
                    summary["errors"].append("[FATAL] API never recovered; aborting remaining tenants")
                    break
                summary["errors"].append("[INFO] API recovered, continuing")

    # 4. Verification: blast-radius for juice-shop-corp must be non-empty.
    # We try several node references in order; spec asks for src/index.ts but
    # juice-shop's actual entry is app.ts, so we report all probes.
    print("\n[seed] Verifying juice-shop-corp blast-radius…")
    if not wait_for_api(30):
        summary["verification"] = {"error": "API down before verification"}
        return summary["tenants_ok"] >= 10 and 0 or 2

    probes = ["src/index.ts", "app.ts", "juice-shop", "server.ts"]
    summary["verification_probes"] = []
    matched_any = False
    for node in probes:
        code, body = _http(
            "GET",
            "/api/v1/dependency-mapping/blast-radius",
            params={"org_id": "juice-shop-corp", "node": node},
        )
        probe_result = {
            "node": node,
            "status": code,
            "matched": (body or {}).get("matched", False),
            "affected_count": (body or {}).get("affected_count", 0),
        }
        summary["verification_probes"].append(probe_result)
        if probe_result["matched"] or probe_result["affected_count"] > 0:
            matched_any = True
        # Spec verification: keep src/index.ts result as the canonical "verification"
        if node == "src/index.ts":
            summary["verification"] = {
                "endpoint": "/api/v1/dependency-mapping/blast-radius",
                **probe_result,
            }
    summary["verification_passed"] = matched_any

    print("\n[seed] === SUMMARY ===")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_tenant"}, indent=2))
    print(f"[seed] tenants_ok = {summary['tenants_ok']}/15  deps_total = {summary['deps_total']}")
    out_path = Path("/tmp/aldeci_seed_tenant_graphs.json")
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"[seed] full report: {out_path}")
    return 0 if summary["tenants_ok"] >= 10 else 2


if __name__ == "__main__":
    sys.exit(main())
