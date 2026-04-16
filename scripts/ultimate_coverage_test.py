#!/usr/bin/env python3
"""
ALDECI ULTIMATE ENDPOINT COVERAGE TEST
Tests every API prefix with real data from live apps.

Strategy: Extract the FIRST GET sub-path from each router file (no params),
try that first, then fall back to a short list of generic probes.
Rate limit: 120 req/min burst=20 → run at 1.5 req/sec = ~6 min for 503 prefixes.
"""

import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Config ─────────────────────────────────────────────────────────────────
BASE_URL   = "http://localhost:8000"
TOKEN      = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
ORG_ID     = "coverage-test"
TIMEOUT    = 8
REQ_DELAY  = 0.52   # ~115 req/min (safely under 120 limit)

LIVE_APPS = {
    "juice_shop":  "http://localhost:3001",
    "django":      "http://localhost:3002",
    "flask":       "http://localhost:3003",
    "petclinic":   "http://localhost:3004",
    "podinfo":     "http://localhost:3005",
    "httpbin":     "http://localhost:3006",
}

HEADERS = {
    "X-API-Key": TOKEN,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

ROUTER_DIR = Path(__file__).parent.parent / "suite-api" / "apps" / "api"

# ── Router analysis ─────────────────────────────────────────────────────────
def extract_prefix_best_paths() -> dict:
    """
    Parse all *_router.py files.
    Returns {prefix: best_probe_url} where best_probe_url is the first
    static (no path params) GET endpoint found, or a generic fallback.
    """
    result = {}
    route_re  = re.compile(r'@router\.(get)\s*\(\s*["\']([^"\']+)["\']')
    prefix_re = re.compile(r'prefix\s*=\s*["\'](/api/v\d/[^"\']*)["\']')

    for fpath in sorted(ROUTER_DIR.glob("*_router.py")):
        try:
            content = fpath.read_text(errors="ignore")
        except Exception:
            continue
        pm = prefix_re.search(content)
        if not pm:
            continue
        prefix = pm.group(1)

        # Find all GET routes; prefer static ones (no path params)
        get_routes = [m.group(2) for m in route_re.finditer(content)]
        static = [r for r in get_routes if "{" not in r and r not in ("", "/")]
        parameterised = [r for r in get_routes if "{" in r]

        if static:
            best_sub = static[0]
        elif parameterised:
            best_sub = ""   # no static GET, use prefix bare
        else:
            best_sub = ""

        result[prefix] = best_sub
    return result


# ── Category detection ──────────────────────────────────────────────────────
def categorize(prefix: str) -> str:
    p = prefix.lower()
    if any(k in p for k in ["vuln", "finding", "cve", "scan", "patch", "sbom", "sca"]):
        return "vuln"
    if any(k in p for k in ["asset", "cmdb", "inventory", "device", "endpoint"]):
        return "asset"
    if any(k in p for k in ["risk", "posture", "score", "benchmark", "maturity",
                              "resilience", "investment"]):
        return "risk"
    if any(k in p for k in ["compliance", "audit", "evidence", "gdpr", "regulatory",
                              "control", "framework", "calendar", "okr", "data-retention",
                              "data-privacy", "questionnaire"]):
        return "compliance"
    if any(k in p for k in ["threat", "intel", "ioc", "dark-web", "feed", "indicator",
                              "attribution", "actor", "hunting", "brief", "zero-day",
                              "ransomware", "phishing"]):
        return "threat"
    if any(k in p for k in ["soc", "incident", "alert", "triage", "playbook", "chaos",
                              "forensic", "breach", "response", "timeline", "comms", "kb",
                              "lessons", "orchestration", "tabletop", "simulation"]):
        return "soc"
    if any(k in p for k in ["network", "firewall", "dns", "ndr", "bandwidth", "segmentation",
                              "microsegmentation", "traffic", "flow", "wireless", "anomaly",
                              "passive-dns"]):
        return "network"
    if any(k in p for k in ["identity", "access", "iam", "mfa", "rbac", "user", "auth",
                              "sso", "pam", "pag", "privileged", "itdr", "lifecycle",
                              "digital-identity", "cloud-identity"]):
        return "identity"
    if any(k in p for k in ["cloud", "k8s", "kubernetes", "container", "drift", "cwp",
                              "casb", "saas", "sspm", "cloud-native", "cloud-ir"]):
        return "cloud"
    if any(k in p for k in ["training", "awareness", "gamif", "campaign", "program",
                              "scoreboard", "culture", "budget", "kpi",
                              "report", "executive", "ciso"]):
        return "training"
    if any(k in p for k in ["api", "app", "web", "devsecops", "appsec", "waf", "gateway",
                              "discovery", "abuse", "browser", "mobile"]):
        return "api_security"
    return "generic"


# ── HTTP helpers ────────────────────────────────────────────────────────────
session = requests.Session()
session.headers.update(HEADERS)

_last_req = [0.0]

def _throttle():
    now = time.time()
    elapsed = now - _last_req[0]
    if elapsed < REQ_DELAY:
        time.sleep(REQ_DELAY - elapsed)
    _last_req[0] = time.time()

def get(path: str) -> tuple[int, dict, float]:
    _throttle()
    url = f"{BASE_URL}{path}"
    t0 = time.time()
    try:
        r = session.get(url, timeout=TIMEOUT)
        elapsed = time.time() - t0
        try:
            body = r.json()
        except Exception:
            body = {}
        return r.status_code, body, elapsed
    except requests.Timeout:
        return 0, {}, TIMEOUT
    except Exception as e:
        return -1, {"_error": str(e)}, time.time() - t0

def post(path: str, payload: dict) -> tuple[int, dict]:
    _throttle()
    url = f"{BASE_URL}{path}"
    try:
        r = session.post(url, json=payload, timeout=TIMEOUT)
        try:
            body = r.json()
        except Exception:
            body = {}
        return r.status_code, body
    except Exception as e:
        return -1, {"_error": str(e)}


# ── Has-data check ──────────────────────────────────────────────────────────
def has_data(body) -> bool:
    if isinstance(body, list):
        return len(body) > 0
    if not isinstance(body, dict):
        return bool(body)
    for key in ("data", "items", "results", "records", "entries",
                 "findings", "alerts", "events", "policies", "rules",
                 "reports", "metrics", "assessments", "detections",
                 "actors", "models", "workflows", "tasks", "cases",
                 "programs", "hunts", "incidents", "vulns", "assets"):
        val = body.get(key)
        if isinstance(val, list) and val:
            return True
        if isinstance(val, dict) and val:
            return True
    for key in ("count", "total", "total_count"):
        val = body.get(key)
        if isinstance(val, (int, float)) and val > 0:
            return True
    # any non-trivial top-level scalar
    interesting = {k: v for k, v in body.items()
                   if v not in (None, 0, [], {}, "", False)
                   and not k.startswith("_")
                   and k not in ("org_id", "status", "message", "timestamp",
                                  "service", "version")}
    return len(interesting) >= 2


# ── Probe a single prefix ───────────────────────────────────────────────────
GENERIC_FALLBACKS = [
    "/stats",
    "/summary",
    "/overview",
    "/health",
    "/status",
    "",           # bare prefix
]

def probe_prefix(prefix: str, best_sub: str) -> dict:
    """
    Try best_sub first (from router analysis), then generic fallbacks.
    All paths include ?org_id={ORG_ID}.
    Return first 200, or the best non-200 seen.
    """
    probes = []
    if best_sub:
        probes.append(f"{prefix}{best_sub}?org_id={ORG_ID}")
    for fb in GENERIC_FALLBACKS:
        candidate = f"{prefix}{fb}?org_id={ORG_ID}"
        if candidate not in probes:
            probes.append(candidate)

    best_result = {
        "prefix": prefix, "status": -1, "url": prefix,
        "elapsed": 0.0, "has_data": False, "body": {},
    }

    for probe_path in probes:
        code, body, elapsed = get(probe_path)

        if code == 200:
            return {
                "prefix": prefix, "status": 200, "url": probe_path,
                "elapsed": elapsed, "has_data": has_data(body), "body": body,
            }
        if code == 429:
            # Rate limited — back off and retry once
            time.sleep(2.0)
            code, body, elapsed = get(probe_path)
            if code == 200:
                return {
                    "prefix": prefix, "status": 200, "url": probe_path,
                    "elapsed": elapsed, "has_data": has_data(body), "body": body,
                }

        # Keep the best non-200 (405/422 = route exists)
        if code in (405, 422) or (code > 0 and best_result["status"] in (-1, 404)):
            best_result = {
                "prefix": prefix, "status": code, "url": probe_path,
                "elapsed": elapsed, "has_data": False, "body": body,
            }
        elif best_result["status"] == -1 and code > 0:
            best_result = {
                "prefix": prefix, "status": code, "url": probe_path,
                "elapsed": elapsed, "has_data": False, "body": body,
            }

        # Don't keep probing after we got a 404 on the specific sub-path
        # (the bare prefix will 404 too most likely)
        if code in (405, 422):
            break   # route exists, just wrong method or missing body

    return best_result


# ── Seed payloads ───────────────────────────────────────────────────────────
def make_seed_payloads() -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    return {
        "vuln": {
            "org_id": ORG_ID, "title": "XSS in Juice Shop /login",
            "severity": "high", "cvss_score": 7.5, "cve_id": "CVE-2023-9999",
            "asset_id": "juice-shop-3001", "source": "dast-scan",
            "description": "Reflected XSS via login form", "status": "open",
            "epss_score": 0.12, "in_kev": False, "discovered_at": ts,
        },
        "asset": {
            "org_id": ORG_ID, "name": "juice-shop", "type": "web_application",
            "hostname": "localhost", "port": 3001, "criticality": "high",
            "environment": "production", "tags": ["live-app", "coverage-test"],
        },
        "risk": {
            "org_id": ORG_ID, "entity_id": "juice-shop-3001",
            "entity_type": "application", "risk_score": 72.5,
            "risk_level": "high", "factors": ["xss", "sqli"],
        },
        "compliance": {
            "org_id": ORG_ID, "framework": "SOC2", "control_id": "CC6.1",
            "status": "partial", "evidence": "DAST scan completed", "assessed_at": ts,
        },
        "threat": {
            "org_id": ORG_ID, "indicator": "malicious-domain.example.com",
            "type": "domain", "confidence": 0.85, "severity": "high",
            "source": "coverage-test", "tlp": "WHITE",
        },
        "soc": {
            "org_id": ORG_ID, "title": "SQLi attempt on Juice Shop",
            "severity": "critical", "source": "waf",
            "description": "SQL injection in search endpoint",
            "asset_id": "juice-shop-3001", "status": "open", "detected_at": ts,
        },
        "network": {
            "org_id": ORG_ID, "source_ip": "192.168.1.100", "dest_ip": "10.0.0.1",
            "source_port": 54321, "dest_port": 443, "protocol": "TCP",
            "bytes_sent": 1024, "bytes_recv": 2048,
            "event_type": "connection", "timestamp": ts,
        },
        "identity": {
            "org_id": ORG_ID, "user_id": "user-coverage-001",
            "username": "coverage_tester", "email": "test@coverage-test.internal",
            "role": "analyst", "department": "security",
            "mfa_enabled": True, "last_login": ts,
        },
        "cloud": {
            "org_id": ORG_ID, "resource_id": "k8s-kind-cluster-001",
            "resource_type": "kubernetes_cluster", "provider": "on-prem",
            "region": "local", "name": "kind-cluster",
            "security_score": 65, "tags": {"env": "test"},
        },
        "training": {
            "org_id": ORG_ID, "name": "Security Awareness Q2",
            "type": "phishing_simulation", "status": "active",
            "completion_rate": 0.0, "target_completion_rate": 0.9,
        },
        "api_security": {
            "org_id": ORG_ID, "endpoint": "/api/v1/health", "method": "GET",
            "risk_score": 10.0, "status": "active", "discovered_at": ts,
        },
        "generic": {
            "org_id": ORG_ID, "name": "coverage-test-entry",
            "description": "Seeded by ultimate coverage test",
            "status": "active", "created_at": ts,
        },
    }


# ── Seed endpoints per category ─────────────────────────────────────────────
SEED_ENDPOINT_MAP = {
    "vuln":        ["/api/v1/vuln-scans/scans", "/api/v1/security-findings/findings",
                    "/api/v1/vuln-lifecycle/findings", "/api/v1/vuln-exceptions/exceptions"],
    "asset":       ["/api/v1/asset-lifecycle/assets", "/api/v1/cmdb/assets",
                    "/api/v1/asset-groups/groups", "/api/v1/asset-tags/assets"],
    "risk":        ["/api/v1/risk-register-engine/risks", "/api/v1/risk-aggregator/entities",
                    "/api/v1/risk-scenarios/scenarios", "/api/v1/risk-treatment/treatments"],
    "compliance":  ["/api/v1/compliance-mapping/mappings", "/api/v1/compliance-automation/jobs",
                    "/api/v1/compliance-workflows/workflows", "/api/v1/gdpr/records"],
    "threat":      ["/api/v1/threat-indicators/indicators", "/api/v1/threat-attribution/actors",
                    "/api/v1/cyber-threat-intel/reports", "/api/v1/feed-subscriptions/subscriptions"],
    "soc":         ["/api/v1/alerting/policies", "/api/v1/alert-triage/alerts",
                    "/api/v1/incident-orchestration/incidents", "/api/v1/soc-workflow/cases"],
    "network":     ["/api/v1/network-monitoring/interfaces", "/api/v1/firewall-policy/rules",
                    "/api/v1/network-threats/threats", "/api/v1/bandwidth-analysis/links"],
    "identity":    ["/api/v1/access-requests/requests", "/api/v1/mfa/enrollments",
                    "/api/v1/identity-lifecycle/identities", "/api/v1/access-reviews/reviews"],
    "cloud":       ["/api/v1/cloud-inventory/resources", "/api/v1/cloud-posture/accounts",
                    "/api/v1/kubernetes-security/findings", "/api/v1/cloud-findings/findings"],
    "training":    ["/api/v1/awareness-program/programs", "/api/v1/security-budget/allocations",
                    "/api/v1/kpi-tracking/kpis", "/api/v1/metrics-dashboard/dashboards"],
    "api_security":["/api/v1/api-inventory/apis", "/api/v1/api-threat-protection/threats",
                    "/api/v1/api-discovery/endpoints", "/api/v1/api-abuse/incidents"],
    "generic":     ["/api/v1/security-registry/artifacts", "/api/v1/security-findings/findings"],
}

def seed_category(cat: str, payloads: dict) -> list:
    payload = payloads.get(cat, payloads["generic"])
    results = []
    for endpoint in SEED_ENDPOINT_MAP.get(cat, SEED_ENDPOINT_MAP["generic"]):
        code, body = post(endpoint, payload)
        results.append((endpoint, code))
        if code in (200, 201):
            break  # one successful seed per category
    return results


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    t_start = time.time()

    print("=" * 72)
    print("ALDECI ULTIMATE ENDPOINT COVERAGE TEST")
    print("=" * 72)
    print(f"Server:  {BASE_URL}")
    print(f"Org:     {ORG_ID}")
    print(f"Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Rate:    {int(60/REQ_DELAY)} req/min (server limit: 120/min)")
    print()

    # ── Step 0: Health check ───────────────────────────────────────────────
    print("[ STEP 0 ] Verifying server health...")
    code, body, _ = get("/api/v1/health")
    if code != 200:
        print(f"  ERROR: Server returned HTTP {code}. Aborting.")
        sys.exit(1)
    print(f"  Server: {body.get('status','ok')} | {body.get('service','')} v{body.get('version','?')}")

    print("\n  Live app status:")
    for name, url in LIVE_APPS.items():
        try:
            r = requests.get(url, timeout=3)
            print(f"    {name:12s}  {url}  -> HTTP {r.status_code}")
        except Exception as e:
            print(f"    {name:12s}  {url}  -> OFFLINE")
    print()

    # ── Step 1: Discover prefixes ──────────────────────────────────────────
    print("[ STEP 1 ] Extracting prefixes from router files...")
    prefix_best = extract_prefix_best_paths()
    all_prefixes = sorted(prefix_best.keys())
    print(f"  Found {len(all_prefixes)} unique prefixes in {ROUTER_DIR.name}/")
    est_secs = len(all_prefixes) * REQ_DELAY
    print(f"  Estimated probe time: ~{est_secs/60:.1f} min at {REQ_DELAY}s/req")
    print()

    # ── Step 2: Phase 1 sequential probe ───────────────────────────────────
    print(f"[ STEP 2 ] Probing all {len(all_prefixes)} prefixes (sequential, rate-safe)...")
    phase1 = {}
    t_batch = time.time()

    for i, prefix in enumerate(all_prefixes, 1):
        result = probe_prefix(prefix, prefix_best[prefix])
        phase1[prefix] = result

        if i % 50 == 0 or i == len(all_prefixes):
            ok = sum(1 for r in phase1.values() if r["status"] == 200)
            elapsed = time.time() - t_batch
            remaining = (len(all_prefixes) - i) * REQ_DELAY
            print(f"  [{i:>3}/{len(all_prefixes)}] {ok} responding | "
                  f"{elapsed:.0f}s elapsed | ~{remaining:.0f}s remaining")

    p1_200      = {p: r for p, r in phase1.items() if r["status"] == 200}
    p1_with_data= {p: r for p, r in p1_200.items() if r["has_data"]}
    p1_empty    = {p: r for p, r in p1_200.items() if not r["has_data"]}
    p1_fail     = {p: r for p, r in phase1.items() if r["status"] != 200}

    print(f"\n  Phase 1: {len(p1_200)} responding | {len(p1_with_data)} with data | "
          f"{len(p1_empty)} empty | {len(p1_fail)} failed")
    print()

    # ── Step 3: Seed data ──────────────────────────────────────────────────
    print("[ STEP 3 ] Seeding data for empty/failed prefixes...")
    payloads = make_seed_payloads()

    categories_to_seed = set(categorize(p) for p in list(p1_empty) + list(p1_fail))
    seed_summary = {}
    for cat in sorted(categories_to_seed):
        results = seed_category(cat, payloads)
        seed_summary[cat] = results
        ok = [(ep, c) for ep, c in results if c in (200, 201)]
        print(f"  [{cat:<15s}]  {len(ok)}/{len(results)} seeded"
              + (f"  -> {ok[0][0]}" if ok else "  (no writable endpoint found)"))

    print()

    # ── Step 4: Re-probe empty + failed prefixes ───────────────────────────
    retry_list = sorted(set(list(p1_empty) + list(p1_fail)))
    print(f"[ STEP 4 ] Re-probing {len(retry_list)} prefixes after seeding...")

    phase2 = {}
    for i, prefix in enumerate(retry_list, 1):
        result = probe_prefix(prefix, prefix_best[prefix])
        phase2[prefix] = result
        if i % 100 == 0:
            ok = sum(1 for r in phase2.values() if r["status"] == 200)
            print(f"  [{i:>3}/{len(retry_list)}] {ok} upgraded to 200...")

    # Merge: phase2 supersedes phase1 for retried prefixes
    final = dict(phase1)
    for prefix, result in phase2.items():
        if result["status"] == 200 and phase1[prefix]["status"] != 200:
            final[prefix] = result   # upgraded!
        elif result["has_data"] and not phase1[prefix].get("has_data"):
            final[prefix] = result   # now has data

    print()

    # ── Tally ──────────────────────────────────────────────────────────────
    total        = len(all_prefixes)
    responding   = [p for p, r in final.items() if r["status"] == 200]
    with_data    = [p for p in responding if final[p]["has_data"]]
    empty_200    = [p for p in responding if not final[p]["has_data"]]
    method_issue = [p for p, r in final.items() if r["status"] in (405, 422)]
    auth_fail    = [p for p, r in final.items() if r["status"] in (401, 403)]
    server_err   = [p for p, r in final.items() if 500 <= r["status"] < 600]
    not_found    = [p for p, r in final.items() if r["status"] == 404]
    rate_limited = [p for p, r in final.items() if r["status"] == 429]
    timed_out    = [p for p, r in final.items() if r["status"] == 0]
    other        = [p for p, r in final.items()
                    if r["status"] not in (200, 404, 401, 403, 405, 422, 429, 0)
                    and not (500 <= r["status"] < 600)]

    cat_totals = defaultdict(int)
    cat_ok     = defaultdict(int)
    for prefix in all_prefixes:
        cat = categorize(prefix)
        cat_totals[cat] += 1
        if prefix in responding:
            cat_ok[cat] += 1

    coverage_pct = len(responding) / total * 100 if total else 0
    t_total = time.time() - t_start

    # ── Print report ────────────────────────────────────────────────────────
    print("=" * 72)
    print("ALDECI ENDPOINT COVERAGE REPORT")
    print("=" * 72)
    print(f"Generated:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Runtime:     {t_total/60:.1f} minutes")
    print()
    print(f"Total prefixes tested:       {total}")
    print(f"Responding (HTTP 200):       {len(responding)}")
    print(f"  With real data:            {len(with_data)}")
    print(f"  Empty (200, no data yet):  {len(empty_200)}")
    print(f"Route exists (405/422):      {len(method_issue)}")
    print(f"Auth failures (401/403):     {len(auth_fail)}")
    print(f"Server errors (5xx):         {len(server_err)}")
    print(f"Not found (404):             {len(not_found)}")
    print(f"Rate limited (429):          {len(rate_limited)}")
    print(f"Timed out:                   {len(timed_out)}")
    print()
    print(f"COVERAGE: {len(responding)}/{total} ({coverage_pct:.1f}%)")
    print(f"  Healthy (data):  {len(with_data)}/{total} ({len(with_data)/total*100:.1f}%)")
    print()

    print("BY CATEGORY:")
    print(f"  {'Category':<22}  {'OK':>4} / {'Total':<6}  {'Pct':>6}  Bar")
    print(f"  {'-'*55}")
    for cat in sorted(cat_totals.keys()):
        tot = cat_totals[cat]
        ok  = cat_ok[cat]
        pct = ok / tot * 100 if tot else 0
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"  {cat:<22}  {ok:>4} / {tot:<6}  {pct:>5.1f}%  {bar}")
    print()

    # Responding with data
    if with_data:
        print(f"RESPONDING WITH DATA ({len(with_data)}):")
        for prefix in sorted(with_data):
            r = final[prefix]
            print(f"  200 [{r['elapsed']*1000:5.0f}ms]  {r['url']}")
        print()

    # Responding but empty
    if empty_200:
        print(f"RESPONDING BUT EMPTY ({len(empty_200)}) — needs seeding:")
        for prefix in sorted(empty_200)[:30]:
            r = final[prefix]
            print(f"  200 (empty)  {r['url']}")
        if len(empty_200) > 30:
            print(f"  ... and {len(empty_200)-30} more")
        print()

    # Method issues
    if method_issue:
        print(f"ROUTE EXISTS — WRONG METHOD ({len(method_issue)}):")
        for prefix in sorted(method_issue):
            r = final[prefix]
            print(f"  {r['status']}  {r['url']}")
        print()

    # Server errors
    if server_err:
        print(f"SERVER ERRORS ({len(server_err)}) — need fixing:")
        for prefix in sorted(server_err):
            r = final[prefix]
            print(f"  {r['status']}  {r['url']}  {str(r.get('body',''))[:80]}")
        print()

    # Rate limited (still)
    if rate_limited:
        print(f"STILL RATE LIMITED ({len(rate_limited)}) — re-run with longer delay:")
        for prefix in sorted(rate_limited)[:20]:
            print(f"  429  {prefix}")
        if len(rate_limited) > 20:
            print(f"  ... and {len(rate_limited)-20} more")
        print()

    # Not found
    combined_fail = sorted(not_found + other)
    if combined_fail:
        print(f"NOT FOUND / OTHER FAILURES ({len(combined_fail)}):")
        for prefix in combined_fail[:40]:
            r = final[prefix]
            print(f"  {r['status']}  {prefix}")
        if len(combined_fail) > 40:
            print(f"  ... and {len(combined_fail)-40} more")
        print()

    # ── Save JSON report ────────────────────────────────────────────────────
    report_path = Path(__file__).parent / "coverage_report.json"
    report = {
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "runtime_secs":  round(t_total, 1),
        "summary": {
            "total":         total,
            "responding":    len(responding),
            "with_data":     len(with_data),
            "empty_200":     len(empty_200),
            "method_issue":  len(method_issue),
            "auth_fail":     len(auth_fail),
            "server_errors": len(server_err),
            "not_found":     len(not_found),
            "rate_limited":  len(rate_limited),
            "timed_out":     len(timed_out),
            "coverage_pct":  round(coverage_pct, 2),
        },
        "by_category": {
            cat: {"ok": cat_ok[cat], "total": cat_totals[cat],
                  "pct": round(cat_ok[cat]/cat_totals[cat]*100, 1) if cat_totals[cat] else 0}
            for cat in sorted(cat_totals)
        },
        "results": {
            p: {
                "status":     r["status"],
                "url":        r["url"],
                "has_data":   r["has_data"],
                "elapsed_ms": round(r["elapsed"] * 1000, 1),
                "category":   categorize(p),
            }
            for p, r in sorted(final.items())
        },
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(f"Full JSON report: {report_path}")
    print()
    print("=" * 72)
    print(f"FINAL COVERAGE: {len(responding)}/{total} ({coverage_pct:.1f}%)")
    print(f"  Data populated: {len(with_data)}/{total} ({len(with_data)/total*100:.1f}%)")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    sys.exit(main())
