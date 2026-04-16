#!/usr/bin/env python3
"""
Frontend Page Test — ALDECI
Checks 30 representative pages for:
  1. HTTP 200 from Vite dev server (localhost:5173)
  2. React root div present in HTML
  3. API endpoints the component calls (extracted from source TSX)
"""

import os
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

FRONTEND_BASE = "http://localhost:5173"
PAGES_DIR = Path("/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages")
DELAY = 0.3  # seconds between requests

# Map: route path -> component filename (resolved from App.tsx)
PAGES = [
    ("/privacy-impact",          "PrivacyImpactDashboard.tsx"),
    ("/threat-indicators",       "ThreatIndicatorDashboard.tsx"),
    ("/ransomware-protection",   "RansomwareProtectionDashboard.tsx"),
    ("/access-anomaly",          "AccessAnomalyDashboard.tsx"),
    ("/dark-web",                "DarkWebMonitoringDashboard.tsx"),
    ("/quantum-crypto",          "QuantumCryptoDashboard.tsx"),
    ("/ai-soc",                  "AIPoweredSOCDashboard.tsx"),
    ("/cloud-drift",             "CloudDriftDashboard.tsx"),
    ("/deception-analytics",     "DeceptionAnalyticsDashboard.tsx"),
    ("/zero-day",                "ZeroDayIntelligenceDashboard.tsx"),
    ("/firmware-security",       "FirmwareSecurityDashboard.tsx"),
    ("/iot-security",            "IoTSecurityDashboard.tsx"),
    ("/mobile-app-security",     "MobileAppSecurityDashboard.tsx"),
    ("/api-abuse",               "APIAbuseDashboard.tsx"),
    ("/supply-chain-attacks",    "SupplyChainAttackDashboard.tsx"),
    ("/cwp",                     "CloudWorkloadProtectionDashboard.tsx"),
    ("/autonomous-remediation",  "AutonomousRemediationDashboard.tsx"),
    ("/vuln-correlation",        "VulnerabilityCorrelationDashboard.tsx"),
    ("/posture-benchmarking",    "PostureBenchmarkingDashboard.tsx"),
    ("/alert-triage",            "AlertTriageDashboard.tsx"),
    ("/patch-management",        "PatchManagementDashboard.tsx"),
    ("/container-posture",       "ContainerPostureDashboard.tsx"),
    ("/cyber-threat-intel",      "CyberThreatIntelDashboard.tsx"),
    ("/digital-twin",            "DigitalTwinDashboard.tsx"),
    ("/access-requests",         "AccessRequestManagementDashboard.tsx"),
    ("/session-recording",       "PrivilegedSessionRecordingDashboard.tsx"),
    ("/cloud-inventory",         "CloudResourceInventoryDashboard.tsx"),
    ("/security-telemetry",      "SecurityTelemetryDashboard.tsx"),
    ("/microsegmentation",       "MicrosegmentationPolicyDashboard.tsx"),
    ("/third-party-vendor",      "ThirdPartyVendorDashboard.tsx"),
]


def fetch_url(url: str) -> tuple[int, str]:
    """Return (status_code, body). On error return (0, error_msg)."""
    try:
        req = urllib.request.Request(url, headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, str(e)
    except Exception as e:
        return 0, str(e)


def has_react_root(html: str) -> bool:
    """Check HTML contains a React mount point div."""
    return bool(re.search(r'<div\s+id=["\']root["\']', html, re.IGNORECASE))


def extract_api_endpoints(tsx_path: Path) -> list[str]:
    """Extract /api/v1/... patterns from the TSX source file."""
    if not tsx_path.exists():
        return []
    source = tsx_path.read_text(errors="replace")
    # Match /api/v1/... strings (stop at quote, backtick, ?, $, space)
    raw = re.findall(r"/api/v1/[a-zA-Z0-9/_\-]+", source)
    # Deduplicate preserving order, strip trailing slash
    seen = {}
    for ep in raw:
        ep = ep.rstrip("/")
        if ep not in seen:
            seen[ep] = True
    return list(seen.keys())


# Pages whose component files are declared in App.tsx via lazy() but the TSX
# file has not been created yet — route returns 200 (SPA catch-all) but the
# component will fail to load in the browser.
MISSING_PAGES = {
    "/privacy-impact",
    "/threat-indicators",
    "/ransomware-protection",
    "/access-anomaly",
}

# Pages that have no Route entry in App.tsx at all — SPA still returns 200
# (catch-all), but they render the 404/fallback component.
NO_ROUTE_PAGES = {
    "/cloud-drift",
}


def find_component_file(filename: str) -> Path:
    """Locate a TSX file by name under PAGES_DIR (handles missing files)."""
    candidate = PAGES_DIR / filename
    if candidate.exists():
        return candidate
    # Fallback: search recursively
    matches = list(PAGES_DIR.rglob(filename))
    return matches[0] if matches else candidate  # return non-existent path if not found


def run_tests():
    print("=" * 80)
    print("ALDECI Frontend Page Test")
    print(f"Frontend: {FRONTEND_BASE}")
    print(f"Pages dir: {PAGES_DIR}")
    print("=" * 80)
    print()

    results = []

    for route, component_file in PAGES:
        url = f"{FRONTEND_BASE}{route}"
        tsx_path = find_component_file(component_file)

        # 1. HTTP check
        status, body = fetch_url(url)
        ok_http = status == 200

        # 2. React root check (only meaningful if we got HTML)
        has_root = has_react_root(body) if ok_http else False

        # 3. API endpoints from source
        endpoints = extract_api_endpoints(tsx_path)
        file_exists = tsx_path.exists()

        results.append({
            "route": route,
            "component": component_file,
            "file_exists": file_exists,
            "status": status,
            "ok_http": ok_http,
            "has_root": has_root,
            "endpoints": endpoints,
        })

        # Annotation flags
        no_route = route in NO_ROUTE_PAGES
        missing_tsx = route in MISSING_PAGES

        # Per-page output
        http_icon = "OK " if ok_http else "ERR"
        root_icon = "OK " if has_root else "NO "
        if no_route:
            file_icon = "NO ROUTE"
        elif missing_tsx:
            file_icon = "TSX MISSING"
        elif file_exists:
            file_icon = "OK"
        else:
            file_icon = "MISSING"
        ep_str = ", ".join(endpoints) if endpoints else "(none found)"
        print(f"[{http_icon}] {route}")
        print(f"       HTTP {status} | React root: {root_icon} | Source: {file_icon} ({component_file})")
        if no_route:
            print(f"       NOTE: No <Route> entry in App.tsx — SPA serves 404/fallback component")
        elif missing_tsx:
            print(f"       NOTE: lazy() import declared in App.tsx but TSX file not yet created")
        print(f"       API endpoints: {ep_str}")
        print()

        time.sleep(DELAY)

    # Summary table
    print("=" * 80)
    print("SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Route':<30} {'HTTP':>6} {'Root':>6} {'Source':>8}  API Endpoints")
    print("-" * 80)

    pass_count = 0
    fail_count = 0
    no_endpoints = []

    for r in results:
        http_str = str(r["status"]) if r["status"] != 0 else "ERR"
        root_str = "YES" if r["has_root"] else "NO"
        route = r["route"]
        if route in NO_ROUTE_PAGES:
            file_str = "NO-ROUTE"
        elif route in MISSING_PAGES:
            file_str = "TSX-MISS"
        elif r["file_exists"]:
            file_str = "YES"
        else:
            file_str = "MISSING"
        ep_str = ", ".join(r["endpoints"][:3])
        if len(r["endpoints"]) > 3:
            ep_str += f" (+{len(r['endpoints'])-3} more)"
        if not ep_str:
            ep_str = "(none found)"
            no_endpoints.append(route)

        # PASS = HTTP 200 + React root. Missing TSX/route is flagged separately.
        all_ok = r["ok_http"] and r["has_root"]
        marker = "PASS" if all_ok else "FAIL"
        if all_ok:
            pass_count += 1
        else:
            fail_count += 1

        print(f"[{marker}] {route:<27} {http_str:>6} {root_str:>6} {file_str:>8}  {ep_str}")

    print("-" * 80)
    print(f"\nResults: {pass_count} PASS / {fail_count} FAIL / {len(results)} total")

    # Gap analysis
    missing_tsx_routes = [r["route"] for r in results if r["route"] in MISSING_PAGES]
    no_route_pages = [r["route"] for r in results if r["route"] in NO_ROUTE_PAGES]

    if missing_tsx_routes:
        print(f"\nGAP — TSX file declared in App.tsx but not yet created ({len(missing_tsx_routes)}):")
        for p in missing_tsx_routes:
            comp = next(c for (rt, c) in PAGES if rt == p)
            print(f"  {p}  ->  suite-ui/aldeci-ui-new/src/pages/{comp}  (needs to be created)")

    if no_route_pages:
        print(f"\nGAP — No <Route> in App.tsx ({len(no_route_pages)}):")
        for p in no_route_pages:
            print(f"  {p}  (route + component file both missing)")

    if no_endpoints:
        print(f"\nPages with no /api/v1/ calls in source ({len(no_endpoints)}):")
        for p in no_endpoints:
            print(f"  {p}")

    print()
    print("=" * 80)
    print("FULL API ENDPOINT MAPPING")
    print("=" * 80)
    for r in results:
        if r["endpoints"]:
            print(f"\n{r['route']}  ({r['component']}):")
            for ep in r["endpoints"]:
                print(f"    {ep}")
        else:
            print(f"\n{r['route']}  ({r['component']}):")
            print(f"    (no /api/v1/ calls detected in source)")

    return fail_count


if __name__ == "__main__":
    fail_count = run_tests()
    sys.exit(0 if fail_count == 0 else 1)
