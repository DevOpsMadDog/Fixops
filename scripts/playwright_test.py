"""
ALDECI Playwright Headless Browser Test
Tests all screens for load state, data presence, and JS errors.
Screenshots saved to .omc/screenshots/

Usage:
    python3 scripts/playwright_test.py
    python3 scripts/playwright_test.py --url http://localhost:5173
    python3 scripts/playwright_test.py --top30   # only first 30 screens
    python3 scripts/playwright_test.py --screen /dashboard,/alert-triage
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright, Error as PlaywrightError

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_URL = "http://localhost:5173"
SCREENSHOT_DIR = Path(__file__).parent.parent / ".omc" / "screenshots"
TIMEOUT_MS = 15_000          # per-page timeout
NETWORK_IDLE_TIMEOUT = 8_000 # wait_for_load_state networkidle timeout
AUTH_TOKEN = "aldeci-dev-token"

# localStorage state injected before every page load via add_init_script
# Strategy "token" + non-empty authToken = authenticated admin in auth.tsx
AUTH_INIT_SCRIPT = """
(function() {
  var user = JSON.stringify({
    id: "playwright-admin",
    email: "test@aldeci.local",
    first_name: "Playwright",
    last_name: "Tester",
    role: "admin"
  });
  localStorage.setItem("aldeci.authToken",    "aldeci-dev-token");
  localStorage.setItem("aldeci.authStrategy", "token");
  localStorage.setItem("aldeci.authUser",     user);
  localStorage.setItem("aldeci.orgId",        "default");
  localStorage.setItem("authToken",           "aldeci-dev-token");
  localStorage.setItem("apiKey",              "aldeci-dev-token");
})();
"""

# ---------------------------------------------------------------------------
# All ALDECI routes (extracted from App.tsx)
# Grouped: core first, then engine dashboards, then Wave 40-41 newest
# ---------------------------------------------------------------------------
ALL_SCREENS = [
    # --- Core / Mission Control ---
    "/",
    "/dashboard",
    "/mission-control",
    "/mission-control/ciso",
    "/mission-control/executive",
    "/mission-control/sla",
    "/mission-control/live-feed",
    "/mission-control/risk",
    "/mission-control/soc",
    "/mission-control/soc-t1",
    "/mission-control/compliance",
    "/mission-control/dev-security",
    "/mission-control/threat-intel",
    "/mission-control/risk-register",
    # --- Discover ---
    "/discover",
    "/discover/code",
    "/discover/secrets",
    "/discover/iac",
    "/discover/cloud",
    "/discover/containers",
    "/discover/sbom",
    "/discover/graph",
    "/discover/attack-paths",
    "/discover/threats",
    "/discover/correlation",
    "/discover/data-fabric",
    # --- Validate ---
    "/validate",
    "/validate/mpte",
    "/validate/simulation",
    "/validate/playbooks",
    "/validate/reachability",
    # --- Remediate ---
    "/remediate",
    "/remediate/autofix",
    "/remediate/collaborate",
    "/remediate/workflows",
    "/remediate/cases",
    "/remediate/tickets",
    # --- Comply ---
    "/comply",
    "/comply/evidence",
    "/comply/bundles",
    "/comply/soc2",
    "/comply/audit",
    "/comply/reports",
    "/comply/analytics",
    "/comply/export",
    # --- AI ---
    "/ai",
    "/ai/brain",
    "/ai/consensus",
    "/ai/algorithms",
    "/ai/ml",
    "/ai/predictions",
    # --- Settings ---
    "/settings",
    "/settings/integrations",
    "/settings/users",
    "/settings/health",
    "/settings/logs",
    # --- Standalone Engine Dashboards ---
    "/alert-triage",
    "/compliance",
    "/security-graph",
    "/brain",
    "/ai-advisor",
    "/ai-advisor-dashboard",
    "/scheduled-reports",
    "/findings",
    "/attack-surface",
    "/integrations",
    "/hunting",
    "/threat-hunting",
    "/developer",
    "/api-explorer",
    "/vendors",
    "/incidents",
    "/risk-acceptance",
    "/sbom",
    "/security-posture",
    "/security-health",
    "/vuln-lifecycle",
    "/threat-intel",
    "/assets",
    "/security-metrics",
    "/security-roadmap",
    "/cross-domain-analytics",
    "/devsecops",
    "/vuln-trends",
    "/config-benchmark",
    "/incident-timeline-dashboard",
    "/security-metrics-live",
    "/zero-trust-policies",
    "/threat-models",
    "/security-exceptions",
    "/regulatory-tracker",
    "/security-scorecard",
    "/ccm",
    "/system-health",
    "/openclaw",
    "/soc-triage",
    "/sbom-dashboard",
    "/ndr",
    "/xdr",
    "/awareness-score",
    "/edr",
    "/identity-analytics",
    "/cnapp",
    "/pentest-mgmt",
    "/supply-chain-intel",
    "/threat-actors",
    "/security-champions",
    "/security-maturity",
    "/privacy-gdpr",
    "/network-traffic",
    "/container-security",
    "/cloud-compliance",
    "/endpoint-compliance",
    "/api-security-mgmt",
    "/vuln-intelligence",
    "/firewall-policy",
    "/network-segmentation",
    "/mfa-management",
    "/threat-scores",
    "/security-budget",
    "/compliance-gaps",
    "/ai-governance",
    "/digital-identity",
    "/attack-chains",
    "/threat-exposure",
    "/license-security",
    "/cloud-identity",
    "/dark-web",
    "/itdr",
    "/container-runtime",
    "/api-discovery",
    "/security-chaos",
    "/incident-metrics",
    "/zero-day",
    "/security-tabletop",
    "/browser-security",
    "/data-exfiltration",
    "/pki-management",
    "/tool-inventory",
    "/firmware-security",
    "/iot-security",
    "/mobile-app-security",
    "/supply-chain-attacks",
    "/cwp",
    "/autonomous-remediation",
    "/vuln-correlation",
    "/posture-benchmarking",
    "/quantum-crypto",
    "/ai-soc",
    "/deception-analytics",
    "/threat-intel-automation",
    "/metrics-aggregator",
    "/endpoint-hunting",
    "/cloud-security-analytics",
    "/identity-risk",
    "/ot-security",
    "/network-forensics",
    "/malware-analysis",
    "/application-risk",
    "/pag",
    "/security-gamification",
    "/vuln-prioritization",
    "/threat-deception",
    "/posture-scoring",
    "/cloud-posture",
    "/api-threat-protection",
    "/risk-register-engine",
    "/change-management",
    "/compliance-automation",
    "/threat-attribution",
    "/cloud-access-security",
    "/behavioral-analytics",
    "/vuln-workflow",
    "/data-pipeline",
    "/awareness-metrics",
    "/patch-management",
    "/container-posture",
    "/cyber-threat-intel",
    "/digital-twin",
    "/access-requests",
    "/session-recording",
    "/cloud-inventory",
    "/security-telemetry",
    "/microsegmentation",
    "/third-party-vendor",
    "/sspm",
    "/api-inventory",
    "/threat-vectors",
    "/awareness-campaigns",
    "/risk-treatment",
    "/data-discovery",
    "/compliance-mapping",
    "/vuln-scans",
    "/threat-briefs",
    "/incident-comms",
    "/asset-tags",
    "/security-registry",
    "/privacy-impact",
    "/threat-indicators",
    "/ransomware-protection",
    "/access-anomaly",
    "/training-effectiveness",
    "/cost-optimization",
    "/arch-review",
    "/hunting-playbooks",
    "/program-maturity",
    "/cloud-ir",
    "/identity-lifecycle",
    "/dependency-mapping",
    "/risk-quant",
    "/cyber-threat-modeling",
    "/capacity-planning",
    "/tprm-exchange",
    "/event-timeline",
    "/vuln-intel-fusion",
    "/posture-reports",
    "/network-anomaly",
    "/privileged-identity",
    "/hunting-automation",
    "/evidence-vault",
    "/service-catalog",
    "/sbom-export",
    "/gap-analysis",
    "/alert-enrichment",
    "/security-baselines",
    "/threat-response",
    "/awareness-program",
    "/posture-maturity",
    "/cloud-findings",
    "/soc-metrics",
    "/vuln-age",
    "/ti-confidence",
    "/dependency-risk",
    "/health-scorecard",
    "/compliance-calendar",
    "/cyber-resilience",
    "/asset-criticality",
    "/security-investment",
    "/threat-modeling-pipeline",
    "/exception-workflow",
    "/actor-tracking",
    "/vuln-scoring",
    "/security-benchmarks",
    "/incident-costs",
    "/security-culture",
    "/security-questionnaires",
    "/risk-scenarios",
    "/feed-subscriptions",
    "/asset-groups",
    "/security-findings",
    "/control-testing",
    "/compliance-workflows",
    "/threat-landscape",
    "/posture-trends",
    "/access-governance",
    "/network-threats",
    "/incident-kb",
    "/access-reviews",
    "/posture-history",
    "/incident-lessons",
    "/cloud-accounts",
    "/intel-enrichment",
    "/security-okrs",
    "/competitive-comparison",
    "/dlp",
    "/secret-scanner",
    "/threat-intel-platform",
    "/attack-surface-dashboard",
    "/executive-reporting",
    "/vuln-heatmap",
    "/security-kpi",
    "/threat-modeling",
    "/vendor-risk",
    "/alert-triage",
    "/awareness-metrics",
    "/patch-management",
    "/container-posture",
    "/digital-twin",
    "/alert-triage",
    "/network-monitoring",
    "/sca",
    "/service-account-audit",
    "/network-segmentation",
    "/threat-geolocation",
    "/ip-reputation",
]

# Deduplicate while preserving order
seen = set()
SCREENS = []
for s in ALL_SCREENS:
    if s not in seen:
        seen.add(s)
        SCREENS.append(s)

TOP_30 = SCREENS[:30]

# ---------------------------------------------------------------------------
# Data-presence selectors (any match = "has data")
# ---------------------------------------------------------------------------
DATA_SELECTORS = [
    "table tbody tr",
    ".recharts-surface",
    ".recharts-responsive-container",
    "[class*='recharts']",
    "[class*='chart']",
    "[class*='Chart']",
    "[class*='data-']",
    "[class*='metric']",
    "[class*='Metric']",
    "[class*='stat']",
    "[class*='Stat']",
    "[class*='card']",
    "[class*='Card']",
    "[class*='badge']",
    "[class*='Badge']",
    "svg",
    ".data-loaded",
    "[data-testid]",
]

ERROR_SELECTORS = [
    ".error",
    "[data-error]",
    "[class*='error']",
    "[class*='Error']",
    "[role='alert']",
    ".alert-error",
    ".toast-error",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def slug(path: str) -> str:
    """Convert URL path (may contain #/) to safe filename."""
    # Strip base URL, hash prefix, leading slashes
    clean = path.replace("/#", "").replace("#", "").strip("/")
    return (clean.replace("/", "_") or "root") + ".png"


_MOCK_API_RESPONSE = json.dumps({
    "status": "ok", "data": [], "items": [], "results": [], "total": 0,
    "page": 1, "pages": 1, "count": 0,
    "metrics": {}, "stats": {}, "summary": {},
    "access_token": "mock-jwt", "user": {
        "id": "api-key", "email": "test@aldeci.local",
        "first_name": "Playwright", "last_name": "Tester", "role": "admin",
    },
})


def _stub_api(route):
    """Return a mock 200 JSON response for any /api/v1/* request."""
    route.fulfill(
        status=200,
        content_type="application/json",
        body=_MOCK_API_RESPONSE,
    )


def setup_api_mocks(context) -> None:
    """
    Intercept ALL /api/* requests context-wide and return 200 mocks.
    This prevents the 401-on-missing-backend → window.location.hash='#/login' redirect
    that both api-client.ts and api/client.ts fire when the backend is down.
    """
    context.route("**/api/**", _stub_api)


def set_auth(context) -> None:
    """
    Inject auth state so React's AuthProvider reads it on every navigation.

    1. add_init_script — sets localStorage before React's useState initializer runs.
    2. setup_api_mocks — intercepts API calls to prevent 401→#/login redirects.
    """
    context.add_init_script(AUTH_INIT_SCRIPT)
    setup_api_mocks(context)


def check_page(page, url: str, screenshot_dir: Path) -> dict:
    """
    Navigate to url, wait for network idle, capture result.
    Returns a result dict.
    """
    result = {
        "url": url,
        "status": "unknown",
        "has_data": False,
        "errors": [],
        "js_errors": [],
        "screenshot": None,
        "load_ms": None,
    }

    js_errors = []
    page.on("pageerror", lambda err: js_errors.append(str(err)))

    t0 = time.time()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=TIMEOUT_MS)
        try:
            page.wait_for_load_state("networkidle", timeout=NETWORK_IDLE_TIMEOUT)
        except Exception:
            pass  # networkidle timeout is non-fatal; page may still render
        result["load_ms"] = int((time.time() - t0) * 1000)

        # Check for redirect to /login (auth wall)
        # With HashRouter the path is in the fragment: http://host/#/login
        current = page.url
        current_hash = page.evaluate("() => window.location.hash")
        result["final_url"] = current + " (hash=" + current_hash + ")"
        if "#/login" in current or "#/onboarding" in current or current_hash in ("#/login", "#/onboarding", "#!/login"):
            result["status"] = "auth_redirect"
        else:
            result["status"] = "loaded"

        # Check for visible error elements
        for sel in ERROR_SELECTORS:
            try:
                els = page.query_selector_all(sel)
                if els:
                    for el in els[:3]:
                        txt = el.inner_text().strip()[:120]
                        if txt:
                            result["errors"].append(f"{sel}: {txt}")
            except Exception:
                pass

        # Check for data-presence elements
        for sel in DATA_SELECTORS:
            try:
                el = page.query_selector(sel)
                if el:
                    result["has_data"] = True
                    break
            except Exception:
                pass

    except PlaywrightError as e:
        result["status"] = "error"
        result["errors"].append(str(e)[:200])
        result["load_ms"] = int((time.time() - t0) * 1000)

    # Screenshot (always attempt)
    try:
        fname = slug(url.replace(BASE_URL, ""))
        fpath = screenshot_dir / fname
        page.screenshot(path=str(fpath), full_page=False, timeout=5000)
        result["screenshot"] = str(fpath)
    except Exception as e:
        result["screenshot"] = f"FAILED: {e}"

    result["js_errors"] = js_errors[:5]
    return result


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(results: list[dict], elapsed: float) -> None:
    loaded = [r for r in results if r["status"] == "loaded"]
    auth_redirect = [r for r in results if r["status"] == "auth_redirect"]
    errors = [r for r in results if r["status"] == "error"]
    has_data = [r for r in results if r["has_data"]]
    with_errors = [r for r in results if r["errors"]]
    with_js_errors = [r for r in results if r["js_errors"]]

    print("\n" + "=" * 72)
    print(f"  ALDECI Playwright Test Report  ({len(results)} screens, {elapsed:.1f}s)")
    print("=" * 72)
    print(f"  Loaded (200):          {len(loaded):>4}")
    print(f"  Auth redirect:         {len(auth_redirect):>4}  (token injection may need adjustment)")
    print(f"  Hard errors:           {len(errors):>4}")
    print(f"  Pages with data:       {len(has_data):>4}")
    print(f"  Pages with UI errors:  {len(with_errors):>4}")
    print(f"  Pages with JS errors:  {len(with_js_errors):>4}")
    print("=" * 72)

    if errors:
        print("\n-- HARD ERRORS (page failed to load) --")
        for r in errors:
            print(f"  {r['url']}")
            for e in r["errors"]:
                print(f"    {e}")

    if with_errors:
        print("\n-- UI ERROR ELEMENTS DETECTED --")
        for r in with_errors:
            print(f"  {r['url']}")
            for e in r["errors"][:3]:
                print(f"    {e}")

    if with_js_errors:
        print("\n-- JS CONSOLE ERRORS --")
        for r in with_js_errors:
            print(f"  {r['url']}")
            for e in r["js_errors"][:2]:
                print(f"    {e}")

    if auth_redirect:
        print("\n-- AUTH REDIRECTS (routes requiring login) --")
        for r in auth_redirect:
            print(f"  {r['url']}")

    print("\n-- PAGES WITHOUT DATA (may need backend running) --")
    no_data = [r for r in loaded if not r["has_data"]]
    for r in no_data[:20]:
        print(f"  {r['url']}")
    if len(no_data) > 20:
        print(f"  ... and {len(no_data)-20} more")

    print(f"\n  Screenshots: {SCREENSHOT_DIR}")
    print("=" * 72 + "\n")


def save_json_report(results: list[dict], elapsed: float) -> None:
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "elapsed_s": round(elapsed, 1),
        "summary": {
            "loaded": sum(1 for r in results if r["status"] == "loaded"),
            "auth_redirect": sum(1 for r in results if r["status"] == "auth_redirect"),
            "errors": sum(1 for r in results if r["status"] == "error"),
            "has_data": sum(1 for r in results if r["has_data"]),
            "ui_errors": sum(1 for r in results if r["errors"]),
            "js_errors": sum(1 for r in results if r["js_errors"]),
        },
        "results": results,
    }
    out = SCREENSHOT_DIR / "report.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"  JSON report: {out}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ALDECI Playwright screen test")
    parser.add_argument("--url", default=BASE_URL, help="Base URL (default: http://localhost:5173)")
    parser.add_argument("--top30", action="store_true", help="Test only top 30 screens")
    parser.add_argument("--screen", help="Comma-separated list of paths to test")
    parser.add_argument("--timeout", type=int, default=TIMEOUT_MS, help="Per-page timeout ms")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    if args.screen:
        screens = [s.strip() for s in args.screen.split(",")]
    elif args.top30:
        screens = TOP_30
    else:
        screens = SCREENS

    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\nALDECI Playwright Test")
    print(f"  Base URL:    {base_url}")
    print(f"  Screens:     {len(screens)}")
    print(f"  Screenshots: {SCREENSHOT_DIR}")
    print(f"  Timeout:     {args.timeout}ms per page")
    print()

    results = []
    t_start = time.time()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
        )
        page = context.new_page()

        # Inject auth + API mocks (must be done on context before any navigation)
        set_auth(context)
        print(f"  Auth init script + API mocks registered")

        for i, path in enumerate(screens, 1):
            url = base_url + "/#" + path
            print(f"  [{i:>3}/{len(screens)}] {path}", end=" ... ", flush=True)
            r = check_page(page, url, SCREENSHOT_DIR)
            results.append(r)

            status_str = r["status"]
            data_str = "data" if r["has_data"] else "no-data"
            err_str = f" | {len(r['errors'])} ui-err" if r["errors"] else ""
            js_str = f" | {len(r['js_errors'])} js-err" if r["js_errors"] else ""
            ms_str = f"{r['load_ms']}ms" if r["load_ms"] else "?ms"
            print(f"{status_str} | {data_str} | {ms_str}{err_str}{js_str}")

        context.close()
        browser.close()

    elapsed = time.time() - t_start
    print_report(results, elapsed)
    save_json_report(results, elapsed)


if __name__ == "__main__":
    main()
