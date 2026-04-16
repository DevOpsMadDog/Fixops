#!/usr/bin/env python3
"""
ALDECI Full Endpoint Probe — extracts ALL routes from the live app,
probes every one, and prints a structured report.
"""

from __future__ import annotations

import json
import os
import sys
import time
import re
from collections import defaultdict

# ── 1. PATH SETUP ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for d in [
    os.path.join(BASE_DIR, "suite-api"),
    os.path.join(BASE_DIR, "suite-core"),
    os.path.join(BASE_DIR, "suite-feeds"),
    os.path.join(BASE_DIR, "suite-evidence-risk"),
    os.path.join(BASE_DIR, "suite-integrations"),
    os.path.join(BASE_DIR, "suite-attack"),
    BASE_DIR,
]:
    if d not in sys.path:
        sys.path.insert(0, d)

sys.setrecursionlimit(5000)

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_")
os.environ.setdefault("FIXOPS_JWT_SECRET", "probe-secret")
os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/probe.db")

# ── 2. ROUTE EXTRACTION ─────────────────────────────────────────────────────────
ROUTES_CACHE = "/tmp/all_routes.json"

def extract_routes() -> list[tuple[str, str]]:
    print("Loading app to extract routes …", flush=True)
    try:
        from apps.api.app import create_app
        app = create_app()
    except Exception as e:
        print(f"ERROR loading app: {e}")
        sys.exit(1)

    routes: list[tuple[str, str]] = []
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", None) or set()
        if not path.startswith("/api/"):
            continue
        for m in methods:
            if m in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                routes.append((m, path))

    routes.sort(key=lambda x: (x[1], x[0]))
    print(f"Extracted {len(routes)} routes from app.", flush=True)

    with open(ROUTES_CACHE, "w") as f:
        json.dump(routes, f)

    return routes


def load_or_extract_routes() -> list[tuple[str, str]]:
    if os.path.exists(ROUTES_CACHE):
        age = time.time() - os.path.getmtime(ROUTES_CACHE)
        if age < 3600:  # use cache if under 1 hour old
            with open(ROUTES_CACHE) as f:
                routes = json.load(f)
            print(f"Loaded {len(routes)} routes from cache ({ROUTES_CACHE}).", flush=True)
            return routes
    return extract_routes()


# ── 3. URL BUILDER ──────────────────────────────────────────────────────────────
PARAM_PLACEHOLDER = re.compile(r"\{[^}]+\}")

def build_url(base: str, method: str, path: str) -> tuple[str, dict | None, dict | None]:
    """Returns (url, params, json_body)."""
    # Replace all path params with test-id-1
    resolved = PARAM_PLACEHOLDER.sub("test-id-1", path)
    url = base.rstrip("/") + resolved

    if method == "GET":
        return url, {"org_id": "probe-test"}, None
    if method == "DELETE":
        return url, {"org_id": "probe-test"}, None
    # POST / PUT / PATCH
    return url, None, {"org_id": "probe-test"}


# ── 4. PROBE ────────────────────────────────────────────────────────────────────
BASE_URL   = "http://localhost:8000"
API_TOKEN  = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
DELAY      = 0.05   # 50 ms between requests
TIMEOUT    = 5      # seconds per request

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def make_session() -> requests.Session:
    s = requests.Session()
    # No retries — we want the raw first-response status
    adapter = HTTPAdapter(max_retries=0, pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "Authorization": f"Bearer {API_TOKEN}",
        "X-API-Key": API_TOKEN,
        "Content-Type": "application/json",
    })
    return s


def probe_all(routes: list[tuple[str, str]]) -> list[dict]:
    session = make_session()
    results = []
    total = len(routes)

    print(f"\nProbing {total} endpoints at {BASE_URL} …", flush=True)
    print("Progress: ", end="", flush=True)

    milestone = max(1, total // 20)  # print a dot every 5%

    for i, (method, path) in enumerate(routes, 1):
        if i % milestone == 0:
            pct = int(i / total * 100)
            print(f"{pct}%", end=" ", flush=True)

        url, params, body = build_url(BASE_URL, method, path)
        start = time.monotonic()
        status = 0
        try:
            resp = session.request(
                method,
                url,
                params=params,
                json=body,
                timeout=TIMEOUT,
                allow_redirects=True,
            )
            status = resp.status_code
        except requests.exceptions.ConnectionError:
            status = -1  # connection refused / timeout
        except requests.exceptions.Timeout:
            status = -2
        except Exception:
            status = -3

        elapsed_ms = int((time.monotonic() - start) * 1000)

        results.append({
            "method": method,
            "path": path,
            "status": status,
            "ms": elapsed_ms,
        })

        time.sleep(DELAY)

    print("100% done.", flush=True)
    return results


# ── 5. REPORT ───────────────────────────────────────────────────────────────────
def print_report(results: list[dict], routes: list[tuple[str, str]]) -> None:
    total = len(results)

    # Status buckets
    by_status: dict[int, list[dict]] = defaultdict(list)
    for r in results:
        by_status[r["status"]].append(r)

    def cnt(code: int) -> int:
        return len(by_status.get(code, []))

    def pct(n: int) -> str:
        return f"{n/total*100:.1f}%" if total else "0%"

    two_xx = [r for r in results if 200 <= r["status"] < 300]
    four_xx = [r for r in results if 400 <= r["status"] < 500]
    five_xx = [r for r in results if r["status"] >= 500]
    errors   = [r for r in results if r["status"] < 0]

    # Per-method summary
    method_stats: dict[str, dict] = {}
    for method, path in routes:
        if method not in method_stats:
            method_stats[method] = {"total": 0, "ok": 0}
        method_stats[method]["total"] += 1

    for r in two_xx:
        if r["method"] in method_stats:
            method_stats[r["method"]]["ok"] += 1

    # Top 500 errors
    top_500 = sorted(five_xx, key=lambda x: x["path"])[:30]

    # Top 422 errors (validation — signals wrong body)
    top_422 = [r for r in results if r["status"] == 422][:20]

    print()
    print("=" * 60)
    print("ALDECI FULL ENDPOINT PROBE RESULTS")
    print("=" * 60)
    print(f"Total probed:          {total}")
    print()

    # Enumerate known status codes
    status_labels = [
        (200, "OK"),
        (201, "Created"),
        (204, "No Content"),
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (405, "Method Not Allowed"),
        (422, "Validation Error"),
        (429, "Rate Limited"),
        (500, "Server Error"),
        (502, "Bad Gateway"),
        (503, "Service Unavailable"),
    ]

    for code, label in status_labels:
        n = cnt(code)
        if n:
            print(f"  {code} ({label:20s}): {n:5d}  ({pct(n)})")

    if errors:
        print(f"  Connection errors:    {len(errors):5d}")

    print()
    print(f"RESPONDING (2xx):      {len(two_xx):5d} / {total}  ({pct(len(two_xx))})")
    print(f"CLIENT ERROR (4xx):    {len(four_xx):5d} / {total}  ({pct(len(four_xx))})")
    print(f"SERVER ERROR (5xx):    {len(five_xx):5d} / {total}  ({pct(len(five_xx))})")
    if errors:
        print(f"CONNECTION ERRORS:     {len(errors):5d} / {total}")

    print()
    print("BY METHOD:")
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        if method in method_stats:
            s = method_stats[method]
            print(f"  {method:6s}: {s['ok']:5d} / {s['total']:5d} responding  ({pct(s['ok'])})")

    if top_500:
        print()
        print(f"TOP SERVER ERRORS (500) — showing up to 30:")
        for r in top_500:
            print(f"  {r['method']:6s} {r['path']}  → {r['status']}  ({r['ms']}ms)")

    if top_422:
        print()
        print(f"TOP VALIDATION ERRORS (422) — showing up to 20:")
        for r in top_422:
            print(f"  {r['method']:6s} {r['path']}")

    # Timing stats
    times = [r["ms"] for r in results if r["status"] > 0]
    if times:
        times_s = sorted(times)
        p50 = times_s[len(times_s) // 2]
        p95 = times_s[int(len(times_s) * 0.95)]
        p99 = times_s[int(len(times_s) * 0.99)]
        avg = sum(times_s) // len(times_s)
        print()
        print(f"RESPONSE TIME (ms):  avg={avg}  p50={p50}  p95={p95}  p99={p99}")

    print("=" * 60)


# ── 6. SAVE RESULTS ─────────────────────────────────────────────────────────────
RESULTS_FILE = "/tmp/probe_results.json"

def save_results(results: list[dict]) -> None:
    with open(RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results saved to {RESULTS_FILE}")


# ── 7. MAIN ─────────────────────────────────────────────────────────────────────
def main() -> None:
    t0 = time.monotonic()

    routes = load_or_extract_routes()
    results = probe_all(routes)
    print_report(results, routes)
    save_results(results)

    elapsed = time.monotonic() - t0
    print(f"Total run time: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
