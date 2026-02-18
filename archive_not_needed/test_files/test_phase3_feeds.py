#!/usr/bin/env python3
"""Phase 3 Feeds Verification — Tests all new refresh methods and router endpoints."""
import os
import sys

root = os.path.dirname(os.path.abspath(__file__))
# Add suite roots for import resolution
for d in [
    "suite-feeds",
    "suite-feeds/api",
    "suite-core",
    "suite-api",
    "suite-attack",
    "suite-evidence-risk",
    "suite-integrations",
]:
    p = os.path.join(root, d)
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

ok = 0
fail = 0


def check(name, condition):
    global ok, fail
    if condition:
        print(f"  [OK] {name}")
        ok += 1
    else:
        print(f"  [FAIL] {name}")
        fail += 1


# ---- Test 1: FeedsService new methods ----
print("\n=== Test 1: FeedsService Methods ===")
from feeds_service import FeedsService

svc = FeedsService.__new__(FeedsService)

for method in [
    "refresh_nvd",
    "refresh_exploitdb",
    "refresh_osv",
    "refresh_github_advisories",
    "get_nvd_cve",
    "get_recent_nvd_cves",
]:
    check(f"FeedsService.{method}()", hasattr(svc, method))

# ---- Test 2: Scheduler uses _refresh_all pattern ----
print("\n=== Test 2: Scheduler ===")
import inspect

src = inspect.getsource(FeedsService.scheduler)
check("scheduler calls refresh_nvd", "refresh_nvd" in src)
check("scheduler calls refresh_exploitdb", "refresh_exploitdb" in src)
check("scheduler calls refresh_osv", "refresh_osv" in src)
check("scheduler calls refresh_github_advisories", "refresh_github_advisories" in src)

# ---- Test 3: feeds_router new endpoints ----
print("\n=== Test 3: Router Endpoints ===")
from feeds_router import router

route_paths = []
for r in router.routes:
    if hasattr(r, "path"):
        route_paths.append(r.path)

needed = [
    "/api/v1/feeds/nvd/refresh",
    "/api/v1/feeds/nvd/recent",
    "/api/v1/feeds/nvd/{cve_id}",
    "/api/v1/feeds/exploitdb/refresh",
    "/api/v1/feeds/osv/refresh",
    "/api/v1/feeds/github/refresh",
    "/api/v1/feeds/refresh/all",
]

for ep in needed:
    check(f"Endpoint {ep}", ep in route_paths)

# ---- Test 4: NVD table in DB schema ----
print("\n=== Test 4: Database Schema ===")
src_init = inspect.getsource(FeedsService._init_db)
check("nvd_cves table defined", "nvd_cves" in src_init)
check("idx_nvd_severity index", "idx_nvd_severity" in src_init)
check("idx_nvd_published index", "idx_nvd_published" in src_init)

# ---- Test 5: refresh_all includes new feeds ----
print("\n=== Test 5: refresh_all_feeds ===")
from feeds_router import refresh_all_feeds

src_all = inspect.getsource(refresh_all_feeds)
check("refresh_all calls refresh_nvd", "refresh_nvd" in src_all)
check("refresh_all calls refresh_exploitdb", "refresh_exploitdb" in src_all)
check("refresh_all calls refresh_osv", "refresh_osv" in src_all)
check(
    "refresh_all calls refresh_github_advisories",
    "refresh_github_advisories" in src_all,
)

# ---- Summary ----
print(f"\n{'='*50}")
print(f"Results: {ok} OK, {fail} FAIL out of {ok+fail} tests")
if fail == 0:
    print("ALL TESTS PASSED")
else:
    print(f"WARNING: {fail} test(s) failed")
