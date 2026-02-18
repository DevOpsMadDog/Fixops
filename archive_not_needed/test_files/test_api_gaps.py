"""Find frontend→backend API gaps by checking which endpoints exist."""
import importlib.util
import os
import re
import sys

root = os.path.dirname(os.path.abspath(__file__))
for sp in [
    "suite-core",
    "suite-api",
    "suite-api/apps",
    "suite-attack",
    "suite-evidence-risk",
    "suite-feeds",
    "suite-integrations",
]:
    p = os.path.join(root, sp)
    if p not in sys.path:
        sys.path.insert(0, p)

# Collect all backend routes
all_routes = []

router_files = [
    ("suite-api/apps/api/app.py", None),  # main app has sub-routers
]

# Find all router files
import glob

for pattern in ["suite-*/api/*_router*.py", "suite-api/apps/api/*_router*.py"]:
    for f in glob.glob(os.path.join(root, pattern)):
        router_files.append((os.path.relpath(f, root), None))

# Also check non-router files that define routes
for pattern in ["suite-*/api/app.py", "suite-api/apps/api/health.py"]:
    for f in glob.glob(os.path.join(root, pattern)):
        router_files.append((os.path.relpath(f, root), None))

# Extract routes from all Python files using regex
route_patterns = set()
for filepath, _ in router_files:
    full = os.path.join(root, filepath)
    if not os.path.exists(full):
        continue
    with open(full) as fh:
        content = fh.read()

    # Find prefix
    prefix_match = re.search(r'APIRouter\(prefix=["\']([^"\']+)', content)
    prefix = prefix_match.group(1) if prefix_match else ""

    # Find route decorators
    for m in re.finditer(
        r'@(?:router|app)\.(get|post|put|patch|delete)\(["\']([^"\']+)', content
    ):
        method = m.group(1).upper()
        path = m.group(2)
        full_path = prefix + path if not path.startswith("/api/") else path
        # Normalize path params
        full_path = re.sub(r"\{[^}]+\}", "{id}", full_path)
        route_patterns.add((method, full_path))

# Frontend endpoints to check (extracted from api.ts)
frontend_calls = [
    ("GET", "/api/v1/mpte/configs"),
    ("POST", "/api/v1/mpte/comprehensive-scan"),
    ("GET", "/api/v1/reachability/metrics"),
    ("GET", "/api/v1/secrets/status"),
    ("GET", "/api/v1/secrets/scanners/status"),
    ("GET", "/api/v1/micro-pentest/health"),
    ("GET", "/api/v1/feeds/health"),
    ("GET", "/api/v1/feeds/stats"),
    ("GET", "/api/v1/analytics/export"),
    ("GET", "/api/v1/search"),
    ("GET", "/api/v1/status"),
    ("GET", "/api/v1/version"),
    ("GET", "/api/v1/auth/sso"),
    ("GET", "/evidence/stats"),
    ("POST", "/evidence/{id}/collect"),
    ("GET", "/api/v1/remediation/metrics"),
    ("POST", "/api/v1/remediation/tasks/{id}/assign"),
    ("GET", "/api/v1/deduplication/stats"),
    ("GET", "/api/v1/analytics/stats"),
    ("GET", "/api/v1/algorithms/status"),
    ("GET", "/api/v1/algorithms/capabilities"),
    ("GET", "/api/v1/feeds/epss"),
    ("GET", "/api/v1/feeds/kev"),
    ("GET", "/api/v1/feeds/exploits"),
    ("GET", "/api/v1/feeds/threat-actors"),
    ("POST", "/api/v1/feeds/epss/refresh"),
    ("POST", "/api/v1/feeds/kev/refresh"),
    ("GET", "/api/v1/workflows/rules"),
]

print(f"Backend routes found: {len(route_patterns)}")
print(f"Frontend calls to check: {len(frontend_calls)}")
print()

# Check each frontend call
gaps = []
matched = []
for method, path in sorted(frontend_calls):
    norm_path = re.sub(r"\{[^}]+\}", "{id}", path)
    found = False
    for rm, rp in route_patterns:
        rp_norm = re.sub(r"\{[^}]+\}", "{id}", rp)
        if rp_norm == norm_path:
            if rm == method:
                found = True
                break
    if found:
        matched.append((method, path))
    else:
        gaps.append((method, path))

print(f"=== MATCHED ({len(matched)}) ===")
for m, p in matched:
    print(f"  {m:6s} {p}")

print(f"\n=== GAPS ({len(gaps)}) ===")
for m, p in gaps:
    print(f"  {m:6s} {p}")

# Print all routes for reference
print(f"\n=== ALL BACKEND ROUTES ({len(route_patterns)}) ===")
for m, p in sorted(route_patterns):
    print(f"  {m:6s} {p}")
