#!/usr/bin/env python3
"""Audit script: count all route decorators across suites."""
import os
import re

router_files = []
for root, dirs, files in os.walk("."):
    if any(
        skip in root
        for skip in ["__pycache__", "node_modules", ".venv", "archive", ".git"]
    ):
        continue
    for f in files:
        if f.endswith(".py"):
            router_files.append(os.path.join(root, f))

route_pattern = re.compile(
    r"@(?:router|app)\.(get|post|put|patch|delete|head|options)\s*\("
)
path_pattern = re.compile(
    r'@(?:router|app)\.(get|post|put|patch|delete|head|options)\s*\(\s*["\']([^"\']*)["\']'
)

suite_counts = {}
all_routes = []
total = 0

for path in sorted(router_files):
    with open(path) as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        m = route_pattern.search(line)
        if m:
            method = m.group(1).upper()
            pm = path_pattern.search(line)
            route_path = pm.group(2) if pm else "UNKNOWN"
            suite = path.split("/")[1] if path.startswith("./suite-") else "other"
            if suite not in suite_counts:
                suite_counts[suite] = {"files": {}, "total": 0, "routes": []}
            fname = path
            if fname not in suite_counts[suite]["files"]:
                suite_counts[suite]["files"][fname] = 0
            suite_counts[suite]["files"][fname] += 1
            suite_counts[suite]["total"] += 1
            suite_counts[suite]["routes"].append((method, route_path, fname, i + 1))
            total += 1

with open("tools/audit_routes_output.txt", "w") as out:
    for suite in sorted(suite_counts.keys()):
        info = suite_counts[suite]
        out.write(f"\n=== {suite} ({info['total']} endpoints) ===\n")
        for f, count in sorted(info["files"].items()):
            out.write(f"  {f}: {count}\n")

    out.write(f"\n{'='*60}\n")
    out.write(f"TOTAL: {total} endpoints\n")
    out.write(f"{'='*60}\n\n")

    # Full route listing
    out.write("\n=== FULL ROUTE INVENTORY ===\n\n")
    for suite in sorted(suite_counts.keys()):
        info = suite_counts[suite]
        out.write(f"\n--- {suite} ---\n")
        for method, rpath, fname, lineno in info["routes"]:
            out.write(f"  {method:7s} {rpath:50s}  ({fname}:{lineno})\n")

print(f"Done. {total} endpoints found. Results in tools/audit_routes_output.txt")
