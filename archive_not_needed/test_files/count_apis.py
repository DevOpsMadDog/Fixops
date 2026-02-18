#!/usr/bin/env python3
"""Count all API endpoints across the FixOps codebase."""
import os
import re

count = {"get": 0, "post": 0, "put": 0, "patch": 0, "delete": 0}
files_with_routes = []
total = 0
all_endpoints = []

for suite in [
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
]:
    for root, dirs, fnames in os.walk(suite):
        if "__pycache__" in root or "node_modules" in root:
            continue
        for fn in fnames:
            if not fn.endswith(".py"):
                continue
            fpath = os.path.join(root, fn)
            with open(fpath, "r", errors="ignore") as f:
                lines = f.readlines()
            endpoints_in_file = 0
            for i, line in enumerate(lines):
                m = re.search(
                    r'@(router|app)\.(get|post|put|patch|delete)\(\s*["\']([^"\']*)["\']',
                    line,
                )
                if m:
                    method = m.group(2).upper()
                    path = m.group(3)
                    count[m.group(2)] += 1
                    total += 1
                    endpoints_in_file += 1
                    all_endpoints.append((method, path, fpath, i + 1))
                elif re.search(r"@(router|app)\.(get|post|put|patch|delete)\(", line):
                    method_match = re.search(r"\.(get|post|put|patch|delete)\(", line)
                    if method_match:
                        method = method_match.group(1).upper()
                        count[method_match.group(1)] += 1
                        total += 1
                        endpoints_in_file += 1
                        all_endpoints.append((method, "?", fpath, i + 1))
            if endpoints_in_file > 0:
                files_with_routes.append((fpath, endpoints_in_file))

print(f"=== TOTAL API ENDPOINTS: {total} ===")
print()
print("By HTTP Method:")
for m, c in sorted(count.items(), key=lambda x: -x[1]):
    print(f"  {m.upper():8s} {c}")
print()
print(f"Router files: {len(files_with_routes)}")
print()

# Group by suite
suite_counts = {}
for fp, cnt in files_with_routes:
    suite = fp.split("/")[0]
    suite_counts[suite] = suite_counts.get(suite, 0) + cnt

print("By Suite:")
for s, c in sorted(suite_counts.items(), key=lambda x: -x[1]):
    print(f"  {s:30s} {c}")
print()

files_with_routes.sort(key=lambda x: -x[1])
print("Top router files:")
for fp, cnt in files_with_routes[:40]:
    print(f"  {cnt:3d}  {fp}")
