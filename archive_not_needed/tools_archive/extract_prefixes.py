#!/usr/bin/env python3
"""Extract all APIRouter prefixes and route paths from the codebase."""
import os, re

SUITES = [
    "suite-api/apps/api",
    "suite-core/api",
    "suite-attack/api",
    "suite-feeds/api",
    "suite-evidence-risk/api",
    "suite-integrations/api",
]

results = {}

for suite_dir in SUITES:
    if not os.path.isdir(suite_dir):
        continue
    for root, dirs, files in os.walk(suite_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            fp = os.path.join(root, fn)
            with open(fp) as f:
                text = f.read()

            # Find prefix in APIRouter(prefix=...) - handle multiline
            m = re.search(r'APIRouter\s*\(\s*prefix\s*=\s*["\']([^"\']+)["\']', text)
            prefix = m.group(1) if m else ""

            # Find all route decorators
            routes = re.findall(
                r'@(?:router|app)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                text,
            )

            if routes:
                results[fp] = {"prefix": prefix, "routes": routes}

# Print organized output
print("=" * 80)
print("ROUTER PREFIX + ROUTE MAP")
print("=" * 80)
total = 0
for fp in sorted(results.keys()):
    info = results[fp]
    prefix = info["prefix"] or "(NO PREFIX)"
    routes = info["routes"]
    total += len(routes)
    print(f"\n{fp}  [prefix={prefix}]  ({len(routes)} endpoints)")
    for method, path in routes:
        full = (info["prefix"] + path) if info["prefix"] else path
        print(f"  {method.upper():6s} {full}")

print(f"\n{'=' * 80}")
print(f"TOTAL: {total} endpoints across {len(results)} router files")

# Also write to a file in workspace
outpath = os.path.join(os.path.dirname(__file__), "prefix_map_output.txt")
with open(outpath, "w") as out:
    out.write("=" * 80 + "\n")
    out.write("ROUTER PREFIX + ROUTE MAP\n")
    out.write("=" * 80 + "\n")
    for fp in sorted(results.keys()):
        info = results[fp]
        prefix = info["prefix"] or "(NO PREFIX)"
        routes = info["routes"]
        out.write(f"\n{fp}  [prefix={prefix}]  ({len(routes)} endpoints)\n")
        for method, path in routes:
            full = (info["prefix"] + path) if info["prefix"] else path
            out.write(f"  {method.upper():6s} {full}\n")
    out.write(f"\n{'=' * 80}\n")
    out.write(f"TOTAL: {total} endpoints across {len(results)} router files\n")

