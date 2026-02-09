#!/usr/bin/env python3
"""Verify all routers load correctly in suite-api."""
import sys, os

os.environ["FIXOPS_MODE"] = "demo"
os.environ["FIXOPS_AUTH_MODE"] = "dev"
os.environ["FIXOPS_DEMO_MODE"] = "true"
os.environ["FIXOPS_API_TOKEN"] = "test-token-verify"
os.environ["FIXOPS_JWT_SECRET"] = "test-jwt-secret"

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(root)

for s in ["suite-api", "suite-core", "suite-attack", "suite-feeds",
          "suite-integrations", "suite-evidence-risk",
          "archive/legacy", "archive/enterprise_legacy"]:
    p = os.path.join(root, s)
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

out = []
try:
    from apps.api.app import app
    routes = [r.path for r in app.routes if hasattr(r, "path")]
    out.append(f"TOTAL ROUTES: {len(routes)}")
    prefixes = {}
    for r in routes:
        parts = r.split("/")
        if len(parts) >= 4:
            k = "/".join(parts[:4])
            prefixes[k] = prefixes.get(k, 0) + 1
    out.append(f"UNIQUE PREFIXES: {len(prefixes)}")
    for p in sorted(prefixes):
        out.append(f"  {p}  ({prefixes[p]})")
    checks = [
        "/api/v1/nerve-center", "/api/v1/pipeline", "/api/v1/copilot",
        "/api/v1/ml", "/api/v1/attack-sim", "/api/v1/sast",
        "/api/v1/container", "/api/v1/dast", "/api/v1/cspm",
        "/api/v1/api-fuzzer", "/api/v1/malware", "/api/v1/evidence",
        "/api/v1/risk", "/api/v1/graph", "/api/v1/provenance",
        "/api/v1/integrations", "/api/v1/webhooks", "/api/v1/iac",
        "/api/v1/ide", "/api/v1/decisions", "/api/v1/business-context",
        "/api/v1/oss",
    ]
    out.append("\nCRITICAL PREFIX CHECK:")
    ok = miss = 0
    for c in checks:
        found = [r for r in routes if c in r]
        st = "OK" if found else "MISSING"
        if found: ok += 1
        else: miss += 1
        out.append(f"  {c}: {st} ({len(found)})")
    out.append(f"\nSUMMARY: {ok} OK, {miss} MISSING of {len(checks)}")
except Exception as e:
    import traceback
    out.append(f"ERROR: {e}")
    out.append(traceback.format_exc())

text = "\n".join(out)
print(text)
outf = os.path.join(root, "tools", "verify_routers_results.txt")
with open(outf, "w") as f:
    f.write(text + "\n")

