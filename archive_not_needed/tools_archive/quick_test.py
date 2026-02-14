#!/usr/bin/env python3
import sys, os
os.environ["FIXOPS_MODE"] = "demo"
os.environ["FIXOPS_AUTH_MODE"] = "dev"
os.environ["FIXOPS_DEMO_MODE"] = "true"
os.environ["FIXOPS_API_TOKEN"] = "test-token-verify"
os.environ["FIXOPS_JWT_SECRET"] = "test-jwt-secret"

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(root)
for s in ["suite-api","suite-core","suite-attack","suite-feeds",
          "suite-integrations","suite-evidence-risk",
          "archive/legacy","archive/enterprise_legacy"]:
    p = os.path.join(root, s)
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

result_path = os.path.join(root, "tools", "quick_results.txt")
with open(result_path, "w") as f:
    f.write("STARTED\n")
    try:
        from apps.api.app import app
        routes = [r.path for r in app.routes if hasattr(r, "path")]
        f.write(f"TOTAL ROUTES: {len(routes)}\n")
        prefixes = {}
        for r in routes:
            parts = r.split("/")
            if len(parts) >= 4:
                k = "/".join(parts[:4])
                prefixes[k] = prefixes.get(k, 0) + 1
        f.write(f"UNIQUE PREFIXES: {len(prefixes)}\n")
        for p in sorted(prefixes):
            f.write(f"  {p}  ({prefixes[p]})\n")
        checks = [
            "/api/v1/nerve-center","/api/v1/pipeline","/api/v1/copilot",
            "/api/v1/ml","/api/v1/attack-sim","/api/v1/sast",
            "/api/v1/container","/api/v1/dast","/api/v1/cspm",
            "/api/v1/api-fuzzer","/api/v1/malware","/api/v1/evidence",
            "/api/v1/risk","/api/v1/graph","/api/v1/provenance",
            "/api/v1/integrations","/api/v1/webhooks","/api/v1/iac",
            "/api/v1/ide","/api/v1/decisions","/api/v1/business-context",
            "/api/v1/oss",
        ]
        f.write("\nCRITICAL PREFIX CHECK:\n")
        ok = miss = 0
        for c in checks:
            found = [r for r in routes if c in r]
            st = "OK" if found else "MISSING"
            if found: ok += 1
            else: miss += 1
            f.write(f"  {c}: {st} ({len(found)})\n")
        f.write(f"\nSUMMARY: {ok} OK, {miss} MISSING of {len(checks)}\n")
    except Exception as e:
        import traceback
        f.write(f"ERROR: {e}\n")
        f.write(traceback.format_exc())
    f.write("DONE\n")

