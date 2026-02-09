"""Test that all routers load correctly in suite-api."""
import sys
import os

# Set env vars BEFORE any imports
os.environ["FIXOPS_MODE"] = "demo"
os.environ["FIXOPS_AUTH_MODE"] = "dev"
os.environ["FIXOPS_DEMO_MODE"] = "true"
os.environ["FIXOPS_API_TOKEN"] = "test-token-for-router-verification"
os.environ["FIXOPS_JWT_SECRET"] = "test-secret-for-router-verification"

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(project_root)
output_file = os.path.join(project_root, "tools", "router_test_results.txt")

# Add suite paths manually
for suite in ["suite-api", "suite-core", "suite-attack", "suite-feeds",
              "suite-integrations", "suite-evidence-risk",
              "archive/legacy", "archive/enterprise_legacy"]:
    sp = os.path.join(project_root, suite)
    if os.path.isdir(sp) and sp not in sys.path:
        sys.path.insert(0, sp)

lines = []
try:
    from apps.api.app import app
    routes = [r.path for r in app.routes if hasattr(r, "path")]
    lines.append(f"TOTAL ROUTES: {len(routes)}")

    prefixes = {}
    for r in routes:
        parts = r.split("/")
        if len(parts) >= 4:
            key = "/".join(parts[:4])
            prefixes[key] = prefixes.get(key, 0) + 1
    lines.append(f"UNIQUE PREFIXES: {len(prefixes)}")
    for p in sorted(prefixes.keys()):
        lines.append(f"  {p}  ({prefixes[p]})")

    # Check critical previously-missing prefixes
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
    lines.append("\nCRITICAL PREFIX CHECK:")
    ok_count = 0
    missing_count = 0
    for check in checks:
        found = [r for r in routes if check in r]
        status = "OK" if found else "MISSING"
        if found:
            ok_count += 1
        else:
            missing_count += 1
        lines.append(f"  {check}: {status} ({len(found)} routes)")
    lines.append(f"\nSUMMARY: {ok_count} OK, {missing_count} MISSING out of {len(checks)} critical prefixes")

except Exception as e:
    import traceback
    lines.append(f"ERROR: {e}")
    lines.append(traceback.format_exc())

result = "\n".join(lines)
print(result)
with open(output_file, "w") as f:
    f.write(result + "\n")
