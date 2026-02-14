import os
out = []
for d in ["suite-evidence-risk/api", "suite-integrations/api", "suite-core/api", "suite-attack/api", "suite-feeds/api"]:
    if os.path.isdir(d):
        files = os.listdir(d)
        out.append(f"DIR EXISTS: {d} -> {files}")
    else:
        out.append(f"DIR MISSING: {d}")

# Check source files still exist
for f in [
    "suite-api/apps/api/enterprise_legacy/business_context.py",
    "suite-api/apps/api/enterprise_legacy/business_context_enhanced.py",
    "suite-api/apps/api/enterprise_legacy/oss_tools.py",
    "suite-api/apps/api/enterprise_legacy/decisions.py",
    "suite-api/apps/api/legacy/enhanced.py",
    "suite-api/apps/api/legacy/marketplace.py",
    "suite-api/apps/api/mpte_router.py",
    "suite-api/apps/api/health_router.py",
    "suite-api/apps/api/legacy_bridge_router.py",
]:
    out.append(f"{'EXISTS' if os.path.isfile(f) else 'MISSING'}: {f}")

with open("_verify_output.txt", "w") as fh:
    fh.write("\n".join(out))
print("DONE")

