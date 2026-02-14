#!/usr/bin/env python3
"""Phase 1: Copy unique enterprise_legacy files to target suites, then report."""
import os
import shutil

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)

results = []

copies = [
    ("suite-api/apps/api/enterprise_legacy/business_context.py", "suite-evidence-risk/api/business_context.py"),
    ("suite-api/apps/api/enterprise_legacy/business_context_enhanced.py", "suite-evidence-risk/api/business_context_enhanced.py"),
    ("suite-api/apps/api/enterprise_legacy/oss_tools.py", "suite-integrations/api/oss_tools.py"),
    ("suite-api/apps/api/enterprise_legacy/decisions.py", "suite-core/api/decisions.py"),
]

for src, dst in copies:
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.isfile(src):
        shutil.copy2(src, dst)
        exists = os.path.isfile(dst)
        results.append(f"COPY {'OK' if exists else 'FAIL'}: {src} -> {dst}")
    else:
        results.append(f"SRC MISSING: {src}")

# Verify
for d in ["suite-evidence-risk/api", "suite-integrations/api", "suite-core/api"]:
    if os.path.isdir(d):
        results.append(f"DIR OK: {d} contains {os.listdir(d)}")
    else:
        results.append(f"DIR MISSING: {d}")

with open("_migrate_result.txt", "w") as f:
    f.write("\n".join(results) + "\n")

for r in results:
    print(r)

