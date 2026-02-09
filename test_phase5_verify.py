"""Phase 5 Verification: PentAGI → MPTE rebrand complete."""
import sys, os, inspect, subprocess

# Add suite paths
for suite in ['suite-core', 'suite-attack', 'suite-feeds', 'suite-api',
              'suite-evidence-risk', 'suite-integrations']:
    sp = os.path.join(os.getcwd(), suite)
    if os.path.isdir(sp) and sp not in sys.path:
        sys.path.insert(0, sp)
    api_p = os.path.join(sp, 'api')
    if os.path.isdir(api_p) and api_p not in sys.path:
        sys.path.insert(0, api_p)

ok = fail = 0

def check(name, condition, detail=""):
    global ok, fail
    if condition:
        ok += 1
        print(f"  [PASS] {name}")
    else:
        fail += 1
        print(f"  [FAIL] {name} — {detail}")

# 1. No PentAGI references in source code
print("=== No PentAGI References in Source Code ===")
result = subprocess.run(
    ["grep", "-rn", "-i", "pentagi",
     "--include=*.py", "--include=*.ts", "--include=*.tsx"],
    capture_output=True, text=True, cwd=os.getcwd()
)
lines = [l for l in result.stdout.strip().split("\n") if l
         and "archive" not in l and "node_modules" not in l
         and "__pycache__" not in l and "rebrand_pentagi" not in l]
check("Zero pentagi refs in .py/.ts/.tsx", len(lines) == 0,
      f"Found {len(lines)} references")

# 2. Renamed files exist
print("\n=== Renamed Files Exist ===")
renamed_files = [
    "suite-attack/api/mpte_router.py",
    "suite-core/core/mpte_advanced.py",
    "suite-core/core/mpte_db.py",
    "suite-core/core/mpte_models.py",
    "suite-integrations/integrations/mpte_client.py",
    "suite-integrations/integrations/mpte_decision_integration.py",
    "suite-integrations/integrations/mpte_service.py",
    "suite-api/apps/mpte_integration.py",
    "suite-ui/aldeci/src/components/attack/MPTEChat.tsx",
    "suite-ui/aldeci/src/pages/attack/MPTEConsole.tsx",
    "docker-compose.mpte.yml",
    "docs/MPTE_INTEGRATION.md",
]
for f in renamed_files:
    check(f"Exists: {f}", os.path.exists(f), "File not found")

# 3. Old files removed
print("\n=== Old Files Removed ===")
old_files = [
    "suite-attack/api/pentagi_router_enhanced.py",
    "suite-core/core/pentagi_advanced.py",
    "suite-core/core/pentagi_db.py",
    "suite-core/core/pentagi_models.py",
    "suite-integrations/integrations/pentagi_client.py",
    "suite-integrations/integrations/pentagi_service.py",
    "suite-api/apps/pentagi_integration.py",
    "docker-compose.pentagi.yml",
]
for f in old_files:
    check(f"Removed: {f}", not os.path.exists(f), "File still exists")

# 4. Critical imports work
print("\n=== Critical Imports ===")
try:
    from mpte_router import router as mpte_r
    check("mpte_router imports", True)
except Exception as e:
    check("mpte_router imports", False, str(e))

try:
    from core.mpte_db import MPTEDB
    check("MPTEDB imports", True)
except Exception as e:
    check("MPTEDB imports", False, str(e))

try:
    from core.mpte_models import PenTestConfig, PenTestRequest, PenTestResult
    check("mpte_models imports", True)
except Exception as e:
    check("mpte_models imports", False, str(e))

try:
    from integrations.mpte_client import MPTEClient
    check("MPTEClient imports", True)
except Exception as e:
    check("MPTEClient imports", False, str(e))

try:
    from integrations.mpte_service import AdvancedMPTEService
    check("AdvancedMPTEService imports", True)
except Exception as e:
    check("AdvancedMPTEService imports", False, str(e))

try:
    from micro_pentest_router import router as mpr
    check("micro_pentest_router imports", True)
except Exception as e:
    check("micro_pentest_router imports", False, str(e))

try:
    from copilot_router import router as cpr
    check("copilot_router imports", True)
except Exception as e:
    check("copilot_router imports", False, str(e))

try:
    from agents_router import router as agr
    check("agents_router imports", True)
except Exception as e:
    check("agents_router imports", False, str(e))

# 5. API prefix is /mpte not /pentagi
print("\n=== API Prefix Correct ===")
try:
    from mpte_router import router as mpte_r
    check("MPTE router prefix is /api/v1/mpte",
          mpte_r.prefix == "/api/v1/mpte",
          f"Got: {mpte_r.prefix}")
except Exception as e:
    check("MPTE router prefix", False, str(e))

# 6. No pentagi in router tags
print("\n=== Router Tags ===")
try:
    tags = mpte_r.tags or []
    check("MPTE router tags don't mention pentagi",
          not any("pentagi" in str(t).lower() for t in tags),
          f"Tags: {tags}")
except Exception as e:
    check("Router tags check", False, str(e))

# 7. Directory rename
print("\n=== Directory Rename ===")
check("mpte-aldeci dir exists",
      os.path.isdir("suite-integrations/mpte-aldeci"))
check("pentagi-aldeci dir removed",
      not os.path.isdir("suite-integrations/pentagi-aldeci"))

# 8. Previous phase 4 tests still pass
print("\n=== Phase 4 Regression (LLM still wired) ===")
try:
    from copilot_router import _HAS_LLM, _HAS_BRAIN
    check("Copilot _HAS_LLM still present", _HAS_LLM is not None)
    check("Copilot _HAS_BRAIN still present", _HAS_BRAIN is not None)
except Exception as e:
    check("Phase 4 regression", False, str(e))

try:
    import micro_pentest_router as mpt_mod
    has_llm = getattr(mpt_mod, '_HAS_LLM', None)
    check("MPTE _HAS_LLM still present", has_llm is not None)
except Exception as e:
    check("MPTE LLM regression", False, str(e))

print(f"\n{'='*50}")
print(f"Phase 5 Results: {ok} PASS, {fail} FAIL out of {ok+fail} tests")
print(f"{'='*50}")

