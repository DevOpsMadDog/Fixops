"""Phase 4 Verification: LLM integration across Copilot + MPTE."""
import inspect
import os
import sys

# Add suite paths
for suite in [
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-api",
    "suite-evidence-risk",
    "suite-integrations",
]:
    sp = os.path.join(os.getcwd(), suite)
    if os.path.isdir(sp) and sp not in sys.path:
        sys.path.insert(0, sp)
    api_p = os.path.join(sp, "api")
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


# 1. Copilot router imports
print("=== Copilot Router Imports ===")
try:
    from copilot_router import (
        _AGENT_SYSTEM_PROMPTS,
        _HAS_BRAIN,
        _HAS_FEEDS,
        _HAS_LLM,
        _call_llm_agent,
        router,
    )

    check("copilot_router imports", True)
    check("_HAS_LLM flag present", _HAS_LLM is not None, f"_HAS_LLM={_HAS_LLM}")
    check("_HAS_BRAIN flag present", _HAS_BRAIN is not None)
    check("_HAS_FEEDS flag present", _HAS_FEEDS is not None)
    check(
        "Agent system prompts",
        len(_AGENT_SYSTEM_PROMPTS) >= 4,
        f"Only {len(_AGENT_SYSTEM_PROMPTS)} prompts",
    )
    check(
        "All 4 agent types",
        all(
            k in _AGENT_SYSTEM_PROMPTS
            for k in ("security_analyst", "pentest", "compliance", "remediation")
        ),
    )
except Exception as e:
    check("copilot_router imports", False, str(e))

# 2. Micro pentest router imports
print("\n=== MPTE Router Imports ===")
try:
    # Check _HAS_LLM exists in module
    import micro_pentest_router as mpt_mod
    from micro_pentest_router import router as mpr

    has_llm = getattr(mpt_mod, "_HAS_LLM", None)
    check("micro_pentest_router imports", True)
    check("MPTE _HAS_LLM flag", has_llm is not None, f"_HAS_LLM={has_llm}")
except Exception as e:
    check("micro_pentest_router imports", False, str(e))

# 3. LLM Provider Manager
print("\n=== LLM Provider Manager ===")
try:
    from core.llm_providers import LLMProviderManager

    mgr = LLMProviderManager()
    check("LLMProviderManager instantiates", True)
    for name in ("openai", "anthropic", "gemini", "sentinel"):
        prov = mgr.get_provider(name)
        has_key = hasattr(prov, "api_key") and bool(prov.api_key)
        check(f"Provider {name} available", prov is not None, "provider is None")
        print(f"    configured={has_key}")
except Exception as e:
    check("LLMProviderManager", False, str(e))

# 4. No asyncio.sleep stubs in comprehensive scan
print("\n=== MPTE: No asyncio.sleep Stubs ===")
try:
    from micro_pentest_router import MicroPentestEngine

    src = inspect.getsource(MicroPentestEngine.run_scan)
    sleep_count = src.count("asyncio.sleep")
    check(
        "No asyncio.sleep in run_scan",
        sleep_count == 0,
        f"Found {sleep_count} occurrences",
    )
except Exception as e:
    check("asyncio.sleep check", False, str(e))

# 5. LLM usage in comprehensive scan
print("\n=== MPTE: LLM Usage in Scan Phases ===")
try:
    src = inspect.getsource(MicroPentestEngine.run_scan)
    check("LLMProviderManager used in scan", "LLMProviderManager" in src)
    check(
        "Phase 1 has LLM prompt",
        "initialising a micro" in src.lower() or "test plan" in src.lower(),
    )
    check("Phase 2 has recon prompt", "reconnaissance" in src.lower())
    check("Phase 3 has threat model prompt", "threat model" in src.lower())
    check(
        "Phase 7 has risk scoring prompt",
        "risk" in src.lower() and "score" in src.lower(),
    )
    check("llm_intelligence in summary", "llm_intelligence" in src)
except Exception as e:
    check("LLM usage check", False, str(e))

# 6. PoC generation enhanced
print("\n=== MPTE: Enhanced PoC Generation ===")
try:
    src = inspect.getsource(MicroPentestEngine._generate_proofs_of_concept)
    check("PoC uses LLM", "LLMProviderManager" in src)
    check("PoC has fallback", "_hardcoded_poc" in src)
    check("_hardcoded_poc method exists", hasattr(MicroPentestEngine, "_hardcoded_poc"))
except Exception as e:
    check("PoC generation check", False, str(e))

# 7. No MindsDB stubs in copilot
print("\n=== Copilot: No MindsDB Stubs ===")
try:
    import copilot_router

    csrc = inspect.getsource(copilot_router)
    mindsdb_count = csrc.lower().count("mindsdb")
    check(
        "No MindsDB references in copilot",
        mindsdb_count == 0,
        f"Found {mindsdb_count} references",
    )
except Exception as e:
    check("MindsDB check", False, str(e))

# 8. Copilot health endpoint reports LLM
print("\n=== Copilot: Health Endpoint ===")
try:
    src = inspect.getsource(copilot_router.copilot_health)
    check("Health reports llm_providers", "llm_providers" in src)
    check("Health reports knowledge_brain", "knowledge_brain" in src)
    check("Health reports feeds_service", "feeds_service" in src)
    check("Version 2.0.0", "2.0.0" in src)
except Exception as e:
    check("Health endpoint check", False, str(e))

# 9. Copilot suggestions uses LLM
print("\n=== Copilot: Suggestions Endpoint ===")
try:
    src = inspect.getsource(copilot_router.get_suggestions)
    check("Suggestions uses LLM", "LLMProviderManager" in src)
    check("Suggestions parses JSON", "json.loads" in src)
except Exception as e:
    check("Suggestions check", False, str(e))

# 10. Quick analyze uses FeedsService directly
print("\n=== Copilot: Quick Analyze ===")
try:
    src = inspect.getsource(copilot_router.quick_analyze)
    check("No sys.path hack", "sys.path" not in src)
    check("No fixops-enterprise", "fixops-enterprise" not in src)
    check("Uses _HAS_FEEDS", "_HAS_FEEDS" in src)
    check("Uses LLM for analysis", "LLMProviderManager" in src or "_HAS_LLM" in src)
except Exception as e:
    check("Quick analyze check", False, str(e))

print(f"\n{'='*50}")
print(f"Phase 4 Results: {ok} PASS, {fail} FAIL out of {ok+fail} tests")
print(f"{'='*50}")
