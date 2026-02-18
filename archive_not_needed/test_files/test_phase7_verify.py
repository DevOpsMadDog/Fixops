#!/usr/bin/env python3
"""Phase 7 Verification: Attack Simulation Engine."""

import asyncio
import os
import sys

# Ensure suite paths are on sys.path
_ROOT = os.path.dirname(os.path.abspath(__file__))
for suite in (
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
    "suite-api",
):
    p = os.path.join(_ROOT, suite)
    if p not in sys.path:
        sys.path.insert(0, p)

ok = 0
fail = 0


def check(label, condition, detail=""):
    global ok, fail
    if condition:
        ok += 1
        print(f"  ✅ {label}")
    else:
        fail += 1
        print(f"  ❌ {label} — {detail}")


# ==========================================================================
# 1. Core Engine Imports
# ==========================================================================
print("\n=== 1. Attack Simulation Engine Imports ===")
try:
    from core.attack_simulation_engine import (
        LATERAL_TECHNIQUES,
        MITRE_TECHNIQUES,
        PRIVILEGE_LEVELS,
        AttackComplexity,
        AttackPath,
        AttackScenario,
        AttackSimulationEngine,
        AttackStep,
        BreachImpact,
        CampaignResult,
        CampaignStatus,
        KillChainPhase,
        ThreatActorProfile,
        get_attack_simulation_engine,
    )

    check("All core imports", True)
    check(
        "MITRE techniques count",
        len(MITRE_TECHNIQUES) == 34,
        f"got {len(MITRE_TECHNIQUES)}",
    )
    check(
        "Kill chain phases",
        len(list(KillChainPhase)) == 8,
        f"got {len(list(KillChainPhase))}",
    )
    check("Threat actor profiles", len(list(ThreatActorProfile)) == 6)
    check("Privilege levels", len(PRIVILEGE_LEVELS) == 7)
    check("Lateral techniques", len(LATERAL_TECHNIQUES) == 8)
except Exception as e:
    check("Core imports", False, str(e))

# ==========================================================================
# 2. Engine Singleton
# ==========================================================================
print("\n=== 2. Engine Singleton ===")
try:
    engine = get_attack_simulation_engine()
    check("Singleton created", engine is not None)
    engine2 = get_attack_simulation_engine()
    check("Singleton is same instance", engine is engine2)
except Exception as e:
    check("Singleton", False, str(e))

# ==========================================================================
# 3. Scenario Management
# ==========================================================================
print("\n=== 3. Scenario Management ===")
try:
    scenario = engine.create_scenario(
        name="Test APT Campaign",
        description="Testing attack simulation",
        threat_actor="nation_state",
        complexity="critical",
        target_assets=["web-server-01", "db-server-01"],
        target_cves=["CVE-2024-1234", "CVE-2024-5678"],
        objectives=["validate_vulnerability", "assess_blast_radius"],
    )
    check("Scenario created", scenario.scenario_id.startswith("scenario-"))
    check("Scenario name", scenario.name == "Test APT Campaign")
    check("Threat actor", scenario.threat_actor == ThreatActorProfile.NATION_STATE)
    check("Complexity", scenario.complexity == AttackComplexity.CRITICAL)
    check("Target CVEs", len(scenario.target_cves) == 2)
    check("Kill chain phases default", len(scenario.kill_chain_phases) == 8)

    # List and get
    scenarios = engine.list_scenarios()
    check("List scenarios", len(scenarios) >= 1)
    fetched = engine.get_scenario(scenario.scenario_id)
    check(
        "Get scenario by ID",
        fetched is not None and fetched.scenario_id == scenario.scenario_id,
    )
    check("Get non-existent scenario", engine.get_scenario("fake-id") is None)
except Exception as e:
    check("Scenario management", False, str(e))

# ==========================================================================
# 4. Campaign Execution (async)
# ==========================================================================
print("\n=== 4. Campaign Execution ===")
try:

    async def test_campaign():
        campaign = await engine.run_campaign(scenario.scenario_id, org_id="org-test")
        return campaign

    campaign = asyncio.run(test_campaign())
    check("Campaign created", campaign.campaign_id.startswith("campaign-"))
    check("Campaign completed", campaign.status == CampaignStatus.COMPLETED)
    check(
        "Steps executed > 0",
        campaign.steps_executed > 0,
        f"got {campaign.steps_executed}",
    )
    check(
        "Steps succeeded > 0",
        campaign.steps_succeeded > 0,
        f"got {campaign.steps_succeeded}",
    )
    check("Risk score > 0", campaign.risk_score > 0, f"got {campaign.risk_score}")
    check(
        "Attack paths built",
        len(campaign.attack_paths) > 0,
        f"got {len(campaign.attack_paths)}",
    )
    check("Breach impact exists", campaign.breach_impact is not None)
    check("MITRE coverage > 0 phases", len(campaign.mitre_coverage) > 0)
    check("Executive summary non-empty", len(campaign.executive_summary) > 0)
    check("Recommendations non-empty", len(campaign.recommendations) > 0)
    check("Started at set", len(campaign.started_at) > 0)
    check("Completed at set", len(campaign.completed_at) > 0)

    # Breach impact details
    bi = campaign.breach_impact
    check("Financial loss expected > 0", bi.financial_loss_expected > 0)
    check("Recovery time > 0", bi.recovery_time_hours > 0)
    check("Systems compromised > 0", bi.systems_compromised > 0)
    check(
        "Reputation impact set",
        bi.reputation_impact in ("low", "medium", "high", "critical"),
    )

    # Campaign queries
    check("Get campaign by ID", engine.get_campaign(campaign.campaign_id) is not None)
    check("List campaigns", len(engine.list_campaigns()) >= 1)
    check("Get non-existent campaign", engine.get_campaign("fake") is None)

    # MITRE heatmap
    heatmap = engine.get_mitre_heatmap()
    check("MITRE heatmap has phases", len(heatmap) > 0)
except Exception as e:
    import traceback

    traceback.print_exc()
    check("Campaign execution", False, str(e))
