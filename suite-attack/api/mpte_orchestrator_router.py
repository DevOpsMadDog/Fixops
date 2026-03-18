"""MPTE Orchestrator API router — unified pentest & decision capabilities as REST endpoints.

Exposes threat intelligence, business impact analysis, attack simulation,
remediation guidance, and capability introspection that were previously
CLI-only via ``advanced-pentest`` subcommands.

Prefix: ``/api/v1/mpte-orchestrator``

This router bridges the gap between the CLI-side ``advanced-pentest`` commands
and the HTTP API surface so that external integrations can
access the same features.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, HTTPException, Depends
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/mpte-orchestrator", tags=["mpte-orchestrator"])


# ---------------------------------------------------------------------------
# Lazy-loaded service singletons (graceful degradation)
# ---------------------------------------------------------------------------

_feeds_service = None
_attack_engine = None
_autofix_engine = None


def _get_feeds():
    """Lazy-load FeedsService."""
    global _feeds_service
    if _feeds_service is None:
        try:
            from feeds_service import FeedsService

            _feeds_service = FeedsService()
            logger.info("mpte_orchestrator.feeds_service.loaded")
        except ImportError as exc:
            logger.warning(
                "mpte_orchestrator.feeds_service.unavailable: %s", type(exc).__name__
            )
    return _feeds_service


def _get_attack_engine():
    """Lazy-load AttackSimulationEngine."""
    global _attack_engine
    if _attack_engine is None:
        try:
            from core.attack_simulation_engine import AttackSimulationEngine

            _attack_engine = AttackSimulationEngine()
            logger.info("mpte_orchestrator.attack_engine.loaded")
        except ImportError as exc:
            logger.warning(
                "mpte_orchestrator.attack_engine.unavailable: %s", type(exc).__name__
            )
    return _attack_engine


def _get_autofix_engine():
    """Lazy-load AutoFixEngine."""
    global _autofix_engine
    if _autofix_engine is None:
        try:
            from core.autofix_engine import AutoFixEngine

            _autofix_engine = AutoFixEngine()
            logger.info("mpte_orchestrator.autofix_engine.loaded")
        except ImportError as exc:
            logger.warning(
                "mpte_orchestrator.autofix_engine.unavailable: %s", type(exc).__name__
            )
    return _autofix_engine


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class ThreatIntelRequest(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-1234")


class BusinessImpactRequest(BaseModel):
    target: Optional[str] = Field(None, description="Target service name")
    cve_ids: Optional[List[str]] = Field(None, description="List of CVE IDs")


class SimulateRequest(BaseModel):
    target: str = Field(..., description="Target URL")
    attack_type: str = Field(
        "chained_exploit",
        description="Attack type: single_exploit, chained_exploit, privilege_escalation, lateral_movement",
    )


class RemediationRequest(BaseModel):
    cve_id: str = Field(..., description="CVE identifier")


class PentestRunRequest(BaseModel):
    target: str = Field(..., description="Target URL or service")
    cve_ids: Optional[List[str]] = Field(None, description="CVE IDs to test")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health")
async def health(org_id: str = Depends(get_org_id)):
    """MPTE Orchestrator health check — dynamically checks availability of sub-engines."""
    feeds_ok = _get_feeds() is not None
    attack_ok = _get_attack_engine() is not None
    autofix_ok = _get_autofix_engine() is not None
    return {
        "status": "healthy" if (feeds_ok or attack_ok) else "degraded",
        "service": "mpte-orchestrator",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mpte_url": os.environ.get("MPTE_BASE_URL", "https://localhost:8443"),
        "engines": {
            "feeds_service": "available" if feeds_ok else "unavailable",
            "attack_simulation": "available" if attack_ok else "unavailable",
            "autofix": "available" if autofix_ok else "unavailable",
        },
    }


@router.get("/status")
async def mpte_orchestrator_status(org_id: str = Depends(get_org_id)):
    """Status alias for MPTE orchestrator."""
    return await health()


@router.get("/capabilities")
async def get_capabilities(org_id: str = Depends(get_org_id)):
    """List MPTE Orchestrator capabilities — dynamically reflects loaded engines."""
    feeds = _get_feeds()
    attack = _get_attack_engine()
    autofix = _get_autofix_engine()

    # Check micro_pentest engine availability
    micro_pentest_available = False
    try:
        from core.micro_pentest import run_micro_pentest  # noqa: F401

        micro_pentest_available = True
    except ImportError:
        pass

    # Check ComplianceEngine availability
    compliance_available = False
    try:
        from core.services.enterprise.compliance_engine import compliance_engine as _ce

        compliance_available = _ce is not None
    except ImportError:
        pass

    # Detect configured AI providers from env
    ai_models = []
    if os.environ.get("OPENAI_API_KEY"):
        ai_models.append("GPT-4")
    if os.environ.get("ANTHROPIC_API_KEY"):
        ai_models.append("Claude")
    if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
        ai_models.append("Gemini")
    if not ai_models:
        ai_models = ["none_configured"]

    return {
        "version": "1.0.0",
        "capabilities": {
            "threat_intelligence": {
                "sources": ["NVD", "CISA KEV", "EPSS", "Exploit-DB", "MITRE ATT&CK"],
                "available": feeds is not None,
            },
            "ai_consensus": {
                "models": ai_models,
                "strategies": ["unanimous", "majority", "weighted"],
                "available": len(ai_models) > 0 and ai_models[0] != "none_configured",
            },
            "attack_simulation": {
                "types": [
                    "single_exploit",
                    "chained_exploit",
                    "privilege_escalation",
                    "lateral_movement",
                ],
                "available": attack is not None,
            },
            "business_impact": {
                "cost_models": [
                    "IBM_breach_report",
                    "regulatory_fines",
                    "reputation_damage",
                ],
                "frameworks": ["FAIR", "custom"],
                "available": feeds is not None,
            },
            "remediation": {
                "code_generation": True,
                "languages": ["python", "javascript", "java", "go", "rust"],
                "available": autofix is not None,
            },
            "compliance_mapping": {
                "frameworks": [
                    "SOC2",
                    "ISO27001",
                    "PCI_DSS",
                    "NIST_SSDF",
                    "HIPAA",
                    "GDPR",
                ],
                "available": compliance_available,
            },
            "micro_pentest": {
                "phases": 8,
                "real_http_checks": 19,
                "cve_verification_stages": 4,
                "multi_ai_consensus": True,
                "available": micro_pentest_available,
            },
            "enterprise": {
                "scan_modes": ["quick", "standard", "full", "stealth"],
                "audit_logging": True,
                "multi_tenant": True,
                "report_formats": ["pdf", "html", "json"],
                "available": True,
            },
        },
    }


@router.post("/threat-intel")
async def threat_intel(body: ThreatIntelRequest, org_id: str = Depends(get_org_id)):
    """Get threat intelligence for a CVE from real feed databases."""
    cve_id = body.cve_id.upper()
    feeds = _get_feeds()

    # NVD data
    nvd_data: Dict[str, Any] = {}
    if feeds:
        nvd_raw = feeds.get_nvd_cve(cve_id)
        if nvd_raw:
            nvd_data = {
                "severity": nvd_raw.get("severity", "unknown"),
                "cvss_v3": nvd_raw.get("cvss_score"),
                "description": nvd_raw.get("description", ""),
                "cwe_ids": nvd_raw.get("cwe_ids", []),
                "references": nvd_raw.get("references", [])[:5],
            }

    # KEV data
    kev_data: Dict[str, Any] = {"in_kev": False}
    if feeds:
        kev_entry = feeds.get_kev_entry(cve_id)
        if kev_entry:
            kev_data = {
                "in_kev": True,
                "date_added": kev_entry.date_added,
                "due_date": kev_entry.due_date,
                "vulnerability_name": kev_entry.vulnerability_name,
                "required_action": kev_entry.required_action,
                "ransomware_use": kev_entry.known_ransomware_campaign_use,
            }

    # EPSS data
    epss_data: Dict[str, Any] = {}
    if feeds:
        epss = feeds.get_epss_score(cve_id)
        if epss:
            epss_data = {
                "score": epss.epss,
                "percentile": round(epss.percentile * 100, 1),
            }

    # Exploit intelligence
    exploit_data: Dict[str, Any] = {"exploits_available": 0, "public_poc": False}
    if feeds:
        exploits = feeds.get_exploits_for_cve(cve_id)
        if exploits:
            exploit_data = {
                "exploits_available": len(exploits),
                "public_poc": any(getattr(e, "is_public", False) for e in exploits),
                "sources": list({getattr(e, "source", "unknown") for e in exploits}),
            }

    # Risk assessment
    cvss = nvd_data.get("cvss_v3") or 0
    epss_score = epss_data.get("score", 0)
    in_kev = kev_data.get("in_kev", False)
    if cvss >= 9.0 or (epss_score >= 0.7 and in_kev):
        risk = "critical"
    elif cvss >= 7.0 or epss_score >= 0.5:
        risk = "high"
    elif cvss >= 4.0:
        risk = "medium"
    else:
        risk = "low"

    recommendation = (
        "Immediate remediation required"
        if risk == "critical"
        else "Prioritize remediation"
        if risk == "high"
        else "Schedule remediation"
        if risk == "medium"
        else "Monitor and patch in next cycle"
    )

    return {
        "cve_id": cve_id,
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "data_source": "live_feeds" if feeds else "no_feed_data",
        "sources": {
            "nvd": nvd_data,
            "kev": kev_data,
            "epss": epss_data,
            "exploit_db": exploit_data,
        },
        "risk_assessment": {
            "overall_risk": risk,
            "exploitability": "high" if epss_score >= 0.5 or in_kev else "low",
            "impact": nvd_data.get("severity", "unknown"),
            "recommendation": recommendation,
        },
    }


@router.post("/business-impact")
async def business_impact(body: BusinessImpactRequest, org_id: str = Depends(get_org_id)):
    """Analyze business impact based on real CVE severity and exploit data."""
    feeds = _get_feeds()
    cve_ids = body.cve_ids or []

    # Gather real severity data for each CVE
    max_cvss = 0.0
    total_exploits = 0
    kev_count = 0
    severities: List[str] = []

    for cve_id in cve_ids:
        if feeds:
            nvd = feeds.get_nvd_cve(cve_id.upper())
            if nvd:
                score = nvd.get("cvss_score") or 0
                max_cvss = max(max_cvss, float(score))
                severities.append(nvd.get("severity", "unknown"))
            feeds.get_epss_score(cve_id.upper())  # warm cache
            kev = feeds.get_kev_entry(cve_id.upper())
            if kev:
                kev_count += 1
            exploits = feeds.get_exploits_for_cve(cve_id.upper())
            total_exploits += len(exploits) if exploits else 0

    # Calculate impact using FAIR-inspired model based on real data
    # Base cost scales with CVSS (IBM 2024 avg breach cost = $4.88M)
    base_cost = 4880000
    cvss_multiplier = max_cvss / 10.0 if max_cvss > 0 else 0.5
    kev_multiplier = 1.5 if kev_count > 0 else 1.0
    exploit_multiplier = 1.0 + (min(total_exploits, 10) * 0.1)
    estimated_breach_cost = int(
        base_cost * cvss_multiplier * kev_multiplier * exploit_multiplier
    )

    # Criticality from actual CVE scores
    if max_cvss >= 9.0 or kev_count > 0:
        criticality = "critical"
        priority = "P1"
        deadline = "24 hours"
    elif max_cvss >= 7.0:
        criticality = "high"
        priority = "P2"
        deadline = "72 hours"
    elif max_cvss >= 4.0:
        criticality = "medium"
        priority = "P3"
        deadline = "2 weeks"
    else:
        criticality = "low"
        priority = "P4"
        deadline = "next sprint"

    return {
        "analysis_id": f"bia-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "target": body.target or "unspecified",
        "cve_ids": cve_ids,
        "data_source": "live_feeds" if feeds else "no_feed_data",
        "impact_assessment": {
            "financial_impact": {
                "estimated_breach_cost": estimated_breach_cost,
                "model": "FAIR-inspired (IBM 2024 baseline)",
                "cvss_multiplier": round(cvss_multiplier, 2),
                "kev_multiplier": kev_multiplier,
                "exploit_multiplier": round(exploit_multiplier, 2),
            },
            "vulnerability_metrics": {
                "max_cvss": max_cvss,
                "cves_in_kev": kev_count,
                "known_exploits": total_exploits,
                "severity_distribution": severities,
            },
            "business_criticality": criticality,
        },
        "recommendation": {
            "priority": priority,
            "remediation_deadline": deadline,
            "mitigation_options": [
                "Apply vendor patches" if kev_count > 0 else "Evaluate vendor patches",
                "Enable WAF rules for known exploit patterns"
                if total_exploits > 0
                else "Review network controls",
                "Isolate affected services"
                if criticality == "critical"
                else "Monitor affected services",
            ],
        },
    }


@router.post("/simulate")
async def simulate_attack(body: SimulateRequest, org_id: str = Depends(get_org_id)):
    """Simulate attack chain using AttackSimulationEngine."""
    engine = _get_attack_engine()
    if not engine:
        raise HTTPException(503, detail="AttackSimulationEngine not available")

    try:
        # Create a scenario from the request
        scenario = engine.create_scenario(
            name=f"mpte-sim-{body.target}",
            description=f"{body.attack_type} simulation against {body.target}",
            target_assets=[body.target],
            initial_access_vector=body.attack_type,
        )

        # Run the campaign — skip per-step LLM enrichment for fast response
        # while keeping ALL real simulation logic (MITRE techniques, kill chain,
        # probabilistic execution, risk scoring, breach impact assessment)
        campaign = await engine.run_campaign(
            scenario.scenario_id,
            skip_llm_enrichment=True,
        )

        # Build response from real campaign results
        attack_chain = []
        for path in campaign.attack_paths or []:
            for step in getattr(path, "steps", []):
                attack_chain.append(
                    {
                        "step": len(attack_chain) + 1,
                        "technique": getattr(step, "technique_name", "unknown"),
                        "technique_id": getattr(step, "technique_id", ""),
                        "success": getattr(step, "success", False),
                        "impact_score": getattr(step, "impact_score", 0),
                    }
                )

        return {
            "simulation_id": campaign.campaign_id,
            "attack_type": body.attack_type,
            "target": body.target,
            "status": campaign.status.value
            if hasattr(campaign.status, "value")
            else str(campaign.status),
            "simulation_results": {
                "attack_chain": attack_chain
                or [{"step": 1, "technique": "Initial Access", "success": False}],
                "steps_executed": campaign.steps_executed,
                "steps_succeeded": campaign.steps_succeeded,
                "steps_failed": campaign.steps_failed,
                "risk_score": campaign.risk_score,
            },
            "mitre_coverage": campaign.mitre_coverage,
            "executive_summary": campaign.executive_summary,
            "recommendations": campaign.recommendations,
        }
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("mpte_orchestrator.simulate.error: %s", type(exc).__name__, exc_info=True)
        raise HTTPException(500, detail=f"Simulation failed: {type(exc).__name__}")


@router.post("/remediation")
async def remediation(body: RemediationRequest, org_id: str = Depends(get_org_id)):
    """Generate remediation guidance using AutoFixEngine and FeedsService."""
    cve_id = body.cve_id.upper()
    feeds = _get_feeds()
    autofix = _get_autofix_engine()

    # Get real CVE data for context
    nvd_data = feeds.get_nvd_cve(cve_id) if feeds else None
    kev_entry = feeds.get_kev_entry(cve_id) if feeds else None

    severity = (nvd_data or {}).get("severity", "unknown")
    description = (nvd_data or {}).get("description", "")
    affected_packages = (nvd_data or {}).get("affected_packages", [])

    # Build finding dict for autofix engine
    finding = {
        "id": cve_id,
        "title": (
            kev_entry.vulnerability_name if kev_entry else f"Vulnerability {cve_id}"
        ),
        "description": description,
        "severity": severity,
        "cve_ids": [cve_id],
        "cwe_id": ((nvd_data or {}).get("cwe_ids") or [""])[0] if nvd_data else "",
    }

    # Try to generate a real fix
    fix_result: Dict[str, Any] = {}
    if autofix:
        try:
            suggestion = await autofix.generate_fix(finding)
            fix_result = {
                "fix_id": suggestion.fix_id,
                "fix_type": suggestion.fix_type.value
                if hasattr(suggestion.fix_type, "value")
                else str(suggestion.fix_type),
                "confidence": suggestion.confidence,
                "code_patches": [
                    {
                        "file_path": p.file_path,
                        "old_code": p.old_code[:200] if p.old_code else "",
                        "new_code": p.new_code[:200] if p.new_code else "",
                        "explanation": p.explanation,
                    }
                    for p in (suggestion.code_patches or [])
                ],
                "dependency_fixes": [
                    {
                        "package": d.package_name,
                        "from": d.current_version,
                        "to": d.fixed_version,
                    }
                    for d in (suggestion.dependency_fixes or [])
                ],
            }
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning("mpte_orchestrator.autofix.error: %s", type(exc).__name__)
            fix_result = {"status": "autofix_unavailable", "error": type(exc).__name__}

    # Build smart remediation steps from real data
    steps = []
    if affected_packages:
        steps.append(
            f"Update affected packages: {', '.join(str(p) for p in affected_packages[:5])}"
        )
    if kev_entry:
        steps.append(f"CISA required action: {kev_entry.required_action}")
    steps.extend(
        [
            "Run security regression tests",
            "Deploy to staging and verify",
            "Deploy to production",
        ]
    )

    risk_if_not_fixed = severity if severity != "unknown" else "high"

    return {
        "cve_id": cve_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_source": "live_feeds" if feeds else "no_feed_data",
        "remediation": {
            "summary": description[:200]
            if description
            else "Apply vendor-recommended patch",
            "steps": steps,
            "autofix": fix_result,
        },
        "estimated_effort": "1-2 hours"
        if fix_result.get("code_patches")
        else "2-4 hours",
        "risk_if_not_fixed": risk_if_not_fixed,
    }


# ---------------------------------------------------------------------------
# Run / Status — backed by AttackSimulationEngine campaigns
# ---------------------------------------------------------------------------

_pentest_campaign_map: Dict[str, str] = {}  # test_id → campaign_id


@router.post("/run")
async def run_pentest(body: PentestRunRequest, org_id: str = Depends(get_org_id)):
    """Run an advanced penetration test using AttackSimulationEngine."""
    engine = _get_attack_engine()
    if not engine:
        raise HTTPException(503, detail="AttackSimulationEngine not available")

    test_id = f"apt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    try:
        scenario = engine.create_scenario(
            name=f"pentest-{test_id}",
            description=f"Advanced pentest against {body.target}",
            target_assets=[body.target],
            target_cves=body.cve_ids or [],
        )

        # Run campaign — skip per-step LLM enrichment for fast response
        # while keeping ALL real simulation logic
        campaign = await engine.run_campaign(
            scenario.scenario_id,
            skip_llm_enrichment=True,
        )

        _pentest_campaign_map[test_id] = campaign.campaign_id

        return {
            "test_id": test_id,
            "campaign_id": campaign.campaign_id,
            "status": campaign.status.value
            if hasattr(campaign.status, "value")
            else str(campaign.status),
            "started_at": campaign.started_at,
            "target": body.target,
            "cve_ids": body.cve_ids or [],
            "steps_executed": campaign.steps_executed,
            "message": f"Advanced pentest {test_id} completed. Use GET /api/v1/mpte-orchestrator/status/{test_id} for details.",
        }
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("mpte_orchestrator.run.error: %s", type(exc).__name__, exc_info=True)
        raise HTTPException(500, detail=f"Pentest run failed: {type(exc).__name__}")


@router.get("/status/{test_id}")
async def get_pentest_status(test_id: str, org_id: str = Depends(get_org_id)):
    """Get real status of an advanced penetration test from engine."""
    engine = _get_attack_engine()

    campaign_id = _pentest_campaign_map.get(test_id)
    if not campaign_id or not engine:
        return {
            "test_id": test_id,
            "status": "not_found",
            "message": "No campaign found for this test ID. It may have expired or the engine is unavailable.",
        }

    campaign = engine.get_campaign(campaign_id)
    if not campaign:
        return {
            "test_id": test_id,
            "status": "not_found",
            "message": "Campaign data no longer available.",
        }

    return {
        "test_id": test_id,
        "campaign_id": campaign_id,
        "status": campaign.status.value,
        "progress": 100 if campaign.status.value == "completed" else 50,
        "results": {
            "steps_executed": campaign.steps_executed,
            "steps_succeeded": campaign.steps_succeeded,
            "steps_failed": campaign.steps_failed,
            "risk_score": campaign.risk_score,
            "attack_paths": len(campaign.attack_paths),
        },
        "mitre_coverage": campaign.mitre_coverage,
        "executive_summary": campaign.executive_summary,
        "recommendations": campaign.recommendations,
    }
