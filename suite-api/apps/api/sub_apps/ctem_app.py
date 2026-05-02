"""CTEM — Continuous Threat Exposure Management router registrar.

Wave 3 extraction from app.py (2026-04-27).

All CTEM-classified include_router blocks that were scattered across
create_app() have been moved here.  Routes are registered directly on the
*parent* FastAPI app (registrar pattern) so ``len(app.routes)`` is unchanged
and the RISK-01 route-count gate continues to pass.

Loop-bound CTEM routers that live inside ``_extra_apps_routers`` / the
``predictions`` tuple-loop remain in app.py and are NOT moved here — that is a
future loop-refactor wave per docs/app_py_refactor_plan_2026-04-27.md.

Usage (from create_app in app.py)::

    from apps.api.sub_apps.ctem_app import register_ctem_routers
    register_ctem_routers(app, _verify_api_key, _require_scope, _logger)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

from fastapi import Depends

if TYPE_CHECKING:
    from fastapi import FastAPI

_log = logging.getLogger(__name__)


def register_ctem_routers(
    app: "FastAPI",
    _verify_api_key: Callable[..., Any],
    _require_scope: Callable[..., Any],
    _logger: logging.Logger | None = None,
) -> None:
    """Register all CTEM routers onto *app* in app.py source order.

    Parameters
    ----------
    app:
        The parent FastAPI application instance.
    _verify_api_key:
        The API-key dependency callable (closure from create_app).
    _require_scope:
        The scope-factory dependency callable (closure from create_app).
    _logger:
        Structlog/stdlib logger; falls back to module-level logger if None.
    """
    if _logger is None:
        _logger = _log

    # ------------------------------------------------------------------
    # CTEM pipeline + early threat-intel (formerly ~L3238-L3312 in app.py)
    # ------------------------------------------------------------------

    # CTEM 15-stage pipeline — ingest, batch processing, stage monitoring
    try:
        from apps.api.ctem_pipeline_router import router as ctem_pipeline_router
    except ImportError:
        ctem_pipeline_router = None  # type: ignore[assignment]
    if ctem_pipeline_router:
        app.include_router(
            ctem_pipeline_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted CTEM Pipeline router")

    # Threat Intel Correlation — threat actors and campaigns
    try:
        from apps.api.threat_intel_router import router as threat_intel_router
    except ImportError:
        threat_intel_router = None  # type: ignore[assignment]
    if threat_intel_router:
        app.include_router(
            threat_intel_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Threat Intel router")

    # Finding Correlation Engine — Exposure Cases, alert fatigue reduction
    try:
        from apps.api.correlation_router import router as correlation_router
    except ImportError:
        correlation_router = None  # type: ignore[assignment]
    if correlation_router:
        app.include_router(
            correlation_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Correlation Engine router")

    # SOAR Engine — automated playbook execution and security response
    try:
        from apps.api.soar_router import router as soar_router
    except ImportError:
        soar_router = None  # type: ignore[assignment]
    if soar_router:
        app.include_router(
            soar_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted SOAR Engine router")

    # Purple Team Exercise Engine
    try:
        from apps.api.purple_team_router import router as purple_team_router
    except ImportError:
        purple_team_router = None  # type: ignore[assignment]
    if purple_team_router:
        app.include_router(
            purple_team_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Purple Team router")

    # IR Playbook Engine — NIST 800-61
    try:
        from apps.api.ir_playbook_router import router as ir_playbook_router
    except ImportError:
        ir_playbook_router = None  # type: ignore[assignment]
    if ir_playbook_router:
        app.include_router(
            ir_playbook_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted IR Playbook Engine router")

    # IR Playbook Runner
    try:
        from apps.api.ir_playbook_runner_router import (
            router as ir_playbook_runner_router,
        )
    except ImportError:
        ir_playbook_runner_router = None  # type: ignore[assignment]
    if ir_playbook_runner_router:
        app.include_router(
            ir_playbook_runner_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted IR Playbook Runner router")

    # Anomaly Detection
    try:
        from apps.api.anomaly_router import router as anomaly_router
    except ImportError:
        anomaly_router = None  # type: ignore[assignment]
    if anomaly_router:
        app.include_router(
            anomaly_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Anomaly Detection router")

    # Anomaly ML Engine — behavioral analytics
    try:
        from apps.api.anomaly_ml_router import router as anomaly_ml_router
    except ImportError:
        anomaly_ml_router = None  # type: ignore[assignment]
    if anomaly_ml_router:
        app.include_router(
            anomaly_ml_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Anomaly ML Engine router")

    # ------------------------------------------------------------------
    # Inline try/except CTEM blocks (formerly ~L5857-L5881 in app.py)
    # ------------------------------------------------------------------

    # Threat Hunting — proactive threat detection with MITRE ATT&CK
    try:
        from apps.api.threat_hunter_router import router as threat_hunter_router
        app.include_router(threat_hunter_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Hunter router")
    except ImportError as _e:
        _logger.warning("Threat Hunter router not available: %s", _e)

    # Bug Bounty / VDP
    try:
        from apps.api.bug_bounty_router import router as bug_bounty_router
        app.include_router(bug_bounty_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Bug Bounty router")
    except ImportError as _e:
        _logger.warning("Bug Bounty router not available: %s", _e)

    # Breach Simulation Engine
    try:
        from apps.api.breach_simulation_router import router as _breach_sim_router
        app.include_router(_breach_sim_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Loaded Breach Simulation router")
    except ImportError as _e:
        _logger.warning("Breach Simulation router not available: %s", _e)

    # Phishing Simulation Engine
    try:
        from apps.api.phishing_router import router as _phishing_router
        app.include_router(_phishing_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Loaded Phishing Simulation router")
    except ImportError as _e:
        _logger.warning("Phishing Simulation router not available: %s", _e)

    # IoT/OT Security Scanner
    try:
        from apps.api.iot_security_router import router as iot_security_router
        app.include_router(iot_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted IoT/OT Security Scanner router at /api/v1/iot")
    except ImportError as _e:
        _logger.warning("IoT/OT Security Scanner router not available: %s", _e)

    # Attack Path Analysis — BFS-based lateral movement
    try:
        from apps.api.attack_path_router import router as attack_path_router
        app.include_router(
            attack_path_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Attack Path Analysis router at /api/v1/attack-paths")
    except ImportError as _e:
        _logger.warning("Attack Path router not available: %s", _e)

    # Insider Threat Detection
    try:
        from apps.api.insider_threat_router import router as insider_threat_router
        app.include_router(
            insider_threat_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Insider Threat router at /api/v1/insider-threat")
    except ImportError as _e:
        _logger.warning("Insider Threat router not available: %s", _e)

    # Digital Risk Protection
    try:
        from apps.api.drp_router import router as drp_router
        app.include_router(
            drp_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Digital Risk Protection router at /api/v1/drp")
    except ImportError as _e:
        _logger.warning("Digital Risk Protection router not available: %s", _e)

    # Deception Engine — canary tokens, honeypots
    try:
        from apps.api.deception_router import router as deception_router
        app.include_router(
            deception_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Deception Engine router at /api/v1/deception")
    except ImportError as _e:
        _logger.warning("Deception Engine router not available: %s", _e)

    # Composite Alerts (GAP-052)
    try:
        from apps.api.composite_alert_router import router as composite_alert_router
        app.include_router(
            composite_alert_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Composite Alert router at /api/v1/composite-alerts")
    except ImportError as _e:
        _logger.warning("Composite Alert router not available: %s", _e)

    # ------------------------------------------------------------------
    # Late-wired CTEM blocks (formerly ~L6270-L6760 in app.py)
    # ------------------------------------------------------------------

    # Endpoint Security / EDR
    try:
        from apps.api.endpoint_security_router import router as endpoint_security_router
        app.include_router(endpoint_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Endpoint Security (EDR) router at /api/v1/endpoint-security")
    except Exception as _e:
        _logger.warning("Endpoint Security router not loaded: %s", _e)

    # Email Security — DMARC/SPF/DKIM analysis, phishing detection
    try:
        from apps.api.email_security_router import router as email_security_router
        app.include_router(email_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Email Security router at /api/v1/email-security")
    except Exception as _e:
        _logger.warning("Email Security router not loaded: %s", _e)

    # Threat Correlation Engine
    try:
        from apps.api.threat_correlation_router import (
            router as threat_correlation_router,
        )
        app.include_router(threat_correlation_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Correlation router at /api/v1/threat-correlation")
    except Exception as _e:
        _logger.warning("Threat Correlation router not loaded: %s", _e)

    # Toxic-Combo (GAP-021) — Wiz-parity toxic-combination correlation
    try:
        from apps.api.toxic_combo_router import router as toxic_combo_router
        app.include_router(toxic_combo_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Toxic-Combo router at /api/v1/toxic-combo")
    except Exception as _e:
        _logger.warning("Toxic-Combo router not loaded: %s", _e)

    # UBA — User Behavior Analytics
    try:
        from apps.api.uba_router import router as uba_router
        app.include_router(uba_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted UBA router at /api/v1/uba")
    except Exception as _e:
        _logger.warning("UBA router not loaded: %s", _e)

    # Digital Forensics
    try:
        from apps.api.digital_forensics_router import router as digital_forensics_router
        app.include_router(digital_forensics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Digital Forensics router at /api/v1/digital-forensics")
    except Exception as _e:
        _logger.warning("Digital Forensics router not loaded: %s", _e)

    # Threat Feed Aggregator
    try:
        from apps.api.threat_feed_aggregator_router import (
            router as threat_feed_aggregator_router,
        )
        app.include_router(threat_feed_aggregator_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Feed Aggregator router at /api/v1/threat-feeds")
    except Exception as _e:
        _logger.warning("Threat Feed Aggregator router not loaded: %s", _e)

    # Asset Risk Calculator
    try:
        from apps.api.asset_risk_calculator_router import (
            router as asset_risk_calculator_router,
        )
        app.include_router(asset_risk_calculator_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Asset Risk Calculator router at /api/v1/asset-risk")
    except Exception as _e:
        _logger.warning("Asset Risk Calculator router not loaded: %s", _e)

    # XDR Correlation Engine
    try:
        from apps.api.xdr_router import router as xdr_router
        app.include_router(xdr_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted XDR Correlation Engine router at /api/v1/xdr")
    except Exception as _e:
        _logger.warning("XDR Correlation Engine router not loaded: %s", _e)

    # EDR Engine
    try:
        from apps.api.edr_router import router as edr_router
        app.include_router(edr_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted EDR Engine router at /api/v1/edr")
    except Exception as _e:
        _logger.warning("EDR Engine router not loaded: %s", _e)

    # EDR/XDR Connector — Falco + osquery + Wazuh
    try:
        from apps.api.edr_connector_router import router as edr_connector_router
        app.include_router(edr_connector_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted EDR/XDR Connector router at /api/v1/connectors/edr")
    except Exception as _e:
        _logger.warning("EDR/XDR Connector router not loaded: %s", _e)

    # CrowdStrike Falcon Connector
    try:
        from apps.api.crowdstrike_falcon_router import (
            router as crowdstrike_falcon_router,
        )
        app.include_router(crowdstrike_falcon_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted CrowdStrike Falcon Connector router at /api/v1/connectors/falcon")
    except Exception as _e:
        _logger.warning("CrowdStrike Falcon Connector router not loaded: %s", _e)

    # SentinelOne Connector
    try:
        from apps.api.sentinelone_connector_router import (
            router as sentinelone_connector_router,
        )
        app.include_router(sentinelone_connector_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted SentinelOne Connector router at /api/v1/connectors/sentinelone")
    except Exception as _e:
        _logger.warning("SentinelOne Connector router not loaded: %s", _e)

    # Pentest Management
    try:
        from apps.api.pentest_mgmt_router import router as pentest_mgmt_router
        app.include_router(pentest_mgmt_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Pentest Mgmt router at /api/v1/pentest-mgmt")
    except Exception as _e:
        _logger.warning("Pentest Mgmt router not loaded: %s", _e)

    # Threat Intel Sharing — STIX/TAXII-lite
    try:
        from apps.api.threat_intel_sharing_router import (
            router as threat_intel_sharing_router,
        )
        app.include_router(threat_intel_sharing_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Intel Sharing router at /api/v1/threat-sharing")
    except Exception as _e:
        _logger.warning("Threat Intel Sharing router not loaded: %s", _e)

    # Phishing Simulation
    try:
        from apps.api.phishing_simulation_router import (
            router as phishing_simulation_router,
        )
        app.include_router(phishing_simulation_router)
    except ImportError:
        pass

    # IoC Enrichment
    try:
        from apps.api.ioc_enrichment_router import router as ioc_enrichment_router
        app.include_router(ioc_enrichment_router)
    except ImportError:
        pass

    # CTEM core router
    try:
        from apps.api.ctem_router import router as ctem_router
        app.include_router(ctem_router)
    except ImportError:
        pass

    # Red Team Management
    try:
        from apps.api.red_team_mgmt_router import router as red_team_mgmt_router
        app.include_router(red_team_mgmt_router)
    except ImportError:
        pass

    # AI Security Advisor
    try:
        from apps.api.ai_security_advisor_router import (
            router as ai_security_advisor_router,
        )
        app.include_router(ai_security_advisor_router)
        _logger.info("Mounted AI Security Advisor router at /api/v1/ai-advisor")
    except ImportError:
        pass

    # Vuln Prioritization
    try:
        from apps.api.vuln_prioritization_router import (
            router as vuln_prioritization_router,
        )
        app.include_router(vuln_prioritization_router)
        _logger.info("Mounted Vuln Prioritization router at /api/v1/vuln-prioritization")
    except ImportError:
        pass

    # Asset Criticality
    try:
        from apps.api.asset_criticality_router import router as asset_criticality_router
        app.include_router(asset_criticality_router)
        _logger.info("Mounted Asset Criticality router at /api/v1/asset-criticality")
    except ImportError:
        pass

    # Blast Radius
    try:
        from apps.api.blast_radius_router import router as blast_radius_router
        app.include_router(blast_radius_router)
        _logger.info("Mounted Blast Radius router at /api/v1/blast-radius")
    except ImportError:
        pass

    # OpenClaw Pentest Swarm
    try:
        from apps.api.openclaw_router import router as openclaw_router
        app.include_router(openclaw_router)
        _logger.info("Mounted OpenClaw Pentest Swarm router at /api/v1/openclaw")
    except ImportError:
        pass

    # SOC Triage
    try:
        from apps.api.soc_triage_router import router as soc_triage_router
        app.include_router(soc_triage_router)
        _logger.info("Mounted SOC Triage router at /api/v1/soc-triage")
    except ImportError:
        pass

    # Attack Simulation
    try:
        from apps.api.attack_simulation_router import router as attack_simulation_router
        app.include_router(attack_simulation_router)
        _logger.info("Mounted Attack Simulation router at /api/v1/attack-sim")
    except ImportError:
        pass

    # Threat Intel Platform
    try:
        from apps.api.threat_intel_platform_router import router as tip_router
        app.include_router(tip_router)
        _logger.info("Mounted Threat Intel Platform router at /api/v1/tip")
    except ImportError:
        pass

    # Attack Surface Management
    try:
        from apps.api.attack_surface_mgmt_router import (
            router as attack_surface_mgmt_router,
        )
        app.include_router(attack_surface_mgmt_router)
        _logger.info("Mounted Attack Surface Management router at /api/v1/asm")
    except ImportError:
        pass

    # Vuln Intelligence
    try:
        from apps.api.vuln_intelligence_router import router as vuln_intelligence_router
        app.include_router(vuln_intelligence_router)
    except ImportError:
        pass

    # MITRE ATT&CK
    try:
        from apps.api.mitre_attack_router import router as mitre_attack_router
        app.include_router(mitre_attack_router)
        _logger.info("Mounted MITRE ATT&CK router at /api/v1/mitre-attack")
    except ImportError:
        pass

    # Attack Surface Engine (duplicate/alternate module)
    try:
        from apps.api.attack_surface_engine_router import (
            router as _attack_surface_engine_router,
        )
        app.include_router(_attack_surface_engine_router)
    except ImportError:
        pass

    # SIEM Integration
    try:
        from apps.api.siem_integration_router import router as siem_integration_router
        app.include_router(siem_integration_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted SIEM Integration router at /api/v1/siem")
    except ImportError:
        pass

    # SIEM Output Connectors
    try:
        from apps.api.siem_output_router import router as siem_output_router
        app.include_router(siem_output_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted SIEM Output router at /api/v1/siem-output")
    except ImportError:
        pass

    # SIEM universal multi-format ingest connector
    try:
        from apps.api.siem_connector_router import router as siem_connector_router
        app.include_router(siem_connector_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted SIEM Connector router at /api/v1/connectors/siem")
    except ImportError:
        pass

    # Passive DNS
    try:
        from apps.api.passive_dns_router import router as passive_dns_router
        app.include_router(passive_dns_router)
        _logger.info("Mounted Passive DNS router at /api/v1/passive-dns")
    except ImportError:
        pass

    # Threat Geolocation
    try:
        from apps.api.threat_geolocation_router import (
            router as threat_geolocation_router,
        )
        app.include_router(threat_geolocation_router)
        _logger.info("Mounted Threat Geolocation router at /api/v1/threat-geolocation")
    except ImportError:
        pass

    # IP Reputation
    try:
        from apps.api.ip_reputation_router import router as _ip_reputation_late
        app.include_router(_ip_reputation_late)
        _logger.info("Mounted IP Reputation router at /api/v1/ip-reputation")
    except ImportError:
        pass

    # Incident Orchestration
    try:
        from apps.api.incident_orchestration_router import (
            router as incident_orchestration_router,
        )
        app.include_router(incident_orchestration_router)
        _logger.info("Mounted Incident Orchestration router at /api/v1/incident-orchestration")
    except ImportError:
        pass

    # DDoS Protection
    try:
        from apps.api.ddos_protection_router import router as ddos_protection_router
        app.include_router(ddos_protection_router)
        _logger.info("Mounted DDoS Protection router at /api/v1/ddos-protection")
    except ImportError:
        pass

    # Security Event Correlation
    try:
        from apps.api.security_event_correlation_router import (
            router as security_event_correlation_router,
        )
        app.include_router(security_event_correlation_router)
        _logger.info("Mounted Security Event Correlation router at /api/v1/event-correlation")
    except ImportError:
        pass

    # Threat Intel Fusion
    try:
        from apps.api.threat_intel_fusion_router import (
            router as threat_intel_fusion_router,
        )
        app.include_router(threat_intel_fusion_router)
        _logger.info("Mounted Threat Intel Fusion router at /api/v1/threat-intel-fusion")
    except ImportError:
        pass

    # OT Security
    try:
        from apps.api.ot_security_router import router as ot_security_router
        app.include_router(ot_security_router)
        _logger.info("Mounted OT Security router at /api/v1/ot-security")
    except ImportError:
        pass

    # Email Filtering
    try:
        from apps.api.email_filtering_router import router as email_filtering_router
        app.include_router(email_filtering_router)
        _logger.info("Mounted Email Filtering router at /api/v1/email-filtering")
    except ImportError:
        pass

    # Anti-Phishing
    try:
        from apps.api.anti_phishing_router import router as anti_phishing_router
        app.include_router(anti_phishing_router)
        _logger.info("Mounted Anti-Phishing router at /api/v1/anti-phishing")
    except ImportError:
        pass

    # SOC Workflow
    try:
        from apps.api.soc_workflow_router import router as soc_workflow_router
        app.include_router(soc_workflow_router)
        _logger.info("Mounted SOC Workflow router at /api/v1/soc-workflow")
    except ImportError:
        pass

    # Incident Triage
    try:
        from apps.api.incident_triage_router import router as incident_triage_router
        app.include_router(incident_triage_router)
        _logger.info("Mounted Incident Triage router at /api/v1/incident-triage")
    except ImportError:
        pass

    # Threat Simulation
    try:
        from apps.api.threat_simulation_router import router as threat_simulation_router
        app.include_router(threat_simulation_router)
        _logger.info("Mounted Threat Simulation router at /api/v1/threat-simulation")
    except ImportError:
        pass

    # Breach Detection
    try:
        from apps.api.breach_detection_router import router as breach_detection_router
        app.include_router(breach_detection_router)
        _logger.info("Mounted Breach Detection router at /api/v1/breach-detection")
    except ImportError:
        pass

    # Forensics Readiness
    try:
        from apps.api.forensics_readiness_router import (
            router as forensics_readiness_router,
        )
        app.include_router(forensics_readiness_router)
        _logger.info("Mounted Forensics Readiness router at /api/v1/forensics-readiness")
    except ImportError:
        pass

    # Supply Chain Attack Detection
    try:
        from apps.api.supply_chain_attack_detection_router import (
            router as supply_chain_attack_detection_router,
        )
        app.include_router(supply_chain_attack_detection_router)
        _logger.info("Mounted Supply Chain Attack Detection router at /api/v1/supply-chain-attacks")
    except ImportError:
        pass

    # Threat Score
    try:
        from apps.api.threat_score_router import router as threat_score_router
        app.include_router(threat_score_router)
        _logger.info("Mounted Threat Score router at /api/v1/threat-scores")
    except ImportError:
        pass

    # Attack Chain
    try:
        from apps.api.attack_chain_router import router as attack_chain_router
        app.include_router(attack_chain_router)
        _logger.info("Mounted Attack Chain router at /api/v1/attack-chains")
    except ImportError:
        pass

    # Threat Exposure
    try:
        from apps.api.threat_exposure_router import router as threat_exposure_router
        app.include_router(threat_exposure_router)
        _logger.info("Mounted Threat Exposure router at /api/v1/threat-exposure")
    except ImportError:
        pass

    # Dark Web Monitoring
    try:
        from apps.api.dark_web_monitoring_router import (
            router as dark_web_monitoring_router,
        )
        app.include_router(dark_web_monitoring_router)
        _logger.info("Mounted Dark Web Monitoring router at /api/v1/dark-web")
    except ImportError:
        pass

    # Security Chaos Engineering
    try:
        from apps.api.security_chaos_router import router as security_chaos_router
        app.include_router(security_chaos_router)
        _logger.info("Mounted Security Chaos router at /api/v1/security-chaos")
    except ImportError:
        pass

    # Zero Day Intelligence
    try:
        from apps.api.zero_day_intelligence_router import (
            router as zero_day_intelligence_router,
        )
        app.include_router(zero_day_intelligence_router)
        _logger.info("Mounted Zero Day Intelligence router at /api/v1/zero-day")
    except ImportError:
        pass

    # AI-Powered SOC
    try:
        from apps.api.ai_powered_soc_router import router as ai_powered_soc_router
        app.include_router(ai_powered_soc_router)
        _logger.info("Mounted AI-Powered SOC router at /api/v1/ai-soc")
    except ImportError:
        pass

    # Deception Analytics
    try:
        from apps.api.deception_analytics_router import (
            router as deception_analytics_router,
        )
        app.include_router(deception_analytics_router)
        _logger.info("Mounted Deception Analytics router at /api/v1/deception-analytics")
    except ImportError:
        pass

    # Threat Intelligence Automation (Wave 23)
    try:
        from apps.api.threat_intelligence_automation_router import (
            router as threat_intelligence_automation_router,
        )
        app.include_router(threat_intelligence_automation_router)
        _logger.info("Mounted Threat Intelligence Automation router at /api/v1/ti-automation")
    except ImportError:
        pass

    # Endpoint Threat Hunting
    try:
        from apps.api.endpoint_threat_hunting_router import (
            router as endpoint_threat_hunting_router,
        )
        app.include_router(endpoint_threat_hunting_router)
        _logger.info("Mounted Endpoint Threat Hunting router at /api/v1/endpoint-hunting")
    except ImportError:
        pass

    # Operational Technology Security
    try:
        from apps.api.operational_technology_security_router import (
            router as operational_technology_security_router,
        )
        app.include_router(operational_technology_security_router)
        _logger.info("Mounted Operational Technology Security router at /api/v1/ot-sec")
    except ImportError:
        pass

    # Network Forensics (Wave 24)
    try:
        from apps.api.network_forensics_router import router as network_forensics_router
        app.include_router(network_forensics_router)
        _logger.info("Mounted Network Forensics router at /api/v1/network-forensics")
    except ImportError:
        pass

    # Malware Analysis (Wave 24)
    try:
        from apps.api.malware_analysis_router import router as malware_analysis_router
        app.include_router(malware_analysis_router)
        _logger.info("Mounted Malware Analysis router at /api/v1/malware-analysis")
    except ImportError:
        pass

    # Vulnerability Prioritization (extended, Wave 24)
    try:
        from apps.api.vulnerability_prioritization_router import (
            router as vulnerability_prioritization_router,
        )
        app.include_router(vulnerability_prioritization_router)
        _logger.info("Mounted Vulnerability Prioritization router at /api/v1/vuln-prioritization")
    except ImportError:
        pass

    # Threat Deception Management (Wave 25)
    try:
        from apps.api.threat_deception_management_router import (
            router as threat_deception_management_router,
        )
        app.include_router(threat_deception_management_router)
        _logger.info("Mounted Threat Deception Management router at /api/v1/threat-deception")
    except ImportError:
        pass

    # Threat Attribution (Wave 26)
    try:
        from apps.api.threat_attribution_router import (
            router as threat_attribution_router,
        )
        app.include_router(threat_attribution_router)
        _logger.info("Mounted Threat Attribution router at /api/v1/threat-attribution")
    except ImportError:
        pass

    # Alert Triage (Wave 27)
    try:
        from apps.api.alert_triage_router import router as alert_triage_router
        app.include_router(alert_triage_router)
        _logger.info("Mounted Alert Triage router at /api/v1/alert-triage")
    except ImportError:
        pass

    # Cyber Threat Intelligence (Wave 27)
    try:
        from apps.api.cyber_threat_intelligence_router import (
            router as cyber_threat_intelligence_router,
        )
        app.include_router(cyber_threat_intelligence_router)
        _logger.info("Mounted Cyber Threat Intelligence router at /api/v1/cyber-threat-intel")
    except ImportError:
        pass

    # Digital Twin Security (Wave 27)
    try:
        from apps.api.digital_twin_security_router import (
            router as digital_twin_security_router,
        )
        app.include_router(digital_twin_security_router)
        _logger.info("Mounted Digital Twin Security router at /api/v1/digital-twin")
    except ImportError:
        pass

    # Threat Vector Analysis
    try:
        from apps.api.threat_vector_analysis_router import (
            router as threat_vector_analysis_router,
        )
        app.include_router(threat_vector_analysis_router)
        _logger.info("Mounted Threat Vector Analysis router at /api/v1/threat-vectors")
    except ImportError:
        pass

    # Threat Brief (Wave 30)
    try:
        from apps.api.threat_brief_router import router as threat_brief_router
        app.include_router(threat_brief_router)
        _logger.info("Mounted Threat Brief router at /api/v1/threat-briefs")
    except ImportError:
        pass

    # Threat Intel Enrichment (Wave 31)
    try:
        from apps.api.threat_intel_enrichment_router import (
            router as threat_intel_enrichment_router,
        )
        app.include_router(threat_intel_enrichment_router)
        _logger.info("Mounted Threat Intel Enrichment router at /api/v1/intel-enrichment")
    except ImportError:
        pass

    # Threat Landscape (Wave 32)
    try:
        from apps.api.threat_landscape_router import router as threat_landscape_router
        app.include_router(threat_landscape_router)
        _logger.info("Mounted Threat Landscape router at /api/v1/threat-landscape")
    except ImportError:
        pass

    # Network Threat (Wave 32)
    try:
        from apps.api.network_threat_router import router as network_threat_router
        app.include_router(network_threat_router)
        _logger.info("Mounted Network Threat router at /api/v1/network-threats")
    except ImportError:
        pass

    # Incident KB (Wave 32)
    try:
        from apps.api.incident_kb_router import router as incident_kb_router
        app.include_router(incident_kb_router)
        _logger.info("Mounted Incident KB router at /api/v1/incident-kb")
    except ImportError:
        pass

    # Threat Feed Subscription (Wave 33)
    try:
        from apps.api.threat_feed_subscription_router import (
            router as threat_feed_subscription_router,
        )
        app.include_router(threat_feed_subscription_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Feed Subscription router at /api/v1/feed-subscriptions")
    except ImportError:
        pass

    # Threat Actor Tracking (Wave 34)
    try:
        from apps.api.threat_actor_tracking_router import (
            router as threat_actor_tracking_router,
        )
        app.include_router(threat_actor_tracking_router)
        _logger.info("Mounted Threat Actor Tracking router at /api/v1/actor-tracking")
    except ImportError:
        pass

    # Vulnerability Scoring (Wave 34)
    try:
        from apps.api.vulnerability_scoring_router import (
            router as vulnerability_scoring_router,
        )
        app.include_router(vulnerability_scoring_router)
        _logger.info("Mounted Vulnerability Scoring router at /api/v1/vuln-scoring")
    except ImportError:
        pass

    # Cyber Resilience (Wave 35)
    try:
        from apps.api.cyber_resilience_router import router as cyber_resilience_router
        app.include_router(cyber_resilience_router)
        _logger.info("Mounted Cyber Resilience router at /api/v1/cyber-resilience")
    except ImportError:
        pass

    # Threat Modeling Pipeline (Wave 35)
    try:
        from apps.api.threat_modeling_pipeline_router import (
            router as threat_modeling_pipeline_router,
        )
        app.include_router(threat_modeling_pipeline_router)
        _logger.info("Mounted Threat Modeling Pipeline router at /api/v1/threat-modeling-pipeline")
    except ImportError:
        pass

    # Cloud Incident Response (Wave 40)
    try:
        from apps.api.cloud_incident_response_router import (
            router as cloud_incident_response_router,
        )
        app.include_router(cloud_incident_response_router)
        _logger.info("Mounted Cloud Incident Response router at /api/v1/cloud-ir")
    except ImportError:
        pass

    # Threat Indicator (Wave 41)
    try:
        from apps.api.threat_indicator_router import router as threat_indicator_router
        app.include_router(threat_indicator_router)
        _logger.info("Mounted Threat Indicator router at /api/v1/threat-indicators")
    except ImportError:
        pass

    # Ransomware Protection (Wave 41)
    try:
        from apps.api.ransomware_protection_router import (
            router as ransomware_protection_router,
        )
        app.include_router(ransomware_protection_router)
        _logger.info("Mounted Ransomware Protection router at /api/v1/ransomware-protection")
    except ImportError:
        pass

    # Choke Point Analyzer (GAP-026)
    try:
        from apps.api.choke_point_router import router as choke_point_router
        app.include_router(choke_point_router)
        _logger.info("Mounted Choke Point router at /api/v1/choke-point")
    except ImportError as _cp_err:
        _logger.warning("Choke Point router not available: %s", _cp_err)

    # CTEM Engine router (Wave 42+)
    try:
        from apps.api.ctem_engine_router import router as ctem_engine_router
        app.include_router(ctem_engine_router)
        _logger.info("Mounted CTEM Engine router at /api/v1/ctem")
    except ImportError:
        pass

    # Threat Intelligence Confidence
    try:
        from apps.api.threat_intelligence_confidence_router import (
            router as threat_intelligence_confidence_router,
        )
        app.include_router(threat_intelligence_confidence_router)
        _logger.info("Mounted Threat Intelligence Confidence router at /api/v1/ti-confidence")
    except ImportError:
        pass

    # Network Anomaly (Wave 38)
    try:
        from apps.api.network_anomaly_router import router as network_anomaly_router
        app.include_router(network_anomaly_router)
        _logger.info("Mounted Network Anomaly router at /api/v1/network-anomaly")
    except ImportError:
        pass

    # Hunting Automation (Wave 38)
    try:
        from apps.api.hunting_automation_router import (
            router as hunting_automation_router,
        )
        app.include_router(hunting_automation_router)
        _logger.info("Mounted Hunting Automation router at /api/v1/hunting-automation")
    except ImportError:
        pass

    # Alert Enrichment
    try:
        from apps.api.alert_enrichment_router import router as alert_enrichment_router
        app.include_router(alert_enrichment_router)
        _logger.info("Mounted Alert Enrichment router at /api/v1/alert-enrichment")
    except ImportError:
        pass

    # Threat Response
    try:
        from apps.api.threat_response_router import router as threat_response_router
        app.include_router(threat_response_router)
        _logger.info("Mounted Threat Response router at /api/v1/threat-response")
    except ImportError:
        pass

    # Cyber Threat Modeling (Wave 39)
    try:
        from apps.api.cyber_threat_modeling_router import (
            router as cyber_threat_modeling_router,
        )
        app.include_router(cyber_threat_modeling_router)
        _logger.info("Mounted Cyber Threat Modeling router at /api/v1/cyber-threat-models")
    except ImportError:
        pass

    # Security Event Timeline (Wave 39)
    try:
        from apps.api.security_event_timeline_router import (
            router as security_event_timeline_router,
        )
        app.include_router(security_event_timeline_router)
        _logger.info("Mounted Security Event Timeline router at /api/v1/event-timeline")
    except ImportError:
        pass

    # Vuln Intel Fusion (Wave 39)
    try:
        from apps.api.vuln_intel_fusion_router import router as vuln_intel_fusion_router
        app.include_router(vuln_intel_fusion_router)
        _logger.info("Mounted Vuln Intel Fusion router at /api/v1/vuln-intel-fusion")
    except ImportError:
        pass

    # Threat Hunting Playbook (Wave 40)
    try:
        from apps.api.threat_hunting_playbook_router import (
            router as threat_hunting_playbook_router,
        )
        app.include_router(threat_hunting_playbook_router)
        _logger.info("Mounted Threat Hunting Playbook router at /api/v1/hunting-playbooks")
    except ImportError:
        pass

    # Incident Comms (Wave 30)
    try:
        from apps.api.incident_comms_router import router as incident_comms_router
        app.include_router(incident_comms_router)
        _logger.info("Mounted Incident Comms router at /api/v1/incident-comms")
    except ImportError:
        pass

    # Vulnerability Age (Wave 36)
    try:
        from apps.api.vulnerability_age_router import router as vulnerability_age_router
        app.include_router(vulnerability_age_router)
        _logger.info("Mounted Vulnerability Age router at /api/v1/vuln-age")
    except ImportError:
        pass

    # Vuln Enricher
    try:
        from apps.api.vuln_enricher_router import router as vuln_enricher_router
        app.include_router(vuln_enricher_router)
        _logger.info("Mounted Vulnerability Enricher router at /api/v1/vuln")
    except ImportError:
        pass

    # Vuln Prioritizer
    try:
        from apps.api.vuln_prioritizer_router import router as vuln_prioritizer_router
        app.include_router(vuln_prioritizer_router)
        _logger.info("Mounted Vulnerability Prioritizer router at /api/v1/vulns")
    except ImportError:
        pass

    # Red Team
    try:
        from apps.api.red_team_router import router as red_team_router
        app.include_router(red_team_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Red Team router at /api/v1/red-team")
    except ImportError:
        pass

    # Threat Model (standalone)
    try:
        from apps.api.threat_model_router import router as threat_model_router
        app.include_router(threat_model_router)
        _logger.info("Mounted Threat Model router at /api/v1/threat-models")
    except ImportError:
        pass

    # Offline Feed Router (GAP-002, air-gapped threat-intel)
    try:
        from apps.api.offline_feed_router import router as offline_feed_router
        app.include_router(offline_feed_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Offline Feed router at /api/v1/offline-feed")
    except ImportError:
        pass

    # Stage Matrix Router (GAP-004, CTEM stage-aware policy enforcement)
    try:
        from apps.api.stage_matrix_router import router as stage_matrix_router
        app.include_router(stage_matrix_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Stage Matrix router at /api/v1/stage-matrix")
    except ImportError:
        pass

    # Threat Correlation (duplicate late-binding)
    try:
        from apps.api.threat_correlation_router import (
            router as _threat_correlation_late,
        )
        app.include_router(_threat_correlation_late)
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # Wave-6 — loop-bound CTEM entries (formerly in _core_routers /
    # _attack_extra_routers / _extra_apps_routers loops in app.py)
    # ------------------------------------------------------------------

    # _core_routers CTEM entries

    # Causal Inference — root cause analysis (suite-core/api/)
    try:
        from api.causal_router import router as causal_router  # noqa: PLC0415
        app.include_router(causal_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Causal Inference router (wave-6)")
    except ImportError:
        pass

    # GNN Attack Paths — graph neural network attack prediction (suite-core/api/)
    try:
        from api.gnn_router import router as gnn_router  # noqa: PLC0415
        app.include_router(gnn_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))])
        _logger.info("Mounted GNN Attack Path router (wave-6)")
    except ImportError:
        pass

    # Monte Carlo Risk Simulation — FAIR stochastic modeling (suite-core/api/)
    try:
        from api.monte_carlo_router import router as monte_carlo_router  # noqa: PLC0415
        app.include_router(monte_carlo_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Monte Carlo Risk Simulation router (wave-6)")
    except ImportError:
        pass

    # Runtime Protection — in-app firewall / RASP (suite-core/api/)
    try:
        from api.runtime_router import router as runtime_router  # noqa: PLC0415
        app.include_router(runtime_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Runtime Protection router (wave-6)")
    except ImportError:
        pass

    # Threat Modeling — STRIDE-based AI threat modeling (suite-core/api/)
    try:
        from api.threat_modeling_router import (
            router as threat_modeling_router,  # noqa: PLC0415
        )
        app.include_router(threat_modeling_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Threat Modeling router (wave-6)")
    except ImportError:
        pass

    # AI Code Guardian — AI-generated code security (suite-core/api/)
    try:
        from api.ai_code_guardian_router import (
            router as ai_code_guardian_router,  # noqa: PLC0415
        )
        app.include_router(ai_code_guardian_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted AI Code Guardian router (wave-6)")
    except ImportError:
        pass

    # Attack Surface Discovery — external asset monitoring (suite-core/api/)
    try:
        from api.attack_surface_router import (
            router as attack_surface_router,  # noqa: PLC0415
        )
        app.include_router(attack_surface_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Attack Surface Discovery router (wave-6)")
    except ImportError:
        pass

    # Attack Surface Manager — full ASM engine (apps/api/)
    try:
        from apps.api.attack_surface_manager_router import (
            router as attack_surface_manager_router,  # noqa: PLC0415
        )
        app.include_router(attack_surface_manager_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Attack Surface Manager router (wave-6)")
    except ImportError:
        pass

    # Attack Surface Monitor — continuous monitoring (apps/api/)
    try:
        from apps.api.attack_surface_monitor_router import (
            router as attack_surface_monitor_router,  # noqa: PLC0415
        )
        app.include_router(attack_surface_monitor_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Attack Surface Monitor router (wave-6)")
    except ImportError:
        pass

    # _attack_extra_routers (all attack:execute scope) — formerly loop-bound

    # Attack Simulation (suite-attack/api/)
    try:
        from api.attack_sim_router import router as attack_sim_router  # noqa: PLC0415
        app.include_router(attack_sim_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Attack Simulation router (wave-6)")
    except ImportError:
        pass

    # SAST (suite-attack/api/)
    try:
        from api.sast_router import router as sast_router  # noqa: PLC0415
        app.include_router(sast_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted SAST router (wave-6)")
    except ImportError:
        pass

    # Container Security Scanner (suite-attack/api/)
    try:
        from api.container_router import router as container_router  # noqa: PLC0415
        app.include_router(container_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Container Security router (wave-6)")
    except ImportError:
        pass

    # DAST (suite-attack/api/)
    try:
        from api.dast_router import router as dast_router  # noqa: PLC0415
        app.include_router(dast_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted DAST router (wave-6)")
    except ImportError:
        pass

    # DAST Pentest OSS (ZAP+Nuclei) (apps/api/)
    try:
        from apps.api.dast_pentest_router import (
            router as dast_pentest_router,  # noqa: PLC0415
        )
        app.include_router(dast_pentest_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted DAST/Pentest OSS router (wave-6)")
    except ImportError:
        pass

    # CSPM attack-path scanner (suite-attack/api/)
    try:
        from api.cspm_router import router as cspm_attack_router  # noqa: PLC0415
        app.include_router(cspm_attack_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted CSPM (attack) router (wave-6)")
    except ImportError:
        pass

    # API Fuzzer (suite-attack/api/)
    try:
        from api.api_fuzzer_router import router as api_fuzzer_router  # noqa: PLC0415
        app.include_router(api_fuzzer_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted API Fuzzer router (wave-6)")
    except ImportError:
        pass

    # Malware Analysis (suite-attack/api/)
    try:
        from api.malware_router import router as malware_router  # noqa: PLC0415
        app.include_router(malware_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Malware Analysis router (wave-6)")
    except ImportError:
        pass

    # Suite-Attack MPTE suite (attack:execute scope) — formerly inline loop
    try:
        from api.mpte_router import router as mpte_router  # noqa: PLC0415
        app.include_router(mpte_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted MPTE router (wave-6)")
    except ImportError:
        pass

    try:
        from api.micro_pentest_router import (
            router as micro_pentest_router,  # noqa: PLC0415
        )
        app.include_router(micro_pentest_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Micro Pentest router (wave-6)")
    except ImportError:
        pass

    try:
        from api.vuln_discovery_router import (
            router as vuln_discovery_router,  # noqa: PLC0415
        )
        app.include_router(vuln_discovery_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Vulnerability Discovery router (wave-6)")
    except ImportError:
        pass

    try:
        from api.mpte_orchestrator_router import (
            router as mpte_orchestrator_router,  # noqa: PLC0415
        )
        app.include_router(mpte_orchestrator_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted MPTE Orchestrator router (wave-6)")
    except ImportError:
        pass

    try:
        from api.secrets_router import router as secrets_router  # noqa: PLC0415
        app.include_router(secrets_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Secrets Scanner router (wave-6)")
    except ImportError:
        pass

    # _extra_apps_routers CTEM entries

    # Intelligent Security Engine (apps/api/)
    try:
        from apps.api.intelligent_security_router import (
            router as intelligent_security_router,  # noqa: PLC0415
        )
        app.include_router(intelligent_security_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Intelligent Security Engine router (wave-6)")
    except ImportError:
        pass

    # MITRE ATT&CK Coverage (apps/api/)
    try:
        from apps.api.mitre_attack_coverage_router import (
            router as mitre_attack_coverage_router,  # noqa: PLC0415
        )
        app.include_router(mitre_attack_coverage_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted MITRE ATT&CK Coverage router (wave-6)")
    except ImportError:
        pass

    # Pentest management (apps/api/)
    try:
        from apps.api.pentest_router import router as pentest_router  # noqa: PLC0415
        app.include_router(pentest_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Pentest router (wave-6)")
    except ImportError:
        pass

    # Auto Pentest (apps/api/)
    try:
        from apps.api.auto_pentest_router import (
            router as auto_pentest_router,  # noqa: PLC0415
        )
        app.include_router(auto_pentest_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Auto Pentest router (wave-6)")
    except ImportError:
        pass

    # SOC Automation (apps/api/)
    try:
        from apps.api.soc_automation_router import (
            router as soc_automation_router,  # noqa: PLC0415
        )
        app.include_router(soc_automation_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted SOC Automation router (wave-6)")
    except ImportError:
        pass

    # Breach Response (apps/api/)
    try:
        from apps.api.breach_response_router import (
            router as breach_response_router,  # noqa: PLC0415
        )
        app.include_router(breach_response_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Breach Response router (wave-6)")
    except ImportError:
        pass

    # Incident Response (apps/api/)
    try:
        from apps.api.incident_response_router import (
            router as incident_response_router,  # noqa: PLC0415
        )
        app.include_router(incident_response_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Incident Response router (wave-6)")
    except ImportError:
        pass

    # Threat Hunting (apps/api/)
    try:
        from apps.api.threat_hunting_router import (
            router as threat_hunting_router,  # noqa: PLC0415
        )
        app.include_router(threat_hunting_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Threat Hunting router (wave-6)")
    except ImportError:
        pass

    # IP Reputation (apps/api/)
    try:
        from apps.api.ip_reputation_router import (
            router as ip_reputation_router,  # noqa: PLC0415
        )
        app.include_router(ip_reputation_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:feeds"))])
        _logger.info("Mounted IP Reputation router (wave-6)")
    except ImportError:
        pass

    # Security Knowledge Base (apps/api/)
    try:
        from apps.api.security_kb_router import (
            router as security_kb_router,  # noqa: PLC0415
        )
        app.include_router(security_kb_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Security KB router (wave-6)")
    except ImportError:
        pass

    _logger.info("CTEM sub-app: all routers registered")
