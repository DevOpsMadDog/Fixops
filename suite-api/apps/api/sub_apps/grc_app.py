"""GRC — Governance, Risk, and Compliance router registrar.

Wave 4 extraction from app.py (2026-04-27).

All GRC-classified include_router blocks that were scattered across
create_app() have been moved here.  Routes are registered directly on the
*parent* FastAPI app (registrar pattern) so ``len(app.routes)`` is unchanged
and the RISK-01 route-count gate continues to pass.

Loop-bound GRC routers that live inside ``_extra_apps_routers`` or the
evidence-risk loop remain in app.py and are NOT moved here — that is a
future loop-refactor wave per docs/app_py_refactor_plan_2026-04-27.md.

Usage (from create_app in app.py)::

    from apps.api.sub_apps.grc_app import register_grc_routers
    register_grc_routers(app, _verify_api_key, _require_scope, _logger)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

from fastapi import Depends

if TYPE_CHECKING:
    from fastapi import FastAPI

_log = logging.getLogger(__name__)


def register_grc_routers(
    app: "FastAPI",
    _verify_api_key: Callable[..., Any],
    _require_scope: Callable[..., Any],
    _logger: logging.Logger | None = None,
) -> None:
    """Register all GRC routers onto *app* in app.py source order.

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
    # Early GRC registrations — module-level Optional[APIRouter] pattern
    # (formerly scattered across ~L3179-L3309 in app.py)
    # ------------------------------------------------------------------

    # Playbook automation router for orchestrated remediation
    try:
        from apps.api.playbook_routes import router as playbook_router
    except ImportError:
        playbook_router = None  # type: ignore[assignment]
    if playbook_router:
        app.include_router(
            playbook_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Playbook automation router")

    # Risk Register — enterprise risk lifecycle (CRUD, scoring, KRI, heat map, board report)
    try:
        from apps.api.risk_register_router import router as risk_register_router
    except ImportError:
        risk_register_router = None  # type: ignore[assignment]
    if risk_register_router:
        app.include_router(
            risk_register_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Risk Register router")

    # IR Playbook Engine — NIST 800-61 incident response, evidence chain, regulatory notifications
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

    # IR Playbook Runner — 5 built-in playbooks, real actions
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

    # Security Policy Document Generator
    try:
        from apps.api.policy_generator_router import router as policy_generator_router
    except ImportError:
        policy_generator_router = None  # type: ignore[assignment]
    if policy_generator_router:
        app.include_router(
            policy_generator_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Policy Generator router")

    # Compliance Reports — multi-framework reporting
    try:
        from apps.api.compliance_reports_router import (
            router as compliance_reports_router,
        )
    except ImportError:
        compliance_reports_router = None  # type: ignore[assignment]
    if compliance_reports_router:
        app.include_router(
            compliance_reports_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Compliance Reports router")

    # Evidence Chain router — tamper-proof cryptographic audit trail (early mount)
    try:
        from apps.api.evidence_chain_router import router as evidence_chain_router
    except ImportError:
        evidence_chain_router = None  # type: ignore[assignment]
    if evidence_chain_router:
        app.include_router(
            evidence_chain_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))],
        )
        _logger.info("Mounted Evidence Chain router")

    # Compliance Planner
    try:
        from apps.api.compliance_planner_router import (
            router as compliance_planner_router,
        )
    except ImportError:
        compliance_planner_router = None  # type: ignore[assignment]
    if compliance_planner_router:
        app.include_router(
            compliance_planner_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))],
        )
        _logger.info("Mounted Compliance Planner router")

    # Evidence Collector
    try:
        from apps.api.evidence_collector_router import (
            router as evidence_collector_router,
        )
    except ImportError:
        evidence_collector_router = None  # type: ignore[assignment]
    if evidence_collector_router:
        app.include_router(
            evidence_collector_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))],
        )
        _logger.info("Mounted Evidence Collector router")

    # Exception / Waiver Policy
    try:
        from apps.api.exception_policy_router import router as exception_policy_router
    except ImportError:
        exception_policy_router = None  # type: ignore[assignment]
    if exception_policy_router:
        app.include_router(
            exception_policy_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Exception Policy router")

    # Executive Report
    try:
        from apps.api.executive_report_router import router as executive_report_router
    except ImportError:
        executive_report_router = None  # type: ignore[assignment]
    if executive_report_router:
        app.include_router(
            executive_report_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))],
        )
        _logger.info("Mounted Executive Report router")

    # Executive Security Reports
    try:
        from apps.api.exec_security_reports_router import (
            router as exec_security_reports_router,
        )
    except ImportError:
        exec_security_reports_router = None  # type: ignore[assignment]
    if exec_security_reports_router:
        app.include_router(
            exec_security_reports_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))],
        )
        _logger.info("Mounted Executive Security Reports router")

    # Regulatory Tracker Engine
    try:
        from apps.api.regulatory_tracker_engine_router import (
            router as regulatory_tracker_engine_router,
        )
    except ImportError:
        regulatory_tracker_engine_router = None  # type: ignore[assignment]
    if regulatory_tracker_engine_router:
        app.include_router(
            regulatory_tracker_engine_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Regulatory Tracker Engine router")

    # Vendor Scorecard
    try:
        from apps.api.vendor_scorecard_router import router as vendor_scorecard_router
    except ImportError:
        vendor_scorecard_router = None  # type: ignore[assignment]
    if vendor_scorecard_router:
        app.include_router(
            vendor_scorecard_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Vendor Scorecard router")

    # ------------------------------------------------------------------
    # Inline try/except GRC blocks — late-wired (formerly ~L5450-L6900)
    # ------------------------------------------------------------------

    # Security KPI Engine — CISO executive dashboard metrics
    try:
        from apps.api.kpi_router import router as kpi_router
        app.include_router(kpi_router)
        _logger.info("Mounted Security KPI router at /api/v1/kpis")
    except ImportError as _e:
        _logger.warning("Security KPI router not loaded: %s", _e)

    # Automated Evidence Collection (SOC2/PCI/HIPAA auto-collect)
    try:
        from apps.api.auto_evidence_router import router as auto_evidence_router
        app.include_router(auto_evidence_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Auto Evidence Collection router at /api/v1/auto-evidence")
    except ImportError as _e:
        _logger.warning("Auto Evidence Collection router not loaded: %s", _e)

    # Vendor Risk Management — third-party risk assessment
    try:
        from apps.api.vendor_risk_router import router as vendor_risk_router
        app.include_router(vendor_risk_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Vendor Risk router")
    except ImportError as _e:
        _logger.warning("Vendor Risk router not available: %s", _e)

    try:
        from apps.api.vendor_risk_router import (
            vra_router as vendor_risk_assessment_router,
        )
        app.include_router(vendor_risk_assessment_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Vendor Risk Assessment (VRA) router")
    except ImportError as _e:
        _logger.warning("Vendor Risk Assessment router not available: %s", _e)

    # Audit Log Analytics — ingest, search, anomaly detection, retention, forensic timeline
    try:
        from apps.api.audit_analytics_router import router as audit_analytics_router
        app.include_router(audit_analytics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Audit Log Analytics router at /api/v1/audit-analytics")
    except ImportError as _e:
        _logger.warning("Audit Log Analytics router not available: %s", _e)

    # Security KPI Metrics Tracker — MTTD/MTTR/compliance scoring with benchmarks
    try:
        from apps.api.security_kpi_router import router as security_kpi_router
        app.include_router(
            security_kpi_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Security KPI router at /api/v1/kpi")
    except ImportError as _e:
        _logger.warning("Security KPI router not available: %s", _e)

    # Security Playbook Engine — automated response playbooks with execution tracking
    try:
        from apps.api.playbook_router import router as _playbook_engine_router
        app.include_router(
            _playbook_engine_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Security Playbook router at /api/v1/playbooks")
    except Exception as _e:
        _logger.warning("Playbook router not loaded: %s", _e)

    # Compliance Automation — 7-framework coverage (SOC2, PCI-DSS, HIPAA, FedRAMP, ISO 27001, NIST, CMMC)
    try:
        from apps.api.compliance_automation_router import (
            router as compliance_automation_router,
        )
        app.include_router(
            compliance_automation_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Compliance Automation router at /api/v1/compliance")
    except Exception as _e:
        _logger.warning("Compliance Automation router not loaded: %s", _e)

    # Data Classification — SCIF-grade asset classification with audit trail
    try:
        from apps.api.data_classification_router import (
            router as data_classification_router,
        )
        app.include_router(
            data_classification_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Data Classification router at /api/v1/classification")
    except Exception as _e:
        _logger.warning("Data Classification router not loaded: %s", _e)

    # Compliance Gap Analysis & Audit Readiness
    try:
        from apps.api.compliance_gap_router import router as compliance_gap_router
        app.include_router(
            compliance_gap_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Compliance Gap Analysis router at /api/v1/compliance-automation")
    except Exception as _e:
        _logger.warning("Compliance Gap Analysis router not loaded: %s", _e)

    # GRC Engine — frameworks, controls, risks, assessments (/api/v1/grc)
    try:
        from apps.api.grc_router import router as grc_router
        app.include_router(grc_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted GRC router at /api/v1/grc")
    except Exception as _e:
        _logger.warning("GRC router not loaded: %s", _e)

    # Cyber Insurance — policies, assessments, claims, portfolio stats
    try:
        from apps.api.cyber_insurance_router import router as cyber_insurance_router
        app.include_router(cyber_insurance_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Cyber Insurance router at /api/v1/cyber-insurance")
    except Exception as _e:
        _logger.warning("Cyber insurance router not loaded: %s", _e)

    # Security Training — courses, enrollments, campaigns, progress
    try:
        from apps.api.security_training_router import router as security_training_router
        app.include_router(security_training_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Training router at /api/v1/security-training")
    except Exception as _e:
        _logger.warning("Security Training router not loaded: %s", _e)

    # FAIR-based financial risk quantification — scenarios, Monte Carlo, treatments, impacts
    try:
        from apps.api.risk_quantification_router import (
            router as risk_quantification_router,
        )
        app.include_router(risk_quantification_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Risk Quantification router at /api/v1/risk-quantification")
    except Exception as _e:
        _logger.warning("Risk Quantification router not loaded: %s", _e)

    # Security Roadmap / Strategic Planning Engine
    try:
        from apps.api.security_roadmap_router import router as security_roadmap_router
        app.include_router(security_roadmap_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Roadmap router at /api/v1/security-roadmap")
    except Exception as _e:
        _logger.warning("Security Roadmap router not loaded: %s", _e)

    # Data Governance — assets, policies, violations, data flows
    try:
        from apps.api.data_governance_router import router as data_governance_router
        app.include_router(data_governance_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Data Governance router at /api/v1/data-governance")
    except Exception as _e:
        _logger.warning("Data Governance router not loaded: %s", _e)

    # Compliance Scanner
    try:
        from apps.api.compliance_scanner_router import (
            router as compliance_scanner_router,
        )
        app.include_router(compliance_scanner_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Compliance Scanner router at /api/v1/compliance-scanner")
    except Exception as _e:
        _logger.warning("Compliance Scanner router not loaded: %s", _e)

    # Security Exception Manager — exception lifecycle, approvals, expiry tracking
    try:
        from apps.api.security_exception_router import (
            router as security_exception_router,
        )
        app.include_router(security_exception_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Exception router at /api/v1/security-exceptions")
    except Exception as _e:
        _logger.warning("Security Exception router not loaded: %s", _e)

    # Continuous Control Monitoring — SOC2/ISO27001/NIST/PCI/HIPAA/CIS control tests
    try:
        from apps.api.ccm_router import router as ccm_router
        app.include_router(ccm_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted CCM router at /api/v1/ccm")
    except Exception as _e:
        _logger.warning("CCM router not loaded: %s", _e)

    # Security Awareness Score Tracker
    try:
        from apps.api.awareness_score_router import router as awareness_score_router
        app.include_router(awareness_score_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Awareness Score router at /api/v1/awareness-score")
    except Exception as _e:
        _logger.warning("Awareness Score router not loaded: %s", _e)

    # Identity Analytics Engine — identity profiles, login events, risks, access certifications
    try:
        from apps.api.identity_analytics_router import (
            router as identity_analytics_router,
        )
        app.include_router(identity_analytics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Identity Analytics router at /api/v1/identity-analytics")
    except Exception as _e:
        _logger.warning("Identity Analytics router not loaded: %s", _e)

    # Report Scheduler
    try:
        from apps.api.report_scheduler_router import router as report_scheduler_router
        app.include_router(report_scheduler_router)
        _logger.info("Mounted Report Scheduler router")
    except Exception as _e:
        _logger.warning("Report scheduler router not loaded: %s", _e)

    # IGA — Identity Governance & Administration (access reviews, orphan detection, SoD)
    try:
        from apps.api.iga_router import router as iga_router
        app.include_router(iga_router)
        _logger.info("Mounted IGA router")
    except Exception as _e:
        _logger.warning("IGA router not loaded: %s", _e)

    # Data Retention
    try:
        from apps.api.data_retention_router import router as data_retention_router
        app.include_router(data_retention_router)
        _logger.info("Mounted Data Retention router at /api/v1/data-retention")
    except ImportError:
        pass

    # Evidence Chain (late-bound variant — after all other routes)
    try:
        from apps.api.evidence_chain_router import router as _evidence_chain_late
        app.include_router(_evidence_chain_late)
        _logger.info("Mounted Evidence Chain router at /api/v1/evidence-chain (late)")
    except ImportError:
        pass

    # Compliance Evidence
    try:
        from apps.api.compliance_evidence_router import (
            router as compliance_evidence_router,
        )
        app.include_router(compliance_evidence_router)
        _logger.info("Mounted Compliance Evidence router at /api/v1/compliance-evidence")
    except ImportError:
        pass

    # Compliance Automation (late-bound / compliance_router alias)
    try:
        from apps.api.compliance_router import router as compliance_router
        app.include_router(compliance_router)
        _logger.info("Mounted Compliance Automation router at /api/v1/compliance (late)")
    except ImportError:
        pass

    # Scheduled Reports (late-bound)
    try:
        from apps.api.scheduled_reports_router import router as scheduled_reports_router
        app.include_router(scheduled_reports_router)
        _logger.info("Mounted Scheduled Reports router at /api/v1/scheduled-reports")
    except ImportError:
        pass

    # Cloud Compliance
    try:
        from apps.api.cloud_compliance_router import router as cloud_compliance_router
        app.include_router(cloud_compliance_router)
        _logger.info("Mounted Cloud Compliance router at /api/v1/cloud-compliance")
    except ImportError:
        pass

    # Endpoint Compliance
    try:
        from apps.api.endpoint_compliance_router import (
            router as endpoint_compliance_router,
        )
        app.include_router(endpoint_compliance_router)
        _logger.info("Mounted Endpoint Compliance router at /api/v1/endpoint-compliance")
    except ImportError:
        pass

    # Executive Reporting Engine
    try:
        from apps.api.executive_reporting_router import (
            router as executive_reporting_router,
        )
        app.include_router(executive_reporting_router)
        _logger.info("Mounted Executive Reporting router at /api/v1/exec-reporting")
    except ImportError:
        pass

    # CISO Report
    try:
        from apps.api.ciso_report_router import router as ciso_report_router
        app.include_router(ciso_report_router)
        _logger.info("Mounted CISO Report router at /api/v1/ciso-report")
    except ImportError:
        pass

    # DLP — Data Loss Prevention
    try:
        from apps.api.dlp_router import router as dlp_router
        app.include_router(dlp_router)
        _logger.info("Mounted DLP router at /api/v1/dlp")
    except ImportError:
        pass

    # Privacy / GDPR
    try:
        from apps.api.privacy_gdpr_router import router as privacy_gdpr_router
        app.include_router(privacy_gdpr_router)
    except ImportError:
        pass

    # GDPR Compliance
    try:
        from apps.api.gdpr_compliance_router import router as gdpr_compliance_router
        app.include_router(gdpr_compliance_router)
        _logger.info("Mounted GDPR Compliance router at /api/v1/gdpr")
    except ImportError:
        pass

    # Data Privacy
    try:
        from apps.api.data_privacy_router import router as data_privacy_router
        app.include_router(data_privacy_router)
        _logger.info("Mounted Data Privacy router at /api/v1/data-privacy")
    except ImportError:
        pass

    # Physical Security Compliance
    try:
        from apps.api.physical_security_router import router as physical_security_router
        app.include_router(physical_security_router)
        _logger.info("Mounted Physical Security router at /api/v1/physical-security")
    except ImportError:
        pass

    # Policy Engine (late-bound policy_router alias)
    try:
        from apps.api.policy_router import router as policy_router
        app.include_router(policy_router)
        _logger.info("Mounted Policy Engine router at /api/v1/policies")
    except ImportError:
        pass

    # Security Playbook (late-bound alias)
    try:
        from apps.api.security_playbook_router import router as security_playbook_router
        app.include_router(security_playbook_router)
        _logger.info("Mounted Security Playbook router at /api/v1/security-playbooks")
    except ImportError:
        pass

    # Security Champions Program
    try:
        from apps.api.security_champions_router import (
            router as security_champions_router,
        )
        app.include_router(security_champions_router)
    except ImportError:
        pass

    # Identity Governance
    try:
        from apps.api.identity_governance_router import (
            router as identity_governance_router,
        )
        app.include_router(identity_governance_router)
        _logger.info("Mounted Identity Governance router at /api/v1/identity-governance")
    except ImportError:
        pass

    # Security Maturity
    try:
        from apps.api.security_maturity_router import router as security_maturity_router
        app.include_router(security_maturity_router)
    except ImportError:
        pass

    # Risk Aggregator
    try:
        from apps.api.risk_aggregator_router import router as risk_aggregator_router
        app.include_router(risk_aggregator_router)
        _logger.info("Mounted Risk Aggregator router at /api/v1/risk-aggregator")
    except ImportError:
        pass

    # Security Metrics Dashboard
    try:
        from apps.api.security_metrics_dashboard_router import (
            router as security_metrics_dashboard_router,
        )
        app.include_router(security_metrics_dashboard_router)
        _logger.info("Mounted Security Metrics Dashboard router at /api/v1/metrics-dashboard")
    except ImportError:
        pass

    # KPI Tracking
    try:
        from apps.api.kpi_tracking_router import router as kpi_tracking_router
        app.include_router(kpi_tracking_router)
        _logger.info("Mounted KPI Tracking router at /api/v1/kpi-tracking")
    except ImportError:
        pass

    # Security Metrics Collector
    try:
        from apps.api.security_metrics_collector_router import (
            router as security_metrics_collector_router,
        )
        app.include_router(security_metrics_collector_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Metrics Collector router at /api/v1/security-metrics-collector")
    except Exception as _e:
        _logger.warning("Security Metrics Collector router not loaded: %s", _e)

    # Third-Party Vendor Management (tprm_exchange)
    try:
        from apps.api.tprm_exchange_router import router as tprm_exchange_router
        app.include_router(tprm_exchange_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted TPRM Exchange router at /api/v1/tprm-exchange")
    except ImportError:
        pass

    # Trust Center — customer-facing security posture portal
    try:
        from apps.api.trust_center_router import router as trust_center_router
        app.include_router(trust_center_router)
        _logger.info("Mounted Trust Center router at /api/v1/trust-center")
    except ImportError:
        pass

    # Quantum-Safe Cryptography
    try:
        from apps.api.quantum_safe_crypto_router import (
            router as quantum_safe_crypto_router,
        )
        app.include_router(quantum_safe_crypto_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Quantum-Safe Crypto router at /api/v1/quantum-crypto")
    except ImportError:
        pass

    # Subsidiary Risk Attribution
    try:
        from apps.api.subsidiary_attribution_router import (
            router as subsidiary_attribution_router,
        )
        app.include_router(subsidiary_attribution_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Subsidiary Attribution router at /api/v1/subsidiary-risk")
    except ImportError:
        pass

    # Vulnerability Exception Management
    try:
        from apps.api.vuln_exception_router import router as vuln_exception_router
        app.include_router(vuln_exception_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Vulnerability Exception router at /api/v1/vuln-exceptions")
    except ImportError:
        pass

    # User Access Review
    try:
        from apps.api.user_access_review_router import (
            router as user_access_review_router,
        )
        app.include_router(user_access_review_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted User Access Review router at /api/v1/access-review")
    except ImportError:
        pass

    # Unified Rules Engine
    try:
        from apps.api.unified_rules_router import router as unified_rules_router
        app.include_router(unified_rules_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Unified Rules Engine router at /api/v1/unified-rules")
    except ImportError:
        pass

    # Risk Scenario Planning
    try:
        from apps.api.risk_scenario_router import router as risk_scenario_router
        app.include_router(risk_scenario_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Risk Scenario router at /api/v1/risk-scenarios")
    except ImportError:
        pass

    # Risk Treatment Workflow
    try:
        from apps.api.risk_treatment_router import router as risk_treatment_router
        app.include_router(risk_treatment_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Risk Treatment router at /api/v1/risk-treatment")
    except ImportError:
        pass

    # Risk Register Engine
    try:
        from apps.api.risk_register_engine_router import (
            router as risk_register_engine_router,
        )
        app.include_router(risk_register_engine_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Risk Register Engine router at /api/v1/risk-register-engine")
    except ImportError:
        pass

    # Risk Quantification Engine (FAIR)
    try:
        from apps.api.risk_quantification_engine_router import (
            router as risk_quantification_engine_router,
        )
        app.include_router(risk_quantification_engine_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Risk Quantification Engine router at /api/v1/risk-quantification-engine")
    except ImportError:
        pass

    # FAIR Per BU
    try:
        from apps.api.fair_per_bu_router import router as fair_per_bu_router
        app.include_router(fair_per_bu_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted FAIR Per BU router at /api/v1/fair-per-bu")
    except ImportError:
        pass

    # Security Budget Management
    try:
        from apps.api.security_budget_router import router as security_budget_router
        app.include_router(security_budget_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Budget router at /api/v1/security-budget")
    except ImportError:
        pass

    # Security Investment ROI
    try:
        from apps.api.security_investment_router import (
            router as security_investment_router,
        )
        app.include_router(security_investment_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Investment router at /api/v1/security-investment")
    except ImportError:
        pass

    # Security Questionnaire
    try:
        from apps.api.security_questionnaire_router import (
            router as security_questionnaire_router,
        )
        app.include_router(security_questionnaire_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Questionnaire router at /api/v1/security-questionnaire")
    except ImportError:
        pass

    # Security Capacity Planning
    try:
        from apps.api.security_capacity_planning_router import (
            router as security_capacity_planning_router,
        )
        app.include_router(security_capacity_planning_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Capacity Planning router at /api/v1/security-capacity")
    except ImportError:
        pass

    # Security Culture Metrics
    try:
        from apps.api.security_culture_router import router as security_culture_router
        app.include_router(security_culture_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Culture router at /api/v1/security-culture")
    except ImportError:
        pass

    # Security Change Management
    try:
        from apps.api.security_change_management_router import (
            router as security_change_management_router,
        )
        app.include_router(security_change_management_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Change Management router at /api/v1/security-change-mgmt")
    except ImportError:
        pass

    # Security Service Catalog
    try:
        from apps.api.security_service_catalog_router import (
            router as security_service_catalog_router,
        )
        app.include_router(security_service_catalog_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Service Catalog router at /api/v1/security-catalog")
    except ImportError:
        pass

    # Security Tabletop Exercise Management
    try:
        from apps.api.security_tabletop_router import router as security_tabletop_router
        app.include_router(security_tabletop_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Tabletop router at /api/v1/tabletop")
    except ImportError:
        pass

    # Security Training Effectiveness
    try:
        from apps.api.security_training_effectiveness_router import (
            router as security_training_effectiveness_router,
        )
        app.include_router(security_training_effectiveness_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Training Effectiveness router at /api/v1/training-effectiveness")
    except ImportError:
        pass

    # Security Awareness Metrics
    try:
        from apps.api.security_awareness_metrics_router import (
            router as security_awareness_metrics_router,
        )
        app.include_router(security_awareness_metrics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Awareness Metrics router at /api/v1/awareness-metrics")
    except ImportError:
        pass

    # Security Awareness Program
    try:
        from apps.api.security_awareness_program_router import (
            router as security_awareness_program_router,
        )
        app.include_router(security_awareness_program_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Awareness Program router at /api/v1/awareness-program")
    except ImportError:
        pass

    # Security Awareness Gamification
    try:
        from apps.api.security_awareness_gamification_router import (
            router as security_awareness_gamification_router,
        )
        app.include_router(security_awareness_gamification_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Awareness Gamification router at /api/v1/awareness-gamification")
    except ImportError:
        pass

    # Regulatory Reporting
    try:
        from apps.api.regulatory_reporting_router import (
            router as regulatory_reporting_router,
        )
        app.include_router(regulatory_reporting_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Regulatory Reporting router at /api/v1/regulatory-reporting")
    except ImportError:
        pass

    # Regulatory Tracker
    try:
        from apps.api.regulatory_tracker_router import (
            router as regulatory_tracker_router,
        )
        app.include_router(regulatory_tracker_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Regulatory Tracker router at /api/v1/regulatory-tracker")
    except ImportError:
        pass

    # FedRAMP Compliance
    try:
        from apps.api.fedramp_router import router as fedramp_router
        app.include_router(fedramp_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted FedRAMP router at /api/v1/fedramp")
    except ImportError:
        pass

    # FIPS Compliance
    try:
        from apps.api.fips_router import router as fips_router
        app.include_router(fips_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted FIPS Compliance router at /api/v1/fips")
    except ImportError:
        pass

    # Compliance Mapping
    try:
        from apps.api.compliance_mapping_router import (
            router as compliance_mapping_router,
        )
        app.include_router(compliance_mapping_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Compliance Mapping router at /api/v1/compliance-mapping")
    except ImportError:
        pass

    # Compliance Workflow
    try:
        from apps.api.compliance_workflow_router import (
            router as compliance_workflow_router,
        )
        app.include_router(compliance_workflow_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Compliance Workflow router at /api/v1/compliance-workflow")
    except ImportError:
        pass

    # Compliance Seed Data
    try:
        from apps.api.compliance_seed_router import router as compliance_seed_router
        app.include_router(compliance_seed_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Compliance Seed router at /api/v1/compliance-seed")
    except ImportError:
        pass

    # Control Testing
    try:
        from apps.api.control_testing_router import router as control_testing_router
        app.include_router(control_testing_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Control Testing router at /api/v1/control-testing")
    except ImportError:
        pass

    # Access Governance
    try:
        from apps.api.access_governance_router import router as access_governance_router
        app.include_router(access_governance_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Access Governance router at /api/v1/access-governance")
    except ImportError:
        pass

    # Access Request Management
    try:
        from apps.api.access_request_management_router import (
            router as access_request_management_router,
        )
        app.include_router(access_request_management_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Access Request Management router at /api/v1/access-requests")
    except ImportError:
        pass

    # AI Governance
    try:
        from apps.api.ai_governance_router import router as ai_governance_router
        app.include_router(ai_governance_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted AI Governance router at /api/v1/ai-governance")
    except ImportError:
        pass

    # Cloud Governance
    try:
        from apps.api.cloud_governance_router import router as cloud_governance_router
        app.include_router(cloud_governance_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Cloud Governance router at /api/v1/cloud-governance")
    except ImportError:
        pass

    # Data Security Management
    try:
        from apps.api.data_security_router import router as data_security_router
        app.include_router(data_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Data Security router at /api/v1/data-security")
    except ImportError:
        pass

    # Evidence Vault
    try:
        from apps.api.evidence_vault_router import router as evidence_vault_router
        app.include_router(evidence_vault_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Evidence Vault router at /api/v1/evidence-vault")
    except ImportError:
        pass

    # Export Coverage
    try:
        from apps.api.export_coverage_router import router as export_coverage_router
        app.include_router(export_coverage_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Export Coverage router at /api/v1/export-coverage")
    except ImportError:
        pass

    # Incident Cost Tracking
    try:
        from apps.api.incident_cost_router import router as incident_cost_router
        app.include_router(incident_cost_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Incident Cost router at /api/v1/incident-costs")
    except ImportError:
        pass

    # Incident Lessons Learned
    try:
        from apps.api.incident_lessons_router import router as incident_lessons_router
        app.include_router(incident_lessons_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Incident Lessons router at /api/v1/incident-lessons")
    except ImportError:
        pass

    # Incident Metrics / MTTR
    try:
        from apps.api.incident_metrics_router import router as incident_metrics_router
        app.include_router(incident_metrics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Incident Metrics router at /api/v1/incident-metrics")
    except ImportError:
        pass

    # License Compliance
    try:
        from apps.api.license_compliance_router import (
            router as license_compliance_router,
        )
        app.include_router(license_compliance_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted License Compliance router at /api/v1/license-compliance")
    except ImportError:
        pass

    # Playbook Marketplace
    try:
        from apps.api.playbook_marketplace_router import (
            router as playbook_marketplace_router,
        )
        app.include_router(playbook_marketplace_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Playbook Marketplace router at /api/v1/playbook-marketplace")
    except ImportError:
        pass

    # Policy Enforcement Engine
    try:
        from apps.api.policy_enforcement_router import (
            router as policy_enforcement_router,
        )
        app.include_router(policy_enforcement_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Policy Enforcement router at /api/v1/policy-enforcement")
    except ImportError:
        pass

    # Privacy Impact Assessment
    try:
        from apps.api.privacy_impact_assessment_router import (
            router as privacy_impact_assessment_router,
        )
        app.include_router(privacy_impact_assessment_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Privacy Impact Assessment router at /api/v1/privacy-impact")
    except ImportError:
        pass

    # Report Builder
    try:
        from apps.api.report_builder_router import router as report_builder_router
        app.include_router(report_builder_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Report Builder router at /api/v1/report-builder")
    except ImportError:
        pass

    # Risk Acceptance Workflow (late-binding — in addition to _extra_apps_routers)
    try:
        from apps.api.risk_acceptance_router import router as risk_acceptance_router
        app.include_router(risk_acceptance_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Risk Acceptance router at /api/v1/risk-acceptance")
    except ImportError:
        pass

    # Security Architecture Review
    try:
        from apps.api.security_architecture_review_router import (
            router as security_architecture_review_router,
        )
        app.include_router(security_architecture_review_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Architecture Review router at /api/v1/security-arch-review")
    except ImportError:
        pass

    # Security Baseline Management
    try:
        from apps.api.security_baseline_router import router as security_baseline_router
        app.include_router(security_baseline_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Baseline router at /api/v1/security-baseline")
    except ImportError:
        pass

    # Security Benchmark
    try:
        from apps.api.security_benchmark_router import (
            router as security_benchmark_router,
        )
        app.include_router(security_benchmark_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Benchmark router at /api/v1/security-benchmark")
    except ImportError:
        pass

    # Security Gap Analysis
    try:
        from apps.api.security_gap_analysis_router import (
            router as security_gap_analysis_router,
        )
        app.include_router(security_gap_analysis_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Gap Analysis router at /api/v1/security-gap")
    except ImportError:
        pass

    # Security Health Scorecard
    try:
        from apps.api.security_health_scorecard_router import (
            router as security_health_scorecard_router,
        )
        app.include_router(security_health_scorecard_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Health Scorecard router at /api/v1/security-health-scorecard")
    except ImportError:
        pass

    # Security Metrics Aggregator
    try:
        from apps.api.security_metrics_aggregator_router import (
            router as security_metrics_aggregator_router,
        )
        app.include_router(security_metrics_aggregator_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Metrics Aggregator router at /api/v1/security-metrics-agg")
    except ImportError:
        pass

    # Security OKR Tracking
    try:
        from apps.api.security_okr_router import router as security_okr_router
        app.include_router(security_okr_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security OKR router at /api/v1/security-okr")
    except ImportError:
        pass

    # Security Operations Metrics
    try:
        from apps.api.security_operations_metrics_router import (
            router as security_operations_metrics_router,
        )
        app.include_router(security_operations_metrics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Operations Metrics router at /api/v1/ops-metrics")
    except ImportError:
        pass

    # Security Posture Benchmarking
    try:
        from apps.api.security_posture_benchmarking_router import (
            router as security_posture_benchmarking_router,
        )
        app.include_router(security_posture_benchmarking_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Posture Benchmarking router at /api/v1/posture-benchmarking")
    except ImportError:
        pass

    # Security Posture History
    try:
        from apps.api.security_posture_history_router import (
            router as security_posture_history_router,
        )
        app.include_router(security_posture_history_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Posture History router at /api/v1/posture-history")
    except ImportError:
        pass

    # Security Posture Maturity
    try:
        from apps.api.security_posture_maturity_router import (
            router as security_posture_maturity_router,
        )
        app.include_router(security_posture_maturity_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Posture Maturity router at /api/v1/posture-maturity")
    except ImportError:
        pass

    # Security Posture PDF Report
    try:
        from apps.api.security_posture_pdf_router import (
            router as security_posture_pdf_router,
        )
        app.include_router(security_posture_pdf_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Posture PDF router at /api/v1/posture-pdf")
    except ImportError:
        pass

    # Security Posture Reporting
    try:
        from apps.api.security_posture_reporting_router import (
            router as security_posture_reporting_router,
        )
        app.include_router(security_posture_reporting_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Posture Reporting router at /api/v1/posture-reporting")
    except ImportError:
        pass

    # Security Posture Scoring
    try:
        from apps.api.security_posture_scoring_router import (
            router as security_posture_scoring_router,
        )
        app.include_router(security_posture_scoring_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Posture Scoring router at /api/v1/posture-scoring")
    except ImportError:
        pass

    # Security Posture Trend
    try:
        from apps.api.security_posture_trend_router import (
            router as security_posture_trend_router,
        )
        app.include_router(security_posture_trend_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Posture Trend router at /api/v1/posture-trend")
    except ImportError:
        pass

    # Security Program Maturity
    try:
        from apps.api.security_program_maturity_router import (
            router as security_program_maturity_router,
        )
        app.include_router(security_program_maturity_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Program Maturity router at /api/v1/program-maturity")
    except ImportError:
        pass

    # Security Scoreboard
    try:
        from apps.api.security_scoreboard_router import (
            router as security_scoreboard_router,
        )
        app.include_router(security_scoreboard_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Scoreboard router at /api/v1/security-scoreboard")
    except ImportError:
        pass

    # Exception Workflow
    try:
        from apps.api.security_exception_workflow_router import (
            router as security_exception_workflow_router,
        )
        app.include_router(security_exception_workflow_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Exception Workflow router at /api/v1/exception-workflow")
    except ImportError:
        pass

    # Vendor Compliance Management
    try:
        from apps.api.vendor_compliance_router import router as vendor_compliance_router
        app.include_router(vendor_compliance_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Vendor Compliance router at /api/v1/vendor-compliance")
    except ImportError:
        pass

    # Awareness Campaign
    try:
        from apps.api.awareness_campaign_router import (
            router as awareness_campaign_router,
        )
        app.include_router(awareness_campaign_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Awareness Campaign router at /api/v1/awareness-campaigns")
    except ImportError:
        pass

    # Training (late-bound)
    try:
        from apps.api.training_router import router as _training_router
        app.include_router(_training_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Training router (late)")
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # Wave-6 — loop-bound GRC entries (formerly in _evidence_routers /
    # _extra_apps_routers loops in app.py, deferred from Waves 1-4)
    # ------------------------------------------------------------------

    # _evidence_routers (all read:evidence scope, /api/v1 prefix)

    # Evidence — tamper-proof evidence chain (suite-evidence-risk/api/)
    try:
        from api.evidence_router import router as evidence_router  # noqa: PLC0415
        app.include_router(evidence_router, prefix="/api/v1", dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Evidence router (wave-6)")
    except ImportError:
        pass

    # Risk — risk register and scoring (suite-evidence-risk/api/)
    try:
        from api.risk_router import router as risk_router_ext  # noqa: PLC0415
        app.include_router(risk_router_ext, prefix="/api/v1", dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Risk router (wave-6)")
    except ImportError:
        pass

    # Graph — attack path / knowledge graph (suite-evidence-risk/api/)
    try:
        from api.graph_router import router as graph_router  # noqa: PLC0415
        app.include_router(graph_router, prefix="/api/v1", dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Graph router (wave-6)")
    except ImportError:
        pass

    # Provenance — data lineage (suite-evidence-risk/api/)
    try:
        from api.provenance_router import router as provenance_router  # noqa: PLC0415
        app.include_router(provenance_router, prefix="/api/v1", dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Provenance router (wave-6)")
    except ImportError:
        pass

    # Compliance Engine — control assessment (suite-evidence-risk/api/)
    try:
        from api.compliance_engine_router import (
            router as compliance_engine_router,  # noqa: PLC0415
        )
        app.include_router(compliance_engine_router, prefix="/api/v1", dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Compliance Engine router (wave-6)")
    except ImportError:
        pass

    # Business Context — asset business criticality (suite-evidence-risk/api/)
    try:
        from api.business_context import router as biz_ctx_router  # noqa: PLC0415
        app.include_router(biz_ctx_router, prefix="/api/v1", dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Business Context router (wave-6)")
    except ImportError:
        pass

    # Business Context Enhanced (suite-evidence-risk/api/)
    try:
        from api.business_context_enhanced import (
            router as biz_ctx_enhanced_router,  # noqa: PLC0415
        )
        app.include_router(biz_ctx_enhanced_router, prefix="/api/v1", dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Business Context Enhanced router (wave-6)")
    except ImportError:
        pass

    # _extra_apps_routers GRC entries

    # Compliance Planner (apps/api/)
    try:
        from apps.api.compliance_planner_router import (
            router as compliance_planner_router,  # noqa: PLC0415
        )
        app.include_router(compliance_planner_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Compliance Planner router (wave-6)")
    except ImportError:
        pass

    # Evidence Collector (apps/api/)
    try:
        from apps.api.evidence_collector_router import (
            router as evidence_collector_router,  # noqa: PLC0415
        )
        app.include_router(evidence_collector_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Evidence Collector router (wave-6)")
    except ImportError:
        pass

    # Exception Policy (apps/api/)
    try:
        from apps.api.exception_policy_router import (
            router as exception_policy_router,  # noqa: PLC0415
        )
        app.include_router(exception_policy_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Exception Policy router (wave-6)")
    except ImportError:
        pass

    # Executive Report (apps/api/)
    try:
        from apps.api.executive_report_router import (
            router as executive_report_router,  # noqa: PLC0415
        )
        app.include_router(executive_report_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Executive Report router (wave-6)")
    except ImportError:
        pass

    # Executive Security Reports (apps/api/)
    try:
        from apps.api.exec_security_reports_router import (
            router as exec_security_reports_router,  # noqa: PLC0415
        )
        app.include_router(exec_security_reports_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Executive Security Reports router (wave-6)")
    except ImportError:
        pass

    # Risk Acceptance (apps/api/)
    try:
        from apps.api.risk_acceptance_router import (
            router as risk_acceptance_router,  # noqa: PLC0415
        )
        app.include_router(risk_acceptance_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Risk Acceptance router (wave-6)")
    except ImportError:
        pass

    # Risk Quantifier (apps/api/)
    try:
        from apps.api.risk_quantifier_router import (
            router as risk_quantifier_router,  # noqa: PLC0415
        )
        app.include_router(risk_quantifier_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Risk Quantifier router (wave-6)")
    except ImportError:
        pass

    # Security ROI (apps/api/)
    try:
        from apps.api.security_roi_router import (
            router as security_roi_router,  # noqa: PLC0415
        )
        app.include_router(security_roi_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Security ROI router (wave-6)")
    except ImportError:
        pass

    # Vendor Scorecard (apps/api/)
    try:
        from apps.api.vendor_scorecard_router import (
            router as vendor_scorecard_router,  # noqa: PLC0415
        )
        app.include_router(vendor_scorecard_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Vendor Scorecard router (wave-6)")
    except ImportError:
        pass

    # Security Scorecard Engine (apps/api/)
    try:
        from apps.api.security_scorecard_engine_router import (
            router as security_scorecard_engine_router,  # noqa: PLC0415
        )
        app.include_router(security_scorecard_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Security Scorecard Engine router (wave-6)")
    except ImportError:
        pass

    # Security Scorecard (apps/api/)
    try:
        from apps.api.security_scorecard_router import (
            router as security_scorecard_router,  # noqa: PLC0415
        )
        app.include_router(security_scorecard_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Security Scorecard router (wave-6)")
    except ImportError:
        pass

    # Regulatory Tracker Engine (apps/api/)
    try:
        from apps.api.regulatory_tracker_engine_router import (
            router as regulatory_tracker_engine_router,  # noqa: PLC0415
        )
        app.include_router(regulatory_tracker_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Regulatory Tracker Engine router (wave-6)")
    except ImportError:
        pass

    # Questionnaire Engine (apps/api/)
    try:
        from apps.api.questionnaire_router import (
            router as questionnaire_router,  # noqa: PLC0415
        )
        app.include_router(questionnaire_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Questionnaire Engine router (wave-6)")
    except ImportError:
        pass

    _logger.info("GRC sub-app: all routers registered")
