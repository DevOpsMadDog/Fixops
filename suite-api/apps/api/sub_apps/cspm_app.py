"""CSPM — Cloud Security Posture Management router registrar.

Wave 2 extraction from app.py (2026-04-28). Mirrors the ASPM Wave 1 registrar
pattern: routers are registered directly on the *parent* FastAPI app so that
``len(app.routes)`` is unchanged and the route-count gate continues to pass.

Loop-bound CSPM routers (cspm_engine, cspm_deep, cspm_connector, drift,
posture, posture_benchmark, privilege_escalation_detector) remain in the
``_extra_apps_routers`` loop in app.py and are NOT moved here — that is a
future loop-refactor wave per docs/app_py_refactor_plan_2026-04-27.md.

Usage (from create_app in app.py)::

    from apps.api.sub_apps.cspm_app import register_cspm_routers
    register_cspm_routers(app, _verify_api_key, _require_scope, _logger)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

from fastapi import Depends

if TYPE_CHECKING:
    from fastapi import FastAPI

_log = logging.getLogger(__name__)


def register_cspm_routers(
    app: "FastAPI",
    _verify_api_key: Callable[..., Any],
    _require_scope: Callable[..., Any],
    _logger: logging.Logger | None = None,
) -> None:
    """Register all CSPM routers onto *app* in app.py source order.

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

    try:
        from apps.api.network_security_router import (
            router as network_security_router,  # noqa: PLC0415
        )
        app.include_router(network_security_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Network Security (NDR) router")
    except ImportError:
        pass

    # Cloud Discovery — multi-cloud asset inventory
    try:
        from apps.api.cloud_discovery_router import (
            router as cloud_discovery_router,  # noqa: PLC0415
        )
        app.include_router(cloud_discovery_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Cloud Discovery router")
    except ImportError:
        pass

    # Database Security Scanner — CIS benchmarks, privilege audit, data exposure, query audit
    try:
        from apps.api.db_security_router import (
            router as db_security_router,  # noqa: PLC0415
        )
        app.include_router(db_security_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Database Security Scanner router")
    except ImportError:
        pass

    # AWS Security Hub — pull findings from AWS Security Hub (ASFF normalization)
    try:
        from apps.api.aws_security_hub_router import (
            router as aws_security_hub_router,  # noqa: PLC0415
        )
        app.include_router(aws_security_hub_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted AWS Security Hub router")
    except ImportError:
        pass

    # Azure Defender — pull alerts/score/recommendations from Microsoft Defender for Cloud
    try:
        from apps.api.azure_defender_router import (
            router as azure_defender_router,  # noqa: PLC0415
        )
        app.include_router(azure_defender_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Azure Defender router")
    except ImportError:
        pass

    # -----------------------------------------------------------------------
    # GAP-020 — Agentless Snapshot Scanning (Wiz/Orca moat, P0)
    # -----------------------------------------------------------------------
    try:
        from apps.api.agentless_snapshot_router import (
            router as agentless_snapshot_router,
        )
        app.include_router(agentless_snapshot_router)
        _logger.info("Mounted Agentless Snapshot Scan router at /api/v1/agentless-snapshot")
    except ImportError as _agentless_err:
        _logger.warning("Agentless Snapshot router not available: %s", _agentless_err)

    # TLS Certificate Management — expiry tracking, weak-config detection
    try:
        from apps.api.cert_router import router as cert_router
        app.include_router(cert_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Certificate Manager router at /api/v1/certificates")
    except Exception as e:
        _logger.warning(f"Certificate Manager router not loaded: {e}")

    # Firewall Rule Analysis — inventory, rule analysis, findings
    try:
        from apps.api.firewall_rule_router import router as firewall_rule_router
        app.include_router(firewall_rule_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Firewall Rule Analysis router at /api/v1/firewall")
    except Exception as e:
        _logger.warning(f"Firewall Rule Analysis router not loaded: {e}")

    # PAM Engine — privileged accounts, sessions, approval workflow, policies, vault
    try:
        from apps.api.pam_router import router as pam_router
        app.include_router(pam_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted PAM Engine router at /api/v1/pam")
    except Exception as e:
        _logger.warning(f"PAM router not loaded: {e}")

    # Security Posture Score — weighted component scoring, history, benchmarks
    try:
        from apps.api.posture_score_router import router as posture_score_router
        app.include_router(posture_score_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Posture Score router at /api/v1/posture-score")
    except Exception as e:
        _logger.warning(f"Posture Score router not loaded: {e}")

    # Cloud Workload Protection Engine — runtime threats, policies, risk scoring
    try:
        from apps.api.cloud_workload_protection_router import (
            router as cloud_workload_protection_router,
        )
        app.include_router(cloud_workload_protection_router)
        _logger.info("Mounted Cloud Workload Protection router at /api/v1/cwp")
    except Exception as e:
        _logger.warning(f"Cloud Workload Protection router not loaded: {e}")

    try:
        from apps.api.zero_trust_enforcement_router import (
            router as zero_trust_enforcement_router,
        )
        app.include_router(zero_trust_enforcement_router)
        _logger.info("Mounted Zero Trust Enforcement router at /api/v1/zero-trust")
    except ImportError:
        pass

    try:
        from apps.api.zero_trust_policy_router import router as zero_trust_policy_router
        app.include_router(zero_trust_policy_router)
        _logger.info("Mounted Zero Trust Policy router at /api/v1/zero-trust-policy")
    except ImportError:
        pass

    try:
        from apps.api.cloud_security_engine_router import (
            router as cloud_security_engine_router,
        )
        app.include_router(cloud_security_engine_router)
        _logger.info("Mounted Cloud Security Engine router at /api/v1/cloud-security-engine")
    except ImportError:
        pass

    try:
        from apps.api.network_traffic_router import router as network_traffic_router
        app.include_router(network_traffic_router)
        _logger.info("Mounted Network Traffic router at /api/v1/network-traffic")
    except ImportError:
        pass

    try:
        from apps.api.firewall_management_router import (
            router as firewall_management_router,
        )
        app.include_router(firewall_management_router)
    except ImportError:
        pass

    try:
        from apps.api.cloud_cost_security_router import (
            router as cloud_cost_security_router,
        )
        app.include_router(cloud_cost_security_router)
        _logger.info("Mounted Cloud Cost Security router at /api/v1/cloud-cost")
    except ImportError:
        pass

    try:
        from apps.api.nac_router import router as nac_router
        app.include_router(nac_router)
        _logger.info("Mounted NAC router at /api/v1/nac")
    except ImportError:
        pass

    try:
        from apps.api.waf_engine_router import router as waf_engine_router
        app.include_router(waf_engine_router)
        _logger.info("Mounted WAF Engine router at /api/v1/waf-engine")
    except ImportError:
        pass

    try:
        from apps.api.mdm_router import router as mdm_router
        app.include_router(mdm_router)
        _logger.info("Mounted MDM router at /api/v1/mdm")
    except ImportError:
        pass

    try:
        from apps.api.casb_router import router as casb_router
        app.include_router(casb_router)
        _logger.info("Mounted CASB router at /api/v1/casb")
    except ImportError:
        pass

    try:
        from apps.api.iam_policy_router import router as iam_policy_router
        app.include_router(iam_policy_router)
        _logger.info("Mounted IAM Policy router at /api/v1/iam-policy")
    except ImportError:
        pass

    try:
        from apps.api.cloud_drift_router import router as cloud_drift_router
        app.include_router(cloud_drift_router)
        _logger.info("Mounted Cloud Drift router at /api/v1/cloud-drift")
    except ImportError:
        pass

    try:
        from apps.api.cloud_native_security_router import (
            router as cloud_native_security_router,
        )
        app.include_router(cloud_native_security_router)
        _logger.info("Mounted Cloud Native Security router at /api/v1/cloud-native")
    except ImportError:
        pass

    try:
        from apps.api.kubernetes_security_router import (
            router as kubernetes_security_router,
        )
        app.include_router(kubernetes_security_router)
        _logger.info("Mounted Kubernetes Security router at /api/v1/kubernetes-security")
    except ImportError:
        pass

    try:
        from apps.api.network_monitoring_router import (
            router as network_monitoring_router,
        )
        app.include_router(network_monitoring_router)
        _logger.info("Mounted Network Monitoring router at /api/v1/network-monitoring")
    except ImportError:
        pass

    try:
        from apps.api.bandwidth_analysis_router import (
            router as bandwidth_analysis_router,
        )
        app.include_router(bandwidth_analysis_router)
        _logger.info("Mounted Bandwidth Analysis router at /api/v1/bandwidth-analysis")
    except ImportError:
        pass

    try:
        from apps.api.service_account_auditor_router import (
            router as service_account_auditor_router,
        )
        app.include_router(service_account_auditor_router)
        _logger.info("Mounted Service Account Auditor router at /api/v1/service-account-auditor")
    except ImportError:
        pass

    try:
        from apps.api.privilege_escalation_router import (
            router as privilege_escalation_router,
        )
        app.include_router(privilege_escalation_router)
        _logger.info("Mounted Privilege Escalation router at /api/v1/privilege-escalation")
    except ImportError:
        pass

    try:
        from apps.api.firewall_policy_router import router as firewall_policy_router
        app.include_router(firewall_policy_router)
        _logger.info("Mounted Firewall Policy router at /api/v1/firewall-policy")
    except ImportError:
        pass

    try:
        from apps.api.network_segmentation_router import (
            router as network_segmentation_router,
        )
        app.include_router(network_segmentation_router)
        _logger.info("Mounted Network Segmentation router at /api/v1/network-segmentation")
    except ImportError:
        pass

    try:
        from apps.api.crypto_key_management_router import (
            router as crypto_key_management_router,
        )
        app.include_router(crypto_key_management_router)
        _logger.info("Mounted Crypto Key Management router at /api/v1/crypto-keys")
    except ImportError:
        pass

    try:
        from apps.api.certificate_lifecycle_router import (
            router as certificate_lifecycle_router,
        )
        app.include_router(certificate_lifecycle_router)
        _logger.info("Mounted Certificate Lifecycle router at /api/v1/certificates")
    except ImportError:
        pass

    try:
        from apps.api.data_lake_security_router import (
            router as data_lake_security_router,
        )
        app.include_router(data_lake_security_router)
        _logger.info("Mounted Data Lake Security router at /api/v1/data-lake-security")
    except ImportError:
        pass

    try:
        from apps.api.mobile_device_management_router import (
            router as mobile_device_management_router,
        )
        app.include_router(mobile_device_management_router)
        _logger.info("Mounted Mobile Device Management router at /api/v1/mdm")
    except ImportError:
        pass

    try:
        from apps.api.access_control_router import router as access_control_router
        app.include_router(access_control_router)
        _logger.info("Mounted Access Control router at /api/v1/access-control")
    except ImportError:
        pass

    try:
        from apps.api.wireless_security_router import router as wireless_security_router
        app.include_router(wireless_security_router)
        _logger.info("Mounted Wireless Security router at /api/v1/wireless-security")
    except ImportError:
        pass

    try:
        from apps.api.network_access_control_router import (
            router as network_access_control_router,
        )
        app.include_router(network_access_control_router)
        _logger.info("Mounted Network Access Control router at /api/v1/nac")
    except ImportError:
        pass

    try:
        from apps.api.mfa_management_router import router as mfa_management_router
        app.include_router(mfa_management_router)
        _logger.info("Mounted MFA Management router at /api/v1/mfa")
    except ImportError:
        pass

    # GAP-059: Shadow-AI inventory (ai_governance + cmdb composite)
    try:
        from apps.api.shadow_ai_router import router as shadow_ai_router
        app.include_router(shadow_ai_router)
        _logger.info("Mounted Shadow AI router at /api/v1/shadow-ai")
    except ImportError:
        pass

    try:
        from apps.api.digital_identity_router import router as digital_identity_router
        app.include_router(digital_identity_router)
        _logger.info("Mounted Digital Identity router at /api/v1/digital-identity")
    except ImportError:
        pass

    try:
        from apps.api.itdr_router import router as itdr_router
        app.include_router(itdr_router)
        _logger.info("Mounted ITDR router at /api/v1/itdr")
    except ImportError:
        pass

    try:
        from apps.api.pki_management_router import router as pki_management_router
        app.include_router(pki_management_router)
        _logger.info("Mounted PKI Management router at /api/v1/pki")
    except ImportError:
        pass

    try:
        from apps.api.cloud_security_analytics_router import (
            router as cloud_security_analytics_router,
        )
        app.include_router(cloud_security_analytics_router)
        _logger.info("Mounted Cloud Security Analytics router at /api/v1/cloud-analytics")
    except ImportError:
        pass

    try:
        from apps.api.identity_risk_router import router as identity_risk_router
        app.include_router(identity_risk_router)
        _logger.info("Mounted Identity Risk router at /api/v1/identity-risk")
    except ImportError:
        pass

    try:
        from apps.api.privileged_access_governance_router import (
            router as privileged_access_governance_router,
        )
        app.include_router(privileged_access_governance_router)
        _logger.info("Mounted Privileged Access Governance router at /api/v1/pag")
    except ImportError:
        pass

    try:
        from apps.api.cloud_posture_router import router as cloud_posture_router
        app.include_router(cloud_posture_router)
        _logger.info("Mounted Cloud Posture router at /api/v1/cloud-posture")
    except ImportError:
        pass

    try:
        from apps.api.container_security_posture_router import (
            router as container_security_posture_router,
        )
        app.include_router(container_security_posture_router)
        _logger.info("Mounted Container Security Posture router at /api/v1/container-posture")
    except ImportError:
        pass

    try:
        from apps.api.privileged_session_recording_router import (
            router as privileged_session_recording_router,
        )
        app.include_router(privileged_session_recording_router)
        _logger.info("Mounted Privileged Session Recording router at /api/v1/session-recording")
    except ImportError:
        pass

    try:
        from apps.api.cloud_resource_inventory_router import (
            router as cloud_resource_inventory_router,
        )
        app.include_router(cloud_resource_inventory_router)
        _logger.info("Mounted Cloud Resource Inventory router at /api/v1/cloud-inventory")
    except ImportError:
        pass

    try:
        from apps.api.microsegmentation_policy_router import (
            router as microsegmentation_policy_router,
        )
        app.include_router(microsegmentation_policy_router)
        _logger.info("Mounted Microsegmentation Policy router at /api/v1/microsegmentation")
    except ImportError:
        pass

    # Wave 29 routers
    try:
        from apps.api.saas_security_posture_router import (
            router as saas_security_posture_router,
        )
        app.include_router(saas_security_posture_router)
        _logger.info("Mounted SaaS Security Posture router at /api/v1/sspm")
    except ImportError:
        pass

    try:
        from apps.api.cloud_account_monitoring_router import (
            router as cloud_account_monitoring_router,
        )
        app.include_router(cloud_account_monitoring_router)
        _logger.info("Mounted Cloud Account Monitoring router at /api/v1/cloud-accounts")
    except ImportError:
        pass

    try:
        from apps.api.cloud_security_findings_router import (
            router as cloud_security_findings_router,
        )
        app.include_router(cloud_security_findings_router)
        _logger.info("Mounted Cloud Security Findings router at /api/v1/cloud-findings")
    except ImportError:
        pass

    # GAP-032/033 CIEM+AD Attack Paths — least-privilege + Kerberoast/DCSync/ESC
    try:
        from apps.api.ciem_ad_router import router as ciem_ad_router
        app.include_router(ciem_ad_router)
        _logger.info("Mounted CIEM+AD router at /api/v1/ciem-ad")
    except ImportError:
        pass

    try:
        from apps.api.privileged_identity_router import (
            router as privileged_identity_router,
        )
        app.include_router(privileged_identity_router)
        _logger.info("Mounted Privileged Identity router at /api/v1/privileged-identity")
    except ImportError:
        pass

    try:
        from apps.api.identity_lifecycle_router import (
            router as identity_lifecycle_router,
        )
        app.include_router(identity_lifecycle_router)
        _logger.info("Mounted Identity Lifecycle router at /api/v1/identity-lifecycle")
    except ImportError:
        pass

    try:
        from apps.api.access_anomaly_router import router as access_anomaly_router
        app.include_router(access_anomaly_router)
        _logger.info("Mounted Access Anomaly router at /api/v1/access-anomaly")
    except ImportError:
        pass

    try:
        from apps.api.cloud_cost_optimization_router import (
            router as cloud_cost_optimization_router,
        )
        app.include_router(cloud_cost_optimization_router)
        _logger.info("Mounted Cloud Cost Optimization router at /api/v1/cost-optimization")
    except ImportError:
        pass

    try:
        from apps.api.cloud_connectors_router import router as cloud_connectors_router
        app.include_router(cloud_connectors_router)
        _logger.info("Mounted Cloud Connectors router at /api/v1/cloud-connectors")
    except ImportError:
        pass

    try:
        from apps.api.cloud_graph_router import router as cloud_graph_router
        app.include_router(cloud_graph_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Cloud Graph router at /api/v1/cloud-graph")
    except ImportError:
        pass

    # GCP Security Command Center — wired 2026-05-04
    # GET  /api/v1/gcp-scc/                         capability summary    (read:scans)
    # GET  /api/v1/gcp-scc/findings                 list findings         (read:scans)
    # GET  /api/v1/gcp-scc/sources                  list SCC sources      (read:scans)
    # GET  /api/v1/gcp-scc/assets                   list assets           (read:scans)
    # GET  /api/v1/gcp-scc/findings/group           groupBy aggregate     (read:scans)
    # POST /api/v1/gcp-scc/findings/{name}:setMute  mute toggle           (read:scans)
    try:
        from apps.api.gcp_scc_router import router as gcp_scc_router
        app.include_router(gcp_scc_router)
        _logger.info("Mounted GCP SCC router at /api/v1/gcp-scc")
    except ImportError:
        pass

    try:
        from apps.api.k8s_security_router import router as k8s_security_router
        app.include_router(k8s_security_router)
        _logger.info("Mounted Kubernetes Security router at /api/v1/k8s")
    except ImportError:
        pass

    # Prowler CSPM — agentless cloud scanning (AWS/Azure/GCP)
    try:
        from apps.api.prowler_router import router as prowler_router
        app.include_router(prowler_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))])
        _logger.info("Mounted Prowler CSPM router at /api/v1/prowler")
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # Wave-6 — loop-bound CSPM entries (formerly in _extra_apps_routers
    # loop in app.py, deferred from Waves 1-2)
    # ------------------------------------------------------------------

    # CSPM Engine (apps/api/)
    try:
        from apps.api.cspm_engine_router import (
            router as cspm_engine_router,  # noqa: PLC0415
        )
        app.include_router(cspm_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted CSPM Engine router (wave-6)")
    except ImportError:
        pass

    # CSPM Deep Scan (apps/api/)
    try:
        from apps.api.cspm_deep_router import (
            router as cspm_deep_router,  # noqa: PLC0415
        )
        app.include_router(cspm_deep_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted CSPM Deep Scan router (wave-6)")
    except ImportError:
        pass

    # CSPM Connector OSS family (apps/api/)
    try:
        from apps.api.cspm_connector_router import (
            router as cspm_connector_router,  # noqa: PLC0415
        )
        app.include_router(cspm_connector_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted CSPM Connector router (wave-6)")
    except ImportError:
        pass

    # Privilege Escalation Detector (apps/api/)
    try:
        from apps.api.privilege_escalation_detector_router import (
            router as privilege_escalation_detector_router,  # noqa: PLC0415
        )
        app.include_router(privilege_escalation_detector_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Privilege Escalation Detector router (wave-6)")
    except ImportError:
        pass

    _logger.info("CSPM sub-app: wave-6 loop-bound routers registered")
