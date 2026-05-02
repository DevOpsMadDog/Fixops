"""ASPM — Application Security Posture Management router registrar.

Wave 1 extraction from app.py (2026-04-28).

All 77 ASPM include_router calls that were scattered across create_app() have
been moved here.  Routes are registered directly on the *parent* FastAPI app
(registrar pattern) so ``len(app.routes)`` is unchanged and the RISK-01 route-
count gate continues to pass.

Usage (from create_app in app.py)::

    from apps.api.sub_apps.aspm_app import register_aspm_routers
    register_aspm_routers(app, _verify_api_key, _require_scope, _logger)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

from fastapi import Depends

if TYPE_CHECKING:
    from fastapi import FastAPI

_log = logging.getLogger(__name__)


def register_aspm_routers(
    app: "FastAPI",
    _verify_api_key: Callable[..., Any],
    _require_scope: Callable[..., Any],
    _logger: logging.Logger | None = None,
) -> None:
    """Register all ASPM routers onto *app* in the same order as app.py Wave 1.

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
    # Early ASPM registrations (formerly at L3396-L3594 in app.py)
    # ------------------------------------------------------------------

    # Unified Triage — crown jewel (finding + attack path + compliance + SLA)
    try:
        from apps.api.triage_router import router as triage_router  # noqa: PLC0415
    except ImportError:
        triage_router = None  # type: ignore[assignment]
    if triage_router is not None:
        app.include_router(triage_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])

    # Wave C changes router — mount BEFORE change_management_router to avoid shadowing
    try:
        from apps.api.wave_c_router import changes_router as _wc_changes_router
        app.include_router(_wc_changes_router)
        _logger.info("Mounted Wave C changes router (precedence over change_management)")
    except ImportError:
        pass

    # CI/CD Gate — auth handled internally via api_key_auth dependency
    try:
        from apps.api.gate_router import router as gate_router  # noqa: PLC0415
        app.include_router(gate_router)
        _logger.info("Mounted CI/CD Gate router")
    except ImportError:
        pass

    # Remediation
    try:
        from apps.api.remediation_router import (
            router as remediation_router,  # noqa: PLC0415
        )
        app.include_router(remediation_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
    except ImportError:
        pass

    # Wave A code-intel routers — 19 graph/dca/reachability/components/ide/runtime endpoints
    try:
        from apps.api.wave_a_code_intel_router import WAVE_A_ROUTERS as _wave_a_routers
        for _wa_router in _wave_a_routers:
            app.include_router(_wa_router)
        _logger.info(
            "Mounted Wave A code-intel routers (%d) — 19 graph/dca/reachability/components/ide/runtime endpoints",
            len(_wave_a_routers),
        )
    except ImportError:
        pass

    # Validation router — compatibility checking for security tool outputs
    try:
        from apps.api.validation_router import (
            router as validation_router,  # noqa: PLC0415
        )
    except ImportError:
        validation_router = None  # type: ignore[assignment]
    if validation_router:
        app.include_router(validation_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])

    # ------------------------------------------------------------------
    # API Security Engine — OWASP API Top 10 scanning
    # ------------------------------------------------------------------
    try:
        from apps.api.api_security_router import router as api_security_router
        app.include_router(api_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Loaded API Security router")
    except ImportError as _e:
        _logger.warning("API Security router not available: %s", _e)

    # Container Runtime Security — image analysis, CIS Docker Benchmark
    try:
        from apps.api.container_runtime_router import router as container_runtime_router
        app.include_router(container_runtime_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Container Runtime Security router")
    except ImportError as _cr_err:
        _logger.warning("Container Runtime router not available: %s", _cr_err)

    # Application Security — SAST/DAST findings, scan runs, appsec stats
    try:
        from apps.api.application_security_router import (
            router as application_security_router,
        )
        app.include_router(application_security_router)
        _logger.info("Mounted Application Security router")
    except ImportError as _as_err:
        _logger.warning("Application Security router not available: %s", _as_err)

    # Application Security (AppSec) — SAST/DAST scans, findings, OWASP tracking
    try:
        from apps.api.app_security_router import router as app_security_router
        app.include_router(app_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted AppSec router at /api/v1/app-security")
    except Exception as e:
        _logger.warning(f"AppSec router not loaded: {e}")

    # Mobile Security Engine — device MDM, threats, policies
    try:
        from apps.api.mobile_security_router import router as mobile_security_router
        app.include_router(mobile_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Mobile Security router at /api/v1/mobile-security")
    except Exception as e:
        _logger.warning(f"Mobile Security router not loaded: {e}")

    # Supply Chain Risk — suppliers, components, risks, SBOM import
    try:
        from apps.api.supply_chain_risk_router import router as supply_chain_risk_router
        app.include_router(supply_chain_risk_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Supply Chain Risk router at /api/v1/supply-chain")
    except Exception as e:
        _logger.warning(f"Supply chain risk router not loaded: {e}")

    # Vulnerability Scanner — scanners, schedules, results, findings, stats
    try:
        from apps.api.vuln_scanner_router import router as vuln_scanner_router
        app.include_router(vuln_scanner_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Vuln Scanner router at /api/v1/vuln-scanner")
    except Exception as e:
        _logger.warning(f"Vuln Scanner router not loaded: {e}")

    # DevSecOps Pipeline Security Engine — CI/CD gate policies, runs, findings
    try:
        from apps.api.devsecops_router import router as devsecops_router
        app.include_router(devsecops_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted DevSecOps router at /api/v1/devsecops")
    except Exception as e:
        _logger.warning(f"DevSecOps router not loaded: {e}")

    # ------------------------------------------------------------------
    # Late-wired ASPM routers (formerly wave 30-42+ blocks in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.ai_code_scanner_router import router as ai_code_scanner_router
        app.include_router(ai_code_scanner_router)
        _logger.info("Mounted AI Code Scanner router at /api/v1/ai-scan")
    except ImportError:
        pass

    try:
        from apps.api.sbom_router import router as _sbom_router_late
        app.include_router(_sbom_router_late)
        _logger.info("Mounted SBOM router at /api/v1/sbom")
    except ImportError:
        pass

    try:
        from apps.api.patch_automation_router import router as patch_automation_router
        app.include_router(patch_automation_router)
        _logger.info("Mounted Patch Automation router at /api/v1/patch-automation")
    except ImportError:
        pass

    try:
        from apps.api.secret_scanner_engine_router import (
            router as secret_scanner_engine_router,
        )
        app.include_router(secret_scanner_engine_router)
        _logger.info("Mounted Secret Scanner Engine router at /api/v1/secret-scanner")
    except ImportError:
        pass

    try:
        from apps.api.vuln_workflow_router import router as vuln_workflow_router
        app.include_router(vuln_workflow_router)
        _logger.info("Mounted Vuln Workflow router at /api/v1/vuln-workflow")
    except ImportError:
        pass

    try:
        from apps.api.api_security_engine_router import (
            router as api_security_engine_router,
        )
        app.include_router(api_security_engine_router)
    except ImportError:
        pass

    try:
        from apps.api.api_security_mgmt_router import router as api_security_mgmt_router
        app.include_router(api_security_mgmt_router)
        _logger.info("Mounted API Security Mgmt router at /api/v1/api-security-engine")
    except ImportError:
        pass

    try:
        from apps.api.supply_chain_router import router as supply_chain_crud_router
        app.include_router(supply_chain_crud_router)
        _logger.info("Mounted Supply Chain CRUD router at /api/v1/supply-chain (components/vendors/stats/sync)")
    except ImportError as _e:
        _logger.warning("Supply Chain CRUD router not available: %s", _e)

    try:
        from apps.api.secret_scanner_router import router as _secret_scanner_late
        app.include_router(_secret_scanner_late)
    except ImportError:
        pass

    try:
        from apps.api.secrets_management_router import (
            router as secrets_management_router,
        )
        app.include_router(secrets_management_router)
        _logger.info("Mounted Secrets Management router at /api/v1/secrets-management")
    except ImportError:
        pass

    try:
        from apps.api.vulnerability_remediation_router import (
            router as vulnerability_remediation_router,
        )
        app.include_router(vulnerability_remediation_router)
        _logger.info("Mounted Vulnerability Remediation router at /api/v1/vuln-remediation")
    except ImportError:
        pass

    try:
        from apps.api.api_gateway_security_router import (
            router as api_gateway_security_router,
        )
        app.include_router(api_gateway_security_router)
        _logger.info("Mounted API Gateway Security router at /api/v1/api-gateway-security")
    except ImportError:
        pass

    try:
        from apps.api.asset_lifecycle_router import router as asset_lifecycle_router
        app.include_router(asset_lifecycle_router)
        _logger.info("Mounted Asset Lifecycle router at /api/v1/asset-lifecycle")
    except ImportError:
        pass

    try:
        from apps.api.supply_chain_monitoring_router import (
            router as supply_chain_monitoring_router,
        )
        app.include_router(supply_chain_monitoring_router)
        _logger.info("Mounted Supply Chain Monitoring router at /api/v1/supply-chain-monitoring")
    except ImportError:
        pass

    try:
        from apps.api.malicious_pkg_router import router as malicious_pkg_router
        app.include_router(malicious_pkg_router)
        _logger.info("Mounted Malicious Package router at /api/v1/malicious-pkg")
    except ImportError:
        pass

    try:
        from apps.api.container_runtime_security_router import (
            router as container_runtime_security_router,
        )
        app.include_router(container_runtime_security_router)
        _logger.info("Mounted Container Runtime Security router at /api/v1/container-runtime")
    except ImportError:
        pass

    try:
        from apps.api.api_discovery_router import router as api_discovery_router
        app.include_router(api_discovery_router)
        _logger.info("Mounted API Discovery router at /api/v1/api-discovery")
    except ImportError:
        pass

    try:
        from apps.api.browser_security_router import router as browser_security_router
        app.include_router(browser_security_router)
        _logger.info("Mounted Browser Security router at /api/v1/browser-security")
    except ImportError:
        pass

    try:
        from apps.api.firmware_security_router import router as firmware_security_router
        app.include_router(firmware_security_router)
        _logger.info("Mounted Firmware Security router at /api/v1/firmware-security")
    except ImportError:
        pass

    try:
        from apps.api.mobile_app_security_router import (
            router as mobile_app_security_router,
        )
        app.include_router(mobile_app_security_router)
        _logger.info("Mounted Mobile App Security router at /api/v1/mobile-app-security")
    except ImportError:
        pass

    try:
        from apps.api.api_abuse_detection_router import (
            router as api_abuse_detection_router,
        )
        app.include_router(api_abuse_detection_router)
        _logger.info("Mounted API Abuse Detection router at /api/v1/api-abuse")
    except ImportError:
        pass

    try:
        from apps.api.autonomous_remediation_router import (
            router as autonomous_remediation_router,
        )
        app.include_router(autonomous_remediation_router)
        _logger.info("Mounted Autonomous Remediation router at /api/v1/autonomous-remediation")
    except ImportError:
        pass

    try:
        from apps.api.application_risk_router import router as application_risk_router
        app.include_router(application_risk_router)
        _logger.info("Mounted Application Risk router at /api/v1/app-risk")
    except ImportError:
        pass

    try:
        from apps.api.api_threat_protection_router import (
            router as api_threat_protection_router,
        )
        app.include_router(api_threat_protection_router)
        _logger.info("Mounted API Threat Protection router at /api/v1/api-threat-protection")
    except ImportError:
        pass

    try:
        from apps.api.dev_identity_router import router as dev_identity_router
        app.include_router(dev_identity_router)
        _logger.info("Mounted Dev Identity router at /api/v1/dev-identity")
    except ImportError:
        pass

    try:
        from apps.api.vulnerability_workflow_router import (
            router as vulnerability_workflow_router,
        )
        app.include_router(vulnerability_workflow_router)
        _logger.info("Mounted Vulnerability Workflow router at /api/v1/vuln-workflow")
    except ImportError:
        pass

    try:
        from apps.api.universal_ingest_router import router as universal_ingest_router
        app.include_router(universal_ingest_router)
        _logger.info("Mounted Universal Ingest router at /api/v1/ingest")
    except ImportError:
        pass

    try:
        from apps.api.patch_management_router import router as patch_management_router
        app.include_router(patch_management_router)
        _logger.info("Mounted Patch Management router at /api/v1/patch-management")
    except ImportError:
        pass

    try:
        from apps.api.api_inventory_router import router as api_inventory_router
        app.include_router(api_inventory_router)
        _logger.info("Mounted API Inventory router at /api/v1/api-inventory")
    except ImportError:
        pass

    try:
        from apps.api.vuln_scan_router import router as vuln_scan_router
        app.include_router(vuln_scan_router)
        _logger.info("Mounted Vuln Scan router at /api/v1/vuln-scans")
    except ImportError:
        pass

    try:
        from apps.api.asset_tagging_router import router as asset_tagging_router
        app.include_router(asset_tagging_router)
        _logger.info("Mounted Asset Tagging router at /api/v1/asset-tags")
    except ImportError:
        pass

    try:
        from apps.api.security_findings_router import router as security_findings_router
        app.include_router(security_findings_router)
        _logger.info("Mounted Security Findings router at /api/v1/security-findings")
    except ImportError:
        pass

    try:
        from apps.api.unified_issues_router import router as unified_issues_router
        app.include_router(unified_issues_router)
        _logger.info("Mounted Unified Issues router at /api/v1/issues (GAP-049+066)")
    except ImportError:
        pass

    try:
        from apps.api.security_dependency_risk_router import (
            router as security_dependency_risk_router,
        )
        app.include_router(security_dependency_risk_router)
        _logger.info("Mounted Security Dependency Risk router at /api/v1/dependency-risk")
    except ImportError:
        pass

    try:
        from apps.api.sbom_reeval_router import router as sbom_reeval_router
        app.include_router(sbom_reeval_router)
        _logger.info("Mounted SBOM Re-Eval router at /api/v1/sbom-reeval")
    except ImportError:
        pass

    try:
        from apps.api.sbom_export_router import router as sbom_export_router
        app.include_router(sbom_export_router)
        _logger.info("Mounted SBOM Export router at /api/v1/sbom-export")
    except ImportError:
        pass

    try:
        from apps.api.pipeline_bom_router import router as pipeline_bom_router
        app.include_router(pipeline_bom_router)
        _logger.info("Mounted Pipeline BOM (PBOM) router at /api/v1/pbom")
    except ImportError:
        pass

    try:
        from apps.api.github_app_router import (
            router as github_app_router,
        )
        from apps.api.github_app_router import (
            router_hooks as hooks_yaml_router,
        )
        app.include_router(github_app_router)
        app.include_router(hooks_yaml_router)
        _logger.info(
            "Mounted GitHub App router at /api/v1/github-app and "
            "Hooks YAML router at /api/v1/hooks-yaml"
        )
    except ImportError:
        pass

    try:
        from apps.api.github_app_autofix_router import (
            router as github_app_autofix_router,
        )
        app.include_router(github_app_autofix_router)
        _logger.info("Mounted GitHub App AutoFix router at /api/v1/github-app/autofix")
    except ImportError:
        pass

    try:
        from apps.api.slsa_provenance_router import router as slsa_provenance_router
        app.include_router(slsa_provenance_router)
        _logger.info("Mounted SLSA Provenance router at /api/v1/slsa")
    except ImportError:
        pass

    try:
        from apps.api.findings_wave_b_router import router as _findings_wave_b_router
        app.include_router(_findings_wave_b_router)
        _logger.info("Mounted Wave B findings/risk/scoring router (16 routes)")
    except ImportError as exc:
        _logger.warning("Wave B router not loaded: %s", exc)

    try:
        from apps.api.dynamic_rule_dsl_router import router as dynamic_rule_dsl_router
        app.include_router(dynamic_rule_dsl_router)
        _logger.info("Mounted Dynamic Rule DSL router at /api/v1/rules/dsl")
    except ImportError:
        pass

    # GAP-063 Findings Lifecycle — firstSeenAt/previousViolationId/resolvedAt chain
    try:
        from apps.api.findings_lifecycle_router import (
            router as findings_lifecycle_router,
        )
        app.include_router(findings_lifecycle_router)
        _logger.info("Mounted Findings Lifecycle router at /api/v1/findings/lifecycle")
    except ImportError:
        pass

    try:
        from apps.api.security_dependency_mapping_router import (
            router as security_dependency_mapping_router,
        )
        app.include_router(security_dependency_mapping_router)
        _logger.info("Mounted Security Dependency Mapping router at /api/v1/dependency-mapping")
    except ImportError:
        pass

    # GAP-065 — architecture-aware graph (layer classifier + flow tracer)
    try:
        from apps.api.arch_graph_router import router as arch_graph_router
        app.include_router(arch_graph_router)
        _logger.info("Mounted Architecture-Aware Graph router at /api/v1/arch-graph")
    except ImportError:
        pass

    # GAP-010 — function-level reachability (Endor Labs moat)
    try:
        from apps.api.function_reachability_router import (
            router as function_reachability_router,
        )
        app.include_router(function_reachability_router)
        _logger.info("Mounted Function Reachability router at /api/v1/reachability")
    except ImportError:
        pass

    # GAP-013 code-to-runtime matcher (3-strategy runtime→code mapping)
    try:
        from apps.api.code_to_runtime_router import router as code_to_runtime_router
        app.include_router(code_to_runtime_router)
        _logger.info("Mounted Code→Runtime Matcher router at /api/v1/code-to-runtime")
    except ImportError:
        pass

    # GAP-012 Deep Code Analysis — Apiiro DCA parity
    try:
        from apps.api.deep_code_analysis_router import (
            router as deep_code_analysis_router,
        )
        app.include_router(deep_code_analysis_router)
        _logger.info("Mounted DCA router at /api/v1/dca")
    except ImportError:
        pass

    # NEW-G070 Semantic Analyzer — tree-sitter + LSP + ORM schema readers
    try:
        from apps.api.semantic_analyzer_router import router as semantic_analyzer_router
        app.include_router(semantic_analyzer_router)
        _logger.info("Mounted Semantic Analyzer router at /api/v1/semantic")
        _logger.info("Mounted Code-to-Runtime router at /api/v1/code-to-runtime")
    except ImportError:
        pass

    # Wave C — 21 endpoints: compliance/org/system/admin/tokens/cspm/skills/rules/llm
    try:
        from apps.api.wave_c_router import WAVE_C_ROUTERS as _wave_c_routers
        for _wc_router in _wave_c_routers:
            app.include_router(_wc_router)
        _logger.info("Mounted Wave C routers (%d) — 21 compliance/org/system endpoints", len(_wave_c_routers))
    except ImportError as _wc_exc:
        _logger.warning("Wave C router not mounted: %s", _wc_exc)

    try:
        from apps.api.code_ownership_router import router as code_ownership_router
        app.include_router(code_ownership_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Code Ownership router at /api/v1/ownership")
    except ImportError:
        pass

    try:
        from apps.api.container_registry_security_router import (
            router as container_registry_security_router,
        )
        app.include_router(container_registry_security_router)
        _logger.info("Mounted Container Registry Security router at /api/v1/container-registry-security")
    except ImportError:
        pass

    try:
        from apps.api.dep_scanner_router import router as dep_scanner_router
        app.include_router(dep_scanner_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Dependency Scanner router at /api/v1/dep-scanner")
    except ImportError:
        pass

    try:
        from apps.api.github_security_router import router as github_security_router
        app.include_router(github_security_router)
        _logger.info("Mounted GitHub Security router at /api/v1/security/github")
    except ImportError:
        pass

    try:
        from apps.api.graphql_router import router as graphql_router
        app.include_router(graphql_router)
        _logger.info("Mounted GraphQL router at /api/v1/graphql")
    except ImportError:
        pass

    try:
        from apps.api.iac_scanner_router import router as iac_scanner_router
        app.include_router(iac_scanner_router)
        _logger.info("Mounted IaC Scanner router at /api/v1/iac")
    except ImportError:
        pass

    try:
        from apps.api.license_scanner_router import router as license_scanner_router
        app.include_router(license_scanner_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted License Scanner router at /api/v1/license-scanner")
    except ImportError:
        pass

    try:
        from apps.api.patch_prioritizer_router import router as patch_prioritizer_router
        app.include_router(patch_prioritizer_router)
        _logger.info("Mounted Patch Prioritizer router at /api/v1/patch-priority")
    except ImportError:
        pass

    try:
        from apps.api.remediation_board_router import router as remediation_board_router
        app.include_router(remediation_board_router)
        _logger.info("Mounted Remediation Board router at /api/v1/remediation-board")
    except ImportError:
        pass

    try:
        from apps.api.secrets_rotation_router import router as secrets_rotation_router
        app.include_router(secrets_rotation_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Secrets Rotation router at /api/v1/secrets-rotation")
    except ImportError:
        pass

    try:
        from apps.api.software_composition_analysis_router import (
            router as software_composition_analysis_router,
        )
        app.include_router(software_composition_analysis_router)
        _logger.info("Mounted Software Composition Analysis router at /api/v1/sca")
    except ImportError:
        pass

    # GAP-008: Binary Fingerprint Engine (Sonatype ABF-style)
    try:
        from apps.api.binary_fingerprint_router import (
            router as binary_fingerprint_router,
        )
        app.include_router(binary_fingerprint_router)
        _logger.info("Mounted Binary Fingerprint router at /api/v1/binary-fp")
    except ImportError:
        pass

    # NEW-G071: IDE-in-browser backend (file tree + content + analysis snapshots + diff)
    try:
        from apps.api.ide_backend_router import router as ide_backend_router
        app.include_router(ide_backend_router)
        _logger.info("Mounted IDE Backend router at /api/v1/ide")
    except ImportError:
        pass

    # OSV (Open Source Vulnerabilities) feed — Google-run open vuln DB
    try:
        from apps.api.osv_router import router as osv_router
        app.include_router(osv_router)
        _logger.info("Mounted OSV router at /api/v1/osv")
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # Wave-6 — loop-bound ASPM entries (formerly in _core_routers /
    # _extra_apps_routers loops in app.py, deferred from Waves 1-5)
    # ------------------------------------------------------------------

    # Nerve Center — unified findings + risk dashboard (suite-core/api/)
    try:
        from api.nerve_center import router as nerve_center_router  # noqa: PLC0415
        app.include_router(nerve_center_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Nerve Center router (wave-6)")
    except ImportError:
        pass

    # Decisions — AI decision log and audit trail (suite-core/api/)
    try:
        from api.decisions import router as decisions_router  # noqa: PLC0415
        app.include_router(decisions_router, prefix="/api/v1", dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Decisions router (wave-6)")
    except ImportError:
        pass

    # Deduplication — finding dedup engine (suite-core/api/)
    try:
        from api.deduplication_router import (
            router as deduplication_router,  # noqa: PLC0415
        )
        app.include_router(deduplication_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Deduplication router (wave-6)")
    except ImportError:
        pass

    # Smart Dedup — ML-assisted deduplication (suite-core/api/)
    try:
        from api.smart_dedup_router import router as smart_dedup_router  # noqa: PLC0415
        app.include_router(smart_dedup_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Smart Dedup router (wave-6)")
    except ImportError:
        pass

    # AutoFix Verification — post-fix validation (suite-core/api/)
    try:
        from api.autofix_verify_router import (
            router as autofix_verify_router,  # noqa: PLC0415
        )
        app.include_router(autofix_verify_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted AutoFix Verification router (wave-6)")
    except ImportError:
        pass

    # MPTE Post-Fix Verification (suite-core/api/)
    try:
        from api.postfix_verify_router import (
            router as postfix_verify_router,  # noqa: PLC0415
        )
        app.include_router(postfix_verify_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted MPTE Post-Fix Verification router (wave-6)")
    except ImportError:
        pass

    # MITRE ATT&CK Application-Layer Mapper (suite-core/api/)
    try:
        from api.mitre_mapper_router import (
            router as mitre_mapper_router,  # noqa: PLC0415
        )
        app.include_router(mitre_mapper_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted MITRE ATT&CK Mapper router (wave-6)")
    except ImportError:
        pass

    # Supply Chain Security (suite-core/api/)
    try:
        from api.supply_chain_router import (
            router as supply_chain_router,  # noqa: PLC0415
        )
        app.include_router(supply_chain_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:sbom"))])
        _logger.info("Mounted Supply Chain Security router (wave-6)")
    except ImportError:
        pass

    # _extra_apps_routers ASPM entries (formerly loop-bound in app.py)

    # Container Scanner (apps/api/)
    try:
        from apps.api.container_scanner_router import (
            router as container_scanner_router,  # noqa: PLC0415
        )
        app.include_router(container_scanner_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Container Scanner router (wave-6)")
    except ImportError:
        pass

    # CI/CD Security (apps/api/)
    try:
        from apps.api.cicd_router import router as cicd_router  # noqa: PLC0415
        app.include_router(cicd_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted CI/CD router (wave-6)")
    except ImportError:
        pass

    # Context Engine — code context graph (apps/api/)
    try:
        from apps.api.context_engine_router import (
            router as context_engine_router,  # noqa: PLC0415
        )
        app.include_router(context_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Context Engine router (wave-6)")
    except ImportError:
        pass

    # Fix Engine — AutoFix dispatch (apps/api/)
    try:
        from apps.api.fix_engine_router import (
            router as fix_engine_router,  # noqa: PLC0415
        )
        app.include_router(fix_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Fix Engine router (wave-6)")
    except ImportError:
        pass

    # PR Generator — AutoFix PR creation (apps/api/)
    try:
        from apps.api.pr_generator_router import (
            router as pr_generator_router,  # noqa: PLC0415
        )
        app.include_router(pr_generator_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted PR Generator router (wave-6)")
    except ImportError:
        pass

    # SBOM (apps/api/)
    try:
        from apps.api.sbom_router import router as sbom_router  # noqa: PLC0415
        app.include_router(sbom_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:sbom"))])
        _logger.info("Mounted SBOM router (wave-6)")
    except ImportError:
        pass

    # Secret Scanner (apps/api/)
    try:
        from apps.api.secret_scanner_router import (
            router as secret_scanner_router,  # noqa: PLC0415
        )
        app.include_router(secret_scanner_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Secret Scanner router (wave-6)")
    except ImportError:
        pass

    # Bulk Operations (apps/api/)
    try:
        from apps.api.bulk_operations_router import (
            router as bulk_operations_router,  # noqa: PLC0415
        )
        app.include_router(bulk_operations_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Bulk Operations router (wave-6)")
    except ImportError:
        pass

    # Asset Inventory (apps/api/)
    try:
        from apps.api.asset_inventory_router import (
            router as asset_inventory_router,  # noqa: PLC0415
        )
        app.include_router(asset_inventory_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Asset Inventory router (wave-6)")
    except ImportError:
        pass

    # Patch Manager (apps/api/)
    try:
        from apps.api.patch_manager_router import (
            router as patch_manager_router,  # noqa: PLC0415
        )
        app.include_router(patch_manager_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Patch Manager router (wave-6)")
    except ImportError:
        pass

    # Validation — security tool output compatibility (apps/api/)
    try:
        from apps.api.verification_router import (
            router as verification_router,  # noqa: PLC0415
        )
        app.include_router(verification_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])
        _logger.info("Mounted Multi-Stage Verification router (wave-6)")
    except ImportError:
        pass

    _logger.info("ASPM sub-app: wave-6 loop-bound routers registered")
