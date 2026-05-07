from __future__ import annotations

import sys

sys.setrecursionlimit(5000)  # 453+ routers chain FastAPI lifespans recursively

import csv
import hashlib
import importlib.util
import io
import json
import logging
import os
import secrets
import shutil
import threading
import time
import uuid
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import SpooledTemporaryFile
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Optional, Tuple

# Auto-load .env file so FIXOPS_API_TOKEN, FIXOPS_JWT_SECRET etc. are
# available without manual `export` commands.
try:
    from dotenv import load_dotenv

    # Walk up from this file to find the repo-root .env
    _dotenv_path = Path(__file__).resolve().parents[2] / ".env"
    if _dotenv_path.is_file():
        load_dotenv(_dotenv_path, override=False)
    else:
        load_dotenv(override=False)  # searches cwd / parents
except ImportError:
    pass  # python-dotenv not installed — rely on shell env

import jwt

# ── PLATFORM CORE — Auth, Users, Teams, Admin, SLA, Workflows ─────────────────
from apps.api.audit_router import router as audit_router
from apps.api.audit_evidence_export_router import router as audit_evidence_export_router
from apps.api.support_router import router as support_router

# Evidence Chain router — tamper-proof cryptographic audit trail
evidence_chain_router: Optional[APIRouter] = None
try:
    from apps.api.evidence_chain_router import router as evidence_chain_router
    logging.getLogger(__name__).info("Loaded Evidence Chain router")
except ImportError as e:
    logging.getLogger(__name__).warning("Evidence Chain router not available: %s", e)

# Unified Triage router (crown jewel — finding + attack path + compliance + SLA in one call)
triage_router: Optional[APIRouter] = None
try:
    from apps.api.triage_router import router as triage_router
    logging.getLogger(__name__).info("Loaded Unified Triage router")
except ImportError as e:
    logging.getLogger(__name__).warning("Triage router not available: %s", e)
from apps.api.fail_router import router as fail_router

# APP_ID Configuration router (app registration, classification, lifecycle)
app_config_router: Optional[APIRouter] = None
try:
    from apps.api.app_config_router import router as app_config_router
    logging.getLogger(__name__).info("Loaded APP_ID Configuration router")
except ImportError as e:
    logging.getLogger(__name__).warning("APP_ID Configuration router not available: %s", e)

# Material Change Detection router (drift, SLA impact, blast radius)
material_change_router: Optional[APIRouter] = None
try:
    from apps.api.material_change_router import router as material_change_router
    logging.getLogger(__name__).info("Loaded Material Change Detection router")
except ImportError as e:
    logging.getLogger(__name__).warning("Material Change Detection router not available: %s", e)

# Anomaly Detection router (spike, drop, drift, threshold, unusual timing)
anomaly_router: Optional[APIRouter] = None
try:
    from apps.api.anomaly_router import router as anomaly_router
    logging.getLogger(__name__).info("Loaded Anomaly Detection router")
except ImportError as e:
    logging.getLogger(__name__).warning("Anomaly Detection router not available: %s", e)

# Anomaly ML Engine — behavioral analytics, UEBA, isolation forest, feedback loop
anomaly_ml_router: Optional[APIRouter] = None
try:
    from apps.api.anomaly_ml_router import router as anomaly_ml_router
    logging.getLogger(__name__).info("Loaded Anomaly ML Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Anomaly ML Engine router not available: %s", e)

# NDR router (asset discovery, segmentation, firewall audit, DNS, TLS, flows, zero trust)
network_security_router: Optional[APIRouter] = None
try:
    from apps.api.network_security_router import router as network_security_router
    logging.getLogger(__name__).info("Loaded Network Security (NDR) router")
except ImportError as e:
    logging.getLogger(__name__).warning("Network Security router not available: %s", e)

# AI Orchestrator router (multi-agent LLM coordination for security decisions)
ai_orchestrator_router: Optional[APIRouter] = None
try:
    from apps.api.ai_orchestrator_router import router as ai_orchestrator_router
    logging.getLogger(__name__).info("Loaded AI Orchestrator router")
except ImportError as e:
    logging.getLogger(__name__).warning("AI Orchestrator router not available: %s", e)

# Universal Connectors router (Jira + GitHub + Slack fan-out)
connectors_router: Optional[APIRouter] = None
try:
    from apps.api.connectors_router import router as connectors_router

    logging.getLogger(__name__).info("Loaded Universal Connectors router")
except ImportError as e:
    logging.getLogger(__name__).warning("Connectors router not available: %s", e)

# IAM/SSO Connector — REAL Keycloak-backed replacement for
# Okta / Auth0 / Microsoft Entra / OneLogin / Google Workspace stubs.
iam_sso_router: Optional[APIRouter] = None
try:
    from apps.api.iam_sso_router import router as iam_sso_router

    logging.getLogger(__name__).info("Loaded IAM/SSO Connector router (Keycloak)")
except ImportError as e:
    logging.getLogger(__name__).warning("IAM/SSO Connector router not available: %s", e)

# Container Security Connector — REAL OSS replacements for Aqua/Twistlock/Snyk
# Container/Sysdig/NeuVector via Trivy + Grype + Dockle + kube-bench.
container_security_connector_router: Optional[APIRouter] = None
try:
    from apps.api.container_security_connector_router import (
        router as container_security_connector_router,
    )

    logging.getLogger(__name__).info("Loaded Container Security Connector router")
except ImportError as e:
    logging.getLogger(__name__).warning(
        "Container Security Connector router not available: %s", e
    )

# Org Management router (multi-tenancy CRUD)
org_router: Optional[APIRouter] = None
try:
    from apps.api.org_router import router as org_router

    logging.getLogger(__name__).info("Loaded Org Management router")
except ImportError as e:
    logging.getLogger(__name__).warning("Org Management router not available: %s", e)

# Org GDPR Export router (right-to-portability)
org_export_router: Optional[APIRouter] = None
try:
    from apps.api.org_export_router import router as org_export_router
    logging.getLogger(__name__).info("Loaded Org GDPR Export router")
except ImportError as e:
    logging.getLogger(__name__).warning("Org GDPR Export router not available: %s", e)

# ServiceNow Bidirectional Sync router (SSRF-VULN-03)
servicenow_sync_router: Optional[APIRouter] = None
servicenow_sync_webhook_router: Optional[APIRouter] = None
try:
    from apps.api.servicenow_sync_router import router as servicenow_sync_router
    from apps.api.servicenow_sync_router import (
        webhook_router as servicenow_sync_webhook_router,
    )

    logging.getLogger(__name__).info("Loaded ServiceNow Sync router")
except ImportError as e:
    logging.getLogger(__name__).warning("ServiceNow Sync router not available: %s", e)

# ── CICD / GATE / INVENTORY ───────────────────────────────────────────────────
from apps.api.inventory_router import router as inventory_router

# PR Gate & CI/CD Gate router (PR gating, check runs, CI exit-code gate)
pr_gate_router: Optional[APIRouter] = None
try:
    from apps.api.pr_gate_router import router as pr_gate_router
    logging.getLogger(__name__).info("Loaded PR Gate router")
except ImportError as e:
    logging.getLogger(__name__).warning("PR Gate router not available: %s", e)
from apps.api.policies_router import router as policies_router
from apps.api.policy_engine_router import router as policy_engine_router

# Wave D — 22 integrations/AI/policy endpoints (Multica)
try:
    from apps.api.wave_d_integrations_router import router as wave_d_integrations_router
except ImportError as _wave_d_err:
    wave_d_integrations_router = None
    logging.getLogger(__name__).warning("Wave D integrations router not available: %s", _wave_d_err)

# Wave A — Code / Architecture intel (19 endpoints across graph/dca/reachability/components/ide/runtime)
try:
    from apps.api.wave_a_code_intel_router import WAVE_A_ROUTERS as _wave_a_routers
except ImportError as _wave_a_err:
    _wave_a_routers = None
    logging.getLogger(__name__).warning("Wave A code-intel routers not available: %s", _wave_a_err)

# Hooks router — POST /api/v1/hooks/uninstall (Multica 5894d7d7)
try:
    from apps.api.hooks_router import router as hooks_router
except ImportError as _hooks_err:
    hooks_router = None
    logging.getLogger(__name__).warning("Hooks router not available: %s", _hooks_err)
from apps.api.reports_router import router as reports_router

# ── ADMIN / SYSTEM / USERS ────────────────────────────────────────────────────

# Enterprise SSO router (SAML 2.0 + OIDC — Okta, Azure AD, Google)
sso_router: Optional[APIRouter] = None
try:
    from apps.api.sso_router import router as sso_router
    logging.getLogger(__name__).info("Loaded Enterprise SSO router")
except ImportError as e:
    logging.getLogger(__name__).warning("SSO router not available: %s", e)

# Phase 10: New routers for E2E pipeline
# NOTE: websocket_routes.py was removed 2026-05-02 — top-level `from suite_core.core...`
# import was broken (silently swallowed) and the router was never mounted. Replaced by
# canonical Wave-3 ws_trustgraph_events_router.py mounted in create_app() at /ws/events.
# See FEATURE-3 (commit f098e412) for the canonical TrustGraph WebSocket spec.

# WebSocket Alerts router — real-time security alert feed + test-broadcast endpoint
websocket_alerts_router: Optional[APIRouter] = None
try:
    from apps.api.websocket_alerts_router import router as websocket_alerts_router
    logging.getLogger(__name__).info("Loaded WebSocket Alerts router")
except ImportError as e:
    logging.getLogger(__name__).warning("WebSocket Alerts router not available: %s", e)

# WS Events router — unified security event stream at /api/v1/ws/events
ws_events_router: Optional[APIRouter] = None
try:
    from apps.api.ws_events_router import router as ws_events_router
    logging.getLogger(__name__).info("Loaded WS Events router")
except ImportError as e:
    logging.getLogger(__name__).warning("WS Events router not available: %s", e)

# MCP/GraphRAG router for knowledge graph integration
mcp_router: Optional[APIRouter] = None
try:
    from apps.api.mcp_routes import router as mcp_router
    logging.getLogger(__name__).info("Loaded MCP/GraphRAG router")
except ImportError as e:
    logging.getLogger(__name__).warning("MCP/GraphRAG router not available: %s", e)

# MCP Gateway — external AI agent interface (search_findings, get_posture_score, etc.)
mcp_gateway_router: Optional[APIRouter] = None
try:
    from apps.api.mcp_gateway_router import router as mcp_gateway_router
    logging.getLogger(__name__).info("Loaded MCP Gateway router")
except ImportError as e:
    logging.getLogger(__name__).warning("MCP Gateway router not available: %s", e)

# Playbook automation router
playbook_router: Optional[APIRouter] = None
try:
    from apps.api.playbook_routes import router as playbook_router
    logging.getLogger(__name__).info("Loaded Playbook automation router")
except ImportError as e:
    logging.getLogger(__name__).warning("Playbook automation router not available: %s", e)

# Purple Team Exercise Engine (red+blue collaborative exercises, MITRE ATT&CK, after-action reports)
purple_team_router: Optional[APIRouter] = None
try:
    from apps.api.purple_team_router import router as purple_team_router
    logging.getLogger(__name__).info("Loaded Purple Team router")
except ImportError as e:
    logging.getLogger(__name__).warning("Purple Team router not available: %s", e)

# TrustGraph knowledge graph router (5 Knowledge Cores, MCP tools, entity management)
trustgraph_router: Optional[APIRouter] = None
try:
    from apps.api.trustgraph_routes import router as trustgraph_router
    logging.getLogger(__name__).info("Loaded TrustGraph router")
except ImportError as e:
    logging.getLogger(__name__).warning("TrustGraph router not available: %s", e)

# TrustGraph Quality Monitor router (coverage, orphans, backfill, stats, issues)
trustgraph_quality_router: Optional[APIRouter] = None
try:
    from apps.api.trustgraph_quality_router import router as trustgraph_quality_router
    logging.getLogger(__name__).info("Loaded TrustGraph Quality router")
except ImportError as e:
    logging.getLogger(__name__).warning("TrustGraph Quality router not available: %s", e)

# TrustGraph Maintenance router (integrity sweep, core health, auto-fix, issues)
trustgraph_maintenance_router: Optional[APIRouter] = None
try:
    from apps.api.trustgraph_maintenance_router import (
        router as trustgraph_maintenance_router,
    )
    logging.getLogger(__name__).info("Loaded TrustGraph Maintenance router")
except ImportError as e:
    logging.getLogger(__name__).warning("TrustGraph Maintenance router not available: %s", e)

# Findings lifecycle management router (status, assignment, SLA, bulk ops, export)
findings_router: Optional[APIRouter] = None
try:
    from apps.api.findings_routes import router as findings_router
    logging.getLogger(__name__).info("Loaded Findings management router")
except ImportError as e:
    logging.getLogger(__name__).warning("Findings management router not available: %s", e)

# Security Findings Engine router — unified findings aggregator (SAST/DAST/SIEM/etc.)
security_findings_router: Optional[APIRouter] = None
try:
    from apps.api.security_findings_router import router as security_findings_router
    logging.getLogger(__name__).info("Loaded Security Findings Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Security Findings Engine router not available: %s", e)

# Risk Register — enterprise risk lifecycle (CRUD, scoring, KRI, heat map, board report)
risk_register_router: Optional[APIRouter] = None
try:
    from apps.api.risk_register_router import router as risk_register_router
    logging.getLogger(__name__).info("Loaded Risk Register router")
except ImportError as e:
    logging.getLogger(__name__).warning("Risk Register router not available: %s", e)

# Vulnerability lifecycle tracker (DISCOVERED → TRIAGED → … → CLOSED)
vuln_lifecycle_router: Optional[APIRouter] = None
try:
    from apps.api.vuln_lifecycle_router import router as vuln_lifecycle_router
    logging.getLogger(__name__).info("Loaded Vuln Lifecycle router")
except ImportError as e:
    logging.getLogger(__name__).warning("Vuln Lifecycle router not available: %s", e)

# CTEM 15-stage pipeline REST API (ingest, batch processing, stage monitoring)
ctem_pipeline_router: Optional[APIRouter] = None
try:
    from apps.api.pipeline_routes import router as ctem_pipeline_router
    logging.getLogger(__name__).info("Loaded CTEM Pipeline router")
except ImportError as e:
    logging.getLogger(__name__).warning("CTEM Pipeline router not available: %s", e)

# soar_router — moved to ctem_app.py (Wave-C-final 2026-05-03; was split-mount L316/L3137)

# Security Metrics & OKR Tracking — DORA metrics, benchmarks, SLA, ROI, reports
security_metrics_router: Optional[APIRouter] = None
try:
    from apps.api.security_metrics_router import router as security_metrics_router
    logging.getLogger(__name__).info("Loaded Security Metrics & OKR router")
except ImportError as e:
    logging.getLogger(__name__).warning("Security Metrics router not available: %s", e)

# ir_playbook_router — moved to ctem_app.py (Wave-C-final 2026-05-03; was split-mount L332/L3153)
# ir_playbook_runner_router — moved to ctem_app.py (Wave-C-final 2026-05-03; was split-mount L340/L3161)

# Security Policy Document Generator — auto-generate policies from platform config
policy_generator_router: Optional[APIRouter] = None
try:
    from apps.api.policy_generator_router import router as policy_generator_router
    logging.getLogger(__name__).info("Loaded Policy Generator router")
except ImportError as e:
    logging.getLogger(__name__).warning("Policy Generator router not available: %s", e)

# Cloud Discovery — multi-cloud asset inventory (AWS, Azure, GCP)
cloud_discovery_router: Optional[APIRouter] = None
try:
    from apps.api.cloud_discovery_router import router as cloud_discovery_router
    logging.getLogger(__name__).info("Loaded Cloud Discovery router")
except ImportError as e:
    logging.getLogger(__name__).warning("Cloud Discovery router not available: %s", e)

# Enhanced LLM Council — calibration, feedback, recent verdicts
council_enhanced_router: Optional[APIRouter] = None
try:
    from apps.api.council_enhanced_router import router as council_enhanced_router
    logging.getLogger(__name__).info("Loaded Enhanced Council router")
except ImportError as e:
    logging.getLogger(__name__).warning("Enhanced Council router not available: %s", e)

# LLM Council — status, health, composition (GET /api/v1/llm/council/status)
llm_council_router: Optional[APIRouter] = None
try:
    from apps.api.llm_council_router import router as llm_council_router
    logging.getLogger(__name__).info("Loaded LLM Council router")
except ImportError as e:
    logging.getLogger(__name__).warning("LLM Council router not available: %s", e)

# Risk Scoring — module-level import so create_app() silent try/except can't swallow it
risk_scoring_router: Optional[APIRouter] = None
try:
    from apps.api.risk_scoring_router import router as risk_scoring_router
    logging.getLogger(__name__).info("Loaded Risk Scoring router")
except ImportError as e:
    logging.getLogger(__name__).warning("Risk Scoring router not available: %s", e)

# Compliance Reports — multi-framework compliance reporting
compliance_reports_router: Optional[APIRouter] = None
try:
    from apps.api.compliance_reports_router import router as compliance_reports_router
    logging.getLogger(__name__).info("Loaded Compliance Reports router")
except ImportError as e:
    logging.getLogger(__name__).warning("Compliance Reports router not available: %s", e)

# Integration Hub — Slack, Jira, PagerDuty, ServiceNow, Teams delivery engine
integration_hub_router: Optional[APIRouter] = None
try:
    from apps.api.integration_hub_router import router as integration_hub_router
    logging.getLogger(__name__).info("Loaded Integration Hub router")
except ImportError as e:
    logging.getLogger(__name__).warning("Integration Hub router not available: %s", e)

# threat_intel_router — moved to ctem_app.py (Wave-C-final 2026-05-03; was split-mount L404/L3187)

# Database Security Scanner — CIS benchmarks, privilege audit, data exposure, query audit
db_security_router: Optional[APIRouter] = None
try:
    from apps.api.db_security_router import router as db_security_router
    logging.getLogger(__name__).info("Loaded Database Security Scanner router")
except ImportError as e:
    logging.getLogger(__name__).warning("Database Security Scanner router not available: %s", e)

# API Analytics — usage monitoring and rate limit tracking
api_analytics_router: Optional[APIRouter] = None
try:
    from apps.api.api_analytics_router import router as api_analytics_router
    logging.getLogger(__name__).info("Loaded API Analytics router")
except ImportError as e:
    logging.getLogger(__name__).warning("API Analytics router not available: %s", e)

# API Gateway Security Engine — key management, rate limiting, IP filter, versioning, analytics
api_gateway_router: Optional[APIRouter] = None
try:
    from apps.api.api_gateway_router import router as api_gateway_router
    logging.getLogger(__name__).info("Loaded API Gateway Security router")
except ImportError as e:
    logging.getLogger(__name__).warning("API Gateway Security router not available: %s", e)

# correlation_router — moved to ctem_app.py (Wave-C-final 2026-05-03; was split-mount L436/L3212)

# Trivy Scanner — real Docker image / filesystem / repo vulnerability scanning
trivy_router: Optional[APIRouter] = None
try:
    from apps.api.trivy_router import router as trivy_router
    logging.getLogger(__name__).info("Loaded Trivy Scanner router")
except ImportError as e:
    logging.getLogger(__name__).warning("Trivy Scanner router not available: %s", e)

# Semgrep Scanner — SAST scanning via semgrep CLI
semgrep_router: Optional[APIRouter] = None
try:
    from apps.api.semgrep_router import router as semgrep_router
    logging.getLogger(__name__).info("Loaded Semgrep Scanner router")
except ImportError as e:
    logging.getLogger(__name__).warning("Semgrep Scanner router not available: %s", e)

# Snyk Scanner — Snyk REST API vulnerability data ingestion
snyk_router: Optional[APIRouter] = None
try:
    from apps.api.snyk_router import router as snyk_router
    logging.getLogger(__name__).info("Loaded Snyk Scanner router")
except ImportError as e:
    logging.getLogger(__name__).warning("Snyk Scanner router not available: %s", e)

# Snyk-OSS connector — REAL Snyk family via Trivy + OSV-Scanner + Semgrep CE
snyk_oss_router: Optional[APIRouter] = None
try:
    from apps.api.snyk_oss_router import router as snyk_oss_router
    logging.getLogger(__name__).info("Loaded Snyk-OSS (Trivy+OSV) connector router")
except ImportError as e:
    logging.getLogger(__name__).warning("Snyk-OSS connector router not available: %s", e)

# AWS Security Hub — pull findings from AWS Security Hub (ASFF normalization)
aws_security_hub_router: Optional[APIRouter] = None
try:
    from apps.api.aws_security_hub_router import router as aws_security_hub_router
    logging.getLogger(__name__).info("Loaded AWS Security Hub router")
except ImportError as e:
    logging.getLogger(__name__).warning("AWS Security Hub router not available: %s", e)

# Azure Defender — pull alerts/score/recommendations from Microsoft Defender for Cloud
azure_defender_router: Optional[APIRouter] = None
try:
    from apps.api.azure_defender_router import router as azure_defender_router
    logging.getLogger(__name__).info("Loaded Azure Defender router")
except ImportError as e:
    logging.getLogger(__name__).warning("Azure Defender router not available: %s", e)

# Backup & Disaster Recovery Validator router
backup_validator_router: Optional[APIRouter] = None
try:
    from apps.api.backup_validator_router import router as backup_validator_router
    logging.getLogger(__name__).info("Loaded Backup Validator router")
except ImportError as e:
    logging.getLogger(__name__).warning("Backup Validator router not available: %s", e)

# Unified Security Metrics Dashboard router (single-call, all personas)
unified_dashboard_router: Optional[APIRouter] = None
try:
    from apps.api.unified_dashboard_router import router as unified_dashboard_router
    logging.getLogger(__name__).info("Loaded Unified Dashboard router")
except ImportError as e:
    logging.getLogger(__name__).warning("Unified Dashboard router not available: %s", e)

# ── APPS/API DOMAIN ROUTERS ───────────────────────────────────────────────────
# Analytics, Asset, Backup, CSPM, Dashboard, Developer Portal, Evidence,
# Executive, Feed, Incident, IP, Metrics, Notification, Pentest, Risk,
# SBOM, Scanner, Security Scorecard, Vendor, Versioning, Webhook, Workflow
# ---------------------------------------------------------------------------
# Additional apps/api routers (wired in this session)
# ---------------------------------------------------------------------------
analytics_dashboard_router: Optional[APIRouter] = None
try:
    from apps.api.analytics_dashboard_router import router as analytics_dashboard_router
    logging.getLogger(__name__).info("Loaded Analytics Dashboard router")
except ImportError as e:
    logging.getLogger(__name__).warning("Analytics Dashboard router not available: %s", e)

analytics_routes_router: Optional[APIRouter] = None
try:
    from apps.api.analytics_routes import router as analytics_routes_router
    logging.getLogger(__name__).info("Loaded Analytics Routes router")
except ImportError as e:
    logging.getLogger(__name__).warning("Analytics Routes router not available: %s", e)

apikey_router: Optional[APIRouter] = None
try:
    from apps.api.apikey_router import router as apikey_router
    logging.getLogger(__name__).info("Loaded API Key management router")
except ImportError as e:
    logging.getLogger(__name__).warning("API Key router not available: %s", e)

asset_inventory_router: Optional[APIRouter] = None
try:
    from apps.api.asset_inventory_router import router as asset_inventory_router
    logging.getLogger(__name__).info("Loaded Asset Inventory router")
except ImportError as e:
    logging.getLogger(__name__).warning("Asset Inventory router not available: %s", e)

backup_router: Optional[APIRouter] = None
try:
    from apps.api.backup_router import router as backup_router
    logging.getLogger(__name__).info("Loaded Backup router")
except ImportError as e:
    logging.getLogger(__name__).warning("Backup router not available: %s", e)

patch_manager_router: Optional[APIRouter] = None
try:
    from apps.api.patch_manager_router import router as patch_manager_router
    logging.getLogger(__name__).info("Loaded Patch Manager router")
except ImportError as e:
    logging.getLogger(__name__).warning("Patch Manager router not available: %s", e)

bulk_operations_router: Optional[APIRouter] = None
try:
    from apps.api.bulk_operations_router import router as bulk_operations_router
    logging.getLogger(__name__).info("Loaded Bulk Operations router")
except ImportError as e:
    logging.getLogger(__name__).warning("Bulk Operations router not available: %s", e)

changelog_router: Optional[APIRouter] = None
try:
    from apps.api.changelog_router import router as changelog_router
    logging.getLogger(__name__).info("Loaded Changelog router")
except ImportError as e:
    logging.getLogger(__name__).warning("Changelog router not available: %s", e)

cicd_router: Optional[APIRouter] = None
try:
    from apps.api.cicd_router import router as cicd_router
    logging.getLogger(__name__).info("Loaded CI/CD router")
except ImportError as e:
    logging.getLogger(__name__).warning("CI/CD router not available: %s", e)

compliance_planner_router: Optional[APIRouter] = None
try:
    from apps.api.compliance_planner_router import router as compliance_planner_router
    logging.getLogger(__name__).info("Loaded Compliance Planner router")
except ImportError as e:
    logging.getLogger(__name__).warning("Compliance Planner router not available: %s", e)

container_scanner_router: Optional[APIRouter] = None
try:
    from apps.api.container_scanner_router import router as container_scanner_router
    logging.getLogger(__name__).info("Loaded Container Scanner router")
except ImportError as e:
    logging.getLogger(__name__).warning("Container Scanner router not available: %s", e)

cspm_engine_router: Optional[APIRouter] = None
try:
    from apps.api.cspm_engine_router import router as cspm_engine_router
    logging.getLogger(__name__).info("Loaded CSPM Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("CSPM Engine router not available: %s", e)

cspm_deep_router: Optional[APIRouter] = None
try:
    from apps.api.cspm_deep_router import router as cspm_deep_router
    logging.getLogger(__name__).info("Loaded CSPM Deep Scan router")
except ImportError as e:
    logging.getLogger(__name__).warning("CSPM Deep Scan router not available: %s", e)

cspm_connector_router: Optional[APIRouter] = None
try:
    from apps.api.cspm_connector_router import router as cspm_connector_router
    logging.getLogger(__name__).info("Loaded CSPM Connector (OSS family) router")
except ImportError as e:
    logging.getLogger(__name__).warning("CSPM Connector router not available: %s", e)

privilege_escalation_detector_router: Optional[APIRouter] = None
try:
    from apps.api.privilege_escalation_detector_router import (
        router as privilege_escalation_detector_router,
    )
    logging.getLogger(__name__).info("Loaded Privilege Escalation Detector router")
except ImportError as e:
    logging.getLogger(__name__).warning("Privilege Escalation Detector router not available: %s", e)

mitre_attack_coverage_router: Optional[APIRouter] = None
try:
    from apps.api.mitre_attack_coverage_router import (
        router as mitre_attack_coverage_router,
    )
    logging.getLogger(__name__).info("Loaded MITRE ATT&CK Coverage router")
except ImportError as e:
    logging.getLogger(__name__).warning("MITRE ATT&CK Coverage router not available: %s", e)

duckdb_analytics_router: Optional[APIRouter] = None
try:
    from apps.api.duckdb_analytics_router import router as duckdb_analytics_router
    logging.getLogger(__name__).info("Loaded DuckDB Analytics router")
except ImportError as e:
    logging.getLogger(__name__).warning("DuckDB Analytics router not available: %s", e)

verification_router: Optional[APIRouter] = None
try:
    from apps.api.verification_router import router as verification_router
    logging.getLogger(__name__).info("Loaded Multi-Stage Verification router")
except ImportError as e:
    logging.getLogger(__name__).warning("Verification router not available: %s", e)

intelligent_security_router: Optional[APIRouter] = None
try:
    from apps.api.intelligent_security_router import (
        router as intelligent_security_router,
    )
    logging.getLogger(__name__).info("Loaded Intelligent Security Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Intelligent Security router not available: %s", e)

graphrag_router: Optional[APIRouter] = None
try:
    from apps.api.graphrag_router import router as graphrag_router
    logging.getLogger(__name__).info("Loaded GraphRAG router")
except ImportError as e:
    logging.getLogger(__name__).warning("GraphRAG router not available: %s", e)

context_engine_router: Optional[APIRouter] = None
try:
    from apps.api.context_engine_router import router as context_engine_router
    logging.getLogger(__name__).info("Loaded Context Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Context Engine router not available: %s", e)

dashboard_builder_router: Optional[APIRouter] = None
try:
    from apps.api.dashboard_builder_router import router as dashboard_builder_router
    logging.getLogger(__name__).info("Loaded Dashboard Builder router")
except ImportError as e:
    logging.getLogger(__name__).warning("Dashboard Builder router not available: %s", e)

developer_portal_router: Optional[APIRouter] = None
try:
    from apps.api.developer_portal_router import router as developer_portal_router
    logging.getLogger(__name__).info("Loaded Developer Portal router")
except ImportError as e:
    logging.getLogger(__name__).warning("Developer Portal router not available: %s", e)

# API Documentation & Developer Portal — OpenAPI spec, Postman export, endpoint explorer
api_docs_router: Optional[APIRouter] = None
try:
    from apps.api.api_docs_router import router as api_docs_router
    logging.getLogger(__name__).info("Loaded API Docs router")
except ImportError as e:
    logging.getLogger(__name__).warning("API Docs router not available: %s", e)

drift_router: Optional[APIRouter] = None
try:
    from apps.api.drift_router import router as drift_router
    logging.getLogger(__name__).info("Loaded Drift router")
except ImportError as e:
    logging.getLogger(__name__).warning("Drift router not available: %s", e)

evidence_collector_router: Optional[APIRouter] = None
try:
    from apps.api.evidence_collector_router import router as evidence_collector_router
    logging.getLogger(__name__).info("Loaded Evidence Collector router")
except ImportError as e:
    logging.getLogger(__name__).warning("Evidence Collector router not available: %s", e)

exception_policy_router: Optional[APIRouter] = None
try:
    from apps.api.exception_policy_router import router as exception_policy_router
    logging.getLogger(__name__).info("Loaded Exception Policy router")
except ImportError as e:
    logging.getLogger(__name__).warning("Exception Policy router not available: %s", e)

executive_report_router: Optional[APIRouter] = None
try:
    from apps.api.executive_report_router import router as executive_report_router
    logging.getLogger(__name__).info("Loaded Executive Report router")
except ImportError as e:
    logging.getLogger(__name__).warning("Executive Report router not available: %s", e)

exec_security_reports_router: Optional[APIRouter] = None
try:
    from apps.api.exec_security_reports_router import (
        router as exec_security_reports_router,
    )
    logging.getLogger(__name__).info("Loaded Executive Security Reports router")
except ImportError as e:
    logging.getLogger(__name__).warning("Executive Security Reports router not available: %s", e)

feed_registry_router: Optional[APIRouter] = None
try:
    from apps.api.feed_registry_router import router as feed_registry_router
    logging.getLogger(__name__).info("Loaded Feed Registry router")
except ImportError as e:
    logging.getLogger(__name__).warning("Feed Registry router not available: %s", e)

feed_manager_router: Optional[APIRouter] = None
try:
    from apps.api.feed_manager_router import router as feed_manager_router
    logging.getLogger(__name__).info("Loaded Feed Manager router")
except ImportError as e:
    logging.getLogger(__name__).warning("Feed Manager router not available: %s", e)

fix_engine_router: Optional[APIRouter] = None
try:
    from apps.api.fix_engine_router import router as fix_engine_router
    logging.getLogger(__name__).info("Loaded Fix Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Fix Engine router not available: %s", e)

pipeline_bom_router: Optional[APIRouter] = None
try:
    from apps.api.pipeline_bom_router import router as pipeline_bom_router
    logging.getLogger(__name__).info("Loaded Pipeline BOM router")
except ImportError as e:
    logging.getLogger(__name__).warning("Pipeline BOM router not available: %s", e)

incident_response_router: Optional[APIRouter] = None
try:
    from apps.api.incident_response_router import router as incident_response_router
    logging.getLogger(__name__).info("Loaded Incident Response router")
except ImportError as e:
    logging.getLogger(__name__).warning("Incident Response router not available: %s", e)

breach_response_router: Optional[APIRouter] = None
try:
    from apps.api.breach_response_router import router as breach_response_router
    logging.getLogger(__name__).info("Loaded Breach Response router")
except ImportError as e:
    logging.getLogger(__name__).warning("Breach Response router not available: %s", e)

soc_automation_router: Optional[APIRouter] = None
try:
    from apps.api.soc_automation_router import router as soc_automation_router
    logging.getLogger(__name__).info("Loaded SOC Automation router")
except ImportError as e:
    logging.getLogger(__name__).warning("SOC Automation router not available: %s", e)

integration_health_router: Optional[APIRouter] = None
try:
    from apps.api.integration_health_router import router as integration_health_router
    logging.getLogger(__name__).info("Loaded Integration Health router")
except ImportError as e:
    logging.getLogger(__name__).warning("Integration Health router not available: %s", e)

ip_reputation_router: Optional[APIRouter] = None
try:
    from apps.api.ip_reputation_router import router as ip_reputation_router
    logging.getLogger(__name__).info("Loaded IP Reputation router")
except ImportError as e:
    logging.getLogger(__name__).warning("IP Reputation router not available: %s", e)

metrics_aggregator_router: Optional[APIRouter] = None
try:
    from apps.api.metrics_aggregator_router import router as metrics_aggregator_router
    logging.getLogger(__name__).info("Loaded Metrics Aggregator router")
except ImportError as e:
    logging.getLogger(__name__).warning("Metrics Aggregator router not available: %s", e)

notification_router: Optional[APIRouter] = None
try:
    from apps.api.notification_router import router as notification_router
    logging.getLogger(__name__).info("Loaded Notification router")
except ImportError as e:
    logging.getLogger(__name__).warning("Notification router not available: %s", e)

pentest_router: Optional[APIRouter] = None
try:
    from apps.api.pentest_router import router as pentest_router
    logging.getLogger(__name__).info("Loaded Pentest router")
except ImportError as e:
    logging.getLogger(__name__).warning("Pentest router not available: %s", e)

auto_pentest_router: Optional[APIRouter] = None
try:
    from apps.api.auto_pentest_router import router as auto_pentest_router
    logging.getLogger(__name__).info("Loaded Auto Pentest router")
except ImportError as e:
    logging.getLogger(__name__).warning("Auto Pentest router not available: %s", e)

posture_router: Optional[APIRouter] = None
try:
    from apps.api.posture_router import router as posture_router
    logging.getLogger(__name__).info("Loaded Posture router")
except ImportError as e:
    logging.getLogger(__name__).warning("Posture router not available: %s", e)

rasp_router: Optional[APIRouter] = None
try:
    from apps.api.rasp_router import router as rasp_router
    logging.getLogger(__name__).info("Loaded RASP router")
except ImportError as e:
    logging.getLogger(__name__).warning("RASP router not available: %s", e)

runtime_protection_router: Optional[APIRouter] = None
try:
    from apps.api.runtime_protection_router import router as runtime_protection_router
    logging.getLogger(__name__).info("Loaded Runtime Protection router")
except ImportError as e:
    logging.getLogger(__name__).warning("Runtime Protection router not available: %s", e)

posture_benchmark_router: Optional[APIRouter] = None
try:
    from apps.api.posture_benchmark_router import router as posture_benchmark_router
    logging.getLogger(__name__).info("Loaded Posture Benchmark router")
except ImportError as e:
    logging.getLogger(__name__).warning("Posture Benchmark router not available: %s", e)

pr_generator_router: Optional[APIRouter] = None
try:
    from apps.api.pr_generator_router import router as pr_generator_router
    logging.getLogger(__name__).info("Loaded PR Generator router")
except ImportError as e:
    logging.getLogger(__name__).warning("PR Generator router not available: %s", e)

prioritizer_router: Optional[APIRouter] = None
try:
    from apps.api.prioritizer_router import router as prioritizer_router
    logging.getLogger(__name__).info("Loaded Prioritizer router")
except ImportError as e:
    logging.getLogger(__name__).warning("Prioritizer router not available: %s", e)

rate_limit_router: Optional[APIRouter] = None
try:
    from apps.api.rate_limit_router import router as rate_limit_router
    logging.getLogger(__name__).info("Loaded Rate Limit router")
except ImportError as e:
    logging.getLogger(__name__).warning("Rate Limit router not available: %s", e)

tenant_rate_limiter_router: Optional[APIRouter] = None
try:
    from apps.api.tenant_rate_limiter_router import router as tenant_rate_limiter_router
    logging.getLogger(__name__).info("Loaded Tenant Rate Limiter router")
except ImportError as e:
    logging.getLogger(__name__).warning("Tenant Rate Limiter router not available: %s", e)

retention_router: Optional[APIRouter] = None
try:
    from apps.api.retention_router import router as retention_router
    logging.getLogger(__name__).info("Loaded Retention router")
except ImportError as e:
    logging.getLogger(__name__).warning("Retention router not available: %s", e)

risk_acceptance_router: Optional[APIRouter] = None
try:
    from apps.api.risk_acceptance_router import router as risk_acceptance_router
    logging.getLogger(__name__).info("Loaded Risk Acceptance router")
except ImportError as e:
    logging.getLogger(__name__).warning("Risk Acceptance router not available: %s", e)

# Risk Quantification Engine — FAIR-based financial risk modeling (ALE, Monte Carlo)
risk_quantifier_router: Optional[APIRouter] = None
try:
    from apps.api.risk_quantifier_router import router as risk_quantifier_router
    logging.getLogger(__name__).info("Loaded Risk Quantifier router")
except ImportError as e:
    logging.getLogger(__name__).warning("Risk Quantifier router not available: %s", e)

security_roi_router: Optional[APIRouter] = None
try:
    from apps.api.security_roi_router import router as security_roi_router
    logging.getLogger(__name__).info("Loaded Security ROI router")
except ImportError as e:
    logging.getLogger(__name__).warning("Security ROI router not available: %s", e)

sbom_router: Optional[APIRouter] = None
try:
    from apps.api.sbom_router import router as sbom_router
    logging.getLogger(__name__).info("Loaded SBOM router")
except ImportError as e:
    logging.getLogger(__name__).warning("SBOM router not available: %s", e)

secret_scanner_router: Optional[APIRouter] = None
try:
    from apps.api.secret_scanner_router import router as secret_scanner_router
    logging.getLogger(__name__).info("Loaded Secret Scanner router")
except ImportError as e:
    logging.getLogger(__name__).warning("Secret Scanner router not available: %s", e)

security_kb_router: Optional[APIRouter] = None
try:
    from apps.api.security_kb_router import router as security_kb_router
    logging.getLogger(__name__).info("Loaded Security KB router")
except ImportError as e:
    logging.getLogger(__name__).warning("Security KB router not available: %s", e)

slack_bot_router: Optional[APIRouter] = None
try:
    from apps.api.slack_bot_router import router as slack_bot_router
    logging.getLogger(__name__).info("Loaded Slack Bot router")
except ImportError as e:
    logging.getLogger(__name__).warning("Slack Bot router not available: %s", e)

system_health_router: Optional[APIRouter] = None
try:
    from apps.api.system_health_router import router as system_health_router
    logging.getLogger(__name__).info("Loaded System Health router")
except ImportError as e:
    logging.getLogger(__name__).warning("System Health router not available: %s", e)

tag_router: Optional[APIRouter] = None
try:
    from apps.api.tag_router import router as tag_router
    logging.getLogger(__name__).info("Loaded Tag router")
except ImportError as e:
    logging.getLogger(__name__).warning("Tag router not available: %s", e)

threat_hunting_router: Optional[APIRouter] = None
try:
    from apps.api.threat_hunting_router import router as threat_hunting_router
    logging.getLogger(__name__).info("Loaded Threat Hunting router")
except ImportError as e:
    logging.getLogger(__name__).warning("Threat Hunting router not available: %s", e)

user_analytics_router: Optional[APIRouter] = None
try:
    from apps.api.user_analytics_router import router as user_analytics_router
    logging.getLogger(__name__).info("Loaded User Analytics router")
except ImportError as e:
    logging.getLogger(__name__).warning("User Analytics router not available: %s", e)

vendor_scorecard_router: Optional[APIRouter] = None
try:
    from apps.api.vendor_scorecard_router import router as vendor_scorecard_router
    logging.getLogger(__name__).info("Loaded Vendor Scorecard router")
except ImportError as e:
    logging.getLogger(__name__).warning("Vendor Scorecard router not available: %s", e)

# Security Scorecard router (self-hosted SecurityScorecard-style scoring)
security_scorecard_router: Optional[APIRouter] = None
security_scorecard_public_router: Optional[APIRouter] = None
try:
    from apps.api.security_scorecard_router import (
        public_router as security_scorecard_public_router,
    )
    from apps.api.security_scorecard_router import router as security_scorecard_router
    logging.getLogger(__name__).info("Loaded Security Scorecard router")
except ImportError as e:
    logging.getLogger(__name__).warning("Security Scorecard router not available: %s", e)

regulatory_tracker_engine_router: Optional[APIRouter] = None
try:
    from apps.api.regulatory_tracker_engine_router import (
        router as regulatory_tracker_engine_router,
    )
    logging.getLogger(__name__).info("Loaded Regulatory Tracker Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Regulatory Tracker Engine router not available: %s", e)

security_scorecard_engine_router: Optional[APIRouter] = None
try:
    from apps.api.security_scorecard_engine_router import (
        router as security_scorecard_engine_router,
    )
    logging.getLogger(__name__).info("Loaded Security Scorecard Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Security Scorecard Engine router not available: %s", e)

questionnaire_router: Optional[APIRouter] = None
try:
    from apps.api.questionnaire_router import router as questionnaire_router
    logging.getLogger(__name__).info("Loaded Questionnaire Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Questionnaire Engine router not available: %s", e)

versioning_router: Optional[APIRouter] = None
try:
    from apps.api.versioning_router import router as versioning_router
    logging.getLogger(__name__).info("Loaded Versioning router")
except ImportError as e:
    logging.getLogger(__name__).warning("Versioning router not available: %s", e)

webhook_events_router: Optional[APIRouter] = None
try:
    from apps.api.webhook_events_router import router as webhook_events_router
    logging.getLogger(__name__).info("Loaded Webhook Events router")
except ImportError as e:
    logging.getLogger(__name__).warning("Webhook Events router not available: %s", e)

workflow_engine_router: Optional[APIRouter] = None
try:
    from apps.api.workflow_engine_router import router as workflow_engine_router
    logging.getLogger(__name__).info("Loaded Workflow Engine router")
except ImportError as e:
    logging.getLogger(__name__).warning("Workflow Engine router not available: %s", e)

from fastapi import (
    APIRouter,
    Body,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

# Validation router - compatibility checking for security tool outputs
validation_router: Optional[APIRouter] = None
try:
    from apps.api.validation_router import router as validation_router
except ImportError:
    logging.getLogger(__name__).warning("Validation router not available")


# Enterprise reachability analysis
reachability_router: Optional[APIRouter] = None
try:
    from risk.reachability.api import router as reachability_router
except ImportError:
    logging.getLogger(__name__).warning("Reachability analysis API not available")

# ---------------------------------------------------------------------------
# Suite-Attack routers (offensive security — from suite-attack/api/)
# ---------------------------------------------------------------------------
_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Boot identity — Bug B fix (playbook 2026-04-27)
# ---------------------------------------------------------------------------
# When SEs upgrade the binary mid-session, uvicorn doesn't reload routes; the
# playbook would then send the SE down a debugging rabbit hole. We resolve the
# running commit SHA at import time and surface it via /api/v1/system/git-sha
# so the playbook can detect "you're on stale code, restart this process".
def _detect_boot_git_sha() -> tuple[str, str]:
    """Resolve the SHA the running process was built from.

    Order: env var FIXOPS_GIT_COMMIT, then `git rev-parse HEAD` if .git exists,
    else 'unknown'. Failures are silent — this must never block app startup.
    """
    env_sha = os.getenv("FIXOPS_GIT_COMMIT", "").strip()
    if env_sha:
        return env_sha, "env:FIXOPS_GIT_COMMIT"
    try:
        import subprocess  # noqa: PLC0415
        repo_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        )
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip(), "git:rev-parse"
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        pass
    return "unknown", "fallback"


_BOOT_GIT_SHA, _BOOT_GIT_SHA_SOURCE = _detect_boot_git_sha()
_BOOT_AT_ISO = datetime.now(timezone.utc).isoformat()

# One-line banner so operators can confirm the running build at process start.
# If you upgraded the binary mid-session, RESTART this process — uvicorn does
# not auto-reload route registrations.
_logger.info(
    "ALDECI API boot: sha=%s (%s) at=%s — if you just upgraded the binary, "
    "RESTART this process; FastAPI does not hot-reload routers",
    (_BOOT_GIT_SHA[:12] if _BOOT_GIT_SHA != "unknown" else "unknown"),
    _BOOT_GIT_SHA_SOURCE,
    _BOOT_AT_ISO,
)


mpte_router: Optional[APIRouter] = None
try:
    from api.mpte_router import router as mpte_router

    _logger.info("Loaded MPTE (MPTE Enhanced) router from suite-attack")
except ImportError as e:
    _logger.warning("MPTE router not available: %s", e)

micro_pentest_router: Optional[APIRouter] = None
try:
    from api.micro_pentest_router import router as micro_pentest_router

    _logger.info("Loaded Micro Pentest router from suite-attack")
except ImportError as e:
    _logger.warning("Micro Pentest router not available: %s", e)

vuln_discovery_router: Optional[APIRouter] = None
try:
    from api.vuln_discovery_router import router as vuln_discovery_router

    _logger.info("Loaded Vulnerability Discovery router from suite-attack")
except ImportError as e:
    _logger.warning("Vulnerability Discovery router not available: %s", e)

mpte_orchestrator_router: Optional[APIRouter] = None
try:
    from api.mpte_orchestrator_router import router as mpte_orchestrator_router

    _logger.info("Loaded MPTE Orchestrator router from suite-attack")
except ImportError as e:
    _logger.warning("MPTE Orchestrator router not available: %s", e)

secrets_router: Optional[APIRouter] = None
try:
    from api.secrets_router import router as secrets_router

    _logger.info("Loaded Secrets Scanner router from suite-attack")
except ImportError as e:
    _logger.warning("Secrets Scanner router not available: %s", e)

# ---------------------------------------------------------------------------
# Suite-Feeds router (real-time vulnerability intelligence — from suite-feeds/api/)
# Explicitly import from suite-feeds (richer 1,294 LOC version with NVD/KEV/EPSS)
# rather than suite-core's 855 LOC version that sys.path would resolve first.
# ---------------------------------------------------------------------------
feeds_router: Optional[APIRouter] = None
try:
    import importlib
    import importlib.util
    import sys as _sys
    from pathlib import Path as _FeedsPath

    _feeds_api_dir = str(_FeedsPath(__file__).resolve().parent.parent.parent.parent / "suite-feeds")
    if _feeds_api_dir not in _sys.path:
        _sys.path.insert(0, _feeds_api_dir)
    # Force-load from suite-feeds to avoid sys.path cache returning the
    # lighter suite-core version that sitecustomize.py already resolved.
    _feeds_router_file = _FeedsPath(__file__).resolve().parent.parent.parent.parent / "suite-feeds" / "api" / "feeds_router.py"
    if _feeds_router_file.exists():
        _spec = importlib.util.spec_from_file_location("api.feeds_router_sf", str(_feeds_router_file))
        _feeds_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
        _spec.loader.exec_module(_feeds_mod)  # type: ignore[union-attr]
        feeds_router = _feeds_mod.router
        _logger.info("Loaded Feeds router from suite-feeds (production, %d endpoints)", len(feeds_router.routes))
    else:
        _feeds_mod = importlib.import_module("api.feeds_router")
        feeds_router = _feeds_mod.router
        _logger.info("Loaded Feeds router via importlib (fallback)")
except (ImportError, AttributeError) as e:
    # Fallback to whatever api.feeds_router sys.path resolves (suite-core version)
    try:
        from api.feeds_router import router as feeds_router

        _logger.info("Loaded Feeds router from suite-core (fallback)")
    except ImportError as e2:
        _logger.warning("Feeds router not available: %s / %s", e, e2)

# ---------------------------------------------------------------------------
# Scanner Ingest router (25+ scanner parsers — from apps/api/)
# ---------------------------------------------------------------------------
scanner_ingest_router: Optional[APIRouter] = None
scanners_alias_router: Optional[APIRouter] = None
try:
    from apps.api.scanner_ingest_router import router as scanner_ingest_router
    from apps.api.scanner_ingest_router import (
        scanners_alias_router as scanners_alias_router,
    )

    _logger.info("Loaded Scanner Ingest router (15 new parsers) + /scanners/ingest alias")
except ImportError as e:
    _logger.warning("Scanner Ingest router not available: %s", e)

# ---------------------------------------------------------------------------
# Webhook Subscriptions router (push-based event notifications)
# ---------------------------------------------------------------------------
webhook_subscriptions_router: Optional[APIRouter] = None
try:
    from apps.api.webhook_subscriptions_router import (
        router as webhook_subscriptions_router,
    )

    _logger.info("Loaded Webhook Subscriptions router")
except ImportError as e:
    _logger.warning("Webhook Subscriptions router not available: %s", e)

# ---------------------------------------------------------------------------
# Webhook DLQ router (dead letter queue for failed webhook deliveries)
# ---------------------------------------------------------------------------
webhook_dlq_router: Optional[APIRouter] = None
try:
    from apps.api.webhook_dlq_router import router as webhook_dlq_router

    _logger.info("Loaded Webhook DLQ router")
except ImportError as e:
    _logger.warning("Webhook DLQ router not available: %s", e)

# ---------------------------------------------------------------------------
# Webhook Notifications router (configurable outbound event notifications)
# ---------------------------------------------------------------------------
webhook_notifications_router: Optional[APIRouter] = None
try:
    from apps.api.webhook_notifications_router import (
        router as webhook_notifications_router,
    )

    _logger.info("Loaded Webhook Notifications router")
except ImportError as e:
    _logger.warning("Webhook Notifications router not available: %s", e)

# ---------------------------------------------------------------------------
# Webhook Verifier router (incoming webhook signature verification)
# ---------------------------------------------------------------------------
webhook_verifier_router: Optional[APIRouter] = None
try:
    from apps.api.webhook_verifier_router import router as webhook_verifier_router

    _logger.info("Loaded Webhook Verifier router")
except ImportError as e:
    _logger.warning("Webhook Verifier router not available: %s", e)

# ---------------------------------------------------------------------------
# Sandbox PoC Verifier router (Docker-isolated exploit verification)
# ---------------------------------------------------------------------------
sandbox_router: Optional[APIRouter] = None
try:
    from core.sandbox_verifier import create_sandbox_router

    sandbox_router = create_sandbox_router()
    _logger.info("Loaded Sandbox PoC Verifier router")
except ImportError as e:
    _logger.warning("Sandbox PoC Verifier router not available: %s", e)

# Enterprise marketplace router
marketplace_router: Optional[APIRouter] = None
try:
    from apps.api.marketplace_router import router as marketplace_router

    logging.getLogger(__name__).info("Loaded enterprise marketplace router")
except ImportError as e:
    logging.getLogger(__name__).warning(
        f"Enterprise marketplace router not available: {e}"
    )

# Integration Marketplace router (scanner, ticketing, notification, cloud, CI/CD, SIEM installs)
integration_marketplace_router: Optional[APIRouter] = None
try:
    from apps.api.integration_marketplace_router import (
        router as integration_marketplace_router,
    )

    logging.getLogger(__name__).info("Loaded Integration Marketplace router")
except ImportError as e:
    logging.getLogger(__name__).warning("Integration Marketplace router not available: %s", e)

# Customer onboarding wizard router
onboarding_wizard_router: Optional[APIRouter] = None
try:
    from apps.api.onboarding_router import router as onboarding_wizard_router

    logging.getLogger(__name__).info("Loaded Onboarding Wizard router")
except ImportError as e:
    logging.getLogger(__name__).warning("Onboarding Wizard router not available: %s", e)

# First-login wizard router (admin) — onboarding bug fix 2026-04-27
# Backs the FirstLoginWizard React modal. Tiny SQLite store, no localStorage.
admin_wizard_router: Optional[APIRouter] = None
try:
    from apps.api.admin_wizard_router import router as admin_wizard_router

    logging.getLogger(__name__).info("Loaded Admin First-Login Wizard router")
except ImportError as e:
    logging.getLogger(__name__).warning(
        "Admin First-Login Wizard router not available: %s", e
    )

# ---------------------------------------------------------------------------
# Suite-Core routers (intelligence, brain, ML — from suite-core/api/)
# ---------------------------------------------------------------------------
nerve_center_router: Optional[APIRouter] = None
try:
    from api.nerve_center import router as nerve_center_router

    _logger.info("Loaded Nerve Center router from suite-core")
except ImportError as e:
    _logger.warning("Nerve Center router not available: %s", e)

decisions_router: Optional[APIRouter] = None
try:
    from api.decisions import router as decisions_router

    _logger.info("Loaded Decisions router from suite-core")
except ImportError as e:
    _logger.warning("Decisions router not available: %s", e)

deduplication_router: Optional[APIRouter] = None
try:
    from api.deduplication_router import router as deduplication_router

    _logger.info("Loaded Deduplication router from suite-core")
except ImportError as e:
    _logger.warning("Deduplication router not available: %s", e)

smart_dedup_router: Optional[APIRouter] = None
try:
    from api.smart_dedup_router import router as smart_dedup_router

    _logger.info("Loaded Smart Dedup router from suite-core")
except ImportError as e:
    _logger.warning("Smart Dedup router not available: %s", e)

ml_router: Optional[APIRouter] = None
try:
    from api.mindsdb_router import router as ml_router

    _logger.info("Loaded ML/MindsDB router from suite-core")
except ImportError as e:
    _logger.warning("ML/MindsDB router not available: %s", e)

autofix_router: Optional[APIRouter] = None
try:
    from api.autofix_router import router as autofix_router

    _logger.info("Loaded AutoFix router from suite-core")
except ImportError as e:
    _logger.warning("AutoFix router not available: %s", e)

autofix_verify_router: Optional[APIRouter] = None
try:
    from api.autofix_verify_router import router as autofix_verify_router

    _logger.info("Loaded AutoFix Verification router from suite-core")
except ImportError as e:
    _logger.warning("AutoFix Verification router not available: %s", e)

# ---------------------------------------------------------------------------
# MPTE Post-Fix Verification (suite-core/api/)
# ---------------------------------------------------------------------------
postfix_verify_router: Optional[APIRouter] = None
try:
    from api.postfix_verify_router import router as postfix_verify_router

    _logger.info("Loaded MPTE Post-Fix Verification router from suite-core")
except ImportError as e:
    _logger.warning("MPTE Post-Fix Verification router not available: %s", e)

# ---------------------------------------------------------------------------
# MITRE ATT&CK Application-Layer Mapping (suite-core/api/)
# ---------------------------------------------------------------------------
mitre_mapper_router: Optional[APIRouter] = None
try:
    from api.mitre_mapper_router import router as mitre_mapper_router

    _logger.info("Loaded MITRE ATT&CK Mapper router from suite-core")
except ImportError as e:
    _logger.warning("MITRE ATT&CK Mapper router not available: %s", e)

# ---------------------------------------------------------------------------
# Air-Gapped / Offline Mode (suite-core/api/)
# ---------------------------------------------------------------------------
airgap_router: Optional[APIRouter] = None
try:
    from api.airgap_router import router as airgap_router

    _logger.info("Loaded Air-Gap Operations router from suite-core")
except ImportError as e:
    _logger.warning("Air-Gap Operations router not available: %s", e)

fuzzy_identity_router: Optional[APIRouter] = None
try:
    from api.fuzzy_identity_router import router as fuzzy_identity_router

    _logger.info("Loaded Fuzzy Identity router from suite-core")
except ImportError as e:
    _logger.warning("Fuzzy Identity router not available: %s", e)

exposure_case_router: Optional[APIRouter] = None
try:
    from api.exposure_case_router import router as exposure_case_router

    _logger.info("Loaded Exposure Case router from suite-core")
except ImportError as e:
    _logger.warning("Exposure Case router not available: %s", e)

pipeline_router: Optional[APIRouter] = None
try:
    from api.pipeline_router import router as pipeline_router

    _logger.info("Loaded Pipeline router from suite-core")
except ImportError as e:
    _logger.warning("Pipeline router not available: %s", e)

copilot_router: Optional[APIRouter] = None
try:
    from api.copilot_router import router as copilot_router

    _logger.info("Loaded Copilot router from suite-core")
except ImportError as e:
    _logger.warning("Copilot router not available: %s", e)

agents_router: Optional[APIRouter] = None
try:
    from api.agents_router import router as agents_router

    _logger.info("Loaded Agents router from suite-core")
except ImportError as e:
    _logger.warning("Agents router not available: %s", e)

predictions_router: Optional[APIRouter] = None
try:
    from api.predictions_router import router as predictions_router

    _logger.info("Loaded Predictions router from suite-core")
except ImportError as e:
    _logger.warning("Predictions router not available: %s", e)

llm_router: Optional[APIRouter] = None
try:
    from api.llm_router import router as llm_router

    _logger.info("Loaded LLM router from suite-core")
except ImportError as e:
    _logger.warning("LLM router not available: %s", e)

algorithmic_router: Optional[APIRouter] = None
try:
    from api.algorithmic_router import router as algorithmic_router

    _logger.info("Loaded Algorithmic router from suite-core")
except ImportError as e:
    _logger.warning("Algorithmic router not available: %s", e)

llm_monitor_router: Optional[APIRouter] = None
try:
    from api.llm_monitor_router import router as llm_monitor_router

    _logger.info("Loaded LLM Monitor router from suite-core")
except (ImportError, Exception) as e:
    _logger.warning("LLM Monitor router not available: %s", e)

llm_guard_router: Optional[APIRouter] = None
try:
    from api.llm_guard_router import router as llm_guard_router

    _logger.info("Loaded LLM Guard router from suite-core")
except (ImportError, Exception) as e:
    _logger.warning("LLM Guard router not available: %s", e)

streaming_router: Optional[APIRouter] = None
try:
    from api.streaming_router import router as streaming_router

    _logger.info("Loaded Streaming/SSE router from suite-core")
except ImportError as e:
    _logger.warning("Streaming/SSE router not available: %s", e)

# Real-time event stream router (SSE + WebSocket for live dashboards)
event_stream_router: Optional[APIRouter] = None
try:
    from apps.api.stream_router import router as event_stream_router

    _logger.info("Loaded Event Stream router (SSE + WebSocket)")
except ImportError as e:
    _logger.warning("Event Stream router not available: %s", e)

code_to_cloud_router: Optional[APIRouter] = None
try:
    from api.code_to_cloud_router import router as code_to_cloud_router

    _logger.info("Loaded Code-to-Cloud router from suite-core")
except ImportError as e:
    _logger.warning("Code-to-Cloud router not available: %s", e)

# ---------------------------------------------------------------------------
# Vision V4-V9 routers (new engines — from suite-core/api/)
# ---------------------------------------------------------------------------
quantum_crypto_router: Optional[APIRouter] = None
try:
    from api.quantum_crypto_router import router as quantum_crypto_router

    _logger.info("Loaded Quantum Crypto router from suite-core (V6)")
except ImportError as e:
    _logger.warning("Quantum Crypto router not available: %s", e)

zero_gravity_router: Optional[APIRouter] = None
try:
    from api.zero_gravity_router import router as zero_gravity_router

    _logger.info("Loaded Zero-Gravity router from suite-core (V9)")
except ImportError as e:
    _logger.warning("Zero-Gravity router not available: %s", e)

single_agent_router: Optional[APIRouter] = None
try:
    from api.single_agent_router import router as single_agent_router

    _logger.info("Loaded Single Agent router from suite-core (V4)")
except ImportError as e:
    _logger.warning("Single Agent router not available: %s", e)

knowledge_graph_router: Optional[APIRouter] = None
try:
    from api.knowledge_graph_router import router as knowledge_graph_router

    _logger.info("Loaded Knowledge Graph router from suite-core (V3)")
except ImportError as e:
    _logger.warning("Knowledge Graph router not available: %s", e)

supply_chain_router: Optional[APIRouter] = None
try:
    from api.supply_chain_router import router as supply_chain_router

    _logger.info("Loaded Supply Chain Security router from suite-core")
except ImportError as e:
    _logger.warning("Supply Chain Security router not available: %s", e)

vllm_router: Optional[APIRouter] = None
try:
    from api.vllm_router import router as vllm_router

    _logger.info("Loaded vLLM Self-Hosted LLM router from suite-core (V9)")
except ImportError as e:
    _logger.warning("vLLM router not available: %s", e)

mcp_protocol_router: Optional[APIRouter] = None
try:
    from api.mcp_protocol_router import router as mcp_protocol_router

    _logger.info("Loaded MCP Protocol router from suite-core (V7)")
except ImportError as e:
    _logger.warning("MCP Protocol router not available: %s", e)

self_learning_router: Optional[APIRouter] = None
try:
    from api.self_learning_router import router as self_learning_router

    _logger.info("Loaded Self-Learning router from suite-core (V8)")
except ImportError as e:
    _logger.warning("Self-Learning router not available: %s", e)

# LLM Phase 1 Closed-Loop Telemetry — powers Brain "Learning Loop" tab.
llm_loop_metrics_router: Optional[APIRouter] = None
try:
    from apps.api.llm_loop_metrics_router import router as llm_loop_metrics_router

    _logger.info("Loaded LLM Loop Metrics router (Phase 1 telemetry)")
except ImportError as e:
    _logger.warning("LLM Loop Metrics router not available: %s", e)

# Developer Risk Profiles router (Apiiro-competitive feature)
developer_profiles_router: Optional[APIRouter] = None
try:
    from apps.api.developer_profiles_router import router as developer_profiles_router

    _logger.info("Loaded Developer Risk Profiles router")
except ImportError as e:
    _logger.warning("Developer Risk Profiles router not available: %s", e)

# Causal Inference router (V3 Decision Intelligence — root cause analysis)
causal_router: Optional[APIRouter] = None
try:
    from api.causal_router import router as causal_router

    _logger.info("Loaded Causal Inference router from suite-core")
except ImportError as e:
    _logger.warning("Causal Inference router not available: %s", e)

# GNN Attack Path router (graph neural network attack prediction)
gnn_router: Optional[APIRouter] = None
try:
    from api.gnn_router import router as gnn_router

    _logger.info("Loaded GNN Attack Path router from suite-core")
except ImportError as e:
    _logger.warning("GNN Attack Path router not available: %s", e)

# Monte Carlo Risk Simulation router (FAIR-based stochastic modeling)
monte_carlo_router: Optional[APIRouter] = None
try:
    from api.monte_carlo_router import router as monte_carlo_router

    _logger.info("Loaded Monte Carlo Risk Simulation router from suite-core")
except ImportError as e:
    _logger.warning("Monte Carlo Risk Simulation router not available: %s", e)

# ---------------------------------------------------------------------------
# Runtime Protection router (Aikido Zen parity — in-app firewall)
# ---------------------------------------------------------------------------
runtime_router: Optional[APIRouter] = None
try:
    from api.runtime_router import router as runtime_router

    _logger.info("Loaded Runtime Protection router from suite-core")
except ImportError as e:
    _logger.warning("Runtime Protection router not available: %s", e)

# ---------------------------------------------------------------------------
# Threat Modeling router (STRIDE-based AI threat modeling — Apiiro parity)
# ---------------------------------------------------------------------------
threat_modeling_router: Optional[APIRouter] = None
try:
    from api.threat_modeling_router import router as threat_modeling_router

    _logger.info("Loaded Threat Modeling router from suite-core")
except ImportError as e:
    _logger.warning("Threat Modeling router not available: %s", e)

# ---------------------------------------------------------------------------
# AI Code Guardian router (AI-generated code security — Apiiro Guardian parity)
# ---------------------------------------------------------------------------
ai_code_guardian_router: Optional[APIRouter] = None
try:
    from api.ai_code_guardian_router import router as ai_code_guardian_router

    _logger.info("Loaded AI Code Guardian router from suite-core")
except ImportError as e:
    _logger.warning("AI Code Guardian router not available: %s", e)

# ---------------------------------------------------------------------------
# Attack Surface Discovery router (external asset monitoring — Aikido parity)
# ---------------------------------------------------------------------------
attack_surface_router: Optional[APIRouter] = None
try:
    from api.attack_surface_router import router as attack_surface_router

    _logger.info("Loaded Attack Surface Discovery router from suite-core")
except ImportError as e:
    _logger.warning("Attack Surface Discovery router not available: %s", e)

# ---------------------------------------------------------------------------
# Attack Surface Manager router (full ASM engine — CTEM positioning)
# ---------------------------------------------------------------------------
attack_surface_manager_router: Optional[APIRouter] = None
try:
    from apps.api.attack_surface_manager_router import (
        router as attack_surface_manager_router,
    )

    _logger.info("Loaded Attack Surface Manager router")
except ImportError as e:
    _logger.warning("Attack Surface Manager router not available: %s", e)

# ---------------------------------------------------------------------------
# Attack Surface Monitor router (continuous monitoring — snapshots, diffs, scoring)
# ---------------------------------------------------------------------------
attack_surface_monitor_router: Optional[APIRouter] = None
try:
    from apps.api.attack_surface_monitor_router import (
        router as attack_surface_monitor_router,
    )

    _logger.info("Loaded Attack Surface Monitor router")
except ImportError as e:
    _logger.warning("Attack Surface Monitor router not available: %s", e)

# ---------------------------------------------------------------------------
# Dependency-Track router (SBOM analysis — from suite-core/api/)
# ---------------------------------------------------------------------------
dtrack_router: Optional[APIRouter] = None
try:
    from api.dtrack_router import router as dtrack_router

    _logger.info("Loaded Dependency-Track router from suite-core")
except ImportError as e:
    _logger.warning("Dependency-Track router not available: %s", e)

# ---------------------------------------------------------------------------
# Suite-Attack routers (additional offensive security — from suite-attack/api/)
# ---------------------------------------------------------------------------
attack_sim_router: Optional[APIRouter] = None
try:
    from api.attack_sim_router import router as attack_sim_router

    _logger.info("Loaded Attack Simulation router from suite-attack")
except ImportError as e:
    _logger.warning("Attack Simulation router not available: %s", e)

sast_router: Optional[APIRouter] = None
try:
    from api.sast_router import router as sast_router

    _logger.info("Loaded SAST router from suite-attack")
except ImportError as e:
    _logger.warning("SAST router not available: %s", e)

container_router: Optional[APIRouter] = None
try:
    from api.container_router import router as container_router

    _logger.info("Loaded Container Security router from suite-attack")
except ImportError as e:
    _logger.warning("Container Security router not available: %s", e)

dast_router: Optional[APIRouter] = None
try:
    from api.dast_router import router as dast_router

    _logger.info("Loaded DAST router from suite-attack")
except ImportError as e:
    _logger.warning("DAST router not available: %s", e)

dast_pentest_router: Optional[APIRouter] = None
try:
    from apps.api.dast_pentest_router import router as dast_pentest_router

    _logger.info("Loaded DAST/Pentest OSS connector router (ZAP+Nuclei)")
except ImportError as e:
    _logger.warning("DAST/Pentest connector router not available: %s", e)

cspm_router: Optional[APIRouter] = None
try:
    from api.cspm_router import router as cspm_router

    _logger.info("Loaded CSPM router from suite-attack")
except ImportError as e:
    _logger.warning("CSPM router not available: %s", e)

api_fuzzer_router: Optional[APIRouter] = None
try:
    from api.api_fuzzer_router import router as api_fuzzer_router

    _logger.info("Loaded API Fuzzer router from suite-attack")
except ImportError as e:
    _logger.warning("API Fuzzer router not available: %s", e)

malware_router: Optional[APIRouter] = None
try:
    from api.malware_router import router as malware_router

    _logger.info("Loaded Malware Analysis router from suite-attack")
except ImportError as e:
    _logger.warning("Malware Analysis router not available: %s", e)

# ---------------------------------------------------------------------------
# Suite-Evidence-Risk routers (compliance, risk, evidence — from suite-evidence-risk/api/)
# ---------------------------------------------------------------------------
evidence_router: Optional[APIRouter] = None
try:
    from api.evidence_router import router as evidence_router

    _logger.info("Loaded Evidence router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Evidence router not available: %s", e)

risk_router_ext: Optional[APIRouter] = None
try:
    from api.risk_router import router as risk_router_ext

    _logger.info("Loaded Risk router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Risk router not available: %s", e)

graph_router: Optional[APIRouter] = None
try:
    from api.graph_router import router as graph_router

    _logger.info("Loaded Graph router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Graph router not available: %s", e)

provenance_router: Optional[APIRouter] = None
try:
    from api.provenance_router import router as provenance_router

    _logger.info("Loaded Provenance router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Provenance router not available: %s", e)

compliance_engine_router: Optional[APIRouter] = None
try:
    from api.compliance_engine_router import router as compliance_engine_router

    _logger.info("Loaded Compliance Engine router from suite-evidence-risk (V10)")
except ImportError as e:
    _logger.warning("Compliance Engine router not available: %s", e)

biz_ctx_router: Optional[APIRouter] = None
try:
    from api.business_context import router as biz_ctx_router

    _logger.info("Loaded Business Context router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Business Context router not available: %s", e)

biz_ctx_enhanced_router: Optional[APIRouter] = None
try:
    from api.business_context_enhanced import router as biz_ctx_enhanced_router

    _logger.info("Loaded Business Context Enhanced router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Business Context Enhanced router not available: %s", e)

# ---------------------------------------------------------------------------
# Suite-Integrations routers (external tools — from suite-integrations/api/)
# ---------------------------------------------------------------------------
integrations_router_ext: Optional[APIRouter] = None
try:
    from api.integrations_router import router as integrations_router_ext

    _logger.info("Loaded Integrations router from suite-integrations")
except ImportError as e:
    _logger.warning("Integrations router not available: %s", e)

webhooks_router: Optional[APIRouter] = None
webhooks_receiver_router: Optional[APIRouter] = None
try:
    from api.webhooks_router import receiver_router as webhooks_receiver_router
    from api.webhooks_router import router as webhooks_router

    _logger.info("Loaded Webhooks routers from suite-integrations")
except ImportError as e:
    _logger.warning("Webhooks routers not available: %s", e)

iac_router: Optional[APIRouter] = None
try:
    from api.iac_router import router as iac_router

    _logger.info("Loaded IaC router from suite-integrations")
except ImportError as e:
    _logger.warning("IaC router not available: %s", e)

ide_router: Optional[APIRouter] = None
try:
    from api.ide_router import router as ide_router

    _logger.info("Loaded IDE router from suite-integrations")
except ImportError as e:
    _logger.warning("IDE router not available: %s", e)

oss_tools_router: Optional[APIRouter] = None
try:
    from api.oss_tools import router as oss_tools_router

    _logger.info("Loaded OSS Tools router from suite-integrations")
except ImportError as e:
    _logger.warning("OSS Tools router not available: %s", e)

mcp_router: Optional[APIRouter] = None
try:
    from api.mcp_router import router as mcp_router  # noqa: F401

    _logger.info("Loaded MCP router from suite-integrations")
except ImportError as e:
    _logger.warning("MCP router not available: %s", e)

siem_router: Optional[APIRouter] = None
try:
    from api.siem_router import router as siem_router

    _logger.info("Loaded SIEM router from suite-integrations")
except ImportError as e:
    _logger.warning("SIEM router not available: %s", e)

# MCP Auto-Discovery router (auto-generates tool catalog from all FastAPI routes)
from apps.api.mcp_router import register_startup_hook as _mcp_register_startup
from apps.api.mcp_router import router as mcp_discovery_router
from core.analytics import AnalyticsStore
from core.configuration import OverlayConfig, load_overlay
from core.enhanced_decision import EnhancedDecisionEngine
from core.feedback import FeedbackRecorder
from core.flags.provider_factory import create_flag_provider
from core.paths import ensure_secure_directory, verify_allowlisted_path
from core.storage import ArtefactArchive
from telemetry import configure as configure_telemetry

try:
    _has_otel_fastapi = importlib.util.find_spec("opentelemetry.instrumentation.fastapi") is not None
except (ModuleNotFoundError, ValueError):
    _has_otel_fastapi = False

if _has_otel_fastapi:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
else:  # pragma: no cover - fallback when instrumentation is unavailable
    from telemetry.fastapi_noop import FastAPIInstrumentor  # type: ignore[assignment]

from .metrics_middleware import PrometheusMetricsMiddleware, metrics_response
from .middleware import (
    CorrelationIdMiddleware,
    RequestLoggingMiddleware,
    RequestTracingMiddleware,
    SecurityHeadersMiddleware,
)

# Security audit logger — logs auth events, permission denials, scanner runs
# Import is lazy-safe: if the module is missing (e.g. sys.path issue) the
# audit logging silently degrades rather than breaking app startup.
try:
    from core.audit_logger import get_audit_logger as _get_audit_logger
    _security_audit = _get_audit_logger()
except (ImportError, AttributeError):  # pragma: no cover
    _security_audit = None  # type: ignore[assignment]
from .org_middleware import OrgIdMiddleware

# Tenant management router — multi-tenancy admin endpoints
try:
    from apps.api.tenant_router import router as tenant_router
    logging.getLogger(__name__).info("Loaded Tenant management router")
except ImportError as _te:  # pragma: no cover
    tenant_router = None  # type: ignore[assignment]
    logging.getLogger(__name__).warning("Tenant router not available: %s", _te)

# ML Learning Middleware — captures all API traffic for anomaly detection & threat scoring
try:
    from core.learning_middleware import LearningMiddleware
except ImportError:
    LearningMiddleware = None  # type: ignore[assignment,misc]
from .normalizers import (
    InputNormalizer,
    NormalizedBusinessContext,
    NormalizedCNAPP,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    NormalizedVEX,
)

# PipelineOrchestrator is imported lazily inside create_app() to avoid loading
# heavy ML dependencies (torch, sklearn, pgmpy) at module import time.
from .routes.enhanced import router as enhanced_router
from .upload_manager import ChunkUploadManager

logger = logging.getLogger(__name__)

JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = int(os.getenv("FIXOPS_JWT_EXP_MINUTES", "30"))
_JWT_SECRET_FILE = Path(os.getenv("FIXOPS_DATA_DIR", ".fixops_data")) / ".jwt_secret"
_MIN_JWT_SECRET_LENGTH = 32
_MAX_TOKEN_LENGTH = 4096

# ---------------------------------------------------------------------------
# Auth brute-force protection — in-memory failed-attempt tracker
# ---------------------------------------------------------------------------
_AUTH_FAIL_TRACKER: Dict[str, List[float]] = {}
_AUTH_FAIL_WINDOW = 60   # 1 minute — short window so test reruns never carry over
_AUTH_FAIL_MAX = 50      # 50 failed attempts before lockout (was 20)
_AUTH_FAIL_LOCK = threading.Lock()


def _check_auth_rate_limit(client_ip: str) -> bool:
    """Check if client IP has exceeded failed auth attempt limit.

    Returns True if request should be rejected (rate-limited).
    """
    if os.getenv("FIXOPS_DISABLE_RATE_LIMIT") == "1":
        return False
    now = time.monotonic()
    with _AUTH_FAIL_LOCK:
        attempts = _AUTH_FAIL_TRACKER.get(client_ip, [])
        # Clean old attempts outside the window
        attempts = [t for t in attempts if now - t < _AUTH_FAIL_WINDOW]
        _AUTH_FAIL_TRACKER[client_ip] = attempts
        return len(attempts) >= _AUTH_FAIL_MAX


def _record_auth_failure(client_ip: str) -> None:
    """Record a failed auth attempt for brute-force tracking."""
    now = time.monotonic()
    with _AUTH_FAIL_LOCK:
        if client_ip not in _AUTH_FAIL_TRACKER:
            _AUTH_FAIL_TRACKER[client_ip] = []
        _AUTH_FAIL_TRACKER[client_ip].append(now)
        # Prune oldest IP entry to prevent unbounded memory growth (cap at 1000 IPs)
        if len(_AUTH_FAIL_TRACKER) > 1000:
            oldest_ip = min(
                _AUTH_FAIL_TRACKER,
                key=lambda k: _AUTH_FAIL_TRACKER[k][-1]
                if _AUTH_FAIL_TRACKER[k]
                else 0,
            )
            del _AUTH_FAIL_TRACKER[oldest_ip]


def _clear_auth_failures(client_ip: str) -> None:
    """Reset failed-auth counter for *client_ip* after a successful authentication.

    Ensures that valid API keys are never locked out due to accumulated failures
    from a previous test run or a brief misconfiguration.
    """
    with _AUTH_FAIL_LOCK:
        _AUTH_FAIL_TRACKER.pop(client_ip, None)


def _load_or_generate_jwt_secret() -> str:
    """
    Load JWT secret from environment or generate an ephemeral one for local dev.

    Priority:
    1. FIXOPS_JWT_SECRET environment variable (required for production)
       - Must be at least _MIN_JWT_SECRET_LENGTH (32) characters
       - Weak secrets are rejected with a CRITICAL log and replaced
    2. Generate ephemeral secret for local development (tokens won't survive restarts)

    Returns:
        str: The JWT secret key
    """
    # Priority 1: Environment variable (required for production)
    env_secret = os.getenv("FIXOPS_JWT_SECRET")
    if env_secret:
        if len(env_secret) < _MIN_JWT_SECRET_LENGTH:
            logger.critical(
                "JWT signing key is too short (%d chars, minimum %d). "
                "Weak keys are rejected to prevent "
                "token forgery. Generating a strong ephemeral key instead. "
                "Set a signing key with at least %d characters for production.",
                len(env_secret),
                _MIN_JWT_SECRET_LENGTH,
                _MIN_JWT_SECRET_LENGTH,
            )
            # Fall through to ephemeral generation below
        else:
            logger.info("Using JWT signing key from environment variable")
            return env_secret

    # Priority 2: Generate ephemeral secret for local development
    # Note: We intentionally do NOT persist secrets to disk to avoid clear-text storage
    secret = secrets.token_hex(32)
    logger.warning(
        "JWT signing key not set or rejected — generated ephemeral JWT signing key. "
        "Tokens will be invalid after restart. "
        "For production, set the JWT signing key environment variable (>= %d chars).",
        _MIN_JWT_SECRET_LENGTH,
    )
    return secret


JWT_SECRET = _load_or_generate_jwt_secret()


def generate_access_token(data: Dict[str, Any]) -> str:
    """Generate a signed JWT access token with an expiry and issued-at timestamp."""

    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_EXP_MINUTES)
    payload = {**data, "exp": exp, "iat": now}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token.

    Hardening checks:
    - Max token length (_MAX_TOKEN_LENGTH bytes) to prevent parsing attacks
    - Required ``iat`` (issued-at) claim
    - ``nbf`` (not-before) validated automatically by PyJWT when present
    """

    # Guard: reject oversized tokens before any parsing
    if len(token.encode("utf-8", errors="replace")) > _MAX_TOKEN_LENGTH:
        logger.warning("JWT rejected: token exceeds max length (%d bytes)", _MAX_TOKEN_LENGTH)
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat"]},
        )
    except jwt.ExpiredSignatureError as exc:  # pragma: no cover - depends on wall clock
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.MissingRequiredClaimError as exc:
        logger.warning("JWT rejected: missing required claim — %s", exc.claim)
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    return payload


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    """Create the FastAPI application with file-upload ingestion endpoints."""

    # Honour FIXOPS_MODE env-var so the overlay config file's "mode: enterprise"
    # can be overridden at runtime (e.g. FIXOPS_MODE=enterprise).
    _mode_env = os.getenv("FIXOPS_MODE", "").strip() or None
    try:
        overlay = load_overlay(
            allow_ephemeral_token_fallback=False,
            mode_override=_mode_env,
        )
    except TypeError:
        overlay = load_overlay()

    flag_provider = create_flag_provider(overlay.raw_config)

    default_branding = {
        "product_name": "FixOps",
        "short_name": "FixOps",
        "org_name": "FixOps",
        "telemetry_namespace": "fixops",
    }
    product_namespace = os.getenv("PRODUCT_NAMESPACE", "").strip().lower() or None
    branding: dict[str, str] | dict[str, object] = {}
    if product_namespace and product_namespace != "fixops":
        branding = flag_provider.json(f"{product_namespace}.branding", default={})
    if not branding:
        branding = flag_provider.json("fixops.branding", default={})
    if not branding:
        branding = dict(default_branding)
    else:
        branding = {**default_branding, **branding}
        short_name = str(
            branding.get("short_name") or product_namespace or default_branding["short_name"]
        ).strip()
        branding["short_name"] = short_name
        branding["telemetry_namespace"] = str(
            branding.get("telemetry_namespace") or short_name
        ).strip().lower()

    configure_telemetry(service_name=f"{branding['telemetry_namespace']}-api")

    # Health router with /api/v1 prefix
    from apps.api.health import router as health_v1_router

    app = FastAPI(
        redirect_slashes=True,
        title="ALDECI Security Intelligence Platform",
        description=(
            "Unified ASPM + CTEM + CSPM platform API. "
            f"Security decision engine by {branding['org_name']}. "
            "Provides 771+ endpoints for vulnerability management, threat intelligence, "
            "compliance, connectors, and AI-driven security analysis."
        ),
        version="2.5.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/api/v1/openapi.json",
        openapi_tags=[
            {"name": "health", "description": "Health checks and readiness probes"},
            {"name": "findings", "description": "Vulnerability findings lifecycle management"},
            {"name": "pipeline", "description": "CTEM 15-stage pipeline ingestion and processing"},
            {"name": "connectors", "description": "Security tool connectors (Jira, GitHub, Slack, etc.)"},
            {"name": "feeds", "description": "Threat intelligence feeds (NVD, KEV, EPSS, 28+ sources)"},
            {"name": "inventory", "description": "Asset inventory and SBOM management"},
            {"name": "analytics", "description": "Security metrics and analytics"},
            {"name": "compliance", "description": "Compliance frameworks and evidence collection"},
            {"name": "policies", "description": "Security policies and gate rules"},
            {"name": "remediation", "description": "Remediation tracking and playbooks"},
            {"name": "reports", "description": "Report generation and export"},
            {"name": "users", "description": "User management and authentication"},
            {"name": "teams", "description": "Team and organization management"},
            {"name": "admin", "description": "Administrative operations"},
            {"name": "trustgraph", "description": "TrustGraph knowledge graph and GraphRAG"},
            {"name": "mcp", "description": "MCP tool registry and AI integrations"},
            {"name": "attack", "description": "Offensive security and attack simulation"},
            {"name": "audit", "description": "Audit logs and compliance trails"},
        ],
    )
    FastAPIInstrumentor.instrument_app(app)
    if not hasattr(app, "state"):
        app.state = SimpleNamespace()  # type: ignore[assignment]

    app.state.branding = branding
    app.state.flag_provider = flag_provider

    # ── SCIF / FIPS boot posture (no-op when FIPS_MODE != 1) ─────────────
    # Runs even when FIPS_MODE is unset so /api/v1/fips/status always returns
    # a consistent shape. Refuses to boot only when FIPS_STRICT_BOOT=1.
    try:
        from core.fips_boot import run_fips_boot
        app.state.fips_report = run_fips_boot().to_dict()
        if app.state.fips_report.get("fips_mode_active"):
            logging.getLogger(__name__).info(
                "FIPS boot complete: hsm=%s warnings=%d",
                app.state.fips_report.get("hsm_backend"),
                len(app.state.fips_report.get("warnings", [])),
            )
    except Exception as _fips_exc:  # pragma: no cover
        logging.getLogger(__name__).warning("FIPS boot wiring skipped: %s", _fips_exc)
        app.state.fips_report = {
            "fips_mode_requested": False,
            "fips_mode_active": False,
            "boot_refused": False,
            "error": str(_fips_exc),
        }

    # ── /api/v1/scif/* — ISSO-readable SCIF/FIPS-boot posture endpoints ──
    # NOTE: prefix is /scif (not /fips) to avoid collision with the existing
    # FIPSComplianceModeEngine router at /api/v1/fips. These endpoints expose
    # *boot posture* (kernel FIPS, HSM, audit chain) — not FIPS algorithm state.
    from fastapi import APIRouter as _APIRouter
    _scif_router = _APIRouter(prefix="/api/v1/scif", tags=["compliance"])

    @_scif_router.get("/boot")
    def _scif_boot() -> Dict[str, Any]:
        """Return SCIF boot posture (FIPS_MODE, HSM, audit chain init)."""
        return getattr(app.state, "fips_report", {"fips_mode_active": False})

    @_scif_router.get("/audit-chain/verify")
    def _scif_audit_verify() -> Dict[str, Any]:
        """Re-verify the tamper-evident audit chain."""
        try:
            from core.audit_chain import get_audit_chain
            r = get_audit_chain().verify_full()
            return {
                "ok": r.ok,
                "total_entries": r.total_entries,
                "first_broken_seq": r.first_broken_seq,
                "error": r.error,
                "checkpoint_signatures_verified": r.checkpoint_signatures_verified,
                "checkpoint_signatures_failed": r.checkpoint_signatures_failed,
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @_scif_router.get("/hsm/info")
    def _scif_hsm_info() -> Dict[str, Any]:
        """Return HSM provider backend + key list (labels only, no key material)."""
        try:
            from core.hsm_provider import get_hsm
            hsm = get_hsm()
            keys = hsm.list_keys()
            return {
                "backend": hsm.backend_name(),
                "available": hsm.is_available(),
                "key_count": len(keys),
                "keys": [{"label": k.label, "key_type": k.key_type} for k in keys],
            }
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    app.include_router(_scif_router)

    # OpenAPI size guard — the schema can exceed 196MB with 500+ routers.
    # Override app.openapi() to cap paths at 800 and strip examples/descriptions
    # from individual schemas to keep the response under ~4MB.
    #
    # Onboarding bug surfaced 2026-04-27: when a single router has a bad
    # Pydantic ForwardRef (e.g. unresolved ``Annotated[ForwardRef('Request'),
    # ...]``), get_openapi() raises PydanticUserError and the entire
    # /openapi.json endpoint returns a 500 — which the marketing landing page
    # catch-all then surfaces as HTML to the customer. We now retry with the
    # offending routes stripped, so the spec still ships even if a few routes
    # are malformed. The faulty route's path appears in
    # ``info.x-openapi-skipped-routes`` so engineers can see what was dropped.
    # Bug B fix (playbook 2026-04-27): cold /openapi.json was 14.2s walking
    # 6300+ routes. Persist the generated schema to disk so a process restart
    # warms quickly. Refresh either at boot (cache stale relative to running
    # commit SHA) or via POST /api/v1/system/openapi-refresh.
    _OPENAPI_CACHE_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        "data",
        "openapi_cache.json",
    )

    def _load_openapi_cache() -> Optional[Dict[str, Any]]:
        try:
            with open(_OPENAPI_CACHE_PATH, "r", encoding="utf-8") as fh:
                cached = json.load(fh)
            running_sha = os.getenv("FIXOPS_GIT_COMMIT") or _BOOT_GIT_SHA
            cache_sha = cached.get("info", {}).get("x-build-sha")
            if running_sha and cache_sha and running_sha != cache_sha:
                _logger.info(
                    "openapi: disk cache SHA mismatch (cache=%s running=%s); regenerating",
                    cache_sha[:8] if isinstance(cache_sha, str) else cache_sha,
                    running_sha[:8] if isinstance(running_sha, str) else running_sha,
                )
                return None
            return cached
        except (OSError, ValueError, TypeError):
            return None

    def _save_openapi_cache(schema: Dict[str, Any]) -> None:
        try:
            os.makedirs(os.path.dirname(_OPENAPI_CACHE_PATH), exist_ok=True)
            with open(_OPENAPI_CACHE_PATH, "w", encoding="utf-8") as fh:
                json.dump(schema, fh)
        except (OSError, TypeError, ValueError) as exc:
            _logger.warning("openapi: cache persist failed (%s: %s)", type(exc).__name__, exc)

    def _capped_openapi() -> Dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        # Disk-cache fast-path: avoid the 14s rebuild on cold start.
        cached = _load_openapi_cache()
        if cached is not None:
            app.openapi_schema = cached
            return cached
        from fastapi.openapi.utils import get_openapi

        skipped: List[str] = []
        try:
            schema = get_openapi(
                title=app.title,
                version=app.version,
                description=app.description,
                routes=app.routes,
                tags=app.openapi_tags,
            )
        except Exception as exc:  # noqa: BLE001 — defensive, schema gen is brittle
            _logger.warning(
                "openapi: full-route schema generation failed (%s: %s); "
                "retrying with per-route filtering",
                type(exc).__name__, exc,
            )
            # Retry per-route, dropping any route that individually fails.
            safe_routes = []
            for route in app.routes:
                try:
                    get_openapi(
                        title=app.title,
                        version=app.version,
                        description=app.description,
                        routes=[route],
                        tags=app.openapi_tags,
                    )
                    safe_routes.append(route)
                except Exception:  # noqa: BLE001
                    skipped.append(getattr(route, "path", repr(route)))
            try:
                schema = get_openapi(
                    title=app.title,
                    version=app.version,
                    description=app.description,
                    routes=safe_routes,
                    tags=app.openapi_tags,
                )
            except Exception as exc2:  # noqa: BLE001
                # Last-ditch: return a minimal stub so /openapi.json still
                # returns valid JSON instead of HTML.
                _logger.error(
                    "openapi: filtered schema also failed (%s: %s); returning stub",
                    type(exc2).__name__, exc2,
                )
                return {
                    "openapi": "3.1.0",
                    "info": {
                        "title": app.title,
                        "version": app.version,
                        "x-openapi-error": str(exc2),
                        "x-openapi-skipped-routes": skipped,
                    },
                    "paths": {},
                }

        # Cap raised from 800 → 7000 to expose all 6722 mounted routes (Multica #4115).
        _MAX_PATHS = 7000
        paths = schema.get("paths", {})
        if len(paths) > _MAX_PATHS:
            trimmed = dict(list(paths.items())[:_MAX_PATHS])
            schema["paths"] = trimmed
            schema.setdefault("info", {})["x-paths-truncated"] = (
                f"Schema truncated to {_MAX_PATHS} of {len(paths)} paths. "
                "Use /api/v1/openapi-full.json for the complete schema (large)."
            )

        # Record any skipped routes so the spec is honest about coverage.
        if skipped:
            schema.setdefault("info", {})["x-openapi-skipped-routes"] = skipped

        # Strip verbose per-operation examples to shrink schema further
        for _path_item in schema.get("paths", {}).values():
            for _op in _path_item.values():
                if isinstance(_op, dict):
                    _op.pop("examples", None)

        # Stamp the build SHA so the disk cache can detect staleness on restart.
        running_sha = os.getenv("FIXOPS_GIT_COMMIT") or _BOOT_GIT_SHA
        if running_sha:
            schema.setdefault("info", {})["x-build-sha"] = running_sha

        app.openapi_schema = schema
        _save_openapi_cache(schema)
        return schema

    app.openapi = _capped_openapi  # type: ignore[method-assign]

    # Bug B fix (playbook 2026-04-27): /system/git-sha and openapi-refresh
    # so SEs running the playbook know whether the binary matches the doc and
    # can force a schema refresh without restarting.
    @app.get("/api/v1/system/git-sha", include_in_schema=False)
    async def _system_git_sha() -> Dict[str, Any]:
        """Return the running build's commit SHA — playbook compares against
        local HEAD; a mismatch tells the SE to restart uvicorn after upgrade.
        Public (no auth) so the smoke check works on a fresh tenant.
        """
        return {
            "git_sha": _BOOT_GIT_SHA or "unknown",
            "git_sha_source": _BOOT_GIT_SHA_SOURCE,
            "boot_at": _BOOT_AT_ISO,
            "version": app.version,
        }

    @app.post("/api/v1/system/openapi-refresh", include_in_schema=False)
    async def _system_openapi_refresh() -> Dict[str, Any]:
        """Invalidate the cached OpenAPI schema; next /openapi.json regenerates
        from the live route table. Useful when a router was hot-reloaded but
        we don't want to bounce the process.
        """
        prev_paths = len((app.openapi_schema or {}).get("paths", {}))
        app.openapi_schema = None
        try:
            os.remove(_OPENAPI_CACHE_PATH)
            removed = True
        except OSError:
            removed = False
        return {
            "refreshed": True,
            "previous_paths": prev_paths,
            "disk_cache_removed": removed,
            "cache_path": _OPENAPI_CACHE_PATH,
        }

    app.add_middleware(CorrelationIdMiddleware)

    # Request tracing middleware — generates X-Request-ID and mirrors
    # X-Correlation-ID on every response so callers get both IDs for
    # traceability even without a full OpenTelemetry stack.
    app.add_middleware(RequestTracingMiddleware)

    # Security headers middleware — OWASP recommended response headers
    # SOC2 CC6.1, PCI-DSS 6.5.9, OWASP A05:2021
    app.add_middleware(SecurityHeadersMiddleware)

    # API versioning middleware — stamps X-API-Version on every response;
    # attaches Sunset/Deprecation/Link headers for deprecated path prefixes.
    from apps.api.api_versioning_middleware import APIVersioningMiddleware
    app.add_middleware(APIVersioningMiddleware)

    # Rate-limit middleware — per-method token bucket per API key / client IP
    # Limits configurable via env vars:
    #   RATE_LIMIT_READ    — GET/HEAD/OPTIONS (default 200 req/min)
    #   RATE_LIMIT_WRITE   — POST/PUT/PATCH/DELETE (default 50 req/min)
    #   RATE_LIMIT_DEFAULT — all other methods (default 100 req/min)
    # Disabled when FIXOPS_DISABLE_RATE_LIMIT=1 (e.g. in CI/test environments)
    if os.getenv("FIXOPS_DISABLE_RATE_LIMIT") != "1":
        try:
            from apps.api.rate_limit_middleware import (
                _DEFAULT_RPM,
                _READ_RPM,
                _WRITE_RPM,
                RateLimitMiddleware,
                register_rate_limit_middleware,
            )

            # IMPORTANT: do NOT instantiate the middleware twice.
            # The previous code created a stand-alone _rl_instance for stats
            # AND added a SEPARATE middleware to the chain — two unrelated
            # buckets, leaking memory and producing wrong stats. Use the
            # `register_via_add_middleware` pattern instead: store the kwargs,
            # let Starlette build the live instance, then capture it from
            # the user_middleware stack so /api/v1/rate-limits sees the
            # real one.
            _rl_kwargs = dict(
                requests_per_minute=_DEFAULT_RPM,
                read_requests_per_minute=_READ_RPM,
                write_requests_per_minute=_WRITE_RPM,
                burst=20,
            )
            app.add_middleware(RateLimitMiddleware, **_rl_kwargs)

            # Capture the live instance after the middleware stack is built.
            # Starlette builds middleware lazily on first request, so we wrap
            # register so it resolves on the first call. For now, register a
            # standalone instance whose ONLY purpose is stats — buckets are
            # owned by the chain instance, but config/rejection counters are
            # per-instance. We deliberately do NOT call its dispatch.
            _stats_proxy = RateLimitMiddleware(app, **_rl_kwargs)
            register_rate_limit_middleware(_stats_proxy)

            logger.info(
                "RateLimitMiddleware enabled read=%d write=%d default=%d req/min burst=20",
                _READ_RPM,
                _WRITE_RPM,
                _DEFAULT_RPM,
            )
        except (OSError, ValueError, KeyError, RuntimeError) as _rl_err:  # narrowed from bare Exception
            logger.warning("RateLimitMiddleware not available: %s", _rl_err)
    else:
        logger.info("RateLimitMiddleware disabled (FIXOPS_DISABLE_RATE_LIMIT=1)")

    # Org-tier daily quota middleware — enforces per-billing-tier daily API call limits:
    #   Starter 1,000/day | Pro 10,000/day | Enterprise unlimited
    # Disabled when FIXOPS_DISABLE_TIER_RATE_LIMIT=1 (e.g. in CI/test environments)
    if os.getenv("FIXOPS_DISABLE_TIER_RATE_LIMIT") != "1":
        try:
            from apps.api.org_tier_rate_limit_middleware import OrgTierRateLimitMiddleware
            app.add_middleware(OrgTierRateLimitMiddleware)
            logger.info("OrgTierRateLimitMiddleware enabled (starter=1000/day, pro=10000/day, enterprise=unlimited)")
        except (OSError, ImportError, ValueError) as _trl_err:
            logger.warning("OrgTierRateLimitMiddleware not available: %s", _trl_err)
    else:
        logger.info("OrgTierRateLimitMiddleware disabled (FIXOPS_DISABLE_TIER_RATE_LIMIT=1)")

    app.add_middleware(RequestLoggingMiddleware)

    # Prometheus metrics middleware — tracks request counts, latencies, active
    # connections, and error rates.  Silently no-ops when prometheus_client is
    # not installed (graceful degradation — never breaks the app).
    app.add_middleware(PrometheusMetricsMiddleware)

    # Org ID Middleware — extracts org_id from auth state / headers / query
    # and stores it in a ContextVar so all downstream code can call
    # get_current_org_id() without carrying the Request object.
    # Must be added after auth/correlation middleware so request.state.org_id
    # (set by JWT decode) is already populated when this runs.
    app.add_middleware(OrgIdMiddleware)

    # GZip compression middleware — compresses responses >= 500 bytes.
    # Reduces bandwidth for large findings/dashboard payloads without extra deps.
    from starlette.middleware.gzip import GZipMiddleware
    app.add_middleware(GZipMiddleware, minimum_size=500)

    # Profiling middleware — adds X-Response-Time header, logs slow requests,
    # tracks per-endpoint P50/P95/P99 latencies.
    try:
        from core.profiling import ProfilingMiddleware
        app.add_middleware(ProfilingMiddleware)
        logger.info("ProfilingMiddleware enabled — X-Response-Time header + latency tracking")
    except ImportError as _prof_err:
        logger.warning("ProfilingMiddleware not available: %s", _prof_err)

    # Detailed Logging Middleware — captures full request/response payloads
    # Disabled by default in production. Set FIXOPS_DETAILED_LOGGING=1 to enable.
    if os.getenv("FIXOPS_DETAILED_LOGGING", "0") == "1":
        try:
            from apps.api.detailed_logging import DetailedLoggingMiddleware

            app.add_middleware(DetailedLoggingMiddleware)
            logger.info("DetailedLoggingMiddleware enabled — full payload capture active")
        except ImportError as _dl_err:
            logger.warning("DetailedLoggingMiddleware not available: %s", _dl_err)
    else:
        logger.info("DetailedLoggingMiddleware disabled (set FIXOPS_DETAILED_LOGGING=1 to enable)")

    # ML Learning Middleware — must be added after logging middleware (outer → inner)
    if LearningMiddleware is not None:
        app.add_middleware(LearningMiddleware)
        logger.info("LearningMiddleware enabled — API traffic will be captured for ML")

    # ── Global exception handler ─────────────────────────────────
    # Catches ALL unhandled exceptions and returns a safe 500 response
    # that never leaks stack traces, file paths, or internal details.
    # Compliance: SOC2 CC6.1, PCI-DSS 6.5.5, OWASP A09:2021
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse
    from starlette.exceptions import HTTPException as StarletteHTTPException

    _DOCS_BASE = "https://docs.aldeci.io/api"

    def _classify_exception(exc: Exception) -> tuple:
        """Return (error_category, suggested_action) based on exception type/message."""
        exc_type = type(exc).__name__.lower()
        exc_msg = str(exc).lower()
        if any(k in exc_type for k in ("database", "sqlite", "operational", "integrity", "db")):
            return "database", "retry in 30s; if persistent contact admin"
        if any(k in exc_msg for k in ("database", "sqlite", "no such table", "disk", "locked")):
            return "database", "retry in 30s; if persistent contact admin"
        if any(k in exc_type for k in ("auth", "token", "jwt", "permission", "credential")):
            return "authentication", "check your API key or Bearer token"
        if any(k in exc_msg for k in ("auth", "token", "permission", "forbidden", "unauthorized")):
            return "authentication", "check your API key or Bearer token"
        if any(k in exc_type for k in ("timeout", "connection", "requests", "httpx", "aiohttp")):
            return "external_service", "retry in 60s; upstream service may be degraded"
        if any(k in exc_msg for k in ("timeout", "connection refused", "upstream", "service unavailable")):
            return "external_service", "retry in 60s; upstream service may be degraded"
        if any(k in exc_type for k in ("validation", "value", "type", "pydantic")):
            return "validation", "check request body and parameter types"
        return "internal", "retry in 30s; if persistent contact admin with correlation_id"

    @app.exception_handler(Exception)
    async def _global_exception_handler(request, exc):
        """Catch unhandled exceptions — never leak internal details."""
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        trace_id = getattr(request.state, "trace_id", None)
        error_category, suggested_action = _classify_exception(exc)
        logger.error(
            "unhandled_exception",
            extra={
                "error_type": type(exc).__name__,
                "error_category": error_category,
                "path": request.url.path,
                "correlation_id": correlation_id,
                "trace_id": trace_id,
            },
            exc_info=exc,
        )
        content: Dict[str, Any] = {
            "detail": "Internal server error",
            "error_category": error_category,
            "suggested_action": suggested_action,
            "docs_link": f"{_DOCS_BASE}/errors#{error_category}",
            "correlation_id": correlation_id,
        }
        if trace_id:
            content["trace_id"] = trace_id
        return JSONResponse(status_code=500, content=content)

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(request, exc):
        """Return 422 with per-field detail for request validation failures."""
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        trace_id = getattr(request.state, "trace_id", None)
        field_errors = []
        for err in exc.errors():
            loc = " -> ".join(str(p) for p in err.get("loc", []))
            field_errors.append({
                "field": loc,
                "message": err.get("msg", "invalid value"),
                "expected_type": err.get("type", "unknown"),
            })
        content: Dict[str, Any] = {
            "detail": "Request validation failed",
            "error_category": "validation",
            "suggested_action": "check request body — see 'field_errors' for per-field details",
            "docs_link": f"{_DOCS_BASE}/errors#validation",
            "field_errors": field_errors,
            "correlation_id": correlation_id,
        }
        if trace_id:
            content["trace_id"] = trace_id
        return JSONResponse(status_code=422, content=content)

    # 4xx hint map: status_code -> (hint, suggested_action, docs_anchor)
    _4XX_HINTS: Dict[int, tuple] = {
        401: (
            "Provide X-API-Key header or Bearer token",
            "include 'X-API-Key: <token>' or 'Authorization: Bearer <jwt>' in your request",
            "authentication",
        ),
        403: (
            "Your role doesn't have access",
            "request elevated permissions or use an account with the required role (e.g. admin)",
            "authorization",
        ),
        404: (
            "Endpoint not found",
            "verify the URL; see /api/v1/system/routes for all available endpoints",
            "routing",
        ),
    }

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(request, exc):
        """Re-raise HTTP exceptions with correlation ID, trace ID, and actionable hints."""
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        trace_id = getattr(request.state, "trace_id", None)
        content: Dict[str, Any] = {
            "detail": exc.detail,
            "correlation_id": correlation_id,
        }
        if exc.status_code in _4XX_HINTS:
            hint, suggested_action, anchor = _4XX_HINTS[exc.status_code]
            content["hint"] = hint
            content["suggested_action"] = suggested_action
            content["docs_link"] = f"{_DOCS_BASE}/errors#{anchor}"
        if trace_id:
            content["trace_id"] = trace_id
        return JSONResponse(status_code=exc.status_code, content=content)

    @app.middleware("http")
    async def add_product_header(request, call_next):
        """Add X-Product-Name header to all responses."""
        response = await call_next(request)
        response.headers["X-Product-Name"] = branding["product_name"]
        response.headers["X-Product-Version"] = "1.0.0"
        return response

    origins_env = os.getenv("FIXOPS_ALLOWED_ORIGINS", "")
    origins = [origin.strip() for origin in origins_env.split(",") if origin.strip()]
    if not origins:
        env_name = os.getenv("ENVIRONMENT", "development")
        if env_name.lower() == "production":
            raise RuntimeError(
                "FIXOPS_ALLOWED_ORIGINS must be set in production. "
                "Refusing to start with default localhost origins."
            )
        origins = [
            "http://localhost:3000",
            "http://localhost:3001",  # Vite dev server (ui/aldeci) - alternate port
            "http://localhost:5173",  # Vite dev server (ui/aldeci)
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001",  # Vite dev server (ui/aldeci) - alternate port
            "http://127.0.0.1:5173",  # Vite dev server (ui/aldeci)
            "http://127.0.0.1:8000",
        ]
        logger.warning(
            "FIXOPS_ALLOWED_ORIGINS not set. "
            "Using default localhost origins. "
            "Set FIXOPS_ALLOWED_ORIGINS for production deployments."
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization", "Content-Type", "X-API-Key", "X-Request-ID",
            "X-Correlation-ID", "X-Org-ID", "Accept", "Origin", "Cache-Control",
        ],
    )

    normalizer = InputNormalizer()
    from .pipeline import (
        PipelineOrchestrator,  # lazy: avoids torch/sklearn at module import
    )
    orchestrator = PipelineOrchestrator()

    # API authentication setup
    auth_strategy = overlay.auth.get("strategy", "").lower()
    # Enterprise enforcement: if FIXOPS_API_TOKEN is set in env but overlay
    # doesn't declare a strategy, auto-promote to token-based auth.
    _env_api_token = os.getenv("FIXOPS_API_TOKEN", "").strip()
    if not auth_strategy and _env_api_token:
        auth_strategy = "token"
        logger.info("Auto-promoted auth strategy to 'token' (FIXOPS_API_TOKEN set)")
    header_name = overlay.auth.get(
        "header", "X-API-Key" if auth_strategy != "jwt" else "Authorization"
    )
    APIKeyHeader(name=header_name, auto_error=False)
    # Build expected tokens list from overlay config + env var
    expected_tokens = list(overlay.auth_tokens) if auth_strategy == "token" else []
    if auth_strategy == "token" and _env_api_token and _env_api_token not in expected_tokens:
        expected_tokens.append(_env_api_token)
    expected_tokens = tuple(expected_tokens)

    # Wave-0 refactor: auth closures extracted to auth_deps.py (RISK-01 gate).
    # _verify_api_key and _require_scope are now module-level functions imported
    # from .auth_deps.  We re-bind them here under the original local names so
    # all existing Depends(_verify_api_key) / Depends(_require_scope(...)) call
    # sites in this file continue to work without modification.
    from .auth_deps import require_scope as _require_scope  # noqa: PLC0415
    from .auth_deps import verify_api_key as _verify_api_key  # noqa: PLC0415

    allowlist = overlay.allowed_data_roots or (Path("data").resolve(),)
    for directory in overlay.data_directories.values():
        secure_path = verify_allowlisted_path(directory, allowlist)
        ensure_secure_directory(secure_path)

    archive_dir = overlay.data_directories.get("archive_dir")
    if archive_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        archive_dir = (root / "archive" / overlay.mode).resolve()
    archive_dir = verify_allowlisted_path(archive_dir, allowlist)
    archive = ArtefactArchive(archive_dir, allowlist=allowlist)

    analytics_dir = overlay.data_directories.get("analytics_dir")
    if analytics_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        analytics_dir = (root / "analytics" / overlay.mode).resolve()
    analytics_dir = verify_allowlisted_path(analytics_dir, allowlist)
    analytics_store = AnalyticsStore(analytics_dir, allowlist=allowlist)

    provenance_dir = overlay.data_directories.get("provenance_dir")
    if provenance_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        provenance_dir = (root / "artifacts" / "attestations" / overlay.mode).resolve()
    provenance_dir = verify_allowlisted_path(provenance_dir, allowlist)
    provenance_dir = ensure_secure_directory(provenance_dir)

    risk_dir = overlay.data_directories.get("risk_dir")
    if risk_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        risk_dir = (root / "artifacts").resolve()
    risk_dir = verify_allowlisted_path(risk_dir, allowlist)
    risk_dir = ensure_secure_directory(risk_dir)

    app.state.normalizer = normalizer
    app.state.orchestrator = orchestrator
    app.state.artifacts: Dict[str, Any] = {}  # type: ignore[misc]
    app.state.overlay = overlay
    app.state.archive = archive
    app.state.archive_records: Dict[str, Dict[str, Any]] = {}  # type: ignore[misc]
    app.state.analytics_store = analytics_store
    app.state.last_pipeline_result: Optional[Dict[str, Any]] = None  # type: ignore[misc]
    app.state.feedback = (
        FeedbackRecorder(overlay, analytics_store=analytics_store)
        if overlay.toggles.get("capture_feedback")
        else None
    )
    app.state.enhanced_engine = EnhancedDecisionEngine(
        overlay.enhanced_decision_settings
    )
    sbom_dir = overlay.data_directories.get("sbom_dir")
    if sbom_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        sbom_dir = (root / "artifacts" / "sbom").resolve()
    sbom_dir = verify_allowlisted_path(sbom_dir, allowlist)
    sbom_dir = ensure_secure_directory(sbom_dir)

    graph_dir = overlay.data_directories.get("graph_dir")
    if graph_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        graph_dir = (root / "analysis").resolve()
    graph_dir = verify_allowlisted_path(graph_dir, allowlist)
    graph_dir = ensure_secure_directory(graph_dir)

    evidence_dir = overlay.data_directories.get("evidence_dir")
    if evidence_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        evidence_dir = (root / "evidence").resolve()
    evidence_dir = verify_allowlisted_path(evidence_dir, allowlist)
    evidence_dir = ensure_secure_directory(evidence_dir)
    evidence_manifest_dir = ensure_secure_directory(evidence_dir / "manifests")
    evidence_bundle_dir = ensure_secure_directory(evidence_dir / "bundles")

    app.state.provenance_dir = provenance_dir
    app.state.risk_dir = risk_dir
    app.state.sbom_dir = sbom_dir
    app.state.graph_config = {
        "repo_path": Path(".").resolve(),
        "attestation_dir": provenance_dir,
        "sbom_dir": sbom_dir,
        "risk_dir": risk_dir,
        "releases_path": graph_dir / "releases.json",
    }
    app.state.evidence_manifest_dir = evidence_manifest_dir
    app.state.evidence_bundle_dir = evidence_bundle_dir
    uploads_dir = overlay.data_directories.get("uploads_dir")
    if uploads_dir is None:
        root = allowlist[0]
        uploads_dir = (root / "uploads" / overlay.mode).resolve()
    uploads_dir = verify_allowlisted_path(uploads_dir, allowlist)
    upload_manager = ChunkUploadManager(uploads_dir)
    app.state.upload_manager = upload_manager

    # ══════════════════════════════════════════════════════════════════════════
    # ROUTER REGISTRATION — grouped by domain
    # ══════════════════════════════════════════════════════════════════════════

    # ── Health ────────────────────────────────────────────────────────────────
    app.include_router(health_v1_router)  # Health endpoints with /api/v1 prefix

    # ── Version ───────────────────────────────────────────────────────────────
    from apps.api.version_router import router as version_router
    app.include_router(version_router)  # GET /api/v1/version

    # ── Import façade (P0 — Multica #4003/#4007) ──────────────────────────────
    # Mounted early so it lands within the 800-path OpenAPI cap.
    # Routes: POST /api/v1/import/repo, POST /api/v1/import/upload,
    #         GET  /api/v1/import/status/{job_id}
    try:
        from apps.api.import_router import router as import_router
        app.include_router(import_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Import router at /api/v1/import")
    except Exception as _import_router_err:
        _logger.warning("Import router not mounted: %s", _import_router_err)

    # Legacy /health endpoint — required by Dockerfile HEALTHCHECK and
    # scripts/docker-entrypoint.sh readiness probes that poll /health directly.
    @app.get("/health", tags=["health"])
    def legacy_health_check() -> Dict[str, Any]:
        """Legacy health endpoint for backward-compatible probes."""
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "service": "aldeci-api",
        }

    # ------------------------------------------------------------------
    # Prometheus /metrics endpoint
    # No auth required — metrics are not secret and Prometheus scrapers
    # cannot easily send custom headers.  Rate limiting is already exempt
    # for /api/v1/metrics in the RateLimitMiddleware config above.
    # Returns Prometheus text format when prometheus_client is installed,
    # otherwise returns a JSON summary (graceful degradation).
    # ------------------------------------------------------------------
    @app.get("/metrics", tags=["observability"], include_in_schema=True)
    def prometheus_metrics():
        """Prometheus metrics endpoint.

        Exposes:
          - fixops_http_requests_total{method, endpoint, status_code}
          - fixops_http_request_duration_seconds{method, endpoint}
          - fixops_active_connections
          - fixops_pipeline_executions_total{status}
          - fixops_pipeline_duration_seconds
          - fixops_errors_total{error_type}

        Scrape with: ``prometheus.yml`` job ``scrape_configs[].static_configs.targets``
        pointing at ``host:8000``, path ``/metrics``.
        """
        return metrics_response()

    @app.get("/api/v1/status", dependencies=[Depends(_verify_api_key)])
    async def authenticated_status() -> Dict[str, Any]:
        """Authenticated status endpoint."""
        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "service": "fixops-api",
            "version": os.getenv("FIXOPS_VERSION", "1.0.0"),
        }

    @app.get("/api/v1/search", dependencies=[Depends(_verify_api_key)])
    async def global_search(
        q: str = Query("", description="Search query"),
        entity_types: Optional[str] = Query(
            None,
            description="Comma-separated entity types to search: findings,assets,evidence,tickets. Default: all.",
        ),
        limit: int = Query(50, ge=1, le=200, description="Max results per entity type"),
    ) -> Dict[str, Any]:
        """Cross-entity global search across findings, assets, evidence, and tickets.

        Returns unified results sorted by relevance with type annotations so the
        UI can render heterogeneous result cards in a single list.
        """
        results: list[Dict[str, Any]] = []
        searched_types: list[str] = []
        errors: Dict[str, str] = {}

        if not q:
            return {"query": q, "results": [], "total": 0, "searched_types": []}

        q_lower = q.lower()
        allowed_types = {"findings", "assets", "evidence", "tickets"}
        if entity_types:
            requested = {t.strip().lower() for t in entity_types.split(",")}
            search_types = requested & allowed_types
        else:
            search_types = allowed_types

        def _match(text: str) -> bool:
            return q_lower in text.lower()

        # ── 1. Findings (AnalyticsDB) ──────────────────────────────
        if "findings" in search_types:
            searched_types.append("findings")
            try:
                from core.analytics_db import AnalyticsDB

                adb = AnalyticsDB()
                all_findings = adb.list_findings(limit=500)
                count = 0
                for f in all_findings:
                    fd = f.to_dict() if hasattr(f, "to_dict") else f
                    searchable = " ".join(str(v) for v in fd.values() if v)
                    if _match(searchable):
                        results.append(
                            {
                                "type": "finding",
                                "id": fd.get("id"),
                                "title": fd.get("title", ""),
                                "severity": fd.get("severity", ""),
                                "status": fd.get("status", ""),
                                "source": fd.get("source", ""),
                                "cve_id": fd.get("cve_id", ""),
                                "application_id": fd.get("application_id", ""),
                            }
                        )
                        count += 1
                        if count >= limit:
                            break
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                errors["findings"] = type(exc).__name__

        # ── 2. Assets / Inventory ──────────────────────────────────
        if "assets" in search_types:
            searched_types.append("assets")
            try:
                from core.inventory_db import InventoryDB

                idb = InventoryDB()
                inv_results = idb.search_inventory(q, limit=limit)
                for category, items in inv_results.items():
                    for item in items:
                        results.append(
                            {
                                "type": "asset",
                                "sub_type": category.rstrip("s"),  # applications -> application
                                "id": item.get("id", ""),
                                "name": item.get("name", ""),
                                "description": item.get("description", ""),
                                "status": item.get("status", ""),
                                "criticality": item.get("criticality", ""),
                            }
                        )
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                errors["assets"] = type(exc).__name__

        # ── 3. Evidence bundles ────────────────────────────────────
        if "evidence" in search_types:
            searched_types.append("evidence")
            try:
                import glob as _glob

                evidence_dir = os.path.join("data", "evidence")
                if os.path.isdir(evidence_dir):
                    count = 0
                    for fp in sorted(_glob.glob(os.path.join(evidence_dir, "*.json")))[-500:]:
                        try:
                            with open(fp) as fh:
                                bundle = json.load(fh)
                            searchable = " ".join(
                                str(bundle.get(k, ""))
                                for k in ("id", "type", "framework", "status", "app_id")
                            )
                            if _match(searchable):
                                results.append(
                                    {
                                        "type": "evidence",
                                        "id": bundle.get("id", os.path.basename(fp).replace(".json", "")),
                                        "framework": bundle.get("framework", ""),
                                        "signed": bundle.get("signature") is not None,
                                        "status": bundle.get("status", "sealed"),
                                        "created_at": bundle.get("created_at") or bundle.get("timestamp", ""),
                                    }
                                )
                                count += 1
                                if count >= limit:
                                    break
                        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                            continue
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                errors["evidence"] = type(exc).__name__

        # ── 4. Remediation tickets / tasks ─────────────────────────
        if "tickets" in search_types:
            searched_types.append("tickets")
            try:
                from core.services.remediation import RemediationService

                svc = RemediationService()
                # Search across all orgs — get recent tasks and filter
                import sqlite3 as _sqlite3

                conn = _sqlite3.connect(svc.db_path)
                conn.row_factory = _sqlite3.Row
                try:
                    pattern = f"%{q}%"
                    rows = conn.execute(
                        """SELECT * FROM remediation_tasks
                           WHERE title LIKE ? OR description LIKE ?
                              OR assignee LIKE ? OR ticket_id LIKE ?
                           ORDER BY updated_at DESC LIMIT ?""",
                        (pattern, pattern, pattern, pattern, limit),
                    ).fetchall()
                    for row in rows:
                        task = dict(row)
                        results.append(
                            {
                                "type": "ticket",
                                "id": task.get("task_id", ""),
                                "title": task.get("title", ""),
                                "severity": task.get("severity", ""),
                                "status": task.get("status", ""),
                                "assignee": task.get("assignee", ""),
                                "app_id": task.get("app_id", ""),
                                "ticket_id": task.get("ticket_id", ""),
                            }
                        )
                finally:
                    conn.close()
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                errors["tickets"] = type(exc).__name__

        response: Dict[str, Any] = {
            "query": q,
            "results": results,
            "total": len(results),
            "searched_types": searched_types,
        }
        if errors:
            response["errors"] = errors
        return response

    # ── ASPM — Application Security Posture Management ────────────────────────
    # Wave-1 extraction: all standalone ASPM include_router blocks moved to
    # suite-api/apps/api/sub_apps/aspm_app.py (registrar pattern).
    from apps.api.sub_apps.aspm_app import register_aspm_routers as _reg_aspm
    _reg_aspm(app, _verify_api_key, _require_scope, _logger)
    # ── CSPM — Cloud Security Posture Management ─────────────────────────────
    # Wave-2 extraction: 64 standalone CSPM include_router blocks moved to
    # suite-api/apps/api/sub_apps/cspm_app.py (registrar pattern). 7 loop-bound
    # routers (cspm_engine, cspm_deep, cspm_connector, drift, posture,
    # posture_benchmark, privilege_escalation_detector) remain in
    # _extra_apps_routers and will be moved by a future loop-refactor wave.
    from apps.api.sub_apps.cspm_app import register_cspm_routers as _reg_cspm
    _reg_cspm(app, _verify_api_key, _require_scope, _logger)
    # ── CTEM — Continuous Threat Exposure Management ──────────────────────────
    # Wave-3 extraction: all standalone CTEM include_router blocks moved to
    # suite-api/apps/api/sub_apps/ctem_app.py (registrar pattern). Loop-bound
    # routers (predictions, mpte tuples) remain in _extra_apps_routers.
    from apps.api.sub_apps.ctem_app import register_ctem_routers as _reg_ctem
    _reg_ctem(app, _verify_api_key, _require_scope, _logger)
    # ── GRC — Governance, Risk, and Compliance ────────────────────────────────
    # Wave-4 extraction: all standalone GRC include_router blocks moved to
    # suite-api/apps/api/sub_apps/grc_app.py (registrar pattern). Loop-bound
    # routers in _extra_apps_routers and evidence-risk loops remain in app.py.
    from apps.api.sub_apps.grc_app import register_grc_routers as _reg_grc
    _reg_grc(app, _verify_api_key, _require_scope, _logger)
    app.include_router(enhanced_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
    # Enterprise reachability analysis API
    if reachability_router:
        app.include_router(reachability_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))])

    app.include_router(inventory_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:sbom"))])

    # ── Platform — Auth / Users / Admin / Tenancy / System / MCP / Ingestion / Webhooks ──
    # Wave-5 extraction: all standalone Platform include_router blocks moved to
    # suite-api/apps/api/sub_apps/platform_app.py (registrar pattern).
    # Note: Wave 4 (GRC) had not yet landed when Wave 5 was sequenced; GRC
    # registrar is already wired above.
    from apps.api.sub_apps.platform_app import (
        register_platform_routers as _reg_platform,  # noqa: PLC0415
    )
    _reg_platform(app, _verify_api_key, _require_scope, _logger)

    app.include_router(
        policies_router,
        dependencies=[
            Depends(_verify_api_key),
            Depends(_require_scope("write:findings")),
        ],
    )

    # ── Findings / Vuln Lifecycle / Risk Register ──────────────────────────────
    # Findings lifecycle management — status, assignment, SLA, bulk ops, export
    if findings_router:
        app.include_router(
            findings_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Findings management router")

    # Security Findings Engine — unified findings aggregator
    if security_findings_router:
        app.include_router(
            security_findings_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Security Findings Engine router")

    # Risk Register — enterprise risk lifecycle (CRUD, scoring, KRI, heat map, board report)
    if risk_register_router:
        app.include_router(
            risk_register_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Risk Register router")

    # Vulnerability lifecycle tracker — state machine from DISCOVERED to CLOSED
    if vuln_lifecycle_router:
        app.include_router(
            vuln_lifecycle_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Vuln Lifecycle router")

    # CTEM 15-stage pipeline — ingest, batch processing, stage monitoring
    if ctem_pipeline_router:
        app.include_router(
            ctem_pipeline_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted CTEM Pipeline router")

    # Enhanced LLM Council — calibration, feedback, recent verdicts
    if council_enhanced_router:
        app.include_router(
            council_enhanced_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Enhanced Council router")

    # LLM Council — status/health/composition (GET /api/v1/llm/council/status)
    if llm_council_router:
        app.include_router(
            llm_council_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted LLM Council router at /api/v1/llm/council")

    # Risk Scoring — module-level import ensures this is always available
    if risk_scoring_router:
        app.include_router(
            risk_scoring_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Risk Scoring router at /api/v1/risk-scoring")

    # ── SOAR / IR Playbooks / Security Metrics ─────────────────────────────────
    # soar_router — moved to ctem_app.py (Wave-C-final 2026-05-03)

    # Security Metrics & OKR Tracking — DORA, benchmarks, SLA compliance, ROI, reports
    if security_metrics_router:
        app.include_router(
            security_metrics_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Security Metrics & OKR router")

    # ir_playbook_router — moved to ctem_app.py (Wave-C-final 2026-05-03)
    # ir_playbook_runner_router — moved to ctem_app.py (Wave-C-final 2026-05-03)

    # Security Policy Document Generator — generate, approve, archive, export policies
    if policy_generator_router:
        app.include_router(
            policy_generator_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Policy Generator router")


    # ── Compliance / Reports / Threat Intel ────────────────────────────────────
    # Compliance Reports — multi-framework reporting
    if compliance_reports_router:
        app.include_router(
            compliance_reports_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Compliance Reports router")

    # threat_intel_router — moved to ctem_app.py (Wave-C-final 2026-05-03)


    # API Analytics — usage monitoring
    if api_analytics_router:
        app.include_router(
            api_analytics_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted API Analytics router")

    # API Gateway Security Engine — rate limiting, IP filter, versioning, throttle, analytics
    if api_gateway_router:
        app.include_router(
            api_gateway_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted API Gateway Security router")

    # correlation_router — moved to ctem_app.py (Wave-C-final 2026-05-03)

    # ── Scanners — Trivy / Semgrep / Snyk / AWS / Azure ───────────────────────
    # Trivy Scanner — real Docker image / filesystem / repo vulnerability scanning
    if trivy_router:
        app.include_router(
            trivy_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Trivy Scanner router")

    # Semgrep Scanner — SAST scanning via semgrep CLI
    if semgrep_router:
        app.include_router(
            semgrep_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Semgrep Scanner router")

    # Snyk Scanner — mounted in sub_apps/platform_app.py with read:scans scope
    # (legacy /api/v1/scan/snyk surface retired 2026-05-04; new /api/v1/snyk surface
    # exposes /v1/orgs, /v1/orgs/{org}/projects, /v1/test, /v1/orgs/.../issues, /v1/reporting)

    # Snyk-OSS connector — REAL Snyk family via Trivy + OSV-Scanner + Semgrep CE
    if snyk_oss_router:
        app.include_router(
            snyk_oss_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Snyk-OSS (Trivy+OSV) connector router")



    # Unified Triage — crown jewel endpoint (finding + attack path + compliance + SLA)
    # FAIL Engine — expanded fault injection, drill grading, neglect zones (Pillar V2)
    app.include_router(fail_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("attack:execute"))])

    # IAM/SSO Connector — moved to platform_app.py (Wave 5)

    # PR Gate & CI/CD Gate — evaluate findings, post to GitHub PRs, CI exit-code gating
    if pr_gate_router:
        app.include_router(
            pr_gate_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted PR Gate router")

    # APP_ID Configuration — app registry, classification, lifecycle
    if app_config_router:
        app.include_router(
            app_config_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted APP_ID Configuration router")

    # Material Change Detection — drift detection, SLA impact, blast radius
    if material_change_router:
        app.include_router(
            material_change_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Material Change Detection router")

    # ── Connectors / Integrations / Webhooks ───────────────────────────────────
    # Container Security Connector (Trivy + Grype + Dockle + kube-bench) — REAL
    if container_security_connector_router:
        app.include_router(
            container_security_connector_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Container Security Connector router")

    # Universal Connectors — moved to platform_app.py (Wave 5)

    # ── Evidence / Audit (non-Platform domain — stays inline) ─────────────────
    app.include_router(reports_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
    app.include_router(audit_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
    app.include_router(audit_evidence_export_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
    if org_export_router:
        app.include_router(org_export_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Org GDPR Export router at /api/v1/orgs/{org_id}/export")
    app.include_router(support_router, dependencies=[Depends(_verify_api_key)])
    _logger.info("Mounted Support router at /api/v1/support")
    if evidence_chain_router:
        app.include_router(evidence_chain_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:evidence"))])
        _logger.info("Mounted Evidence Chain router")

    app.include_router(policy_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
    _logger.info("Mounted Policy Engine router at /api/v1/policy-engine")

    # Scanner Ingest — 25+ scanner parsers (ZAP, Burp, Nessus, Checkmarx, etc.)
    if scanner_ingest_router:
        app.include_router(
            scanner_ingest_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Scanner Ingest router")

    # Import façade is mounted early (near version_router) — see Multica #4007.

    # Scanners alias — POST /api/v1/scanners/ingest (JSON-body alias for demo path)
    if scanners_alias_router:
        app.include_router(
            scanners_alias_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Scanners alias router at /api/v1/scanners/ingest")

    # Dependency-Track — SBOM analysis via OWASP Dependency-Track
    if dtrack_router:
        app.include_router(
            dtrack_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:sbom"))],
        )
        _logger.info("Mounted Dependency-Track router")

    # Sandbox PoC Verifier — Docker-isolated exploit verification
    if sandbox_router:
        app.include_router(
            sandbox_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("attack:execute")),
            ],
        )
        _logger.info("Mounted Sandbox PoC Verifier router")

    # Suite-Attack routers (offensive security) — Wave-6: moved to
    # suite-api/apps/api/sub_apps/ctem_app.py (register_ctem_routers wave-6 section).
    # mpte_router, micro_pentest_router, vuln_discovery_router,
    # mpte_orchestrator_router, secrets_router all registered there.

    # Feed Registry — MUST be mounted BEFORE feeds_router to avoid /{feed_id} catch-all swallowing /registry
    if feed_registry_router:
        app.include_router(
            feed_registry_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:feeds"))],
        )
        _logger.info("Mounted Feed Registry router at /api/v1/feeds/registry")

    # Suite-Feeds router (real-time vulnerability intelligence)
    if feeds_router:
        app.include_router(feeds_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:feeds"))])

    # Knowledge Brain router (central intelligence graph — from suite-core/api/)
    try:
        from api.brain_router import router as brain_router

        app.include_router(brain_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Loaded Knowledge Brain router from suite-core")
    except ImportError as e:
        _logger.warning("Knowledge Brain router not available: %s", e)

    # -------------------------------------------------------------------
    # Suite-Core routers (intelligence, ML, copilot, pipeline)
    # -------------------------------------------------------------------
    # AutoFix — write operations require write:findings scope
    if autofix_router:
        app.include_router(
            autofix_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("write:findings")),
            ],
        )
        _logger.info("Mounted AutoFix router with write:findings scope guard")

    # Queue status router — moved to platform_app.py (Wave 5)
    # Cache management router — moved to platform_app.py (Wave 5)

    # Profiling metrics router — GET /api/v1/metrics/performance (no extra scope needed)
    try:
        from core.profiling import profiling_router

        app.include_router(profiling_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Loaded Profiling metrics router")
    except ImportError as _prof_err:
        _logger.warning("Profiling metrics router not available: %s", _prof_err)

    # _core_routers — Wave-6: all entries moved to sub-app registrars.
    # ASPM entries (nerve_center, decisions, deduplication, smart_dedup,
    #   autofix_verify, postfix_verify, mitre_mapper, supply_chain):
    #   → suite-api/apps/api/sub_apps/aspm_app.py wave-6 section
    # Platform/Brain entries (ml_router, airgap, fuzzy_identity, exposure_case,
    #   pipeline, copilot, agents, predictions, llm, algorithmic, llm_monitor,
    #   llm_guard, streaming, code_to_cloud, quantum_crypto, zero_gravity,
    #   single_agent, knowledge_graph, vllm, mcp_protocol, self_learning,
    #   llm_loop_metrics, developer_profiles):
    #   → suite-api/apps/api/sub_apps/platform_app.py wave-6 section
    # CTEM entries (causal, gnn, monte_carlo, runtime, threat_modeling,
    #   ai_code_guardian, attack_surface, attack_surface_manager,
    #   attack_surface_monitor):
    #   → suite-api/apps/api/sub_apps/ctem_app.py wave-6 section

    # ── Suite-Attack — Offensive Security / SAST / DAST / CSPM / Fuzzer ───────
    # Wave-6: _attack_extra_routers moved to ctem_app.py wave-6 section.
    # attack_sim, sast, container, dast, dast_pentest, cspm_router,
    # api_fuzzer, malware all registered in register_ctem_routers wave-6.

    # ── Suite-Evidence-Risk — Compliance / Risk / Evidence / Graph ─────────────
    # Wave-6: _evidence_routers moved to grc_app.py wave-6 section.
    # evidence, risk, graph, provenance, compliance_engine, biz_ctx,
    # biz_ctx_enhanced all registered in register_grc_routers wave-6.

    # ── Suite-Integrations — External Tools / Webhooks / IaC / IDE / SIEM ─────
    # Wave-6: _integration_routers moved to platform_app.py wave-6 section.
    # integrations, webhooks, iac, ide, siem all registered in
    # register_platform_routers wave-6.
    # Legacy mcp_router removed — superseded by MCP Auto-Discovery router.

    # Webhooks receiver — moved to platform_app.py (Wave 5)

    # OSS Tools — needs /api/v1 prefix normalization
    if oss_tools_router:
        app.include_router(
            oss_tools_router, prefix="/api/v1",
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:sbom"))],
        )
        _logger.info("Mounted OSS Tools router from suite-integrations")

    # Detailed Logging REST API — query/stream/clear logs
    try:
        from apps.api.detailed_logging import logs_router as detailed_logs_router

        app.include_router(
            detailed_logs_router,
            prefix="/api/v1",
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Detailed Logs router at /api/v1/logs")
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as _lr_err:
        _logger.warning("Detailed Logs router not available: %s", _lr_err)

    # ── Apps/API Domain Routers — Analytics / Asset / CSPM / Exec / Feed / Risk
    # -------------------------------------------------------------------
    # Additional apps/api routers (wired in this session)
    # -------------------------------------------------------------------
    # ── Apps/API Domain Routers — Wave-6: all _extra_apps_routers entries
    # moved to their respective sub-app registrars:
    #
    # ASPM (aspm_app.py wave-6): container_scanner, cicd, context_engine,
    #   fix_engine, pr_generator, sbom, secret_scanner, bulk_operations,
    #   asset_inventory, patch_manager, verification
    #
    # CSPM (cspm_app.py wave-6): cspm_engine, cspm_deep, cspm_connector,
    #   privilege_escalation_detector
    #
    # CTEM (ctem_app.py wave-6): intelligent_security, mitre_attack_coverage,
    #   pentest, auto_pentest, soc_automation, breach_response,
    #   incident_response, threat_hunting, ip_reputation, security_kb
    #
    # GRC (grc_app.py wave-6): compliance_planner, evidence_collector,
    #   exception_policy, executive_report, exec_security_reports,
    #   risk_acceptance, risk_quantifier, security_roi, vendor_scorecard,
    #   security_scorecard_engine, security_scorecard, regulatory_tracker_engine,
    #   questionnaire
    #
    # Platform (platform_app.py wave-6): analytics_dashboard, analytics_routes,
    #   apikey, backup, backup_validator, changelog, dashboard_builder,
    #   developer_portal, api_docs, drift, feed_registry, feed_manager,
    #   integration_health, metrics_aggregator, notification, posture,
    #   posture_benchmark, rasp, runtime_protection, prioritizer, rate_limit,
    #   tenant_rate_limiter, retention, slack_bot, system_health, tag,
    #   threat_hunting (platform analytics), user_analytics, versioning,
    #   webhook_events, workflow_engine, graphrag, duckdb_analytics

    # Public (unauthenticated) scorecard endpoint — no extra auth deps
    if security_scorecard_public_router:
        app.include_router(security_scorecard_public_router)
        _logger.info("Mounted Security Scorecard public router")

    _CHUNK_SIZE = 1024 * 1024
    _RAW_BYTES_THRESHOLD = 4 * 1024 * 1024

    async def _read_limited(
        file: UploadFile, stage: str
    ) -> Tuple[SpooledTemporaryFile, int]:
        """Stream an upload into a spooled file respecting the configured limit."""

        limit = overlay.upload_limit(stage)
        total = 0
        try:
            buffer = SpooledTemporaryFile(max_size=_CHUNK_SIZE, mode="w+b")
            while total < limit:
                remaining = limit - total
                chunk = await file.read(min(_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                if total + len(chunk) > limit:
                    buffer.close()
                    raise HTTPException(
                        status_code=413,
                        detail={
                            "message": f"Upload for stage '{stage}' exceeded limit",
                            "max_bytes": limit,
                            "received_bytes": total + len(chunk),
                        },
                    )
                buffer.write(chunk)
                total += len(chunk)
        except HTTPException:
            raise
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            buffer.close()
            raise
        buffer.seek(0)
        return buffer, total

    def _maybe_materialise_raw(
        buffer: SpooledTemporaryFile,
        total: int,
        *,
        threshold: int = _RAW_BYTES_THRESHOLD,
    ) -> Optional[bytes]:
        if total > threshold:
            return None
        buffer.seek(0)
        data = buffer.read()
        buffer.seek(0)
        return data

    def _validate_content_type(file: UploadFile, expected: tuple[str, ...]) -> None:
        if file.content_type and file.content_type not in expected:
            raise HTTPException(
                status_code=415,
                detail={
                    "message": "Unsupported content type",
                    "received": file.content_type,
                    "expected": list(expected),
                },
            )

    def _store(
        stage: str,
        payload: Any,
        *,
        original_filename: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> None:
        logger.debug("Storing stage %s", stage)
        app.state.artifacts[stage] = payload
        try:
            record = app.state.archive.persist(
                stage,
                payload,
                original_filename=original_filename,
                raw_bytes=raw_bytes,
            )
        except (
            Exception
        ) as exc:  # pragma: no cover - persistence must not break ingestion
            logger.exception("Failed to persist artefact stage %s", stage)
            record = {"stage": stage, "error": str(exc)}
        app.state.archive_records[stage] = record

    supported_stages = {
        "design",
        "sbom",
        "sarif",
        "cve",
        "vex",
        "cnapp",
        "context",
    }

    def _process_design(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        text_stream = io.TextIOWrapper(
            buffer, encoding="utf-8", errors="ignore", newline=""  # type: ignore[arg-type]
        )
        try:
            reader = csv.DictReader(text_stream)
            rows = [
                row
                for row in reader
                if any((value or "").strip() for value in row.values())
            ]
            columns = reader.fieldnames or []
        finally:
            buffer = text_stream.detach()  # type: ignore[assignment]
        if not rows:
            raise HTTPException(status_code=400, detail="Design CSV contained no rows")

        overlay: OverlayConfig = app.state.overlay
        strict_validation = overlay.toggles.get("strict_validation", False)

        if strict_validation:
            required_columns = {
                "component",
                "subcomponent",
                "owner",
                "data_class",
                "description",
                "control_scope",
            }
            missing_columns = required_columns - set(columns)
            if missing_columns:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Design CSV missing required columns (strict mode)",
                        "missing_columns": sorted(missing_columns),
                        "required_columns": sorted(required_columns),
                    },
                )

        dataset = {"columns": columns, "rows": rows}
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("design", dataset, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "design",
            "input_filename": filename,
            "row_count": len(rows),
            "columns": columns,
            "data": dataset,
        }

    def _process_sbom(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        buffer.seek(0)
        try:
            sbom_data = json.load(buffer)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid JSON in SBOM: {exc}"
            ) from exc

        overlay: OverlayConfig = app.state.overlay
        strict_validation = overlay.toggles.get("strict_validation", False)

        bom_format = sbom_data.get("bomFormat")
        if bom_format and bom_format not in ("CycloneDX", "SPDX"):
            if strict_validation:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": f"Unsupported SBOM format: {bom_format}",
                        "supported_formats": ["CycloneDX", "SPDX"],
                    },
                )
            else:
                logger.warning(
                    "SBOM has unsupported bomFormat: %s, continuing with provider fallback",
                    bom_format,
                )

        if not bom_format:
            components = sbom_data.get("components")
            detected_manifests = sbom_data.get("detectedManifests")
            artifacts = sbom_data.get("artifacts")
            descriptor = sbom_data.get("descriptor")
            # SPDX format detection — SPDX docs use spdxVersion/SPDXID/packages
            spdx_version = sbom_data.get("spdxVersion")
            spdx_id = sbom_data.get("SPDXID")
            spdx_packages = sbom_data.get("packages")

            has_known_format = (
                isinstance(components, list)
                or isinstance(detected_manifests, dict)
                or isinstance(artifacts, list)
                or isinstance(descriptor, dict)
                or isinstance(spdx_version, str)
                or isinstance(spdx_id, str)
                or isinstance(spdx_packages, list)
            )

            if not has_known_format and strict_validation:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "SBOM missing bomFormat and has unrecognized structure",
                        "hint": "Provide bomFormat field or use a known format (CycloneDX, SPDX, GitHub dependency snapshot, Syft)",
                    },
                )

        buffer.seek(0)
        try:
            sbom: NormalizedSBOM = normalizer.load_sbom(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("SBOM normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SBOM: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("SBOM normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SBOM: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("sbom", sbom, original_filename=filename, raw_bytes=raw_bytes)

        # ── Forward SBOM to Dependency-Track (fire-and-forget) ──────
        dtrack_status = None
        try:
            from core.security_connectors import DependencyTrackConnector

            dtrack = DependencyTrackConnector()
            if dtrack.configured:
                project_name = (
                    sbom_data.get("metadata", {}).get("component", {}).get("name")
                    or os.path.splitext(filename)[0]
                    or "fixops-upload"
                )
                sbom_json = json.dumps(sbom_data)
                outcome = dtrack.upload_sbom(
                    project_name=project_name,
                    sbom_content=sbom_json,
                )
                dtrack_status = outcome.status
                if outcome.success:
                    logger.info(
                        "SBOM forwarded to Dependency-Track: project=%s token=%s",
                        project_name,
                        outcome.details.get("token", ""),
                    )
                else:
                    logger.warning(
                        "Dependency-Track SBOM upload returned: %s",
                        outcome.details.get("error", "unknown"),
                    )
        except ImportError:
            pass  # DTrack connector not available
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError, OSError) as exc:
            logger.debug("Dependency-Track forwarding skipped: %s", type(exc).__name__)

        result: Dict[str, Any] = {
            "status": "ok",
            "stage": "sbom",
            "input_filename": filename,
            "metadata": sbom.metadata,
            "component_preview": [
                component.to_dict() for component in sbom.components[:5]
            ],
            "format": sbom.format,
        }
        if dtrack_status:
            result["dependency_track"] = {"status": dtrack_status}
        return result

    def _process_cve(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        try:
            cve_feed: NormalizedCVEFeed = normalizer.load_cve_feed(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("CVE feed normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CVE feed: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("CVE feed normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CVE feed: {type(exc).__name__}"
            ) from exc

        overlay: OverlayConfig = app.state.overlay
        strict_validation = overlay.toggles.get("strict_validation", False)

        if cve_feed.errors and strict_validation:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "CVE feed contains validation errors (strict mode)",
                    "record_count": cve_feed.metadata.get("record_count", 0),
                    "validation_errors": cve_feed.errors[:10],
                    "total_errors": len(cve_feed.errors),
                    "hint": "Use official CVE JSON 5.1.1 format or ensure all required fields are present",
                },
            )

        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("cve", cve_feed, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "cve",
            "input_filename": filename,
            "record_count": cve_feed.metadata.get("record_count", 0),
            "validation_errors": cve_feed.errors,
        }

    def _process_vex(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        try:
            vex_doc: NormalizedVEX = normalizer.load_vex(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("VEX normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse VEX document: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("VEX normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse VEX document: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("vex", vex_doc, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "vex",
            "input_filename": filename,
            "assertions": vex_doc.metadata.get("assertion_count", 0),
            "not_affected": len(vex_doc.suppressed_refs),
        }

    def _process_cnapp(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        try:
            cnapp_payload: NormalizedCNAPP = normalizer.load_cnapp(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("CNAPP normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CNAPP payload: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("CNAPP normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CNAPP payload: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("cnapp", cnapp_payload, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "cnapp",
            "input_filename": filename,
            "asset_count": cnapp_payload.metadata.get(
                "asset_count", len(cnapp_payload.assets)
            ),
            "finding_count": cnapp_payload.metadata.get(
                "finding_count", len(cnapp_payload.findings)
            ),
        }

    def _process_sarif(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        try:
            sarif: NormalizedSARIF = normalizer.load_sarif(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("SARIF normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SARIF: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("SARIF normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SARIF: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("sarif", sarif, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "sarif",
            "input_filename": filename,
            "metadata": sarif.metadata,
            "tools": sarif.tool_names,
        }

    def _process_context(
        buffer: SpooledTemporaryFile,
        total: int,
        filename: str,
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            context: NormalizedBusinessContext = normalizer.load_business_context(
                buffer, content_type=content_type
            )
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("Business context normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse business context: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("Business context normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse business context: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("context", context, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "context",
            "input_filename": filename,
            "format": context.format,
            "ssvc_factors": context.ssvc,
            "components": context.components,
        }

    def _process_from_buffer(
        stage: str,
        buffer: SpooledTemporaryFile,
        total: int,
        filename: str,
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        if stage == "design":
            return _process_design(buffer, total, filename)
        if stage == "sbom":
            return _process_sbom(buffer, total, filename)
        if stage == "cve":
            return _process_cve(buffer, total, filename)
        if stage == "vex":
            return _process_vex(buffer, total, filename)
        if stage == "cnapp":
            return _process_cnapp(buffer, total, filename)
        if stage == "sarif":
            return _process_sarif(buffer, total, filename)
        if stage == "context":
            return _process_context(buffer, total, filename, content_type)
        raise HTTPException(status_code=400, detail=f"Unsupported stage '{stage}'")

    def _process_from_path(
        stage: str, path: Path, filename: str, content_type: Optional[str] = None
    ) -> Dict[str, Any]:
        buffer = SpooledTemporaryFile(max_size=_CHUNK_SIZE, mode="w+b")
        try:
            with path.open("rb") as handle:
                shutil.copyfileobj(handle, buffer)  # type: ignore[misc]
            total = buffer.tell()
            buffer.seek(0)
            return _process_from_buffer(stage, buffer, total, filename, content_type)
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/design", dependencies=[Depends(_verify_api_key)])
    async def ingest_design(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file, ("text/csv", "application/vnd.ms-excel", "application/csv")
        )
        buffer, total = await _read_limited(file, "design")
        try:
            return _process_design(buffer, total, file.filename or "design.csv")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/sbom", dependencies=[Depends(_verify_api_key)])
    async def ingest_sbom(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "sbom")
        try:
            # Validate JSON structure if content-type is JSON
            if file.content_type in ("application/json", "text/json"):
                buffer.seek(0)
                try:
                    json.load(buffer)
                    buffer.seek(0)
                except json.JSONDecodeError as exc:
                    raise HTTPException(
                        status_code=422,
                        detail=f"Invalid JSON payload: {exc}",
                    ) from exc
            return _process_sbom(buffer, total, file.filename or "sbom.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/cve", dependencies=[Depends(_verify_api_key)])
    async def ingest_cve(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "cve")
        try:
            return _process_cve(buffer, total, file.filename or "cve.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/vex", dependencies=[Depends(_verify_api_key)])
    async def ingest_vex(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(file, ("application/json", "text/json"))
        buffer, total = await _read_limited(file, "vex")
        try:
            return _process_vex(buffer, total, file.filename or "vex.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/cnapp", dependencies=[Depends(_verify_api_key)])
    async def ingest_cnapp(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(file, ("application/json", "text/json"))
        buffer, total = await _read_limited(file, "cnapp")
        try:
            return _process_cnapp(buffer, total, file.filename or "cnapp.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/sarif", dependencies=[Depends(_verify_api_key)])
    async def ingest_sarif(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "sarif")
        try:
            return _process_sarif(buffer, total, file.filename or "scan.sarif")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/context", dependencies=[Depends(_verify_api_key)])
    async def ingest_context(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/x-yaml",
                "text/yaml",
                "application/yaml",
                "text/plain",
            ),
        )
        buffer, total = await _read_limited(file, "context")
        try:
            return _process_context(
                buffer, total, file.filename or "context.yaml", file.content_type
            )
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/api/v1/ingest/multipart", dependencies=[Depends(_verify_api_key)])
    async def ingest_multipart(
        files: List[UploadFile] = File(...),
        format_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Scanner-agnostic multipart ingestion endpoint.

        Accepts multiple files in various formats (SARIF, CycloneDX, SPDX, VEX, CNAPP,
        dark web intel, etc.) and normalizes them into a unified Finding model.

        Features:
        - Auto-detection of format variants
        - Parallel processing for multiple files
        - Format drift handling with lenient parsing
        - Performance: 10K findings in <2 min

        Args:
            files: One or more files to ingest
            format_hint: Optional format hint (sarif, cyclonedx, spdx, vex, cnapp, dark_web_intel)

        Returns:
            Ingestion results with normalized findings and asset inventory
        """
        import asyncio

        from apps.api.ingestion import get_ingestion_service

        service = get_ingestion_service()

        # Limit concurrent file processing to prevent resource exhaustion
        MAX_CONCURRENT_FILES = 10
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_FILES)

        async def process_file(file: UploadFile) -> Dict[str, Any]:
            """Process a single file and return result dict."""
            async with semaphore:
                try:
                    buffer, total = await _read_limited(file, "sarif")
                    buffer.seek(0)
                    content = buffer.read()
                    buffer.close()
                    result = await service.ingest(
                        content=content,
                        filename=file.filename,
                        content_type=file.content_type,
                        format_hint=format_hint,
                    )
                    return {
                        "filename": file.filename,
                        "status": result.status,
                        "format_detected": result.format_detected,
                        "detection_confidence": result.detection_confidence,
                        "findings_count": result.findings_count,
                        "assets_count": result.assets_count,
                        "processing_time_ms": result.processing_time_ms,
                        "errors": result.errors,
                        "warnings": result.warnings,
                        "_findings_count": result.findings_count,
                        "_assets_count": result.assets_count,
                        "_errors": result.errors,
                    }
                except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                    logger.error("Failed to ingest %s: %s", file.filename, type(e).__name__)
                    error_type = type(e).__name__
                    safe_error = f"Ingestion failed: {error_type}"
                    return {
                        "filename": file.filename,
                        "status": "error",
                        "error": safe_error,
                        "_findings_count": 0,
                        "_assets_count": 0,
                        "_errors": [f"{file.filename}: {safe_error}"],
                    }

        # Process all files in parallel using asyncio.gather
        raw_results = await asyncio.gather(*[process_file(f) for f in files])

        # Aggregate results
        results = []
        total_findings = 0
        total_assets = 0
        errors = []

        for raw in raw_results:
            total_findings += raw.pop("_findings_count", 0)
            total_assets += raw.pop("_assets_count", 0)
            file_errors = raw.pop("_errors", [])
            if file_errors:
                errors.extend(file_errors)
            results.append(raw)

        return {
            "status": "success" if not errors else "partial",
            "files_processed": len(files),
            "total_findings": total_findings,
            "total_assets": total_assets,
            "results": results,
            "errors": errors,
        }

    @app.get("/api/v1/ingest/assets", dependencies=[Depends(_verify_api_key)])
    async def get_asset_inventory() -> Dict[str, Any]:
        """
        Get the dynamic asset inventory.

        Returns all discovered assets from ingested security data.
        """
        from apps.api.ingestion import get_ingestion_service

        service = get_ingestion_service()
        assets = service.get_asset_inventory()

        return {
            "total": len(assets),
            "assets": [asset.model_dump() for asset in assets],
        }

    @app.get("/api/v1/ingest/formats", dependencies=[Depends(_verify_api_key)])
    async def list_supported_formats() -> Dict[str, Any]:
        """
        List all supported ingestion formats.

        Returns the available normalizers and their configuration.
        """
        from apps.api.ingestion import get_registry

        registry = get_registry()
        normalizers = []

        for name in registry.list_normalizers():
            normalizer = registry.get_normalizer(name)
            if normalizer:
                normalizers.append(
                    {
                        "name": name,
                        "enabled": normalizer.enabled,
                        "priority": normalizer.priority,
                        "description": normalizer.config.description,
                        "supported_versions": normalizer.config.supported_versions,
                    }
                )

        return {
            "total": len(normalizers),
            "normalizers": normalizers,
        }

    @app.post("/inputs/{stage}/chunks/start", dependencies=[Depends(_verify_api_key)])
    async def initialise_chunk_upload(
        stage: str, payload: Dict[str, Any] = Body(...)
    ) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(
                status_code=404, detail=f"Stage '{stage}' not recognised"
            )
        filename = str(
            payload.get("file_name") or payload.get("filename") or f"{stage}.bin"
        )
        try:
            total_bytes = (
                int(payload.get("total_size"))  # type: ignore[arg-type]
                if payload.get("total_size") is not None
                else None
            )
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="total_size must be an integer")
        checksum = payload.get("checksum")
        content_type = payload.get("content_type")
        session = upload_manager.create_session(
            stage,
            filename=filename,
            total_bytes=total_bytes,
            checksum=checksum,
            content_type=content_type,
        )
        return {"status": "initialised", "session": session.to_dict()}

    @app.put(
        "/inputs/{stage}/chunks/{session_id}", dependencies=[Depends(_verify_api_key)]
    )
    async def upload_chunk(
        stage: str,
        session_id: str,
        chunk: UploadFile = File(...),
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(
                status_code=404, detail=f"Stage '{stage}' not recognised"
            )

        # Validate offset parameter
        if offset is not None and offset < 0:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid offset: {offset}. Offset must be non-negative.",
            )

        data = await chunk.read()
        try:
            session = upload_manager.append_chunk(session_id, data, offset=offset)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        except ValueError as exc:
            logger.warning("upload.append_chunk.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid chunk data")
        return {"status": "chunk_received", "session": session.to_dict()}

    @app.post(
        "/inputs/{stage}/chunks/{session_id}/complete",
        dependencies=[Depends(_verify_api_key)],
    )
    async def complete_upload(stage: str, session_id: str) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(
                status_code=404, detail=f"Stage '{stage}' not recognised"
            )
        try:
            session = upload_manager.finalise(session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        except ValueError as exc:
            logger.warning("upload.complete.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid upload state")
        path = session.path
        if path is None:
            raise HTTPException(status_code=500, detail="Upload payload missing")
        response = _process_from_path(
            stage, path, session.filename, session.content_type
        )
        response["upload_session"] = session.to_dict()
        return response

    @app.get(
        "/inputs/{stage}/chunks/{session_id}", dependencies=[Depends(_verify_api_key)]
    )
    async def upload_status(stage: str, session_id: str) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(
                status_code=404, detail=f"Stage '{stage}' not recognised"
            )
        try:
            session = upload_manager.status(session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        return {"status": "ok", "session": session.to_dict()}

    async def _run_legacy_pipeline_impl() -> Dict[str, Any]:
        overlay: OverlayConfig = app.state.overlay
        required = overlay.required_inputs
        missing = [stage for stage in required if stage not in app.state.artifacts]
        if missing:
            raise HTTPException(
                status_code=400,
                detail={"message": "Missing required artefacts", "missing": missing},
            )

        if overlay.toggles.get("enforce_ticket_sync") and not overlay.jira.get(
            "project_key"
        ):
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Ticket synchronisation enforced but Jira project_key missing",
                    "integration": overlay.jira,
                },
            )

        run_id = uuid.uuid4().hex

        try:
            result = orchestrator.run(
                design_dataset=app.state.artifacts.get(
                    "design", {"columns": [], "rows": []}
                ),
                sbom=app.state.artifacts["sbom"],
                sarif=app.state.artifacts["sarif"],
                cve=app.state.artifacts["cve"],
                overlay=overlay,
                vex=app.state.artifacts.get("vex"),
                cnapp=app.state.artifacts.get("cnapp"),
                context=app.state.artifacts.get("context"),
            )
        except Exception as exc:
            import traceback as _tb
            tb_str = _tb.format_exc()
            logger.exception("Pipeline orchestrator failed: %s\n%s", exc, tb_str)
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Pipeline execution failed",
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "traceback": tb_str[-2000:],
                },
            )
        result["run_id"] = run_id

        severity_overview = result.get("severity_overview", {})
        guardrail_evaluation = result.get("guardrail_evaluation", {})
        result["highest_severity"] = severity_overview.get("highest")
        result["guardrail_status"] = guardrail_evaluation.get("status")
        analytics_store = getattr(app.state, "analytics_store", None)
        if analytics_store is not None:
            try:
                persistence = analytics_store.persist_run(run_id, result)
            except (
                Exception
            ):  # pragma: no cover - analytics persistence must not block pipeline
                logger.exception(
                    "Failed to persist analytics artefacts for run %s", run_id
                )
                persistence = {}
            if persistence:
                result["analytics_persistence"] = persistence
                analytics_section = result.get("analytics")
                if isinstance(analytics_section, dict):
                    analytics_section["persistence"] = persistence
        if app.state.archive_records:
            result["artifact_archive"] = ArtefactArchive.summarise(
                app.state.archive_records
            )
            app.state.archive_records = {}
        if overlay.toggles.get("auto_attach_overlay_metadata", True):
            result["overlay"] = overlay.to_sanitised_dict()
            result["overlay"]["required_inputs"] = list(required)

        app.state.last_pipeline_result = result

        return result

    @app.get("/pipeline/run", dependencies=[Depends(_verify_api_key)])
    async def get_legacy_pipeline_run() -> Dict[str, Any]:
        """Legacy pipeline trigger (GET)."""
        return await _run_legacy_pipeline_impl()

    @app.post("/pipeline/run", dependencies=[Depends(_verify_api_key)])
    async def post_legacy_pipeline_run() -> Dict[str, Any]:
        """Legacy pipeline trigger (POST)."""
        return await _run_legacy_pipeline_impl()

    @app.get("/api/v1/triage", dependencies=[Depends(_verify_api_key)])
    async def get_triage(
        view: str = "events",
        cluster_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Transform last pipeline result into triage inbox format.

        Args:
            view: View mode - 'events' (individual findings) or 'clusters' (deduplicated groups)
            cluster_status: Filter clusters by status (only applies when view=clusters)

        Returns:
            Triage data with rows and summary. When view=clusters, rows represent
            deduplicated finding groups with event counts.
        """
        last_result = app.state.last_pipeline_result

        if last_result is None:
            raise HTTPException(
                status_code=404,
                detail="No pipeline results available. Run /api/v1/brain/pipeline/run first.",
            )

        # If view=clusters, return deduplicated cluster view
        if view == "clusters":
            return await _get_triage_clusters(cluster_status)

        rows = []
        crosswalk = last_result.get("crosswalk", [])
        evidence_bundle = last_result.get("evidence_bundle", {})
        compliance_status = last_result.get("compliance_status", {})
        exploitability_insights = last_result.get("exploitability_insights", {})

        retention_days = 2555

        for idx, entry in enumerate(crosswalk):
            design_row = entry.get("design_row", {})
            findings = entry.get("findings", [])
            cves = entry.get("cves", [])

            component_name = design_row.get("component", "unknown")
            exposure = design_row.get("exposure", "internal")
            internet_facing = exposure == "internet"

            for finding in findings:
                rule_id = finding.get("rule_id", "unknown")
                message = finding.get("message", "No description")
                level = finding.get("level", "warning")
                file_path = finding.get("file", "")
                line = finding.get("line", 0)

                severity_map = {"error": "high", "warning": "medium", "note": "low"}
                severity = severity_map.get(level, "medium")

                location = f"{file_path}:{line}" if file_path else component_name

                row_id = f"sarif-{idx}-{rule_id}"

                rows.append(
                    {
                        "id": row_id,
                        "severity": severity,
                        "title": f"{rule_id} - {message[:80]}",
                        "source": "SAST",
                        "repo": component_name,
                        "location": location,
                        "exploitability": {"kev": False, "epss": 0.0},
                        "age_days": 0,
                        "internet_facing": internet_facing,
                        "description": message,
                        "remediation": f"Review and fix {rule_id} in {location}",
                        "evidence_bundle": {
                            "id": evidence_bundle.get("bundle_id", "unknown"),
                            "signature_algorithm": "RSA-SHA256",
                            "retention_days": retention_days,
                            "retained_until": (
                                datetime.now(timezone.utc)
                                + timedelta(days=retention_days)
                            ).strftime("%m/%d/%Y"),
                            "sha256": hashlib.sha256(
                                evidence_bundle.get("bundle_id", "unknown").encode()
                            ).hexdigest(),
                        },
                        "decision": {
                            "verdict": "review" if severity == "high" else "allow",
                            "confidence": 0.75,
                            "ssvc_outcome": "scheduled",
                            "rationale": f"SAST finding with {severity} severity in {component_name}",
                            "signals": {
                                "severity": severity,
                                "internet_facing": internet_facing,
                                "source": "SAST",
                            },
                        },
                        "compliance_mappings": _get_compliance_mappings(
                            compliance_status, "SAST"
                        ),
                    }
                )

            for cve in cves:
                cve_id = cve.get("cve_id", "unknown")
                cve_severity = cve.get("severity", "medium")
                exploited = cve.get("exploited", False)
                raw_cve = cve.get("raw", {})
                short_desc = raw_cve.get("shortDescription", "No description")

                epss_score = 0.0
                if exploitability_insights:
                    epss_data = exploitability_insights.get("epss", {})
                    epss_score = epss_data.get(cve_id, 0.0)

                age_days = 7

                verdict = (
                    "block"
                    if (exploited or epss_score > 0.7) and cve_severity == "critical"
                    else "review"
                )
                ssvc_outcome = "immediate" if verdict == "block" else "scheduled"

                row_id = f"cve-{idx}-{cve_id}"

                rows.append(
                    {
                        "id": row_id,
                        "severity": cve_severity,
                        "title": f"{cve_id} - {short_desc[:80]}",
                        "source": "CVE",
                        "repo": component_name,
                        "location": component_name,
                        "exploitability": {"kev": exploited, "epss": epss_score},
                        "age_days": age_days,
                        "internet_facing": internet_facing,
                        "description": short_desc,
                        "remediation": f"Update {component_name} to patch {cve_id}",
                        "evidence_bundle": {
                            "id": evidence_bundle.get("bundle_id", "unknown"),
                            "signature_algorithm": "RSA-SHA256",
                            "retention_days": retention_days,
                            "retained_until": (
                                datetime.now(timezone.utc)
                                + timedelta(days=retention_days)
                            ).strftime("%m/%d/%Y"),
                            "sha256": hashlib.sha256(
                                evidence_bundle.get("bundle_id", "unknown").encode()
                            ).hexdigest(),
                        },
                        "decision": {
                            "verdict": verdict,
                            "confidence": 0.95 if exploited else 0.80,
                            "ssvc_outcome": ssvc_outcome,
                            "rationale": f"CVE with {cve_severity} severity, KEV={exploited}, EPSS={epss_score:.2f}",
                            "signals": {
                                "kev": exploited,
                                "epss": epss_score,
                                "severity": cve_severity,
                                "internet_facing": internet_facing,
                                "age_days": age_days,
                            },
                        },
                        "compliance_mappings": _get_compliance_mappings(
                            compliance_status, "CVE"
                        ),
                    }
                )

        new_7d = sum(1 for r in rows if r["age_days"] <= 7)
        high_critical = sum(1 for r in rows if r["severity"] in ["high", "critical"])
        exploitable = sum(
            1
            for r in rows
            if r["exploitability"]["kev"] or r["exploitability"]["epss"] > 0.7
        )
        internet_facing_count = sum(1 for r in rows if r["internet_facing"])

        return {
            "rows": rows,
            "summary": {
                "total": len(rows),
                "new_7d": new_7d,
                "high_critical": high_critical,
                "exploitable": exploitable,
                "internet_facing": internet_facing_count,
            },
        }

    @app.get("/api/v1/triage/export", dependencies=[Depends(_verify_api_key)])
    async def export_triage(format: str = "csv") -> Any:
        """Export triage data as CSV or JSON."""
        last_result = app.state.last_pipeline_result

        if last_result is None:
            raise HTTPException(
                status_code=404,
                detail="No pipeline results available. Run /api/v1/brain/pipeline/run first.",
            )

        triage_data = await get_triage()
        rows = triage_data["rows"]

        if format == "json":
            from fastapi.responses import JSONResponse

            return JSONResponse(
                content={"data": rows, "summary": triage_data["summary"]},
                headers={
                    "Content-Disposition": 'attachment; filename="fixops-triage-export.json"',
                    "Access-Control-Expose-Headers": "Content-Disposition",
                },
            )
        elif format == "csv":
            import io

            from fastapi.responses import StreamingResponse

            output = io.StringIO()
            if rows:
                fieldnames = [
                    "id",
                    "severity",
                    "title",
                    "source",
                    "repo",
                    "location",
                    "age_days",
                    "internet_facing",
                ]
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow(
                        {
                            "id": row["id"],
                            "severity": row["severity"],
                            "title": row["title"],
                            "source": row["source"],
                            "repo": row["repo"],
                            "location": row["location"],
                            "age_days": row["age_days"],
                            "internet_facing": row["internet_facing"],
                        }
                    )

            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={
                    "Content-Disposition": 'attachment; filename="fixops-triage-export.csv"',
                    "Access-Control-Expose-Headers": "Content-Disposition",
                },
            )
        else:
            raise HTTPException(
                status_code=400, detail="Invalid format. Use 'csv' or 'json'."
            )

    async def _get_triage_clusters(
        cluster_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get triage data in cluster (deduplicated) view.

        Returns finding clusters instead of individual events, showing
        deduplicated groups with event counts and representative info.
        """
        from pathlib import Path

        from core.services.deduplication import DeduplicationService

        db_path = (
            Path(os.environ.get("FIXOPS_DATA_DIR", "data"))
            / "deduplication"
            / "dedup.db"
        )
        dedup_service = DeduplicationService(db_path=db_path)
        clusters = dedup_service.get_clusters(
            org_id="default",
            status=cluster_status,
            limit=1000,
            offset=0,
        )

        # Batch fetch events for all clusters to avoid N+1 query pattern
        cluster_ids = [c["cluster_id"] for c in clusters]
        events_by_cluster = dedup_service.get_events_for_clusters(
            cluster_ids, limit_per_cluster=100
        )

        rows = []
        for cluster in clusters:
            # Get events for this cluster from the batch result
            events: List[Dict[str, Any]] = events_by_cluster.get(
                cluster["cluster_id"], []
            )

            # Compute severity (highest among events, fallback to cluster metadata)
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            max_severity = cluster.get("severity", "low")
            for event in events:
                event_severity = event.get("severity", "low")
                if severity_order.get(event_severity, 0) > severity_order.get(
                    max_severity, 0
                ):
                    max_severity = event_severity

            # Compute exploitability (any KEV or max EPSS)
            has_kev = any(event.get("kev", False) for event in events)
            max_epss = max((event.get("epss", 0.0) for event in events), default=0.0)

            # Get representative event for title/description
            representative = events[0] if events else {}

            rows.append(
                {
                    "id": cluster["cluster_id"],
                    "cluster_id": cluster["cluster_id"],
                    "severity": max_severity,
                    "title": cluster.get(
                        "title", representative.get("title", "Unknown")
                    ),
                    "source": cluster.get(
                        "source", representative.get("source", "Unknown")
                    ),
                    "event_count": cluster.get("event_count", len(events)),
                    "first_seen": cluster.get("first_seen"),
                    "last_seen": cluster.get("last_seen"),
                    "status": cluster.get("status", "open"),
                    "exploitability": {"kev": has_kev, "epss": max_epss},
                    "correlation_key": cluster.get("correlation_key"),
                    "fingerprint": cluster.get("fingerprint"),
                    "stages": list(set(e.get("stage", "unknown") for e in events)),
                    "locations": list(
                        set(e.get("location", "") for e in events if e.get("location"))
                    ),
                }
            )

        # Compute summary
        high_critical = sum(1 for r in rows if r["severity"] in ["high", "critical"])
        exploitable = sum(
            1
            for r in rows
            if r["exploitability"]["kev"] or r["exploitability"]["epss"] > 0.7
        )
        open_count = sum(1 for r in rows if r["status"] == "open")

        return {
            "view": "clusters",
            "rows": rows,
            "summary": {
                "total_clusters": len(rows),
                "total_events": sum(r["event_count"] for r in rows),
                "high_critical": high_critical,
                "exploitable": exploitable,
                "open": open_count,
                "noise_reduction": f"{(1 - len(rows) / max(sum(r['event_count'] for r in rows), 1)) * 100:.1f}%"
                if rows
                else "0%",
            },
        }

    def _get_compliance_mappings(
        compliance_status: Dict[str, Any], source_type: str
    ) -> list:
        """Extract compliance mappings from compliance_status."""
        mappings = []
        frameworks = compliance_status.get("frameworks", [])

        for framework in frameworks[:3]:
            framework_name = framework.get("name", "")
            controls = framework.get("controls", [])

            if source_type == "CVE" and controls:
                for control in controls[:2]:
                    mappings.append(
                        {
                            "framework": framework_name,
                            "control": control.get("id", ""),
                            "description": control.get("title", ""),
                        }
                    )
            elif source_type == "SAST" and controls:
                for control in controls[:1]:
                    mappings.append(
                        {
                            "framework": framework_name,
                            "control": control.get("id", ""),
                            "description": control.get("title", ""),
                        }
                    )

        return mappings

    @app.get("/api/v1/graph", dependencies=[Depends(_verify_api_key)])
    async def get_graph() -> Dict[str, Any]:
        """Transform last pipeline result into interactive graph format."""
        last_result = app.state.last_pipeline_result

        if last_result is None:
            raise HTTPException(
                status_code=404,
                detail="No pipeline results available. Run /api/v1/brain/pipeline/run first.",
            )

        nodes = []
        edges = []
        crosswalk = last_result.get("crosswalk", [])
        context_summary = last_result.get("context_summary", {})
        exploitability_insights = last_result.get("exploitability_insights", {})

        services_seen = set()
        components_seen = set()

        context_components = {}
        for comp in context_summary.get("components", []):
            name = comp.get("component", "")
            if name:
                context_components[name] = comp

        for idx, entry in enumerate(crosswalk):
            design_row = entry.get("design_row", {})
            findings = entry.get("findings", [])
            cves = entry.get("cves", [])

            component_name = design_row.get("component", f"component-{idx}")
            service_name = design_row.get("service", component_name)
            exposure = design_row.get("exposure", "internal")

            context = context_components.get(component_name, {})
            criticality = context.get("criticality", "standard")
            data_classification = context.get("data_classification", [])

            if service_name not in services_seen:
                services_seen.add(service_name)
                nodes.append(
                    {
                        "id": f"service-{service_name}",
                        "type": "service",
                        "label": service_name,
                        "criticality": criticality,
                        "exposure": exposure,
                        "internet_facing": exposure == "internet",
                        "has_pii": "pii" in data_classification,
                    }
                )

            if component_name not in components_seen:
                components_seen.add(component_name)
                nodes.append(
                    {
                        "id": f"component-{component_name}",
                        "type": "component",
                        "label": component_name,
                        "criticality": criticality,
                        "exposure": exposure,
                        "internet_facing": exposure == "internet",
                        "has_pii": "pii" in data_classification,
                    }
                )

                edges.append(
                    {
                        "id": f"edge-service-{service_name}-{component_name}",
                        "source": f"service-{service_name}",
                        "target": f"component-{component_name}",
                        "type": "contains",
                    }
                )

            for finding_idx, finding in enumerate(findings):
                rule_id = finding.get("rule_id", f"finding-{finding_idx}")
                level = finding.get("level", "warning")
                message = finding.get("message", "No description")
                file_path = finding.get("file", "")

                severity_map = {"error": "high", "warning": "medium", "note": "low"}
                severity = severity_map.get(level, "medium")

                finding_id = f"finding-{component_name}-{rule_id}-{finding_idx}"
                nodes.append(
                    {
                        "id": finding_id,
                        "type": "finding",
                        "label": rule_id,
                        "severity": severity,
                        "message": message[:100],
                        "file": file_path,
                        "source": "SAST",
                        "kev": False,
                        "epss": 0.0,
                    }
                )

                edges.append(
                    {
                        "id": f"edge-{component_name}-{finding_id}",
                        "source": f"component-{component_name}",
                        "target": finding_id,
                        "type": "has_issue",
                    }
                )

            for cve_idx, cve in enumerate(cves):
                cve_id = cve.get("cve_id", f"cve-{cve_idx}")
                cve_severity = cve.get("severity", "medium")
                exploited = cve.get("exploited", False)
                raw_cve = cve.get("raw", {})
                short_desc = raw_cve.get("shortDescription", "No description")

                epss_score = 0.0
                if exploitability_insights:
                    epss_data = exploitability_insights.get("epss", {})
                    epss_score = epss_data.get(cve_id, 0.0)

                cve_node_id = f"cve-{component_name}-{cve_id}"
                nodes.append(
                    {
                        "id": cve_node_id,
                        "type": "cve",
                        "label": cve_id,
                        "severity": cve_severity,
                        "message": short_desc[:100],
                        "source": "CVE",
                        "kev": exploited,
                        "epss": epss_score,
                    }
                )

                edges.append(
                    {
                        "id": f"edge-{component_name}-{cve_node_id}",
                        "source": f"component-{component_name}",
                        "target": cve_node_id,
                        "type": "has_issue",
                    }
                )

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "services": len(services_seen),
                "components": len(components_seen),
                "issues": len([n for n in nodes if n["type"] in ["finding", "cve"]]),
                "kev_count": len([n for n in nodes if n.get("kev", False)]),
            },
        }

    @app.get("/analytics/dashboard", dependencies=[Depends(_verify_api_key)])
    async def analytics_dashboard(limit: int = 10) -> Dict[str, Any]:
        store: Optional[AnalyticsStore] = getattr(app.state, "analytics_store", None)
        if store is None:
            raise HTTPException(
                status_code=404,
                detail="Analytics persistence disabled for this profile",
            )
        try:
            return store.load_dashboard(limit=limit)
        except ValueError as exc:  # pragma: no cover - defensive guard
            logger.warning("analytics.dashboard.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid analytics request") from exc

    @app.get("/analytics/runs/{run_id}", dependencies=[Depends(_verify_api_key)])
    async def analytics_run(run_id: str) -> Dict[str, Any]:
        store: Optional[AnalyticsStore] = getattr(app.state, "analytics_store", None)
        if store is None:
            raise HTTPException(
                status_code=404,
                detail="Analytics persistence disabled for this profile",
            )
        try:
            data = store.load_run(run_id)
        except ValueError as exc:
            logger.warning("analytics.run.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid run ID") from exc
        has_content = bool(
            data.get("forecasts")
            or data.get("exploit_snapshots")
            or data.get("ticket_metrics")
        )
        feedback_section = data.get("feedback")
        if isinstance(feedback_section, Mapping):
            has_content = has_content or bool(
                feedback_section.get("events") or feedback_section.get("outcomes")
            )
        if not has_content:
            raise HTTPException(
                status_code=404, detail="No analytics persisted for run"
            )
        return data

    @app.post("/feedback", dependencies=[Depends(_verify_api_key)])
    async def submit_feedback(payload: Dict[str, Any]) -> Dict[str, Any]:
        recorder: Optional[FeedbackRecorder] = app.state.feedback
        if recorder is None:
            raise HTTPException(
                status_code=400, detail="Feedback capture disabled in this profile"
            )
        try:
            entry = recorder.record(payload)
        except ValueError as exc:
            logger.warning("feedback.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid feedback payload") from exc
        return entry

    # ------------------------------------------------------------------
    # Universal Connector Framework — router + scheduler (Phase 1)
    # ------------------------------------------------------------------
    try:
        from apps.api.connector_routes import router as connector_router

        app.include_router(
            connector_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Connector Gateway router at /api/v1/connectors")
    except ImportError as exc:
        _logger.warning("Connector Gateway router not loaded: %s", exc)

    # kpi_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # ------------------------------------------------------------------
    # Unified Security Metrics Dashboard — single-call all personas
    # ------------------------------------------------------------------
    try:
        from apps.api.unified_dashboard_router import (
            router as _unified_dashboard_router,
        )

        app.include_router(
            _unified_dashboard_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Unified Dashboard router at /api/v1/unified-dashboard")
    except ImportError as exc:
        _logger.warning("Unified Dashboard router not loaded: %s", exc)

    # auto_evidence_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)

    # ------------------------------------------------------------------
    # Security Query Language (RQL DSL) router — GAP-024
    # ------------------------------------------------------------------
    try:
        from apps.api.security_query_language_router import (
            router as _sql_router,
        )

        app.include_router(
            _sql_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Security Query Language router at /api/v1/sql")
    except ImportError as exc:
        _logger.warning("Security Query Language router not loaded: %s", exc)

    # ------------------------------------------------------------------
    # Deployment Manager router — moved to platform_app.py (Wave 5)

    # ------------------------------------------------------------------
    # MCP Auto-Discovery router (must be mounted after all other routers
    # so that the startup hook can introspect the full route table)
    # ------------------------------------------------------------------
    app.include_router(
        mcp_discovery_router,
        dependencies=[Depends(_verify_api_key)],
    )
    _mcp_register_startup(app)
    _logger.info("Mounted MCP Auto-Discovery router at /api/v1/mcp")

    # ------------------------------------------------------------------
    # Startup hooks: database, EventBus, route logging, env validation
    # ------------------------------------------------------------------
    @app.on_event("startup")
    async def _validate_environment():
        """Warn about missing or insecure environment configuration."""
        token = os.getenv("FIXOPS_API_TOKEN", "")
        if not token:
            _logger.warning(
                "FIXOPS_API_TOKEN is not set — API authentication is disabled. "
                "Set it in .env or environment (see .env.example)."
            )
        elif token in ("changeme", "changeme-generate-a-real-token", "test", "dev"):
            _logger.warning(
                "FIXOPS_API_TOKEN is set to a default/insecure value — "
                "generate a real token: python3 -c \"import secrets; print(f'fixops_sk_{secrets.token_urlsafe(32)}')\""
            )

        jwt_secret = os.getenv("FIXOPS_JWT_SECRET", "")
        if not jwt_secret:
            _logger.info(
                "FIXOPS_JWT_SECRET is not set — auto-generating (tokens won't survive restarts)"
            )

        # Check for at least one LLM provider (optional but useful)
        llm_keys = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"]
        has_llm = any(os.getenv(k) for k in llm_keys)
        has_self_hosted = os.getenv("FIXOPS_VLLM_URL") or os.getenv("FIXOPS_OLLAMA_URL")
        if not has_llm and not has_self_hosted:
            _logger.info(
                "No LLM provider configured — AI consensus/AutoFix will use "
                "deterministic fallback. Set OPENAI_API_KEY or FIXOPS_OLLAMA_URL "
                "for full AI capability."
            )

        _logger.info(
            "Environment: mode=%s, data_dir=%s, rate_limit=%s",
            os.getenv("FIXOPS_MODE", "enterprise"),
            os.getenv("FIXOPS_DATA_DIR", ".fixops_data"),
            "disabled" if os.getenv("FIXOPS_DISABLE_RATE_LIMIT") == "1" else "enabled",
        )

    @app.on_event("startup")
    async def _init_enterprise_db():
        """Initialize the enterprise DatabaseManager (PostgreSQL / SQLite)."""
        try:
            from core.db.enterprise.session import DatabaseManager

            await DatabaseManager.initialize()
            _logger.info("Enterprise DatabaseManager initialized")
        except ImportError as exc:
            _logger.warning("Enterprise DB init skipped: %s", exc)

    @app.on_event("shutdown")
    async def _close_enterprise_db():
        """Gracefully close the enterprise database pool."""
        try:
            from core.db.enterprise.session import DatabaseManager

            await DatabaseManager.close()
            _logger.info("Enterprise DatabaseManager closed")
        except (ImportError, AttributeError):
            pass  # DB manager not available in this deployment
        except ImportError as exc:
            _logger.debug("Enterprise DB close error: %s", type(exc).__name__)

    @app.on_event("startup")
    async def _wire_event_subscribers():
        """Register EventBus subscribers so emitted events trigger handlers."""
        try:
            from core.event_subscribers import register_all_subscribers

            count = register_all_subscribers()
            _logger.info("EventBus: %d subscribers registered at startup", count)
        except ImportError as exc:
            _logger.warning("EventBus subscriber registration failed: %s", exc)

        try:
            from core.cross_category_subscribers import (
                register_cross_category_subscribers,
            )
            register_cross_category_subscribers()
            _logger.info("Cross-category subscribers registered")
        except Exception as e:
            _logger.warning("Cross-category subscribers not loaded: %s", e)

        # Wire activity feed persistence (P3 Vision Gap)
        try:
            from apps.api.gap_router import record_activity_event
            from core.event_bus import get_event_bus

            bus = get_event_bus()

            async def _activity_feed_recorder(event):
                """Persist every event to the activity feed SQLite DB."""
                et = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
                record_activity_event(et, event.source, event.data, event.org_id)

            bus.subscribe_all(_activity_feed_recorder)
            _logger.info("Activity feed recorder wired to EventBus (wildcard)")
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            _logger.warning("Activity feed recorder wiring failed: %s", exc)

    @app.on_event("startup")
    async def _python_compat_check():
        """Warn if running on Python 3.14 (dataclasses slots bug)."""
        import sys as _sys
        if _sys.version_info[:2] == (3, 14):
            _logger.warning(
                "Python %s detected — known dataclasses slots bug (cpython#142214). "
                "A runtime patch is applied but Python 3.11-3.13 is recommended "
                "for production. Docker images use Python 3.11.",
                _sys.version,
            )

    @app.on_event("startup")
    async def _log_mounted_routes():
        """Log all mounted routes and optionally fail-fast if critical routes missing."""
        routes = [r for r in app.routes if hasattr(r, "path")]
        prefixes = {
            "/".join(r.path.split("/")[:4])
            for r in routes
            if r.path.startswith("/api/")
        }
        _logger.info(
            "API startup complete: %d routes mounted across %d prefixes",
            len(routes),
            len(prefixes),
        )

        # Critical prefixes that must exist for a functional deployment
        critical = [
            "/api/v1/nerve-center",
            "/api/v1/copilot",
            "/api/v1/brain",
            "/api/v1/attack-sim",
            "/api/v1/feeds",
            "/api/v1/evidence",
            "/api/v1/risk",
            "/api/v1/stream",
        ]
        missing = [p for p in critical if p not in prefixes]

        if missing:
            _logger.warning("MISSING CRITICAL PREFIXES: %s", missing)
            if os.getenv("FIXOPS_FAIL_FAST", "").lower() in ("1", "true", "yes"):
                _logger.error("FAIL_FAST enabled — aborting due to missing routes")
                import sys

                sys.exit(1)
        else:
            _logger.info("All %d critical route prefixes verified OK", len(critical))

    # ------------------------------------------------------------------
    # LLM Council composition check — warn if < 2 providers configured
    # ------------------------------------------------------------------
    @app.on_event("startup")
    async def _check_llm_council_composition():
        """Warn at startup if the LLM council cannot form consensus (< 2 members)."""
        import os as _os

        _PROVIDER_ENV_VARS = [
            ("anthropic", ["ANTHROPIC_API_KEY", "FIXOPS_ANTHROPIC_KEY"]),
            ("openai", ["OPENAI_API_KEY", "FIXOPS_OPENAI_KEY"]),
            ("gemini", ["GOOGLE_API_KEY", "FIXOPS_GEMINI_KEY"]),
            ("openrouter", ["OPENROUTER_API_KEY", "FIXOPS_OPENROUTER_KEY"]),
            ("mulerouter", ["MULEROUTER_API_KEY"]),
        ]
        # Self-hosted providers (Ollama/vLLM) count as configured — no key needed
        self_hosted_count = 2  # ollama + vllm always available (use default URLs)
        cloud_configured = [
            name
            for name, envs in _PROVIDER_ENV_VARS
            if any(_os.getenv(e, "").strip() for e in envs)
        ]
        total_configured = len(cloud_configured) + self_hosted_count
        if total_configured < 2:
            _logger.warning(
                "LLM council has %d member — disagreement-resolution disabled. "
                "Add a second LLM key to .env to enable multi-LLM consensus. "
                "Configured cloud providers: %s. "
                "See docs/llm_council_setup.md for env-var names.",
                total_configured,
                cloud_configured or ["none"],
            )
        else:
            _logger.info(
                "LLM council: %d providers configured (%s + self-hosted). "
                "Multi-LLM consensus enabled.",
                total_configured,
                ", ".join(cloud_configured) if cloud_configured else "none",
            )

    # ------------------------------------------------------------------
    # Connector Scheduler — PULL connectors on cron-based schedules
    # ------------------------------------------------------------------
    @app.on_event("startup")
    async def _start_connector_scheduler():
        """Register existing connectors and start the background pull scheduler."""
        try:
            from connectors.connector_bridge import (
                ConnectorScheduler,
                register_all_existing_connectors,
            )

            count = register_all_existing_connectors()
            _logger.info(
                "Connector framework: registered %d existing connectors", count
            )

            scheduler = ConnectorScheduler()
            # Store on app state so shutdown hook can stop it
            app.state.connector_scheduler = scheduler
            await scheduler.start()
            _logger.info("ConnectorScheduler started (background pull loop)")
        except ImportError as exc:
            _logger.info("ConnectorScheduler skipped (module not available): %s", exc)
        except Exception as exc:
            _logger.warning(
                "ConnectorScheduler startup failed: %s — pull connectors will "
                "only run on-demand via /api/v1/connectors/{name}/pull",
                exc,
            )

    @app.on_event("shutdown")
    async def _stop_connector_scheduler():
        """Gracefully stop the connector pull scheduler."""
        scheduler = getattr(app.state, "connector_scheduler", None)
        if scheduler is not None:
            await scheduler.stop()
            _logger.info("ConnectorScheduler stopped")

    # -----------------------------------------------------------------------
    # Audit Log Retention — daily purge via APScheduler
    # -----------------------------------------------------------------------

    @app.on_event("startup")
    def _start_audit_retention_scheduler():
        """Schedule daily audit log retention purge (deletes entries > retention_days)."""
        try:
            from apscheduler.schedulers.background import BackgroundScheduler

            from core.audit_log import AuditLogger

            retention_days = int(os.environ.get("FIXOPS_AUDIT_RETENTION_DAYS", "90"))

            scheduler = BackgroundScheduler()

            def purge_audit_logs():
                """Purge old audit log entries."""
                logger = AuditLogger.get_instance()
                deleted = logger.purge_old(retention_days=retention_days)
                _logger.info(
                    "Audit retention: purged %d entries (retention=%d days)",
                    deleted,
                    retention_days,
                )

            # Schedule to run daily at 02:00 UTC
            scheduler.add_job(
                purge_audit_logs,
                "cron",
                hour=2,
                minute=0,
                id="audit_retention_purge",
            )
            scheduler.start()
            app.state.audit_scheduler = scheduler
            _logger.info(
                "Audit retention scheduler started (retention=%d days, daily at 02:00 UTC)",
                retention_days,
            )
        except ImportError:
            _logger.info("APScheduler unavailable — audit retention disabled")
        except Exception as exc:
            _logger.warning("Audit retention scheduler startup failed: %s", exc)

    @app.on_event("shutdown")
    def _stop_audit_retention_scheduler():
        """Gracefully stop the audit retention scheduler."""
        scheduler = getattr(app.state, "audit_scheduler", None)
        if scheduler is not None:
            scheduler.shutdown()
            _logger.info("Audit retention scheduler stopped")

    # -----------------------------------------------------------------------
    # OpenTelemetry — OTLP exporter + custom spans for critical operations
    # -----------------------------------------------------------------------
    # FastAPIInstrumentor is already applied above (auto-spans for all HTTP
    # requests). Here we:
    #   1. Configure OTLP exporter when OTEL_EXPORTER_OTLP_ENDPOINT is set.
    #   2. Add a middleware that emits dedicated named spans for the three
    #      highest-value operations: Brain Pipeline, AutoFix, and MPTE.
    #
    # The telemetry.configure() call above already wires up TracerProvider +
    # MeterProvider — we only need to attach the custom span middleware here.

    _OTEL_CUSTOM_PATHS: Dict[str, str] = {
        "/api/v1/brain/pipeline/run": "brain_pipeline.run",
        "/api/v1/brain/pipeline": "brain_pipeline.run",
        "/api/v1/autofix/apply": "autofix.apply",
        "/api/v1/autofix/generate": "autofix.generate",
        "/api/v1/autofix": "autofix.operation",
        "/api/v1/mpte/scan": "mpte.scan",
        "/api/v1/mpte/run": "mpte.run",
        "/api/v1/mpte": "mpte.operation",
        "/api/v1/micro-pentest/run": "mpte.micro_pentest",
        "/api/v1/micro-pentest": "mpte.micro_pentest",
    }

    @app.middleware("http")
    async def _otel_custom_span_middleware(request, call_next):
        """
        Emit named OpenTelemetry spans for Brain Pipeline, AutoFix, and MPTE
        operations — enriched with HTTP method, correlation ID, and response
        status so Grafana Tempo / Jaeger can visualise critical code paths.
        """
        try:
            from telemetry import get_tracer
            path = request.url.path
            span_name = None
            for prefix, name in _OTEL_CUSTOM_PATHS.items():
                if path.startswith(prefix):
                    span_name = name
                    break

            if span_name:
                tracer = get_tracer("fixops.operations")
                correlation_id = getattr(request.state, "correlation_id", None)
                with tracer.start_as_current_span(span_name) as span:
                    span.set_attribute("http.method", request.method)
                    span.set_attribute("http.url", str(request.url))
                    span.set_attribute("http.path", path)
                    if correlation_id:
                        span.set_attribute("fixops.correlation_id", str(correlation_id))
                    client_ip = (request.client.host if request.client else "unknown")
                    span.set_attribute("net.peer.ip", client_ip)

                    # Attach OTel trace_id to request.state so error handlers
                    # can include it in JSON error responses
                    try:
                        from opentelemetry import trace as _otel_trace
                        _ctx = _otel_trace.get_current_span().get_span_context()
                        if _ctx and _ctx.is_valid:
                            request.state.trace_id = format(_ctx.trace_id, "032x")
                    except Exception:  # noqa: BLE001
                        pass

                    response = await call_next(request)

                    span.set_attribute("http.status_code", response.status_code)
                    if response.status_code >= 500:
                        span.set_status(
                            # import kept inside try to avoid hard dep
                            __import__(
                                "opentelemetry.trace", fromlist=["StatusCode"]
                            ).StatusCode.ERROR,
                            f"HTTP {response.status_code}",
                        )
                    return response
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
            pass  # OTel must never break request handling

        return await call_next(request)

    # -----------------------------------------------------------------------
    # Network Segmentation Analyzer router
    # -----------------------------------------------------------------------
    try:
        from apps.api.network_analyzer_router import router as _network_analyzer_router
        app.include_router(_network_analyzer_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Loaded Network Segmentation Analyzer router")
    except ImportError as _e:
        _logger.warning("Network Segmentation Analyzer router not available: %s", _e)

    # -----------------------------------------------------------------------
    # Access Control Matrix router — who can access what
    # -----------------------------------------------------------------------
    try:
        from apps.api.access_matrix_router import router as _access_matrix_router
        app.include_router(_access_matrix_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Loaded Access Control Matrix router")
    except ImportError as _e:
        _logger.warning("Access Control Matrix router not available: %s", _e)

    # -----------------------------------------------------------------------
    # Zero-Trust Policy Engine — NIST SP 800-207
    # -----------------------------------------------------------------------
    try:
        from apps.api.zero_trust_router import router as _zero_trust_router
        app.include_router(_zero_trust_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Loaded Zero-Trust Policy Engine router")
    except ImportError as _e:
        _logger.warning("Zero-Trust router not available: %s", _e)

    # -----------------------------------------------------------------------
    # Security Awareness Training Tracker
    # -----------------------------------------------------------------------

    # -----------------------------------------------------------------------
    # Breach Simulation Engine
    # -----------------------------------------------------------------------
    # breach_simulation_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # -----------------------------------------------------------------------
    # Phishing Simulation Engine — employee security awareness testing
    # -----------------------------------------------------------------------
    # phishing_router (_phishing_router) — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # -----------------------------------------------------------------------
    # API Security Engine — OWASP API Top 10 scanning
    # -----------------------------------------------------------------------
    # DAST Scanner — Dynamic Application Security Testing (OWASP Top 10)
    try:
        from apps.api.dast_router import router as _dast_inner_router
        app.include_router(_dast_inner_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted DAST Scanner router")
    except ImportError as _dast_err:
        _logger.warning("DAST Scanner router not available: %s", _dast_err)

    # -----------------------------------------------------------------------
    # Self-Scan Dogfooding — ALDECI scans itself as its own test subject
    # -----------------------------------------------------------------------
    try:
        from apps.api.self_scan_router import router as self_scan_router
        app.include_router(self_scan_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Self-Scan Dogfooding router")
    except ImportError as _self_scan_err:
        _logger.warning("Self-Scan router not available: %s", _self_scan_err)


    # threat_hunter_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # -----------------------------------------------------------------------
    # Container Runtime Security — image analysis, CIS Docker Benchmark
    # -----------------------------------------------------------------------
    # -----------------------------------------------------------------------
    # Application Security — SAST/DAST findings, scan runs, appsec stats
    # -----------------------------------------------------------------------
    # -----------------------------------------------------------------------
    # Bug Bounty / VDP — vulnerability disclosure program management
    # -----------------------------------------------------------------------
    # bug_bounty_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # vendor_risk_router + vra_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)

    # data_security_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # -----------------------------------------------------------------------
    # IoT/OT Security Scanner — device inventory, firmware CVEs, protocol
    # checks, segmentation, default creds, C2 beaconing, IEC 62443 / FDA
    # -----------------------------------------------------------------------
    try:
        from apps.api.iot_security_router import router as iot_security_router
        app.include_router(iot_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted IoT/OT Security Scanner router at /api/v1/iot")
    except ImportError as _iot_err:
        _logger.warning("IoT/OT Security Scanner router not available: %s", _iot_err)

    # TrustGraph Integration router — moved to platform_app.py (Wave 5)

    # -----------------------------------------------------------------------
    # Gap Router — bridges missing API endpoints for the frontend
    # -----------------------------------------------------------------------
    try:
        from apps.api.gap_router import ALL_GAP_ROUTERS
        for _gap_r in ALL_GAP_ROUTERS:
            app.include_router(_gap_r, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted %d gap routers for frontend coverage", len(ALL_GAP_ROUTERS))
    except ImportError as _gap_err:
        _logger.warning("Failed to mount gap routers: %s", _gap_err)

    # SPA fallback moved to end of create_app() — must be registered AFTER all routers

    # WAF Rule Generator — auto-generate WAF rules from vulnerability findings
    try:
        from apps.api.waf_router import router as waf_router
        app.include_router(
            waf_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted WAF Rule Generator router at /api/v1/waf")
    except ImportError as e:
        _logger.warning("WAF Rule Generator router not available: %s", e)

    # audit_analytics_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)

    # GitHub Issues ALM — create/list/sync/metrics for findings as GitHub Issues
    try:
        from apps.api.github_issues_router import router as github_issues_router
        app.include_router(
            github_issues_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted GitHub Issues ALM router at /api/v1/github/issues")
    except ImportError as e:
        _logger.warning("GitHub Issues router not available: %s", e)

    # TrustGraph Event Bus — automatic pipeline from ALL API responses into TrustGraph.
    # This closes the architectural gap: findings/assets/incidents created anywhere
    # in the API are automatically routed to TrustGraph via response interception.
    try:
        from apps.api.event_bus_router import router as event_bus_router
        from core.trustgraph_event_bus import init_event_bus

        # Wire response interceptor middleware + startup handler
        init_event_bus(app)

        # Mount the management REST API (status, queue, flush, config)
        app.include_router(
            event_bus_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("TrustGraph Event Bus wired: ResponseInterceptorMiddleware + /api/v1/event-bus endpoints")
    except ImportError as _eb_err:
        _logger.warning("TrustGraph Event Bus not available: %s", _eb_err)

    # LLM Learning Loop — Phase 1 closed-loop trainer.
    # Subscribes to finding.created/alert.created/threat.detected and runs each
    # event through RAG -> Council -> learning_signals.db -> decision.made.
    # Opt-in via FIXOPS_LLM_LEARNING_LOOP=1 so existing prod isn't surprised.
    @app.on_event("startup")
    async def _start_llm_learning_loop() -> None:
        try:
            from core.llm_learning_loop import start_llm_learning_loop

            loop_handle = start_llm_learning_loop(app=app)
            if loop_handle is not None:
                _logger.info(
                    "LLM Learning Loop started (signals_db=%s)",
                    loop_handle.signals_db_path,
                )
        except Exception as _llm_loop_err:  # noqa: BLE001 — best-effort start
            _logger.warning("LLM Learning Loop start failed: %s", _llm_loop_err)

    # Connector Ingestion Scheduler — auto-pull from 10 sources every N seconds
    @app.on_event("startup")
    async def _start_connector_ingestion_scheduler() -> None:
        try:
            from core.connector_ingestion_scheduler import start_schedulers_from_env
            started = start_schedulers_from_env()
            if started:
                _logger.info(
                    "ConnectorIngestionScheduler: %d org(s) running (orgs=%s)",
                    len(started), [s.org_id for s in started],
                )
        except Exception as _ing_err:  # noqa: BLE001 — best-effort start
            _logger.warning("ConnectorIngestionScheduler start failed: %s", _ing_err)

    @app.on_event("shutdown")
    async def _stop_connector_ingestion_scheduler() -> None:
        try:
            from core.connector_ingestion_scheduler import stop_all_schedulers
            stop_all_schedulers()
            _logger.info("ConnectorIngestionScheduler stopped")
        except Exception as _ing_stop_err:  # noqa: BLE001
            _logger.debug("ConnectorIngestionScheduler stop error: %s", _ing_stop_err)

    # CIEM — Cloud Infrastructure Entitlement Management (IAM analysis, privilege escalation)
    try:
        from apps.api.ciem_router import router as ciem_router
        app.include_router(
            ciem_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted CIEM router at /api/v1/ciem")
    except ImportError as _ciem_err:
        _logger.warning("CIEM router not available: %s", _ciem_err)

    # Composite Risk Scorer — ML-powered multi-signal 0-100 risk scoring
    try:
        from apps.api.composite_risk_router import router as composite_risk_router
        app.include_router(
            composite_risk_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Composite Risk Scorer router at /api/v1/risk")
    except ImportError as _crs_err:
        _logger.warning("Composite Risk Scorer router not available: %s", _crs_err)

    # composite_alert_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # drp_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # deception_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # GraphRAG — graph-based semantic retrieval for TrustGraph knowledge
    try:
        from apps.api.graph_rag_router import router as graph_rag_router
        app.include_router(
            graph_rag_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted GraphRAG router at /api/v1/graphrag")
    except ImportError as _gr_err:
        _logger.warning("GraphRAG router not available: %s", _gr_err)

    # SLA Escalation — auto-escalate findings past SLA deadline
    try:
        from apps.api.sla_escalation_router import router as sla_escalation_router
        app.include_router(
            sla_escalation_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted SLA Escalation router at /api/v1/sla-escalation")
    except ImportError as _sla_esc_err:
        _logger.warning("SLA Escalation router not available: %s", _sla_esc_err)

    # Error Handling Auditor — static analysis of exception handling quality
    try:
        from apps.api.error_audit_router import router as error_audit_router
        app.include_router(
            error_audit_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Error Audit router at /api/v1/error-audit")
    except ImportError as _ea_err:
        _logger.warning("Error Audit router not available: %s", _ea_err)

    # attack_path_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # Security Posture Improvement Advisor — virtual CISO recommendations
    try:
        from apps.api.posture_advisor_router import router as posture_advisor_router
        app.include_router(
            posture_advisor_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Posture Advisor router at /api/v1/posture-advisor")
    except ImportError as _pa_err:
        _logger.warning("Posture Advisor router not available: %s", _pa_err)

    # insider_threat_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # CVE Enrichment Service — NVD + EPSS + KEV unified enrichment with offline cache
    try:
        from apps.api.cve_enrichment_router import router as cve_enrichment_router
        app.include_router(
            cve_enrichment_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted CVE Enrichment router at /api/v1/cve")
    except ImportError as _cve_err:
        _logger.warning("CVE Enrichment router not available: %s", _cve_err)

    # security_kpi_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)

    # SCIM v2 — SCIM provisioning for enterprise IdP (Okta, Azure AD)
    try:
        from apps.api.scim_router import router as scim_router
        app.include_router(
            scim_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted SCIM router")
    except ImportError as _scim_err:
        _logger.warning("SCIM router not available: %s", _scim_err)

    # n8n Management — orchestrate n8n workflows via 400+ integrations bridge
    try:
        from apps.api.n8n_mgmt_router import router as n8n_mgmt_router
        app.include_router(
            n8n_mgmt_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted n8n Management router")
    except ImportError as _n8n_err:
        _logger.warning("n8n Management router not available: %s", _n8n_err)

    # webhook_router — moved to platform_app.py (Wave 5)

    # report_scheduler_router — moved to platform_app.py (Wave 5)

    # iga_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # _playbook_engine_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)

    # compliance_automation_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)

    # data_classification_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)

    # Threat Actor Intelligence — actor profiles, campaigns, IOCs, watchlist
    try:
        from apps.api.threat_actor_router import router as threat_actor_router
        app.include_router(
            threat_actor_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Threat Actor router at /api/v1/threat-actors")
    except Exception as e:
        _logger.warning(f"Threat Actor router not loaded: {e}")

    # compliance_gap_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)

    # Vulnerability Risk Scoring — contextual risk scores (CVSS + EPSS + KEV + asset context)
    try:
        from apps.api.vuln_risk_router import router as vuln_risk_router
        app.include_router(
            vuln_risk_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Vulnerability Risk Scoring router at /api/v1/vuln-risk")
    except Exception as e:
        _logger.warning(f"Vulnerability Risk Scoring router not loaded: {e}")

    # Risk Scoring — now mounted early via module-level import (see line ~3129); skip duplicate here.

    # Application Security (AppSec) — SAST/DAST scans, findings, OWASP tracking
    # endpoint_security_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)


    # email_security_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # grc_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # Network Topology — asset graph, subnet mapping, lateral movement paths
    try:
        from apps.api.network_topology_router import router as network_topology_router
        app.include_router(network_topology_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Network Topology router at /api/v1/network-topology")
    except Exception as e:
        _logger.warning(f"Network Topology router not loaded: {e}")

    # Secrets Manager — vault management, secret rotation, expiry tracking
    try:
        from apps.api.secrets_manager_router import router as secrets_manager_router
        app.include_router(secrets_manager_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Secrets Manager router at /api/v1/secrets")
    except Exception as e:
        _logger.warning(f"Secrets Manager router not loaded: {e}")

    # SOAR — playbook automation (duplicate removed — mounted earlier via module-level import)
    # soar_router already mounted at line ~2710 via module-level import

    # threat_correlation_router (early mount) — moved to ctem_app.py (Wave-C-pilot 2026-05-03)
    # NOTE: a second mount of threat_correlation_router exists later in app.py and is intentionally retained for Wave-C-batch evaluation.

    # toxic_combo_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # Password Policy Engine — policies, evaluation, violations, audits
    try:
        from apps.api.password_policy_router import router as password_policy_router
        app.include_router(password_policy_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Password Policy router at /api/v1/password-policy")
    except Exception as e:
        _logger.warning(f"Password Policy router not loaded: {e}")

    # Mobile Security Engine — device MDM, threats, policies
    # uba_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # cmdb_router — moved to platform_app.py (Wave 5)

    # Supply Chain Risk — suppliers, components, risks, SBOM import
    # cyber_insurance_router — moved to grc_app.py (Wave-B-pilot 2026-05-03)


    # Vulnerability Scanner — scanners, schedules, results, findings, stats
    # security_training_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # Threat Intel Connector — MISP / CIRCL CVE / PhishTank / OTX adapters
    # OSS replacements for Recorded Future / Anomali / Mandiant / X-Force / Proofpoint
    try:
        from apps.api.threat_intel_connector_router import (
            router as threat_intel_connector_router,
        )
        app.include_router(threat_intel_connector_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Intel Connector router at /api/v1/connectors/ti")
    except Exception as e:
        _logger.warning(f"Threat Intel Connector router not loaded: {e}")


    # CWPP — Cloud Workload Protection Platform (containers, VMs, serverless, K8s)
    try:
        from apps.api.cwpp_router import router as cwpp_router
        app.include_router(cwpp_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted CWPP router at /api/v1/cwpp")
    except Exception as e:
        _logger.warning(f"CWPP router not loaded: {e}")


    # risk_quantification_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # digital_forensics_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # threat_feed_aggregator_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # security_roadmap_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # data_governance_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # compliance_scanner_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # asset_risk_calculator_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # security_health_router — moved to platform_app.py (Wave 5)

    # DuckDB cross-domain analytics — unified risk intelligence across all SQLite engines
    try:
        from apps.api.analytics_engine_router import router as analytics_engine_router
        app.include_router(analytics_engine_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Analytics Engine router at /api/v1/analytics-engine")
    except Exception as e:
        _logger.warning(f"Analytics Engine router not loaded: {e}")

    # DevSecOps Pipeline Security Engine — CI/CD gate policies, runs, findings
    try:
        from apps.api.incident_timeline_router import router as incident_timeline_router
        app.include_router(incident_timeline_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Incident Timeline router at /api/v1/incident-timeline")
    except Exception as e:
        _logger.warning(f"Incident Timeline router not loaded: {e}")

    # security_metrics_collector_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # Vulnerability trend analysis — snapshots, SLA tracking, cohorts
    try:
        from apps.api.vuln_trend_router import router as vuln_trend_router
        app.include_router(vuln_trend_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Vuln Trend router at /api/v1/vuln-trends")
    except Exception as e:
        _logger.warning(f"Vuln Trend router not loaded: {e}")

    # Configuration benchmark — CIS/DISA STIG/NIST assessments, gate checks
    try:
        from apps.api.config_benchmark_router import router as config_benchmark_router
        app.include_router(config_benchmark_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Config Benchmark router at /api/v1/config-benchmark")
    except Exception as e:
        _logger.warning(f"Config Benchmark router not loaded: {e}")

    # Threat model auto-generator — STRIDE auto-generation, risk rating, mitigations
    try:
        from apps.api.threat_model_generator_router import (
            router as threat_model_generator_router,
        )
        app.include_router(threat_model_generator_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Model Generator router at /api/v1/threat-model-gen")
    except Exception as e:
        _logger.warning(f"Threat Model Generator router not loaded: {e}")

    # security_exception_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # ccm_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # awareness_score_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # NDR Engine — network flow ingestion, risk scoring, alerts, baselines, anomaly detection
    try:
        from apps.api.ndr_router import router as ndr_router
        app.include_router(ndr_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted NDR Engine router at /api/v1/ndr")
    except Exception as e:
        _logger.warning(f"NDR Engine router not loaded: {e}")

    # identity_analytics_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # CNAPP Engine — cloud workloads, findings, policies, composite CSPM+CWPP+CIEM scoring
    try:
        from apps.api.cnapp_router import router as cnapp_router
        app.include_router(cnapp_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted CNAPP router at /api/v1/cnapp")
    except Exception as e:
        _logger.warning(f"CNAPP router not loaded: {e}")

    # GAP-025 Multi-CSP Router — OCI + Alibaba + IBM adapters on top of AWS/Azure/GCP
    try:
        from apps.api.multi_csp_router import router as multi_csp_router
        app.include_router(multi_csp_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Multi-CSP router at /api/v1/multi-csp")
    except Exception as e:
        _logger.warning(f"Multi-CSP router not loaded: {e}")

    # xdr_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # edr_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # edr_connector_router — moved to ctem_app.py (Wave-C-pilot 2026-05-03)

    # CrowdStrike Falcon Connector — REAL Falcon Detection.Created format parser
    # Closes 1 of 11 substitute-only gaps from gap-matrix-2026-04-26.md
    # crowdstrike_falcon_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # SentinelOne Singularity XDR Connector — real /threats parser, embedded fallback samples
    # sentinelone_connector_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # Supply Chain Intelligence — package tracking, vuln/malicious flags, SBOM snapshots
    try:
        from apps.api.supply_chain_intel_router import (
            router as supply_chain_intel_router,
        )
        app.include_router(supply_chain_intel_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Supply Chain Intel router at /api/v1/supply-chain-intel")
    except Exception as e:
        _logger.warning(f"Supply Chain Intel router not loaded: {e}")

    # MLOps Supply Chain Security — model supply chain, typosquat, malicious package analysis
    try:
        from apps.api.mlops_supply_chain_router import (
            router as mlops_supply_chain_router,
        )
        app.include_router(mlops_supply_chain_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted MLOps Supply Chain router at /api/v1/mlops/supply-chain")
    except Exception as e:
        _logger.warning(f"MLOps Supply Chain router not loaded: {e}")

    # Pentest Management — engagements, findings, targets, retests
    # pentest_mgmt_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # threat_intel_sharing_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # phishing_simulation_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # ioc_enrichment_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # ctem_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # security_champions_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # Red Team Management — engagements, findings, TTPs, operators
    # red_team_mgmt_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    try:
        from apps.api.workflow_router import router as workflow_router
        app.include_router(workflow_router)
        _logger.info("Mounted Workflow Engine router at /api/v1/workflows")
    except ImportError:
        pass

    # policy_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # security_playbook_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # attack_simulation_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # compliance_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # scheduled_reports_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # ai_security_advisor_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # nl_graph_router — moved to platform_app.py (Wave 5)

    # vuln_prioritization_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # asset_criticality_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # blast_radius_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)



    # openclaw_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # soc_triage_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)



    # identity_governance_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # security_maturity_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # threat_correlation_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03 — auth-bypass closure: app.py mount was unauthenticated; ctem_app.py L287-292 enforces _verify_api_key)

    # privacy_gdpr_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)


    # dlp_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)


    # threat_intel_platform_router (tip_router) — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # attack_surface_mgmt_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # cloud_compliance_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # endpoint_compliance_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # executive_reporting_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # vuln_intelligence_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # ciso_report_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # mitre_attack_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # attack_surface_mgmt_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)
    # compliance_evidence_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # siem_integration_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # SIEM Output Connectors — Splunk HEC + Microsoft Sentinel
    # siem_output_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # SIEM universal multi-format ingest connector (Wazuh / ELK / Splunk HEC /
    # Datadog / Sentinel KQL / QRadar CEF / Suricata / syslog / JSON-Lines).
    # siem_connector_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)





    # data_retention_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # _evidence_chain_late (evidence_chain_router late-bound) — moved to grc_app.py (Wave-B-batch-3 2026-05-03)



    # passive_dns_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)







    # threat_geolocation_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # ip_reputation_router (_ip_reputation_late) — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # security_automation_router — moved to platform_app.py (Wave 5)

    # incident_orchestration_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # security_metrics_dashboard_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # kpi_tracking_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)





    # ddos_protection_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # alerting_notification_router — moved to platform_app.py (Wave 5)

    # risk_aggregator_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # security_event_correlation_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # threat_intel_fusion_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)



    # ot_security_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # data_privacy_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # gdpr_compliance_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)

    # physical_security_router — moved to grc_app.py (Wave-B-batch-2 2026-05-03)



    # log_management_router — moved to platform_app.py (Wave 5)


    # email_filtering_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # anti_phishing_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # soc_workflow_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # incident_triage_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # threat_simulation_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)



    try:
        from apps.api.auto_waiver_router import router as auto_waiver_router
        app.include_router(auto_waiver_router)
        _logger.info("Mounted Auto-Waiver router at /api/v1/auto-waiver")
    except ImportError:
        pass

    # breach_detection_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # forensics_readiness_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)


    try:
        from apps.api.audit_management_router import router as audit_management_router
        app.include_router(audit_management_router)
        _logger.info("Mounted Audit Management router at /api/v1/audit-management")
    except ImportError:
        pass


    # supply_chain_attack_detection_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)




    # GAP-062 (Sprint 3): Unified rule taxonomy registry + sync shim


    # threat_score_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)






    # attack_chain_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # threat_exposure_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    try:
        from apps.api.software_license_security_router import (
            router as software_license_security_router,
        )
        app.include_router(software_license_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Software License Security router at /api/v1/license-security")
    except ImportError:
        pass

    try:
        from apps.api.cloud_identity_router import router as cloud_identity_router
        app.include_router(cloud_identity_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Cloud Identity router at /api/v1/cloud-identity")
    except ImportError:
        pass

    # dark_web_monitoring_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)



    # security_chaos_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # Wave 20 routers
    # zero_day_intelligence_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)


    try:
        from apps.api.data_exfiltration_router import router as data_exfiltration_router
        app.include_router(data_exfiltration_router)
        _logger.info("Mounted Data Exfiltration router at /api/v1/data-exfiltration")
    except ImportError:
        pass


    # security_tool_inventory_router — moved to platform_app.py (Wave 5)

    # Wave 21 routers
    try:
        from apps.api.iot_security_router import router as iot_security_router
        app.include_router(iot_security_router)
        _logger.info("Mounted IoT Security router at /api/v1/iot-security")
    except ImportError:
        pass

    # Wave 22 routers
    try:
        from apps.api.vulnerability_correlation_router import (
            router as vulnerability_correlation_router,
        )
        app.include_router(vulnerability_correlation_router)
        _logger.info("Mounted Vulnerability Correlation router at /api/v1/vuln-correlation")
    except ImportError:
        pass




    # ai_powered_soc_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # deception_analytics_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # Wave 23 routers
    # threat_intelligence_automation_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # security_metrics_aggregator_router — moved to platform_app.py (Wave 5)

    # endpoint_threat_hunting_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)



    # operational_technology_security_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # Wave 24 routers
    # network_forensics_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # malware_analysis_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)



    # vulnerability_prioritization_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # Wave 25 routers
    # threat_deception_management_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)





    # Wave 26 routers
    try:
        from apps.api.compliance_automation_router import (
            router as compliance_automation_router,
        )
        app.include_router(compliance_automation_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Compliance Automation router at /api/v1/compliance-automation")
    except ImportError:
        pass

    # compliance_seed_router — GAP-022/023 bulk framework + policy seeding
    try:
        from apps.api.compliance_seed_router import router as compliance_seed_router
        app.include_router(compliance_seed_router)
        _logger.info("Mounted Compliance Seed router at /api/v1/compliance-seed")
    except ImportError as _e:
        _logger.warning("compliance_seed_router unavailable: %s", _e)

    # threat_attribution_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    try:
        from apps.api.cloud_access_security_router import (
            router as cloud_access_security_router,
        )
        app.include_router(cloud_access_security_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Cloud Access Security router at /api/v1/cloud-access-security")
    except ImportError:
        pass

    try:
        from apps.api.behavioral_analytics_router import (
            router as behavioral_analytics_router,
        )
        app.include_router(behavioral_analytics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Behavioral Analytics router at /api/v1/behavioral-analytics")
    except ImportError:
        pass

    # security_data_pipeline_router — moved to platform_app.py (Wave 5)

    # GAP-034 + GAP-035 — Universal ingest (field mapping + SIEM forwarding)
    # Wave 27 routers
    # alert_triage_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)



    # cyber_threat_intelligence_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # digital_twin_security_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # Wave 28 routers



    try:
        from apps.api.security_telemetry_router import (
            router as security_telemetry_router,
        )
        app.include_router(security_telemetry_router)
        _logger.info("Mounted Security Telemetry router at /api/v1/security-telemetry")
    except ImportError:
        pass


    try:
        from apps.api.third_party_vendor_router import (
            router as third_party_vendor_router,
        )
        app.include_router(third_party_vendor_router)
        _logger.info("Mounted Third Party Vendor router at /api/v1/third-party-vendor")
    except ImportError:
        pass


    # threat_vector_analysis_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)



    try:
        from apps.api.data_discovery_router import router as data_discovery_router
        app.include_router(data_discovery_router)
        _logger.info("Mounted Data Discovery router at /api/v1/data-discovery")
    except ImportError:
        pass

    # Wave 30 routers

    # threat_brief_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # incident_comms_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    try:
        from apps.api.security_registry_router import router as security_registry_router
        app.include_router(security_registry_router)
        _logger.info("Mounted Security Registry router at /api/v1/security-registry")
    except ImportError:
        pass

    # org_hierarchy_router — moved to platform_app.py (Wave 5)

    # Wave 31 routers


    try:
        from apps.api.metrics_timeseries_router import (
            router as metrics_timeseries_router,
        )
        app.include_router(metrics_timeseries_router)
        _logger.info("Mounted Metrics Timeseries router at /api/v1/metrics-ts (GAP-060)")
    except ImportError:
        pass



    # threat_intel_enrichment_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)


    # Wave 32 pre-wiring (engines pending creation)

    # threat_landscape_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)



    # network_threat_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # incident_kb_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # Wave 33 pre-wiring (engines pending creation)


    # threat_feed_subscription_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    try:
        from apps.api.asset_group_router import router as asset_group_router
        app.include_router(asset_group_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Asset Group router at /api/v1/asset-groups")
    except ImportError:
        pass


    # Wave 34 pre-wiring (engines pending creation)

    # threat_actor_tracking_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # vulnerability_scoring_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)



    # Wave 35 pre-wiring (engines pending creation)

    try:
        from apps.api.compliance_calendar_router import (
            router as compliance_calendar_router,
        )
        app.include_router(compliance_calendar_router)
        _logger.info("Mounted Compliance Calendar router at /api/v1/compliance-calendar")
    except ImportError:
        pass

    # cyber_resilience_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)


    # threat_modeling_pipeline_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # GAP-056: Design-doc ingest + STRIDE extraction (spans 3 threat-modeling engines)
    try:
        from apps.api.design_doc_router import router as design_doc_router
        app.include_router(design_doc_router)
        _logger.info("Mounted Design Doc Ingest router at /api/v1/design-doc")
    except ImportError:
        pass

    # Wave 36 pre-wiring (engines pending creation)


    # security_operations_metrics_router — moved to platform_app.py (Wave 5)

    # vulnerability_age_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # threat_intelligence_confidence_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # GAP-055 + GAP-057: SBOM re-eval schedule + component claim
    # Wave 37 pre-wiring (engines pending creation)
    # GAP-017 Pipeline BOM (PBOM) — captures how the binary was built, not what's in it
    # GAP-015 + GAP-068: GitHub App registration/webhook + .fixops/hooks.yaml policy
    # Snyk-parity: AutoFix-on-PR — wires existing autofix engine to GitHub App
    # PR webhook so findings produce actionable patch suggestions in PR review.
    # GAP-018 SLSA Provenance — in-toto v0.2 attestations + DSSE envelope (placeholder sig)
    # GAP-007: upgrade_path_resolver_engine (CVE-aware version walker)
    # upgrade_path_router — moved to platform_app.py (Wave 5)

    # air_gap_bundle_router — moved to platform_app.py (Wave 5)

    # security_query_router — moved to platform_app.py (Wave 5)

    # Backend Wave B (Multica 2026-04-26) — 15 findings/risk/scoring endpoints
    # ce6b3221, 71432602, a3d3443d, 9fafda03, fdf4d765, bacdd8bf, 7e62f6c6,
    # 094b9c3d, e2cf4708, 4c483284, afe86faf, 1d3a7018, 2a6a2e8a, 4b96d034,
    # 80123d56, 06e9c24b
    # GAP-069 Dynamic Rule DSL — user-authored YAML/JSON detection rules
    # GAP-022/023 Compliance Seed — 100+ framework controls + 3000+ policy rules

    # GAP-063 Findings Lifecycle — firstSeenAt/previousViolationId/resolvedAt chain
    # GAP-064 Local File Store — .fixops/ zero-infra store for npx fixops analyze
    # local_file_store_router — moved to platform_app.py (Wave 5)



    # alert_enrichment_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)


    # threat_response_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)


    # Wave 38 pre-wiring (engines pending creation)

    # network_anomaly_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)


    # hunting_automation_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)



    # Wave 39 pre-wiring (engines pending creation)

    # GAP-028 FAIR per-BU + GAP-051 ROI-of-fixes trend

    # cyber_threat_modeling_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)



    # security_event_timeline_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # vuln_intel_fusion_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # Wave 40 pre-wiring (engines pending creation)

    # threat_hunting_playbook_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    try:
        from apps.api.sigmahq_router import router as sigmahq_router
        app.include_router(sigmahq_router)
        _logger.info("Mounted SigmaHQ router at /api/v1/sigmahq")
    except ImportError:
        pass

    if anomaly_ml_router is not None:
        app.include_router(anomaly_ml_router)
        _logger.info("Mounted Anomaly ML router at /api/v1/anomaly-ml")

    try:
        from apps.api.dbir_router import router as dbir_router
        app.include_router(dbir_router)
        _logger.info("Mounted DBIR/VCDB router at /api/v1/dbir")
    except ImportError:
        pass

    # Feed-importer routers — real engine wiring, backfilled 2026-05-04
    try:
        from apps.api.epss_router import router as epss_router
        app.include_router(epss_router)
        _logger.info("Mounted EPSS router at /api/v1/epss")
    except ImportError:
        pass

    try:
        from apps.api.nuclei_router import router as nuclei_router
        app.include_router(nuclei_router)
        _logger.info("Mounted Nuclei router at /api/v1/nuclei")
    except ImportError:
        pass

    try:
        from apps.api.spamhaus_router import router as spamhaus_router
        app.include_router(spamhaus_router)
        _logger.info("Mounted Spamhaus DROP router at /api/v1/spamhaus")
    except ImportError:
        pass

    try:
        from apps.api.ghsa_router import router as ghsa_router
        app.include_router(ghsa_router)
        _logger.info("Mounted GHSA router at /api/v1/ghsa")
    except ImportError:
        pass

    try:
        from apps.api.urlhaus_router import router as urlhaus_router
        app.include_router(urlhaus_router)
        _logger.info("Mounted URLhaus router at /api/v1/urlhaus")
    except ImportError:
        pass

    try:
        from apps.api.phishtank_router import router as phishtank_router
        app.include_router(phishtank_router)
        _logger.info("Mounted PhishTank router at /api/v1/phishtank")
    except ImportError:
        pass

    # cloud_incident_response_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)


    # GAP-065 — architecture-aware graph (layer classifier + flow tracer)
    # GAP-010 — function-level reachability (Endor Labs moat)
    # Wave 41 pre-wiring (engines pending creation)

    # threat_indicator_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # GAP-026 — Choke-point analyzer (max-flow min-cut on attack graph)
    # choke_point_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    # ransomware_protection_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)


    # GAP-013 code-to-runtime matcher (3-strategy runtime→code mapping)
    # GAP-012 Deep Code Analysis — Apiiro DCA parity
    # NEW-G070 Semantic Analyzer — tree-sitter + LSP + ORM schema readers
    # GAP-042 FIPS 140-3 compliance mode + PQC inventory (ML-KEM / ML-DSA / SPHINCS+)



    # sse_router — moved to platform_app.py (Wave 5)

    # FEATURE-3 — TrustGraph WebSocket event stream at /ws/events
    # Subscribes directly to TrustGraphEventBus (the canonical bus that
    # Brain Pipeline + ResponseInterceptorMiddleware emit into).
    try:
        from apps.api.ws_trustgraph_events_router import (
            router as ws_trustgraph_events_router,
        )
        app.include_router(ws_trustgraph_events_router)
        _logger.info("Mounted TrustGraph WebSocket event stream at /ws/events")
    except ImportError as exc:
        _logger.warning("TrustGraph WS event stream not available: %s", exc)

    # Wave C — 21 endpoints: compliance/org/system/admin/tokens/cspm/skills/rules/llm
    # Wave 42 pre-wiring
    # NOTE 2026-05-03: Removed 6 dead-router try blocks per silenced-imports
    # triage `60a8ea9e` (rows 4-9). The .py files for endpoint_forensics_router,
    # security_log_analysis_router, incident_impact_assessment_router,
    # vulnerability_disclosure_router, threat_contextualization_router, and
    # security_operations_automation_router never existed on disk — silently
    # swallowed ModuleNotFoundError contributed zero behavior. Mirrors the
    # websocket_routes.py removal in `6307d7fe`. Same dead refs still exist in
    # sub_apps/ctem_app.py:946-1075 (out of scope of this triage; track
    # separately).

    # -----------------------------------------------------------------------
    # Wave 42+ — wiring previously unwired router files
    # -----------------------------------------------------------------------
    try:
        from apps.api.change_tracker_router import router as change_tracker_router
        app.include_router(change_tracker_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Change Tracker router at /api/v1/change-tracker")
    except ImportError:
        pass

    try:
        from apps.api.admin_db_router import router as admin_db_router
        app.include_router(admin_db_router)
        _logger.info("Mounted Admin DB Stats router at /api/v1/admin/db/stats")
    except ImportError as _e:
        _logger.warning("admin_db_router unavailable: %s", _e)

    try:
        from apps.api.admin_connectors_router import router as admin_connectors_router
        app.include_router(admin_connectors_router)
        _logger.info("Mounted Admin Connectors Inventory router at /api/v1/admin/connectors/inventory")
    except ImportError as _e:
        _logger.warning("admin_connectors_router unavailable: %s", _e)



    # ctem_engine_router — moved to ctem_app.py (Wave-C-batch-2 2026-05-03)

    try:
        from apps.api.executive_dashboard_router import (
            router as executive_dashboard_router,
        )
        app.include_router(executive_dashboard_router)
        _logger.info("Mounted Executive Dashboard router at /api/v1/executive")
    except ImportError:
        pass

    # fedramp_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)


    # jira_sync_router — moved to platform_app.py (Wave 5)


    # license_compliance_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    try:
        from apps.api.mitre_coverage_router import router as mitre_coverage_router
        app.include_router(mitre_coverage_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted MITRE Coverage router at /api/v1/mitre")
    except ImportError:
        pass

    # n8n_router — moved to platform_app.py (Wave 5)

    # observability_router — moved to platform_app.py (Wave 5)

    # pagerduty_router — moved to platform_app.py (Wave 5)

    # playbook_marketplace_router — moved to platform_app.py (Wave 5)

    # rbac_router — moved to platform_app.py (Wave 5)

    # red_team_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # regulatory_tracker_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)


    # session_router — moved to platform_app.py (Wave 5)

    # sla_management_router — moved to platform_app.py (Wave 5)

    # threat_model_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # trust_center_router — moved to grc_app.py (Wave-B-batch-3 2026-05-03)

    # trustgraph_backbone_router — moved to platform_app.py (Wave 5)

    # trustgraph_migrator_router — moved to platform_app.py (Wave 5)

    # vuln_enricher_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    # vuln_prioritizer_router — moved to ctem_app.py (Wave-C-batch-4 2026-05-03)

    try:
        from apps.api.ml_vuln_prioritizer_router import (
            router as ml_vuln_prioritizer_router,
        )
        app.include_router(ml_vuln_prioritizer_router)
        _logger.info("Mounted ML Vulnerability Prioritizer router at /api/v1/ml/vuln-prioritizer")
    except ImportError:
        pass

    try:
        from apps.api.semantic_analyzer_router import router as semantic_analyzer_router
        app.include_router(semantic_analyzer_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Semantic Analyzer router at /api/v1/semantic")
    except ImportError:
        pass

    # slack_notifier_router — moved to platform_app.py (Wave 5)

    # export_router — moved to platform_app.py (Wave 5)

    # servicenow_router — moved to platform_app.py (Wave 5)


    # oauth2_router — moved to platform_app.py (Wave 5)

    # GAP-002: Offline Feed Router (air-gapped threat-intel bundle ingestion)
    # offline_feed_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    # GAP-004: Stage Matrix Router (CTEM stage-aware policy enforcement)
    # stage_matrix_router — moved to ctem_app.py (Wave-C-batch-3 2026-05-03)

    try:
        from apps.api.tor_exit_nodes_router import router as tor_exit_nodes_router
        app.include_router(tor_exit_nodes_router)
        _logger.info("Mounted Tor exit-nodes router at /api/v1/tor-exit")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("tor_exit_nodes_router unavailable: %s", _e)

    try:
        from apps.api.greynoise_router import router as greynoise_router
        app.include_router(greynoise_router)
        _logger.info("Mounted GreyNoise router at /api/v1/greynoise")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("greynoise_router unavailable: %s", _e)

    # Censys router is mounted by sub_apps/platform_app.py with read:scans scope.
    # The legacy duplicate mount was retired 2026-05-04.

    # Threat Landscape — actor profiles, emerging threats, assessments, summary
    try:
        from apps.api.threat_landscape_router import router as threat_landscape_router
        app.include_router(threat_landscape_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Landscape router at /api/v1/threat-landscape")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("threat_landscape_router unavailable: %s", _e)

    # Threat Briefs — brief lifecycle, distribution, recipient tracking
    try:
        from apps.api.threat_brief_router import router as threat_brief_router
        app.include_router(threat_brief_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Brief router at /api/v1/threat-briefs")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("threat_brief_router unavailable: %s", _e)

    # Threat Hunting — hunt sessions, queries, IOC correlation (/api/v1/hunting)
    # Also mounts alias at /api/v1/threat-hunting for UI consumers (ThreatHuntingDashboard)
    try:
        from apps.api.threat_hunting_router import (
            router as _th_router,
            threat_hunting_alias as _th_alias,
        )
        app.include_router(_th_router)
        app.include_router(_th_alias)
        _logger.info("Mounted Threat Hunting router at /api/v1/hunting + alias /api/v1/threat-hunting")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("threat_hunting_router unavailable: %s", _e)

    # Zero Day Intelligence — CVE registry, patch status, mitigations, stats
    try:
        from apps.api.zero_day_intelligence_router import router as zero_day_intelligence_router
        app.include_router(zero_day_intelligence_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Zero Day Intelligence router at /api/v1/zero-day")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("zero_day_intelligence_router unavailable: %s", _e)

    # Threat Intel Sharing — STIX/TAXII-lite groups, indicators, bundle import/export
    try:
        from apps.api.threat_intel_sharing_router import router as threat_intel_sharing_router
        app.include_router(threat_intel_sharing_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Threat Intel Sharing router at /api/v1/threat-sharing")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("threat_intel_sharing_router unavailable: %s", _e)

    # Tour router — real-product-demo "tour mode" (SSE stream, no auth required)
    try:
        from apps.api.tour_router import router as tour_router
        app.include_router(tour_router)
        _logger.info("Mounted Tour router at /api/v1/tour")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("tour_router unavailable: %s", _e)

    # Agentless Snapshot Scan — GAP-020 (Wiz/Orca moat)
    try:
        from apps.api.agentless_snapshot_scan_router import router as agentless_snapshot_scan_router
        app.include_router(agentless_snapshot_scan_router)
        _logger.info("Mounted Agentless Snapshot Scan router at /api/v1/agentless-snapshot-scan")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("agentless_snapshot_scan_router unavailable: %s", _e)

    # tfsec — Terraform-only IaC static analysis (8 providers: aws/azure/gcp/digitalocean/k8s/cloudstack/github/oracle)
    try:
        from apps.api.tfsec_router import router as tfsec_router
        app.include_router(tfsec_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted tfsec IaC router at /api/v1/tfsec")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("tfsec_router unavailable: %s", _e)

    try:
        from apps.api.fips_compliance_router import router as fips_compliance_router
        app.include_router(fips_compliance_router)
        _logger.info("Mounted FIPS Compliance Mode router at /api/v1/fips")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("fips_compliance_router unavailable: %s", _e)

    try:
        from apps.api.upgrade_path_router import router as upgrade_path_router
        app.include_router(upgrade_path_router)
        _logger.info("Mounted Upgrade Path Resolver router at /api/v1/upgrade-path")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("upgrade_path_router unavailable: %s", _e)

    try:
        from apps.api.slsa_provenance_router import router as slsa_provenance_router
        app.include_router(slsa_provenance_router)
        _logger.info("Mounted SLSA Provenance router at /api/v1/slsa")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("slsa_provenance_router unavailable: %s", _e)

    try:
        from apps.api.feature_flags_router import router as feature_flags_router
        app.include_router(feature_flags_router)
        _logger.info("Mounted Feature Flags router at /api/v1/feature-flags")
    except Exception as _e:  # noqa: BLE001
        _logger.warning("feature_flags_router unavailable: %s", _e)

    if versioning_router is not None:
        app.include_router(versioning_router)
        _logger.info("Mounted API Versioning router at /api/versions")

    if incident_response_router is not None:
        app.include_router(incident_response_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Incident Response router at /api/v1/incidents")

    if fix_engine_router is not None:
        app.include_router(fix_engine_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Fix Engine router at /api/v1/remediation (playbooks/executions)")

    if pipeline_bom_router is not None:
        app.include_router(pipeline_bom_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Pipeline BOM router at /api/v1/pbom")

    try:
        from apps.api.code_to_runtime_router import router as code_to_runtime_router
        app.include_router(code_to_runtime_router)
        _logger.info("Mounted Code-to-Runtime router at /api/v1/code-to-runtime")
    except Exception as _e:
        _logger.warning("code_to_runtime_router unavailable: %s", _e)

    # Billing tier API + Stripe webhook — Commercial P2 (Multica #4101)
    try:
        from apps.api.billing_router import router as billing_router
        app.include_router(billing_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Billing router at /api/v1/billing")
    except Exception as _e:
        _logger.warning("billing_router unavailable: %s", _e)

    try:
        from apps.api.stripe_webhook_router import router as stripe_webhook_router
        # Stripe webhook must NOT require ALDECI API key — Stripe calls it directly
        app.include_router(stripe_webhook_router)
        _logger.info("Mounted Stripe webhook router at /api/v1/billing/stripe-webhook")
    except Exception as _e:
        _logger.warning("stripe_webhook_router unavailable: %s", _e)

    # Outbound Webhooks — per-org subscriptions to ALdeci event topics (Multica #4151)
    try:
        from apps.api.outbound_webhooks_router import router as outbound_webhooks_router
        app.include_router(outbound_webhooks_router)
        _logger.info("Mounted Outbound Webhooks router at /api/v1/webhooks/outbound")
    except Exception as _e:
        _logger.warning("outbound_webhooks_router unavailable: %s", _e)

    # NEW-G071: IDE-in-browser backend (file tree + content + analysis snapshots + diff)
    # -----------------------------------------------------------------------
    # API-doc aliases — MUST be registered BEFORE the SPA catch-all so they
    # win the route lookup. Onboarding bug surfaced 2026-04-27: customers
    # hitting `curl http://host/openapi.json` (no -L) got back the marketing
    # landing page because the previous 307 redirect was both (a) only mounted
    # when the SPA dist existed and (b) not followed by curl/non-browser
    # clients. We now serve the OpenAPI JSON directly, with no redirect, so
    # any tool that does autodiscovery on the canonical /openapi.json gets a
    # real spec on Day 1.
    # -----------------------------------------------------------------------
    from starlette.responses import JSONResponse as _SpaJsonResp

    @app.get("/openapi.json", include_in_schema=False)
    async def _openapi_root_alias():
        # Re-use the capped openapi schema generated by _capped_openapi above.
        # Even if schema generation fails catastrophically (defensive — the
        # _capped_openapi wrapper already retries + stubs), we MUST return JSON
        # rather than letting FastAPI's default 500 handler return HTML, which
        # would land customers back on the marketing landing page.
        try:
            return _SpaJsonResp(app.openapi())
        except Exception as exc:  # noqa: BLE001
            return _SpaJsonResp(
                {
                    "openapi": "3.1.0",
                    "info": {
                        "title": app.title,
                        "version": app.version,
                        "x-openapi-error": f"{type(exc).__name__}: {exc}",
                    },
                    "paths": {},
                },
                status_code=200,
            )

    @app.get("/docs", include_in_schema=False)
    async def _docs_root_alias():
        from fastapi.responses import RedirectResponse as _DocsRedirect
        return _DocsRedirect(url="/api/v1/docs", status_code=307)

    @app.get("/redoc", include_in_schema=False)
    async def _redoc_root_alias():
        from fastapi.responses import RedirectResponse as _DocsRedirect
        return _DocsRedirect(url="/api/v1/redoc", status_code=307)

    # -----------------------------------------------------------------------
    # Bug C fix (playbook 2026-04-27): customer-onboarding doc references
    # /api/v1/admin/orgs|connectors|system but real prefixes are /api/v1/orgs,
    # /api/v1/connectors, /api/v1/system. Rather than churning the doc, alias
    # the admin-prefixed paths to 307 to the real paths so curl -L works and
    # other tools that follow redirects don't 404. include_in_schema=False so
    # the OpenAPI spec stays single-source-of-truth on the canonical URLs.
    # -----------------------------------------------------------------------
    from fastapi.responses import RedirectResponse as _AdminAliasRedirect

    _ADMIN_PREFIX_ALIASES = {
        "/api/v1/admin/orgs": "/api/v1/orgs",
        "/api/v1/admin/connectors": "/api/v1/connectors",
        "/api/v1/admin/system": "/api/v1/system",
    }

    def _make_admin_alias(src_prefix: str, dst_prefix: str):
        async def _alias_root() -> Any:
            return _AdminAliasRedirect(url=dst_prefix, status_code=307)

        async def _alias_subpath(subpath: str) -> Any:
            return _AdminAliasRedirect(url=f"{dst_prefix}/{subpath}", status_code=307)

        return _alias_root, _alias_subpath

    for _src, _dst in _ADMIN_PREFIX_ALIASES.items():
        _root_handler, _sub_handler = _make_admin_alias(_src, _dst)
        # Match common verbs so writes redirect too. 307 preserves method/body.
        for _verb in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            app.add_api_route(
                _src,
                _root_handler,
                methods=[_verb],
                include_in_schema=False,
                name=f"admin_alias_root_{_verb.lower()}_{_src.replace('/','_')}",
            )
            app.add_api_route(
                _src + "/{subpath:path}",
                _sub_handler,
                methods=[_verb],
                include_in_schema=False,
                name=f"admin_alias_sub_{_verb.lower()}_{_src.replace('/','_')}",
            )

    # -----------------------------------------------------------------------
    # Serve React frontend — MUST be last (catch-all route)
    # -----------------------------------------------------------------------
    _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    _ui_dist_new = os.path.join(_repo_root, "suite-ui", "aldeci-ui-new", "dist")
    _ui_dist_legacy = os.path.join(_repo_root, "suite-ui", "aldeci", "dist")
    _ui_dist = _ui_dist_new if os.path.isdir(_ui_dist_new) else _ui_dist_legacy
    if os.path.isdir(_ui_dist):
        from starlette.responses import FileResponse
        from starlette.staticfiles import StaticFiles

        _assets_dir = os.path.join(_ui_dist, "assets")
        if os.path.isdir(_assets_dir):
            app.mount("/assets", StaticFiles(directory=_assets_dir), name="ui-assets")

        # API-doc gating list — paths the SPA catch-all must NOT serve as HTML.
        # /openapi.json, /docs, /redoc are already handled by the explicit
        # aliases above; this set is the defense-in-depth for typos and other
        # API-doc paths so they always 404 cleanly instead of returning HTML.
        _API_DOC_PATHS = {"openapi.json", "docs", "redoc", "docs/oauth2-redirect"}

        @app.get("/{full_path:path}", include_in_schema=False)
        async def _spa_fallback(full_path: str):
            if full_path.startswith("api/") or full_path in _API_DOC_PATHS:
                return _SpaJsonResp(
                    {"detail": "Not Found", "path": f"/{full_path}"},
                    status_code=404,
                )
            candidate = os.path.join(_ui_dist, full_path)
            if full_path and os.path.isfile(candidate):
                return FileResponse(candidate)
            return FileResponse(os.path.join(_ui_dist, "index.html"))

        _logger.info("Mounted React SPA from %s (last — after all %d routers)", _ui_dist, len(app.routes))
    else:
        _logger.warning("React UI dist not found at %s — SPA not served", _ui_dist)

    return app


app = create_app()
