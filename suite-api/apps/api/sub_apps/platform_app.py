"""Platform — Auth / Users / Admin / Tenancy / Billing / System-Health / MCP / Ingestion / Webhooks router registrar.

Wave 5 extraction from app.py (2026-04-27).  Wave 4 (GRC) had not yet landed
when Wave 5 was executed; commit subject notes the sequencing.

All Platform-classified include_router blocks that were scattered across
create_app() have been moved here.  Routes are registered directly on the
*parent* FastAPI app (registrar pattern) so ``len(app.routes)`` is unchanged
and the RISK-01 route-count gate continues to pass.

Loop-bound Platform routers that live inside ``_extra_apps_routers`` / the
``predictions`` tuple-loop remain in app.py and are NOT moved here — that is a
future loop-refactor wave per docs/app_py_refactor_plan_2026-04-27.md.

Usage (from create_app in app.py)::

    from apps.api.sub_apps.platform_app import register_platform_routers
    register_platform_routers(app, _verify_api_key, _require_scope, _logger)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

from fastapi import Depends

if TYPE_CHECKING:
    from fastapi import FastAPI

_log = logging.getLogger(__name__)


def register_platform_routers(
    app: "FastAPI",
    _verify_api_key: Callable[..., Any],
    _require_scope: Callable[..., Any],
    _logger: logging.Logger | None = None,
) -> None:
    """Register all Platform routers onto *app* in app.py source order.

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
    # Identity / Auth / Admin (formerly ~L3059-L3095 in app.py)
    # ------------------------------------------------------------------

    # Login endpoint — public (no auth required)
    try:
        from apps.api.users_router import (
            public_router as users_public_router,  # noqa: PLC0415
        )
        app.include_router(users_public_router)
        _logger.info("Mounted public users router (login)")
    except ImportError as exc:
        _logger.warning("users_public_router not available: %s", exc)

    # User management — admin only
    try:
        from apps.api.users_router import router as users_router  # noqa: PLC0415
        app.include_router(
            users_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Users router (admin:all)")
    except ImportError as exc:
        _logger.warning("users_router not available: %s", exc)

    try:
        from apps.api.teams_router import router as teams_router  # noqa: PLC0415
        app.include_router(
            teams_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Teams router (admin:all)")
    except ImportError as exc:
        _logger.warning("teams_router not available: %s", exc)

    try:
        from apps.api.admin_router import router as admin_router  # noqa: PLC0415
        app.include_router(
            admin_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Admin router (admin:all)")
    except ImportError as exc:
        _logger.warning("admin_router not available: %s", exc)

    # Tenant management — multi-tenancy isolation admin endpoints
    try:
        from apps.api.tenant_router import router as tenant_router  # noqa: PLC0415
        app.include_router(tenant_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Tenant Management router")
    except ImportError as exc:
        _logger.warning("tenant_router not available: %s", exc)

    # System administration routes — health, info, config
    try:
        from apps.api.system_router import router as system_router  # noqa: PLC0415
        app.include_router(
            system_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted System router (admin:all)")
    except ImportError as exc:
        _logger.warning("system_router not available: %s", exc)

    # Prometheus-compatible metrics endpoint
    try:
        from apps.api.metrics_router import router as metrics_router  # noqa: PLC0415
        app.include_router(metrics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Metrics router")
    except ImportError as exc:
        _logger.warning("metrics_router not available: %s", exc)

    # Platform health dashboard
    try:
        from apps.api.platform_router import router as platform_router  # noqa: PLC0415
        app.include_router(platform_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Platform router")
    except ImportError as exc:
        _logger.warning("platform_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Analytics / AI Orchestrator (formerly ~L3096-L3136 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.analytics_router import (
            router as analytics_router,  # noqa: PLC0415
        )
        app.include_router(analytics_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Analytics router")
    except ImportError as exc:
        _logger.warning("analytics_router not available: %s", exc)

    try:
        from apps.api.ai_orchestrator_router import (
            router as ai_orchestrator_router,  # noqa: PLC0415
        )
        app.include_router(
            ai_orchestrator_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted AI Orchestrator router")
    except ImportError as exc:
        _logger.warning("ai_orchestrator_router not available: %s", exc)

    # AI Teammates router (GAP-044)
    try:
        from apps.api.ai_orchestrator_router import (
            teammates_router as _teammates_router,  # noqa: PLC0415
        )
        app.include_router(_teammates_router)
        _logger.info("Mounted AI Teammates router at /api/v1/teammates (GAP-044)")
    except ImportError as exc:
        _logger.warning("AI Teammates router not available: %s", exc)

    # Formula Transparency router (GAP-043)
    try:
        from apps.api.formula_transparency_router import (
            router as _formula_router,  # noqa: PLC0415
        )
        app.include_router(_formula_router)
        _logger.info("Mounted Formula Transparency router at /api/v1/formula (GAP-043)")
    except ImportError as exc:
        _logger.warning("Formula Transparency router not available: %s", exc)

    # ------------------------------------------------------------------
    # Real-Time Streaming / WebSocket / EventBus (formerly ~L3138-L3168)
    # ------------------------------------------------------------------
    # NOTE: websocket_routes.py was removed 2026-05-02 — top-level `from suite_core.core...`
    # import was broken (silently swallowed) and the router was never effectively mounted.
    # Canonical /ws/events lives in ws_trustgraph_events_router.py (Wave-3 FEATURE-3).

    try:
        from apps.api.websocket_alerts_router import (
            router as websocket_alerts_router,  # noqa: PLC0415
        )
        app.include_router(websocket_alerts_router)
        _logger.info("Mounted WebSocket Alerts router")
    except ImportError as exc:
        _logger.warning("websocket_alerts_router not available: %s", exc)

    try:
        from apps.api.ws_events_router import (
            router as ws_events_router,  # noqa: PLC0415
        )
        app.include_router(ws_events_router)
        _logger.info("Mounted WS Events router")
    except ImportError as exc:
        _logger.warning("ws_events_router not available: %s", exc)

    try:
        from apps.api.stream_router import (
            router as event_stream_router,  # noqa: PLC0415
        )
        app.include_router(
            event_stream_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted Event Stream router (SSE + WebSocket)")
    except ImportError as exc:
        _logger.warning("event_stream_router not available: %s", exc)

    # ------------------------------------------------------------------
    # MCP / GraphRAG / TrustGraph (formerly ~L3170-L3217 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.mcp_routes import router as mcp_router  # noqa: PLC0415
        app.include_router(
            mcp_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted MCP/GraphRAG router")
    except ImportError as exc:
        _logger.warning("mcp_router not available: %s", exc)

    try:
        from apps.api.mcp_gateway_router import (
            router as mcp_gateway_router,  # noqa: PLC0415
        )
        app.include_router(mcp_gateway_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted MCP Gateway router")
    except ImportError as exc:
        _logger.warning("mcp_gateway_router not available: %s", exc)

    try:
        from apps.api.trustgraph_routes import (
            router as trustgraph_router,  # noqa: PLC0415
        )
        app.include_router(
            trustgraph_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))],
        )
        _logger.info("Mounted TrustGraph router")
    except ImportError as exc:
        _logger.warning("trustgraph_router not available: %s", exc)

    try:
        from apps.api.trustgraph_quality_router import (
            router as trustgraph_quality_router,  # noqa: PLC0415
        )
        app.include_router(
            trustgraph_quality_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))],
        )
        _logger.info("Mounted TrustGraph Quality router")
    except ImportError as exc:
        _logger.warning("trustgraph_quality_router not available: %s", exc)

    try:
        from apps.api.trustgraph_maintenance_router import (
            router as trustgraph_maintenance_router,  # noqa: PLC0415
        )
        app.include_router(
            trustgraph_maintenance_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))],
        )
        _logger.info("Mounted TrustGraph Maintenance router")
    except ImportError as exc:
        _logger.warning("trustgraph_maintenance_router not available: %s", exc)

    try:
        from apps.api.trustgraph_integration_router import (
            router as trustgraph_integration_router,  # noqa: PLC0415
        )
        app.include_router(trustgraph_integration_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted TrustGraph Integration router")
    except ImportError as exc:
        _logger.warning("trustgraph_integration_router not available: %s", exc)

    try:
        from apps.api.trustgraph_backbone_router import (
            router as trustgraph_backbone_router,  # noqa: PLC0415
        )
        app.include_router(trustgraph_backbone_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted TrustGraph Backbone router at /api/v1/graph")
    except ImportError as exc:
        _logger.warning("trustgraph_backbone_router not available: %s", exc)

    try:
        from apps.api.trustgraph_migrator_router import (
            router as trustgraph_migrator_router,  # noqa: PLC0415
        )
        app.include_router(trustgraph_migrator_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted TrustGraph Migrator router at /api/v1/trustgraph/migrate")
    except ImportError as exc:
        _logger.warning("trustgraph_migrator_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Connectors / Integrations / Webhooks (formerly ~L3412-L3446 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.iam_sso_router import router as iam_sso_router  # noqa: PLC0415
        app.include_router(iam_sso_router)
        _logger.info("Mounted IAM/SSO Connector router (Keycloak)")
    except ImportError as exc:
        _logger.warning("iam_sso_router not available: %s", exc)

    try:
        from apps.api.connectors_router import (
            router as connectors_router,  # noqa: PLC0415
        )
        app.include_router(
            connectors_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Universal Connectors router")
    except ImportError as exc:
        _logger.warning("connectors_router not available: %s", exc)

    try:
        from apps.api.org_router import router as org_router  # noqa: PLC0415
        app.include_router(org_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Org Management router")
    except ImportError as exc:
        _logger.warning("org_router not available: %s", exc)

    try:
        from apps.api.servicenow_sync_router import (
            router as servicenow_sync_router,  # noqa: PLC0415
        )
        app.include_router(
            servicenow_sync_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted ServiceNow Sync router")
    except ImportError as exc:
        _logger.warning("servicenow_sync_router not available: %s", exc)

    try:
        from apps.api.servicenow_sync_router import (
            webhook_router as servicenow_sync_webhook_router,  # noqa: PLC0415
        )
        app.include_router(servicenow_sync_webhook_router)
        _logger.info("Mounted ServiceNow Sync Webhook router (no auth)")
    except ImportError as exc:
        _logger.warning("servicenow_sync_webhook_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Workflows / SSO / SLA / Collaboration (formerly ~L3457-L3494 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.auth_router import router as auth_router  # noqa: PLC0415
        app.include_router(
            auth_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Auth router (admin:all)")
    except ImportError as exc:
        _logger.warning("auth_router not available: %s", exc)

    try:
        from apps.api.sso_router import router as sso_router  # noqa: PLC0415
        app.include_router(sso_router)
        _logger.info("Mounted Enterprise SSO router (SAML 2.0 + OIDC)")
    except ImportError as exc:
        _logger.warning("sso_router not available: %s", exc)

    try:
        from apps.api.bulk_router import router as bulk_router  # noqa: PLC0415
        app.include_router(
            bulk_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted Bulk router")
    except ImportError as exc:
        _logger.warning("bulk_router not available: %s", exc)

    try:
        from apps.api.collaboration_router import (
            router as collaboration_router,  # noqa: PLC0415
        )
        app.include_router(collaboration_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Collaboration router")
    except ImportError as exc:
        _logger.warning("collaboration_router not available: %s", exc)

    try:
        from apps.api.sla_router import router as sla_router  # noqa: PLC0415
        app.include_router(sla_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted SLA router")
    except ImportError as exc:
        _logger.warning("sla_router not available: %s", exc)

    try:
        from apps.api.sla_engine_router import (
            router as sla_engine_router,  # noqa: PLC0415
        )
        app.include_router(sla_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted SLA Engine router")
    except ImportError as exc:
        _logger.warning("sla_engine_router not available: %s", exc)

    try:
        from apps.api.workflows_router import (
            router as workflows_router,  # noqa: PLC0415
        )
        app.include_router(workflows_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Workflows router")
    except ImportError as exc:
        _logger.warning("workflows_router not available: %s", exc)

    try:
        from apps.api.change_management_router import (
            router as change_management_router,  # noqa: PLC0415
        )
        app.include_router(change_management_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Change Management router")
    except ImportError as exc:
        _logger.warning("change_management_router not available: %s", exc)

    # Wave D — 22 Multica integrations/AI/policy endpoints
    try:
        from apps.api.wave_d_integrations_router import (
            router as wave_d_integrations_router,  # noqa: PLC0415
        )
        app.include_router(wave_d_integrations_router)
        _logger.info("Mounted Wave D integrations router (22 endpoints)")
    except ImportError as exc:
        _logger.warning("wave_d_integrations_router not available: %s", exc)

    # Hooks router — POST /api/v1/hooks/uninstall
    try:
        from apps.api.hooks_router import router as hooks_router  # noqa: PLC0415
        app.include_router(hooks_router)
        _logger.info("Mounted Hooks router (POST /api/v1/hooks/uninstall)")
    except ImportError as exc:
        _logger.warning("hooks_router not available: %s", exc)

    # Integration Marketplace API
    try:
        from apps.api.integration_marketplace_router import (
            router as integration_marketplace_router,  # noqa: PLC0415
        )
        app.include_router(integration_marketplace_router)
        _logger.info("Mounted Integration Marketplace router at /api/v1/integrations")
    except ImportError as exc:
        _logger.warning("integration_marketplace_router not available: %s", exc)

    # Enterprise marketplace API
    try:
        from apps.api.marketplace_router import (
            router as marketplace_router,  # noqa: PLC0415
        )
        app.include_router(
            marketplace_router,
            prefix="/api/v1/marketplace",
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Marketplace router at /api/v1/marketplace")
    except ImportError as exc:
        _logger.warning("marketplace_router not available: %s", exc)

    # Customer onboarding wizard
    try:
        from apps.api.onboarding_router import (
            router as onboarding_wizard_router,  # noqa: PLC0415
        )
        app.include_router(
            onboarding_wizard_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Onboarding Wizard router")
    except ImportError as exc:
        _logger.warning("onboarding_wizard_router not available: %s", exc)

    # Admin first-login wizard (no auth)
    try:
        from apps.api.admin_wizard_router import (
            router as admin_wizard_router,  # noqa: PLC0415
        )
        app.include_router(admin_wizard_router)
        _logger.info("Mounted Admin First-Login Wizard router (no auth — first-login flow)")
    except ImportError as exc:
        _logger.warning("admin_wizard_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Queue / Cache / Deployment (formerly ~L3631-L3658 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.queue_router import router as queue_router  # noqa: PLC0415
        app.include_router(queue_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Loaded Queue status router")
    except ImportError as exc:
        _logger.warning("queue_router not available: %s", exc)

    try:
        from apps.api.cache_router import router as cache_router  # noqa: PLC0415
        app.include_router(
            cache_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Loaded Cache management router")
    except ImportError as exc:
        _logger.warning("cache_router not available: %s", exc)

    try:
        from apps.api.deployment_router import (
            router as deployment_router,  # noqa: PLC0415
        )
        app.include_router(deployment_router)
        _logger.info("Mounted Deployment Manager router at /api/v1/deployment")
    except ImportError as exc:
        _logger.warning("deployment_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Webhook management (formerly ~L5504-L5534 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.webhook_subscriptions_router import (
            router as webhook_subscriptions_router,  # noqa: PLC0415
        )
        app.include_router(
            webhook_subscriptions_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook Subscriptions router")
    except ImportError as exc:
        _logger.warning("webhook_subscriptions_router not available: %s", exc)

    try:
        from apps.api.webhook_dlq_router import (
            router as webhook_dlq_router,  # noqa: PLC0415
        )
        app.include_router(
            webhook_dlq_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook DLQ router")
    except ImportError as exc:
        _logger.warning("webhook_dlq_router not available: %s", exc)

    try:
        from apps.api.webhook_notifications_router import (
            router as webhook_notifications_router,  # noqa: PLC0415
        )
        app.include_router(
            webhook_notifications_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook Notifications router")
    except ImportError as exc:
        _logger.warning("webhook_notifications_router not available: %s", exc)

    try:
        from apps.api.webhook_verifier_router import (
            router as webhook_verifier_router,  # noqa: PLC0415
        )
        app.include_router(
            webhook_verifier_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook Verifier router")
    except ImportError as exc:
        _logger.warning("webhook_verifier_router not available: %s", exc)

    try:
        from apps.api.webhook_filter_rules_router import (  # noqa: PLC0415
            router as webhook_filter_rules_router,
        )
        app.include_router(
            webhook_filter_rules_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook Filter Rules router")
    except ImportError as exc:
        _logger.warning("webhook_filter_rules_router not available: %s", exc)

    try:
        from apps.api.webhook_router import router as webhook_router  # noqa: PLC0415
        app.include_router(webhook_router)
        _logger.info("Mounted Webhook router")
    except ImportError as exc:
        _logger.warning("webhook_router not available: %s", exc)

    try:
        from api.webhooks_router import (
            receiver_router as webhooks_receiver_router,  # noqa: PLC0415
        )
        from api.webhooks_router import router as webhooks_router  # noqa: PLC0415
        app.include_router(webhooks_router)
        app.include_router(webhooks_receiver_router)
        _logger.info("Mounted inbound Webhooks router")
    except ImportError as exc:
        _logger.warning("webhooks_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Integrations hub / Jira / PagerDuty / Slack / ServiceNow / n8n
    # (formerly scattered across L6185-L8340 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.integration_hub_router import (
            router as integration_hub_router,  # noqa: PLC0415
        )
        app.include_router(integration_hub_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Integration Hub router")
    except ImportError as exc:
        _logger.warning("integration_hub_router not available: %s", exc)

    try:
        from apps.api.integration_health_router import (
            router as integration_health_router,  # noqa: PLC0415
        )
        app.include_router(integration_health_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Integration Health router")
    except ImportError as exc:
        _logger.warning("integration_health_router not available: %s", exc)

    try:
        from apps.api.jira_sync_router import (
            router as jira_sync_router,  # noqa: PLC0415
        )
        app.include_router(jira_sync_router)
        _logger.info("Mounted Jira Sync router at /api/v1/jira-sync")
    except ImportError as exc:
        _logger.warning("jira_sync_router not available: %s", exc)

    try:
        from apps.api.jira_cloud_router import (
            router as jira_cloud_router,  # noqa: PLC0415
        )
        app.include_router(
            jira_cloud_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Jira Cloud router at /api/v1/jira-cloud")
    except ImportError as exc:
        _logger.warning("jira_cloud_router not available: %s", exc)

    try:
        from apps.api.servicenow_router import (
            router as servicenow_itsm_router,  # noqa: PLC0415
        )
        app.include_router(
            servicenow_itsm_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted ServiceNow ITSM router at /api/v1/servicenow (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("servicenow_itsm_router not available: %s", exc)

    try:
        from apps.api.workday_router import (
            router as workday_router,  # noqa: PLC0415
        )
        app.include_router(
            workday_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Workday HCM router at /api/v1/workday (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("workday_router not available: %s", exc)

    try:
        from apps.api.mattermost_router import (
            router as mattermost_router,  # noqa: PLC0415
        )
        app.include_router(
            mattermost_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Mattermost router at /api/v1/mattermost (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("mattermost_router not available: %s", exc)

    try:
        from apps.api.jenkins_router import (
            router as jenkins_router,  # noqa: PLC0415
        )
        app.include_router(
            jenkins_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Jenkins CI router at /api/v1/jenkins (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("jenkins_router not available: %s", exc)

    try:
        from apps.api.gitlab_pipeline_router import (
            router as gitlab_pipeline_router,  # noqa: PLC0415
        )
        app.include_router(
            gitlab_pipeline_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted GitLab CI/CD router at /api/v1/gitlab-pipeline (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("gitlab_pipeline_router not available: %s", exc)

    try:
        from apps.api.harbor_router import (
            router as harbor_router,  # noqa: PLC0415
        )
        app.include_router(
            harbor_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Harbor container registry router at /api/v1/harbor (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("harbor_router not available: %s", exc)
    try:
        from apps.api.gar_router import (
            router as gar_router,  # noqa: PLC0415
        )
        app.include_router(
            gar_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Google Artifact Registry router at /api/v1/gar (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("gar_router not available: %s", exc)


    try:
        from apps.api.bitbucket_router import (
            router as bitbucket_router,  # noqa: PLC0415
        )
        app.include_router(
            bitbucket_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Bitbucket Cloud router at /api/v1/bitbucket (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("bitbucket_router not available: %s", exc)

    try:
        from apps.api.circleci_router import (
            router as circleci_router,  # noqa: PLC0415
        )
        app.include_router(
            circleci_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted CircleCI v2 router at /api/v1/circleci (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("circleci_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Checkmarx One — SAST/SCA/IaC platform (read:scans)
    # ------------------------------------------------------------------
    # GET  /api/v1/checkmarx/                                                                  capability summary
    # POST /api/v1/checkmarx/api/iam/auth/realms/{tenant}/protocol/openid-connect/token        OAuth2 client_credentials
    # GET  /api/v1/checkmarx/api/projects                                                      list projects
    # GET  /api/v1/checkmarx/api/projects/{project_id}                                         project detail
    # GET  /api/v1/checkmarx/api/scans                                                         list scans
    # POST /api/v1/checkmarx/api/scans                                                         create scan
    # GET  /api/v1/checkmarx/api/scan-results                                                  list scan results
    # GET  /api/v1/checkmarx/api/scan-results/{result_id}                                      result detail
    # POST /api/v1/checkmarx/api/scan-results                                                  triage update
    # GET  /api/v1/checkmarx/api/cx-policy-management/policies                                 list policies
    # ------------------------------------------------------------------
    try:
        from apps.api.checkmarx_router import (
            router as checkmarx_router,  # noqa: PLC0415
        )
        app.include_router(
            checkmarx_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Checkmarx One router at /api/v1/checkmarx (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("checkmarx_router not available: %s", exc)

    try:
        from apps.api.github_api_router import (
            router as github_api_router,  # noqa: PLC0415
        )
        app.include_router(
            github_api_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted GitHub REST v3 router at /api/v1/github-api (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("github_api_router not available: %s", exc)

    try:
        from apps.api.pagerduty_router import (
            router as pagerduty_router,  # noqa: PLC0415
        )
        app.include_router(
            pagerduty_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted PagerDuty router at /api/v1/pagerduty (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("pagerduty_router not available: %s", exc)

    try:
        from apps.api.pagerduty_events_router import (
            router as pagerduty_events_router,  # noqa: PLC0415
        )
        app.include_router(
            pagerduty_events_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted PagerDuty Events v2 router at /api/v1/pagerduty-events (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("pagerduty_events_router not available: %s", exc)

    try:
        from apps.api.argocd_router import (
            router as argocd_router,  # noqa: PLC0415
        )
        app.include_router(
            argocd_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted ArgoCD GitOps router at /api/v1/argocd (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("argocd_router not available: %s", exc)

    try:
        from apps.api.crossplane_router import (
            router as crossplane_router,  # noqa: PLC0415
        )
        app.include_router(
            crossplane_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Crossplane (k8s API proxy) router at /api/v1/crossplane (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("crossplane_router not available: %s", exc)

    try:
        from apps.api.aws_securityhub_router import (
            router as aws_securityhub_router,  # noqa: PLC0415
        )
        app.include_router(
            aws_securityhub_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted AWS Security Hub router at /api/v1/aws-securityhub (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("aws_securityhub_router not available: %s", exc)

    try:
        from apps.api.lacework_router import (
            router as lacework_router,  # noqa: PLC0415
        )
        app.include_router(
            lacework_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Lacework CSPM router at /api/v1/lacework (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("lacework_router not available: %s", exc)

    try:
        from apps.api.amazon_inspector_router import (
            router as amazon_inspector_router,  # noqa: PLC0415
        )
        app.include_router(
            amazon_inspector_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Amazon Inspector v2 router at /api/v1/amazon-inspector (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("amazon_inspector_router not available: %s", exc)

    try:
        from apps.api.aws_iam_router import (
            router as aws_iam_router,  # noqa: PLC0415
        )
        app.include_router(
            aws_iam_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted AWS IAM router at /api/v1/aws-iam (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("aws_iam_router not available: %s", exc)

    try:
        from apps.api.proofpoint_tap_router import (
            router as proofpoint_tap_router,  # noqa: PLC0415
        )
        app.include_router(
            proofpoint_tap_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Proofpoint TAP router at /api/v1/proofpoint-tap (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("proofpoint_tap_router not available: %s", exc)

    try:
        from apps.api.datadog_security_router import (
            router as datadog_security_router,  # noqa: PLC0415
        )
        app.include_router(
            datadog_security_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Datadog Cloud SIEM router at /api/v1/datadog-security (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("datadog_security_router not available: %s", exc)

    try:
        from apps.api.defender_xdr_router import (
            router as defender_xdr_router,  # noqa: PLC0415
        )
        app.include_router(
            defender_xdr_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Microsoft Defender XDR router at /api/v1/defender-xdr (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("defender_xdr_router not available: %s", exc)

    try:
        from apps.api.purview_dlp_router import (
            router as purview_dlp_router,  # noqa: PLC0415
        )
        app.include_router(
            purview_dlp_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Microsoft Purview DLP router at /api/v1/microsoft-purview (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("purview_dlp_router not available: %s", exc)

    try:
        from apps.api.snowflake_router import (
            router as snowflake_router,  # noqa: PLC0415
        )
        app.include_router(
            snowflake_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Snowflake SQL API router at /api/v1/snowflake (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("snowflake_router not available: %s", exc)

    try:
        from apps.api.newrelic_router import (
            router as newrelic_router,  # noqa: PLC0415
        )
        app.include_router(
            newrelic_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted New Relic APM router at /api/v1/newrelic (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("newrelic_router not available: %s", exc)

    try:
        from apps.api.discord_router import (
            router as discord_router,  # noqa: PLC0415
        )
        app.include_router(
            discord_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Discord router at /api/v1/discord (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("discord_router not available: %s", exc)

    try:
        from apps.api.ansible_tower_router import (
            router as ansible_tower_router,  # noqa: PLC0415
        )
        app.include_router(
            ansible_tower_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Ansible Tower router at /api/v1/ansible-tower (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("ansible_tower_router not available: %s", exc)


    try:
        from apps.api.harness_router import (
            router as harness_router,  # noqa: PLC0415
        )
        app.include_router(
            harness_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Harness CD router at /api/v1/harness (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("harness_router not available: %s", exc)

    try:
        from apps.api.terraform_cloud_router import (
            router as terraform_cloud_router,  # noqa: PLC0415
        )
        app.include_router(
            terraform_cloud_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Terraform Cloud router at /api/v1/terraform-cloud (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("terraform_cloud_router not available: %s", exc)

    try:
        from apps.api.microsoft_teams_router import (
            router as microsoft_teams_router,  # noqa: PLC0415
        )
        app.include_router(
            microsoft_teams_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Microsoft Teams router at /api/v1/microsoft-teams (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("microsoft_teams_router not available: %s", exc)

    try:
        from apps.api.google_chat_router import (
            router as google_chat_router,  # noqa: PLC0415
        )
        app.include_router(
            google_chat_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Google Chat router at /api/v1/google-chat (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("google_chat_router not available: %s", exc)

    try:
        from apps.api.slack_bot_router import (
            router as slack_bot_router,  # noqa: PLC0415
        )
        app.include_router(slack_bot_router)
        _logger.info("Mounted Slack Bot router")
    except ImportError as exc:
        _logger.warning("slack_bot_router not available: %s", exc)

    try:
        from apps.api.slack_notifier_router import (
            router as slack_notifier_router,  # noqa: PLC0415
        )
        app.include_router(slack_notifier_router)
        _logger.info("Mounted Slack Notifier router at /api/v1/integrations/slack")
    except ImportError as exc:
        _logger.warning("slack_notifier_router not available: %s", exc)

    try:
        from apps.api.slack_chatops_router import (
            router as slack_chatops_router,  # noqa: PLC0415
        )
        app.include_router(
            slack_chatops_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Slack ChatOps router at /api/v1/slack-chatops (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("slack_chatops_router not available: %s", exc)

    try:
        from apps.api.fastly_router import (
            router as fastly_router,  # noqa: PLC0415
        )
        app.include_router(
            fastly_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:scans"))],
        )
        _logger.info("Mounted Fastly Edge router at /api/v1/fastly (scope=read:scans)")
    except ImportError as exc:
        _logger.warning("fastly_router not available: %s", exc)

    try:
        from servicenow.servicenow_router import (
            router as servicenow_router,  # noqa: PLC0415
        )
        app.include_router(servicenow_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted ServiceNow connector at /api/v1/servicenow")
    except ImportError as exc:
        _logger.warning("servicenow_router not available: %s", exc)

    try:
        from apps.api.n8n_router import router as n8n_router  # noqa: PLC0415
        app.include_router(n8n_router)
        _logger.info("Mounted n8n router at /api/v1/n8n")
    except ImportError as exc:
        _logger.warning("n8n_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Analytics dashboards / DuckDB / GraphRAG / NL graph
    # (formerly ~L3385-L3435 expanded section in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.analytics_dashboard_router import (
            router as analytics_dashboard_router,  # noqa: PLC0415
        )
        app.include_router(analytics_dashboard_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Analytics Dashboard router")
    except ImportError as exc:
        _logger.warning("analytics_dashboard_router not available: %s", exc)

    try:
        from apps.api.analytics_routes import (
            router as analytics_routes_router,  # noqa: PLC0415
        )
        app.include_router(analytics_routes_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Analytics Routes router")
    except ImportError as exc:
        _logger.warning("analytics_routes_router not available: %s", exc)

    try:
        from apps.api.duckdb_analytics_router import (
            router as duckdb_analytics_router,  # noqa: PLC0415
        )
        app.include_router(duckdb_analytics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted DuckDB Analytics router")
    except ImportError as exc:
        _logger.warning("duckdb_analytics_router not available: %s", exc)

    try:
        from apps.api.graphrag_router import router as graphrag_router  # noqa: PLC0415
        app.include_router(graphrag_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted GraphRAG router")
    except ImportError as exc:
        _logger.warning("graphrag_router not available: %s", exc)

    try:
        from apps.api.nl_graph_router import router as nl_graph_router  # noqa: PLC0415
        app.include_router(nl_graph_router)
        _logger.info("Mounted NL Graph Assistant router at /api/v1/nl-graph (GAP-029)")
    except ImportError as exc:
        _logger.warning("nl_graph_router not available: %s", exc)

    try:
        from apps.api.dashboard_builder_router import (
            router as dashboard_builder_router,  # noqa: PLC0415
        )
        app.include_router(dashboard_builder_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Dashboard Builder router")
    except ImportError as exc:
        _logger.warning("dashboard_builder_router not available: %s", exc)

    try:
        from apps.api.unified_dashboard_router import (
            router as unified_dashboard_router,  # noqa: PLC0415
        )
        app.include_router(unified_dashboard_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Unified Dashboard router")
    except ImportError as exc:
        _logger.warning("unified_dashboard_router not available: %s", exc)

    try:
        from apps.api.api_analytics_router import (
            router as api_analytics_router,  # noqa: PLC0415
        )
        app.include_router(api_analytics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted API Analytics router")
    except ImportError as exc:
        _logger.warning("api_analytics_router not available: %s", exc)

    try:
        from apps.api.api_gateway_router import (
            router as api_gateway_router,  # noqa: PLC0415
        )
        app.include_router(api_gateway_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted API Gateway Security router")
    except ImportError as exc:
        _logger.warning("api_gateway_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Metrics / SLA / RBAC / Session / SSE / OAuth2
    # (formerly ~L7560-L8340 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.metrics_aggregator_router import (
            router as metrics_aggregator_router,  # noqa: PLC0415
        )
        app.include_router(metrics_aggregator_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Metrics Aggregator router")
    except ImportError as exc:
        _logger.warning("metrics_aggregator_router not available: %s", exc)

    try:
        from apps.api.metrics_timeseries_router import (
            router as metrics_timeseries_router,  # noqa: PLC0415
        )
        app.include_router(metrics_timeseries_router)
        _logger.info("Mounted Metrics Time-Series router")
    except ImportError as exc:
        _logger.warning("metrics_timeseries_router not available: %s", exc)

    try:
        from apps.api.notification_router import (
            router as notification_router,  # noqa: PLC0415
        )
        app.include_router(notification_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Notification router")
    except ImportError as exc:
        _logger.warning("notification_router not available: %s", exc)

    try:
        from apps.api.alerting_notification_router import (
            router as alerting_notification_router,  # noqa: PLC0415
        )
        app.include_router(alerting_notification_router)
        _logger.info("Mounted Alerting Notification router at /api/v1/alerting")
    except ImportError as exc:
        _logger.warning("alerting_notification_router not available: %s", exc)

    try:
        from apps.api.rate_limit_router import (
            router as rate_limit_router,  # noqa: PLC0415
        )
        app.include_router(rate_limit_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Rate Limit router")
    except ImportError as exc:
        _logger.warning("rate_limit_router not available: %s", exc)

    try:
        from apps.api.tenant_rate_limiter_router import (
            router as tenant_rate_limiter_router,  # noqa: PLC0415
        )
        app.include_router(tenant_rate_limiter_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Tenant Rate Limiter router")
    except ImportError as exc:
        _logger.warning("tenant_rate_limiter_router not available: %s", exc)

    try:
        from apps.api.rbac_router import router as rbac_router  # noqa: PLC0415
        app.include_router(rbac_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted RBAC router at /api/v1/rbac")
    except ImportError as exc:
        _logger.warning("rbac_router not available: %s", exc)

    try:
        from apps.api.session_router import router as session_router  # noqa: PLC0415
        app.include_router(session_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Session router at /api/v1/sessions")
    except ImportError as exc:
        _logger.warning("session_router not available: %s", exc)

    try:
        from apps.api.sla_management_router import (
            router as sla_management_router,  # noqa: PLC0415
        )
        app.include_router(sla_management_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted SLA Management router at /api/v1/sla-management")
    except ImportError as exc:
        _logger.warning("sla_management_router not available: %s", exc)

    try:
        from apps.api.sse_router import router as sse_router  # noqa: PLC0415
        app.include_router(sse_router)
        _logger.info("Mounted SSE event stream router at /api/v1/events/stream")
    except ImportError as exc:
        _logger.warning("sse_router not available: %s", exc)

    try:
        from apps.api.oauth2_router import router as oauth2_router  # noqa: PLC0415
        app.include_router(oauth2_router)
        _logger.info("Mounted OAuth2 token endpoint at /api/v1/oauth2/token")
    except ImportError as exc:
        _logger.warning("oauth2_router not available: %s", exc)

    try:
        from apps.api.observability_router import (
            router as observability_router,  # noqa: PLC0415
        )
        app.include_router(observability_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Observability router at /api/v1/observability")
    except ImportError as exc:
        _logger.warning("observability_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Platform configuration / changelog / backup / bulk ops / export
    # (formerly ~L5540-L5570 expanded section in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.backup_router import router as backup_router  # noqa: PLC0415
        app.include_router(backup_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Backup router")
    except ImportError as exc:
        _logger.warning("backup_router not available: %s", exc)

    try:
        from apps.api.changelog_router import (
            router as changelog_router,  # noqa: PLC0415
        )
        app.include_router(changelog_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Changelog router")
    except ImportError as exc:
        _logger.warning("changelog_router not available: %s", exc)

    try:
        from apps.api.export_router import router as export_router  # noqa: PLC0415
        app.include_router(export_router)
        _logger.info("Mounted Data Export router at /api/v1/export")
    except ImportError as exc:
        _logger.warning("export_router not available: %s", exc)

    try:
        from apps.api.tag_router import router as tag_router  # noqa: PLC0415
        app.include_router(tag_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Tag router")
    except ImportError as exc:
        _logger.warning("tag_router not available: %s", exc)

    try:
        from apps.api.log_management_router import (
            router as log_management_router,  # noqa: PLC0415
        )
        app.include_router(log_management_router)
        _logger.info("Mounted Log Management router at /api/v1/log-management")
    except ImportError as exc:
        _logger.warning("log_management_router not available: %s", exc)

    try:
        from apps.api.cmdb_router import router as cmdb_router  # noqa: PLC0415
        app.include_router(cmdb_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted CMDB router at /api/v1/cmdb")
    except ImportError as exc:
        _logger.warning("cmdb_router not available: %s", exc)

    try:
        from apps.api.local_file_store_router import (
            router as local_file_store_router,  # noqa: PLC0415
        )
        app.include_router(local_file_store_router)
        _logger.info("Mounted Local File Store router")
    except ImportError as exc:
        _logger.warning("local_file_store_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Security tooling / health / telemetry / registry / query / automation
    # (formerly ~L6455-L7580 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.security_health_router import (
            router as security_health_router,  # noqa: PLC0415
        )
        app.include_router(security_health_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Health router at /api/v1/security-health")
    except ImportError as exc:
        _logger.warning("security_health_router not available: %s", exc)

    try:
        from apps.api.security_telemetry_router import (
            router as security_telemetry_router,  # noqa: PLC0415
        )
        app.include_router(security_telemetry_router)
        _logger.info("Mounted Security Telemetry router")
    except ImportError as exc:
        _logger.warning("security_telemetry_router not available: %s", exc)

    try:
        from apps.api.security_registry_router import (
            router as security_registry_router,  # noqa: PLC0415
        )
        app.include_router(security_registry_router)
        _logger.info("Mounted Security Registry router")
    except ImportError as exc:
        _logger.warning("security_registry_router not available: %s", exc)

    try:
        from apps.api.security_query_router import (
            router as security_query_router,  # noqa: PLC0415
        )
        app.include_router(security_query_router)
        _logger.info("Mounted Security Query Language router")
    except ImportError as exc:
        _logger.warning("security_query_router not available: %s", exc)

    try:
        from apps.api.security_automation_router import (
            router as security_automation_router,  # noqa: PLC0415
        )
        app.include_router(security_automation_router)
        _logger.info("Mounted Security Automation router at /api/v1/security-automation")
    except ImportError as exc:
        _logger.warning("security_automation_router not available: %s", exc)

    try:
        from apps.api.security_data_pipeline_router import (
            router as security_data_pipeline_router,  # noqa: PLC0415
        )
        app.include_router(security_data_pipeline_router)
        _logger.info("Mounted Security Data Pipeline router")
    except ImportError as exc:
        _logger.warning("security_data_pipeline_router not available: %s", exc)

    try:
        from apps.api.security_tool_inventory_router import (
            router as security_tool_inventory_router,  # noqa: PLC0415
        )
        app.include_router(security_tool_inventory_router)
        _logger.info("Mounted Security Tool Inventory router at /api/v1/tool-inventory")
    except ImportError as exc:
        _logger.warning("security_tool_inventory_router not available: %s", exc)

    # ------------------------------------------------------------------
    # LLM loop metrics / user analytics / upgrade path / air gap bundle
    # (formerly ~L3689 expanded section in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.llm_loop_metrics_router import (
            router as llm_loop_metrics_router,  # noqa: PLC0415
        )
        app.include_router(llm_loop_metrics_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted LLM Loop Telemetry router")
    except ImportError as exc:
        _logger.warning("llm_loop_metrics_router not available: %s", exc)

    try:
        from apps.api.user_analytics_router import (
            router as user_analytics_router,  # noqa: PLC0415
        )
        app.include_router(user_analytics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted User Analytics router")
    except ImportError as exc:
        _logger.warning("user_analytics_router not available: %s", exc)

    try:
        from apps.api.upgrade_path_router import (
            router as upgrade_path_router,  # noqa: PLC0415
        )
        app.include_router(upgrade_path_router)
        _logger.info("Mounted Upgrade Path Resolver router at /api/v1/upgrade-path")
    except ImportError as exc:
        _logger.warning("upgrade_path_router not available: %s", exc)

    try:
        from apps.api.air_gap_bundle_router import (
            router as air_gap_bundle_router,  # noqa: PLC0415
        )
        app.include_router(air_gap_bundle_router)
        _logger.info("Mounted Air-Gap Bundle router at /api/v1/air-gap")
    except ImportError as exc:
        _logger.warning("air_gap_bundle_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Council / GraphRAG enhanced / workflow engine / versioning
    # (formerly scattered in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.council_enhanced_router import (
            router as council_enhanced_router,  # noqa: PLC0415
        )
        app.include_router(council_enhanced_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Council Enhanced router")
    except ImportError as exc:
        _logger.warning("council_enhanced_router not available: %s", exc)

    try:
        from apps.api.llm_council_router import (
            router as llm_council_router,  # noqa: PLC0415
        )
        app.include_router(llm_council_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted LLM Council Status router at /api/v1/llm/council/status")
    except ImportError as exc:
        _logger.warning("llm_council_router not available: %s", exc)

    try:
        from apps.api.workflow_engine_router import (
            router as workflow_engine_router,  # noqa: PLC0415
        )
        app.include_router(workflow_engine_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Workflow Engine router")
    except ImportError as exc:
        _logger.warning("workflow_engine_router not available: %s", exc)

    try:
        from apps.api.versioning_router import (
            router as versioning_router,  # noqa: PLC0415
        )
        app.include_router(versioning_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted API Versioning router")
    except ImportError as exc:
        _logger.warning("versioning_router not available: %s", exc)

    try:
        from apps.api.webhook_events_router import (
            router as webhook_events_router,  # noqa: PLC0415
        )
        app.include_router(webhook_events_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Webhook Events router")
    except ImportError as exc:
        _logger.warning("webhook_events_router not available: %s", exc)

    try:
        from apps.api.app_config_router import (
            router as app_config_router,  # noqa: PLC0415
        )
        app.include_router(
            app_config_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted APP_ID Configuration router")
    except ImportError as exc:
        _logger.warning("app_config_router not available: %s", exc)

    try:
        from apps.api.org_hierarchy_router import (
            router as org_hierarchy_router,  # noqa: PLC0415
        )
        app.include_router(org_hierarchy_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Org Hierarchy router")
    except ImportError as exc:
        _logger.warning("org_hierarchy_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Wave-6 — loop-bound Platform entries (formerly in _core_routers /
    # _integration_routers / _extra_apps_routers loops in app.py)
    # ------------------------------------------------------------------

    # _core_routers Platform/Brain entries (read:findings unless noted)

    # ML/MindsDB router (suite-core/api/)
    try:
        from api.mindsdb_router import router as ml_router  # noqa: PLC0415
        app.include_router(ml_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted ML/MindsDB router (wave-6)")
    except ImportError:
        pass

    # Air-Gap Operations (suite-core/api/)
    try:
        from api.airgap_router import router as airgap_router  # noqa: PLC0415
        app.include_router(airgap_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted Air-Gap Operations router (wave-6)")
    except ImportError:
        pass

    # Fuzzy Identity (suite-core/api/)
    try:
        from api.fuzzy_identity_router import (
            router as fuzzy_identity_router,  # noqa: PLC0415
        )
        app.include_router(fuzzy_identity_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Fuzzy Identity router (wave-6)")
    except ImportError:
        pass

    # Exposure Case (suite-core/api/)
    try:
        from api.exposure_case_router import (
            router as exposure_case_router,  # noqa: PLC0415
        )
        app.include_router(exposure_case_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Exposure Case router (wave-6)")
    except ImportError:
        pass

    # Pipeline — Brain Pipeline (suite-core/api/)
    try:
        from api.pipeline_router import router as pipeline_router  # noqa: PLC0415
        app.include_router(pipeline_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Pipeline router (wave-6)")
    except ImportError:
        pass

    # Copilot (suite-core/api/)
    try:
        from api.copilot_router import router as copilot_router  # noqa: PLC0415
        app.include_router(copilot_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Copilot router (wave-6)")
    except ImportError:
        pass

    # Agents (suite-core/api/)
    try:
        from api.agents_router import router as agents_router  # noqa: PLC0415
        app.include_router(agents_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Agents router (wave-6)")
    except ImportError:
        pass

    # Predictions (suite-core/api/)
    try:
        from api.predictions_router import router as predictions_router  # noqa: PLC0415
        app.include_router(predictions_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Predictions router (wave-6)")
    except ImportError:
        pass

    # LLM (suite-core/api/)
    try:
        from api.llm_router import router as llm_router  # noqa: PLC0415
        app.include_router(llm_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted LLM router (wave-6)")
    except ImportError:
        pass

    # Algorithmic (suite-core/api/)
    try:
        from api.algorithmic_router import router as algorithmic_router  # noqa: PLC0415
        app.include_router(algorithmic_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Algorithmic router (wave-6)")
    except ImportError:
        pass

    # LLM Monitor (suite-core/api/)
    try:
        from api.llm_monitor_router import router as llm_monitor_router  # noqa: PLC0415
        app.include_router(llm_monitor_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted LLM Monitor router (wave-6)")
    except (ImportError, Exception):
        pass

    # LLM Guard (suite-core/api/)
    try:
        from api.llm_guard_router import router as llm_guard_router  # noqa: PLC0415
        app.include_router(llm_guard_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted LLM Guard router (wave-6)")
    except (ImportError, Exception):
        pass

    # SSE Streaming (suite-core/api/)
    try:
        from api.streaming_router import router as streaming_router  # noqa: PLC0415
        app.include_router(streaming_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted SSE Streaming router (wave-6)")
    except ImportError:
        pass

    # Code-to-Cloud Tracing (suite-core/api/)
    try:
        from api.code_to_cloud_router import (
            router as code_to_cloud_router,  # noqa: PLC0415
        )
        app.include_router(code_to_cloud_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))])
        _logger.info("Mounted Code-to-Cloud router (wave-6)")
    except ImportError:
        pass

    # Quantum Crypto (suite-core/api/)
    try:
        from api.quantum_crypto_router import (
            router as quantum_crypto_router,  # noqa: PLC0415
        )
        app.include_router(quantum_crypto_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted Quantum Crypto router (wave-6)")
    except ImportError:
        pass

    # Zero-Gravity Data (suite-core/api/)
    try:
        from api.zero_gravity_router import (
            router as zero_gravity_router,  # noqa: PLC0415
        )
        app.include_router(zero_gravity_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted Zero-Gravity router (wave-6)")
    except ImportError:
        pass

    # Single Agent (suite-core/api/)
    try:
        from api.single_agent_router import (
            router as single_agent_router,  # noqa: PLC0415
        )
        app.include_router(single_agent_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Single Agent router (wave-6)")
    except ImportError:
        pass

    # Knowledge Graph (suite-core/api/)
    try:
        from api.knowledge_graph_router import (
            router as knowledge_graph_router,  # noqa: PLC0415
        )
        app.include_router(knowledge_graph_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))])
        _logger.info("Mounted Knowledge Graph router (wave-6)")
    except ImportError:
        pass

    # vLLM Self-Hosted (suite-core/api/)
    try:
        from api.vllm_router import router as vllm_router  # noqa: PLC0415
        app.include_router(vllm_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted vLLM router (wave-6)")
    except ImportError:
        pass

    # MCP Protocol (suite-core/api/)
    try:
        from api.mcp_protocol_router import (
            router as mcp_protocol_router,  # noqa: PLC0415
        )
        app.include_router(mcp_protocol_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted MCP Protocol router (wave-6)")
    except ImportError:
        pass

    # Self-Learning (suite-core/api/)
    try:
        from api.self_learning_router import (
            router as self_learning_router,  # noqa: PLC0415
        )
        app.include_router(self_learning_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Self-Learning router (wave-6)")
    except ImportError:
        pass

    # LLM Loop Metrics telemetry (apps/api/)
    try:
        from apps.api.llm_loop_metrics_router import (
            router as llm_loop_metrics_router,  # noqa: PLC0415
        )
        app.include_router(llm_loop_metrics_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted LLM Loop Metrics router (wave-6)")
    except ImportError:
        pass

    # Developer Risk Profiles (apps/api/)
    try:
        from apps.api.developer_profiles_router import (
            router as developer_profiles_router,  # noqa: PLC0415
        )
        app.include_router(developer_profiles_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Developer Risk Profiles router (wave-6)")
    except ImportError:
        pass

    # _integration_routers (all write:integrations scope)

    # Integrations (suite-integrations/api/)
    try:
        from api.integrations_router import (
            router as integrations_router_ext,  # noqa: PLC0415
        )
        app.include_router(integrations_router_ext, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))])
        _logger.info("Mounted Integrations router (wave-6)")
    except ImportError:
        pass

    # Webhooks (suite-integrations/api/)
    try:
        from api.webhooks_router import router as webhooks_router  # noqa: PLC0415
        app.include_router(webhooks_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))])
        _logger.info("Mounted Webhooks router (wave-6)")
    except ImportError:
        pass

    # IaC (suite-integrations/api/)
    try:
        from api.iac_router import router as iac_router  # noqa: PLC0415
        app.include_router(iac_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))])
        _logger.info("Mounted IaC router (wave-6)")
    except ImportError:
        pass

    # IDE (suite-integrations/api/)
    try:
        from api.ide_router import router as ide_router  # noqa: PLC0415
        app.include_router(ide_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))])
        _logger.info("Mounted IDE router (wave-6)")
    except ImportError:
        pass

    # SIEM (suite-integrations/api/)
    try:
        from api.siem_router import router as siem_router  # noqa: PLC0415
        app.include_router(siem_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))])
        _logger.info("Mounted SIEM router (wave-6)")
    except ImportError:
        pass

    # _extra_apps_routers Platform entries

    # Analytics Dashboard (apps/api/)
    try:
        from apps.api.analytics_dashboard_router import (
            router as analytics_dashboard_router,  # noqa: PLC0415
        )
        app.include_router(analytics_dashboard_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Analytics Dashboard router (wave-6)")
    except ImportError:
        pass

    # Analytics Routes (apps/api/)
    try:
        from apps.api.analytics_routes import (
            router as analytics_routes_router,  # noqa: PLC0415
        )
        app.include_router(analytics_routes_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Analytics Routes router (wave-6)")
    except ImportError:
        pass

    # API Key Management (apps/api/)
    try:
        from apps.api.apikey_router import router as apikey_router  # noqa: PLC0415
        app.include_router(apikey_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted API Key Management router (wave-6)")
    except ImportError:
        pass

    # Backup (apps/api/)
    try:
        from apps.api.backup_router import router as backup_router  # noqa: PLC0415
        app.include_router(backup_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted Backup router (wave-6)")
    except ImportError:
        pass

    # Backup DR Validator (apps/api/)
    try:
        from apps.api.backup_validator_router import (
            router as backup_validator_router,  # noqa: PLC0415
        )
        app.include_router(backup_validator_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted Backup DR Validator router (wave-6)")
    except ImportError:
        pass

    # Changelog (apps/api/)
    try:
        from apps.api.changelog_router import (
            router as changelog_router,  # noqa: PLC0415
        )
        app.include_router(changelog_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Changelog router (wave-6)")
    except ImportError:
        pass

    # Dashboard Builder (apps/api/)
    try:
        from apps.api.dashboard_builder_router import (
            router as dashboard_builder_router,  # noqa: PLC0415
        )
        app.include_router(dashboard_builder_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Dashboard Builder router (wave-6)")
    except ImportError:
        pass

    # Developer Portal (apps/api/)
    try:
        from apps.api.developer_portal_router import (
            router as developer_portal_router,  # noqa: PLC0415
        )
        app.include_router(developer_portal_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Developer Portal router (wave-6)")
    except ImportError:
        pass

    # API Docs (apps/api/)
    try:
        from apps.api.api_docs_router import router as api_docs_router  # noqa: PLC0415
        app.include_router(api_docs_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted API Docs router (wave-6)")
    except ImportError:
        pass

    # Drift (apps/api/)
    try:
        from apps.api.drift_router import router as drift_router  # noqa: PLC0415
        app.include_router(drift_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Drift router (wave-6)")
    except ImportError:
        pass

    # Feed Registry (apps/api/)
    try:
        from apps.api.feed_registry_router import (
            router as feed_registry_router,  # noqa: PLC0415
        )
        app.include_router(feed_registry_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:feeds"))])
        _logger.info("Mounted Feed Registry router (wave-6)")
    except ImportError:
        pass

    # Feed Manager (apps/api/)
    try:
        from apps.api.feed_manager_router import (
            router as feed_manager_router,  # noqa: PLC0415
        )
        app.include_router(feed_manager_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:feeds"))])
        _logger.info("Mounted Feed Manager router (wave-6)")
    except ImportError:
        pass

    # Integration Health (apps/api/)
    try:
        from apps.api.integration_health_router import (
            router as integration_health_router,  # noqa: PLC0415
        )
        app.include_router(integration_health_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Integration Health router (wave-6)")
    except ImportError:
        pass

    # Metrics Aggregator (apps/api/)
    try:
        from apps.api.metrics_aggregator_router import (
            router as metrics_aggregator_router,  # noqa: PLC0415
        )
        app.include_router(metrics_aggregator_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Metrics Aggregator router (wave-6)")
    except ImportError:
        pass

    # Notifications (apps/api/)
    try:
        from apps.api.notification_router import (
            router as notification_router,  # noqa: PLC0415
        )
        app.include_router(notification_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Notifications router (wave-6)")
    except ImportError:
        pass

    # Posture (apps/api/)
    try:
        from apps.api.posture_router import router as posture_router  # noqa: PLC0415
        app.include_router(posture_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Posture router (wave-6)")
    except ImportError:
        pass

    # Posture Benchmark (apps/api/)
    try:
        from apps.api.posture_benchmark_router import (
            router as posture_benchmark_router,  # noqa: PLC0415
        )
        app.include_router(posture_benchmark_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Posture Benchmark router (wave-6)")
    except ImportError:
        pass

    # RASP (apps/api/)
    try:
        from apps.api.rasp_router import router as rasp_router  # noqa: PLC0415
        app.include_router(rasp_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted RASP router (wave-6)")
    except ImportError:
        pass

    # Runtime Protection (apps/api/)
    try:
        from apps.api.runtime_protection_router import (
            router as runtime_protection_router,  # noqa: PLC0415
        )
        app.include_router(runtime_protection_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Runtime Protection router (wave-6)")
    except ImportError:
        pass

    # Prioritizer (apps/api/)
    try:
        from apps.api.prioritizer_router import (
            router as prioritizer_router,  # noqa: PLC0415
        )
        app.include_router(prioritizer_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Prioritizer router (wave-6)")
    except ImportError:
        pass

    # Rate Limits (apps/api/)
    try:
        from apps.api.rate_limit_router import (
            router as rate_limit_router,  # noqa: PLC0415
        )
        app.include_router(rate_limit_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted Rate Limits router (wave-6)")
    except ImportError:
        pass

    # Tenant Rate Limiter (apps/api/)
    try:
        from apps.api.tenant_rate_limiter_router import (
            router as tenant_rate_limiter_router,  # noqa: PLC0415
        )
        app.include_router(tenant_rate_limiter_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted Tenant Rate Limiter router (wave-6)")
    except ImportError:
        pass

    # Retention (apps/api/)
    try:
        from apps.api.retention_router import (
            router as retention_router,  # noqa: PLC0415
        )
        app.include_router(retention_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted Retention router (wave-6)")
    except ImportError:
        pass

    # Slack Bot (apps/api/)
    try:
        from apps.api.slack_bot_router import (
            router as slack_bot_router,  # noqa: PLC0415
        )
        app.include_router(slack_bot_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))])
        _logger.info("Mounted Slack Bot router (wave-6)")
    except ImportError:
        pass

    # System Health (apps/api/)
    try:
        from apps.api.system_health_router import (
            router as system_health_router,  # noqa: PLC0415
        )
        app.include_router(system_health_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])
        _logger.info("Mounted System Health router (wave-6)")
    except ImportError:
        pass

    # Tags (apps/api/)
    try:
        from apps.api.tag_router import router as tag_router  # noqa: PLC0415
        app.include_router(tag_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Tags router (wave-6)")
    except ImportError:
        pass

    # User Analytics (apps/api/)
    try:
        from apps.api.user_analytics_router import (
            router as user_analytics_router,  # noqa: PLC0415
        )
        app.include_router(user_analytics_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted User Analytics router (wave-6)")
    except ImportError:
        pass

    # Versioning (apps/api/)
    try:
        from apps.api.versioning_router import (
            router as versioning_router,  # noqa: PLC0415
        )
        app.include_router(versioning_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Versioning router (wave-6)")
    except ImportError:
        pass

    # Webhook Events (apps/api/)
    try:
        from apps.api.webhook_events_router import (
            router as webhook_events_router,  # noqa: PLC0415
        )
        app.include_router(webhook_events_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Webhook Events router (wave-6)")
    except ImportError:
        pass

    # Workflow Engine (apps/api/)
    try:
        from apps.api.workflow_engine_router import (
            router as workflow_engine_router,  # noqa: PLC0415
        )
        app.include_router(workflow_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Workflow Engine router (wave-6)")
    except ImportError:
        pass

    # GraphRAG (apps/api/)
    try:
        from apps.api.graphrag_router import router as graphrag_router  # noqa: PLC0415
        app.include_router(graphrag_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted GraphRAG router (wave-6)")
    except ImportError:
        pass

    # DuckDB Analytics (apps/api/)
    try:
        from apps.api.duckdb_analytics_router import (
            router as duckdb_analytics_router,  # noqa: PLC0415
        )
        app.include_router(duckdb_analytics_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted DuckDB Analytics router (wave-6)")
    except ImportError:
        pass

    _logger.info("Platform sub-app: wave-6 loop-bound routers registered")

    # ------------------------------------------------------------------
    # Wave-7: Live connector routers (PAM / MDM / SSPM / SOAR / EDR)
    # 11 routers: CrowdStrike-live, Defender-XDR-live, Okta-live,
    # Jamf-live, Vault-live, CyberArk-live, Intune-live,
    # WorkspaceOne-live, AppOmni-live, AdaptiveShield-live, SplunkSOAR-live
    # ------------------------------------------------------------------
    try:
        from apps.api.crowdstrike_live_connector_router import (
            router as crowdstrike_live_router,  # noqa: PLC0415
        )
        app.include_router(crowdstrike_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted CrowdStrike live connector router (wave-7)")
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # CrowdStrike Falcon EDR Live REST — 2026-05-04
    # GET  /api/v1/falcon/                                 capability summary  (read:scans)
    # GET  /api/v1/falcon/detects/queries/detects          list detection ids  (read:scans)
    # POST /api/v1/falcon/detects/entities/summaries       fetch detail        (read:scans)
    # GET  /api/v1/falcon/incidents/queries/incidents      list incidents      (read:scans)
    # GET  /api/v1/falcon/iocs/queries/indicators          list IoCs           (read:scans)
    # POST /api/v1/falcon/iocs/entities/indicators         submit IoCs         (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.falcon_router import router as falcon_router  # noqa: PLC0415
        app.include_router(
            falcon_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted CrowdStrike Falcon live REST router (read:scans)")
    except ImportError as exc:
        _logger.warning("falcon_router not available: %s", exc)

    # ------------------------------------------------------------------
    # SentinelOne Singularity EDR Live REST — 2026-05-04
    # GET  /api/v1/sentinelone/                                       capability summary  (read:scans)
    # GET  /api/v1/sentinelone/web/api/v2.1/agents                    list agents          (read:scans)
    # GET  /api/v1/sentinelone/web/api/v2.1/threats                   list threats         (read:scans)
    # GET  /api/v1/sentinelone/web/api/v2.1/sites                     list sites           (read:scans)
    # GET  /api/v1/sentinelone/web/api/v2.1/groups                    list groups          (read:scans)
    # POST /api/v1/sentinelone/web/api/v2.1/threats/mitigate/{action} mitigate threats     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.sentinelone_router import router as sentinelone_router  # noqa: PLC0415
        app.include_router(
            sentinelone_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted SentinelOne EDR live REST router (read:scans)")
    except ImportError as exc:
        _logger.warning("sentinelone_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Tanium Endpoint Platform Live REST — 2026-05-04
    # GET  /api/v1/tanium/                                  capability summary  (read:scans)
    # POST /api/v1/tanium/api/v2/sessions                   open session        (read:scans)
    # GET  /api/v1/tanium/api/v2/system_status              cluster health      (read:scans)
    # POST /api/v1/tanium/api/v2/parse_question             NLP parser          (read:scans)
    # POST /api/v1/tanium/api/v2/questions                  issue question      (read:scans)
    # GET  /api/v1/tanium/api/v2/result_data                fetch results       (read:scans)
    # GET  /api/v1/tanium/api/v2/sensors                    list sensors        (read:scans)
    # GET  /api/v1/tanium/api/v2/saved_questions            saved-questions     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.tanium_router import router as tanium_router  # noqa: PLC0415
        app.include_router(
            tanium_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Tanium endpoint platform live REST router (read:scans)")
    except ImportError as exc:
        _logger.warning("tanium_router not available: %s", exc)

    try:
        from apps.api.defender_xdr_live_connector_router import (
            router as defender_xdr_live_router,  # noqa: PLC0415
        )
        app.include_router(defender_xdr_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Defender XDR live connector router (wave-7)")
    except ImportError:
        pass

    try:
        from apps.api.okta_live_connector_router import (
            router as okta_live_router,  # noqa: PLC0415
        )
        app.include_router(okta_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Okta live connector router (wave-7)")
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # Okta IAM Live REST — 2026-05-04
    # GET  /api/v1/okta/                                  capability summary  (read:scans)
    # GET  /api/v1/okta/api/v1/users                      list users          (read:scans)
    # GET  /api/v1/okta/api/v1/groups                     list groups         (read:scans)
    # GET  /api/v1/okta/api/v1/apps                       list applications   (read:scans)
    # GET  /api/v1/okta/api/v1/logs                       System Log events   (read:scans)
    # GET  /api/v1/okta/api/v1/sessions/{session_id}      fetch session       (read:scans)
    # POST /api/v1/okta/api/v1/sessions/me/lifecycle/refresh  refresh session (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.okta_router import router as okta_router  # noqa: PLC0415
        app.include_router(
            okta_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Okta IAM live REST router (read:scans)")
    except ImportError as exc:
        _logger.warning("okta_router not available: %s", exc)

    # ------------------------------------------------------------------
    # SailPoint IdentityNow IGA Live REST — 2026-05-04
    # GET /api/v1/sailpoint-iga/                                                       capability summary       (read:scans)
    # GET /api/v1/sailpoint-iga/v3/identities                                          list identities          (read:scans)
    # GET /api/v1/sailpoint-iga/v3/identities/{identity_id}                            single identity          (read:scans)
    # GET /api/v1/sailpoint-iga/v3/identities/{identity_id}/account-summary            identity accounts        (read:scans)
    # GET /api/v1/sailpoint-iga/v3/access-profiles                                     list access profiles     (read:scans)
    # GET /api/v1/sailpoint-iga/v3/roles                                               list roles               (read:scans)
    # GET /api/v1/sailpoint-iga/v3/certification-campaigns                             list campaigns           (read:scans)
    # GET /api/v1/sailpoint-iga/v3/access-requests                                     list access requests     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.sailpoint_iga_router import router as sailpoint_iga_router  # noqa: PLC0415
        app.include_router(
            sailpoint_iga_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted SailPoint IdentityNow IGA live REST router (read:scans)")
    except ImportError as exc:
        _logger.warning("sailpoint_iga_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Cloudflare API v4 Live REST — 2026-05-04
    # GET /api/v1/cloudflare/                                                              capability summary  (read:scans)
    # GET /api/v1/cloudflare/client/v4/zones                                               list zones          (read:scans)
    # GET /api/v1/cloudflare/client/v4/zones/{zone_id}                                     single zone         (read:scans)
    # GET /api/v1/cloudflare/client/v4/zones/{zone_id}/dns_records                         DNS records         (read:scans)
    # GET /api/v1/cloudflare/client/v4/zones/{zone_id}/firewall/rules                      firewall rules      (read:scans)
    # GET /api/v1/cloudflare/client/v4/zones/{zone_id}/waf/packages                        WAF packages        (read:scans)
    # GET /api/v1/cloudflare/client/v4/zones/{zone_id}/security_events                     security events     (read:scans)
    # GET /api/v1/cloudflare/client/v4/accounts/{account_id}/access/groups                 access groups       (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.cloudflare_router import router as cloudflare_router  # noqa: PLC0415
        app.include_router(
            cloudflare_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Cloudflare API v4 live REST router (read:scans)")
    except ImportError as exc:
        _logger.warning("cloudflare_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Netskope CASB Live REST — 2026-05-04
    # GET  /api/v1/netskope/                                                              capability summary       (read:scans)
    # GET  /api/v1/netskope/api/v2/events/data/page                                       alerts/events page       (read:scans)
    # GET  /api/v1/netskope/api/v2/events/data/incidents                                  DLP incidents            (read:scans)
    # GET  /api/v1/netskope/api/v2/scim/Users                                             SCIM v2 user directory   (read:scans)
    # GET  /api/v1/netskope/api/v2/policy/url/list                                        URL policy lists         (read:scans)
    # GET  /api/v1/netskope/api/v2/services/operational/uci                               UCI series               (read:scans)
    # POST /api/v1/netskope/api/v2/incidents/uba/getuci                                   per-user UCI detail      (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.netskope_router import router as netskope_router  # noqa: PLC0415
        app.include_router(
            netskope_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Netskope CASB live REST router (read:scans)")
    except ImportError as exc:
        _logger.warning("netskope_router not available: %s", exc)

    try:
        from apps.api.jamf_live_connector_router import (
            router as jamf_live_router,  # noqa: PLC0415
        )
        app.include_router(jamf_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Jamf live connector router (wave-7)")
    except ImportError:
        pass

    try:
        from apps.api.vault_live_connector_router import (
            router as vault_live_router,  # noqa: PLC0415
        )
        app.include_router(vault_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted HashiCorp Vault live connector router (wave-7)")
    except ImportError:
        pass

    try:
        from apps.api.cyberark_live_connector_router import (
            router as cyberark_live_router,  # noqa: PLC0415
        )
        app.include_router(cyberark_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted CyberArk live connector router (wave-7)")
    except ImportError:
        pass

    try:
        from apps.api.intune_live_connector_router import (
            router as intune_live_router,  # noqa: PLC0415
        )
        app.include_router(intune_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Microsoft Intune live connector router (wave-7)")
    except ImportError:
        pass

    try:
        from apps.api.workspace_one_live_connector_router import (
            router as workspace_one_live_router,  # noqa: PLC0415
        )
        app.include_router(workspace_one_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted VMware Workspace ONE live connector router (wave-7)")
    except ImportError:
        pass

    try:
        from apps.api.appomni_live_connector_router import (
            router as appomni_live_router,  # noqa: PLC0415
        )
        app.include_router(appomni_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted AppOmni live connector router (wave-7)")
    except ImportError:
        pass

    try:
        from apps.api.adaptive_shield_live_connector_router import (
            router as adaptive_shield_live_router,  # noqa: PLC0415
        )
        app.include_router(adaptive_shield_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Adaptive Shield live connector router (wave-7)")
    except ImportError:
        pass

    try:
        from apps.api.splunk_soar_live_connector_router import (
            router as splunk_soar_live_router,  # noqa: PLC0415
        )
        app.include_router(splunk_soar_live_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Splunk SOAR live connector router (wave-7)")
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # Splunk SIEM router (suite-core/core/splunk_siem_engine.py)
    # GET    /api/v1/splunk/                                        capability summary
    # POST   /api/v1/splunk/services/search/jobs                    create search job
    # GET    /api/v1/splunk/services/search/jobs/{sid}              job metadata
    # GET    /api/v1/splunk/services/search/jobs/{sid}/results      results page
    # DELETE /api/v1/splunk/services/search/jobs/{sid}              cancel job
    # GET    /api/v1/splunk/services/saved/searches                 list saved searches
    # POST   /api/v1/splunk/services/saved/searches/{name}/dispatch dispatch saved search
    # Scope: read:scans
    # ------------------------------------------------------------------
    try:
        from apps.api.splunk_router import router as splunk_router  # noqa: PLC0415
        app.include_router(
            splunk_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Splunk SIEM router (read:scans)")
    except ImportError as exc:
        _logger.warning("splunk_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Sumo Logic Cloud SIEM router (suite-core/core/sumologic_siem_engine.py)
    # GET    /api/v1/sumologic/                                                capability summary
    # POST   /api/v1/sumologic/api/v1/search/jobs                              create search job
    # GET    /api/v1/sumologic/api/v1/search/jobs/{job_id}                     job state
    # GET    /api/v1/sumologic/api/v1/search/jobs/{job_id}/messages            messages page
    # GET    /api/v1/sumologic/api/v1/search/jobs/{job_id}/records             records page
    # DELETE /api/v1/sumologic/api/v1/search/jobs/{job_id}                     cancel job
    # GET    /api/v1/sumologic/api/v1/dashboards                               list dashboards
    # GET    /api/v1/sumologic/api/v1/collectors                               list collectors
    # GET    /api/v1/sumologic/api/v1/collectors/{cid}/sources                 nested sources
    # GET    /api/v1/sumologic/api/sec/v1/insights                             Cloud SIEM insights
    # GET    /api/v1/sumologic/api/v1/health-events                            health events
    # Scope: read:scans
    # ------------------------------------------------------------------
    try:
        from apps.api.sumologic_router import router as sumologic_router  # noqa: PLC0415
        app.include_router(
            sumologic_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Sumo Logic Cloud SIEM router (read:scans)")
    except ImportError as exc:
        _logger.warning("sumologic_router not available: %s", exc)

    _logger.info("Platform sub-app: wave-7 live connector routers registered (11 connectors)")

    # ------------------------------------------------------------------
    # ZAP DAST scan router (suite-core/core/zap_scan_engine.py)
    # Scopes: read:scan / write:scan
    # ------------------------------------------------------------------
    try:
        from apps.api.zap_scan_router import router as zap_scan_router  # noqa: PLC0415
        app.include_router(
            zap_scan_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scan")),
            ],
        )
        _logger.info("Mounted ZAP DAST scan router (read:scan / write:scan)")
    except ImportError as exc:
        _logger.warning("zap_scan_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Syft SBOM generation router (read:scan + write:scan)
    # ------------------------------------------------------------------
    try:
        from apps.api.syft_router import router as syft_router  # noqa: PLC0415

        app.include_router(
            syft_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scan")),
                Depends(_require_scope("write:scan")),
            ],
        )
        _logger.info("Mounted Syft SBOM router (read:scan/write:scan)")
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # Semgrep SAST Scanner (async-queue, durable SQLite) — 2026-05-04
    # GET  /api/v1/semgrep/                 capability summary  (read:scans)
    # GET  /api/v1/semgrep/rule-packs       rule pack catalog   (read:scans)
    # POST /api/v1/semgrep/scan             queue a new scan    (read:scans)
    # GET  /api/v1/semgrep/scan/{scan_id}   fetch scan record   (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.semgrep_scan_router import router as semgrep_scan_router  # noqa: PLC0415
        app.include_router(
            semgrep_scan_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Semgrep SAST scanner router (read:scans)")
    except ImportError as exc:
        _logger.warning("semgrep_scan_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Grype Vulnerability Scanner (image / sbom / dir) — 2026-05-04
    # GET /api/v1/grype/                  capability summary  (read:scan)
    # POST /api/v1/grype/scan             queue a new scan    (write:scan)
    # GET /api/v1/grype/scan/{scan_id}    fetch scan record   (read:scan)
    # ------------------------------------------------------------------
    try:
        from apps.api.grype_router import router as grype_router  # noqa: PLC0415
        app.include_router(
            grype_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scan")),
            ],
        )
        _logger.info("Mounted Grype vulnerability scanner router")
    except ImportError as exc:
        _logger.warning("grype_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Checkov IaC Scanner (14 frameworks) — 2026-05-04
    # GET  /api/v1/checkov/                  capability summary  (read:scan)
    # GET  /api/v1/checkov/frameworks        framework catalog   (read:scan)
    # POST /api/v1/checkov/scan              queue a new scan    (read:scan)
    # GET  /api/v1/checkov/scan/{scan_id}    fetch scan record   (read:scan)
    # ------------------------------------------------------------------
    try:
        from apps.api.checkov_router import router as checkov_router  # noqa: PLC0415
        app.include_router(
            checkov_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scan")),
            ],
        )
        _logger.info("Mounted Checkov IaC scanner router")
    except ImportError as exc:
        _logger.warning("checkov_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Gitleaks Secret-Detection Scanner (12+ default rules) — 2026-05-04
    # GET  /api/v1/gitleaks/                  capability summary  (read:scans)
    # GET  /api/v1/gitleaks/rules             rule catalog        (read:scans)
    # POST /api/v1/gitleaks/scan              queue a new scan    (read:scans)
    # GET  /api/v1/gitleaks/scan/{scan_id}    fetch scan record   (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.gitleaks_router import router as gitleaks_router  # noqa: PLC0415
        app.include_router(
            gitleaks_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Gitleaks secret-detection router (read:scans)")
    except ImportError as exc:
        _logger.warning("gitleaks_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Shodan Threat-Intel Lookup — 2026-05-04
    # GET /api/v1/shodan/                       capability summary  (read:scans)
    # GET /api/v1/shodan/host/{ip}              host enrichment    (read:scans)
    # GET /api/v1/shodan/search                 search query       (read:scans)
    # GET /api/v1/shodan/honeyscore/{ip}        honeypot score     (read:scans)
    # GET /api/v1/shodan/count                  count + facets     (read:scans)
    # GET /api/v1/shodan/dns/resolve            hostname → IP map  (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.shodan_router import router as shodan_router  # noqa: PLC0415
        app.include_router(
            shodan_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Shodan threat-intel router (read:scans)")
    except ImportError as exc:
        _logger.warning("shodan_router not available: %s", exc)

    # ------------------------------------------------------------------
    # VirusTotal v3 Threat-Intel Lookup — 2026-05-04
    # GET /api/v1/virustotal/                            capability summary  (read:scans)
    # GET /api/v1/virustotal/v3/files/{hash}             file enrichment    (read:scans)
    # GET /api/v1/virustotal/v3/urls/{url_id}            URL analysis       (read:scans)
    # GET /api/v1/virustotal/v3/domains/{domain}         domain enrichment  (read:scans)
    # GET /api/v1/virustotal/v3/ip_addresses/{ip}        IP enrichment      (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.virustotal_router import router as virustotal_router  # noqa: PLC0415
        app.include_router(
            virustotal_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted VirusTotal threat-intel router (read:scans)")
    except ImportError as exc:
        _logger.warning("virustotal_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Censys Threat-Intel Lookup — 2026-05-04
    # GET /api/v1/censys/                                  capability summary  (read:scans)
    # GET /api/v1/censys/v2/hosts/{ip}                     host enrichment    (read:scans)
    # GET /api/v1/censys/v2/certificates/{fingerprint}     certificate detail (read:scans)
    # GET /api/v1/censys/v2/hosts/search                   host search        (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.censys_router import router as censys_router  # noqa: PLC0415
        app.include_router(
            censys_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Censys threat-intel router (read:scans)")
    except ImportError as exc:
        _logger.warning("censys_router not available: %s", exc)

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # ThousandEyes Network Intelligence (v6 REST API) — 2026-05-04
    # GET  /api/v1/thousandeyes/                              capability summary       (read:scans)
    # GET  /api/v1/thousandeyes/v6/tests.json                 list tests               (read:scans)
    # GET  /api/v1/thousandeyes/v6/tests/{test_id}.json       single test detail       (read:scans)
    # GET  /api/v1/thousandeyes/v6/agents.json                list agents              (read:scans)
    # GET  /api/v1/thousandeyes/v6/alerts.json                list alerts in window    (read:scans)
    # GET  /api/v1/thousandeyes/v6/web/page-load.json         page-load test results   (read:scans)
    # GET  /api/v1/thousandeyes/v6/net/metrics.json           network-layer metrics    (read:scans)
    # GET  /api/v1/thousandeyes/v6/dns/server-metrics.json    DNS server metrics       (read:scans)
    # GET  /api/v1/thousandeyes/v6/bgp/metrics.json           BGP metrics              (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.thousandeyes_router import router as thousandeyes_router  # noqa: PLC0415
        app.include_router(
            thousandeyes_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted ThousandEyes network-intelligence router (read:scans)")
    except ImportError as exc:
        _logger.warning("thousandeyes_router not available: %s", exc)

    # AbuseIPDB Threat-Intel Lookup (v2 surface) — 2026-05-04
    # GET  /api/v1/abuseipdb/                              capability summary  (read:scans)
    # GET  /api/v1/abuseipdb/v2/check                      IP reputation       (read:scans)
    # GET  /api/v1/abuseipdb/v2/blacklist                  top-N abusive IPs   (read:scans)
    # POST /api/v1/abuseipdb/v2/report                     submit abuse report (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.abuseipdb_router import router as abuseipdb_router  # noqa: PLC0415
        app.include_router(
            abuseipdb_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted AbuseIPDB threat-intel router (read:scans)")
    except ImportError as exc:
        _logger.warning("abuseipdb_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Braintrust LLM-eval (experiments / datasets / projects / scores) — 2026-05-04
    # GET  /api/v1/braintrust/                            capability summary  (read:scans)
    # GET  /api/v1/braintrust/v1/experiment               list experiments    (read:scans)
    # GET  /api/v1/braintrust/v1/experiment/{exp_id}      single experiment   (read:scans)
    # POST /api/v1/braintrust/v1/experiment               create experiment   (read:scans)
    # POST /api/v1/braintrust/v1/experiment/{id}/insert   append events       (read:scans)
    # GET  /api/v1/braintrust/v1/dataset                  list datasets       (read:scans)
    # GET  /api/v1/braintrust/v1/dataset/{ds_id}          single dataset      (read:scans)
    # POST /api/v1/braintrust/v1/dataset/{ds_id}/insert   append dataset rows (read:scans)
    # GET  /api/v1/braintrust/v1/project                  list projects       (read:scans)
    # GET  /api/v1/braintrust/v1/score                    list scoring fns    (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.braintrust_router import router as braintrust_router  # noqa: PLC0415
        app.include_router(
            braintrust_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Braintrust LLM-eval router (read:scans)")
    except ImportError as exc:
        _logger.warning("braintrust_router not available: %s", exc)

    # ------------------------------------------------------------------
    # JupiterOne Asset Graph (GraphQL/J1QL + Sync + Alerts + Integrations) - 2026-05-04
    # GET  /api/v1/jupiterone/                                           capability summary  (read:scans)
    # POST /api/v1/jupiterone/graphql                                    J1QL graphql query  (read:scans)
    # GET  /api/v1/jupiterone/persister/synchronization/jobs             list sync jobs      (read:scans)
    # POST /api/v1/jupiterone/persister/synchronization/jobs             create sync job     (read:scans)
    # POST /api/v1/jupiterone/persister/synchronization/jobs/{id}/upload upload entities     (read:scans)
    # POST /api/v1/jupiterone/persister/synchronization/jobs/{id}/finalize finalize sync     (read:scans)
    # GET  /api/v1/jupiterone/alerts                                     list alerts         (read:scans)
    # GET  /api/v1/jupiterone/alerts/{instance_id}                       single alert detail (read:scans)
    # POST /api/v1/jupiterone/alerts/{instance_id}/dismiss               dismiss alert       (read:scans)
    # POST /api/v1/jupiterone/alerts/{instance_id}/snooze                snooze alert        (read:scans)
    # GET  /api/v1/jupiterone/accounts/{account_id}/integrations         list integrations   (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.jupiterone_router import router as jupiterone_router  # noqa: PLC0415
        app.include_router(
            jupiterone_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted JupiterOne asset graph router (read:scans)")
    except ImportError as exc:
        _logger.warning("jupiterone_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Imperva Cloud WAF (Provisioning v1 + Modern v3 + Incidents v1) - 2026-05-04
    # GET  /api/v1/imperva/                                     capability summary  (read:scans)
    # POST /api/v1/imperva/api/prov/v1/sites/list               list managed sites  (read:scans)
    # POST /api/v1/imperva/api/prov/v1/sites/status             one site status     (read:scans)
    # POST /api/v1/imperva/api/prov/v1/sites/configure/security set WAF rule action (read:scans)
    # GET  /api/v1/imperva/api/v3/policies                      list policies (v3)  (read:scans)
    # GET  /api/v1/imperva/api/v3/sites/{site_id}               site detail (v3)    (read:scans)
    # GET  /api/v1/imperva/api/incidents/v1/incidents           list incidents      (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.imperva_router import router as imperva_router  # noqa: PLC0415
        app.include_router(
            imperva_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Imperva Cloud WAF router (read:scans)")
    except ImportError as exc:
        _logger.warning("imperva_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Mimecast Email Security (TTP URL decode + Gateway hold + Threat-Intel
    #   feed + SIEM logs + Managed senders + Anti-spoofing policy) - 2026-05-04
    # GET  /api/v1/mimecast/                                          capability summary  (read:scans)
    # POST /api/v1/mimecast/api/ttp/url/decode-url                    decode rewritten URLs (read:scans)
    # POST /api/v1/mimecast/api/gateway/get-hold-message-list         list held messages   (read:scans)
    # POST /api/v1/mimecast/api/gateway/release-hold-message          release held messages (read:scans)
    # POST /api/v1/mimecast/api/ttp/threat-intel/get-feed             pull threat-intel feed (read:scans)
    # POST /api/v1/mimecast/api/audit/get-siem-logs                   pull SIEM audit logs (read:scans)
    # POST /api/v1/mimecast/api/managedsender/get-managed-senders     list managed senders (read:scans)
    # POST /api/v1/mimecast/api/policy/anti-spoofing/get-policy       list anti-spoofing policies (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.mimecast_router import router as mimecast_router  # noqa: PLC0415
        app.include_router(
            mimecast_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Mimecast Email Security router (read:scans)")
    except ImportError as exc:
        _logger.warning("mimecast_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Duo Security MFA (Auth v2 + Admin v1) - 2026-05-04
    # GET  /api/v1/duo/                              capability summary    (read:scans)
    # POST /api/v1/duo/auth/v2/preauth               enrollment + factors  (read:scans)
    # POST /api/v1/duo/auth/v2/auth                  issue auth challenge  (read:scans)
    # GET  /api/v1/duo/auth/v2/auth_status           poll async tx         (read:scans)
    # GET  /api/v1/duo/auth/v2/check                 signature/time check  (read:scans)
    # GET  /api/v1/duo/admin/v1/users                list users            (read:scans)
    # GET  /api/v1/duo/admin/v1/integrations         list integrations     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.duo_router import router as duo_router  # noqa: PLC0415
        app.include_router(
            duo_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Duo Security MFA router (read:scans)")
    except ImportError as exc:
        _logger.warning("duo_router not available: %s", exc)

    # ------------------------------------------------------------------
    # GCP Security Command Center (real OAuth2 + read-only) — 2026-05-04
    # GET  /api/v1/gcp-scc/                         capability summary    (read:scans)
    # GET  /api/v1/gcp-scc/findings                 list findings         (read:scans)
    # GET  /api/v1/gcp-scc/sources                  list sources          (read:scans)
    # GET  /api/v1/gcp-scc/assets                   list assets           (read:scans)
    # GET  /api/v1/gcp-scc/findings/group           groupBy aggregate     (read:scans)
    # POST /api/v1/gcp-scc/findings/{name}:setMute  mute toggle           (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.gcp_scc_router import router as gcp_scc_router  # noqa: PLC0415
        app.include_router(
            gcp_scc_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted GCP SCC router (read:scans)")
    except ImportError as exc:
        _logger.warning("gcp_scc_router not available: %s", exc)

    # ------------------------------------------------------------------
    # GCP GKE — Google Kubernetes Engine v1 (real OAuth2 + read-only) — 2026-05-04
    # GET  /api/v1/gcp-gke/                                                          capability summary  (read:scans)
    # GET  /api/v1/gcp-gke/v1/projects/{p}/locations/{loc}/clusters                  list clusters       (read:scans)
    # GET  /api/v1/gcp-gke/v1/projects/{p}/locations/{loc}/clusters/{c}              single cluster      (read:scans)
    # GET  /api/v1/gcp-gke/v1/projects/{p}/locations/{loc}/clusters/{c}/nodePools    list node pools     (read:scans)
    # POST /api/v1/gcp-gke/v1/projects/{p}/locations/{loc}/clusters/{c}:getJwks      cluster JWKs        (read:scans)
    # GET  /api/v1/gcp-gke/v1/projects/{p}/locations/{loc}/operations                list operations     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.gcp_gke_router import router as gcp_gke_router  # noqa: PLC0415
        app.include_router(
            gcp_gke_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted GCP GKE router (read:scans)")
    except ImportError as exc:
        _logger.warning("gcp_gke_router not available: %s", exc)

    # ------------------------------------------------------------------
    # HashiCorp Vault (real HTTP API + read-only/KV-v2 write) — 2026-05-04
    # GET  /api/v1/hashicorp-vault/                              capability summary  (read:scans)
    # GET  /api/v1/hashicorp-vault/v1/sys/health                 vault health        (read:scans)
    # GET  /api/v1/hashicorp-vault/v1/sys/seal-status            seal status         (read:scans)
    # GET  /api/v1/hashicorp-vault/v1/secret/data/{path}         KV v2 read          (read:scans)
    # POST /api/v1/hashicorp-vault/v1/secret/data/{path}         KV v2 write         (read:scans)
    # GET  /api/v1/hashicorp-vault/v1/sys/policies/acl           ACL policy list     (read:scans)
    # GET  /api/v1/hashicorp-vault/v1/sys/policies/acl/{name}    ACL policy read     (read:scans)
    # GET  /api/v1/hashicorp-vault/v1/sys/auth                   enabled auth        (read:scans)
    # GET  /api/v1/hashicorp-vault/v1/sys/mounts                 enabled mounts      (read:scans)
    # NOTE: distinct prefix from evidence_vault_router (ALDECI's own evidence vault)
    # ------------------------------------------------------------------
    try:
        from apps.api.hashicorp_vault_router import router as hashicorp_vault_router  # noqa: PLC0415
        app.include_router(
            hashicorp_vault_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted HashiCorp Vault router (read:scans)")
    except ImportError as exc:
        _logger.warning("hashicorp_vault_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Snyk Vulnerability Scanner (REST v1 surface) — 2026-05-04
    # GET  /api/v1/snyk/                                            capability summary  (read:scans)
    # GET  /api/v1/snyk/v1/orgs                                     organisations list  (read:scans)
    # GET  /api/v1/snyk/v1/orgs/{org}/projects                      project list        (read:scans)
    # POST /api/v1/snyk/v1/test/{ecosystem}/{file_path}             manifest test       (read:scans)
    # GET  /api/v1/snyk/v1/orgs/{org}/projects/{project}/issues     project issues      (read:scans)
    # GET  /api/v1/snyk/v1/reporting                                reporting status    (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.snyk_router import router as snyk_router  # noqa: PLC0415
        app.include_router(
            snyk_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Snyk vulnerability router (read:scans)")
    except ImportError as exc:
        _logger.warning("snyk_router not available: %s", exc)
    # ------------------------------------------------------------------
    # Pulumi Cloud (REST surface) — 2026-05-04
    # GET  /api/v1/pulumi/                                                  capability summary  (read:scans)
    # GET  /api/v1/pulumi/api/user                                          viewer + orgs       (read:scans)
    # GET  /api/v1/pulumi/api/orgs/{org}/stacks                             stacks list         (read:scans)
    # GET  /api/v1/pulumi/api/stacks/{org}/{project}/{stack}                stack detail        (read:scans)
    # GET  /api/v1/pulumi/api/stacks/{org}/{project}/{stack}/updates        updates list        (read:scans)
    # GET  /api/v1/pulumi/api/stacks/{org}/{project}/{stack}/updates/...    update detail       (read:scans)
    # GET  /api/v1/pulumi/api/stacks/{org}/{project}/{stack}/exports        state export        (read:scans)
    # GET  /api/v1/pulumi/api/orgs/{org}/policygroups                       policy groups       (read:scans)
    # GET  /api/v1/pulumi/api/orgs/{org}/policypacks                        policy packs        (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.pulumi_router import router as pulumi_router  # noqa: PLC0415
        app.include_router(
            pulumi_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Pulumi Cloud router (read:scans)")
    except ImportError as exc:
        _logger.warning("pulumi_router not available: %s", exc)



    # ------------------------------------------------------------------
    # 42Crunch API Security (Platform v2 surface) — 2026-05-04
    # GET  /api/v1/apicrunch/                                                       capability summary  (read:scans)
    # GET  /api/v1/apicrunch/api/v2/collections                                     list collections    (read:scans)
    # GET  /api/v1/apicrunch/api/v2/collections/{coll_id}                           single collection   (read:scans)
    # GET  /api/v1/apicrunch/api/v2/collections/{coll_id}/apis                      apis in collection  (read:scans)
    # GET  /api/v1/apicrunch/api/v2/apis/{api_id}                                   api descriptor      (read:scans)
    # GET  /api/v1/apicrunch/api/v2/apis/{api_id}/auditReport                       audit report        (read:scans)
    # POST /api/v1/apicrunch/api/v2/apis/{api_id}/scan                              trigger scan        (read:scans)
    # GET  /api/v1/apicrunch/api/v2/apis/{api_id}/scanReport                        latest scan report  (read:scans)
    # GET  /api/v1/apicrunch/api/v2/apis/{api_id}/scanReport/{scan_id}              scan report by id   (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.apicrunch_router import router as apicrunch_router  # noqa: PLC0415
        app.include_router(
            apicrunch_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted 42Crunch API security router (read:scans)")
    except ImportError as exc:
        _logger.warning("apicrunch_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Veracode SAST Scanner (REST AppSec v1/v2 surface) — 2026-05-04
    # GET  /api/v1/veracode/                                             capability summary  (read:scans)
    # GET  /api/v1/veracode/appsec/v1/applications                       application list    (read:scans)
    # GET  /api/v1/veracode/appsec/v1/applications/{guid}                single application  (read:scans)
    # GET  /api/v1/veracode/appsec/v2/applications/{guid}/findings       findings list       (read:scans)
    # GET  /api/v1/veracode/appsec/v1/findings/{id}/annotations          annotations         (read:scans)
    # GET  /api/v1/veracode/appsec/v1/policies                           policies list       (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.veracode_router import router as veracode_router  # noqa: PLC0415
        app.include_router(
            veracode_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Veracode SAST router (read:scans)")
    except ImportError as exc:
        _logger.warning("veracode_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Vanta Compliance (REST v1 surface) — 2026-05-04
    # GET  /api/v1/vanta/                                            capability summary  (read:scans)
    # GET  /api/v1/vanta/v1/controls                                 list controls       (read:scans)
    # GET  /api/v1/vanta/v1/controls/{control_id}                    single control      (read:scans)
    # GET  /api/v1/vanta/v1/controls/{control_id}/tests              control tests       (read:scans)
    # GET  /api/v1/vanta/v1/integrations                             integrations        (read:scans)
    # GET  /api/v1/vanta/v1/audits                                   audits              (read:scans)
    # GET  /api/v1/vanta/v1/people                                   people              (read:scans)
    # GET  /api/v1/vanta/v1/findings                                 findings            (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.vanta_router import router as vanta_router  # noqa: PLC0415
        app.include_router(
            vanta_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Vanta compliance router (read:scans)")
    except ImportError as exc:
        _logger.warning("vanta_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Drata Compliance (REST surface) — 2026-05-04
    # GET  /api/v1/drata/                                            capability summary  (read:scans)
    # GET  /api/v1/drata/api/controls                                list controls       (read:scans)
    # GET  /api/v1/drata/api/controls/{control_id}                   single control      (read:scans)
    # GET  /api/v1/drata/api/controls/{control_id}/tests             control tests       (read:scans)
    # GET  /api/v1/drata/api/integrations                            integrations        (read:scans)
    # GET  /api/v1/drata/api/audits                                  audits              (read:scans)
    # GET  /api/v1/drata/api/people                                  people              (read:scans)
    # GET  /api/v1/drata/api/findings                                findings            (read:scans)
    # GET  /api/v1/drata/api/policies                                policies            (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.drata_router import router as drata_router  # noqa: PLC0415
        app.include_router(
            drata_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Drata compliance router (read:scans)")
    except ImportError as exc:
        _logger.warning("drata_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Tenable.io Vulnerability Scanner — 2026-05-04
    # GET  /api/v1/tenable-io/                                              capability summary  (read:scans)
    # GET  /api/v1/tenable-io/scans                                          list scans         (read:scans)
    # GET  /api/v1/tenable-io/scans/{scan_id}                                scan detail        (read:scans)
    # GET  /api/v1/tenable-io/scans/{scan_id}/hosts/{host_id}                host detail        (read:scans)
    # GET  /api/v1/tenable-io/agents                                         agent inventory    (read:scans)
    # GET  /api/v1/tenable-io/policies                                       scan policies      (read:scans)
    # POST /api/v1/tenable-io/workbenches/vulnerabilities                    workbench query    (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.tenable_io_router import router as tenable_io_router  # noqa: PLC0415
        app.include_router(
            tenable_io_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Tenable.io vulnerability router (read:scans)")
    except ImportError as exc:
        _logger.warning("tenable_io_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Qualys VMDR Vulnerability + Compliance Scanner - 2026-05-04
    # GET  /api/v1/qualys/                                                       capability summary  (read:scans)
    # GET  /api/v1/qualys/api/2.0/fo/asset/host/?action=list                     host inventory      (read:scans)
    # GET  /api/v1/qualys/api/2.0/fo/asset/host/vm/detection/?action=list        host vuln detect    (read:scans)
    # GET  /api/v1/qualys/api/2.0/fo/scan/?action=list                           scan list           (read:scans)
    # POST /api/v1/qualys/api/2.0/fo/scan/?action=launch                         launch scan         (read:scans)
    # GET  /api/v1/qualys/api/2.0/fo/compliance/policy/?action=list              PC policy list      (read:scans)
    # GET  /api/v1/qualys/api/2.0/fo/report/?action=list                         report list         (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.qualys_router import router as qualys_router  # noqa: PLC0415
        app.include_router(
            qualys_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Qualys VMDR router (read:scans)")
    except ImportError as exc:
        _logger.warning("qualys_router not available: %s", exc)

    # ------------------------------------------------------------------
    # GreyNoise Threat-Intel Lookup — 2026-05-04
    # GET /api/v1/greynoise/                              capability summary  (read:scans)
    # GET /api/v1/greynoise/v3/community/{ip}              free-tier classification
    # GET /api/v1/greynoise/v2/noise/context/{ip}          paid context
    # GET /api/v1/greynoise/v2/riot/{ip}                   paid RIOT
    # ------------------------------------------------------------------
    try:
        from apps.api.greynoise_router import router as greynoise_router  # noqa: PLC0415
        app.include_router(
            greynoise_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted GreyNoise threat-intel router (read:scans)")
    except ImportError as exc:
        _logger.warning("greynoise_router not available: %s", exc)

    # ------------------------------------------------------------------
    # MISP Threat-Sharing Integration — 2026-05-04
    # GET  /api/v1/misp/                              capability summary
    # GET  /api/v1/misp/events                        paginated event list
    # GET  /api/v1/misp/events/{event_id}             single event view
    # POST /api/v1/misp/attributes/restSearch         flexible attribute search
    # GET  /api/v1/misp/feeds                         enabled feeds catalog
    # GET  /api/v1/misp/tags                          tag lookup
    # ------------------------------------------------------------------
    try:
        from apps.api.misp_router import router as misp_router  # noqa: PLC0415
        app.include_router(
            misp_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted MISP threat-sharing router (read:scans)")
    except ImportError as exc:
        _logger.warning("misp_router not available: %s", exc)



    # ------------------------------------------------------------------
    # Prometheus Alerts (in-memory rule catalog + PromQL-subset eval) — 2026-05-04
    # GET  /api/v1/prometheus/                 capability summary       (read:scans)
    # GET  /api/v1/prometheus/groups           rule groups + counts     (read:scans)
    # GET  /api/v1/prometheus/rules            full rule catalog        (read:scans)
    # GET  /api/v1/prometheus/rules/{rule_id}  single rule detail       (read:scans)
    # POST /api/v1/prometheus/alerts/test      evaluate against metrics (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.prometheus_alerts_router import router as prometheus_alerts_router  # noqa: PLC0415
        app.include_router(
            prometheus_alerts_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Prometheus alerts router (read:scans)")
    except ImportError as exc:
        _logger.warning("prometheus_alerts_router not available: %s", exc)

    # ------------------------------------------------------------------
    # kube-bench CIS Kubernetes Benchmark Scanner (Aqua Security) — 2026-05-04
    # GET  /api/v1/kube-bench/                  capability summary  (read:scans)
    # GET  /api/v1/kube-bench/benchmarks        benchmark catalog   (read:scans)
    # POST /api/v1/kube-bench/scan              queue a new scan    (read:scans)
    # GET  /api/v1/kube-bench/scan/{scan_id}    fetch scan record   (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.kube_bench_router import router as kube_bench_router  # noqa: PLC0415
        app.include_router(
            kube_bench_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted kube-bench CIS K8s benchmark router (read:scans)")
    except ImportError as exc:
        _logger.warning("kube_bench_router not available: %s", exc)

    # ------------------------------------------------------------------
    # OpenSearch Anomaly Detection (AD plugin) — 2026-05-04
    # GET  /api/v1/opensearch/                              capability summary  (read:scans)
    # GET  /api/v1/opensearch/detectors                     list detectors      (read:scans)
    # POST /api/v1/opensearch/detectors                     create detector     (read:scans)
    # GET  /api/v1/opensearch/detectors/{id}                detector detail     (read:scans)
    # POST /api/v1/opensearch/detectors/{id}/_start         start detection job (read:scans)
    # POST /api/v1/opensearch/detectors/{id}/_stop          stop detection job  (read:scans)
    # GET  /api/v1/opensearch/detectors/{id}/results        anomaly results     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.opensearch_router import router as opensearch_router  # noqa: PLC0415
        app.include_router(
            opensearch_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted OpenSearch Anomaly Detection router (read:scans)")
    except ImportError as exc:
        _logger.warning("opensearch_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Elastic Security Detection Engine — 2026-05-04
    # GET  /api/v1/elastic-security/                                    capability summary  (read:scans)
    # GET  /api/v1/elastic-security/api/detection_engine/rules          list rules          (read:scans)
    # POST /api/v1/elastic-security/api/detection_engine/signals/search alert search        (read:scans)
    # GET  /api/v1/elastic-security/api/cases                           list cases          (read:scans)
    # GET  /api/v1/elastic-security/api/exception_lists                 exception lists     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.elastic_security_router import router as elastic_security_router  # noqa: PLC0415
        app.include_router(
            elastic_security_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Elastic Security detection-engine router (read:scans)")
    except ImportError as exc:
        _logger.warning("elastic_security_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Grafana Loki Integration (proxy + capability) — 2026-05-04
    # GET  /api/v1/loki/                       capability summary       (read:scans)
    # GET  /api/v1/loki/labels                 list label names         (read:scans)
    # GET  /api/v1/loki/label/{name}/values    list label values        (read:scans)
    # POST /api/v1/loki/push                   forward log streams      (read:scans)
    # POST /api/v1/loki/query                  instant LogQL query      (read:scans)
    # POST /api/v1/loki/query_range            range LogQL query        (read:scans)
    # GET  /api/v1/loki/series                 series matching selector (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.loki_router import router as loki_router  # noqa: PLC0415
        app.include_router(
            loki_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Grafana Loki integration router (read:scans)")
    except ImportError as exc:
        _logger.warning("loki_router not available: %s", exc)

    # ------------------------------------------------------------------
    # OpenCTI Threat-Intel Platform — 2026-05-04
    # GET  /api/v1/opencti/                       capability summary       (read:scans)
    # GET  /api/v1/opencti/api/threat-actors      list threat actors       (read:scans)
    # GET  /api/v1/opencti/api/indicators         lookup indicators        (read:scans)
    # POST /api/v1/opencti/api/stix-import        import STIX 2.1 bundle   (read:scans)
    # GET  /api/v1/opencti/api/intrusion-sets     list intrusion sets      (read:scans)
    # GET  /api/v1/opencti/api/malware            lookup malware by family (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.opencti_router import router as opencti_router  # noqa: PLC0415
        app.include_router(
            opencti_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted OpenCTI threat-intel router (read:scans)")
    except ImportError as exc:
        _logger.warning("opencti_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Wiz CNAPP/CSPM router (suite-core/core/wiz_cnapp_engine.py) — 2026-05-04
    # GET   /api/v1/wiz/                       capability summary           (read:scans)
    # POST  /api/v1/wiz/graphql                raw GraphQL passthrough      (read:scans)
    # GET   /api/v1/wiz/issues                 list issues w/ filters       (read:scans)
    # GET   /api/v1/wiz/inventory              cloud-resource inventory     (read:scans)
    # GET   /api/v1/wiz/vulnerabilities        vulnerability findings       (read:scans)
    # GET   /api/v1/wiz/threats                threat-detection signals     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.wiz_router import router as wiz_router  # noqa: PLC0415
        app.include_router(
            wiz_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Wiz CNAPP router (read:scans)")
    except ImportError as exc:
        _logger.warning("wiz_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Splunk SOAR (Phantom) REST router (suite-core/core/splunk_soar_engine.py) — 2026-05-04
    # GET   /api/v1/splunk-soar-rest/                                    capability summary       (read:scans)
    # GET   /api/v1/splunk-soar-rest/rest/playbook                       list playbooks            (read:scans)
    # GET   /api/v1/splunk-soar-rest/rest/container                      list containers           (read:scans)
    # GET   /api/v1/splunk-soar-rest/rest/container/{container_id}       container detail          (read:scans)
    # POST  /api/v1/splunk-soar-rest/rest/playbook_run                   trigger playbook run      (read:scans)
    # GET   /api/v1/splunk-soar-rest/rest/playbook_run/{run_id}          playbook run status       (read:scans)
    # GET   /api/v1/splunk-soar-rest/rest/action_run                     list action runs          (read:scans)
    # GET   /api/v1/splunk-soar-rest/rest/asset                          list configured assets    (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.splunk_soar_router import (
            router as splunk_soar_rest_router,  # noqa: PLC0415
        )
        app.include_router(
            splunk_soar_rest_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Splunk SOAR (Phantom) REST router (read:scans)")
    except ImportError as exc:
        _logger.warning("splunk_soar_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Noname Security API posture router (suite-core/core/noname_engine.py) — 2026-05-04
    # GET   /api/v1/noname/                                    capability summary           (read:scans)
    # GET   /api/v1/noname/api/v3/apis                         list APIs (paginate/filter)  (read:scans)
    # GET   /api/v1/noname/api/v3/apis/{api_id}                single API + classifications (read:scans)
    # GET   /api/v1/noname/api/v3/apis/{api_id}/endpoints      per-API endpoint list        (read:scans)
    # GET   /api/v1/noname/api/v3/issues                       posture issues w/ filters    (read:scans)
    # GET   /api/v1/noname/api/v3/inventory/endpoints          endpoint inventory           (read:scans)
    # GET   /api/v1/noname/api/v3/sources                      traffic sources              (read:scans)
    # GET   /api/v1/noname/api/v3/posture-policies             posture-mgmt policies        (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.noname_router import router as noname_router  # noqa: PLC0415
        app.include_router(
            noname_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Noname Security router (read:scans)")
    except ImportError as exc:
        _logger.warning("noname_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Microsoft Sentinel (Azure SIEM/SOAR) — 2026-05-04
    # GET  /api/v1/azure-sentinel/                  capability summary    (read:scans)
    # GET  /api/v1/azure-sentinel/incidents         list incidents        (read:scans)
    # GET  /api/v1/azure-sentinel/alertRules        list alert rules      (read:scans)
    # GET  /api/v1/azure-sentinel/bookmarks         list bookmarks        (read:scans)
    # GET  /api/v1/azure-sentinel/watchlists        list watchlists       (read:scans)
    # POST /api/v1/azure-sentinel/entities/expand   expand entity         (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.azure_sentinel_router import router as azure_sentinel_router  # noqa: PLC0415
        app.include_router(
            azure_sentinel_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Azure Sentinel router (read:scans)")
    except ImportError as exc:
        _logger.warning("azure_sentinel_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Azure Key Vault (secrets / keys / certificates) — 2026-05-04
    # GET  /api/v1/azure-keyvault/                                     capability summary  (read:scans)
    # GET  /api/v1/azure-keyvault/vaults                               list vaults (ARM)   (read:scans)
    # GET  /api/v1/azure-keyvault/vaults/{name}/secrets                list secrets        (read:scans)
    # GET  /api/v1/azure-keyvault/vaults/{name}/secrets/{secret_name}  get secret          (read:scans)
    # GET  /api/v1/azure-keyvault/vaults/{name}/secrets/{name}/versions list versions      (read:scans)
    # GET  /api/v1/azure-keyvault/vaults/{name}/keys                   list keys           (read:scans)
    # GET  /api/v1/azure-keyvault/vaults/{name}/keys/{key_name}        get key             (read:scans)
    # GET  /api/v1/azure-keyvault/vaults/{name}/certificates           list certificates   (read:scans)
    # GET  /api/v1/azure-keyvault/vaults/{name}/certificates/{cert}    get certificate     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.azure_keyvault_router import router as azure_keyvault_router  # noqa: PLC0415
        app.include_router(
            azure_keyvault_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Azure Key Vault router (read:scans)")
    except ImportError as exc:
        _logger.warning("azure_keyvault_router not available: %s", exc)

    # ------------------------------------------------------------------
    # AWS S3 inventory + posture (suite-core/core/aws_s3_engine.py) — 2026-05-04
    # GET  /api/v1/aws-s3/                                       capability summary           (read:scans)
    # GET  /api/v1/aws-s3/buckets                                ListBuckets                  (read:scans)
    # GET  /api/v1/aws-s3/buckets/{name}/policy                  GetBucketPolicy              (read:scans)
    # GET  /api/v1/aws-s3/buckets/{name}/encryption              GetBucketEncryption          (read:scans)
    # GET  /api/v1/aws-s3/buckets/{name}/acl                     GetBucketAcl                 (read:scans)
    # GET  /api/v1/aws-s3/buckets/{name}/public-access-block     GetPublicAccessBlock         (read:scans)
    # GET  /api/v1/aws-s3/buckets/{name}/versioning              GetBucketVersioning          (read:scans)
    # GET  /api/v1/aws-s3/buckets/{name}/logging                 GetBucketLogging             (read:scans)
    # GET  /api/v1/aws-s3/buckets/{name}/lifecycle               GetBucketLifecycleConfig     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.aws_s3_router import router as aws_s3_router  # noqa: PLC0415
        app.include_router(
            aws_s3_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted AWS S3 inventory+posture router at /api/v1/aws-s3 (read:scans)")
    except ImportError as exc:
        _logger.warning("aws_s3_router not available: %s", exc)

    # ------------------------------------------------------------------
    # AWS ECR (Elastic Container Registry) inventory + scan-findings
    # (suite-core/core/aws_ecr_engine.py) — 2026-05-04
    # GET  /api/v1/aws-ecr/                                                       capability summary           (read:scans)
    # GET  /api/v1/aws-ecr/repositories                                           DescribeRepositories         (read:scans)
    # GET  /api/v1/aws-ecr/repositories/{name}/images                             ListImages                   (read:scans)
    # POST /api/v1/aws-ecr/repositories/{name}/images/batch-describe              BatchDescribeImages          (read:scans)
    # GET  /api/v1/aws-ecr/repositories/{name}/images/{image_id}/scan-findings    DescribeImageScanFindings    (read:scans)
    # GET  /api/v1/aws-ecr/repositories/{name}/lifecycle-policy                   GetLifecyclePolicy           (read:scans)
    # GET  /api/v1/aws-ecr/repositories/{name}/policy                             GetRepositoryPolicy          (read:scans)
    # GET  /api/v1/aws-ecr/registry-scanning-config                               GetRegistryScanningConfig    (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.aws_ecr_router import router as aws_ecr_router  # noqa: PLC0415
        app.include_router(
            aws_ecr_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted AWS ECR inventory+scan-findings router at /api/v1/aws-ecr (read:scans)")
    except ImportError as exc:
        _logger.warning("aws_ecr_router not available: %s", exc)

    # ------------------------------------------------------------------
    # AWS EKS inventory router (read:scans)
    # ------------------------------------------------------------------
    # GET  /api/v1/aws-eks/                                           capability summary
    # GET  /api/v1/aws-eks/clusters                                   ListClusters                 (read:scans)
    # GET  /api/v1/aws-eks/clusters/{name}                            DescribeCluster              (read:scans)
    # GET  /api/v1/aws-eks/clusters/{name}/nodegroups                 ListNodegroups               (read:scans)
    # GET  /api/v1/aws-eks/clusters/{name}/nodegroups/{ng}            DescribeNodegroup            (read:scans)
    # GET  /api/v1/aws-eks/clusters/{name}/addons                     ListAddons                   (read:scans)
    # GET  /api/v1/aws-eks/clusters/{name}/addons/{addon}             DescribeAddon                (read:scans)
    # GET  /api/v1/aws-eks/clusters/{name}/fargate-profiles           ListFargateProfiles          (read:scans)
    # GET  /api/v1/aws-eks/clusters/{name}/access-entries             ListAccessEntries            (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.aws_eks_router import router as aws_eks_router  # noqa: PLC0415
        app.include_router(
            aws_eks_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted AWS EKS inventory router at /api/v1/aws-eks (read:scans)")
    except ImportError as exc:
        _logger.warning("aws_eks_router not available: %s", exc)

    # ------------------------------------------------------------------
    # AWS WAFv2 (Web ACLs, Rule Groups, IP Sets, Regex Pattern Sets,
    # Managed Rule Groups, Sampled Requests)
    # (suite-core/core/aws_waf_engine.py) — 2026-05-04
    # GET  /api/v1/aws-waf/                                       capability summary           (read:scans)
    # GET  /api/v1/aws-waf/web-acls                               ListWebACLs                  (read:scans)
    # GET  /api/v1/aws-waf/web-acls/{Scope}/{Id}/{Name}           GetWebACL                    (read:scans)
    # GET  /api/v1/aws-waf/rule-groups                            ListRuleGroups               (read:scans)
    # GET  /api/v1/aws-waf/rule-groups/{Scope}/{Id}/{Name}        GetRuleGroup                 (read:scans)
    # GET  /api/v1/aws-waf/ip-sets                                ListIPSets                   (read:scans)
    # GET  /api/v1/aws-waf/ip-sets/{Scope}/{Id}/{Name}            GetIPSet                     (read:scans)
    # GET  /api/v1/aws-waf/regex-pattern-sets                     ListRegexPatternSets         (read:scans)
    # GET  /api/v1/aws-waf/managed-rule-groups                    ListAvailableManagedRuleGroups  (read:scans)
    # POST /api/v1/aws-waf/sampled-requests                       GetSampledRequests           (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.aws_waf_router import router as aws_waf_router  # noqa: PLC0415
        app.include_router(
            aws_waf_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted AWS WAFv2 router at /api/v1/aws-waf (read:scans)")
    except ImportError as exc:
        _logger.warning("aws_waf_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Sigstore Rekor transparency log proxy router (read:scans)
    # ------------------------------------------------------------------
    # GET    /api/v1/rekor/                          capability summary
    # GET    /api/v1/rekor/api/v1/log                tree state
    # GET    /api/v1/rekor/api/v1/log/proof          consistency proof
    # GET    /api/v1/rekor/api/v1/log/entries/{u}    entry by uuid
    # GET    /api/v1/rekor/api/v1/log/entries        entry by logIndex
    # POST   /api/v1/rekor/api/v1/log/entries        submit entry
    # POST   /api/v1/rekor/api/v1/index/retrieve     search index
    # ------------------------------------------------------------------
    try:
        from apps.api.rekor_router import router as rekor_router  # noqa: PLC0415
        app.include_router(
            rekor_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Sigstore Rekor router at /api/v1/rekor (read:scans)")
    except ImportError as exc:
        _logger.warning("rekor_router not available: %s", exc)

    # ------------------------------------------------------------------
    # SonarQube — code quality + security platform (Web API wrapper)
    # ------------------------------------------------------------------
    # GET  /api/v1/sonarqube/                                  capability       (read:scans)
    # GET  /api/v1/sonarqube/api/projects/search               projects.search  (read:scans)
    # GET  /api/v1/sonarqube/api/issues/search                 issues.search    (read:scans)
    # GET  /api/v1/sonarqube/api/qualitygates/project_status   QG status        (read:scans)
    # GET  /api/v1/sonarqube/api/measures/component            measures         (read:scans)
    # GET  /api/v1/sonarqube/api/components/show               components.show  (read:scans)
    # GET  /api/v1/sonarqube/api/hotspots/search               hotspots.search  (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.sonarqube_router import router as sonarqube_router  # noqa: PLC0415
        app.include_router(
            sonarqube_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted SonarQube router at /api/v1/sonarqube (read:scans)")
    except ImportError as exc:
        _logger.warning("sonarqube_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Akamai — EdgeGrid PAPI v1 + AppSec v1 (read:scans)
    # ------------------------------------------------------------------
    # GET  /api/v1/akamai/                                          capability summary
    # GET  /api/v1/akamai/papi/v1/groups                            PAPI groups
    # GET  /api/v1/akamai/papi/v1/properties                        PAPI properties
    # GET  /api/v1/akamai/papi/v1/properties/{prp}/versions         version history
    # GET  /api/v1/akamai/papi/v1/properties/{prp}/versions/{v}/rules  rule tree
    # GET  /api/v1/akamai/appsec/v1/configs                         AppSec configs
    # GET  /api/v1/akamai/appsec/v1/configs/{id}/versions           AppSec versions
    # POST /api/v1/akamai/appsec/v1/configs/{id}/versions/{v}/security-events
    # ------------------------------------------------------------------
    try:
        from apps.api.akamai_router import router as akamai_router  # noqa: PLC0415
        app.include_router(
            akamai_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Akamai EdgeGrid router at /api/v1/akamai (read:scans)")
    except ImportError as exc:
        _logger.warning("akamai_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Veeam Backup Enterprise Manager — REST v1 (read:scans) - 2026-05-04
    # GET  /api/v1/veeam/                                       capability summary
    # POST /api/v1/veeam/api/oauth2/token                       OAuth2 token (password/refresh)
    # GET  /api/v1/veeam/api/v1/backupSessions                  list sessions
    # GET  /api/v1/veeam/api/v1/backupSessions/{session_id}     single session
    # GET  /api/v1/veeam/api/v1/jobs                            list jobs
    # GET  /api/v1/veeam/api/v1/jobs/{job_id}                   single job
    # POST /api/v1/veeam/api/v1/jobs/{job_id}/start             start job (202)
    # POST /api/v1/veeam/api/v1/jobs/{job_id}/stop              stop job (202)
    # GET  /api/v1/veeam/api/v1/backups                         list backups
    # GET  /api/v1/veeam/api/v1/restorePoints?BackupUid=        restore points
    # GET  /api/v1/veeam/api/v1/managedServers                  managed Veeam servers
    # ------------------------------------------------------------------
    try:
        from apps.api.veeam_router import router as veeam_router  # noqa: PLC0415
        app.include_router(
            veeam_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Veeam Backup Enterprise Manager router at /api/v1/veeam (read:scans)")
    except ImportError as exc:
        _logger.warning("veeam_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Kong Admin API — services / routes / plugins / consumers / upstreams
    #                  / certs / SNIs / status (read:scans)
    # ------------------------------------------------------------------
    # GET    /api/v1/kong/                                       capability summary
    # GET    /api/v1/kong/services                               list services
    # GET    /api/v1/kong/services/{service_id_or_name}          single service
    # GET    /api/v1/kong/routes                                 list routes (filter: service.id)
    # GET    /api/v1/kong/plugins                                list plugins (filter: service/route/consumer)
    # GET    /api/v1/kong/consumers                              list consumers
    # GET    /api/v1/kong/consumers/{id}/key-auth                consumer key-auth credentials
    # GET    /api/v1/kong/upstreams                              list upstreams
    # GET    /api/v1/kong/upstreams/{id}/targets                 upstream targets
    # GET    /api/v1/kong/certificates                           TLS certificates
    # GET    /api/v1/kong/snis                                   SNIs
    # GET    /api/v1/kong/status                                 Kong node status
    # ------------------------------------------------------------------
    try:
        from apps.api.kong_router import router as kong_router  # noqa: PLC0415
        app.include_router(
            kong_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Kong Admin API router at /api/v1/kong (read:scans)")
    except ImportError as exc:
        _logger.warning("kong_router not available: %s", exc)



    # ------------------------------------------------------------------
    # Akto — API Security platform (read:scans)
    # ------------------------------------------------------------------
    # GET  /api/v1/akto/                              capability summary
    # GET  /api/v1/akto/api/discovered-apis           inventory of discovered APIs
    # GET  /api/v1/akto/api/sensitive-data            sensitive-data findings
    # GET  /api/v1/akto/api/test-results              security test results
    # GET  /api/v1/akto/api/runtime-issues            runtime-detected issues
    # POST /api/v1/akto/api/start-test                kick off a test run
    # GET  /api/v1/akto/api/test-runs                 historical test-run summaries
    # GET  /api/v1/akto/api/collections               API collection list
    # ------------------------------------------------------------------
    try:
        from apps.api.akto_router import router as akto_router  # noqa: PLC0415
        app.include_router(
            akto_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Akto API security router at /api/v1/akto (read:scans)")
    except ImportError as exc:
        _logger.warning("akto_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Palo Alto Cortex XSOAR (Demisto) — incidents/playbooks/integrations
    # GET  /api/v1/xsoar/                                  capability summary  (read:scans)
    # POST /api/v1/xsoar/incidents/search                  filter incidents    (read:scans)
    # GET  /api/v1/xsoar/incidents/{id}                    one incident        (read:scans)
    # POST /api/v1/xsoar/incidents/{id}/run                trigger playbook    (read:scans)
    # POST /api/v1/xsoar/entry                             add war-room entry  (read:scans)
    # POST /api/v1/xsoar/playbooks/search                  filter playbooks    (read:scans)
    # POST /api/v1/xsoar/settings/integration/search       integration list    (read:scans)
    # POST /api/v1/xsoar/settings/integration/test         test integration    (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.xsoar_router import router as xsoar_router  # noqa: PLC0415
        app.include_router(
            xsoar_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
    except ImportError as exc:
        _logger.warning("xsoar_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Contrast Security — RASP/IAST + SCA libraries (read:scans)
    # ------------------------------------------------------------------
    # GET  /api/v1/contrast/                                          capability summary
    # GET  /api/v1/contrast/api/ng/{org}/applications                 application inventory
    # GET  /api/v1/contrast/api/ng/{org}/applications/{app_id}        single application
    # GET  /api/v1/contrast/api/ng/{org}/traces/{app_id}/filter       Assess traces
    # GET  /api/v1/contrast/api/ng/{org}/traces/{trace_uuid}          single trace
    # GET  /api/v1/contrast/api/ng/{org}/protect/policies             RASP Protect policies
    # GET  /api/v1/contrast/api/ng/{org}/servers                      monitored servers
    # GET  /api/v1/contrast/api/ng/{org}/libraries                    third-party libraries + vulns
    # ------------------------------------------------------------------
    try:
        from apps.api.contrast_router import router as contrast_router  # noqa: PLC0415
        app.include_router(
            contrast_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Contrast Security RASP/IAST router at /api/v1/contrast (read:scans)")
    except ImportError as exc:
        _logger.warning("contrast_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Apigee Edge X — Google API management platform (read:scans)
    # ------------------------------------------------------------------
    # GET  /api/v1/apigee/                                                                   capability summary
    # GET  /api/v1/apigee/v1/organizations/{org}/apis                                         API proxy list
    # GET  /api/v1/apigee/v1/organizations/{org}/apis/{api_name}                              proxy detail
    # GET  /api/v1/apigee/v1/organizations/{org}/apis/{api_name}/revisions                    revision list
    # GET  /api/v1/apigee/v1/organizations/{org}/apis/{api_name}/revisions/{rev}              revision detail
    # GET  /api/v1/apigee/v1/organizations/{org}/apis/{api_name}/revisions/{rev}/policies     policy list
    # GET  /api/v1/apigee/v1/organizations/{org}/environments                                 environment list
    # GET  /api/v1/apigee/v1/organizations/{org}/environments/{env}/apis/{api}/revisions/{rev}/deployments
    # GET  /api/v1/apigee/v1/organizations/{org}/apiproducts                                  API product list
    # GET  /api/v1/apigee/v1/organizations/{org}/developers                                   developer list
    # GET  /api/v1/apigee/v1/organizations/{org}/developers/{email}/apps                      developer apps
    # GET  /api/v1/apigee/v1/organizations/{org}/apps                                         all apps
    # ------------------------------------------------------------------
    try:
        from apps.api.apigee_router import router as apigee_router  # noqa: PLC0415
        app.include_router(
            apigee_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Apigee Edge X router at /api/v1/apigee (read:scans)")
    except ImportError as exc:
        _logger.warning("apigee_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Salt Security — API protection telemetry (read:scans)
    # ------------------------------------------------------------------
    # GET  /api/v1/salt-security/                                    capability summary
    # POST /api/v1/salt-security/api/oauth/token                     OAuth2 client_credentials
    # GET  /api/v1/salt-security/api/v1/incidents                    incidents (paged, filterable)
    # GET  /api/v1/salt-security/api/v1/api-catalog                  API catalog (paged, filterable)
    # GET  /api/v1/salt-security/api/v1/api-catalog/{id}             single API entry
    # GET  /api/v1/salt-security/api/v1/api-catalog/{id}/endpoints   endpoints w/ sensitive overlay
    # GET  /api/v1/salt-security/api/v1/attackers                    attackers (page-token paged)
    # GET  /api/v1/salt-security/api/v1/policies                     detection/protection policies
    # ------------------------------------------------------------------
    try:
        from apps.api.salt_security_router import router as salt_security_router  # noqa: PLC0415
        app.include_router(
            salt_security_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Salt Security router at /api/v1/salt-security (read:scans)")
    except ImportError as exc:
        _logger.warning("salt_security_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Zscaler ZIA — Internet Access REST surfaces (read:scans)
    # ------------------------------------------------------------------
    # GET    /api/v1/zscaler-zia/                                    capability summary
    # POST   /api/v1/zscaler-zia/api/v1/authenticatedSession         cookie session login
    # DELETE /api/v1/zscaler-zia/api/v1/authenticatedSession         logout
    # GET    /api/v1/zscaler-zia/api/v1/sandbox/report/{md5}         sandbox detonation
    # GET    /api/v1/zscaler-zia/api/v1/urlCategories                URL categories
    # GET    /api/v1/zscaler-zia/api/v1/firewallFilteringRules       firewall rules
    # GET    /api/v1/zscaler-zia/api/v1/users                        users (paged)
    # GET    /api/v1/zscaler-zia/api/v1/locations                    locations (paged)
    # ------------------------------------------------------------------
    try:
        from apps.api.zscaler_zia_router import router as zscaler_zia_router  # noqa: PLC0415
        app.include_router(
            zscaler_zia_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Zscaler ZIA router at /api/v1/zscaler-zia (read:scans)")
    except ImportError as exc:
        _logger.warning("zscaler_zia_router not available: %s", exc)


    # ------------------------------------------------------------------
    # Auth0 — Management API v2 (read:scans)
    # ------------------------------------------------------------------
    # GET /api/v1/auth0/                                          capability summary
    # GET /api/v1/auth0/api/v2/users                              list users (lucene q)
    # GET /api/v1/auth0/api/v2/users/{user_id}                    single user
    # GET /api/v1/auth0/api/v2/users/{user_id}/roles              user roles
    # GET /api/v1/auth0/api/v2/users/{user_id}/permissions        user permissions
    # GET /api/v1/auth0/api/v2/clients                            applications/clients
    # GET /api/v1/auth0/api/v2/connections                        identity providers
    # GET /api/v1/auth0/api/v2/logs                               tenant log events
    # GET /api/v1/auth0/api/v2/roles                              roles
    # GET /api/v1/auth0/api/v2/roles/{role_id}/permissions        role permissions
    # ------------------------------------------------------------------
    try:
        from apps.api.auth0_router import router as auth0_router  # noqa: PLC0415
        app.include_router(
            auth0_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Auth0 Management API router at /api/v1/auth0 (read:scans)")
    except ImportError as exc:
        _logger.warning("auth0_router not available: %s", exc)


    # ------------------------------------------------------------------
    # CyberArk PAM (PVWA REST API surface) — 2026-05-04
    # GET  /api/v1/cyberark-pam/                                                              capability summary  (read:scans)
    # POST /api/v1/cyberark-pam/PasswordVault/API/auth/Cyberark/Logon                          session token       (read:scans)
    # POST /api/v1/cyberark-pam/PasswordVault/API/auth/Logoff                                  invalidate token    (read:scans)
    # GET  /api/v1/cyberark-pam/PasswordVault/API/Accounts                                     account list        (read:scans)
    # GET  /api/v1/cyberark-pam/PasswordVault/API/Accounts/{id}                                single account      (read:scans)
    # POST /api/v1/cyberark-pam/PasswordVault/API/Accounts/{id}/Password/Retrieve              password retrieval  (read:scans)
    # GET  /api/v1/cyberark-pam/PasswordVault/API/Safes                                        safe list           (read:scans)
    # GET  /api/v1/cyberark-pam/PasswordVault/API/Safes/{safe_url_id}/Members                  safe members        (read:scans)
    # GET  /api/v1/cyberark-pam/PasswordVault/API/PSM/Sessions                                 PSM sessions list   (read:scans)
    # GET  /api/v1/cyberark-pam/PasswordVault/API/PSM/Recordings                               PSM recordings list (read:scans)
    # NOTE: distinct prefix from cyberark_live_connector_router (higher-level wrapper)
    # ------------------------------------------------------------------
    try:
        from apps.api.cyberark_pam_router import router as cyberark_pam_router  # noqa: PLC0415
        app.include_router(
            cyberark_pam_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted CyberArk PAM (PVWA) router at /api/v1/cyberark-pam (read:scans)")
    except ImportError as exc:
        _logger.warning("cyberark_pam_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Traceable AI (Runtime API security: services + APIs + anomalies +
    #   threats + users-and-attribution + policy-test) - 2026-05-04
    # GET  /api/v1/traceable/                                  capability summary           (read:scans)
    # GET  /api/v1/traceable/api/v1/services                   service inventory            (read:scans)
    # GET  /api/v1/traceable/api/v1/apis                       API inventory                (read:scans)
    # GET  /api/v1/traceable/api/v1/apis/{api_id}              API detail                   (read:scans)
    # GET  /api/v1/traceable/api/v1/anomalies                  runtime anomalies            (read:scans)
    # GET  /api/v1/traceable/api/v1/threats                    active threats               (read:scans)
    # GET  /api/v1/traceable/api/v1/users-and-attribution      attributed users             (read:scans)
    # POST /api/v1/traceable/api/v1/policies/test              policy evaluation            (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.traceable_router import router as traceable_router  # noqa: PLC0415
        app.include_router(
            traceable_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Traceable AI router at /api/v1/traceable (read:scans)")
    except ImportError as exc:
        _logger.warning("traceable_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Guardrails AI (LLM input/output validation surface) - 2026-05-04
    # GET  /api/v1/guardrails/                                        capability summary             (read:scans)
    # POST /api/v1/guardrails/v1/validate                             ad-hoc validate                (read:scans)
    # GET  /api/v1/guardrails/v1/specs                                list registered specs          (read:scans)
    # GET  /api/v1/guardrails/v1/specs/{spec_name}                    spec detail                    (read:scans)
    # POST /api/v1/guardrails/v1/spec                                 register custom spec (201)     (read:scans)
    # POST /api/v1/guardrails/v1/guards/{guard_name}/validate         validate against named guard   (read:scans)
    # POST /api/v1/guardrails/v1/openai/chat/completions              guarded OpenAI passthrough     (read:scans)
    # GET  /api/v1/guardrails/v1/health                               upstream health probe          (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.guardrails_router import router as guardrails_router  # noqa: PLC0415
        app.include_router(
            guardrails_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted Guardrails AI router at /api/v1/guardrails (read:scans)")
    except ImportError as exc:
        _logger.warning("guardrails_router not available: %s", exc)

    # ------------------------------------------------------------------
    # LangSmith — LLM observability (runs / datasets / examples / feedback /
    #   sessions) - 2026-05-04
    # GET  /api/v1/langsmith/                                  capability summary           (read:scans)
    # GET  /api/v1/langsmith/api/v1/runs                       list LLM/chain/tool runs     (read:scans)
    # GET  /api/v1/langsmith/api/v1/runs/{run_id}              single run detail            (read:scans)
    # GET  /api/v1/langsmith/api/v1/datasets                   list datasets                (read:scans)
    # GET  /api/v1/langsmith/api/v1/datasets/{dataset_id}      single dataset detail        (read:scans)
    # GET  /api/v1/langsmith/api/v1/datasets/{id}/examples     list dataset examples        (read:scans)
    # POST /api/v1/langsmith/api/v1/datasets/{id}/examples     bulk create examples         (read:scans)
    # POST /api/v1/langsmith/api/v1/feedback                   attach feedback to a run     (read:scans)
    # GET  /api/v1/langsmith/api/v1/sessions                   list sessions / projects     (read:scans)
    # ------------------------------------------------------------------
    try:
        from apps.api.langsmith_router import router as langsmith_router  # noqa: PLC0415
        app.include_router(
            langsmith_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("read:scans")),
            ],
        )
        _logger.info("Mounted LangSmith observability router at /api/v1/langsmith (read:scans)")
    except ImportError as exc:
        _logger.warning("langsmith_router not available: %s", exc)
