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
        from apps.api.pagerduty_router import (
            router as pagerduty_router,  # noqa: PLC0415
        )
        app.include_router(pagerduty_router)
        _logger.info("Mounted PagerDuty router at /api/v1/pagerduty")
    except ImportError as exc:
        _logger.warning("pagerduty_router not available: %s", exc)

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
