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
        from apps.api.users_router import public_router as users_public_router  # noqa: PLC0415
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
        from apps.api.analytics_router import router as analytics_router  # noqa: PLC0415
        app.include_router(analytics_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted Analytics router")
    except ImportError as exc:
        _logger.warning("analytics_router not available: %s", exc)

    try:
        from apps.api.ai_orchestrator_router import router as ai_orchestrator_router  # noqa: PLC0415
        app.include_router(
            ai_orchestrator_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted AI Orchestrator router")
    except ImportError as exc:
        _logger.warning("ai_orchestrator_router not available: %s", exc)

    # AI Teammates router (GAP-044)
    try:
        from apps.api.ai_orchestrator_router import teammates_router as _teammates_router  # noqa: PLC0415
        app.include_router(_teammates_router)
        _logger.info("Mounted AI Teammates router at /api/v1/teammates (GAP-044)")
    except ImportError as exc:
        _logger.warning("AI Teammates router not available: %s", exc)

    # Formula Transparency router (GAP-043)
    try:
        from apps.api.formula_transparency_router import router as _formula_router  # noqa: PLC0415
        app.include_router(_formula_router)
        _logger.info("Mounted Formula Transparency router at /api/v1/formula (GAP-043)")
    except ImportError as exc:
        _logger.warning("Formula Transparency router not available: %s", exc)

    # ------------------------------------------------------------------
    # Real-Time Streaming / WebSocket / EventBus (formerly ~L3138-L3168)
    # ------------------------------------------------------------------

    try:
        from apps.api.websocket_routes import router as websocket_router  # noqa: PLC0415
        app.include_router(
            websocket_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))],
        )
        _logger.info("Mounted WebSocket router")
    except ImportError as exc:
        _logger.warning("websocket_router not available: %s", exc)

    try:
        from apps.api.websocket_alerts_router import router as websocket_alerts_router  # noqa: PLC0415
        app.include_router(websocket_alerts_router)
        _logger.info("Mounted WebSocket Alerts router")
    except ImportError as exc:
        _logger.warning("websocket_alerts_router not available: %s", exc)

    try:
        from apps.api.ws_events_router import router as ws_events_router  # noqa: PLC0415
        app.include_router(ws_events_router)
        _logger.info("Mounted WS Events router")
    except ImportError as exc:
        _logger.warning("ws_events_router not available: %s", exc)

    try:
        from apps.api.stream_router import router as event_stream_router  # noqa: PLC0415
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
        from apps.api.mcp_gateway_router import router as mcp_gateway_router  # noqa: PLC0415
        app.include_router(mcp_gateway_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted MCP Gateway router")
    except ImportError as exc:
        _logger.warning("mcp_gateway_router not available: %s", exc)

    try:
        from apps.api.trustgraph_routes import router as trustgraph_router  # noqa: PLC0415
        app.include_router(
            trustgraph_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))],
        )
        _logger.info("Mounted TrustGraph router")
    except ImportError as exc:
        _logger.warning("trustgraph_router not available: %s", exc)

    try:
        from apps.api.trustgraph_quality_router import router as trustgraph_quality_router  # noqa: PLC0415
        app.include_router(
            trustgraph_quality_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))],
        )
        _logger.info("Mounted TrustGraph Quality router")
    except ImportError as exc:
        _logger.warning("trustgraph_quality_router not available: %s", exc)

    try:
        from apps.api.trustgraph_maintenance_router import router as trustgraph_maintenance_router  # noqa: PLC0415
        app.include_router(
            trustgraph_maintenance_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:graph"))],
        )
        _logger.info("Mounted TrustGraph Maintenance router")
    except ImportError as exc:
        _logger.warning("trustgraph_maintenance_router not available: %s", exc)

    try:
        from apps.api.trustgraph_integration_router import router as trustgraph_integration_router  # noqa: PLC0415
        app.include_router(trustgraph_integration_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted TrustGraph Integration router")
    except ImportError as exc:
        _logger.warning("trustgraph_integration_router not available: %s", exc)

    try:
        from apps.api.trustgraph_backbone_router import router as trustgraph_backbone_router  # noqa: PLC0415
        app.include_router(trustgraph_backbone_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted TrustGraph Backbone router at /api/v1/graph")
    except ImportError as exc:
        _logger.warning("trustgraph_backbone_router not available: %s", exc)

    try:
        from apps.api.trustgraph_migrator_router import router as trustgraph_migrator_router  # noqa: PLC0415
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
        from apps.api.connectors_router import router as connectors_router  # noqa: PLC0415
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
        from apps.api.servicenow_sync_router import router as servicenow_sync_router  # noqa: PLC0415
        app.include_router(
            servicenow_sync_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted ServiceNow Sync router")
    except ImportError as exc:
        _logger.warning("servicenow_sync_router not available: %s", exc)

    try:
        from apps.api.servicenow_sync_router import webhook_router as servicenow_sync_webhook_router  # noqa: PLC0415
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
        from apps.api.collaboration_router import router as collaboration_router  # noqa: PLC0415
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
        from apps.api.sla_engine_router import router as sla_engine_router  # noqa: PLC0415
        app.include_router(sla_engine_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted SLA Engine router")
    except ImportError as exc:
        _logger.warning("sla_engine_router not available: %s", exc)

    try:
        from apps.api.workflows_router import router as workflows_router  # noqa: PLC0415
        app.include_router(workflows_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))])
        _logger.info("Mounted Workflows router")
    except ImportError as exc:
        _logger.warning("workflows_router not available: %s", exc)

    try:
        from apps.api.change_management_router import router as change_management_router  # noqa: PLC0415
        app.include_router(change_management_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Change Management router")
    except ImportError as exc:
        _logger.warning("change_management_router not available: %s", exc)

    # Wave D — 22 Multica integrations/AI/policy endpoints
    try:
        from apps.api.wave_d_integrations_router import router as wave_d_integrations_router  # noqa: PLC0415
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
        from apps.api.integration_marketplace_router import router as integration_marketplace_router  # noqa: PLC0415
        app.include_router(integration_marketplace_router)
        _logger.info("Mounted Integration Marketplace router at /api/v1/integrations")
    except ImportError as exc:
        _logger.warning("integration_marketplace_router not available: %s", exc)

    # Enterprise marketplace API
    try:
        from apps.api.marketplace_router import router as marketplace_router  # noqa: PLC0415
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
        from apps.api.onboarding_router import router as onboarding_wizard_router  # noqa: PLC0415
        app.include_router(
            onboarding_wizard_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
        )
        _logger.info("Mounted Onboarding Wizard router")
    except ImportError as exc:
        _logger.warning("onboarding_wizard_router not available: %s", exc)

    # Admin first-login wizard (no auth)
    try:
        from apps.api.admin_wizard_router import router as admin_wizard_router  # noqa: PLC0415
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
        from apps.api.deployment_router import router as deployment_router  # noqa: PLC0415
        app.include_router(deployment_router)
        _logger.info("Mounted Deployment Manager router at /api/v1/deployment")
    except ImportError as exc:
        _logger.warning("deployment_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Webhook management (formerly ~L5504-L5534 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.webhook_subscriptions_router import router as webhook_subscriptions_router  # noqa: PLC0415
        app.include_router(
            webhook_subscriptions_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook Subscriptions router")
    except ImportError as exc:
        _logger.warning("webhook_subscriptions_router not available: %s", exc)

    try:
        from apps.api.webhook_dlq_router import router as webhook_dlq_router  # noqa: PLC0415
        app.include_router(
            webhook_dlq_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook DLQ router")
    except ImportError as exc:
        _logger.warning("webhook_dlq_router not available: %s", exc)

    try:
        from apps.api.webhook_notifications_router import router as webhook_notifications_router  # noqa: PLC0415
        app.include_router(
            webhook_notifications_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook Notifications router")
    except ImportError as exc:
        _logger.warning("webhook_notifications_router not available: %s", exc)

    try:
        from apps.api.webhook_verifier_router import router as webhook_verifier_router  # noqa: PLC0415
        app.include_router(
            webhook_verifier_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:integrations"))],
        )
        _logger.info("Mounted Webhook Verifier router")
    except ImportError as exc:
        _logger.warning("webhook_verifier_router not available: %s", exc)

    try:
        from apps.api.webhook_router import router as webhook_router  # noqa: PLC0415
        app.include_router(webhook_router)
        _logger.info("Mounted Webhook router")
    except ImportError as exc:
        _logger.warning("webhook_router not available: %s", exc)

    try:
        from api.webhooks_router import receiver_router as webhooks_receiver_router  # noqa: PLC0415
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
        from apps.api.integration_hub_router import router as integration_hub_router  # noqa: PLC0415
        app.include_router(integration_hub_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Integration Hub router")
    except ImportError as exc:
        _logger.warning("integration_hub_router not available: %s", exc)

    try:
        from apps.api.integration_health_router import router as integration_health_router  # noqa: PLC0415
        app.include_router(integration_health_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Integration Health router")
    except ImportError as exc:
        _logger.warning("integration_health_router not available: %s", exc)

    try:
        from apps.api.jira_sync_router import router as jira_sync_router  # noqa: PLC0415
        app.include_router(jira_sync_router)
        _logger.info("Mounted Jira Sync router at /api/v1/jira-sync")
    except ImportError as exc:
        _logger.warning("jira_sync_router not available: %s", exc)

    try:
        from apps.api.pagerduty_router import router as pagerduty_router  # noqa: PLC0415
        app.include_router(pagerduty_router)
        _logger.info("Mounted PagerDuty router at /api/v1/pagerduty")
    except ImportError as exc:
        _logger.warning("pagerduty_router not available: %s", exc)

    try:
        from apps.api.slack_bot_router import router as slack_bot_router  # noqa: PLC0415
        app.include_router(slack_bot_router)
        _logger.info("Mounted Slack Bot router")
    except ImportError as exc:
        _logger.warning("slack_bot_router not available: %s", exc)

    try:
        from apps.api.slack_notifier_router import router as slack_notifier_router  # noqa: PLC0415
        app.include_router(slack_notifier_router)
        _logger.info("Mounted Slack Notifier router at /api/v1/integrations/slack")
    except ImportError as exc:
        _logger.warning("slack_notifier_router not available: %s", exc)

    try:
        from servicenow.servicenow_router import router as servicenow_router  # noqa: PLC0415
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

    try:
        from apps.api.report_scheduler_router import router as report_scheduler_router  # noqa: PLC0415
        app.include_router(report_scheduler_router)
        _logger.info("Mounted Report Scheduler router")
    except ImportError as exc:
        _logger.warning("report_scheduler_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Analytics dashboards / DuckDB / GraphRAG / NL graph
    # (formerly ~L3385-L3435 expanded section in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.analytics_dashboard_router import router as analytics_dashboard_router  # noqa: PLC0415
        app.include_router(analytics_dashboard_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Analytics Dashboard router")
    except ImportError as exc:
        _logger.warning("analytics_dashboard_router not available: %s", exc)

    try:
        from apps.api.analytics_routes import router as analytics_routes_router  # noqa: PLC0415
        app.include_router(analytics_routes_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Analytics Routes router")
    except ImportError as exc:
        _logger.warning("analytics_routes_router not available: %s", exc)

    try:
        from apps.api.duckdb_analytics_router import router as duckdb_analytics_router  # noqa: PLC0415
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
        from apps.api.dashboard_builder_router import router as dashboard_builder_router  # noqa: PLC0415
        app.include_router(dashboard_builder_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Dashboard Builder router")
    except ImportError as exc:
        _logger.warning("dashboard_builder_router not available: %s", exc)

    try:
        from apps.api.unified_dashboard_router import router as unified_dashboard_router  # noqa: PLC0415
        app.include_router(unified_dashboard_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Unified Dashboard router")
    except ImportError as exc:
        _logger.warning("unified_dashboard_router not available: %s", exc)

    try:
        from apps.api.api_analytics_router import router as api_analytics_router  # noqa: PLC0415
        app.include_router(api_analytics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted API Analytics router")
    except ImportError as exc:
        _logger.warning("api_analytics_router not available: %s", exc)

    try:
        from apps.api.api_gateway_router import router as api_gateway_router  # noqa: PLC0415
        app.include_router(api_gateway_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted API Gateway Security router")
    except ImportError as exc:
        _logger.warning("api_gateway_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Metrics / SLA / RBAC / Session / SSE / OAuth2
    # (formerly ~L7560-L8340 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.metrics_aggregator_router import router as metrics_aggregator_router  # noqa: PLC0415
        app.include_router(metrics_aggregator_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Metrics Aggregator router")
    except ImportError as exc:
        _logger.warning("metrics_aggregator_router not available: %s", exc)

    try:
        from apps.api.metrics_timeseries_router import router as metrics_timeseries_router  # noqa: PLC0415
        app.include_router(metrics_timeseries_router)
        _logger.info("Mounted Metrics Time-Series router")
    except ImportError as exc:
        _logger.warning("metrics_timeseries_router not available: %s", exc)

    try:
        from apps.api.notification_router import router as notification_router  # noqa: PLC0415
        app.include_router(notification_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Notification router")
    except ImportError as exc:
        _logger.warning("notification_router not available: %s", exc)

    try:
        from apps.api.alerting_notification_router import router as alerting_notification_router  # noqa: PLC0415
        app.include_router(alerting_notification_router)
        _logger.info("Mounted Alerting Notification router at /api/v1/alerting")
    except ImportError as exc:
        _logger.warning("alerting_notification_router not available: %s", exc)

    try:
        from apps.api.rate_limit_router import router as rate_limit_router  # noqa: PLC0415
        app.include_router(rate_limit_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Rate Limit router")
    except ImportError as exc:
        _logger.warning("rate_limit_router not available: %s", exc)

    try:
        from apps.api.tenant_rate_limiter_router import router as tenant_rate_limiter_router  # noqa: PLC0415
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
        from apps.api.sla_management_router import router as sla_management_router  # noqa: PLC0415
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
        from apps.api.observability_router import router as observability_router  # noqa: PLC0415
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
        from apps.api.bulk_operations_router import router as bulk_operations_router  # noqa: PLC0415
        app.include_router(bulk_operations_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Bulk Operations router")
    except ImportError as exc:
        _logger.warning("bulk_operations_router not available: %s", exc)

    try:
        from apps.api.changelog_router import router as changelog_router  # noqa: PLC0415
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
        from apps.api.feature_flag_router import router as feature_flag_router  # noqa: PLC0415
        app.include_router(feature_flag_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Feature Flag router")
    except ImportError as exc:
        _logger.warning("feature_flag_router not available: %s", exc)

    try:
        from apps.api.log_management_router import router as log_management_router  # noqa: PLC0415
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
        from apps.api.local_file_store_router import router as local_file_store_router  # noqa: PLC0415
        app.include_router(local_file_store_router)
        _logger.info("Mounted Local File Store router")
    except ImportError as exc:
        _logger.warning("local_file_store_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Security tooling / health / telemetry / registry / query / automation
    # (formerly ~L6455-L7580 in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.security_health_router import router as security_health_router  # noqa: PLC0415
        app.include_router(security_health_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Security Health router at /api/v1/security-health")
    except ImportError as exc:
        _logger.warning("security_health_router not available: %s", exc)

    try:
        from apps.api.security_telemetry_router import router as security_telemetry_router  # noqa: PLC0415
        app.include_router(security_telemetry_router)
        _logger.info("Mounted Security Telemetry router")
    except ImportError as exc:
        _logger.warning("security_telemetry_router not available: %s", exc)

    try:
        from apps.api.security_registry_router import router as security_registry_router  # noqa: PLC0415
        app.include_router(security_registry_router)
        _logger.info("Mounted Security Registry router")
    except ImportError as exc:
        _logger.warning("security_registry_router not available: %s", exc)

    try:
        from apps.api.security_query_router import router as security_query_router  # noqa: PLC0415
        app.include_router(security_query_router)
        _logger.info("Mounted Security Query Language router")
    except ImportError as exc:
        _logger.warning("security_query_router not available: %s", exc)

    try:
        from apps.api.security_automation_router import router as security_automation_router  # noqa: PLC0415
        app.include_router(security_automation_router)
        _logger.info("Mounted Security Automation router at /api/v1/security-automation")
    except ImportError as exc:
        _logger.warning("security_automation_router not available: %s", exc)

    try:
        from apps.api.security_data_pipeline_router import router as security_data_pipeline_router  # noqa: PLC0415
        app.include_router(security_data_pipeline_router)
        _logger.info("Mounted Security Data Pipeline router")
    except ImportError as exc:
        _logger.warning("security_data_pipeline_router not available: %s", exc)

    try:
        from apps.api.security_tool_inventory_router import router as security_tool_inventory_router  # noqa: PLC0415
        app.include_router(security_tool_inventory_router)
        _logger.info("Mounted Security Tool Inventory router at /api/v1/tool-inventory")
    except ImportError as exc:
        _logger.warning("security_tool_inventory_router not available: %s", exc)

    # ------------------------------------------------------------------
    # LLM loop metrics / user analytics / upgrade path / air gap bundle
    # (formerly ~L3689 expanded section in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.llm_loop_metrics_router import router as llm_loop_metrics_router  # noqa: PLC0415
        app.include_router(llm_loop_metrics_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("read:findings"))])
        _logger.info("Mounted LLM Loop Telemetry router")
    except ImportError as exc:
        _logger.warning("llm_loop_metrics_router not available: %s", exc)

    try:
        from apps.api.user_analytics_router import router as user_analytics_router  # noqa: PLC0415
        app.include_router(user_analytics_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted User Analytics router")
    except ImportError as exc:
        _logger.warning("user_analytics_router not available: %s", exc)

    try:
        from apps.api.upgrade_path_router import router as upgrade_path_router  # noqa: PLC0415
        app.include_router(upgrade_path_router)
        _logger.info("Mounted Upgrade Path Resolver router at /api/v1/upgrade-path")
    except ImportError as exc:
        _logger.warning("upgrade_path_router not available: %s", exc)

    try:
        from apps.api.air_gap_bundle_router import router as air_gap_bundle_router  # noqa: PLC0415
        app.include_router(air_gap_bundle_router)
        _logger.info("Mounted Air-Gap Bundle router at /api/v1/air-gap")
    except ImportError as exc:
        _logger.warning("air_gap_bundle_router not available: %s", exc)

    # ------------------------------------------------------------------
    # Council / GraphRAG enhanced / workflow engine / versioning
    # (formerly scattered in app.py)
    # ------------------------------------------------------------------

    try:
        from apps.api.council_enhanced_router import router as council_enhanced_router  # noqa: PLC0415
        app.include_router(council_enhanced_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Council Enhanced router")
    except ImportError as exc:
        _logger.warning("council_enhanced_router not available: %s", exc)

    try:
        from apps.api.workflow_engine_router import router as workflow_engine_router  # noqa: PLC0415
        app.include_router(workflow_engine_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Workflow Engine router")
    except ImportError as exc:
        _logger.warning("workflow_engine_router not available: %s", exc)

    try:
        from apps.api.versioning_router import router as versioning_router  # noqa: PLC0415
        app.include_router(versioning_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted API Versioning router")
    except ImportError as exc:
        _logger.warning("versioning_router not available: %s", exc)

    try:
        from apps.api.webhook_events_router import router as webhook_events_router  # noqa: PLC0415
        app.include_router(webhook_events_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Webhook Events router")
    except ImportError as exc:
        _logger.warning("webhook_events_router not available: %s", exc)

    try:
        from apps.api.app_config_router import router as app_config_router  # noqa: PLC0415
        app.include_router(
            app_config_router,
            dependencies=[Depends(_verify_api_key), Depends(_require_scope("write:findings"))],
        )
        _logger.info("Mounted APP_ID Configuration router")
    except ImportError as exc:
        _logger.warning("app_config_router not available: %s", exc)

    try:
        from apps.api.playbook_marketplace_router import router as playbook_marketplace_router  # noqa: PLC0415
        app.include_router(playbook_marketplace_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Playbook Marketplace router")
    except ImportError as exc:
        _logger.warning("playbook_marketplace_router not available: %s", exc)

    try:
        from apps.api.org_hierarchy_router import router as org_hierarchy_router  # noqa: PLC0415
        app.include_router(org_hierarchy_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted Org Hierarchy router")
    except ImportError as exc:
        _logger.warning("org_hierarchy_router not available: %s", exc)
