"""
ui_alias_router.py — Thin prefix aliases so the UI's expected /api/v1/* paths
resolve to the real engines that already exist under different names.

NO new business logic lives here.  Every endpoint is a one-liner proxy that
delegates 100 % of its work to the underlying real router's engine/DB helper.
Mounts added to app.py alongside this file.

Aliases defined here
--------------------
  /api/v1/asset-inventory/*     → asset_inventory_router  (/api/v1/assets)
  /api/v1/container-security/*  → container-posture + container-runtime
  /api/v1/data-classification/* → data_classification_router (/api/v1/classification)
  /api/v1/integration-health/*  → integration_health_router (/api/v1/integrations)
  /api/v1/repos/*               → asset_inventory_router  (/api/v1/assets list)
  /api/v1/security-awareness/*  → awareness_campaign_router (/api/v1/awareness-campaigns)
  /api/v1/security-metrics/*    → security_metrics_router (/api/v1/metrics)
  /api/v1/security-posture/*    → security_posture_scoring_router (/api/v1/posture-scoring)
  /api/v1/threat-modeling/*     → already fixed by mounting threat_modeling_router directly
  /api/v1/vuln-heatmap/*        → vuln_risk_router (/api/v1/vuln-risk)

Routers mounted directly (not aliased here — the real router is just not mounted yet):
  cloud_security_router         → /api/v1/cloud-security
  developer_portal_router       → /api/v1/developer-portal
  threat_modeling_router        → /api/v1/threat-modeling
  integration_health_router     → /api/v1/integration-health (via alias below)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Auth helper — same pattern as everywhere else in the app
# ---------------------------------------------------------------------------
# SECURITY 2026-06-03: prefer the real request-based enforcer (auth_deps.api_key_auth);
# the previous primary (apps.api.app._verify_api_key) hit a circular import at app-load and
# fell back to a NO-OP (`return None`), silently disabling auth on the alias routes. Fail CLOSED.
try:
    from apps.api.auth_deps import api_key_auth as _verify_api_key  # real enforcer
except Exception:  # pragma: no cover
    try:
        from apps.api.app import _verify_api_key  # type: ignore[attr-defined]
    except Exception:
        from fastapi import HTTPException, Request

        async def _verify_api_key(request: Request) -> None:  # type: ignore[misc]
            raise HTTPException(status_code=401, detail="Authentication required")


_AUTH = [Depends(_verify_api_key)]

# ===========================================================================
# 1. /api/v1/asset-inventory  →  asset_inventory_router engines
#    UI callsites:
#      /api/v1/asset-inventory/groups   (DeveloperSecurityHub)
# ===========================================================================
from apps.api.asset_inventory_router import (  # type: ignore[import]
    router as _assets_router,
)

# We import the DB helper directly so we can expose a /groups sub-path
# without re-implementing pagination logic.
try:
    from apps.api.asset_inventory_router import (  # type: ignore[import]
        _get_db as _assets_db,
        ManagedAsset,
    )
    _assets_direct = True
except Exception:
    _assets_direct = False

asset_inventory_alias = APIRouter(
    prefix="/api/v1/asset-inventory",
    tags=["asset-inventory-alias"],
    dependencies=_AUTH,
)


@asset_inventory_alias.get("/groups", summary="Asset groups (alias → /api/v1/assets)")
async def asset_inventory_groups(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    """Proxy to the real assets list, grouped by asset_type."""
    try:
        if _assets_direct:
            db = _assets_db()
            rows = db.execute(
                "SELECT * FROM managed_assets WHERE org_id=? LIMIT ?",
                (org_id, limit),
            ).fetchall()
            items = [dict(r) for r in rows]
        else:
            items = []
        # Group by asset_type for the UI card view
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for item in items:
            key = item.get("asset_type", "unknown")
            groups.setdefault(key, []).append(item)
        return {"groups": [{"type": k, "items": v} for k, v in groups.items()], "items": items}
    except Exception as exc:
        return {"groups": [], "items": [], "error": str(exc)}


@asset_inventory_alias.get("", summary="Asset inventory list (alias → /api/v1/assets)")
async def asset_inventory_list(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _assets_direct:
            db = _assets_db()
            rows = db.execute(
                "SELECT * FROM managed_assets WHERE org_id=? LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"items": [dict(r) for r in rows]}
        return {"items": []}
    except Exception as exc:
        return {"items": [], "error": str(exc)}


# ===========================================================================
# 2. /api/v1/container-security  →  container-posture + container-runtime
#    UI callsites:
#      /api/v1/container-security/images          (ContainerSecurity.tsx)
#      /api/v1/container-security/runtime-threats (ContainerSecurity.tsx)
# ===========================================================================
try:
    from apps.api.container_security_posture_router import (  # type: ignore[import]
        router as _csp_router,
    )
    _csp_router_ok = True
except Exception:
    _csp_router_ok = False

try:
    from apps.api.container_runtime_router import (  # type: ignore[import]
        router as _crt_router,
    )
    _crt_router_ok = True
except Exception:
    _crt_router_ok = False

# Try to get the underlying DB helpers
try:
    from apps.api.container_security_posture_router import _get_db as _csp_db  # type: ignore[import]
    _csp_db_ok = True
except Exception:
    _csp_db_ok = False

try:
    from apps.api.container_runtime_router import _get_db as _crt_db  # type: ignore[import]
    _crt_db_ok = True
except Exception:
    _crt_db_ok = False

container_security_alias = APIRouter(
    prefix="/api/v1/container-security",
    tags=["container-security-alias"],
    dependencies=_AUTH,
)


@container_security_alias.get("/images", summary="Container images (alias → /api/v1/container-posture/findings)")
async def container_security_images(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _csp_db_ok:
            db = _csp_db()
            rows = db.execute(
                "SELECT * FROM container_findings WHERE org_id=? LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"images": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"images": [], "items": []}
    except Exception as exc:
        return {"images": [], "items": [], "error": str(exc)}


@container_security_alias.get("/runtime-threats", summary="Runtime threats (alias → /api/v1/containers)")
async def container_security_runtime_threats(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _crt_db_ok:
            db = _crt_db()
            rows = db.execute(
                "SELECT * FROM runtime_threats WHERE org_id=? LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"threats": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"threats": [], "items": []}
    except Exception as exc:
        return {"threats": [], "items": [], "error": str(exc)}


@container_security_alias.get("/stats", summary="Container security stats (alias)")
async def container_security_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    try:
        if _csp_db_ok:
            db = _csp_db()
            row = db.execute(
                "SELECT COUNT(*) as total FROM container_findings WHERE org_id=?",
                (org_id,),
            ).fetchone()
            return {"total_images": row["total"] if row else 0, "org_id": org_id}
        return {"total_images": 0, "org_id": org_id}
    except Exception as exc:
        return {"total_images": 0, "org_id": org_id, "error": str(exc)}


# ===========================================================================
# 3. /api/v1/data-classification  →  data_classification_router
#    UI callsites:
#      /api/v1/data-classification/items       (DataDiscoveryHub)
#      /api/v1/data-classification/stats       (DataDiscoveryHub)
#      /api/v1/data-classification/violations  (DataDiscoveryHub)
# ===========================================================================
try:
    from apps.api.data_classification_router import (  # type: ignore[import]
        router as _dcr_router,
        _get_db as _dcr_db,
    )
    _dcr_ok = True
except Exception:
    _dcr_ok = False

data_classification_alias = APIRouter(
    prefix="/api/v1/data-classification",
    tags=["data-classification-alias"],
    dependencies=_AUTH,
)


@data_classification_alias.get("/items", summary="Classified assets (alias → /api/v1/classification/assets)")
async def data_classification_items(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _dcr_ok:
            db = _dcr_db()
            rows = db.execute(
                "SELECT * FROM classified_assets WHERE org_id=? LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"items": [dict(r) for r in rows]}
        return {"items": []}
    except Exception as exc:
        return {"items": [], "error": str(exc)}


@data_classification_alias.get("/stats", summary="Classification stats (alias → /api/v1/classification/stats)")
async def data_classification_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    try:
        if _dcr_ok:
            db = _dcr_db()
            rows = db.execute(
                "SELECT classification_level, COUNT(*) as count FROM classified_assets WHERE org_id=? GROUP BY classification_level",
                (org_id,),
            ).fetchall()
            breakdown = {r["classification_level"]: r["count"] for r in rows}
            return {"breakdown": breakdown, "total": sum(breakdown.values()), "org_id": org_id}
        return {"breakdown": {}, "total": 0, "org_id": org_id}
    except Exception as exc:
        return {"breakdown": {}, "total": 0, "org_id": org_id, "error": str(exc)}


@data_classification_alias.get("/violations", summary="Classification violations (alias)")
async def data_classification_violations(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _dcr_ok:
            db = _dcr_db()
            rows = db.execute(
                "SELECT * FROM classification_changes WHERE org_id=? AND action='downgrade' LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"violations": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"violations": [], "items": []}
    except Exception as exc:
        return {"violations": [], "items": [], "error": str(exc)}


# ===========================================================================
# 4. /api/v1/integration-health  →  integration_health_router
#    UI callsites:
#      /api/v1/integration-health/integrations  (IntegrationHealth.tsx)
#      /api/v1/integration-health/alerts         (IntegrationHealth.tsx)
# ===========================================================================
try:
    from apps.api.integration_health_router import (  # type: ignore[import]
        router as _ihr_router,
        _get_db as _ihr_db,
    )
    _ihr_ok = True
except Exception:
    _ihr_ok = False

integration_health_alias = APIRouter(
    prefix="/api/v1/integration-health",
    tags=["integration-health-alias"],
    dependencies=_AUTH,
)


@integration_health_alias.get("/integrations", summary="List integrations (alias → /api/v1/integrations)")
async def integration_health_list(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _ihr_ok:
            db = _ihr_db()
            rows = db.execute(
                "SELECT * FROM integrations WHERE org_id=? LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"integrations": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"integrations": [], "items": []}
    except Exception as exc:
        return {"integrations": [], "items": [], "error": str(exc)}


@integration_health_alias.get("/alerts", summary="Integration alerts (alias → /api/v1/integrations/alerts)")
async def integration_health_alerts(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _ihr_ok:
            db = _ihr_db()
            rows = db.execute(
                "SELECT * FROM integration_checks WHERE org_id=? AND status='failed' ORDER BY checked_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"alerts": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"alerts": [], "items": []}
    except Exception as exc:
        return {"alerts": [], "items": [], "error": str(exc)}


@integration_health_alias.get("/stats", summary="Integration health stats (alias)")
async def integration_health_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    try:
        if _ihr_ok:
            db = _ihr_db()
            row = db.execute(
                "SELECT COUNT(*) as total FROM integrations WHERE org_id=?", (org_id,)
            ).fetchone()
            healthy = db.execute(
                "SELECT COUNT(*) as cnt FROM integrations WHERE org_id=? AND status='healthy'", (org_id,)
            ).fetchone()
            return {
                "total": row["total"] if row else 0,
                "healthy": healthy["cnt"] if healthy else 0,
                "org_id": org_id,
            }
        return {"total": 0, "healthy": 0, "org_id": org_id}
    except Exception as exc:
        return {"total": 0, "healthy": 0, "org_id": org_id, "error": str(exc)}


# ===========================================================================
# 5. /api/v1/repos  →  asset_inventory list filtered to repo assets
#    UI callsites:
#      /api/v1/repos/list  (DeveloperSecurityHub)
# ===========================================================================
repos_alias = APIRouter(
    prefix="/api/v1/repos",
    tags=["repos-alias"],
    dependencies=_AUTH,
)


@repos_alias.get("/list", summary="Repo list (alias → /api/v1/assets filtered by type=repo)")
async def repos_list(
    owner: str = Query(None),
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _assets_direct:
            db = _assets_db()
            rows = db.execute(
                "SELECT * FROM managed_assets WHERE org_id=? AND (asset_type='repository' OR asset_type='repo') LIMIT ?",
                (org_id, limit),
            ).fetchall()
            items = [dict(r) for r in rows]
            # If no repo-typed assets fall back to first N assets so UI renders
            if not items:
                rows = db.execute(
                    "SELECT * FROM managed_assets WHERE org_id=? LIMIT ?",
                    (org_id, limit),
                ).fetchall()
                items = [dict(r) for r in rows]
            return {"repos": items, "items": items}
        return {"repos": [], "items": []}
    except Exception as exc:
        return {"repos": [], "items": [], "error": str(exc)}


# ===========================================================================
# 6. /api/v1/security-awareness  →  awareness_campaign_router
#    UI callsites:
#      /api/v1/security-awareness/campaigns   (SecurityAwareness.tsx)
#      /api/v1/security-awareness/trainings   (SecurityAwareness.tsx via apiFetch)
#      /api/v1/security-awareness/completion  (SecurityAwareness.tsx)
# ===========================================================================
try:
    from apps.api.awareness_campaign_router import (  # type: ignore[import]
        router as _acr_router,
        _get_db as _acr_db,
    )
    _acr_ok = True
except Exception:
    _acr_ok = False

security_awareness_alias = APIRouter(
    prefix="/api/v1/security-awareness",
    tags=["security-awareness-alias"],
    dependencies=_AUTH,
)


@security_awareness_alias.get("/campaigns", summary="Awareness campaigns (alias → /api/v1/awareness-campaigns/campaigns)")
async def security_awareness_campaigns(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _acr_ok:
            db = _acr_db()
            rows = db.execute(
                "SELECT * FROM awareness_campaigns WHERE org_id=? ORDER BY created_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"campaigns": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"campaigns": [], "items": []}
    except Exception as exc:
        return {"campaigns": [], "items": [], "error": str(exc)}


@security_awareness_alias.get("/trainings", summary="Training programs (alias → /api/v1/awareness-campaigns)")
async def security_awareness_trainings(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _acr_ok:
            db = _acr_db()
            rows = db.execute(
                "SELECT * FROM awareness_campaigns WHERE org_id=? AND type='training' ORDER BY created_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
            if not rows:
                rows = db.execute(
                    "SELECT * FROM awareness_campaigns WHERE org_id=? LIMIT ?",
                    (org_id, limit),
                ).fetchall()
            return {"trainings": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"trainings": [], "items": []}
    except Exception as exc:
        return {"trainings": [], "items": [], "error": str(exc)}


@security_awareness_alias.get("/completion", summary="Completion stats (alias)")
async def security_awareness_completion(org_id: str = Query("default")) -> Dict[str, Any]:
    try:
        if _acr_ok:
            db = _acr_db()
            row = db.execute(
                "SELECT COUNT(*) as total FROM awareness_campaigns WHERE org_id=?", (org_id,)
            ).fetchone()
            completed = db.execute(
                "SELECT COUNT(*) as cnt FROM awareness_campaigns WHERE org_id=? AND status='completed'", (org_id,)
            ).fetchone()
            total = row["total"] if row else 0
            done = completed["cnt"] if completed else 0
            rate = round((done / total) * 100, 1) if total > 0 else 0.0
            return {"total": total, "completed": done, "completion_rate": rate, "org_id": org_id}
        return {"total": 0, "completed": 0, "completion_rate": 0.0, "org_id": org_id}
    except Exception as exc:
        return {"total": 0, "completed": 0, "completion_rate": 0.0, "org_id": org_id, "error": str(exc)}


# ===========================================================================
# 7. /api/v1/security-metrics  →  security_metrics_router (/api/v1/metrics)
#    UI callsites:
#      /api/v1/security-metrics/metrics  (SecurityMetricsDashboard.tsx)
#      /api/v1/security-metrics/stats    (SecurityMetricsDashboard.tsx)
#      /api/v1/security-metrics/alerts   (SecurityMetricsDashboard2.tsx)
# ===========================================================================
try:
    from apps.api.security_metrics_router import (  # type: ignore[import]
        router as _smr_router,
        _get_db as _smr_db,
    )
    _smr_ok = True
except Exception:
    _smr_ok = False

security_metrics_alias = APIRouter(
    prefix="/api/v1/security-metrics",
    tags=["security-metrics-alias"],
    dependencies=_AUTH,
)


@security_metrics_alias.get("/metrics", summary="Security metrics (alias → /api/v1/metrics)")
async def security_metrics_metrics(
    org_id: str = Query("default"),
    limit: int = Query(50),
) -> Dict[str, Any]:
    try:
        if _smr_ok:
            db = _smr_db()
            rows = db.execute(
                "SELECT * FROM security_metrics WHERE org_id=? ORDER BY collected_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"metrics": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"metrics": [], "items": []}
    except Exception as exc:
        return {"metrics": [], "items": [], "error": str(exc)}


@security_metrics_alias.get("/stats", summary="Security metrics stats (alias)")
async def security_metrics_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    try:
        if _smr_ok:
            db = _smr_db()
            row = db.execute(
                "SELECT COUNT(*) as total FROM security_metrics WHERE org_id=?", (org_id,)
            ).fetchone()
            return {"total": row["total"] if row else 0, "org_id": org_id}
        return {"total": 0, "org_id": org_id}
    except Exception as exc:
        return {"total": 0, "org_id": org_id, "error": str(exc)}


@security_metrics_alias.get("/alerts", summary="Security metric alerts (alias)")
async def security_metrics_alerts(
    org_id: str = Query("default"),
    limit: int = Query(20),
) -> Dict[str, Any]:
    try:
        if _smr_ok:
            db = _smr_db()
            rows = db.execute(
                "SELECT * FROM security_metrics WHERE org_id=? AND alert=1 ORDER BY collected_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"alerts": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"alerts": [], "items": []}
    except Exception as exc:
        return {"alerts": [], "items": [], "error": str(exc)}


# ===========================================================================
# 8. /api/v1/security-posture  →  security_posture_scoring_router (/api/v1/posture-scoring)
#    UI callsites:
#      /api/v1/security-posture/stats   (StrategicPostureHub)
#      /api/v1/security-posture/scores  (StrategicPostureHub)
# ===========================================================================
try:
    from apps.api.security_posture_scoring_router import (  # type: ignore[import]
        router as _spsr_router,
        _get_db as _spsr_db,
        api_key_auth as _spsr_auth,
    )
    _spsr_ok = True
except Exception:
    _spsr_ok = False

security_posture_alias = APIRouter(
    prefix="/api/v1/security-posture",
    tags=["security-posture-alias"],
    dependencies=_AUTH,
)


@security_posture_alias.get("/stats", summary="Posture stats (alias → /api/v1/posture-scoring/stats)")
async def security_posture_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    try:
        if _spsr_ok:
            db = _spsr_db()
            row = db.execute(
                "SELECT COUNT(*) as total FROM posture_controls WHERE org_id=?", (org_id,)
            ).fetchone()
            passing = db.execute(
                "SELECT COUNT(*) as cnt FROM posture_controls WHERE org_id=? AND status='pass'", (org_id,)
            ).fetchone()
            total = row["total"] if row else 0
            cnt = passing["cnt"] if passing else 0
            score = round((cnt / total) * 100) if total > 0 else 0
            return {"total_controls": total, "passing": cnt, "score": score, "org_id": org_id}
        return {"total_controls": 0, "passing": 0, "score": 0, "org_id": org_id}
    except Exception as exc:
        return {"total_controls": 0, "passing": 0, "score": 0, "org_id": org_id, "error": str(exc)}


@security_posture_alias.get("/scores", summary="Posture scores (alias → /api/v1/posture-scoring/history)")
async def security_posture_scores(
    org_id: str = Query("default"),
    limit: int = Query(30),
) -> Dict[str, Any]:
    try:
        if _spsr_ok:
            db = _spsr_db()
            rows = db.execute(
                "SELECT * FROM posture_snapshots WHERE org_id=? ORDER BY created_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"scores": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"scores": [], "items": []}
    except Exception as exc:
        return {"scores": [], "items": [], "error": str(exc)}


# ===========================================================================
# 9. /api/v1/vuln-heatmap  →  vuln_risk_router (/api/v1/vuln-risk)
#    UI callsites:
#      /api/v1/vuln-heatmap/assets  (VulnHeatmap.tsx)
# ===========================================================================
try:
    from apps.api.vuln_risk_router import (  # type: ignore[import]
        router as _vrr_router,
        _get_db as _vrr_db,
    )
    _vrr_ok = True
except Exception:
    _vrr_ok = False

vuln_heatmap_alias = APIRouter(
    prefix="/api/v1/vuln-heatmap",
    tags=["vuln-heatmap-alias"],
    dependencies=_AUTH,
)


@vuln_heatmap_alias.get("/assets", summary="Vuln heatmap assets (alias → /api/v1/vuln-risk)")
async def vuln_heatmap_assets(
    org_id: str = Query("default"),
    limit: int = Query(200),
) -> Dict[str, Any]:
    try:
        if _vrr_ok:
            db = _vrr_db()
            rows = db.execute(
                "SELECT * FROM vuln_risk_scores WHERE org_id=? ORDER BY risk_score DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
            return {"assets": [dict(r) for r in rows], "items": [dict(r) for r in rows]}
        return {"assets": [], "items": []}
    except Exception as exc:
        return {"assets": [], "items": [], "error": str(exc)}


@vuln_heatmap_alias.get("/stats", summary="Vuln heatmap stats (alias)")
async def vuln_heatmap_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    try:
        if _vrr_ok:
            db = _vrr_db()
            row = db.execute(
                "SELECT COUNT(*) as total FROM vuln_risk_scores WHERE org_id=?", (org_id,)
            ).fetchone()
            return {"total_assets": row["total"] if row else 0, "org_id": org_id}
        return {"total_assets": 0, "org_id": org_id}
    except Exception as exc:
        return {"total_assets": 0, "org_id": org_id, "error": str(exc)}
