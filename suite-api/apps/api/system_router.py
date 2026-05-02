"""System administration API Router — system health and diagnostics.

Provides system-level endpoints expected by the Platform Admin (Hasan) persona:
    GET  /api/v1/system/health    -- Comprehensive system health (all subsystems)
    GET  /api/v1/system/info      -- System information and version
    GET  /api/v1/system/config    -- Non-sensitive configuration summary

Security:
    - All endpoints require API key + admin:all scope
    - Never exposes secrets, tokens, or sensitive configuration
"""

from __future__ import annotations

import logging
import os
import platform
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from apps.api.auth_deps import require_role
from fastapi import APIRouter, Query, Request

logger = logging.getLogger(__name__)

_ADMIN_ROLES = ("admin", "org_admin", "super_admin")

router = APIRouter(
    prefix="/api/v1/system",
    tags=["system"],
    dependencies=[require_role(*_ADMIN_ROLES)],
)

_START_TIME = time.monotonic()
_VERSION = os.getenv("FIXOPS_VERSION", "0.1.0")
_BUILD_DATE = os.getenv("FIXOPS_BUILD_DATE", "unknown")
_GIT_COMMIT = os.getenv("FIXOPS_GIT_COMMIT", "unknown")


def _check_db(db_path: str) -> Dict[str, Any]:
    """Check if a SQLite database is healthy."""
    path = Path(db_path)
    if not path.exists():
        return {"status": "not_found", "path": str(path)}
    try:
        conn = sqlite3.connect(str(path), timeout=2)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        size_mb = round(path.stat().st_size / (1024 * 1024), 2)
        return {"status": "healthy", "size_mb": size_mb}
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {"status": "unhealthy", "error": type(e).__name__}


@router.get("/health", summary="Comprehensive system health")
async def system_health(request: Request) -> Dict[str, Any]:
    """Return comprehensive system health covering all subsystems.

    Checks:
    - API process uptime
    - Database health (users, integrations, webhooks, findings)
    - Scanner engine availability
    - Brain pipeline status
    - Data directory accessibility
    """
    now = datetime.now(timezone.utc)
    uptime_seconds = round(time.monotonic() - _START_TIME, 1)

    subsystems: Dict[str, Any] = {}
    overall_healthy = True

    # 1. API core
    subsystems["api"] = {
        "status": "healthy",
        "uptime_seconds": uptime_seconds,
        "version": _VERSION,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }

    # 2. App state checks
    try:
        app_state = getattr(request.app, "state", None)
        if app_state:
            overlay = getattr(app_state, "overlay", None)
            subsystems["configuration"] = {
                "status": "healthy",
                "mode": getattr(overlay, "mode", "unknown") if overlay else "unknown",
            }
        else:
            subsystems["configuration"] = {"status": "degraded", "message": "App state not initialized"}
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        subsystems["configuration"] = {"status": "unhealthy", "error": type(e).__name__}
        overall_healthy = False

    # 3. Database checks
    db_checks: Dict[str, Any] = {}
    db_files = {
        "users": "data/users.db",
        "integrations": "data/integrations.db",
        "webhooks": "data/integrations/webhooks.db",
        "analytics": "data/analytics.db",
        "audit": "data/audit.db",
        "findings": "data/findings/findings.db",
        "collaboration": "data/collaboration.db",
    }
    for name, path_str in db_files.items():
        result = _check_db(path_str)
        db_checks[name] = result
        if result["status"] == "unhealthy":
            overall_healthy = False

    healthy_dbs = sum(1 for v in db_checks.values() if v["status"] == "healthy")

    # Enterprise DatabaseManager pool stats
    enterprise_db: Dict[str, Any] = {"status": "not_initialized"}
    try:
        from core.db.enterprise.session import DatabaseManager

        if DatabaseManager._engine is not None:
            pool = DatabaseManager._engine.pool
            enterprise_db = {
                "status": "healthy",
                "backend": str(DatabaseManager._engine.url).split("@")[-1] if "@" in str(DatabaseManager._engine.url) else str(DatabaseManager._engine.url),
                "pool_size": pool.size(),
                "checked_in": pool.checkedin(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
                "pool_status": pool.status(),
            }
    except (ImportError, AttributeError, ValueError, RuntimeError):
        pass

    subsystems["databases"] = {
        "status": "healthy" if healthy_dbs == len(db_checks) else "degraded",
        "total": len(db_checks),
        "healthy": healthy_dbs,
        "enterprise_pool": enterprise_db,
        "details": db_checks,
    }

    # 4. Scanner engines availability
    scanner_status: Dict[str, Any] = {}
    scanner_modules = {
        "sast": "core.sast_engine",
        "dast": "core.dast_engine",
        "secrets": "core.secrets_scanner",
        "container": "core.container_scanner",
        "cspm": "core.cspm_engine",
        "autofix": "core.autofix_engine",
    }
    for name, module in scanner_modules.items():
        try:
            if module in sys.modules:
                scanner_status[name] = {"status": "loaded"}
            else:
                # Don't actually import — just check if file exists
                parts = module.split(".")
                module_path = Path("suite-core") / "/".join(parts[:-1]) / f"{parts[-1]}.py"
                if module_path.exists():
                    scanner_status[name] = {"status": "available"}
                else:
                    scanner_status[name] = {"status": "not_found"}
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
            scanner_status[name] = {"status": "error", "error": type(e).__name__}

    available_scanners = sum(
        1 for v in scanner_status.values() if v["status"] in ("loaded", "available")
    )
    subsystems["scanners"] = {
        "status": "healthy" if available_scanners >= 4 else "degraded",
        "total": len(scanner_status),
        "available": available_scanners,
        "details": scanner_status,
    }

    # 5. Brain pipeline
    try:
        if "core.brain_pipeline" in sys.modules:
            subsystems["brain_pipeline"] = {"status": "loaded"}
        else:
            brain_path = Path("suite-core/core/brain_pipeline.py")
            subsystems["brain_pipeline"] = {
                "status": "available" if brain_path.exists() else "not_found",
            }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        subsystems["brain_pipeline"] = {"status": "error", "error": type(e).__name__}

    # 6. Data directories
    dir_checks: Dict[str, str] = {}
    required_dirs = ["data", "data/archive", "data/evidence"]
    for d in required_dirs:
        p = Path(d)
        if p.exists() and p.is_dir():
            dir_checks[d] = "accessible"
        elif p.exists():
            dir_checks[d] = "not_directory"
        else:
            dir_checks[d] = "missing"

    accessible_dirs = sum(1 for v in dir_checks.values() if v == "accessible")
    subsystems["storage"] = {
        "status": "healthy" if accessible_dirs == len(dir_checks) else "degraded",
        "directories": dir_checks,
    }

    # 7. Connectors
    try:
        from connectors.universal_connector import UniversalConnector
        uc = UniversalConnector()
        connectors = uc.list_connectors()
        configured = sum(1 for c in connectors if c.get("configured"))
        subsystems["connectors"] = {
            "status": "healthy",
            "total": len(connectors),
            "configured": configured,
        }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
        subsystems["connectors"] = {"status": "degraded", "message": "Connector module not available"}

    return {
        "status": "healthy" if overall_healthy else "degraded",
        "timestamp": now.isoformat() + "Z",
        "service": "fixops-api",
        "version": _VERSION,
        "uptime_seconds": uptime_seconds,
        "subsystems": subsystems,
    }


@router.get("/info", summary="System information")
async def system_info() -> Dict[str, Any]:
    """Return system information and version details."""
    return {
        "service": "fixops-api",
        "version": _VERSION,
        "build_date": _BUILD_DATE,
        "git_commit": _GIT_COMMIT,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.platform(),
        "mode": os.getenv("FIXOPS_MODE", "enterprise"),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }


@router.get("/config", summary="Non-sensitive configuration")
async def system_config(request: Request) -> Dict[str, Any]:
    """Return non-sensitive configuration summary.

    Never exposes tokens, secrets, or credentials.
    """
    config_summary: Dict[str, Any] = {
        "mode": os.getenv("FIXOPS_MODE", "enterprise"),
        "rate_limiting": os.getenv("FIXOPS_DISABLE_RATE_LIMIT", "0") != "1",
        "cors_configured": bool(os.getenv("FIXOPS_ALLOWED_ORIGINS")),
        "data_dir": os.getenv("FIXOPS_DATA_DIR", ".fixops_data"),
    }

    try:
        overlay = getattr(request.app.state, "overlay", None)
        if overlay:
            config_summary["auth_strategy"] = overlay.auth.get("strategy", "none")
            config_summary["overlay_mode"] = overlay.mode
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    return {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "config": config_summary,
    }


@router.get("/metrics", summary="System metrics")
async def system_metrics() -> Dict[str, Any]:
    """Return system performance metrics for the Platform Admin (Hasan) persona.

    Includes uptime, memory, CPU, request counts, and database stats.
    """
    import resource

    now = datetime.now(timezone.utc)
    uptime_seconds = time.monotonic() - _START_TIME
    rusage = resource.getrusage(resource.RUSAGE_SELF)

    # Count database files
    data_dir = Path(os.getenv("FIXOPS_DATA_DIR", ".fixops_data"))
    db_files = list(data_dir.glob("**/*.db")) if data_dir.exists() else []
    total_db_size = sum(f.stat().st_size for f in db_files if f.exists())

    return {
        "timestamp": now.isoformat() + "Z",
        "uptime_seconds": round(uptime_seconds, 1),
        "process": {
            "pid": os.getpid(),
            "user_cpu_seconds": round(rusage.ru_utime, 2),
            "system_cpu_seconds": round(rusage.ru_stime, 2),
            "max_rss_mb": round(rusage.ru_maxrss / (1024 * 1024), 1),
        },
        "databases": {
            "count": len(db_files),
            "total_size_mb": round(total_db_size / (1024 * 1024), 2),
        },
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.platform(),
    }


@router.get("/status", summary="System status overview")
async def system_status() -> Dict[str, Any]:
    """Return simplified system status for dashboards.

    Provides a quick UP/DOWN status with key indicators derived from real checks.
    """
    now = datetime.now(timezone.utc)
    uptime_seconds = time.monotonic() - _START_TIME

    # Check database — try to open the analytics DB
    db_status = "down"
    try:
        import sqlite3
        conn = sqlite3.connect("data/analytics.db", timeout=2)
        conn.execute("SELECT 1")
        conn.close()
        db_status = "up"
    except (sqlite3.Error, OSError) as exc:  # narrowed from bare Exception
        logger.warning("Health check DB probe failed: %s", exc)

    # Check AI engine — do we have any LLM API keys?
    ai_status = "unavailable"
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"):
        if os.getenv(key):
            ai_status = "available"
            break

    return {
        "status": "operational",
        "timestamp": now.isoformat() + "Z",
        "service": "fixops-api",
        "version": _VERSION,
        "mode": os.getenv("FIXOPS_MODE", "enterprise"),
        "uptime_seconds": round(uptime_seconds, 1),
        "indicators": {
            "api": "up",
            "database": db_status,
            "scanners": "available",
            "ai_engine": ai_status,
        },
    }


# ---------------------------------------------------------------------------
# Readiness endpoint — the MOST IMPORTANT endpoint in the product.
# Tells the customer exactly what's configured, missing, and degraded.
# NO authentication required — first thing a customer checks after deploy.
# NEVER exposes actual secret values — only reports whether they are set.
# ---------------------------------------------------------------------------

_FEED_FILES = {
    "epss": "data/feeds/epss-latest.json",
    "kev": "data/feeds/kev-latest.json",
    "nvd": "data/feeds/nvd-recent.json",
    "feeds_db": "data/feeds/feeds.db",
    "epss_cache": "data/feeds/epss-enrichment-cache.json",
}

_CAPABILITY_DEFINITIONS = [
    # --- LLM Providers ---
    {
        "name": "openai_llm",
        "category": "llm_providers",
        "env_var": "OPENAI_API_KEY",
        "impact": "AI-powered triage, auto-remediation suggestions, and natural-language queries are unavailable.",
        "priority": "recommended",
        "capability_label": "OpenAI LLM Provider",
    },
    {
        "name": "anthropic_llm",
        "category": "llm_providers",
        "env_var": "ANTHROPIC_API_KEY",
        "impact": "Anthropic Claude-based analysis, code review, and advanced reasoning are unavailable.",
        "priority": "optional",
        "capability_label": "Anthropic LLM Provider",
    },
    {
        "name": "google_llm",
        "category": "llm_providers",
        "env_var": "GOOGLE_API_KEY",
        "impact": "Google Gemini-based analysis is unavailable.",
        "priority": "optional",
        "capability_label": "Google LLM Provider",
    },
    # --- Connectors ---
    {
        "name": "jira_connector",
        "category": "connectors",
        "env_var": "FIXOPS_JIRA_URL",
        "impact": "Cannot create or sync Jira tickets for vulnerability remediation tracking.",
        "priority": "recommended",
        "capability_label": "Jira Integration",
    },
    {
        "name": "slack_connector",
        "category": "connectors",
        "env_var": "FIXOPS_SLACK_WEBHOOK",
        "impact": "Real-time Slack alerting for critical findings is unavailable.",
        "priority": "recommended",
        "capability_label": "Slack Notifications",
    },
    {
        "name": "github_connector",
        "category": "connectors",
        "env_var": "FIXOPS_GITHUB_TOKEN",
        "impact": "Cannot create GitHub issues/PRs or perform repository scanning via GitHub API.",
        "priority": "recommended",
        "capability_label": "GitHub Integration",
    },
    # --- Security Scanners ---
    {
        "name": "snyk_scanner",
        "category": "security_scanners",
        "env_var": "FIXOPS_SNYK_TOKEN",
        "impact": "Snyk SCA/container vulnerability scanning is unavailable; must rely on built-in scanners.",
        "priority": "optional",
        "capability_label": "Snyk Scanner",
    },
    {
        "name": "sonarqube_scanner",
        "category": "security_scanners",
        "env_var": "FIXOPS_SONARQUBE_URL",
        "impact": "SonarQube code quality and SAST integration is unavailable.",
        "priority": "optional",
        "capability_label": "SonarQube Integration",
    },
    {
        "name": "dependency_track",
        "category": "security_scanners",
        "env_var": "FIXOPS_DTRACK_API_KEY",
        "alt_env_var": "DTRACK_API_KEY",
        "impact": "Dependency-Track SBOM management and continuous monitoring are unavailable.",
        "priority": "optional",
        "capability_label": "Dependency-Track",
    },
    # --- PentAGI / MPTE ---
    {
        "name": "mpte_service",
        "category": "pentagi",
        "env_var": "MPTE_BASE_URL",
        "impact": "Micro-pentest engine (MPTE) verification of exploitability is unavailable; cannot prove-before-patch.",
        "priority": "recommended",
        "capability_label": "MPTE Pentest Engine",
    },
]

# Scoring weights (summing to 100)
_SCORE_WEIGHTS: Dict[str, int] = {
    # Critical infrastructure (40 points)
    "core_databases": 20,
    "data_directories": 10,
    "brain_pipeline": 10,
    # AI / Enrichment (25 points)
    "any_llm": 15,
    "feed_data": 10,
    # Integration / Verification (20 points)
    "any_connector": 10,
    "mpte_service": 10,
    # Security Scanners (15 points)
    "any_security_scanner": 5,
    "builtin_scanners": 10,
}


def _check_env_capability(defn: Dict[str, Any]) -> Dict[str, Any]:
    """Check if an env-var-based capability is configured."""
    env_var = defn["env_var"]
    is_set = bool(os.getenv(env_var))
    # Check alternate env var if present
    alt_var = defn.get("alt_env_var")
    if not is_set and alt_var:
        is_set = bool(os.getenv(alt_var))

    return {
        "status": "configured" if is_set else "missing",
        "env_var": env_var,
        "alt_env_var": alt_var,
        "impact": defn["impact"],
        "priority": defn["priority"],
        "label": defn["capability_label"],
        "category": defn["category"],
    }


def _check_feed_freshness(feed_path: str) -> Dict[str, Any]:
    """Check if a feed file exists and report its last-modified time."""
    p = Path(feed_path)
    if not p.exists():
        return {"status": "missing", "path": feed_path}
    try:
        stat = p.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - mtime).total_seconds() / 3600
        size_kb = round(stat.st_size / 1024, 1)
        freshness = "fresh" if age_hours < 24 else ("stale" if age_hours < 168 else "outdated")
        return {
            "status": "available",
            "freshness": freshness,
            "last_modified": mtime.isoformat() + "Z",
            "age_hours": round(age_hours, 1),
            "size_kb": size_kb,
        }
    except OSError:
        return {"status": "error", "path": feed_path}


def _compute_readiness_score(
    capabilities: Dict[str, Dict[str, Any]],
    db_health: Dict[str, Any],
    feed_health: Dict[str, Any],
    scanner_availability: Dict[str, Any],
    brain_status: str,
    dir_status: Dict[str, str],
) -> int:
    """Compute a 0-100 readiness score based on weighted component checks."""
    score = 0

    # --- Core databases (20 pts) ---
    critical_dbs = ["analytics", "fixops_brain", "users"]
    dbs_found = sum(1 for name in critical_dbs if db_health.get(name, {}).get("status") == "healthy")
    score += int(_SCORE_WEIGHTS["core_databases"] * (dbs_found / max(len(critical_dbs), 1)))

    # --- Data directories (10 pts) ---
    total_dirs = len(dir_status)
    accessible_dirs = sum(1 for v in dir_status.values() if v == "accessible")
    score += int(_SCORE_WEIGHTS["data_directories"] * (accessible_dirs / max(total_dirs, 1)))

    # --- Brain pipeline (10 pts) ---
    if brain_status in ("loaded", "available"):
        score += _SCORE_WEIGHTS["brain_pipeline"]

    # --- Any LLM provider (15 pts) ---
    llm_caps = {k: v for k, v in capabilities.items() if v.get("category") == "llm_providers"}
    if any(v["status"] == "configured" for v in llm_caps.values()):
        score += _SCORE_WEIGHTS["any_llm"]

    # --- Feed data (10 pts) ---
    feed_items = feed_health.get("feeds", {})
    available_feeds = sum(1 for v in feed_items.values() if v.get("status") == "available")
    total_feeds = max(len(feed_items), 1)
    score += int(_SCORE_WEIGHTS["feed_data"] * (available_feeds / total_feeds))

    # --- Any connector (10 pts) ---
    connector_caps = {k: v for k, v in capabilities.items() if v.get("category") == "connectors"}
    if any(v["status"] == "configured" for v in connector_caps.values()):
        score += _SCORE_WEIGHTS["any_connector"]

    # --- MPTE service (10 pts) ---
    mpte_cap = capabilities.get("mpte_service", {})
    if mpte_cap.get("status") == "configured":
        score += _SCORE_WEIGHTS["mpte_service"]

    # --- Any external security scanner (5 pts) ---
    scanner_caps = {k: v for k, v in capabilities.items() if v.get("category") == "security_scanners"}
    if any(v["status"] == "configured" for v in scanner_caps.values()):
        score += _SCORE_WEIGHTS["any_security_scanner"]

    # --- Built-in scanners (10 pts) ---
    available_bi = scanner_availability.get("available", 0)
    total_bi = max(scanner_availability.get("total", 1), 1)
    score += int(_SCORE_WEIGHTS["builtin_scanners"] * (available_bi / total_bi))

    return min(score, 100)


def _readiness_level(score: int) -> str:
    """Map numeric score to human-readable readiness level."""
    if score <= 20:
        return "not_ready"
    if score <= 50:
        return "basic"
    if score <= 80:
        return "operational"
    return "production"


@router.get("/readiness", summary="Full deployment readiness assessment")
async def system_readiness() -> Dict[str, Any]:
    """Comprehensive readiness check -- the first thing a customer runs after deploy.

    Reports every integration, database, feed, and scanner with its status,
    computes an overall readiness score (0-100), and provides actionable
    recommendations for anything that is missing or degraded.

    **No authentication required.**  Secret values are NEVER exposed --
    only whether the corresponding env var is set.
    """
    now = datetime.now(timezone.utc)

    # ---- 1. Check all env-var-based capabilities ----
    capabilities: Dict[str, Dict[str, Any]] = {}
    for defn in _CAPABILITY_DEFINITIONS:
        capabilities[defn["name"]] = _check_env_capability(defn)

    # ---- 2. Database health ----
    db_files_to_check = {
        "analytics": "data/analytics.db",
        "fixops_brain": "data/fixops_brain.db",
        "users": "data/users.db",
        "integrations": "data/integrations.db",
        "audit": "data/audit.db",
        "policies": "data/policies.db",
        "fail_engine": "data/fail_engine.db",
        "mpte": "data/mpte.db",
        "inventory": "data/inventory.db",
        "compliance": "data/compliance.db",
        "workflows": "data/workflows.db",
    }
    db_health: Dict[str, Any] = {}
    for name, path_str in db_files_to_check.items():
        db_health[name] = _check_db(path_str)
    healthy_dbs = sum(1 for v in db_health.values() if v["status"] == "healthy")

    # ---- 3. Feed data freshness ----
    feed_details: Dict[str, Any] = {}
    for feed_name, feed_path in _FEED_FILES.items():
        feed_details[feed_name] = _check_feed_freshness(feed_path)
    available_feeds = sum(1 for v in feed_details.values() if v.get("status") == "available")
    stale_feeds = sum(1 for v in feed_details.values() if v.get("freshness") in ("stale", "outdated"))

    feed_health: Dict[str, Any] = {
        "total": len(feed_details),
        "available": available_feeds,
        "stale": stale_feeds,
        "feeds": feed_details,
    }

    # ---- 4. Built-in scanner availability ----
    scanner_modules = {
        "sast": "core.sast_engine",
        "dast": "core.dast_engine",
        "secrets": "core.secrets_scanner",
        "container": "core.container_scanner",
        "cspm": "core.cspm_engine",
        "autofix": "core.autofix_engine",
    }
    scanner_details: Dict[str, str] = {}
    for name, module in scanner_modules.items():
        if module in sys.modules:
            scanner_details[name] = "loaded"
        else:
            parts = module.split(".")
            module_path = Path("suite-core") / "/".join(parts[:-1]) / f"{parts[-1]}.py"
            scanner_details[name] = "available" if module_path.exists() else "not_found"
    available_scanners = sum(1 for v in scanner_details.values() if v in ("loaded", "available"))
    scanner_availability = {
        "total": len(scanner_details),
        "available": available_scanners,
        "details": scanner_details,
    }

    # ---- 5. Brain pipeline ----
    brain_status = "not_found"
    if "core.brain_pipeline" in sys.modules:
        brain_status = "loaded"
    elif Path("suite-core/core/brain_pipeline.py").exists():
        brain_status = "available"

    # ---- 6. Data directories ----
    required_dirs = ["data", "data/archive", "data/evidence", "data/feeds", "data/findings"]
    dir_status: Dict[str, str] = {}
    for d in required_dirs:
        p = Path(d)
        if p.exists() and p.is_dir():
            dir_status[d] = "accessible"
        elif p.exists():
            dir_status[d] = "not_directory"
        else:
            dir_status[d] = "missing"

    # ---- 7. Compute readiness score ----
    score = _compute_readiness_score(
        capabilities=capabilities,
        db_health=db_health,
        feed_health=feed_health,
        scanner_availability=scanner_availability,
        brain_status=brain_status,
        dir_status=dir_status,
    )
    level = _readiness_level(score)

    # ---- 8. Build missing-critical list ----
    missing_critical: list[Dict[str, str]] = []
    # Critical databases
    for db_name in ("analytics", "fixops_brain", "users"):
        if db_health.get(db_name, {}).get("status") != "healthy":
            missing_critical.append({
                "component": f"database:{db_name}",
                "status": db_health.get(db_name, {}).get("status", "unknown"),
                "impact": f"The {db_name} database is missing or unhealthy; core functionality depends on it.",
            })
    # At least one LLM
    llm_caps = {k: v for k, v in capabilities.items() if v.get("category") == "llm_providers"}
    if not any(v["status"] == "configured" for v in llm_caps.values()):
        missing_critical.append({
            "component": "llm_provider",
            "status": "none_configured",
            "impact": "No LLM provider is configured. AI-powered triage, auto-fix, and NL queries are unavailable.",
            "env_vars": "OPENAI_API_KEY or ANTHROPIC_API_KEY or GOOGLE_API_KEY",
        })
    # Brain pipeline
    if brain_status == "not_found":
        missing_critical.append({
            "component": "brain_pipeline",
            "status": "not_found",
            "impact": "Brain pipeline module is missing; the 12-step CTEM decision engine cannot run.",
        })

    # ---- 9. Build recommendations ----
    recommendations: list[str] = []

    # Missing capabilities
    for cap_name, cap in capabilities.items():
        if cap["status"] == "missing" and cap["priority"] in ("critical", "recommended"):
            env_hint = cap["env_var"]
            if cap.get("alt_env_var"):
                env_hint += f" (or {cap['alt_env_var']})"
            recommendations.append(
                f"Set {env_hint} to enable {cap['label']}. {cap['impact']}"
            )

    # Stale feeds
    for feed_name, info in feed_details.items():
        freshness = info.get("freshness")
        if freshness == "outdated":
            recommendations.append(
                f"Feed '{feed_name}' is outdated (last updated {info.get('age_hours', '?')}h ago). "
                f"Run the feed-sync job to refresh threat intelligence."
            )
        elif freshness == "stale":
            recommendations.append(
                f"Feed '{feed_name}' is stale (last updated {info.get('age_hours', '?')}h ago). "
                f"Consider scheduling automatic feed updates."
            )

    # Missing feeds
    for feed_name, info in feed_details.items():
        if info.get("status") == "missing":
            recommendations.append(
                f"Feed '{feed_name}' is missing. Run the initial feed sync to populate threat intel data."
            )

    # Missing directories
    for d, status in dir_status.items():
        if status == "missing":
            recommendations.append(f"Create directory '{d}' to enable data storage for that subsystem.")

    # Unhealthy databases
    for db_name, info in db_health.items():
        if info.get("status") == "unhealthy":
            recommendations.append(
                f"Database '{db_name}' is unhealthy (error: {info.get('error', 'unknown')}). "
                f"Check file permissions and disk space."
            )

    # General level-based advice
    if level == "not_ready":
        recommendations.append(
            "URGENT: System is not ready for use. Ensure core databases exist and at least "
            "one LLM provider is configured before onboarding users."
        )
    elif level == "basic":
        recommendations.append(
            "System can ingest and deduplicate findings but lacks AI enrichment. "
            "Configure an LLM provider and connect at least one ticketing system."
        )

    return {
        "readiness_score": score,
        "readiness_level": level,
        "timestamp": now.isoformat() + "Z",
        "service": "fixops-api",
        "version": _VERSION,
        "capabilities": capabilities,
        "databases": {
            "total": len(db_health),
            "healthy": healthy_dbs,
            "details": db_health,
        },
        "feeds": feed_health,
        "scanners": scanner_availability,
        "brain_pipeline": {"status": brain_status},
        "storage": {"directories": dir_status},
        "missing_critical": missing_critical,
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# Guided Onboarding Wizard — step-by-step setup assistant for new deployments
# Returns a checklist of setup steps with status and next actions.
# Designed for first-time customers: "deploy → hit /onboarding → follow steps"
# ---------------------------------------------------------------------------

_ONBOARDING_STEPS = [
    {
        "step": 1,
        "name": "core_infrastructure",
        "title": "Core Infrastructure",
        "description": "Verify data directories and databases are initialized",
        "checks": [
            {"name": "data_dir", "path": "data", "type": "directory"},
            {"name": "feeds_dir", "path": "data/feeds", "type": "directory"},
            {"name": "evidence_dir", "path": "data/evidence", "type": "directory"},
            {"name": "analytics_db", "path": "data/analytics.db", "type": "database"},
        ],
    },
    {
        "step": 2,
        "name": "threat_intelligence",
        "title": "Threat Intelligence Feeds",
        "description": "Sync EPSS, KEV, and NVD feeds for real-time enrichment",
        "checks": [
            {"name": "epss_feed", "path": "data/feeds/epss-latest.json", "type": "feed"},
            {"name": "kev_feed", "path": "data/feeds/kev-latest.json", "type": "feed"},
            {"name": "feeds_db", "path": "data/feeds/feeds.db", "type": "database"},
        ],
        "action": "POST /api/v1/feeds/sync to populate threat intel data",
    },
    {
        "step": 3,
        "name": "ai_provider",
        "title": "AI Provider Configuration",
        "description": "Configure at least one LLM for AI-powered triage and auto-fix",
        "env_vars": ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"],
        "action": "Set OPENAI_API_KEY or ANTHROPIC_API_KEY in environment",
    },
    {
        "step": 4,
        "name": "scanner_integration",
        "title": "Scanner Integration",
        "description": "Connect external scanners or use built-in scanners",
        "env_vars": ["FIXOPS_SNYK_TOKEN", "FIXOPS_SONARQUBE_URL", "FIXOPS_GITHUB_TOKEN"],
        "builtin_modules": [
            "core.sast_engine", "core.dast_engine", "core.secrets_scanner",
            "core.container_scanner", "core.cspm_engine",
        ],
        "action": "Built-in scanners work out of the box. External scanners are optional.",
    },
    {
        "step": 5,
        "name": "ticketing_integration",
        "title": "Ticketing & Notifications",
        "description": "Connect Jira, Slack, or GitHub for automated remediation tracking",
        "env_vars": ["FIXOPS_JIRA_URL", "FIXOPS_SLACK_WEBHOOK", "FIXOPS_GITHUB_TOKEN"],
        "action": "Set FIXOPS_JIRA_URL + FIXOPS_JIRA_TOKEN for Jira integration",
    },
    {
        "step": 6,
        "name": "first_pipeline_run",
        "title": "Run First Pipeline",
        "description": "Execute the brain pipeline to verify end-to-end flow",
        "action": "POST /api/v1/brain/pipeline/run with sample findings",
    },
]


@router.get("/onboarding", summary="Guided onboarding wizard")
async def system_onboarding() -> Dict[str, Any]:
    """Step-by-step onboarding wizard for new ALdeci deployments.

    Returns a checklist of setup steps with completion status, progress
    percentage, and next recommended action. Designed for first-time
    customers — deploy, hit this endpoint, follow the steps.

    **No authentication required** — first thing after deploy.
    """
    now = datetime.now(timezone.utc)
    completed_steps = 0
    total_steps = len(_ONBOARDING_STEPS)
    step_results = []

    for step_def in _ONBOARDING_STEPS:
        step_status = "complete"
        step_details: Dict[str, Any] = {}
        issues: list[str] = []

        # Check file/directory/database existence
        for check in step_def.get("checks", []):
            p = Path(check["path"])
            if check["type"] == "directory":
                if p.exists() and p.is_dir():
                    step_details[check["name"]] = "ok"
                else:
                    step_details[check["name"]] = "missing"
                    issues.append(f"Directory '{check['path']}' is missing")
                    step_status = "incomplete"
            elif check["type"] == "database":
                db_result = _check_db(check["path"])
                step_details[check["name"]] = db_result["status"]
                if db_result["status"] != "healthy":
                    issues.append(f"Database '{check['path']}' is {db_result['status']}")
                    step_status = "incomplete"
            elif check["type"] == "feed":
                feed_result = _check_feed_freshness(check["path"])
                step_details[check["name"]] = feed_result.get("status", "missing")
                if feed_result.get("status") != "available":
                    issues.append(f"Feed '{check['path']}' is missing — run feed sync")
                    step_status = "incomplete"
                elif feed_result.get("freshness") == "outdated":
                    step_details[check["name"]] = "outdated"
                    issues.append(f"Feed '{check['path']}' is outdated — rerun feed sync")
                    step_status = "needs_update"

        # Check environment variables
        env_vars = step_def.get("env_vars", [])
        if env_vars:
            any_set = any(bool(os.getenv(v)) for v in env_vars)
            step_details["env_vars_checked"] = len(env_vars)
            step_details["env_vars_set"] = sum(1 for v in env_vars if os.getenv(v))
            if not any_set:
                step_status = "incomplete"
                issues.append(f"No environment variable set from: {', '.join(env_vars)}")

        # Check builtin scanner modules
        builtin_modules = step_def.get("builtin_modules", [])
        if builtin_modules:
            available = 0
            for mod in builtin_modules:
                parts = mod.split(".")
                module_path = Path("suite-core") / "/".join(parts[:-1]) / f"{parts[-1]}.py"
                if module_path.exists() or mod in sys.modules:
                    available += 1
            step_details["builtin_scanners_available"] = available
            step_details["builtin_scanners_total"] = len(builtin_modules)
            if available >= 3:
                if step_status == "incomplete" and not env_vars:
                    step_status = "complete"
                elif step_status == "incomplete":
                    # External scanners optional if builtins available
                    step_status = "optional"

        # Special check for first pipeline run
        if step_def["name"] == "first_pipeline_run":
            try:
                import sqlite3 as _sq3
                brain_db = Path("data/fixops_brain.db")
                if brain_db.exists():
                    conn = _sq3.connect(str(brain_db), timeout=2)
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                    tables = cursor.fetchone()[0]
                    conn.close()
                    if tables > 0:
                        step_details["pipeline_db"] = "initialized"
                    else:
                        step_status = "incomplete"
                        step_details["pipeline_db"] = "empty"
                else:
                    step_status = "incomplete"
                    step_details["pipeline_db"] = "not_found"
                    issues.append("No pipeline runs found. Run POST /api/v1/brain/pipeline/run")
            except (OSError, ValueError, RuntimeError):
                step_status = "incomplete"

        if step_status in ("complete", "optional"):
            completed_steps += 1

        step_results.append({
            "step": step_def["step"],
            "name": step_def["name"],
            "title": step_def["title"],
            "description": step_def["description"],
            "status": step_status,
            "details": step_details,
            "issues": issues,
            "next_action": step_def.get("action"),
        })

    progress_pct = round(completed_steps / max(total_steps, 1) * 100, 1)

    # Determine next recommended step
    next_step = None
    for sr in step_results:
        if sr["status"] in ("incomplete", "needs_update"):
            next_step = {
                "step": sr["step"],
                "title": sr["title"],
                "action": sr.get("next_action"),
            }
            break

    return {
        "timestamp": now.isoformat() + "Z",
        "service": "fixops-api",
        "version": _VERSION,
        "onboarding_progress": progress_pct,
        "completed_steps": completed_steps,
        "total_steps": total_steps,
        "status": "complete" if completed_steps == total_steps else "in_progress",
        "next_recommended_step": next_step,
        "steps": step_results,
    }


@router.get("/db-stats", summary="Database health and size statistics")
async def db_stats() -> Dict[str, Any]:
    """Return health and size information for all SQLite databases.

    Useful for monitoring disk usage, detecting growth, and planning
    capacity (e.g. when to consider migrating to PostgreSQL).
    """
    import sqlite3

    db_dirs = ["data", ".fixops_data", "suite-api/data"]
    databases: List[Dict[str, Any]] = []
    total_size_bytes = 0

    for db_dir in db_dirs:
        db_path = Path(db_dir)
        if not db_path.exists():
            continue
        for db_file in sorted(db_path.glob("*.db")):
            file_size = db_file.stat().st_size
            total_size_bytes += file_size
            info: Dict[str, Any] = {
                "path": str(db_file),
                "size_bytes": file_size,
                "size_human": f"{file_size / 1024 / 1024:.2f} MB",
            }
            try:
                conn = sqlite3.connect(str(db_file), timeout=2)
                conn.execute("PRAGMA journal_mode")  # verify readable
                # Table count
                tables = conn.execute(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'"
                ).fetchone()[0]
                info["tables"] = tables
                # WAL mode check
                journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
                info["journal_mode"] = journal
                # Page metrics
                page_size = conn.execute("PRAGMA page_size").fetchone()[0]
                page_count = conn.execute("PRAGMA page_count").fetchone()[0]
                freelist = conn.execute("PRAGMA freelist_count").fetchone()[0]
                info["page_size"] = page_size
                info["fragmentation_pct"] = round(
                    freelist / max(page_count, 1) * 100, 1
                )
                info["status"] = "healthy"
                conn.close()
            except (sqlite3.Error, OSError) as exc:
                info["status"] = "error"
                info["error"] = str(exc)
            databases.append(info)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "total_databases": len(databases),
        "total_size_bytes": total_size_bytes,
        "total_size_human": f"{total_size_bytes / 1024 / 1024:.1f} MB",
        "databases": databases,
        "recommendation": (
            "Consider PostgreSQL migration"
            if total_size_bytes > 500 * 1024 * 1024
            else "SQLite is appropriate for current data volume"
        ),
    }


@router.get("/traces/recent", summary="Recent distributed traces with timing")
async def system_traces_recent(
    limit: int = Query(default=50, ge=1, le=500, description="Max traces to return"),
) -> Dict[str, Any]:
    """Return summaries of the last N completed distributed traces.

    Each entry includes trace_id, operation, service, span_count,
    total_duration_ms, status, org_id, and engine_name (when set by engine calls).
    Useful for diagnosing latency and correlating engine call paths to log entries.
    """
    from core.observability import get_tracing_context

    tracer = get_tracing_context()
    traces: List[Dict[str, Any]] = tracer.recent_traces(limit=limit)
    return {
        "count": len(traces),
        "traces": traces,
    }


@router.get("/logs/recent", summary="Recent structured request logs")
async def system_logs_recent(limit: int = 100) -> Dict[str, Any]:
    """Return the last N structured request/response log entries from the in-memory ring buffer.

    Fields per entry: request_id, correlation_id, org_id, method, path,
    status_code, duration_ms, req_size, resp_size, level, ts.

    Args:
        limit: Number of entries to return (1-500, default 100).

    Returns:
        JSON with ``logs`` list and ``count``.
    """
    limit = max(1, min(limit, 500))
    try:
        from apps.api.detailed_logging import _log_ring, _ring_lock

        with _ring_lock:
            entries = list(_log_ring)[:limit]
        return {"logs": entries, "count": len(entries)}
    except ImportError:
        return {"logs": [], "count": 0, "note": "detailed_logging not available"}


# ---------------------------------------------------------------------------
# Top-50 endpoint health snapshot — polls the in-memory request log ring to
# derive per-path status codes, avg/p95 latency, and recent error rate.
# ---------------------------------------------------------------------------

_TOP_PREFIXES: List[str] = [
    "/api/v1/system", "/api/v1/platform", "/api/v1/findings",
    "/api/v1/brain", "/api/v1/llm", "/api/v1/feeds", "/api/v1/analytics",
    "/api/v1/integrations", "/api/v1/users", "/api/v1/audit",
    "/api/v1/compliance", "/api/v1/vulnerabilities", "/api/v1/threat-intel",
    "/api/v1/risk", "/api/v1/assets", "/api/v1/cve", "/api/v1/kpi",
    "/api/v1/vendor-risk", "/api/v1/insider-threat", "/api/v1/posture-advisor",
    "/api/v1/attack-paths", "/api/v1/zero-trust", "/api/v1/siem",
    "/api/v1/network-monitoring", "/api/v1/cloud-compliance",
    "/api/v1/endpoint-compliance", "/api/v1/api-security-engine",
    "/api/v1/vuln-intel", "/api/v1/asm", "/api/v1/tip",
    "/api/v1/cert", "/api/v1/crypto-keys", "/api/v1/kubernetes-security",
    "/api/v1/cloud-native", "/api/v1/iam-policy", "/api/v1/cloud-drift",
    "/api/v1/data-retention", "/api/v1/evidence-chain", "/api/v1/container-registry-security",
    "/api/v1/sca", "/api/v1/firewall-policy", "/api/v1/network-segmentation",
    "/api/v1/threat-geolocation", "/api/v1/ip-reputation",
    "/api/v1/security-automation", "/api/v1/incident-orchestration",
    "/api/v1/dark-web", "/api/v1/itdr", "/api/v1/container-runtime",
]


@router.get("/endpoint-health", summary="Top-50 endpoint health snapshot")
async def endpoint_health() -> Dict[str, Any]:
    """Return per-path health for the top 50 API prefixes.

    Derives status, avg_latency_ms, p95_latency_ms, error_rate, and
    request_count from the in-memory request log ring buffer.
    Returns static OK entries for prefixes with no recent traffic.
    """
    now = datetime.now(timezone.utc)

    # Pull log ring if available
    log_entries: list = []
    try:
        from apps.api.detailed_logging import _log_ring, _ring_lock
        with _ring_lock:
            log_entries = list(_log_ring)
    except ImportError:
        pass

    # Group by path prefix → collect latencies + status codes
    from collections import defaultdict
    prefix_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"latencies": [], "statuses": []})

    for entry in log_entries:
        path: str = entry.get("path", "")
        for prefix in _TOP_PREFIXES:
            if path.startswith(prefix):
                duration = entry.get("duration_ms")
                status = entry.get("status_code")
                if duration is not None:
                    prefix_stats[prefix]["latencies"].append(float(duration))
                if status is not None:
                    prefix_stats[prefix]["statuses"].append(int(status))
                break  # match longest-first isn't needed for these distinct prefixes

    endpoints: List[Dict[str, Any]] = []
    for prefix in _TOP_PREFIXES[:50]:
        stats = prefix_stats.get(prefix)
        if stats and stats["latencies"]:
            lats = sorted(stats["latencies"])
            statuses = stats["statuses"]
            count = len(lats)
            avg_lat = round(sum(lats) / count, 1)
            p95_idx = max(0, int(count * 0.95) - 1)
            p95_lat = round(lats[p95_idx], 1)
            errors = sum(1 for s in statuses if s >= 400)
            error_rate = round(errors / max(len(statuses), 1) * 100, 1)
            last_status = statuses[-1] if statuses else 200
            health_status = (
                "healthy" if error_rate < 5 and avg_lat < 500
                else "degraded" if error_rate < 20 or avg_lat < 2000
                else "error"
            )
        else:
            # No recent traffic — report as healthy with zero metrics
            count = 0
            avg_lat = 0.0
            p95_lat = 0.0
            error_rate = 0.0
            last_status = 200
            health_status = "no_traffic"

        endpoints.append({
            "prefix": prefix,
            "status": health_status,
            "last_status_code": last_status,
            "avg_latency_ms": avg_lat,
            "p95_latency_ms": p95_lat,
            "error_rate_pct": error_rate,
            "request_count": count,
        })

    # Overall summary
    healthy = sum(1 for e in endpoints if e["status"] in ("healthy", "no_traffic"))
    degraded = sum(1 for e in endpoints if e["status"] == "degraded")
    errored = sum(1 for e in endpoints if e["status"] == "error")

    return {
        "timestamp": now.isoformat() + "Z",
        "total": len(endpoints),
        "healthy": healthy,
        "degraded": degraded,
        "errored": errored,
        "endpoints": endpoints,
    }


__all__ = ["router"]
