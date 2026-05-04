"""Deployment Manager — single-command deployment health and lifecycle.

Provides:
  - Health Check Aggregator: HTTP, Redis PING, Postgres SELECT 1, TrustGraph
  - First-Boot Initializer: schema creation, admin seed, self-scan, TrustGraph index
  - Migration Runner: ordered migrations with rollback on failure
  - Service Discovery: graceful degradation when optional services are absent
  - Configuration Validator: env vars, ports, DB connectivity
  - Deployment Status API: uptime, version, feature flags, enabled modules

Usage:
    manager = DeploymentManager()
    status = await manager.aggregate_health()
    result = await manager.initialize_first_boot()
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import asyncio
import importlib
import logging
import os
import socket
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ─── Version / build info ─────────────────────────────────────────────────────
ALDECI_VERSION = os.getenv("ALDECI_VERSION", "2.5.0")
ALDECI_BUILD = os.getenv("ALDECI_BUILD", "local")
_STARTUP_TIME = time.monotonic()
_STARTUP_TS = datetime.now(timezone.utc)


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class ServiceHealth:
    """Health status for a single service."""
    name: str
    status: str          # "healthy" | "degraded" | "unavailable"
    latency_ms: float
    message: str = ""
    optional: bool = False


@dataclass
class AggregateHealth:
    """Aggregated health across all services."""
    status: str          # "healthy" | "degraded" | "unavailable"
    services: List[ServiceHealth] = field(default_factory=list)
    checked_at: str = ""
    uptime_seconds: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "checked_at": self.checked_at,
            "services": {
                s.name: {
                    "status": s.status,
                    "latency_ms": round(s.latency_ms, 2),
                    "message": s.message,
                    "optional": s.optional,
                }
                for s in self.services
            },
        }


@dataclass
class MigrationRecord:
    """Tracks a single applied migration."""
    version: str
    name: str
    applied_at: str
    checksum: str


@dataclass
class DeploymentStatus:
    """Full deployment status snapshot."""
    healthy: bool
    version: str
    build: str
    uptime_seconds: float
    started_at: str
    services: Dict[str, Any]
    feature_flags: Dict[str, bool]
    enabled_modules: List[str]
    migration_version: str
    first_boot_complete: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "healthy": self.healthy,
            "version": self.version,
            "build": self.build,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "started_at": self.started_at,
            "services": self.services,
            "feature_flags": self.feature_flags,
            "enabled_modules": self.enabled_modules,
            "migration_version": self.migration_version,
            "first_boot_complete": self.first_boot_complete,
        }


# ─── Migration definitions ────────────────────────────────────────────────────

_MIGRATIONS: List[Dict[str, Any]] = [
    {
        "version": "001",
        "name": "create_deployment_meta",
        "up": """
            CREATE TABLE IF NOT EXISTS _deployment_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """,
        "down": "DROP TABLE IF EXISTS _deployment_meta;",
    },
    {
        "version": "002",
        "name": "create_migration_history",
        "up": """
            CREATE TABLE IF NOT EXISTS _migration_history (
                version    TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                checksum   TEXT NOT NULL
            );
        """,
        "down": "DROP TABLE IF EXISTS _migration_history;",
    },
    {
        "version": "003",
        "name": "create_service_discovery",
        "up": """
            CREATE TABLE IF NOT EXISTS _service_registry (
                service_name  TEXT PRIMARY KEY,
                status        TEXT NOT NULL DEFAULT 'unknown',
                url           TEXT,
                last_seen     TEXT,
                optional      INTEGER NOT NULL DEFAULT 1
            );
        """,
        "down": "DROP TABLE IF EXISTS _service_registry;",
    },
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _elapsed_ms(t0: float) -> float:
    return (time.monotonic() - t0) * 1000


def _migration_checksum(m: Dict[str, Any]) -> str:
    import hashlib
    raw = f"{m['version']}:{m['name']}:{m['up']}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _uptime() -> float:
    return time.monotonic() - _STARTUP_TIME


# ─── DeploymentManager ────────────────────────────────────────────────────────

class DeploymentManager:
    """Central lifecycle and observability manager for ALDECI.

    All methods are async-safe. CPU-bound DB calls run in thread pools via
    asyncio.to_thread so they don't block the event loop.
    """

    def __init__(self) -> None:
        self._data_dir = Path(os.getenv("FIXOPS_DATA_DIR", "/app/data"))
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._meta_db_path = self._data_dir / "_deployment.db"

        # Service URLs from environment
        self._api_url = os.getenv("ALDECI_API_URL", "http://localhost:8000")
        self._ui_url = os.getenv("ALDECI_UI_URL", "http://localhost:3000")
        self._trustgraph_url = os.getenv("TRUSTGRAPH_URL", "http://trustgraph:8888")
        self._redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        self._postgres_dsn = os.getenv(
            "DATABASE_URL",
            "postgresql://aldeci:aldeci_pw_change_me@postgres:5432/aldeci",
        )

        # Ensure meta DB is bootstrapped synchronously (lightweight)
        self._bootstrap_meta_db()

    # ─── Meta DB bootstrap (sync) ──────────────────────────────────────────

    def _bootstrap_meta_db(self) -> None:
        """Create the deployment meta database if it doesn't exist."""
        try:
            with sqlite3.connect(str(self._meta_db_path)) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS _deployment_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS _migration_history (
                        version TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at TEXT NOT NULL,
                        checksum TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS _service_registry (
                        service_name TEXT PRIMARY KEY,
                        status TEXT NOT NULL DEFAULT 'unknown',
                        url TEXT,
                        last_seen TEXT,
                        optional INTEGER NOT NULL DEFAULT 1
                    )
                """)
                conn.commit()
        except sqlite3.Error as exc:
            logger.warning("deployment_manager: meta db bootstrap failed: %s", exc)

    def _meta_get(self, key: str, default: str = "") -> str:
        try:
            with sqlite3.connect(str(self._meta_db_path)) as conn:
                row = conn.execute(
                    "SELECT value FROM _deployment_meta WHERE key = ?", (key,)
                ).fetchone()
                return row[0] if row else default
        except sqlite3.Error:
            return default

    def _meta_set(self, key: str, value: str) -> None:
        try:
            with sqlite3.connect(str(self._meta_db_path)) as conn:
                conn.execute(
                    """INSERT INTO _deployment_meta (key, value, updated_at)
                       VALUES (?, ?, ?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                    (key, value, _now_iso()),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.warning("deployment_manager: meta_set failed key=%s: %s", key, exc)  # nosemgrep: python-logger-credential-disclosure

    # ─── Health Check Aggregator ───────────────────────────────────────────

    async def aggregate_health(self) -> AggregateHealth:
        """Check all services concurrently and return aggregate status."""
        checks = await asyncio.gather(
            self._check_api(),
            self._check_ui(),
            self._check_trustgraph(),
            self._check_redis(),
            self._check_postgres(),
            return_exceptions=True,
        )

        services: List[ServiceHealth] = []
        for result in checks:
            if isinstance(result, ServiceHealth):
                services.append(result)
            elif isinstance(result, Exception):
                logger.warning("health check raised: %s", result)

        # Aggregate: any required service unhealthy → unhealthy
        #            all required healthy, optional degraded → degraded
        required_healthy = all(
            s.status == "healthy" for s in services if not s.optional
        )
        all_healthy = all(s.status == "healthy" for s in services)

        if required_healthy and all_healthy:
            overall = "healthy"
        elif required_healthy:
            overall = "degraded"
        else:
            overall = "unavailable"

        health = AggregateHealth(
            status=overall,
            services=services,
            checked_at=_now_iso(),
            uptime_seconds=_uptime(),
        )
        _emit_event("deployment_manager.health_checked", {
            "status": overall,
            "uptime_seconds": round(_uptime(), 1),
            "service_count": len(services),
        })
        return health

    async def _check_api(self) -> ServiceHealth:
        return await asyncio.to_thread(self._http_check, "api", self._api_url + "/health", optional=False)

    async def _check_ui(self) -> ServiceHealth:
        return await asyncio.to_thread(self._http_check, "ui", self._ui_url + "/nginx-health", optional=True)

    async def _check_trustgraph(self) -> ServiceHealth:
        return await asyncio.to_thread(
            self._http_check, "trustgraph", self._trustgraph_url + "/api/v1/health", optional=True
        )

    async def _check_redis(self) -> ServiceHealth:
        return await asyncio.to_thread(self._redis_ping)

    async def _check_postgres(self) -> ServiceHealth:
        return await asyncio.to_thread(self._postgres_ping)

    def _http_check(self, name: str, url: str, optional: bool = False) -> ServiceHealth:
        """Perform an HTTP GET health check."""
        try:
            import urllib.request
            t0 = time.monotonic()
            req = urllib.request.Request(url, method="GET")  # nosemgrep: dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                latency = _elapsed_ms(t0)
                if resp.status < 400:
                    return ServiceHealth(name=name, status="healthy", latency_ms=latency, optional=optional)
                return ServiceHealth(
                    name=name, status="degraded", latency_ms=latency,
                    message=f"HTTP {resp.status}", optional=optional,
                )
        except Exception as exc:
            return ServiceHealth(
                name=name, status="unavailable", latency_ms=0.0,
                message=str(exc)[:120], optional=optional,
            )

    def _redis_ping(self) -> ServiceHealth:
        """PING redis via raw socket (no redis-py dependency required)."""
        t0 = time.monotonic()
        try:
            # Parse redis://host:port/db
            url = self._redis_url.replace("redis://", "")
            host_port = url.split("/")[0]
            host, port_str = (host_port.split(":") + ["6379"])[:2]
            port = int(port_str)

            with socket.create_connection((host, port), timeout=3) as sock:
                sock.sendall(b"PING\r\n")
                response = sock.recv(64)
                latency = _elapsed_ms(t0)
                if b"PONG" in response:
                    return ServiceHealth(name="redis", status="healthy", latency_ms=latency, optional=False)
                return ServiceHealth(
                    name="redis", status="degraded", latency_ms=latency,
                    message=f"unexpected response: {response!r}"
                )
        except Exception as exc:
            return ServiceHealth(
                name="redis", status="unavailable", latency_ms=_elapsed_ms(t0),
                message=str(exc)[:120], optional=False,
            )

    def _postgres_ping(self) -> ServiceHealth:
        """Execute SELECT 1 against Postgres (psycopg2 or asyncpg sync wrapper)."""
        t0 = time.monotonic()
        try:
            import psycopg2  # type: ignore
            conn = psycopg2.connect(self._postgres_dsn, connect_timeout=5)
            try:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                latency = _elapsed_ms(t0)
                return ServiceHealth(name="postgres", status="healthy", latency_ms=latency, optional=False)
            finally:
                conn.close()
        except ImportError:
            # psycopg2 not installed — try raw socket
            return self._postgres_socket_ping(t0)
        except Exception as exc:
            return ServiceHealth(
                name="postgres", status="unavailable", latency_ms=_elapsed_ms(t0),
                message=str(exc)[:120], optional=False,
            )

    def _postgres_socket_ping(self, t0: float) -> ServiceHealth:
        """Fallback: raw TCP connect to postgres port."""
        try:
            # postgresql://user:pass@host:port/db
            dsn = self._postgres_dsn.replace("postgresql://", "").replace("postgres://", "")
            at_idx = dsn.rfind("@")
            host_db = dsn[at_idx + 1:] if at_idx >= 0 else dsn
            host_port = host_db.split("/")[0]
            host, port_str = (host_port.split(":") + ["5432"])[:2]
            port = int(port_str)
            with socket.create_connection((host, port), timeout=3):
                latency = _elapsed_ms(t0)
                return ServiceHealth(
                    name="postgres", status="degraded", latency_ms=latency,
                    message="TCP reachable but SELECT 1 not confirmed (psycopg2 missing)",
                    optional=False,
                )
        except Exception as exc:
            return ServiceHealth(
                name="postgres", status="unavailable", latency_ms=_elapsed_ms(t0),
                message=str(exc)[:120], optional=False,
            )

    # ─── First-Boot Initializer ────────────────────────────────────────────

    async def initialize_first_boot(self) -> Dict[str, Any]:
        """Idempotent first-boot sequence: schema → admin → self-scan → TrustGraph index."""
        steps: Dict[str, Any] = {}
        already_done = self._meta_get("first_boot_complete") == "true"

        if already_done:
            return {
                "status": "already_initialized",
                "message": "First-boot was already completed. Re-running is safe (idempotent).",
                "steps": {},
            }

        # Step 1: Run migrations
        migration_result = await self.run_migrations()
        steps["migrations"] = migration_result

        # Step 2: Seed admin user
        steps["admin_seed"] = await asyncio.to_thread(self._seed_admin_user)

        # Step 3: Create default config
        steps["default_config"] = await asyncio.to_thread(self._create_default_config)

        # Step 4: Register services in service registry
        steps["service_registry"] = await asyncio.to_thread(self._populate_service_registry)

        # Step 5: TrustGraph index (optional — graceful if unavailable)
        steps["trustgraph_index"] = await self._index_trustgraph()

        # Mark complete
        self._meta_set("first_boot_complete", "true")
        self._meta_set("first_boot_at", _now_iso())
        self._meta_set("aldeci_version", ALDECI_VERSION)

        success = all(
            v.get("status") in ("ok", "skipped")
            for v in steps.values()
            if isinstance(v, dict)
        )

        return {
            "status": "initialized" if success else "partial",
            "steps": steps,
            "initialized_at": _now_iso(),
        }

    def _seed_admin_user(self) -> Dict[str, Any]:
        """Create default admin user if none exists."""
        try:
            from core.auth_db import AuthDB  # type: ignore
            db = AuthDB()
            if hasattr(db, "list_users"):
                users = db.list_users()
                if users:
                    return {"status": "skipped", "reason": "users already exist"}
            if hasattr(db, "create_user"):
                admin_token = os.getenv("FIXOPS_API_TOKEN", "")
                db.create_user(
                    email="admin@aldeci.local",
                    password=os.getenv("ALDECI_ADMIN_PASSWORD", ""),  # must be set via env before first deploy
                    role="admin",
                    api_token=admin_token or None,
                )
                return {"status": "ok", "message": "Admin user created: admin@aldeci.local"}
            return {"status": "skipped", "reason": "AuthDB.create_user not available"}
        except ImportError:
            return {"status": "skipped", "reason": "AuthDB not available"}
        except Exception as exc:
            logger.warning("first_boot: admin seed failed: %s", exc)
            return {"status": "error", "error": str(exc)[:200]}

    def _create_default_config(self) -> Dict[str, Any]:
        """Write default configuration markers to meta DB."""
        try:
            defaults = {
                "feature_flag.llm_consensus": "true",
                "feature_flag.trustgraph": "true",
                "feature_flag.real_time_streaming": "true",
                "feature_flag.compliance_engine": "true",
                "feature_flag.attack_surface": "true",
                "deployment.mode": os.getenv("ALDECI_MODE", "full"),
                "deployment.version": ALDECI_VERSION,
            }
            for k, v in defaults.items():
                if not self._meta_get(k):
                    self._meta_set(k, v)
            return {"status": "ok", "keys_written": len(defaults)}
        except Exception as exc:
            return {"status": "error", "error": str(exc)[:200]}

    def _populate_service_registry(self) -> Dict[str, Any]:
        """Register all known services in the local registry."""
        services = [
            ("api", self._api_url, False),
            ("ui", self._ui_url, True),
            ("trustgraph", self._trustgraph_url, True),
            ("redis", self._redis_url, False),
            ("postgres", self._postgres_dsn.split("@")[-1] if "@" in self._postgres_dsn else "postgres:5432", False),
        ]
        try:
            with sqlite3.connect(str(self._meta_db_path)) as conn:
                for name, url, optional in services:
                    conn.execute(
                        """INSERT INTO _service_registry (service_name, status, url, last_seen, optional)
                           VALUES (?, 'registered', ?, ?, ?)
                           ON CONFLICT(service_name) DO UPDATE SET
                               url=excluded.url,
                               last_seen=excluded.last_seen""",
                        (name, url, _now_iso(), int(optional)),
                    )
                conn.commit()
            return {"status": "ok", "services_registered": len(services)}
        except Exception as exc:
            return {"status": "error", "error": str(exc)[:200]}

    async def _index_trustgraph(self) -> Dict[str, Any]:
        """Index ALDECI codebase entities into TrustGraph (optional)."""
        tg_health = await asyncio.to_thread(
            self._http_check, "trustgraph", self._trustgraph_url + "/api/v1/health", optional=True
        )
        if tg_health.status != "healthy":
            return {"status": "skipped", "reason": f"TrustGraph unavailable: {tg_health.message}"}
        # NOTE: legacy trustgraph.store.KnowledgeStore module was retired in
        # favour of the in-process suite-core.trustgraph package. The first-
        # boot indexer now delegates to that package via the HTTP ingest API
        # rather than importing a Python client. Until that wiring lands,
        # report a clean "skipped" result instead of throwing ImportError.
        return {
            "status": "skipped",
            "reason": "trustgraph in-process client retired; HTTP ingest wiring pending",
        }

    # ─── Migration Runner ──────────────────────────────────────────────────

    async def run_migrations(self) -> Dict[str, Any]:
        """Apply pending migrations in order. Rolls back on failure."""
        return await asyncio.to_thread(self._run_migrations_sync)

    def _run_migrations_sync(self) -> Dict[str, Any]:
        applied: List[str] = []
        skipped: List[str] = []
        failed: Optional[str] = None

        try:
            with sqlite3.connect(str(self._meta_db_path)) as conn:
                for migration in _MIGRATIONS:
                    version = migration["version"]
                    name = migration["name"]
                    checksum = _migration_checksum(migration)

                    # Check if already applied
                    row = conn.execute(
                        "SELECT version FROM _migration_history WHERE version = ?",
                        (version,),
                    ).fetchone()
                    if row:
                        skipped.append(version)
                        continue

                    # Apply migration
                    try:
                        conn.execute("BEGIN")
                        conn.executescript(migration["up"])
                        conn.execute(
                            """INSERT INTO _migration_history (version, name, applied_at, checksum)
                               VALUES (?, ?, ?, ?)""",
                            (version, name, _now_iso(), checksum),
                        )
                        conn.execute("COMMIT")
                        applied.append(version)
                        logger.info("migration %s (%s) applied", version, name)
                    except sqlite3.Error as exc:
                        conn.execute("ROLLBACK")
                        failed = f"migration {version} ({name}) failed: {exc}"
                        logger.error("migration runner: %s", failed)
                        break

        except sqlite3.Error as exc:
            return {"status": "error", "error": str(exc), "applied": applied}

        if failed:
            return {
                "status": "error",
                "error": failed,
                "applied": applied,
                "skipped": skipped,
            }

        # Update migration version in meta
        current = _MIGRATIONS[-1]["version"] if _MIGRATIONS else "000"
        self._meta_set("migration_version", current)

        return {
            "status": "ok",
            "applied": applied,
            "skipped": skipped,
            "current_version": current,
        }

    def get_migration_history(self) -> List[MigrationRecord]:
        """Return list of applied migrations."""
        try:
            with sqlite3.connect(str(self._meta_db_path)) as conn:
                rows = conn.execute(
                    "SELECT version, name, applied_at, checksum FROM _migration_history ORDER BY version"
                ).fetchall()
                return [
                    MigrationRecord(version=r[0], name=r[1], applied_at=r[2], checksum=r[3])
                    for r in rows
                ]
        except sqlite3.Error:
            return []

    # ─── Service Discovery ─────────────────────────────────────────────────

    async def discover_services(self) -> Dict[str, Any]:
        """Detect which services are reachable. Updates service registry."""
        health = await self.aggregate_health()
        registry: Dict[str, Any] = {}

        for svc in health.services:
            registry[svc.name] = {
                "available": svc.status == "healthy",
                "status": svc.status,
                "optional": svc.optional,
            }
            # Persist last-seen
            await asyncio.to_thread(self._update_service_status, svc.name, svc.status)

        return {
            "services": registry,
            "checked_at": _now_iso(),
            "degraded_services": [
                n for n, v in registry.items() if v["status"] == "degraded"
            ],
            "unavailable_required": [
                n for n, v in registry.items()
                if v["status"] == "unavailable" and not v["optional"]
            ],
        }

    def _update_service_status(self, name: str, status: str) -> None:
        try:
            with sqlite3.connect(str(self._meta_db_path)) as conn:
                conn.execute(
                    """UPDATE _service_registry SET status=?, last_seen=?
                       WHERE service_name=?""",
                    (status, _now_iso(), name),
                )
                conn.commit()
        except sqlite3.Error:
            pass

    def get_service_registry(self) -> List[Dict[str, Any]]:
        """Return current service registry from meta DB."""
        try:
            with sqlite3.connect(str(self._meta_db_path)) as conn:
                rows = conn.execute(
                    "SELECT service_name, status, url, last_seen, optional FROM _service_registry"
                ).fetchall()
                return [
                    {
                        "name": r[0],
                        "status": r[1],
                        "url": r[2],
                        "last_seen": r[3],
                        "optional": bool(r[4]),
                    }
                    for r in rows
                ]
        except sqlite3.Error:
            return []

    # ─── Configuration Validator ───────────────────────────────────────────

    async def validate_configuration(self) -> Dict[str, Any]:
        """Check env vars, ports, and DB connectivity."""
        issues: List[str] = []
        warnings: List[str] = []
        checks: Dict[str, Any] = {}

        # Required env vars
        required_env = {
            "FIXOPS_API_TOKEN": "API authentication token",
            "FIXOPS_JWT_SECRET": "JWT signing secret",
        }
        for var, desc in required_env.items():
            val = os.getenv(var, "")
            if not val:
                warnings.append(f"{var} not set ({desc}) — will be auto-generated")
                checks[f"env.{var}"] = "missing"
            elif val in ("changeme", "test", "dev", "your-secret-key-change-in-prod"):
                warnings.append(f"{var} is set to an insecure default value")
                checks[f"env.{var}"] = "insecure_default"
            else:
                checks[f"env.{var}"] = "ok"

        # Optional but recommended
        optional_env = [
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY",
            "FIXOPS_OLLAMA_URL",
        ]
        has_llm = any(os.getenv(k) for k in optional_env)
        checks["env.llm_provider"] = "ok" if has_llm else "not_configured"
        if not has_llm:
            warnings.append("No LLM provider configured — AI features will use fallback mode")

        # Port availability (on local machine only)
        port_checks = {
            "api": int(os.getenv("API_PORT", "8000")),
            "ui": int(os.getenv("UI_PORT", "3000")),
        }
        for service, port in port_checks.items():
            available = await asyncio.to_thread(self._check_port_available, "localhost", port)
            checks[f"port.{port}"] = "available" if available else "in_use"

        # Database connectivity
        db_health = await asyncio.gather(
            self._check_postgres(),
            self._check_redis(),
            return_exceptions=True,
        )
        for result in db_health:
            if isinstance(result, ServiceHealth):
                checks[f"connectivity.{result.name}"] = result.status
                if result.status == "unavailable" and not result.optional:
                    issues.append(f"{result.name} is unreachable: {result.message}")

        # Data directory
        data_dir = Path(os.getenv("FIXOPS_DATA_DIR", "/app/data"))
        checks["data_dir.exists"] = str(data_dir.exists())
        checks["data_dir.writable"] = str(os.access(str(data_dir), os.W_OK))
        if not data_dir.exists() or not os.access(str(data_dir), os.W_OK):
            issues.append(f"Data directory {data_dir} is not writable")

        status = "ok" if not issues else "invalid"
        return {
            "status": status,
            "issues": issues,
            "warnings": warnings,
            "checks": checks,
            "validated_at": _now_iso(),
        }

    def _check_port_available(self, host: str, port: int) -> bool:
        """Return True if port is NOT in use (available to bind)."""
        try:
            with socket.create_connection((host, port), timeout=1):
                return False  # something is already listening
        except (ConnectionRefusedError, OSError):
            return True  # port is free

    # ─── Deployment Status API ─────────────────────────────────────────────

    async def get_deployment_status(self) -> DeploymentStatus:
        """Return full deployment status snapshot."""
        health = await self.aggregate_health()

        feature_flags = self._get_feature_flags()
        enabled_modules = self._discover_enabled_modules()
        migration_version = self._meta_get("migration_version", "unknown")
        first_boot = self._meta_get("first_boot_complete") == "true"

        return DeploymentStatus(
            healthy=health.status in ("healthy", "degraded"),
            version=ALDECI_VERSION,
            build=ALDECI_BUILD,
            uptime_seconds=_uptime(),
            started_at=_STARTUP_TS.isoformat(),
            services=health.as_dict()["services"],
            feature_flags=feature_flags,
            enabled_modules=enabled_modules,
            migration_version=migration_version,
            first_boot_complete=first_boot,
        )

    def _get_feature_flags(self) -> Dict[str, bool]:
        """Read feature flags from meta DB."""
        flags = {
            "llm_consensus": True,
            "trustgraph": True,
            "real_time_streaming": True,
            "compliance_engine": True,
            "attack_surface": True,
            "auto_fix": True,
            "material_change_detector": True,
        }
        for flag_name in flags:
            stored = self._meta_get(f"feature_flag.{flag_name}")
            if stored:
                flags[flag_name] = stored.lower() == "true"
        # Override via environment
        if os.getenv("FIXOPS_DISABLE_LLM_CONSENSUS") == "1":
            flags["llm_consensus"] = False
        return flags

    def _discover_enabled_modules(self) -> List[str]:
        """Try to import key modules and report which are available."""
        # trustgraph.store — RETIRED 2026-05-03 per
        # docs/suite_core_install_retire_decisions_2026-05-03.md
        # Superseded by suite-core.trustgraph package; legacy entry removed
        # so module_map no longer reports the dead probe as "missing".
        module_map = {
            "brain_pipeline": "core.brain_pipeline",
            "connector_framework": "core.connectors",
            "scanner_parsers": "core.scanner_parsers",
            "llm_council": "core.council_adapter",
            "pipeline_orchestrator": "core.pipeline_orchestrator",
            "auto_fix": "core.autofix_engine",
        }
        enabled: List[str] = []
        for name, module_path in module_map.items():
            try:
                importlib.import_module(module_path)  # nosemgrep: non-literal-import
                enabled.append(name)
            except ImportError:
                pass
        return enabled

    # ─── Sanitized Configuration ───────────────────────────────────────────

    def get_sanitized_config(self) -> Dict[str, Any]:
        """Return current configuration with secrets redacted."""

        def _mask(val: Optional[str]) -> str:
            if not val:
                return ""
            if len(val) <= 8:
                return "***"
            return val[:4] + "***" + val[-2:]

        return {
            "mode": os.getenv("ALDECI_MODE", os.getenv("FIXOPS_MODE", "enterprise")),
            "version": ALDECI_VERSION,
            "build": ALDECI_BUILD,
            "data_dir": os.getenv("FIXOPS_DATA_DIR", "/app/data"),
            "log_level": os.getenv("FIXOPS_LOG_LEVEL", "warning"),
            "api_token_set": bool(os.getenv("FIXOPS_API_TOKEN")),
            "api_token_preview": _mask(os.getenv("FIXOPS_API_TOKEN")),
            "jwt_secret_set": bool(os.getenv("FIXOPS_JWT_SECRET")),
            "database_url_preview": _mask_dsn(self._postgres_dsn),
            "redis_url": self._redis_url,
            "trustgraph_url": self._trustgraph_url,
            "workers": os.getenv("FIXOPS_WORKERS", "1"),
            "rate_limit_enabled": os.getenv("FIXOPS_DISABLE_RATE_LIMIT") != "1",
            "telemetry_enabled": os.getenv("FIXOPS_DISABLE_TELEMETRY") != "1",
            "llm_providers": {
                "openai": bool(os.getenv("OPENAI_API_KEY")),
                "anthropic": bool(os.getenv("ANTHROPIC_API_KEY")),
                "openrouter": bool(os.getenv("OPENROUTER_API_KEY")),
                "ollama": bool(os.getenv("FIXOPS_OLLAMA_URL")),
            },
            "feature_flags": self._get_feature_flags(),
            "enabled_modules": self._discover_enabled_modules(),
        }


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _mask_dsn(dsn: str) -> str:
    """Mask password in a DSN like postgresql://user:pass@host:port/db."""
    try:
        if "://" not in dsn:
            return dsn
        scheme, rest = dsn.split("://", 1)
        if "@" in rest:
            creds, host_part = rest.rsplit("@", 1)
            user = creds.split(":")[0]
            return f"{scheme}://{user}:***@{host_part}"
        return dsn
    except Exception:
        return "***"


# ─── Singleton ────────────────────────────────────────────────────────────────

_manager: Optional[DeploymentManager] = None


def get_deployment_manager() -> DeploymentManager:
    """Return the singleton DeploymentManager instance."""
    global _manager
    if _manager is None:
        _manager = DeploymentManager()
    return _manager
