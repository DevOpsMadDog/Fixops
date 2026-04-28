"""
API Versioning module for ALDECI/Fixops.

Provides:
- APIVersion and DeprecationStatus enums
- EndpointVersion and VersionNegotiation Pydantic models
- APIVersionManager (SQLite-backed) for registering, deprecating,
  querying versioned endpoints
- VersioningMiddleware that injects X-API-Version / Deprecation / Sunset
  response headers
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Request, Response
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class APIVersion(str, Enum):
    V1 = "v1"
    V2 = "v2"


class DeprecationStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUNSET = "sunset"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class EndpointVersion(BaseModel):
    path: str = Field(..., description="API endpoint path, e.g. /api/v1/findings")
    version: APIVersion = Field(..., description="API version this endpoint belongs to")
    status: DeprecationStatus = Field(
        default=DeprecationStatus.ACTIVE, description="Lifecycle status"
    )
    deprecated_at: Optional[str] = Field(
        None, description="ISO-8601 timestamp when deprecation was announced"
    )
    sunset_date: Optional[str] = Field(
        None, description="ISO-8601 date when endpoint will be removed"
    )
    replacement_path: Optional[str] = Field(
        None, description="Replacement endpoint path"
    )
    migration_guide: Optional[str] = Field(
        None, description="Human-readable migration instructions"
    )


class VersionNegotiation(BaseModel):
    requested: str = Field(..., description="Raw version string from request")
    resolved: APIVersion = Field(..., description="Resolved API version")
    method: str = Field(
        ..., description="Negotiation method: 'header', 'url', or 'default'"
    )


# ---------------------------------------------------------------------------
# APIVersionManager
# ---------------------------------------------------------------------------


class APIVersionManager:
    """SQLite-backed manager for API version lifecycle."""

    _DEFAULT_DB = "data/api_versioning.db"

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = Path(db_path or self._DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        with self._lock:
            with self._conn() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS endpoint_versions (
                        path TEXT NOT NULL,
                        version TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        deprecated_at TEXT,
                        sunset_date TEXT,
                        replacement_path TEXT,
                        migration_guide TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (path, version)
                    );
                    CREATE INDEX IF NOT EXISTS idx_ev_version ON endpoint_versions(version);
                    CREATE INDEX IF NOT EXISTS idx_ev_status  ON endpoint_versions(status);
                    """
                )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_model(row: sqlite3.Row) -> EndpointVersion:
        return EndpointVersion(
            path=row["path"],
            version=APIVersion(row["version"]),
            status=DeprecationStatus(row["status"]),
            deprecated_at=row["deprecated_at"],
            sunset_date=row["sunset_date"],
            replacement_path=row["replacement_path"],
            migration_guide=row["migration_guide"],
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_endpoint(
        self,
        path: str,
        version: APIVersion,
        status: DeprecationStatus = DeprecationStatus.ACTIVE,
    ) -> EndpointVersion:
        """Register a new endpoint version (upsert)."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO endpoint_versions
                        (path, version, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(path, version) DO UPDATE SET
                        status = excluded.status,
                        updated_at = excluded.updated_at
                    """,
                    (path, version.value, status.value, now, now),
                )
        return EndpointVersion(path=path, version=version, status=status)

    def deprecate_endpoint(
        self,
        path: str,
        version: APIVersion,
        replacement_path: Optional[str] = None,
        sunset_date: Optional[str] = None,
        migration_guide: Optional[str] = None,
    ) -> EndpointVersion:
        """Mark an endpoint as deprecated and set sunset/replacement info."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE endpoint_versions
                    SET status = 'deprecated',
                        deprecated_at = ?,
                        sunset_date = ?,
                        replacement_path = ?,
                        migration_guide = ?,
                        updated_at = ?
                    WHERE path = ? AND version = ?
                    """,
                    (
                        now,
                        sunset_date,
                        replacement_path,
                        migration_guide,
                        now,
                        path,
                        version.value,
                    ),
                )
                if conn.execute(
                    "SELECT changes()"
                ).fetchone()[0] == 0:
                    # Row did not exist — insert it as deprecated
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO endpoint_versions
                            (path, version, status, deprecated_at, sunset_date,
                             replacement_path, migration_guide, created_at, updated_at)
                        VALUES (?, ?, 'deprecated', ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            path,
                            version.value,
                            now,
                            sunset_date,
                            replacement_path,
                            migration_guide,
                            now,
                            now,
                        ),
                    )
        ev = self.get_endpoint_version(path)
        if ev is None:
            # Fallback: return constructed model
            return EndpointVersion(
                path=path,
                version=version,
                status=DeprecationStatus.DEPRECATED,
                deprecated_at=now,
                sunset_date=sunset_date,
                replacement_path=replacement_path,
                migration_guide=migration_guide,
            )
        return ev

    def get_endpoint_version(self, path: str) -> Optional[EndpointVersion]:
        """Return the most relevant version record for a path (prefers v2 > v1)."""
        with self._conn() as conn:
            # Return latest version for the path (v2 > v1 ordering)
            row = conn.execute(
                """
                SELECT * FROM endpoint_versions
                WHERE path = ?
                ORDER BY CASE version WHEN 'v2' THEN 0 ELSE 1 END
                LIMIT 1
                """,
                (path,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_model(row)

    def get_endpoint_version_for(
        self, path: str, version: APIVersion
    ) -> Optional[EndpointVersion]:
        """Return version record for a specific path+version pair."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM endpoint_versions WHERE path = ? AND version = ?",
                (path, version.value),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_model(row)

    def list_endpoints(
        self,
        version: Optional[APIVersion] = None,
        status_filter: Optional[DeprecationStatus] = None,
    ) -> List[EndpointVersion]:
        """List endpoints, optionally filtered by version and/or status."""
        query = "SELECT * FROM endpoint_versions WHERE 1=1"
        params: list[Any] = []
        if version is not None:
            query += " AND version = ?"
            params.append(version.value)
        if status_filter is not None:
            query += " AND status = ?"
            params.append(status_filter.value)
        query += " ORDER BY path, version"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_model(r) for r in rows]

    def negotiate_version(self, request: Request) -> VersionNegotiation:
        """
        Determine API version from request:
        1. Accept-Version header
        2. URL prefix (/api/v1/, /api/v2/)
        3. Default to V1
        """
        # 1. Header
        header_val = request.headers.get("Accept-Version") or request.headers.get(
            "accept-version"
        )
        if header_val:
            normalized = header_val.strip().lower().lstrip("v")
            try:
                resolved = APIVersion(f"v{normalized}" if not normalized.startswith("v") else normalized)
                return VersionNegotiation(
                    requested=header_val, resolved=resolved, method="header"
                )
            except ValueError:
                pass  # fall through to URL check

        # 2. URL prefix
        path = request.url.path
        if "/v2/" in path or path.endswith("/v2"):
            return VersionNegotiation(
                requested="v2", resolved=APIVersion.V2, method="url"
            )
        if "/v1/" in path or path.endswith("/v1"):
            return VersionNegotiation(
                requested="v1", resolved=APIVersion.V1, method="url"
            )

        # 3. Default
        return VersionNegotiation(
            requested="default", resolved=APIVersion.V1, method="default"
        )

    def get_deprecation_warnings(
        self, version: APIVersion
    ) -> List[EndpointVersion]:
        """Return all endpoints deprecated in the given version."""
        return self.list_endpoints(
            version=version, status_filter=DeprecationStatus.DEPRECATED
        )

    def get_migration_guide(
        self, path: str, from_version: APIVersion, to_version: APIVersion
    ) -> str:
        """Return migration guide for upgrading path from one version to another."""
        ev = self.get_endpoint_version_for(path, from_version)
        if ev is None:
            return (
                f"No version record found for {path} at {from_version.value}. "
                "Please register the endpoint first."
            )
        if ev.migration_guide:
            return ev.migration_guide
        replacement = ev.replacement_path or path.replace(
            f"/{from_version.value}/", f"/{to_version.value}/"
        )
        return (
            f"Migrate {path} ({from_version.value}) → {replacement} ({to_version.value}). "
            "Update your API client to use the new path. "
            "Request/response schemas are backward-compatible unless noted."
        )

    def get_sunset_schedule(self) -> List[EndpointVersion]:
        """Return all endpoints that have a sunset_date set (upcoming sunsets)."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM endpoint_versions
                WHERE sunset_date IS NOT NULL
                  AND status IN ('deprecated', 'sunset')
                ORDER BY sunset_date
                """
            ).fetchall()
        return [self._row_to_model(r) for r in rows]

    def get_versioning_stats(self) -> Dict[str, Any]:
        """Return high-level versioning statistics."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM endpoint_versions"
            ).fetchone()[0]

            per_version = {}
            for row in conn.execute(
                "SELECT version, COUNT(*) as cnt FROM endpoint_versions GROUP BY version"
            ).fetchall():
                per_version[row["version"]] = row["cnt"]

            per_status = {}
            for row in conn.execute(
                "SELECT status, COUNT(*) as cnt FROM endpoint_versions GROUP BY status"
            ).fetchall():
                per_status[row["status"]] = row["cnt"]

            with_sunset = conn.execute(
                "SELECT COUNT(*) FROM endpoint_versions WHERE sunset_date IS NOT NULL"
            ).fetchone()[0]

        return {
            "total_endpoints": total,
            "endpoints_per_version": per_version,
            "endpoints_per_status": per_status,
            "deprecated_count": per_status.get("deprecated", 0),
            "sunset_count": per_status.get("sunset", 0),
            "endpoints_with_sunset_date": with_sunset,
            "supported_versions": [v.value for v in APIVersion],
        }


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class VersioningMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that:
    - Resolves the API version for every request
    - Adds X-API-Version response header
    - Adds Deprecation and Sunset headers when the endpoint is deprecated
    """

    def __init__(self, app: ASGIApp, version_manager: APIVersionManager) -> None:
        super().__init__(app)
        self._vm = version_manager

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        negotiation = self._vm.negotiate_version(request)
        response: Response = await call_next(request)

        response.headers["X-API-Version"] = negotiation.resolved.value
        response.headers["X-Version-Method"] = negotiation.method

        # Attach deprecation headers if this endpoint is deprecated
        path = request.url.path
        ev = self._vm.get_endpoint_version(path)
        if ev is not None and ev.status in (
            DeprecationStatus.DEPRECATED,
            DeprecationStatus.SUNSET,
        ):
            if ev.deprecated_at:
                response.headers["Deprecation"] = ev.deprecated_at
            if ev.sunset_date:
                response.headers["Sunset"] = ev.sunset_date
            if ev.replacement_path:
                response.headers["Link"] = (
                    f'<{ev.replacement_path}>; rel="successor-version"'
                )

        return response


# ---------------------------------------------------------------------------
# Module-level singleton (optional convenience)
# ---------------------------------------------------------------------------

_default_manager: Optional[APIVersionManager] = None
_manager_lock = threading.Lock()


def get_version_manager(db_path: Optional[str] = None) -> APIVersionManager:
    """Return the module-level singleton APIVersionManager."""
    global _default_manager
    with _manager_lock:
        if _default_manager is None:
            _default_manager = APIVersionManager(db_path=db_path)
    return _default_manager
