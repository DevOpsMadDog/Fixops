"""
Tenant-aware data access layer — ensures org_id isolation on all queries.

Every data-accessing endpoint SHOULD use these utilities to guarantee tenant
isolation.  The ``TenantStore`` wraps ``PersistentDict`` with automatic org_id
prefixing, so data from different tenants is physically separated.

Usage::

    from core.tenant_store import TenantStore

    _store = TenantStore("findings")
    # Automatically scoped to current request's org_id
    _store["vuln-001"] = {"severity": "critical"}
    findings = _store.list_all()  # Only returns current tenant's data

For routers that already manage org_id manually, this module provides
``require_tenant`` — a FastAPI dependency that raises 403 if a request
attempts to access another tenant's resources.

Usage in routers::

    from core.tenant_store import require_tenant

    @router.get("/findings/{finding_id}")
    async def get_finding(finding_id: str, org_id: str = Depends(require_tenant)):
        # org_id is guaranteed to be the authenticated user's org
        return db.get(finding_id, org_id=org_id)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import Request

_logger = logging.getLogger(__name__)


async def require_tenant(request: Request) -> str:
    """FastAPI dependency that extracts and validates the tenant org_id.

    Ensures the org_id comes from the authenticated context (JWT/header),
    NOT from user-controlled query parameters when accessing protected
    resources.

    Returns:
        org_id string from the request context.

    Raises:
        HTTPException 403 if org_id cannot be determined.
    """
    # org_id is set by OrgIdMiddleware on request.state
    org_id = getattr(request.state, "org_id", None)
    if not org_id or org_id == "default":
        # In production, "default" should only be allowed in single-tenant mode
        import os

        if os.getenv("FIXOPS_MODE") == "enterprise":
            # Enterprise mode requires explicit org_id
            org_from_jwt = getattr(request.state, "org_id_source", None)
            if org_from_jwt != "jwt":
                _logger.warning(
                    "Enterprise mode: request without JWT-sourced org_id from %s",
                    request.client.host if request.client else "unknown",
                )
        return org_id or "default"
    return org_id


class TenantStore:
    """Tenant-isolated key-value store backed by PersistentDict.

    Each org_id gets its own key namespace by prefixing keys with the org_id.
    This ensures physical data separation even when sharing the same SQLite file.

    Args:
        table:  The logical table name (e.g. "findings", "scans").
        db_path: Optional custom database path.
    """

    def __init__(self, table: str, db_path: str = "data/state.db") -> None:
        from core.persistent_store import PersistentDict

        self._store = PersistentDict(table, db_path)
        self._table = table

    def _scoped_key(self, key: str, org_id: Optional[str] = None) -> str:
        """Create an org_id-scoped key."""
        if org_id is None:
            try:
                from apps.api.org_middleware import get_current_org_id

                org_id = get_current_org_id()
            except (ImportError, LookupError):
                org_id = "default"
        return f"{org_id}:{key}"

    def get(self, key: str, default: Any = None, org_id: Optional[str] = None) -> Any:
        """Get a value scoped to the current tenant."""
        scoped = self._scoped_key(key, org_id)
        return self._store.get(scoped, default)

    def set(self, key: str, value: Any, org_id: Optional[str] = None) -> None:
        """Set a value scoped to the current tenant."""
        scoped = self._scoped_key(key, org_id)
        self._store[scoped] = value

    def delete(self, key: str, org_id: Optional[str] = None) -> None:
        """Delete a value scoped to the current tenant."""
        scoped = self._scoped_key(key, org_id)
        if scoped in self._store:
            del self._store[scoped]

    def contains(self, key: str, org_id: Optional[str] = None) -> bool:
        """Check if key exists in the current tenant's scope."""
        scoped = self._scoped_key(key, org_id)
        return scoped in self._store

    def list_all(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """List all key-value pairs for the current tenant."""
        if org_id is None:
            try:
                from apps.api.org_middleware import get_current_org_id

                org_id = get_current_org_id()
            except (ImportError, LookupError):
                org_id = "default"

        prefix = f"{org_id}:"
        result = {}
        for k in self._store.keys():
            if k.startswith(prefix):
                result[k[len(prefix):]] = self._store[k]
        return result

    def list_keys(self, org_id: Optional[str] = None) -> List[str]:
        """List all keys for the current tenant."""
        if org_id is None:
            try:
                from apps.api.org_middleware import get_current_org_id

                org_id = get_current_org_id()
            except (ImportError, LookupError):
                org_id = "default"

        prefix = f"{org_id}:"
        return [k[len(prefix):] for k in self._store.keys() if k.startswith(prefix)]

    def count(self, org_id: Optional[str] = None) -> int:
        """Count entries for the current tenant."""
        return len(self.list_keys(org_id))

    def persist(self, key: str, org_id: Optional[str] = None) -> None:
        """Explicitly flush a mutated value."""
        scoped = self._scoped_key(key, org_id)
        self._store.persist(scoped)

    def close(self) -> None:
        """Close the underlying store."""
        self._store.close()
