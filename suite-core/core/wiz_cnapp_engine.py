"""Wiz CNAPP/CSPM Engine — ALDECI.

Live Wiz REST/GraphQL client. OAuth2 client_credentials at
``auth.app.wiz.io/oauth/token`` (audience=wiz-api). Token cached in-memory
~30 min. NO SQLite cache. NO MOCKS — when env unset, capability_summary
returns ``status=unavailable`` and lookup endpoints raise.

Env:
  WIZ_CLIENT_ID       — OAuth2 client id
  WIZ_CLIENT_SECRET   — OAuth2 client secret
  WIZ_API_URL         — GraphQL endpoint, e.g. https://api.us17.app.wiz.io/graphql

Compliance: NIST CSF DE.CM, ISO/IEC 27001 A.12.4, SOC 2 CC7.2
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

try:  # pragma: no cover - bus optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None


_logger = logging.getLogger(__name__)


# Wiz GraphQL fragments (kept short — caller can override via raw GraphQL)
_ISSUES_QUERY = """
query Issues($first: Int, $after: String, $filterBy: IssueFilters) {
  issues(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      status
      severity
      type
      sourceRule { id name description }
      projects { id name }
      entitySnapshot { id name type }
      createdAt
      dueAt
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()

_INVENTORY_QUERY = """
query CloudResources($first: Int, $after: String, $filterBy: CloudResourceFilters) {
  cloudResources(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      name
      type
      region
      providerUniqueId
      project { id name }
      hasAccessOnPath
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()

_VULNS_QUERY = """
query Vulnerabilities($first: Int, $after: String, $filterBy: VulnerabilityFilters) {
  vulnerabilityFindings(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      name
      vendorSeverity
      score
      cvss31 { score vector }
      fixedVersion
      cvssDescription
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()

_THREATS_QUERY = """
query Threats($first: Int, $after: String) {
  threatDetections(first: $first, after: $after) {
    nodes {
      id
      name
      severity
      detectedAt
      ruleName
      affectedResource { id name type }
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()


class WizCNAPPEngine:
    """Live Wiz CNAPP client.

    Uses OAuth2 client_credentials against ``auth.app.wiz.io/oauth/token`` and
    caches the access token in-memory for ~30 min (Wiz default ttl is 24 h
    but we refresh proactively).
    """

    OAUTH_TOKEN_URL = "https://auth.app.wiz.io/oauth/token"
    OAUTH_AUDIENCE = "wiz-api"
    TOKEN_TTL_SECONDS = 30 * 60  # 30 min in-memory cache

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        self._client_id = client_id or os.environ.get("WIZ_CLIENT_ID", "")
        self._client_secret = client_secret or os.environ.get("WIZ_CLIENT_SECRET", "")
        self._api_url = (api_url or os.environ.get("WIZ_API_URL", "")).rstrip("/")
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._lock = threading.RLock()
        self._client: Optional[httpx.Client] = None
        # Token cache
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def client_id_present(self) -> bool:
        return bool(self._client_id)

    @property
    def client_secret_present(self) -> bool:
        return bool(self._client_secret)

    @property
    def api_url_present(self) -> bool:
        return bool(self._api_url)

    @property
    def configured(self) -> bool:
        return (
            self.client_id_present
            and self.client_secret_present
            and self.api_url_present
        )

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    def _client_inst(self) -> httpx.Client:
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = httpx.Client(
                        timeout=self._timeout,
                        verify=self._verify_tls,
                    )
        return self._client

    def _require_configured(self) -> None:
        if not self.configured:
            raise RuntimeError(
                "Wiz not configured: WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, "
                "and WIZ_API_URL must be set"
            )

    def _get_access_token(self) -> str:
        """OAuth2 client_credentials w/ in-memory ~30min cache."""
        now = time.time()
        if self._access_token and now < self._token_expires_at:
            return self._access_token

        with self._lock:
            now = time.time()
            if self._access_token and now < self._token_expires_at:
                return self._access_token

            resp = self._client_inst().post(
                self.OAUTH_TOKEN_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "audience": self.OAUTH_AUDIENCE,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            payload = resp.json()
            token = payload.get("access_token", "")
            if not token:
                raise RuntimeError("wiz oauth: empty access_token in response")
            self._access_token = token
            # Refresh proactively at TOKEN_TTL_SECONDS regardless of upstream ttl.
            self._token_expires_at = now + self.TOKEN_TTL_SECONDS
            return token

    def _headers(self) -> Dict[str, str]:
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------

    def capability_summary(self) -> Dict[str, Any]:
        if not self.configured:
            status = "unavailable"
        else:
            status = "ok"
        return {
            "service": "Wiz CNAPP",
            "endpoints": [
                "/graphql",
                "/issues",
                "/inventory",
                "/vulnerabilities",
                "/threats",
            ],
            "wiz_client_id_present": self.client_id_present,
            "wiz_client_secret_present": self.client_secret_present,
            "wiz_api_url_present": self.api_url_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Raw GraphQL passthrough
    # ------------------------------------------------------------------

    def graphql(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """POST {query, variables} to ``WIZ_API_URL`` GraphQL endpoint.

        Returns the parsed body. Errors from Wiz are surfaced as-is in
        ``errors``; HTTP errors raise ``httpx.HTTPStatusError``.
        """
        self._require_configured()
        body: Dict[str, Any] = {"query": query}
        if variables is not None:
            body["variables"] = variables

        resp = self._client_inst().post(
            self._api_url,
            json=body,
            headers=self._headers(),
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            payload = {"data": None, "raw": resp.text}

        # TrustGraph emit (best-effort)
        try:
            if _get_tg_bus is not None:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.emit_event(
                        "wiz.graphql.query",
                        {"variables": variables or {}, "errors": payload.get("errors")},
                    )
        except Exception:  # pragma: no cover
            pass

        return payload

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    def list_issues(
        self,
        status: Optional[str] = "OPEN",
        severity: Optional[List[str]] = None,
        project_id: Optional[str] = None,
        first: int = 50,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap GraphQL ``Issues`` query.

        Returns ``{"issues":[...], "pageInfo":{...}}``.
        """
        filter_by: Dict[str, Any] = {}
        if status:
            filter_by["status"] = [status]
        if severity:
            filter_by["severity"] = severity
        if project_id:
            filter_by["project"] = [project_id]

        variables: Dict[str, Any] = {
            "first": first,
            "after": after,
            "filterBy": filter_by or None,
        }
        payload = self.graphql(_ISSUES_QUERY, variables)
        data = (payload.get("data") or {}).get("issues") or {}
        return {
            "issues": data.get("nodes", []),
            "pageInfo": data.get("pageInfo", {"hasNextPage": False, "endCursor": None}),
            "errors": payload.get("errors"),
        }

    def list_inventory(
        self,
        types: Optional[List[str]] = None,
        project_id: Optional[str] = None,
        first: int = 50,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap GraphQL ``CloudResources`` query."""
        filter_by: Dict[str, Any] = {}
        if types:
            filter_by["type"] = types
        if project_id:
            filter_by["projectId"] = [project_id]

        variables: Dict[str, Any] = {
            "first": first,
            "after": after,
            "filterBy": filter_by or None,
        }
        payload = self.graphql(_INVENTORY_QUERY, variables)
        data = (payload.get("data") or {}).get("cloudResources") or {}
        return {
            "nodes": data.get("nodes", []),
            "pageInfo": data.get("pageInfo", {"hasNextPage": False, "endCursor": None}),
            "errors": payload.get("errors"),
        }

    def list_vulnerabilities(
        self,
        severity: Optional[List[str]] = None,
        first: int = 50,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap GraphQL ``Vulnerabilities`` query."""
        filter_by: Dict[str, Any] = {}
        if severity:
            filter_by["severity"] = severity

        variables: Dict[str, Any] = {
            "first": first,
            "after": after,
            "filterBy": filter_by or None,
        }
        payload = self.graphql(_VULNS_QUERY, variables)
        data = (payload.get("data") or {}).get("vulnerabilityFindings") or {}
        return {
            "nodes": data.get("nodes", []),
            "pageInfo": data.get("pageInfo", {"hasNextPage": False, "endCursor": None}),
            "errors": payload.get("errors"),
        }

    def list_threats(
        self,
        first: int = 50,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Wrap GraphQL ``Threats`` query (threat-detection signals)."""
        variables: Dict[str, Any] = {
            "first": first,
            "after": after,
        }
        payload = self.graphql(_THREATS_QUERY, variables)
        data = (payload.get("data") or {}).get("threatDetections") or {}
        return {
            "nodes": data.get("nodes", []),
            "pageInfo": data.get("pageInfo", {"hasNextPage": False, "endCursor": None}),
            "errors": payload.get("errors"),
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                finally:
                    self._client = None
            self._access_token = None
            self._token_expires_at = 0.0


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[WizCNAPPEngine] = None


def get_wiz_cnapp_engine() -> WizCNAPPEngine:
    """Return process-wide WizCNAPPEngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = WizCNAPPEngine()
    return _singleton


def reset_wiz_cnapp_engine() -> None:
    """Reset the singleton (test helper)."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            try:
                _singleton.close()
            except Exception:
                pass
        _singleton = None


__all__ = [
    "WizCNAPPEngine",
    "get_wiz_cnapp_engine",
    "reset_wiz_cnapp_engine",
]
