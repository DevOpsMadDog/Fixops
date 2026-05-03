"""Microsoft Purview DLP Engine — ALDECI.

Live Microsoft Purview / Microsoft 365 compliance + Microsoft Graph DLP client.

Reads AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET from env.
OAuth2 client_credentials flow against
``login.microsoftonline.com/{tenant}/oauth2/v2.0/token`` with
``scope=https://graph.microsoft.com/.default``. Token cached in-memory ~50min.

NO SQLite cache. NO MOCKS — when env unset every lookup raises RuntimeError
which the router maps to HTTP 503.

Coverage:
  GET /v1.0/security/dataLossPreventionPolicies
  GET /v1.0/security/labels/sensitivityLabels
  GET /v1.0/security/incidents              (Defender XDR DLP-flagged)
  GET /v1.0/security/cases/ediscoveryCases
  GET /v1.0/dataClassification/sensitiveTypes

Compliance: NIST CSF PR.DS, ISO/IEC 27001 A.8.2, SOC 2 CC6.1, GDPR Art. 32
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, Optional

import httpx

try:  # pragma: no cover - bus optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None


_logger = logging.getLogger(__name__)


# Public Azure cloud endpoints (override-able via env for sovereign clouds).
_LOGIN_BASE = os.environ.get(
    "AZURE_AAD_LOGIN_BASE", "https://login.microsoftonline.com"
).rstrip("/")
_GRAPH_BASE = os.environ.get(
    "MS_GRAPH_BASE", "https://graph.microsoft.com"
).rstrip("/")
_GRAPH_SCOPE = os.environ.get(
    "MS_GRAPH_SCOPE", "https://graph.microsoft.com/.default"
)

# Token cache lifetime — Microsoft tokens are 60min; refresh at ~50min.
_TOKEN_TTL_SECONDS = 50 * 60


class PurviewDLPEngine:
    """Live Microsoft Purview DLP client via Microsoft Graph + Compliance APIs.

    Uses OAuth2 client_credentials flow. Token is cached in-memory with a
    50-minute TTL (well below the 60-minute Azure default). No persistent
    storage of credentials or tokens. NO MOCKS.
    """

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        self._tenant_id = (tenant_id or os.environ.get("AZURE_TENANT_ID", "")).strip()
        self._client_id = (client_id or os.environ.get("AZURE_CLIENT_ID", "")).strip()
        self._client_secret = (
            client_secret or os.environ.get("AZURE_CLIENT_SECRET", "")
        ).strip()
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._lock = threading.RLock()
        self._client: Optional[httpx.Client] = None

        # Token cache.
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # Configuration probes
    # ------------------------------------------------------------------

    @property
    def tenant_present(self) -> bool:
        return bool(self._tenant_id)

    @property
    def client_present(self) -> bool:
        return bool(self._client_id) and bool(self._client_secret)

    @property
    def configured(self) -> bool:
        return self.tenant_present and self.client_present

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
                "Microsoft Purview DLP not configured: AZURE_TENANT_ID, "
                "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET must be set"
            )

    # ------------------------------------------------------------------
    # OAuth2 client_credentials flow
    # ------------------------------------------------------------------

    def _fetch_token(self) -> str:
        self._require_configured()
        url = f"{_LOGIN_BASE}/{self._tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": _GRAPH_SCOPE,
        }
        resp = self._client_inst().post(
            url,
            data=data,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Azure AAD token endpoint returned non-JSON: {exc}"
            ) from exc
        token = payload.get("access_token")
        if not token:
            raise RuntimeError(
                f"Azure AAD token response missing access_token: {payload}"
            )
        return token

    def _get_token(self) -> str:
        now = time.time()
        with self._lock:
            if self._token and now < self._token_expires_at:
                return self._token
            self._token = self._fetch_token()
            self._token_expires_at = now + _TOKEN_TTL_SECONDS
            return self._token

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------

    def capability_summary(self) -> Dict[str, Any]:
        if not self.configured:
            status = "unavailable"
        elif not (self.tenant_present and self.client_present):
            status = "empty"
        else:
            status = "ok"
        return {
            "service": "Microsoft Purview DLP",
            "endpoints": [
                "/v1.0/security/dataLossPreventionPolicies",
                "/v1.0/security/labels/sensitivityLabels",
                "/v1.0/security/incidents",
                "/v1.0/security/cases/ediscoveryCases",
                "/v1.0/dataClassification/sensitiveTypes",
            ],
            "azure_tenant_present": self.tenant_present,
            "azure_client_present": self.client_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Graph helpers
    # ------------------------------------------------------------------

    def _build_odata_params(
        self,
        top: Optional[int] = None,
        skip: Optional[int] = None,
        odata_filter: Optional[str] = None,
        orderby: Optional[str] = None,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if top is not None:
            params["$top"] = top
        if skip is not None:
            params["$skip"] = skip
        if odata_filter:
            params["$filter"] = odata_filter
        if orderby:
            params["$orderby"] = orderby
        if expand:
            params["$expand"] = expand
        return params

    def _get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        resp = self._client_inst().get(
            url,
            params=params or {},
            headers=self._auth_headers(),
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------
    # DLP policies
    # ------------------------------------------------------------------

    def list_dlp_policies(
        self,
        top: Optional[int] = None,
        skip: Optional[int] = None,
        odata_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = f"{_GRAPH_BASE}/v1.0/security/dataLossPreventionPolicies"
        params = self._build_odata_params(
            top=top, skip=skip, odata_filter=odata_filter
        )
        return self._get(url, params=params)

    # ------------------------------------------------------------------
    # Sensitivity labels
    # ------------------------------------------------------------------

    def list_sensitivity_labels(
        self,
        top: Optional[int] = None,
        odata_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = f"{_GRAPH_BASE}/v1.0/security/labels/sensitivityLabels"
        params = self._build_odata_params(top=top, odata_filter=odata_filter)
        return self._get(url, params=params)

    # ------------------------------------------------------------------
    # Defender XDR incidents (DLP-flagged)
    # ------------------------------------------------------------------

    def list_incidents(
        self,
        top: Optional[int] = None,
        odata_filter: Optional[str] = None,
        orderby: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = f"{_GRAPH_BASE}/v1.0/security/incidents"
        params = self._build_odata_params(
            top=top, odata_filter=odata_filter, orderby=orderby
        )
        return self._get(url, params=params)

    # ------------------------------------------------------------------
    # eDiscovery cases
    # ------------------------------------------------------------------

    def list_ediscovery_cases(
        self,
        top: Optional[int] = None,
        odata_filter: Optional[str] = None,
        orderby: Optional[str] = None,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = f"{_GRAPH_BASE}/v1.0/security/cases/ediscoveryCases"
        params = self._build_odata_params(
            top=top,
            odata_filter=odata_filter,
            orderby=orderby,
            expand=expand,
        )
        return self._get(url, params=params)

    # ------------------------------------------------------------------
    # Sensitive types (data classification)
    # ------------------------------------------------------------------

    def list_sensitive_types(
        self,
        top: Optional[int] = None,
        odata_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = f"{_GRAPH_BASE}/v1.0/dataClassification/sensitiveTypes"
        params = self._build_odata_params(top=top, odata_filter=odata_filter)
        return self._get(url, params=params)

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
            self._token = None
            self._token_expires_at = 0.0


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[PurviewDLPEngine] = None


def get_purview_dlp_engine() -> PurviewDLPEngine:
    """Return process-wide PurviewDLPEngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = PurviewDLPEngine()
    return _singleton


def reset_purview_dlp_engine() -> None:
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
    "PurviewDLPEngine",
    "get_purview_dlp_engine",
    "reset_purview_dlp_engine",
]
