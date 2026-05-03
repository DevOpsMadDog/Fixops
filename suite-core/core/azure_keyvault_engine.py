"""Azure Key Vault Engine — ALDECI.

Live Microsoft Azure Key Vault REST API client (vaults via ARM, secrets / keys /
certificates via the Key Vault data plane).

Reads ``AZURE_TENANT_ID`` + ``AZURE_CLIENT_ID`` + ``AZURE_CLIENT_SECRET`` from
env. OAuth2 ``client_credentials`` flow against
``login.microsoftonline.com/{tenant}/oauth2/v2.0/token`` with two distinct
scopes — one per Azure plane:

  * ``https://management.azure.com/.default``  → ARM (vault enumeration)
  * ``https://vault.azure.net/.default``       → Key Vault data plane

Both tokens are cached in-memory with a 50-minute TTL. NO SQLite cache. NO
MOCKS — when env unset every lookup raises :class:`RuntimeError` which the
router maps to HTTP 503.

Compliance: NIST SP 800-57, ISO/IEC 27001 A.10, SOC 2 CC6.1, FIPS 140-2/3.
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
_MGMT_BASE = os.environ.get(
    "AZURE_MGMT_BASE", "https://management.azure.com"
).rstrip("/")
_KV_DOMAIN = os.environ.get(
    "AZURE_KEYVAULT_DOMAIN", "vault.azure.net"
).strip(". ")

_MGMT_SCOPE = os.environ.get(
    "AZURE_MGMT_SCOPE", "https://management.azure.com/.default"
)
_KV_SCOPE = os.environ.get(
    "AZURE_KEYVAULT_SCOPE", f"https://{_KV_DOMAIN}/.default"
)

# API versions (Microsoft.KeyVault ARM + Key Vault data plane).
_ARM_API_VERSION = os.environ.get("AZURE_KEYVAULT_ARM_API_VERSION", "2023-07-01")
_KV_API_VERSION = os.environ.get("AZURE_KEYVAULT_DATA_API_VERSION", "7.4")

# Token cache lifetime — Microsoft tokens are 60min; refresh at ~50min.
_TOKEN_TTL_SECONDS = 50 * 60


class AzureKeyVaultEngine:
    """Live Microsoft Azure Key Vault client (ARM + data plane).

    Uses OAuth2 ``client_credentials`` flow with two cached bearer tokens —
    one scoped to ARM (vault enumeration), one scoped to the Key Vault data
    plane (secrets / keys / certificates). No persistent storage of
    credentials or tokens.
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

        # Two separate token caches (one per scope).
        self._tokens: Dict[str, str] = {}
        self._token_expires_at: Dict[str, float] = {}

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
                "Azure Key Vault not configured: AZURE_TENANT_ID, "
                "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET must be set"
            )

    # ------------------------------------------------------------------
    # OAuth2 client_credentials flow (per-scope token cache)
    # ------------------------------------------------------------------

    def _fetch_token(self, scope: str) -> str:
        """Acquire a fresh bearer token for the given scope."""
        self._require_configured()
        url = f"{_LOGIN_BASE}/{self._tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": scope,
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

    def _get_token(self, scope: str) -> str:
        """Return cached token for scope or fetch a new one if expired."""
        now = time.time()
        with self._lock:
            cached = self._tokens.get(scope)
            expires = self._token_expires_at.get(scope, 0.0)
            if cached and now < expires:
                return cached
            token = self._fetch_token(scope)
            self._tokens[scope] = token
            self._token_expires_at[scope] = now + _TOKEN_TTL_SECONDS
            return token

    def _arm_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token(_MGMT_SCOPE)}",
            "Accept": "application/json",
        }

    def _kv_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token(_KV_SCOPE)}",
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
            "service": "Azure Key Vault",
            "endpoints": [
                "/vaults",
                "/vaults/{name}/secrets",
                "/vaults/{name}/secrets/{secret}",
                "/vaults/{name}/keys",
                "/vaults/{name}/certificates",
            ],
            "azure_tenant_present": self.tenant_present,
            "azure_client_present": self.client_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Generic GET helpers
    # ------------------------------------------------------------------

    def _arm_get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        merged: Dict[str, Any] = {"api-version": _ARM_API_VERSION}
        if params:
            for k, v in params.items():
                if v is not None:
                    merged[k] = v
        resp = self._client_inst().get(
            url,
            params=merged,
            headers=self._arm_headers(),
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def _kv_get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        merged: Dict[str, Any] = {"api-version": _KV_API_VERSION}
        if params:
            for k, v in params.items():
                if v is not None:
                    merged[k] = v
        resp = self._client_inst().get(
            url,
            params=merged,
            headers=self._kv_headers(),
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------
    # ARM — vaults enumeration
    # ------------------------------------------------------------------

    def list_vaults(
        self,
        subscription_id: str,
        resource_group_name: str,
        top: Optional[int] = None,
    ) -> Dict[str, Any]:
        url = (
            f"{_MGMT_BASE}/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.KeyVault/vaults"
        )
        params: Dict[str, Any] = {}
        if top is not None:
            params["$top"] = top
        return self._arm_get(url, params=params)

    # ------------------------------------------------------------------
    # Data plane — secrets
    # ------------------------------------------------------------------

    def _vault_base(self, vault_name: str) -> str:
        return f"https://{vault_name}.{_KV_DOMAIN}"

    def list_secrets(
        self,
        vault_name: str,
        maxresults: Optional[int] = None,
    ) -> Dict[str, Any]:
        url = f"{self._vault_base(vault_name)}/secrets"
        params: Dict[str, Any] = {}
        if maxresults is not None:
            params["maxresults"] = maxresults
        return self._kv_get(url, params=params)

    def get_secret(
        self,
        vault_name: str,
        secret_name: str,
        version: str = "",
    ) -> Dict[str, Any]:
        suffix = f"/{version}" if version else ""
        url = f"{self._vault_base(vault_name)}/secrets/{secret_name}{suffix}"
        return self._kv_get(url)

    def list_secret_versions(
        self,
        vault_name: str,
        secret_name: str,
        maxresults: Optional[int] = None,
    ) -> Dict[str, Any]:
        url = f"{self._vault_base(vault_name)}/secrets/{secret_name}/versions"
        params: Dict[str, Any] = {}
        if maxresults is not None:
            params["maxresults"] = maxresults
        return self._kv_get(url, params=params)

    # ------------------------------------------------------------------
    # Data plane — keys
    # ------------------------------------------------------------------

    def list_keys(
        self,
        vault_name: str,
        maxresults: Optional[int] = None,
    ) -> Dict[str, Any]:
        url = f"{self._vault_base(vault_name)}/keys"
        params: Dict[str, Any] = {}
        if maxresults is not None:
            params["maxresults"] = maxresults
        return self._kv_get(url, params=params)

    def get_key(
        self,
        vault_name: str,
        key_name: str,
        version: str = "",
    ) -> Dict[str, Any]:
        suffix = f"/{version}" if version else ""
        url = f"{self._vault_base(vault_name)}/keys/{key_name}{suffix}"
        return self._kv_get(url)

    # ------------------------------------------------------------------
    # Data plane — certificates
    # ------------------------------------------------------------------

    def list_certificates(
        self,
        vault_name: str,
        maxresults: Optional[int] = None,
    ) -> Dict[str, Any]:
        url = f"{self._vault_base(vault_name)}/certificates"
        params: Dict[str, Any] = {}
        if maxresults is not None:
            params["maxresults"] = maxresults
        return self._kv_get(url, params=params)

    def get_certificate(
        self,
        vault_name: str,
        cert_name: str,
        version: str = "",
    ) -> Dict[str, Any]:
        suffix = f"/{version}" if version else ""
        url = f"{self._vault_base(vault_name)}/certificates/{cert_name}{suffix}"
        return self._kv_get(url)

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
            self._tokens.clear()
            self._token_expires_at.clear()


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[AzureKeyVaultEngine] = None


def get_azure_keyvault_engine() -> AzureKeyVaultEngine:
    """Return process-wide AzureKeyVaultEngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = AzureKeyVaultEngine()
    return _singleton


def reset_azure_keyvault_engine() -> None:
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
    "AzureKeyVaultEngine",
    "get_azure_keyvault_engine",
    "reset_azure_keyvault_engine",
]
