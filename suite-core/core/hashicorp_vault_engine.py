"""HashiCorp Vault Engine — ALDECI.

Wraps the HashiCorp Vault HTTP API and exposes a process-wide singleton.

Configuration (env)
-------------------
  VAULT_ADDR        Base URL of the Vault server (e.g. http://127.0.0.1:8200)
  VAULT_TOKEN       Vault token used for ``X-Vault-Token`` header
  VAULT_NAMESPACE   Optional Vault Enterprise namespace (X-Vault-Namespace)

NO MOCKS rule
-------------
When ``VAULT_ADDR`` or ``VAULT_TOKEN`` is unset the engine is still
constructible (capability summary still renders) but every live call raises
``HashiCorpVaultUnavailableError`` which the router translates to HTTP 503
with ``status="unavailable"``. We never fabricate secrets, policies, mounts
or auth methods. There is no SQLite cache.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 8.0


class HashiCorpVaultUnavailableError(RuntimeError):
    """Raised when Vault env is not configured or the API returned an unrecoverable error."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class HashiCorpVaultEngine:
    """Thread-safe HashiCorp Vault client with no SQLite cache."""

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        vault_namespace: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_addr = vault_addr
        self._explicit_token = vault_token
        self._explicit_namespace = vault_namespace
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- env

    def vault_addr(self) -> Optional[str]:
        v = self._explicit_addr or os.environ.get("VAULT_ADDR")
        if not v:
            return None
        v = v.strip()
        return v.rstrip("/") if v else None

    def vault_token(self) -> Optional[str]:
        v = self._explicit_token or os.environ.get("VAULT_TOKEN")
        return v.strip() if v else None

    def vault_namespace(self) -> Optional[str]:
        v = self._explicit_namespace or os.environ.get("VAULT_NAMESPACE")
        return v.strip() if v else None

    def vault_addr_present(self) -> bool:
        return bool(self.vault_addr())

    def vault_token_present(self) -> bool:
        return bool(self.vault_token())

    # ------------------------------------------------------------ helpers

    def _ensure_available(self) -> None:
        if not self.vault_addr_present():
            raise HashiCorpVaultUnavailableError(
                "VAULT_ADDR unset — configure the Vault server URL to enable HashiCorp Vault."
            )
        if not self.vault_token_present():
            raise HashiCorpVaultUnavailableError(
                "VAULT_TOKEN unset — configure a Vault token to enable HashiCorp Vault."
            )

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"X-Vault-Token": self.vault_token() or ""}
        ns = self.vault_namespace()
        if ns:
            h["X-Vault-Namespace"] = ns
        return h

    def _url(self, path: str) -> str:
        addr = self.vault_addr() or ""
        if not path.startswith("/"):
            path = "/" + path
        return addr + path

    def _check_response(self, resp: Any) -> Dict[str, Any]:
        sc = getattr(resp, "status_code", 0)
        # Health endpoint can encode state in non-200 codes; caller decides.
        if sc in (401, 403):
            raise HashiCorpVaultUnavailableError(
                f"Vault rejected token ({sc})."
            )
        if sc == 404:
            raise HashiCorpVaultUnavailableError("Vault path not found (404).")
        if sc >= 500 and sc not in (501, 503):
            raise HashiCorpVaultUnavailableError(
                f"Vault upstream error ({sc}): {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise HashiCorpVaultUnavailableError(
                f"Vault returned non-JSON payload: {exc}"
            ) from exc

    # ------------------------------------------------------------ HTTP

    def _http_get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        try:
            resp = self._client.get(
                self._url(path), params=params or {}, headers=self._headers()
            )
        except httpx.HTTPError as exc:
            raise HashiCorpVaultUnavailableError(
                f"Vault HTTP error: {exc}"
            ) from exc
        return self._check_response(resp)

    def _http_post(
        self, path: str, body: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        try:
            resp = self._client.post(
                self._url(path), json=body or {}, headers=self._headers()
            )
        except httpx.HTTPError as exc:
            raise HashiCorpVaultUnavailableError(
                f"Vault HTTP error: {exc}"
            ) from exc
        return self._check_response(resp)

    # -------------------------------------------------------- public API

    def health(
        self,
        standbyok: bool = True,
        perfstandbyok: bool = True,
        sealedcode: int = 503,
        uninitcode: int = 501,
    ) -> Dict[str, Any]:
        """``GET /v1/sys/health`` — Vault encodes state in HTTP code."""
        self._ensure_available()
        params: Dict[str, Any] = {}
        if standbyok:
            params["standbyok"] = "true"
        if perfstandbyok:
            params["perfstandbyok"] = "true"
        if sealedcode is not None:
            params["sealedcode"] = int(sealedcode)
        if uninitcode is not None:
            params["uninitcode"] = int(uninitcode)
        try:
            resp = self._client.get(
                self._url("/v1/sys/health"),
                params=params,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise HashiCorpVaultUnavailableError(
                f"Vault HTTP error: {exc}"
            ) from exc
        # Vault returns these status codes intentionally for /sys/health
        try:
            body = resp.json()
        except Exception as exc:
            raise HashiCorpVaultUnavailableError(
                f"Vault /sys/health returned non-JSON: {exc}"
            ) from exc
        return {
            "initialized": bool(body.get("initialized", False)),
            "sealed": bool(body.get("sealed", False)),
            "standby": bool(body.get("standby", False)),
            "performance_standby": bool(body.get("performance_standby", False)),
            "replication_performance_mode": body.get(
                "replication_performance_mode", "disabled"
            ),
            "replication_dr_mode": body.get("replication_dr_mode", "disabled"),
            "server_time_utc": int(body.get("server_time_utc", 0)),
            "version": body.get("version", ""),
            "cluster_name": body.get("cluster_name", ""),
            "cluster_id": body.get("cluster_id", ""),
        }

    def seal_status(self) -> Dict[str, Any]:
        """``GET /v1/sys/seal-status``"""
        self._ensure_available()
        body = self._http_get("/v1/sys/seal-status")
        return {
            "type": body.get("type", ""),
            "initialized": bool(body.get("initialized", False)),
            "sealed": bool(body.get("sealed", False)),
            "t": int(body.get("t", 0)),
            "n": int(body.get("n", 0)),
            "progress": int(body.get("progress", 0)),
            "nonce": body.get("nonce", ""),
            "version": body.get("version", ""),
            "build_date": body.get("build_date", ""),
            "migration": bool(body.get("migration", False)),
            "recovery_seal": bool(body.get("recovery_seal", False)),
            "storage_type": body.get("storage_type", ""),
        }

    def read_secret(self, path: str) -> Dict[str, Any]:
        """``GET /v1/secret/data/{path}`` — KV v2 read."""
        self._ensure_available()
        if not path:
            raise ValueError("path is required.")
        # Allow nested paths but quote each segment.
        encoded = "/".join(quote(seg, safe="") for seg in path.split("/") if seg)
        body = self._http_get(f"/v1/secret/data/{encoded}")
        data_block = body.get("data") or {}
        inner_data = data_block.get("data") or {}
        meta = data_block.get("metadata") or {}
        return {
            "data": {
                "data": inner_data,
                "metadata": {
                    "created_time": meta.get("created_time", ""),
                    "custom_metadata": meta.get("custom_metadata") or {},
                    "deletion_time": meta.get("deletion_time", ""),
                    "destroyed": bool(meta.get("destroyed", False)),
                    "version": int(meta.get("version", 0)),
                },
            }
        }

    def write_secret(
        self,
        path: str,
        data: Dict[str, Any],
        cas: Optional[int] = None,
    ) -> Dict[str, Any]:
        """``POST /v1/secret/data/{path}`` — KV v2 create/update."""
        self._ensure_available()
        if not path:
            raise ValueError("path is required.")
        if not isinstance(data, dict):
            raise ValueError("data must be an object.")
        encoded = "/".join(quote(seg, safe="") for seg in path.split("/") if seg)
        body_in: Dict[str, Any] = {"data": data}
        if cas is not None:
            body_in["options"] = {"cas": int(cas)}
        body = self._http_post(f"/v1/secret/data/{encoded}", body=body_in)
        meta = (body.get("data") or {})
        return {
            "data": {
                "created_time": meta.get("created_time", ""),
                "custom_metadata": meta.get("custom_metadata") or {},
                "deletion_time": meta.get("deletion_time", ""),
                "destroyed": bool(meta.get("destroyed", False)),
                "version": int(meta.get("version", 0)),
            }
        }

    def list_acl_policies(self) -> Dict[str, Any]:
        """``GET /v1/sys/policies/acl?list=true``"""
        self._ensure_available()
        body = self._http_get("/v1/sys/policies/acl", params={"list": "true"})
        data = body.get("data") or {}
        keys = data.get("keys") or []
        return {"data": {"keys": [str(k) for k in keys]}}

    def read_acl_policy(self, name: str) -> Dict[str, Any]:
        """``GET /v1/sys/policies/acl/{name}``"""
        self._ensure_available()
        if not name:
            raise ValueError("name is required.")
        body = self._http_get(f"/v1/sys/policies/acl/{quote(name, safe='')}")
        data = body.get("data") or {}
        return {
            "data": {
                "name": data.get("name", name),
                "policy": data.get("policy", ""),
            }
        }

    def list_auth_methods(self) -> Dict[str, Dict[str, Any]]:
        """``GET /v1/sys/auth`` — returns mount-path → method spec."""
        self._ensure_available()
        body = self._http_get("/v1/sys/auth")
        # Vault wraps actual mounts inside "data" for newer versions; fall back to top-level.
        source = body.get("data") if isinstance(body.get("data"), dict) else body
        out: Dict[str, Dict[str, Any]] = {}
        for mount_path, spec in source.items():
            if not isinstance(spec, dict):
                continue
            if mount_path in {
                "request_id",
                "lease_id",
                "lease_duration",
                "renewable",
                "warnings",
                "auth",
                "wrap_info",
                "mount_type",
            }:
                continue
            out[mount_path] = {
                "accessor": spec.get("accessor", ""),
                "type": spec.get("type", ""),
                "description": spec.get("description", ""),
                "config": spec.get("config") or {},
                "options": spec.get("options") or {},
                "local": bool(spec.get("local", False)),
                "seal_wrap": bool(spec.get("seal_wrap", False)),
                "external_entropy_access": bool(
                    spec.get("external_entropy_access", False)
                ),
            }
        return out

    def list_mounts(self) -> Dict[str, Dict[str, Any]]:
        """``GET /v1/sys/mounts`` — returns mount-path → mount spec."""
        self._ensure_available()
        body = self._http_get("/v1/sys/mounts")
        source = body.get("data") if isinstance(body.get("data"), dict) else body
        out: Dict[str, Dict[str, Any]] = {}
        for mount_path, spec in source.items():
            if not isinstance(spec, dict):
                continue
            if mount_path in {
                "request_id",
                "lease_id",
                "lease_duration",
                "renewable",
                "warnings",
                "auth",
                "wrap_info",
                "mount_type",
            }:
                continue
            cfg = spec.get("config") or {}
            out[mount_path] = {
                "accessor": spec.get("accessor", ""),
                "type": spec.get("type", ""),
                "description": spec.get("description", ""),
                "config": {
                    "default_lease_ttl": int(cfg.get("default_lease_ttl", 0)),
                    "max_lease_ttl": int(cfg.get("max_lease_ttl", 0)),
                    "force_no_cache": bool(cfg.get("force_no_cache", False)),
                },
                "options": spec.get("options") or {},
                "local": bool(spec.get("local", False)),
                "seal_wrap": bool(spec.get("seal_wrap", False)),
                "external_entropy_access": bool(
                    spec.get("external_entropy_access", False)
                ),
            }
        return out

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_engine_lock = threading.Lock()
_engine_instance: Optional[HashiCorpVaultEngine] = None


def get_hashicorp_vault_engine(
    vault_addr: Optional[str] = None,
    vault_token: Optional[str] = None,
    vault_namespace: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> HashiCorpVaultEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = HashiCorpVaultEngine(
                vault_addr=vault_addr,
                vault_token=vault_token,
                vault_namespace=vault_namespace,
                client=client,
                timeout=timeout,
            )
        return _engine_instance


def reset_hashicorp_vault_engine() -> None:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is not None:
            _engine_instance.close()
        _engine_instance = None
