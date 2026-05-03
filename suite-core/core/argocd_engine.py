"""ALDECI ArgoCD GitOps Engine — REAL API only, NO MOCKS.

Wraps ArgoCD REST API via httpx. Returns ``status="unavailable"`` in the
capability summary and raises ``ArgoCDUnavailableError`` (HTTP 503 at the
router layer) when ``ARGOCD_URL`` or ``ARGOCD_TOKEN`` are not configured.

Endpoints supported (subset of ArgoCD v1):
  - GET  /api/v1/applications
  - GET  /api/v1/applications/{name}
  - POST /api/v1/applications/{name}/sync
  - GET  /api/v1/projects
  - GET  /api/v1/clusters
  - GET  /api/v1/repositories

Singleton: ``get_argocd_engine(url=..., token=..., client=...)``
Reset:     ``reset_argocd_engine()``

NO SQLite cache. NO MOCKS.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class ArgoCDUnavailableError(RuntimeError):
    """Raised when the ArgoCD REST API cannot be reached or is misconfigured."""


class ArgoCDEngine:
    """Thin httpx-backed client for the ArgoCD REST API.

    All methods raise ``ArgoCDUnavailableError`` when ``ARGOCD_URL`` /
    ``ARGOCD_TOKEN`` are not configured (NO MOCKS). Routers translate
    that to HTTP 503.
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._url = (url or os.environ.get("ARGOCD_URL") or "").strip().rstrip("/")
        self._token = (token or os.environ.get("ARGOCD_TOKEN") or "").strip()
        self._timeout = timeout
        self._client = client

    # ------------------------------------------------------------------ utils

    def is_configured(self) -> bool:
        return bool(self._url and self._token)

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout, verify=True)
        return self._client

    def _require_config(self) -> None:
        if not self._url:
            raise ArgoCDUnavailableError(
                "ARGOCD_URL not set — set the env var to call ArgoCD"
            )
        if not self._token:
            raise ArgoCDUnavailableError(
                "ARGOCD_TOKEN not set — set the env var to call ArgoCD"
            )

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _check_resp(self, resp: Any, op: str) -> Any:
        status = getattr(resp, "status_code", 0)
        if status == 401:
            raise ArgoCDUnavailableError(f"ArgoCD 401 (invalid token) for {op}")
        if status == 403:
            raise ArgoCDUnavailableError(f"ArgoCD 403 (forbidden) for {op}")
        if status == 404:
            raise ArgoCDUnavailableError(f"ArgoCD 404 for {op}")
        if status == 429:
            raise ArgoCDUnavailableError(f"ArgoCD 429 (rate-limit) for {op}")
        if status >= 500:
            raise ArgoCDUnavailableError(
                f"ArgoCD {status} (upstream error) for {op}"
            )
        if status >= 400:
            text = getattr(resp, "text", "") or ""
            raise ArgoCDUnavailableError(
                f"ArgoCD {status} for {op}: {text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise ArgoCDUnavailableError(
                f"ArgoCD returned non-JSON for {op}: {exc}"
            ) from exc

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        url_present = bool(self._url)
        token_present = bool(self._token)
        if not url_present or not token_present:
            status = "unavailable"
        else:
            status = "ok"
        return {
            "service": "ArgoCD",
            "endpoints": [
                "/api/v1/applications",
                "/api/v1/projects",
                "/api/v1/clusters",
                "/api/v1/repositories",
            ],
            "argocd_url_present": url_present,
            "argocd_token_present": token_present,
            "status": status,
        }

    # ----------------------------------------------------------- applications

    def list_applications(
        self,
        projects: Optional[List[str]] = None,
        selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_config()
        params: List[tuple] = []
        for proj in projects or []:
            params.append(("projects", proj))
        if selector:
            params.append(("selector", selector))
        client = self._ensure_client()
        resp = client.get(
            f"{self._url}/api/v1/applications",
            headers=self._headers(),
            params=params,
        )
        data = self._check_resp(resp, "GET /api/v1/applications")
        if not isinstance(data, dict):
            data = {}
        return {"items": list(data.get("items") or [])}

    def get_application(self, name: str, refresh: Optional[str] = None) -> Dict[str, Any]:
        self._require_config()
        if not name or not str(name).strip():
            raise ValueError("application name required")
        params: List[tuple] = []
        if refresh:
            if refresh not in ("normal", "hard"):
                raise ValueError("refresh must be 'normal' or 'hard'")
            params.append(("refresh", refresh))
        client = self._ensure_client()
        resp = client.get(
            f"{self._url}/api/v1/applications/{name}",
            headers=self._headers(),
            params=params,
        )
        data = self._check_resp(resp, f"GET /api/v1/applications/{name}")
        return data if isinstance(data, dict) else {}

    def sync_application(
        self,
        name: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_config()
        if not name or not str(name).strip():
            raise ValueError("application name required")
        body = body or {}
        # Validate optional knobs
        if "strategy" in body and body["strategy"] is not None:
            strat = body["strategy"]
            if not isinstance(strat, dict):
                raise ValueError("strategy must be an object")
            allowed = {"hook", "apply"}
            keys = set(strat.keys())
            if keys and not keys.issubset(allowed):
                raise ValueError(
                    f"strategy keys must be one of {sorted(allowed)}, got {sorted(keys)}"
                )
        if "syncOptions" in body and body["syncOptions"] is not None:
            if not isinstance(body["syncOptions"], list):
                raise ValueError("syncOptions must be a list of strings")
        client = self._ensure_client()
        resp = client.post(
            f"{self._url}/api/v1/applications/{name}/sync",
            headers=self._headers(),
            json=body,
        )
        data = self._check_resp(resp, f"POST /api/v1/applications/{name}/sync")
        return data if isinstance(data, dict) else {}

    # ----------------------------------------------------------------- projects

    def list_projects(self) -> Dict[str, Any]:
        self._require_config()
        client = self._ensure_client()
        resp = client.get(
            f"{self._url}/api/v1/projects",
            headers=self._headers(),
        )
        data = self._check_resp(resp, "GET /api/v1/projects")
        if not isinstance(data, dict):
            data = {}
        return {"items": list(data.get("items") or [])}

    # ----------------------------------------------------------------- clusters

    def list_clusters(self) -> Dict[str, Any]:
        self._require_config()
        client = self._ensure_client()
        resp = client.get(
            f"{self._url}/api/v1/clusters",
            headers=self._headers(),
        )
        data = self._check_resp(resp, "GET /api/v1/clusters")
        if not isinstance(data, dict):
            data = {}
        return {"items": list(data.get("items") or [])}

    # ------------------------------------------------------------- repositories

    def list_repositories(self) -> Dict[str, Any]:
        self._require_config()
        client = self._ensure_client()
        resp = client.get(
            f"{self._url}/api/v1/repositories",
            headers=self._headers(),
        )
        data = self._check_resp(resp, "GET /api/v1/repositories")
        if not isinstance(data, dict):
            data = {}
        return {"items": list(data.get("items") or [])}

    # ------------------------------------------------------------------ close

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass


# -------------------------------------------------------------- singleton

_singleton: Optional[ArgoCDEngine] = None
_singleton_lock = threading.Lock()


def get_argocd_engine(
    url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ArgoCDEngine:
    """Process-wide singleton accessor."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ArgoCDEngine(url=url, token=token, client=client)
        return _singleton


def reset_argocd_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ArgoCDEngine",
    "ArgoCDUnavailableError",
    "get_argocd_engine",
    "reset_argocd_engine",
]
