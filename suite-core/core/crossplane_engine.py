"""ALDECI Crossplane (k8s API proxy) Engine — REAL API only, NO MOCKS.

Wraps the Crossplane CRDs exposed via the Kubernetes API server (the
``apis/...`` paths). Returns ``status="unavailable"`` in the capability
summary and raises ``CrossplaneUnavailableError`` (HTTP 503 at the router
layer) when ``KUBE_API_SERVER`` or ``KUBE_TOKEN`` (or ``KUBE_TOKEN_PATH``)
are not configured.

Endpoints supported (subset of Crossplane / dynamic k8s discovery):
  - GET /apis/pkg.crossplane.io/v1/providers
  - GET /apis/apiextensions.crossplane.io/v1/compositions
  - GET /apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions
  - GET /apis/{group}/{version}/{plural}                      (cluster-scoped)
  - GET /apis/{group}/{version}/namespaces/{ns}/{plural}      (namespace-scoped)
  - GET /apis/{group}/{version}/{plural}/{name}               (single resource)
  - GET /apis/pkg.crossplane.io/v1/configurations
  - GET /apis/pkg.crossplane.io/v1/functions
  - GET /apis/pkg.crossplane.io/v1beta1/lock

Auth (in priority order):
  - ``KUBE_TOKEN`` env var (literal Bearer token), OR
  - file at ``KUBE_TOKEN_PATH`` (defaults to the in-cluster mount at
    ``/var/run/secrets/kubernetes.io/serviceaccount/token``)

TLS:
  - ``KUBE_CA_CERT`` env var — path to a CA bundle PEM; if unset, defaults
    to the in-cluster CA at
    ``/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`` when present.
  - ``KUBE_INSECURE_SKIP_VERIFY=1`` disables verification (NOT recommended).

Singleton: ``get_crossplane_engine(api_server=..., token=..., client=...)``
Reset:     ``reset_crossplane_engine()``

NO SQLite cache. NO MOCKS.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_DEFAULT_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


class CrossplaneUnavailableError(RuntimeError):
    """Raised when the kube API server cannot be reached or is misconfigured."""


class CrossplaneEngine:
    """Thin httpx-backed client for Crossplane CRDs via the Kubernetes API.

    All methods raise ``CrossplaneUnavailableError`` when ``KUBE_API_SERVER``
    or auth material is missing (NO MOCKS). Routers translate that to 503.
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        api_server: Optional[str] = None,
        token: Optional[str] = None,
        token_path: Optional[str] = None,
        ca_cert: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_server = (
            api_server or os.environ.get("KUBE_API_SERVER") or ""
        ).strip().rstrip("/")
        # Try literal token first, then a token file path (in-cluster mount).
        literal_token = (token or os.environ.get("KUBE_TOKEN") or "").strip()
        self._token: str = literal_token
        if not self._token:
            path = (
                token_path
                or os.environ.get("KUBE_TOKEN_PATH")
                or (_DEFAULT_TOKEN_PATH if os.path.exists(_DEFAULT_TOKEN_PATH) else "")
            )
            if path and os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        self._token = fh.read().strip()
                except OSError as exc:  # pragma: no cover — defensive
                    logger.warning("crossplane: failed to read token from %s: %s", path, exc)
        # CA bundle resolution (verify can be a path string OR a bool).
        ca = (ca_cert or os.environ.get("KUBE_CA_CERT") or "").strip()
        if not ca and os.path.exists(_DEFAULT_CA_PATH):
            ca = _DEFAULT_CA_PATH
        self._ca_cert: str = ca
        self._insecure = os.environ.get("KUBE_INSECURE_SKIP_VERIFY", "").strip() in (
            "1",
            "true",
            "True",
            "yes",
        )
        self._timeout = timeout
        self._client = client

    # ------------------------------------------------------------------ utils

    def is_configured(self) -> bool:
        return bool(self._api_server and self._token)

    def _verify_value(self) -> Union[bool, str]:
        if self._insecure:
            return False
        if self._ca_cert:
            return self._ca_cert
        return True

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout, verify=self._verify_value())
        return self._client

    def _require_config(self) -> None:
        if not self._api_server:
            raise CrossplaneUnavailableError(
                "KUBE_API_SERVER not set — set the env var to call the kube API"
            )
        if not self._token:
            raise CrossplaneUnavailableError(
                "KUBE_TOKEN (or KUBE_TOKEN_PATH) not set — set one to call the kube API"
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
            raise CrossplaneUnavailableError(f"kube-api 401 (invalid token) for {op}")
        if status == 403:
            raise CrossplaneUnavailableError(f"kube-api 403 (forbidden) for {op}")
        if status == 404:
            raise CrossplaneUnavailableError(f"kube-api 404 for {op}")
        if status == 429:
            raise CrossplaneUnavailableError(f"kube-api 429 (rate-limit) for {op}")
        if status >= 500:
            raise CrossplaneUnavailableError(f"kube-api {status} (upstream error) for {op}")
        if status >= 400:
            text = getattr(resp, "text", "") or ""
            raise CrossplaneUnavailableError(f"kube-api {status} for {op}: {text[:200]}")
        try:
            return resp.json()
        except Exception as exc:
            raise CrossplaneUnavailableError(
                f"kube-api returned non-JSON for {op}: {exc}"
            ) from exc

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        api_present = bool(self._api_server)
        token_present = bool(self._token)
        if not api_present or not token_present:
            status = "unavailable"
        else:
            status = "ok"
        return {
            "service": "Crossplane (k8s)",
            "endpoints": [
                "/apis/pkg.crossplane.io/v1/providers",
                "/apis/apiextensions.crossplane.io/v1/compositions",
                "/apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions",
                "/apis/{group}/{version}/{plural}",
                "/apis/pkg.crossplane.io/v1/configurations",
                "/apis/pkg.crossplane.io/v1/functions",
            ],
            "kube_api_server_present": api_present,
            "kube_token_present": token_present,
            "status": status,
        }

    # ----------------------------------------------------------------- params

    def _list_params(
        self,
        limit: Optional[int] = None,
        cont: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> List[Tuple[str, str]]:
        params: List[Tuple[str, str]] = []
        if limit is not None:
            try:
                lim = int(limit)
            except (TypeError, ValueError):
                raise ValueError("limit must be an integer")
            if lim < 0:
                raise ValueError("limit must be >= 0")
            params.append(("limit", str(lim)))
        if cont:
            params.append(("continue", str(cont)))
        if label_selector:
            params.append(("labelSelector", str(label_selector)))
        if field_selector:
            params.append(("fieldSelector", str(field_selector)))
        return params

    def _get(self, path: str, params: Optional[List[Tuple[str, str]]] = None) -> Dict[str, Any]:
        self._require_config()
        client = self._ensure_client()
        # path begins with "/apis/..."
        url = f"{self._api_server}{path}"
        resp = client.get(url, headers=self._headers(), params=params or [])
        data = self._check_resp(resp, f"GET {path}")
        if not isinstance(data, dict):
            return {}
        return data

    # ---------------------------------------------------------------- providers

    def list_providers(
        self,
        limit: Optional[int] = None,
        cont: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(limit, cont, label_selector, field_selector)
        return self._get("/apis/pkg.crossplane.io/v1/providers", params=params)

    # -------------------------------------------------------------- compositions

    def list_compositions(
        self,
        limit: Optional[int] = None,
        cont: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(limit, cont, label_selector, field_selector)
        return self._get(
            "/apis/apiextensions.crossplane.io/v1/compositions", params=params
        )

    # ------------------------------------------------------------------ XRDs

    def list_xrds(
        self,
        limit: Optional[int] = None,
        cont: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(limit, cont, label_selector, field_selector)
        return self._get(
            "/apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions",
            params=params,
        )

    # --------------------------------------------------------- managed (generic)

    @staticmethod
    def _validate_segment(name: str, value: str) -> str:
        v = (value or "").strip()
        if not v:
            raise ValueError(f"{name} must be non-empty")
        # k8s identifiers — disallow path separators.
        if "/" in v or ".." in v:
            raise ValueError(f"{name} must not contain '/' or '..'")
        return v

    def list_managed(
        self,
        group: str,
        version: str,
        plural: str,
        namespace: Optional[str] = None,
        limit: Optional[int] = None,
        cont: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        # group can contain dots (e.g. ec2.aws.upbound.io); allow them.
        g = (group or "").strip()
        if not g:
            raise ValueError("group must be non-empty")
        if "/" in g or ".." in g:
            raise ValueError("group must not contain '/' or '..'")
        v = self._validate_segment("version", version)
        p = self._validate_segment("plural", plural)
        params = self._list_params(limit, cont, label_selector, field_selector)
        if namespace is not None:
            ns = self._validate_segment("namespace", namespace)
            path = f"/apis/{g}/{v}/namespaces/{ns}/{p}"
        else:
            path = f"/apis/{g}/{v}/{p}"
        return self._get(path, params=params)

    def get_managed(
        self,
        group: str,
        version: str,
        plural: str,
        name: str,
        namespace: Optional[str] = None,
    ) -> Dict[str, Any]:
        g = (group or "").strip()
        if not g:
            raise ValueError("group must be non-empty")
        if "/" in g or ".." in g:
            raise ValueError("group must not contain '/' or '..'")
        v = self._validate_segment("version", version)
        p = self._validate_segment("plural", plural)
        n = self._validate_segment("name", name)
        if namespace is not None:
            ns = self._validate_segment("namespace", namespace)
            path = f"/apis/{g}/{v}/namespaces/{ns}/{p}/{n}"
        else:
            path = f"/apis/{g}/{v}/{p}/{n}"
        return self._get(path)

    # ----------------------------------------------------------- configurations

    def list_configurations(
        self,
        limit: Optional[int] = None,
        cont: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(limit, cont, label_selector, field_selector)
        return self._get("/apis/pkg.crossplane.io/v1/configurations", params=params)

    # ---------------------------------------------------------------- functions

    def list_functions(
        self,
        limit: Optional[int] = None,
        cont: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(limit, cont, label_selector, field_selector)
        return self._get("/apis/pkg.crossplane.io/v1/functions", params=params)

    # -------------------------------------------------------------------- lock

    def get_lock(self) -> Dict[str, Any]:
        # The Lock CR is cluster-scoped, singleton named "lock".
        return self._get("/apis/pkg.crossplane.io/v1beta1/locks/lock")

    # ------------------------------------------------------------------ close

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass


# -------------------------------------------------------------- singleton

_singleton: Optional[CrossplaneEngine] = None
_singleton_lock = threading.Lock()


def get_crossplane_engine(
    api_server: Optional[str] = None,
    token: Optional[str] = None,
    token_path: Optional[str] = None,
    ca_cert: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> CrossplaneEngine:
    """Process-wide singleton accessor."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = CrossplaneEngine(
                api_server=api_server,
                token=token,
                token_path=token_path,
                ca_cert=ca_cert,
                client=client,
            )
        return _singleton


def reset_crossplane_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "CrossplaneEngine",
    "CrossplaneUnavailableError",
    "get_crossplane_engine",
    "reset_crossplane_engine",
]
