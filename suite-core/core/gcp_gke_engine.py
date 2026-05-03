"""GCP GKE (Google Kubernetes Engine) Engine — ALDECI.

Wraps the GCP Container/GKE v1 surface (https://container.googleapis.com)
and exposes a process-wide singleton.

Two backends are supported transparently:

  1. ``google-cloud-container`` python SDK when installed.
  2. Pure-httpx + service-account JWT-bearer OAuth2 fallback when the SDK is
     unavailable but ``GOOGLE_APPLICATION_CREDENTIALS`` is wired.

Configuration (env)
-------------------
  GOOGLE_APPLICATION_CREDENTIALS   path to the service-account JSON key file

NO MOCKS rule
-------------
When ``GOOGLE_APPLICATION_CREDENTIALS`` is unset OR the file is missing the
engine is still constructible (capability summary still renders) but every
live GKE call raises ``GCPGKEUnavailableError`` which the router translates
to HTTP 503 with status="unavailable" — no fabricated cluster data, no
SQLite cache.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

GKE_API_BASE = "https://container.googleapis.com/v1"
DEFAULT_TIMEOUT_SECONDS = 8.0
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GKE_OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


class GCPGKEUnavailableError(RuntimeError):
    """Raised when GCP credentials are absent or GKE returned an unrecoverable error."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GCPGKEEngine:
    """Thread-safe GCP GKE client with no SQLite cache."""

    def __init__(
        self,
        creds_path: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        sdk_client: Optional[Any] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_creds = creds_path
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._sdk_client = sdk_client
        self._timeout = timeout
        self._lock = threading.RLock()
        self._token_cache: Dict[str, Any] = {"access_token": None, "expires_at": 0.0}

    # ---------------------------------------------------------------- env

    def _creds_path(self) -> Optional[str]:
        v = self._explicit_creds or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        return v.strip() if v else None

    def google_app_creds_present(self) -> bool:
        p = self._creds_path()
        return bool(p and Path(p).is_file())

    # ------------------------------------------------------------ helpers

    def _ensure_available(self) -> None:
        if not self.google_app_creds_present():
            raise GCPGKEUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS unset or file missing — "
                "configure a GCP service-account JSON key to enable GKE."
            )

    def _load_service_account(self) -> Dict[str, Any]:
        path = self._creds_path()
        if not path:
            raise GCPGKEUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS env var is empty."
            )
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except OSError as exc:
            raise GCPGKEUnavailableError(
                f"Cannot read service-account key at {path}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise GCPGKEUnavailableError(
                f"Service-account key at {path} is not valid JSON: {exc}"
            ) from exc

    # ----------------------------------------------------------- oauth2

    def _fetch_oauth_token(self) -> str:
        """JWT-bearer (RFC 7523) flow — exchanges a signed JWT for an access token."""
        with self._lock:
            now = time.time()
            cached_token = self._token_cache.get("access_token")
            cached_exp = self._token_cache.get("expires_at", 0.0)
            if cached_token and cached_exp - 60 > now:
                return cached_token

            sa = self._load_service_account()

            try:
                import jwt  # PyJWT
            except ImportError as exc:
                raise GCPGKEUnavailableError(
                    "PyJWT or google-cloud-container is required for "
                    "GCP GKE OAuth2 token exchange."
                ) from exc

            iat = int(now)
            payload = {
                "iss": sa.get("client_email"),
                "scope": GKE_OAUTH_SCOPE,
                "aud": TOKEN_ENDPOINT,
                "iat": iat,
                "exp": iat + 3600,
            }
            assertion = jwt.encode(
                payload, sa.get("private_key"), algorithm="RS256"
            )
            resp = self._client.post(
                TOKEN_ENDPOINT,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
            )
            if resp.status_code != 200:
                raise GCPGKEUnavailableError(
                    f"GCP token exchange failed ({resp.status_code}): {resp.text}"
                )
            body = resp.json()
            token = body.get("access_token")
            if not token:
                raise GCPGKEUnavailableError(
                    "GCP token response missing access_token."
                )
            self._token_cache["access_token"] = token
            self._token_cache["expires_at"] = now + float(
                body.get("expires_in", 3600)
            )
            return token

    # -------------------------------------------------------------- HTTP

    def _http_get(
        self, url: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        token = self._fetch_oauth_token()
        resp = self._client.get(
            url,
            params=params or {},
            headers={"Authorization": f"Bearer {token}"},
        )
        return self._handle_response(resp, url)

    def _http_post(
        self,
        url: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        token = self._fetch_oauth_token()
        resp = self._client.post(
            url,
            json=body or {},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        return self._handle_response(resp, url)

    def _handle_response(self, resp: Any, url: str) -> Dict[str, Any]:
        if resp.status_code == 401:
            raise GCPGKEUnavailableError(
                "GCP GKE rejected credentials (401)."
            )
        if resp.status_code == 403:
            raise GCPGKEUnavailableError(
                "GCP GKE permission denied (403) — check IAM roles."
            )
        if resp.status_code == 404:
            raise GCPGKEUnavailableError(
                f"GCP GKE resource not found (404): {url}"
            )
        if resp.status_code >= 400:
            raise GCPGKEUnavailableError(
                f"GCP GKE returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise GCPGKEUnavailableError(
                f"GCP GKE returned non-JSON payload: {exc}"
            ) from exc

    # ------------------------------------------------------ normalization

    @staticmethod
    def _norm_node_config(nc: Dict[str, Any]) -> Dict[str, Any]:
        nc = nc or {}
        return {
            "machineType": nc.get("machineType", ""),
            "diskSizeGb": int(nc.get("diskSizeGb", 0) or 0),
            "oauthScopes": list(nc.get("oauthScopes", []) or []),
            "serviceAccount": nc.get("serviceAccount", ""),
            "metadata": nc.get("metadata", {}) or {},
            "imageType": nc.get("imageType", ""),
            "labels": nc.get("labels", {}) or {},
            "localSsdCount": int(nc.get("localSsdCount", 0) or 0),
            "tags": list(nc.get("tags", []) or []),
            "preemptible": bool(nc.get("preemptible", False)),
            "accelerators": [
                {
                    "acceleratorCount": int(a.get("acceleratorCount", 0) or 0),
                    "acceleratorType": a.get("acceleratorType", ""),
                    "gpuPartitionSize": a.get("gpuPartitionSize", ""),
                }
                for a in (nc.get("accelerators", []) or [])
            ],
            "diskType": nc.get("diskType", ""),
            "minCpuPlatform": nc.get("minCpuPlatform", ""),
            "workloadMetadataConfig": nc.get("workloadMetadataConfig", {}) or {},
            "taints": list(nc.get("taints", []) or []),
            "shieldedInstanceConfig": nc.get("shieldedInstanceConfig", {}) or {},
            "linuxNodeConfig": nc.get("linuxNodeConfig", {}) or {},
            "kubeletConfig": nc.get("kubeletConfig", {}) or {},
        }

    @classmethod
    def _norm_cluster(cls, c: Dict[str, Any]) -> Dict[str, Any]:
        c = c or {}
        return {
            "name": c.get("name", ""),
            "description": c.get("description", ""),
            "initialNodeCount": int(c.get("initialNodeCount", 0) or 0),
            "nodeConfig": cls._norm_node_config(c.get("nodeConfig", {}) or {}),
            "masterAuth": c.get("masterAuth", {}) or {},
            "loggingService": c.get("loggingService", ""),
            "monitoringService": c.get("monitoringService", ""),
            "network": c.get("network", ""),
            "clusterIpv4Cidr": c.get("clusterIpv4Cidr", ""),
            "addonsConfig": c.get("addonsConfig", {}) or {},
            "subnetwork": c.get("subnetwork", ""),
            "nodePools": [cls._norm_node_pool(np) for np in (c.get("nodePools", []) or [])],
            "locations": list(c.get("locations", []) or []),
            "enableKubernetesAlpha": bool(c.get("enableKubernetesAlpha", False)),
            "resourceLabels": c.get("resourceLabels", {}) or {},
            "labelFingerprint": c.get("labelFingerprint", ""),
            "legacyAbac": c.get("legacyAbac", {}) or {},
            "networkPolicy": c.get("networkPolicy", {}) or {},
            "ipAllocationPolicy": c.get("ipAllocationPolicy", {}) or {},
            "masterAuthorizedNetworksConfig": c.get("masterAuthorizedNetworksConfig", {}) or {},
            "maintenancePolicy": c.get("maintenancePolicy", {}) or {},
            "binaryAuthorization": c.get("binaryAuthorization", {}) or {},
            "autoscaling": c.get("autoscaling", {}) or {},
            "networkConfig": c.get("networkConfig", {}) or {},
            "releaseChannel": c.get("releaseChannel", {}) or {},
            "workloadIdentityConfig": c.get("workloadIdentityConfig", {}) or {},
            "meshCertificates": c.get("meshCertificates", {}) or {},
            "costManagementConfig": c.get("costManagementConfig", {}) or {},
            "notificationConfig": c.get("notificationConfig", {}) or {},
            "confidentialNodes": c.get("confidentialNodes", {}) or {},
            "identityServiceConfig": c.get("identityServiceConfig", {}) or {},
            "selfLink": c.get("selfLink", ""),
            "zone": c.get("zone", ""),
            "endpoint": c.get("endpoint", ""),
            "initialClusterVersion": c.get("initialClusterVersion", ""),
            "currentMasterVersion": c.get("currentMasterVersion", ""),
            "currentNodeVersion": c.get("currentNodeVersion", ""),
            "createTime": c.get("createTime", ""),
            "status": c.get("status", ""),
            "statusMessage": c.get("statusMessage", ""),
            "nodeIpv4CidrSize": int(c.get("nodeIpv4CidrSize", 0) or 0),
            "servicesIpv4Cidr": c.get("servicesIpv4Cidr", ""),
            "instanceGroupUrls": list(c.get("instanceGroupUrls", []) or []),
            "currentNodeCount": int(c.get("currentNodeCount", 0) or 0),
            "expireTime": c.get("expireTime", ""),
            "location": c.get("location", ""),
            "enableTpu": bool(c.get("enableTpu", False)),
            "tpuIpv4CidrBlock": c.get("tpuIpv4CidrBlock", ""),
            "conditions": list(c.get("conditions", []) or []),
            "etag": c.get("etag", ""),
            "autopilot": c.get("autopilot", {}) or {},
            "id": c.get("id", ""),
            "satisfiesPzs": bool(c.get("satisfiesPzs", False)),
            "satisfiesPzi": bool(c.get("satisfiesPzi", False)),
            "fleet": c.get("fleet", {}) or {},
            "securityPostureConfig": c.get("securityPostureConfig", {}) or {},
            "enterpriseConfig": c.get("enterpriseConfig", {}) or {},
        }

    @classmethod
    def _norm_node_pool(cls, np: Dict[str, Any]) -> Dict[str, Any]:
        np = np or {}
        return {
            "name": np.get("name", ""),
            "config": cls._norm_node_config(np.get("config", {}) or {}),
            "initialNodeCount": int(np.get("initialNodeCount", 0) or 0),
            "locations": list(np.get("locations", []) or []),
            "selfLink": np.get("selfLink", ""),
            "version": np.get("version", ""),
            "instanceGroupUrls": list(np.get("instanceGroupUrls", []) or []),
            "status": np.get("status", ""),
            "statusMessage": np.get("statusMessage", ""),
            "autoscaling": np.get("autoscaling", {}) or {},
            "management": np.get("management", {}) or {},
            "maxPodsConstraint": np.get("maxPodsConstraint", {}) or {},
            "conditions": list(np.get("conditions", []) or []),
            "podIpv4CidrSize": int(np.get("podIpv4CidrSize", 0) or 0),
            "upgradeSettings": np.get("upgradeSettings", {}) or {},
            "placementPolicy": np.get("placementPolicy", {}) or {},
            "updateInfo": np.get("updateInfo", {}) or {},
            "etag": np.get("etag", ""),
            "queuedProvisioning": np.get("queuedProvisioning", {}) or {},
            "bestEffortProvisionEnabled": bool(np.get("bestEffortProvisionEnabled", False)),
        }

    @staticmethod
    def _norm_operation(op: Dict[str, Any]) -> Dict[str, Any]:
        op = op or {}
        return {
            "name": op.get("name", ""),
            "zone": op.get("zone", ""),
            "operationType": op.get("operationType", ""),
            "status": op.get("status", ""),
            "detail": op.get("detail", ""),
            "statusMessage": op.get("statusMessage", ""),
            "selfLink": op.get("selfLink", ""),
            "targetLink": op.get("targetLink", ""),
            "location": op.get("location", ""),
            "startTime": op.get("startTime", ""),
            "endTime": op.get("endTime", ""),
            "progress": op.get("progress", {}) or {},
            "clusterConditions": list(op.get("clusterConditions", []) or []),
            "nodepoolConditions": list(op.get("nodepoolConditions", []) or []),
            "error": op.get("error", {}) or {},
        }

    # -------------------------------------------------------- public API

    def list_clusters(
        self,
        project: str,
        location: str,
        parent: Optional[str] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project:
            raise ValueError("project is required.")
        if not location:
            raise ValueError("location is required.")
        params: Dict[str, Any] = {}
        if parent:
            params["parent"] = parent
        if page_token:
            params["pageToken"] = page_token
        url = (
            f"{GKE_API_BASE}/projects/{project}/locations/{location}/clusters"
        )
        body = self._http_get(url, params=params)
        clusters: List[Dict[str, Any]] = []
        for c in body.get("clusters", []) or []:
            clusters.append(self._norm_cluster(c))
        return {
            "clusters": clusters,
            "missingZones": list(body.get("missingZones", []) or []),
        }

    def get_cluster(
        self, project: str, location: str, cluster_id: str
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project or not location or not cluster_id:
            raise ValueError("project, location and cluster_id are required.")
        url = (
            f"{GKE_API_BASE}/projects/{project}/locations/{location}"
            f"/clusters/{cluster_id}"
        )
        body = self._http_get(url)
        return self._norm_cluster(body)

    def list_node_pools(
        self, project: str, location: str, cluster_id: str
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project or not location or not cluster_id:
            raise ValueError("project, location and cluster_id are required.")
        url = (
            f"{GKE_API_BASE}/projects/{project}/locations/{location}"
            f"/clusters/{cluster_id}/nodePools"
        )
        body = self._http_get(url)
        node_pools: List[Dict[str, Any]] = []
        for np in body.get("nodePools", []) or []:
            node_pools.append(self._norm_node_pool(np))
        return {"nodePools": node_pools}

    def get_jwks(
        self, project: str, location: str, cluster_id: str
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project or not location or not cluster_id:
            raise ValueError("project, location and cluster_id are required.")
        url = (
            f"{GKE_API_BASE}/projects/{project}/locations/{location}"
            f"/clusters/{cluster_id}:getJwks"
        )
        body = self._http_post(url, body={})
        return {
            "keys": list(body.get("keys", []) or []),
            "cacheHeader": body.get("cacheHeader", {}) or {},
        }

    def list_operations(
        self,
        project: str,
        location: str,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project:
            raise ValueError("project is required.")
        if not location:
            raise ValueError("location is required.")
        params: Dict[str, Any] = {}
        if page_token:
            params["pageToken"] = page_token
        url = (
            f"{GKE_API_BASE}/projects/{project}/locations/{location}/operations"
        )
        body = self._http_get(url, params=params)
        ops: List[Dict[str, Any]] = []
        for op in body.get("operations", []) or []:
            ops.append(self._norm_operation(op))
        return {
            "operations": ops,
            "missingZones": list(body.get("missingZones", []) or []),
        }

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
_engine_instance: Optional[GCPGKEEngine] = None


def get_gcp_gke_engine(
    creds_path: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    sdk_client: Optional[Any] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> GCPGKEEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = GCPGKEEngine(
                creds_path=creds_path,
                client=client,
                sdk_client=sdk_client,
                timeout=timeout,
            )
        return _engine_instance


def reset_gcp_gke_engine() -> None:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is not None:
            _engine_instance.close()
        _engine_instance = None
