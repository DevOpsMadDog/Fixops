"""GCP Cloud KMS Engine — ALDECI.

Wraps the GCP Cloud KMS v1 surface and exposes a process-wide singleton.
Two backends are supported transparently:

  1. ``google-cloud-kms`` python SDK when installed.
  2. Pure-httpx + service-account JWT-bearer OAuth2 fallback when the SDK is
     unavailable but ``GOOGLE_APPLICATION_CREDENTIALS`` is wired.

Configuration (env)
-------------------
  GOOGLE_APPLICATION_CREDENTIALS   path to the service-account JSON key file

NO MOCKS rule
-------------
When ``GOOGLE_APPLICATION_CREDENTIALS`` is unset OR the file is missing the
engine is still constructible (capability summary still renders) but every
live KMS call raises ``GCPCloudKMSUnavailableError`` which the router
translates to HTTP 503 with status="unavailable" — no fabricated key
material, no SQLite cache.
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

KMS_API_BASE = "https://cloudkms.googleapis.com/v1"
DEFAULT_TIMEOUT_SECONDS = 8.0
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
KMS_OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


class GCPCloudKMSUnavailableError(RuntimeError):
    """Raised when GCP credentials are absent or KMS returned an unrecoverable error."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GCPCloudKMSEngine:
    """Thread-safe GCP Cloud KMS client with no SQLite cache."""

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
            raise GCPCloudKMSUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS unset or file missing — "
                "configure a GCP service-account JSON key to enable Cloud KMS."
            )

    def _load_service_account(self) -> Dict[str, Any]:
        path = self._creds_path()
        if not path:
            raise GCPCloudKMSUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS env var is empty."
            )
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except OSError as exc:
            raise GCPCloudKMSUnavailableError(
                f"Cannot read service-account key at {path}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise GCPCloudKMSUnavailableError(
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
                # Lazy import: only required when the SDK isn't available.
                import jwt  # PyJWT
            except ImportError as exc:
                raise GCPCloudKMSUnavailableError(
                    "PyJWT or google-cloud-kms is required for "
                    "GCP Cloud KMS OAuth2 token exchange."
                ) from exc

            iat = int(now)
            payload = {
                "iss": sa.get("client_email"),
                "scope": KMS_OAUTH_SCOPE,
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
                raise GCPCloudKMSUnavailableError(
                    f"GCP token exchange failed ({resp.status_code}): {resp.text}"
                )
            body = resp.json()
            token = body.get("access_token")
            if not token:
                raise GCPCloudKMSUnavailableError(
                    "GCP token response missing access_token."
                )
            self._token_cache["access_token"] = token
            self._token_cache["expires_at"] = now + float(
                body.get("expires_in", 3600)
            )
            return token

    # ----------------------------------------------------- backend choice

    def _use_sdk(self) -> bool:
        if self._sdk_client is not None:
            return True
        try:
            import google.cloud.kms  # noqa: F401
            return True
        except Exception:
            return False

    def _sdk(self):
        if self._sdk_client is not None:
            return self._sdk_client
        try:
            from google.cloud import kms
            from google.oauth2 import service_account
        except ImportError as exc:
            raise GCPCloudKMSUnavailableError(
                "google-cloud-kms SDK not installed."
            ) from exc
        creds = service_account.Credentials.from_service_account_file(
            self._creds_path()
        )
        self._sdk_client = kms.KeyManagementServiceClient(credentials=creds)
        return self._sdk_client

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
        if resp.status_code == 401:
            raise GCPCloudKMSUnavailableError(
                "GCP Cloud KMS rejected credentials (401)."
            )
        if resp.status_code == 403:
            raise GCPCloudKMSUnavailableError(
                "GCP Cloud KMS permission denied (403) — check IAM roles."
            )
        if resp.status_code == 404:
            raise GCPCloudKMSUnavailableError(
                f"GCP Cloud KMS resource not found (404): {url}"
            )
        if resp.status_code >= 400:
            raise GCPCloudKMSUnavailableError(
                f"GCP Cloud KMS returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise GCPCloudKMSUnavailableError(
                f"GCP Cloud KMS returned non-JSON payload: {exc}"
            ) from exc

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
        if resp.status_code == 401:
            raise GCPCloudKMSUnavailableError(
                "GCP Cloud KMS rejected credentials (401)."
            )
        if resp.status_code == 403:
            raise GCPCloudKMSUnavailableError(
                "GCP Cloud KMS permission denied (403) — check IAM roles."
            )
        if resp.status_code == 404:
            raise GCPCloudKMSUnavailableError(
                f"GCP Cloud KMS resource not found (404): {url}"
            )
        if resp.status_code >= 400:
            raise GCPCloudKMSUnavailableError(
                f"GCP Cloud KMS returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise GCPCloudKMSUnavailableError(
                f"GCP Cloud KMS returned non-JSON payload: {exc}"
            ) from exc

    # ------------------------------------------------------ normalization

    @staticmethod
    def _norm_key_version(v: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": v.get("name", ""),
            "state": v.get("state", ""),
            "createTime": v.get("createTime", ""),
            "generateTime": v.get("generateTime", ""),
            "destroyTime": v.get("destroyTime", ""),
            "destroyEventTime": v.get("destroyEventTime", ""),
            "importJob": v.get("importJob", ""),
            "importTime": v.get("importTime", ""),
            "algorithm": v.get("algorithm", ""),
            "attestation": v.get("attestation", {}) or {},
            "externalProtectionLevelOptions": v.get(
                "externalProtectionLevelOptions", {}
            )
            or {},
            "reimportEligible": bool(v.get("reimportEligible", False)),
        }

    @classmethod
    def _norm_crypto_key(cls, k: Dict[str, Any]) -> Dict[str, Any]:
        primary = k.get("primary") or {}
        return {
            "name": k.get("name", ""),
            "primary": cls._norm_key_version(primary) if primary else {},
            "purpose": k.get("purpose", ""),
            "createTime": k.get("createTime", ""),
            "nextRotationTime": k.get("nextRotationTime", ""),
            "rotationPeriod": k.get("rotationPeriod", ""),
            "versionTemplate": k.get("versionTemplate", {}) or {},
            "labels": k.get("labels", {}) or {},
            "importOnly": bool(k.get("importOnly", False)),
            "destroyScheduledDuration": k.get("destroyScheduledDuration", ""),
            "cryptoKeyBackend": k.get("cryptoKeyBackend", ""),
            "keyAccessJustificationsPolicy": k.get(
                "keyAccessJustificationsPolicy", {}
            )
            or {},
        }

    # -------------------------------------------------------- public API

    def list_locations(self, project: str) -> Dict[str, Any]:
        self._ensure_available()
        if not project:
            raise ValueError("project is required.")
        url = f"{KMS_API_BASE}/projects/{project}/locations"
        body = self._http_get(url)
        locations: List[Dict[str, Any]] = []
        for loc in body.get("locations", []) or []:
            locations.append({
                "name": loc.get("name", ""),
                "locationId": loc.get("locationId", ""),
                "displayName": loc.get("displayName", ""),
                "labels": loc.get("labels", {}) or {},
                "metadata": loc.get("metadata", {}) or {},
            })
        return {
            "locations": locations,
            "nextPageToken": body.get("nextPageToken", ""),
        }

    def list_key_rings(
        self,
        project: str,
        location: str,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project:
            raise ValueError("project is required.")
        if not location:
            raise ValueError("location is required.")
        params: Dict[str, Any] = {}
        if page_size:
            params["pageSize"] = int(page_size)
        if page_token:
            params["pageToken"] = page_token
        url = f"{KMS_API_BASE}/projects/{project}/locations/{location}/keyRings"
        body = self._http_get(url, params=params)
        rings: List[Dict[str, Any]] = []
        for kr in body.get("keyRings", []) or []:
            rings.append({
                "name": kr.get("name", ""),
                "createTime": kr.get("createTime", ""),
            })
        return {
            "keyRings": rings,
            "nextPageToken": body.get("nextPageToken", ""),
            "totalSize": int(body.get("totalSize", len(rings))),
        }

    def get_key_ring(
        self, project: str, location: str, key_ring: str
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project or not location or not key_ring:
            raise ValueError("project, location and key_ring are required.")
        url = (
            f"{KMS_API_BASE}/projects/{project}/locations/{location}"
            f"/keyRings/{key_ring}"
        )
        body = self._http_get(url)
        return {
            "name": body.get("name", ""),
            "createTime": body.get("createTime", ""),
        }

    def list_crypto_keys(
        self,
        project: str,
        location: str,
        key_ring: str,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        version_view: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project or not location or not key_ring:
            raise ValueError("project, location and key_ring are required.")
        if version_view and version_view.upper() not in {"BASIC", "FULL"}:
            raise ValueError("versionView must be BASIC or FULL.")
        params: Dict[str, Any] = {}
        if page_size:
            params["pageSize"] = int(page_size)
        if page_token:
            params["pageToken"] = page_token
        if version_view:
            params["versionView"] = version_view.upper()
        url = (
            f"{KMS_API_BASE}/projects/{project}/locations/{location}"
            f"/keyRings/{key_ring}/cryptoKeys"
        )
        body = self._http_get(url, params=params)
        keys: List[Dict[str, Any]] = []
        for k in body.get("cryptoKeys", []) or []:
            keys.append(self._norm_crypto_key(k))
        return {
            "cryptoKeys": keys,
            "nextPageToken": body.get("nextPageToken", ""),
            "totalSize": int(body.get("totalSize", len(keys))),
        }

    def get_crypto_key(
        self,
        project: str,
        location: str,
        key_ring: str,
        crypto_key: str,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project or not location or not key_ring or not crypto_key:
            raise ValueError(
                "project, location, key_ring and crypto_key are required."
            )
        url = (
            f"{KMS_API_BASE}/projects/{project}/locations/{location}"
            f"/keyRings/{key_ring}/cryptoKeys/{crypto_key}"
        )
        body = self._http_get(url)
        return self._norm_crypto_key(body)

    def list_crypto_key_versions(
        self,
        project: str,
        location: str,
        key_ring: str,
        crypto_key: str,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        filter_: Optional[str] = None,
        order_by: Optional[str] = None,
        view: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project or not location or not key_ring or not crypto_key:
            raise ValueError(
                "project, location, key_ring and crypto_key are required."
            )
        if view and view.upper() not in {"BASIC", "FULL"}:
            raise ValueError("view must be BASIC or FULL.")
        params: Dict[str, Any] = {}
        if page_size:
            params["pageSize"] = int(page_size)
        if page_token:
            params["pageToken"] = page_token
        if filter_:
            params["filter"] = filter_
        if order_by:
            params["orderBy"] = order_by
        if view:
            params["view"] = view.upper()
        url = (
            f"{KMS_API_BASE}/projects/{project}/locations/{location}"
            f"/keyRings/{key_ring}/cryptoKeys/{crypto_key}/cryptoKeyVersions"
        )
        body = self._http_get(url, params=params)
        versions: List[Dict[str, Any]] = []
        for v in body.get("cryptoKeyVersions", []) or []:
            versions.append(self._norm_key_version(v))
        return {
            "cryptoKeyVersions": versions,
            "nextPageToken": body.get("nextPageToken", ""),
            "totalSize": int(body.get("totalSize", len(versions))),
        }

    def get_crypto_key_version(
        self,
        project: str,
        location: str,
        key_ring: str,
        crypto_key: str,
        version: str,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if (
            not project
            or not location
            or not key_ring
            or not crypto_key
            or not version
        ):
            raise ValueError(
                "project, location, key_ring, crypto_key and version are required."
            )
        url = (
            f"{KMS_API_BASE}/projects/{project}/locations/{location}"
            f"/keyRings/{key_ring}/cryptoKeys/{crypto_key}"
            f"/cryptoKeyVersions/{version}"
        )
        body = self._http_get(url)
        return self._norm_key_version(body)

    def get_iam_policy(
        self,
        project: str,
        location: str,
        key_ring: str,
        crypto_key: str,
        requested_policy_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        if not project or not location or not key_ring or not crypto_key:
            raise ValueError(
                "project, location, key_ring and crypto_key are required."
            )
        if requested_policy_version is not None and int(
            requested_policy_version
        ) not in {1, 2, 3}:
            raise ValueError(
                "requestedPolicyVersion must be 1, 2 or 3."
            )
        url = (
            f"{KMS_API_BASE}/projects/{project}/locations/{location}"
            f"/keyRings/{key_ring}/cryptoKeys/{crypto_key}:getIamPolicy"
        )
        body_in: Dict[str, Any] = {}
        if requested_policy_version is not None:
            body_in["options"] = {
                "requestedPolicyVersion": int(requested_policy_version)
            }
        body = self._http_post(url, body=body_in)
        bindings: List[Dict[str, Any]] = []
        for b in body.get("bindings", []) or []:
            bindings.append({
                "role": b.get("role", ""),
                "members": list(b.get("members", []) or []),
            })
        return {
            "version": int(body.get("version", 1)),
            "etag": body.get("etag", ""),
            "bindings": bindings,
            "auditConfigs": body.get("auditConfigs", []) or [],
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
_engine_instance: Optional[GCPCloudKMSEngine] = None


def get_gcp_cloudkms_engine(
    creds_path: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    sdk_client: Optional[Any] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> GCPCloudKMSEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = GCPCloudKMSEngine(
                creds_path=creds_path,
                client=client,
                sdk_client=sdk_client,
                timeout=timeout,
            )
        return _engine_instance


def reset_gcp_cloudkms_engine() -> None:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is not None:
            _engine_instance.close()
        _engine_instance = None
