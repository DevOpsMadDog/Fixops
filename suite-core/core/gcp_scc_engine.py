"""GCP Security Command Center Engine — ALDECI.

Wraps the GCP Security Command Center v1 surface and exposes a process-wide
singleton. Two backends are supported transparently:

  1. ``google-cloud-securitycenter`` python SDK when installed.
  2. Pure-httpx + service-account JWT-bearer OAuth2 fallback when the SDK is
     unavailable but ``GOOGLE_APPLICATION_CREDENTIALS`` is wired.

Configuration (env)
-------------------
  GOOGLE_APPLICATION_CREDENTIALS   path to the service-account JSON key file
  GCP_ORG_ID                       Security Command Center organization ID

NO MOCKS rule
-------------
When ``GOOGLE_APPLICATION_CREDENTIALS`` is unset OR the file is missing the
engine is still constructible (capability summary still renders) but every
live SCC call raises ``GCPSCCUnavailableError`` which the router translates
to HTTP 503 with status="unavailable" — no fabricated findings, no SQLite
cache.
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

SCC_API_BASE = "https://securitycenter.googleapis.com/v1"
DEFAULT_TIMEOUT_SECONDS = 8.0
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
SCC_OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


class GCPSCCUnavailableError(RuntimeError):
    """Raised when GCP credentials are absent or SCC returned an unrecoverable error."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GCPSCCEngine:
    """Thread-safe GCP Security Command Center client with no SQLite cache."""

    def __init__(
        self,
        creds_path: Optional[str] = None,
        org_id: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        sdk_client: Optional[Any] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_creds = creds_path
        self._explicit_org_id = org_id
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

    def org_id(self) -> Optional[str]:
        v = self._explicit_org_id or os.environ.get("GCP_ORG_ID")
        return v.strip() if v else None

    def google_app_creds_present(self) -> bool:
        p = self._creds_path()
        return bool(p and Path(p).is_file())

    def org_id_present(self) -> bool:
        return bool(self.org_id())

    # ------------------------------------------------------------ helpers

    def _ensure_available(self) -> None:
        if not self.google_app_creds_present():
            raise GCPSCCUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS unset or file missing — "
                "configure a GCP service-account JSON key to enable SCC."
            )
        if not self.org_id_present():
            raise GCPSCCUnavailableError(
                "GCP_ORG_ID unset — configure the Security Command Center "
                "organization ID to enable SCC."
            )

    def _load_service_account(self) -> Dict[str, Any]:
        path = self._creds_path()
        if not path:
            raise GCPSCCUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS env var is empty."
            )
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except OSError as exc:
            raise GCPSCCUnavailableError(
                f"Cannot read service-account key at {path}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise GCPSCCUnavailableError(
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
                raise GCPSCCUnavailableError(
                    "PyJWT or google-cloud-securitycenter is required for "
                    "GCP SCC OAuth2 token exchange."
                ) from exc

            iat = int(now)
            payload = {
                "iss": sa.get("client_email"),
                "scope": SCC_OAUTH_SCOPE,
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
                raise GCPSCCUnavailableError(
                    f"GCP token exchange failed ({resp.status_code}): {resp.text}"
                )
            body = resp.json()
            token = body.get("access_token")
            if not token:
                raise GCPSCCUnavailableError("GCP token response missing access_token.")
            self._token_cache["access_token"] = token
            self._token_cache["expires_at"] = now + float(body.get("expires_in", 3600))
            return token

    # ----------------------------------------------------- backend choice

    def _use_sdk(self) -> bool:
        if self._sdk_client is not None:
            return True
        try:
            import google.cloud.securitycenter  # noqa: F401
            return True
        except Exception:
            return False

    def _sdk(self):
        if self._sdk_client is not None:
            return self._sdk_client
        try:
            from google.cloud import securitycenter
            from google.oauth2 import service_account
        except ImportError as exc:
            raise GCPSCCUnavailableError(
                "google-cloud-securitycenter SDK not installed."
            ) from exc
        creds = service_account.Credentials.from_service_account_file(
            self._creds_path()
        )
        self._sdk_client = securitycenter.SecurityCenterClient(credentials=creds)
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
            raise GCPSCCUnavailableError("GCP SCC rejected credentials (401).")
        if resp.status_code == 403:
            raise GCPSCCUnavailableError(
                "GCP SCC permission denied (403) — check IAM roles."
            )
        if resp.status_code >= 400:
            raise GCPSCCUnavailableError(
                f"GCP SCC returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise GCPSCCUnavailableError(
                f"GCP SCC returned non-JSON payload: {exc}"
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
            raise GCPSCCUnavailableError("GCP SCC rejected credentials (401).")
        if resp.status_code == 403:
            raise GCPSCCUnavailableError(
                "GCP SCC permission denied (403) — check IAM roles."
            )
        if resp.status_code >= 400:
            raise GCPSCCUnavailableError(
                f"GCP SCC returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise GCPSCCUnavailableError(
                f"GCP SCC returned non-JSON payload: {exc}"
            ) from exc

    # -------------------------------------------------------- public API

    def list_findings(
        self,
        org_id: Optional[str] = None,
        filter_: Optional[str] = None,
        page_token: Optional[str] = None,
        page_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        org = (org_id or self.org_id() or "").strip()
        if not org:
            raise GCPSCCUnavailableError("orgId required.")
        params: Dict[str, Any] = {}
        if filter_:
            params["filter"] = filter_
        if page_token:
            params["pageToken"] = page_token
        if page_size:
            params["pageSize"] = int(page_size)

        url = f"{SCC_API_BASE}/organizations/{org}/sources/-/findings"
        body = self._http_get(url, params=params)
        # Normalize list-shape: SCC returns {listFindingsResults:[{finding:{}, resource:{}}], totalSize, nextPageToken}
        findings: List[Dict[str, Any]] = []
        for item in body.get("listFindingsResults", []):
            f = item.get("finding") or {}
            findings.append({
                "name": f.get("name", ""),
                "parent": f.get("parent", ""),
                "resourceName": f.get("resourceName", ""),
                "state": f.get("state", ""),
                "category": f.get("category", ""),
                "externalUri": f.get("externalUri", ""),
                "sourceProperties": f.get("sourceProperties", {}),
                "securityMarks": f.get("securityMarks", {"name": "", "marks": {}}),
                "eventTime": f.get("eventTime", ""),
                "createTime": f.get("createTime", ""),
                "severity": f.get("severity", ""),
            })
        return {
            "findings": findings,
            "totalSize": int(body.get("totalSize", len(findings))),
            "nextPageToken": body.get("nextPageToken", ""),
        }

    def list_sources(
        self, org_id: Optional[str] = None, page_token: Optional[str] = None
    ) -> Dict[str, Any]:
        self._ensure_available()
        org = (org_id or self.org_id() or "").strip()
        if not org:
            raise GCPSCCUnavailableError("orgId required.")
        params: Dict[str, Any] = {}
        if page_token:
            params["pageToken"] = page_token
        url = f"{SCC_API_BASE}/organizations/{org}/sources"
        body = self._http_get(url, params=params)
        sources: List[Dict[str, Any]] = []
        for s in body.get("sources", []):
            sources.append({
                "name": s.get("name", ""),
                "displayName": s.get("displayName", ""),
                "description": s.get("description", ""),
                "canonicalName": s.get("canonicalName", s.get("name", "")),
            })
        return {
            "sources": sources,
            "nextPageToken": body.get("nextPageToken", ""),
        }

    def list_assets(
        self,
        org_id: Optional[str] = None,
        filter_: Optional[str] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        org = (org_id or self.org_id() or "").strip()
        if not org:
            raise GCPSCCUnavailableError("orgId required.")
        params: Dict[str, Any] = {}
        if filter_:
            params["filter"] = filter_
        if page_token:
            params["pageToken"] = page_token
        url = f"{SCC_API_BASE}/organizations/{org}/assets"
        body = self._http_get(url, params=params)
        results: List[Dict[str, Any]] = []
        for item in body.get("listAssetsResults", []):
            asset = item.get("asset") or {}
            scp = asset.get("securityCenterProperties") or {}
            results.append({
                "asset": {
                    "name": asset.get("name", ""),
                    "securityCenterProperties": {
                        "resourceName": scp.get("resourceName", ""),
                        "resourceType": scp.get("resourceType", ""),
                        "resourceParent": scp.get("resourceParent", ""),
                        "resourceProject": scp.get("resourceProject", ""),
                        "resourceOwners": scp.get("resourceOwners", []) or [],
                    },
                    "resourceProperties": asset.get("resourceProperties", {}) or {},
                },
                "stateChange": item.get("stateChange", "UNUSED"),
            })
        return {
            "listAssetsResults": results,
            "totalSize": int(body.get("totalSize", len(results))),
            "nextPageToken": body.get("nextPageToken", ""),
        }

    def group_findings(
        self,
        org_id: Optional[str] = None,
        group_by: str = "category",
        filter_: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_available()
        org = (org_id or self.org_id() or "").strip()
        if not org:
            raise GCPSCCUnavailableError("orgId required.")
        if not group_by:
            raise ValueError("groupBy is required.")
        url = f"{SCC_API_BASE}/organizations/{org}/sources/-/findings:group"
        body_in: Dict[str, Any] = {"groupBy": group_by}
        if filter_:
            body_in["filter"] = filter_
        body = self._http_post(url, body=body_in)
        groups: List[Dict[str, Any]] = []
        for g in body.get("groupByResults", []):
            groups.append({
                "properties": g.get("properties", {}) or {},
                "count": int(g.get("count", 0)),
            })
        return {
            "groupByResults": groups,
            "totalSize": int(body.get("totalSize", len(groups))),
        }

    def set_mute(self, finding_name: str, mute: str) -> Dict[str, Any]:
        self._ensure_available()
        if not finding_name:
            raise ValueError("finding name is required.")
        mute_norm = (mute or "").upper().strip()
        if mute_norm not in {"MUTED", "UNMUTED", "UNDEFINED"}:
            raise ValueError(
                "mute must be one of MUTED, UNMUTED, UNDEFINED."
            )
        url = f"{SCC_API_BASE}/{finding_name}:setMute"
        body = self._http_post(url, body={"mute": mute_norm})
        return body

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
_engine_instance: Optional[GCPSCCEngine] = None


def get_gcp_scc_engine(
    creds_path: Optional[str] = None,
    org_id: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    sdk_client: Optional[Any] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> GCPSCCEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = GCPSCCEngine(
                creds_path=creds_path,
                org_id=org_id,
                client=client,
                sdk_client=sdk_client,
                timeout=timeout,
            )
        return _engine_instance


def reset_gcp_scc_engine() -> None:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is not None:
            _engine_instance.close()
        _engine_instance = None
