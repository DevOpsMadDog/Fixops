"""
Apigee Edge X Engine — ALDECI.

Wraps the Google Apigee X management REST API (apigee.googleapis.com).

Endpoint coverage
-----------------
* GET /v1/organizations/{org}/apis
* GET /v1/organizations/{org}/apis/{api_name}
* GET /v1/organizations/{org}/apis/{api_name}/revisions
* GET /v1/organizations/{org}/apis/{api_name}/revisions/{revision}
* GET /v1/organizations/{org}/apis/{api_name}/revisions/{revision}/policies
* GET /v1/organizations/{org}/environments
* GET /v1/organizations/{org}/environments/{env}/apis/{api_name}/revisions/{revision}/deployments
* GET /v1/organizations/{org}/apiproducts
* GET /v1/organizations/{org}/developers
* GET /v1/organizations/{org}/developers/{email}/apps
* GET /v1/organizations/{org}/apps

Auth
----
OAuth2 JWT-bearer flow against ``oauth2.googleapis.com``:

  1. Load Google service-account credentials JSON from the file referenced by
     ``GOOGLE_APPLICATION_CREDENTIALS``.
  2. Sign a JWT with the service-account private key (RS256), ``aud =
     https://oauth2.googleapis.com/token``, ``scope =
     https://www.googleapis.com/auth/cloud-platform``.
  3. Exchange the assertion at the Google token endpoint for a short-lived
     access token.
  4. Send ``Authorization: Bearer {access_token}`` to apigee.googleapis.com.

Cache
-----
NO SQLite cache (per task spec). Access tokens are held in-memory only and
refreshed when expiring.

NO MOCKS rule
-------------
* If ``GOOGLE_APPLICATION_CREDENTIALS`` or ``APIGEE_ORG`` is unset:
    - All live endpoints raise ``ApigeeUnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Apigee.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0
APIGEE_BASE_URL = "https://apigee.googleapis.com"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
TOKEN_TTL_SECONDS = 3600
TOKEN_REFRESH_LEEWAY = 60


class ApigeeUnavailableError(RuntimeError):
    """Raised when GOOGLE_APPLICATION_CREDENTIALS / APIGEE_ORG missing,
    network failed, or upstream returned an unrecoverable status."""


# ---------------------------------------------------------------------------
# JWT signer helper
# ---------------------------------------------------------------------------


def _sign_assertion(
    client_email: str,
    private_key: str,
    *,
    audience: str = GOOGLE_TOKEN_URL,
    scope: str = GOOGLE_CLOUD_PLATFORM_SCOPE,
    now_ts: Optional[int] = None,
) -> str:
    """Sign a JWT assertion for the OAuth2 jwt-bearer flow.

    Uses PyJWT (RS256). Raises ApigeeUnavailableError if the JWT library is
    unavailable or the private key cannot be loaded.
    """
    try:
        import jwt  # noqa: PLC0415
    except ImportError as exc:
        raise ApigeeUnavailableError(
            f"PyJWT is required for Apigee OAuth2 jwt-bearer flow: {exc}"
        ) from exc

    iat = int(now_ts if now_ts is not None else time.time())
    exp = iat + TOKEN_TTL_SECONDS
    payload = {
        "iss": client_email,
        "scope": scope,
        "aud": audience,
        "iat": iat,
        "exp": exp,
    }
    try:
        return jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as exc:
        raise ApigeeUnavailableError(
            f"Failed to sign Google OAuth2 JWT assertion: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ApigeeEngine:
    """Thread-safe Apigee X REST client (no cache)."""

    def __init__(
        self,
        credentials_path: Optional[str] = None,
        org: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        token_url: str = GOOGLE_TOKEN_URL,
        base_url: str = APIGEE_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit values win over env (re-read each call so tests can monkeypatch).
        self._explicit_credentials_path = credentials_path
        self._explicit_org = org
        self._token_url = token_url
        self._base_url = base_url.rstrip("/")

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()
        self._cached_token: Optional[str] = None
        self._cached_token_exp: float = 0.0

    # --------------------------------------------------------- env / creds

    def _credentials_path(self) -> Optional[str]:
        return (
            self._explicit_credentials_path
            or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            or None
        )

    def _org(self) -> Optional[str]:
        return self._explicit_org or os.environ.get("APIGEE_ORG") or None

    def google_app_creds_present(self) -> bool:
        path = self._credentials_path()
        if not path:
            return False
        try:
            return os.path.isfile(path)
        except OSError:
            return False

    def apigee_org_present(self) -> bool:
        return bool(self._org())

    def creds_complete(self) -> bool:
        return self.google_app_creds_present() and self.apigee_org_present()

    # ---------------------------------------------------------- auth

    def _load_service_account(self) -> Dict[str, Any]:
        path = self._credentials_path()
        if not path:
            raise ApigeeUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS is not configured"
            )
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ApigeeUnavailableError(
                f"Failed to read GOOGLE_APPLICATION_CREDENTIALS file: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ApigeeUnavailableError(
                "GOOGLE_APPLICATION_CREDENTIALS file is not a JSON object"
            )
        if not data.get("client_email") or not data.get("private_key"):
            raise ApigeeUnavailableError(
                "service-account JSON missing client_email/private_key"
            )
        return data

    def _exchange_assertion(self, assertion: str) -> Dict[str, Any]:
        body = urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            }
        )
        try:
            resp = self._client.post(
                self._token_url,
                content=body.encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise ApigeeUnavailableError(
                f"Google token endpoint unreachable: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc != 200:
            raise ApigeeUnavailableError(
                f"Google token endpoint returned HTTP {sc}: "
                f"{getattr(resp, 'text', '')[:200]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise ApigeeUnavailableError(
                f"Google token endpoint returned non-JSON: {exc}"
            ) from exc
        if not isinstance(payload, dict) or not payload.get("access_token"):
            raise ApigeeUnavailableError(
                "Google token endpoint did not include access_token"
            )
        return payload

    def _access_token(self) -> str:
        with self._lock:
            now = time.time()
            if (
                self._cached_token
                and now < (self._cached_token_exp - TOKEN_REFRESH_LEEWAY)
            ):
                return self._cached_token
            sa = self._load_service_account()
            assertion = _sign_assertion(
                sa["client_email"],
                sa["private_key"],
            )
            payload = self._exchange_assertion(assertion)
            token = str(payload["access_token"])
            ttl = int(payload.get("expires_in") or TOKEN_TTL_SECONDS)
            self._cached_token = token
            self._cached_token_exp = now + ttl
            return token

    # -------------------------------------------------------- request

    def _build_url(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> str:
        url = f"{self._base_url}{path}"
        if params:
            qs = urlencode(
                [
                    (k, _format_query_value(v))
                    for k, v in params.items()
                    if v is not None and v != ""
                ]
            )
            if qs:
                url = f"{url}?{qs}"
        return url

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        if not self.creds_complete():
            missing = []
            if not self.google_app_creds_present():
                missing.append("GOOGLE_APPLICATION_CREDENTIALS")
            if not self.apigee_org_present():
                missing.append("APIGEE_ORG")
            raise ApigeeUnavailableError(
                "Apigee credentials missing: " + ",".join(missing)
            )
        token = self._access_token()
        url = self._build_url(path, params=params)
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers)
            else:
                raise ApigeeUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise ApigeeUnavailableError(
                f"Apigee request failed: {exc}"
            ) from exc
        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise ApigeeUnavailableError(
                f"Apigee rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise ApigeeUnavailableError(
                f"Apigee resource not found (HTTP 404): {path}"
            )
        if sc == 429:
            raise ApigeeUnavailableError(
                "Apigee rate-limit exceeded (HTTP 429)"
            )
        if sc >= 400:
            raise ApigeeUnavailableError(
                f"Apigee returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise ApigeeUnavailableError(
                f"Apigee returned non-JSON response: {exc}"
            ) from exc

    # -------------------------------------------------- normalise helpers

    @staticmethod
    def _ensure_org(org: str) -> str:
        if not org or not isinstance(org, str):
            raise ValueError("org must be a non-empty string")
        return org

    # -------------------------------------------------- API proxies

    def list_apis(
        self,
        org: str,
        *,
        include_revisions: bool = False,
        include_meta_data: bool = False,
    ) -> Dict[str, Any]:
        org = self._ensure_org(org)
        params: Dict[str, Any] = {}
        if include_revisions:
            params["includeRevisions"] = "true"
        if include_meta_data:
            params["includeMetaData"] = "true"
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/apis",
            params=params or None,
        )
        return _normalize_proxy_list(raw)

    def get_api(self, org: str, api_name: str) -> Dict[str, Any]:
        org = self._ensure_org(org)
        if not api_name:
            raise ValueError("api_name must not be empty")
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/apis/{api_name}",
        )
        return _normalize_proxy_detail(raw)

    def list_api_revisions(self, org: str, api_name: str) -> List[str]:
        org = self._ensure_org(org)
        if not api_name:
            raise ValueError("api_name must not be empty")
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/apis/{api_name}/revisions",
        )
        return [str(r) for r in raw] if isinstance(raw, list) else []

    def get_api_revision(
        self, org: str, api_name: str, revision: str
    ) -> Dict[str, Any]:
        org = self._ensure_org(org)
        if not api_name:
            raise ValueError("api_name must not be empty")
        if not revision:
            raise ValueError("revision must not be empty")
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/apis/{api_name}/revisions/{revision}",
        )
        return _normalize_revision_detail(raw)

    def list_api_revision_policies(
        self, org: str, api_name: str, revision: str
    ) -> List[str]:
        org = self._ensure_org(org)
        if not api_name:
            raise ValueError("api_name must not be empty")
        if not revision:
            raise ValueError("revision must not be empty")
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/apis/{api_name}/revisions/{revision}/policies",
        )
        return [str(p) for p in raw] if isinstance(raw, list) else []

    # -------------------------------------------------- environments

    def list_environments(self, org: str) -> List[str]:
        org = self._ensure_org(org)
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/environments",
        )
        return [str(e) for e in raw] if isinstance(raw, list) else []

    def get_environment_deployments(
        self,
        org: str,
        env: str,
        api_name: str,
        revision: str,
    ) -> Dict[str, Any]:
        org = self._ensure_org(org)
        if not env:
            raise ValueError("env must not be empty")
        if not api_name:
            raise ValueError("api_name must not be empty")
        if not revision:
            raise ValueError("revision must not be empty")
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/environments/{env}/apis/{api_name}/revisions/{revision}/deployments",
        )
        return _normalize_deployment(raw)

    # -------------------------------------------------- API products

    def list_api_products(
        self,
        org: str,
        *,
        expand: bool = False,
        count: Optional[int] = None,
        start_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        org = self._ensure_org(org)
        params: Dict[str, Any] = {}
        if expand:
            params["expand"] = "true"
        if count is not None:
            params["count"] = str(int(count))
        if start_key:
            params["startKey"] = start_key
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/apiproducts",
            params=params or None,
        )
        return _normalize_api_products(raw)

    # -------------------------------------------------- developers

    def list_developers(
        self,
        org: str,
        *,
        expand: bool = False,
        count: Optional[int] = None,
        start_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        org = self._ensure_org(org)
        params: Dict[str, Any] = {}
        if expand:
            params["expand"] = "true"
        if count is not None:
            params["count"] = str(int(count))
        if start_key:
            params["startKey"] = start_key
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/developers",
            params=params or None,
        )
        return _normalize_developers(raw)

    def list_developer_apps(
        self, org: str, email: str
    ) -> Dict[str, Any]:
        org = self._ensure_org(org)
        if not email:
            raise ValueError("email must not be empty")
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/developers/{email}/apps",
        )
        return _normalize_apps(raw)

    # -------------------------------------------------- apps

    def list_apps(
        self,
        org: str,
        *,
        expand: bool = False,
        count: Optional[int] = None,
        start_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        org = self._ensure_org(org)
        params: Dict[str, Any] = {}
        if expand:
            params["expand"] = "true"
        if count is not None:
            params["count"] = str(int(count))
        if start_key:
            params["startKey"] = start_key
        raw = self._request(
            "GET",
            f"/v1/organizations/{org}/apps",
            params=params or None,
        )
        return _normalize_apps(raw)

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Normalizers
# ---------------------------------------------------------------------------


def _format_query_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _normalize_meta(entry: Dict[str, Any]) -> Dict[str, Any]:
    meta = entry.get("metaData") if isinstance(entry, dict) else None
    if not isinstance(meta, dict):
        meta = {}
    return {
        "createdAt": meta.get("createdAt") or "",
        "lastModifiedAt": meta.get("lastModifiedAt") or "",
        "subType": meta.get("subType") or "",
        "createdBy": meta.get("createdBy") or "",
        "lastModifiedBy": meta.get("lastModifiedBy") or "",
    }


def _normalize_proxy_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {
            "name": "",
            "latestRevisionId": "",
            "metaData": _normalize_meta({}),
            "revision": [],
        }
    revisions = entry.get("revision")
    if not isinstance(revisions, list):
        revisions = []
    return {
        "name": entry.get("name") or "",
        "latestRevisionId": entry.get("latestRevisionId") or "",
        "metaData": _normalize_meta(entry),
        "revision": [str(r) for r in revisions],
    }


def _normalize_proxy_list(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        proxies = raw.get("proxies")
        if not isinstance(proxies, list):
            proxies = []
    elif isinstance(raw, list):
        proxies = raw
    else:
        proxies = []
    return {
        "proxies": [_normalize_proxy_entry(p) for p in proxies if isinstance(p, dict)]
    }


def _normalize_proxy_detail(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    return _normalize_proxy_entry(raw)


def _normalize_revision_detail(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    return {
        "name": raw.get("name") or "",
        "revision": str(raw.get("revision") or ""),
        "createdAt": raw.get("createdAt") or "",
        "lastModifiedAt": raw.get("lastModifiedAt") or "",
        "createdBy": raw.get("createdBy") or "",
        "lastModifiedBy": raw.get("lastModifiedBy") or "",
        "displayName": raw.get("displayName") or "",
        "description": raw.get("description") or "",
        "configurationVersion": dict(raw.get("configurationVersion") or {}),
        "contextInfo": raw.get("contextInfo") or "",
        "policies": list(raw.get("policies") or []),
        "proxies": list(raw.get("proxies") or []),
        "proxyEndpoints": list(raw.get("proxyEndpoints") or []),
        "resources": list(raw.get("resources") or []),
        "resourceFiles": dict(raw.get("resourceFiles") or {}),
        "targetEndpoints": list(raw.get("targetEndpoints") or []),
        "targetServers": list(raw.get("targetServers") or []),
        "type": raw.get("type") or "",
        "basepaths": list(raw.get("basepaths") or []),
    }


def _normalize_deployment(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    return {
        "environment": raw.get("environment") or "",
        "apiProxy": raw.get("apiProxy") or "",
        "revision": str(raw.get("revision") or ""),
        "deployStartTime": raw.get("deployStartTime") or "",
        "basePath": raw.get("basePath") or "",
        "state": raw.get("state") or "",
        "errors": list(raw.get("errors") or []),
        "instances": list(raw.get("instances") or []),
        "pods": list(raw.get("pods") or []),
        "routeConflicts": list(raw.get("routeConflicts") or []),
    }


def _normalize_attribute(attr: Any) -> Dict[str, Any]:
    if not isinstance(attr, dict):
        return {"name": "", "value": ""}
    return {
        "name": attr.get("name") or "",
        "value": attr.get("value") or "",
    }


def _normalize_operation_config(cfg: Any) -> Dict[str, Any]:
    if not isinstance(cfg, dict):
        return {}
    operations = cfg.get("operations") if isinstance(cfg.get("operations"), list) else []
    quota = cfg.get("quota") if isinstance(cfg.get("quota"), dict) else {}
    attributes = cfg.get("attributes") if isinstance(cfg.get("attributes"), list) else []
    return {
        "apiSource": cfg.get("apiSource") or "",
        "operations": [
            {
                "resource": op.get("resource") or "",
                "methods": list(op.get("methods") or []),
            }
            for op in operations
            if isinstance(op, dict)
        ],
        "quota": {
            "limit": quota.get("limit") or "",
            "interval": quota.get("interval") or "",
            "timeUnit": quota.get("timeUnit") or "",
        },
        "attributes": [_normalize_attribute(a) for a in attributes],
    }


def _normalize_operation_group(grp: Any) -> Dict[str, Any]:
    if not isinstance(grp, dict):
        return {"operationConfigs": [], "operationConfigType": ""}
    cfgs = grp.get("operationConfigs") if isinstance(grp.get("operationConfigs"), list) else []
    return {
        "operationConfigs": [_normalize_operation_config(c) for c in cfgs],
        "operationConfigType": grp.get("operationConfigType") or "",
    }


def _normalize_api_product(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    attributes = entry.get("attributes") if isinstance(entry.get("attributes"), list) else []
    op_group = entry.get("operationGroup")
    return {
        "name": entry.get("name") or "",
        "displayName": entry.get("displayName") or "",
        "description": entry.get("description") or "",
        "approvalType": entry.get("approvalType") or "auto",
        "attributes": [_normalize_attribute(a) for a in attributes],
        "createdAt": entry.get("createdAt") or "",
        "createdBy": entry.get("createdBy") or "",
        "lastModifiedAt": entry.get("lastModifiedAt") or "",
        "lastModifiedBy": entry.get("lastModifiedBy") or "",
        "scopes": list(entry.get("scopes") or []),
        "proxies": list(entry.get("proxies") or []),
        "environments": list(entry.get("environments") or []),
        "apiResources": list(entry.get("apiResources") or []),
        "quota": entry.get("quota") or "",
        "quotaInterval": entry.get("quotaInterval") or "",
        "quotaTimeUnit": entry.get("quotaTimeUnit") or "",
        "operationGroup": _normalize_operation_group(op_group)
        if op_group is not None
        else {"operationConfigs": [], "operationConfigType": ""},
    }


def _normalize_api_products(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        items = raw.get("apiProduct")
        if not isinstance(items, list):
            items = []
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    return {"apiProduct": [_normalize_api_product(p) for p in items]}


def _normalize_developer(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    attributes = entry.get("attributes") if isinstance(entry.get("attributes"), list) else []
    return {
        "email": entry.get("email") or "",
        "firstName": entry.get("firstName") or "",
        "lastName": entry.get("lastName") or "",
        "userName": entry.get("userName") or "",
        "status": entry.get("status") or "active",
        "organizationName": entry.get("organizationName") or "",
        "attributes": [_normalize_attribute(a) for a in attributes],
        "appName": list(entry.get("apps") or entry.get("appName") or []),
        "companies": list(entry.get("companies") or []),
        "createdAt": entry.get("createdAt") or "",
        "createdBy": entry.get("createdBy") or "",
        "lastModifiedAt": entry.get("lastModifiedAt") or "",
        "lastModifiedBy": entry.get("lastModifiedBy") or "",
        "accessType": entry.get("accessType") or "",
        "developerId": entry.get("developerId") or "",
    }


def _normalize_developers(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        items = raw.get("developer")
        if not isinstance(items, list):
            items = []
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    return {"developer": [_normalize_developer(d) for d in items]}


def _normalize_app(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    attributes = entry.get("attributes") if isinstance(entry.get("attributes"), list) else []
    credentials = entry.get("credentials") if isinstance(entry.get("credentials"), list) else []
    scopes = entry.get("scopes") if isinstance(entry.get("scopes"), list) else []
    return {
        "appId": entry.get("appId") or "",
        "name": entry.get("name") or "",
        "developerId": entry.get("developerId") or "",
        "status": entry.get("status") or "approved",
        "attributes": [_normalize_attribute(a) for a in attributes],
        "callbackUrl": entry.get("callbackUrl") or "",
        "createdAt": entry.get("createdAt") or "",
        "createdBy": entry.get("createdBy") or "",
        "lastModifiedAt": entry.get("lastModifiedAt") or "",
        "lastModifiedBy": entry.get("lastModifiedBy") or "",
        "credentials": list(credentials),
        "scopes": list(scopes),
        "apiProducts": list(entry.get("apiProducts") or []),
    }


def _normalize_apps(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        items = raw.get("app")
        if not isinstance(items, list):
            items = []
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    return {"app": [_normalize_app(a) for a in items]}


# --------------------------------------------------------------- singleton

_singleton: Optional[ApigeeEngine] = None
_singleton_lock = threading.Lock()


def get_apigee_engine(
    credentials_path: Optional[str] = None,
    org: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    token_url: Optional[str] = None,
    base_url: Optional[str] = None,
) -> ApigeeEngine:
    """Return the process-wide ApigeeEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ApigeeEngine(
                credentials_path=credentials_path,
                org=org,
                client=client,
                token_url=token_url or GOOGLE_TOKEN_URL,
                base_url=base_url or APIGEE_BASE_URL,
            )
        return _singleton


def reset_apigee_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ApigeeEngine",
    "ApigeeUnavailableError",
    "get_apigee_engine",
    "reset_apigee_engine",
]
