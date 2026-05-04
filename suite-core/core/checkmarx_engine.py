"""
Checkmarx One/SAST Engine — ALDECI.

Wraps the Checkmarx One REST API and provides a process-wide singleton.
Checkmarx One uses OAuth2 client_credentials against an IAM realm and then
issues calls under the tenant's API base.

Endpoint coverage
-----------------
* POST /api/iam/auth/realms/{tenant}/protocol/openid-connect/token        — OAuth2
* GET  /api/projects                                                       — list projects
* GET  /api/projects/{project_id}                                          — single project
* GET  /api/scans                                                          — list scans
* POST /api/scans                                                          — create a scan
* GET  /api/scan-results                                                   — list results
* GET  /api/scan-results/{result_id}                                       — single result detail
* POST /api/scan-results                                                   — triage update
* GET  /api/cx-policy-management/policies                                  — list policies

Auth
----
OAuth2 client_credentials. The engine caches the access token for ~25 minutes
(Checkmarx default access_token TTL is 30 minutes — we leave 5 minutes of
slack so there's no race against expiry).

NO MOCKS rule
-------------
* When CHECKMARX_BASE_URL / CHECKMARX_CLIENT_ID / CHECKMARX_CLIENT_SECRET /
  CHECKMARX_TENANT env unset:
    - All live endpoints raise CheckmarxUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Checkmarx.
* No SQLite cache — we keep only the OAuth token in memory.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 15.0
# Checkmarx One access tokens default to 30 minutes. We re-issue 5 minutes
# before expiry so there's no race window during request dispatch.
TOKEN_TTL_SECONDS = 25 * 60


class CheckmarxUnavailableError(RuntimeError):
    """Raised when env unset, network failed, or upstream returned an
    unrecoverable status."""


try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore


class CheckmarxEngine:
    """Thread-safe Checkmarx One REST client with cached OAuth token."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        tenant: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_base_url = base_url
        self._explicit_client_id = client_id
        self._explicit_client_secret = client_secret
        self._explicit_tenant = tenant
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # ---------------------------------------------------------------- helpers

    def _base_url(self) -> Optional[str]:
        if self._explicit_base_url:
            return self._explicit_base_url.rstrip("/")
        v = os.environ.get("CHECKMARX_BASE_URL")
        return v.rstrip("/") if v else None

    def _client_id(self) -> Optional[str]:
        if self._explicit_client_id:
            return self._explicit_client_id
        return os.environ.get("CHECKMARX_CLIENT_ID") or None

    def _client_secret(self) -> Optional[str]:
        if self._explicit_client_secret:
            return self._explicit_client_secret
        return os.environ.get("CHECKMARX_CLIENT_SECRET") or None

    def _tenant(self) -> Optional[str]:
        if self._explicit_tenant:
            return self._explicit_tenant
        return os.environ.get("CHECKMARX_TENANT") or None

    def base_url_present(self) -> bool:
        return bool(self._base_url())

    def client_id_present(self) -> bool:
        return bool(self._client_id())

    def client_secret_present(self) -> bool:
        return bool(self._client_secret())

    def tenant_present(self) -> bool:
        return bool(self._tenant())

    def _credentials_complete(self) -> bool:
        return all(
            [
                self.base_url_present(),
                self.client_id_present(),
                self.client_secret_present(),
                self.tenant_present(),
            ]
        )

    # --------------------------------------------------------------- OAuth2

    def request_token(
        self,
        *,
        grant_type: str = "client_credentials",
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        tenant: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/iam/auth/realms/{tenant}/protocol/openid-connect/token

        Exposed publicly for the router's pass-through endpoint. Also used
        internally by ``_get_token`` to refresh the cached bearer.
        """
        cid = client_id or self._client_id()
        cs = client_secret or self._client_secret()
        tn = tenant or self._tenant()
        base = self._base_url()
        if not (base and cid and cs and tn):
            raise CheckmarxUnavailableError(
                "CHECKMARX_BASE_URL, CHECKMARX_CLIENT_ID, CHECKMARX_CLIENT_SECRET, "
                "and CHECKMARX_TENANT must all be configured"
            )
        if grant_type != "client_credentials":
            raise ValueError(
                f"only grant_type=client_credentials is supported, got {grant_type!r}"
            )
        url = (
            f"{base}/api/iam/auth/realms/{tn}/protocol/openid-connect/token"
        )
        data = {
            "grant_type": "client_credentials",
            "client_id": cid,
            "client_secret": cs,
        }
        try:
            resp = self._client.post(
                url,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise CheckmarxUnavailableError(
                f"Checkmarx token request failed: {exc}"
            ) from exc
        if resp.status_code in (400, 401, 403):
            raise CheckmarxUnavailableError(
                f"Checkmarx rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code >= 400:
            raise CheckmarxUnavailableError(
                f"Checkmarx token endpoint returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise CheckmarxUnavailableError(
                f"Checkmarx token endpoint returned non-JSON: {exc}"
            ) from exc
        if "access_token" not in payload:
            raise CheckmarxUnavailableError(
                "Checkmarx token endpoint missing access_token"
            )
        # Cache for internal use (only when we requested it via env creds)
        if not (client_id or client_secret or tenant):
            with self._lock:
                self._token = payload["access_token"]
                self._token_expires_at = time.time() + TOKEN_TTL_SECONDS
        return payload

    def _get_token(self) -> str:
        with self._lock:
            if self._token and time.time() < self._token_expires_at:
                return self._token
        # Refresh outside the lock to avoid blocking other readers
        payload = self.request_token()
        return payload["access_token"]

    # --------------------------------------------------------------- request

    def _auth_header(self) -> Dict[str, str]:
        token = self._get_token()
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self._credentials_complete():
            raise CheckmarxUnavailableError(
                "CHECKMARX_BASE_URL, CHECKMARX_CLIENT_ID, CHECKMARX_CLIENT_SECRET, "
                "and CHECKMARX_TENANT must all be configured"
            )
        base = self._base_url()
        url = f"{base}{path}"
        headers = self._auth_header()
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        try:
            method_u = method.upper()
            if method_u == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method_u == "POST":
                resp = self._client.post(
                    url, headers=headers, params=params, json=json_body
                )
            else:
                raise CheckmarxUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise CheckmarxUnavailableError(
                f"Checkmarx request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            # Token may have been revoked - drop it so the next call refreshes.
            with self._lock:
                self._token = None
                self._token_expires_at = 0.0
            raise CheckmarxUnavailableError(
                f"Checkmarx rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise CheckmarxUnavailableError(
                f"Checkmarx resource not found: {path}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Checkmarx validation error: {body}")
        if resp.status_code == 429:
            raise CheckmarxUnavailableError(
                "Checkmarx rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise CheckmarxUnavailableError(
                f"Checkmarx returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise CheckmarxUnavailableError(
                f"Checkmarx returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------- Projects

    def list_projects(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        name: Optional[str] = None,
        groups: Optional[str] = None,
        tags_keys: Optional[str] = None,
        tags_values: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/projects"""
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        if name:
            params["name"] = name
        if groups:
            params["groups"] = groups
        if tags_keys:
            params["tags-keys"] = tags_keys
        if tags_values:
            params["tags-values"] = tags_values
        return self._request("GET", "/api/projects", params=params or None)

    def get_project(self, project_id: str) -> Dict[str, Any]:
        """GET /api/projects/{project_id}"""
        if not project_id:
            raise ValueError("project_id must not be empty")
        return self._request("GET", f"/api/projects/{project_id}")

    # ----------------------------------------------------- Scans

    _ALLOWED_SCAN_STATUSES = (
        "Queued",
        "Running",
        "Completed",
        "Failed",
        "Partial",
        "Canceled",
    )
    _ALLOWED_ENGINES = (
        "sast",
        "sca",
        "kics",
        "api-security",
        "microengines",
        "sca-resolver",
    )

    def list_scans(
        self,
        *,
        project_id: Optional[str] = None,
        statuses: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        branch: Optional[str] = None,
        tags_keys: Optional[str] = None,
        tags_values: Optional[str] = None,
        engine: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/scans"""
        if statuses:
            for s in statuses.split(","):
                if s and s.strip() not in self._ALLOWED_SCAN_STATUSES:
                    raise ValueError(
                        f"status {s!r} not in {self._ALLOWED_SCAN_STATUSES}"
                    )
        if engine and engine not in self._ALLOWED_ENGINES:
            raise ValueError(f"engine {engine!r} not in {self._ALLOWED_ENGINES}")
        params: Dict[str, Any] = {}
        if project_id:
            params["project-id"] = project_id
        if statuses:
            params["statuses"] = statuses
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        if from_date:
            params["from-date"] = from_date
        if to_date:
            params["to-date"] = to_date
        if branch:
            params["branch"] = branch
        if tags_keys:
            params["tags-keys"] = tags_keys
        if tags_values:
            params["tags-values"] = tags_values
        if engine:
            params["engine"] = engine
        return self._request("GET", "/api/scans", params=params or None)

    def create_scan(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/scans"""
        if not isinstance(body, dict):
            raise ValueError("scan body must be a dict")
        project = body.get("project")
        if not isinstance(project, dict) or not project.get("id"):
            raise ValueError("scan body.project.id is required")
        result = self._request("POST", "/api/scans", json_body=body)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    scan_id = (result or {}).get("id", "unknown") if isinstance(result, dict) else "unknown"
                    _bus.emit(
                        "scan.completed",
                        {
                            "entity_id": str(scan_id),
                            "type": "checkmarx_sast_scan",
                            "severity": "unknown",
                            "source_engine": "checkmarx",
                            "project_id": str(project.get("id", "")),
                        },
                    )
            except Exception:
                pass
        return result

    # ----------------------------------------------------- Scan results

    _ALLOWED_RESULT_SEVERITY = ("HIGH", "MEDIUM", "LOW", "INFO")
    _ALLOWED_RESULT_STATE = (
        "TO_VERIFY",
        "NOT_EXPLOITABLE",
        "PROPOSED_NOT_EXPLOITABLE",
        "CONFIRMED",
        "URGENT",
        "FALSE_POSITIVE",
    )
    _ALLOWED_RESULT_STATUS = ("NEW", "RECURRENT", "FIXED")

    def list_scan_results(
        self,
        *,
        scan_id: str,
        severity: Optional[str] = None,
        state: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """GET /api/scan-results"""
        if not scan_id:
            raise ValueError("scan_id must not be empty")
        if severity and severity not in self._ALLOWED_RESULT_SEVERITY:
            raise ValueError(
                f"severity {severity!r} not in {self._ALLOWED_RESULT_SEVERITY}"
            )
        if state and state not in self._ALLOWED_RESULT_STATE:
            raise ValueError(f"state {state!r} not in {self._ALLOWED_RESULT_STATE}")
        if status and status not in self._ALLOWED_RESULT_STATUS:
            raise ValueError(
                f"status {status!r} not in {self._ALLOWED_RESULT_STATUS}"
            )
        params: Dict[str, Any] = {"scan-id": scan_id}
        if severity:
            params["severity"] = severity
        if state:
            params["state"] = state
        if status:
            params["status"] = status
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        return self._request("GET", "/api/scan-results", params=params)

    def get_scan_result(self, result_id: str) -> Dict[str, Any]:
        """GET /api/scan-results/{result_id}"""
        if not result_id:
            raise ValueError("result_id must not be empty")
        return self._request("GET", f"/api/scan-results/{result_id}")

    def update_scan_result(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/scan-results — triage update."""
        if not isinstance(body, dict):
            raise ValueError("update body must be a dict")
        for required in ("scanId", "projectId", "similarityId"):
            if not body.get(required):
                raise ValueError(f"update body.{required} is required")
        sev = body.get("severity")
        if sev and sev not in self._ALLOWED_RESULT_SEVERITY:
            raise ValueError(
                f"severity {sev!r} not in {self._ALLOWED_RESULT_SEVERITY}"
            )
        st = body.get("state")
        if st and st not in self._ALLOWED_RESULT_STATE:
            raise ValueError(f"state {st!r} not in {self._ALLOWED_RESULT_STATE}")
        stat = body.get("status")
        if stat and stat not in self._ALLOWED_RESULT_STATUS:
            raise ValueError(
                f"status {stat!r} not in {self._ALLOWED_RESULT_STATUS}"
            )
        return self._request("POST", "/api/scan-results", json_body=body)

    # ----------------------------------------------------- Policies

    def list_policies(self, *, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """GET /api/cx-policy-management/policies"""
        params: Dict[str, Any] = {}
        if tenant_id:
            params["tenantId"] = tenant_id
        return self._request(
            "GET",
            "/api/cx-policy-management/policies",
            params=params or None,
        )

    # --------------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[CheckmarxEngine] = None
_singleton_lock = threading.Lock()


def get_checkmarx_engine(
    base_url: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    tenant: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> CheckmarxEngine:
    """Return the process-wide CheckmarxEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = CheckmarxEngine(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                tenant=tenant,
                client=client,
            )
        return _singleton


def reset_checkmarx_engine() -> None:
    """Tear down the singleton — used by tests with stub clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "CheckmarxEngine",
    "CheckmarxUnavailableError",
    "get_checkmarx_engine",
    "reset_checkmarx_engine",
]
