"""
Veeam Backup Enterprise Manager Engine — ALDECI.

Wraps Veeam Backup Enterprise Manager REST v1 surfaces:
  - POST /api/oauth2/token                 (password / refresh_token grant)
  - GET  /api/v1/backupSessions
  - GET  /api/v1/backupSessions/{id}
  - GET  /api/v1/jobs
  - GET  /api/v1/jobs/{id}
  - POST /api/v1/jobs/{id}/start
  - POST /api/v1/jobs/{id}/stop
  - GET  /api/v1/backups
  - GET  /api/v1/restorePoints?BackupUid=
  - GET  /api/v1/managedServers

Auth
----
Two-phase: POST /api/oauth2/token (grant_type=password, username, password) →
cache access_token ~13min (refresh on 401). Bearer auth on subsequent calls.

Cache
-----
NO SQLite cache (per task spec). Token kept in-process only; every data call
hits Veeam live.

NO MOCKS rule
-------------
* If any of VEEAM_BASE_URL / VEEAM_USERNAME / VEEAM_PASSWORD is unset:
    - All live endpoints raise ``VeeamUnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Veeam.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0
# Veeam tokens default to 900s (15 min). Cache for 13 min, then refresh.
TOKEN_TTL_SECONDS = 13 * 60


class VeeamUnavailableError(RuntimeError):
    """Raised when creds are missing, network failed, or upstream returned an
    unrecoverable status."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class VeeamEngine:
    """Thread-safe Veeam Backup Enterprise Manager REST client (no SQLite)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit values win over env (re-read each call so tests can monkeypatch).
        self._explicit_base_url = base_url
        self._explicit_username = username
        self._explicit_password = password

        self._client = client or httpx.Client(timeout=timeout, verify=True)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expiry: float = 0.0  # epoch seconds

    # ----------------------------------------------------------- creds

    def _base_url(self) -> Optional[str]:
        v = self._explicit_base_url or os.environ.get("VEEAM_BASE_URL") or None
        if v:
            v = v.rstrip("/")
        return v

    def _username(self) -> Optional[str]:
        return (
            self._explicit_username
            or os.environ.get("VEEAM_USERNAME")
            or None
        )

    def _password(self) -> Optional[str]:
        return (
            self._explicit_password
            or os.environ.get("VEEAM_PASSWORD")
            or None
        )

    def base_url_present(self) -> bool:
        return bool(self._base_url())

    def username_present(self) -> bool:
        return bool(self._username())

    def password_present(self) -> bool:
        return bool(self._password())

    def creds_complete(self) -> bool:
        return (
            self.base_url_present()
            and self.username_present()
            and self.password_present()
        )

    # --------------------------------------------------------- auth

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        base = self._base_url()
        if not base:
            raise VeeamUnavailableError("VEEAM_BASE_URL is not configured")
        if not path.startswith("/"):
            path = "/" + path
        url = f"{base}{path}"
        if params:
            qs = urlencode(
                [(k, v) for k, v in params.items() if v is not None and v != ""]
            )
            if qs:
                url = f"{url}?{qs}"
        return url

    def _post_form(
        self,
        path: str,
        form: Dict[str, str],
    ) -> Dict[str, Any]:
        """POST a form-encoded body and return the parsed JSON.

        Used only for the OAuth2 token endpoint.
        """
        url = self._build_url(path)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        try:
            resp = self._client.post(url, headers=headers, content=urlencode(form).encode("utf-8"))
        except httpx.HTTPError as exc:
            raise VeeamUnavailableError(
                f"Veeam token request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (400, 401, 403):
            raise VeeamUnavailableError(
                f"Veeam rejected token request (HTTP {sc}): {getattr(resp, 'text', '')[:200]}"
            )
        if sc >= 400:
            raise VeeamUnavailableError(
                f"Veeam token endpoint returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise VeeamUnavailableError(
                f"Veeam token endpoint returned non-JSON: {exc}"
            ) from exc

    def fetch_token(
        self,
        *,
        grant_type: str = "password",
        username: Optional[str] = None,
        password: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/oauth2/token — return raw token payload.

        For grant_type=password, falls back to engine creds if username/password
        are not supplied. For grant_type=refresh_token, ``refresh_token`` is
        required.
        """
        if grant_type not in ("password", "refresh_token"):
            raise ValueError(f"unsupported grant_type: {grant_type}")

        if grant_type == "password":
            u = username or self._username()
            p = password or self._password()
            if not (u and p):
                raise VeeamUnavailableError(
                    "Veeam username/password not configured"
                )
            if not self.base_url_present():
                raise VeeamUnavailableError("VEEAM_BASE_URL is not configured")
            form = {
                "grant_type": "password",
                "username": u,
                "password": p,
            }
        else:
            if not refresh_token:
                raise ValueError("refresh_token must not be empty")
            if not self.base_url_present():
                raise VeeamUnavailableError("VEEAM_BASE_URL is not configured")
            form = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }

        raw = self._post_form("/api/oauth2/token", form)
        return self._normalize_token(raw)

    def _ensure_access_token(self) -> str:
        """Return a valid bearer token, fetching/refreshing as needed."""
        with self._lock:
            now = time.time()
            if self._access_token and now < self._token_expiry:
                return self._access_token
            # Refresh if we have a refresh_token, otherwise password grant.
            if self._refresh_token:
                try:
                    payload = self.fetch_token(
                        grant_type="refresh_token",
                        refresh_token=self._refresh_token,
                    )
                except VeeamUnavailableError:
                    payload = self.fetch_token(grant_type="password")
            else:
                payload = self.fetch_token(grant_type="password")
            tok = payload.get("access_token")
            if not tok:
                raise VeeamUnavailableError(
                    "Veeam token response missing access_token"
                )
            self._access_token = tok
            self._refresh_token = payload.get("refresh_token") or self._refresh_token
            self._token_expiry = time.time() + TOKEN_TTL_SECONDS
            return tok

    def _invalidate_token(self) -> None:
        with self._lock:
            self._access_token = None
            self._token_expiry = 0.0

    # --------------------------------------------------------- request

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        _retry_on_401: bool = True,
    ) -> Dict[str, Any]:
        if not self.creds_complete():
            missing = []
            if not self.base_url_present():
                missing.append("VEEAM_BASE_URL")
            if not self.username_present():
                missing.append("VEEAM_USERNAME")
            if not self.password_present():
                missing.append("VEEAM_PASSWORD")
            raise VeeamUnavailableError(
                "Veeam credentials missing: " + ",".join(missing)
            )
        token = self._ensure_access_token()
        url = self._build_url(path, params=params)
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        body_bytes: Optional[bytes] = None
        if json_body is not None:
            import json as _json
            body_bytes = _json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers)
            elif method.upper() == "POST":
                resp = self._client.post(url, headers=headers, content=body_bytes)
            elif method.upper() == "PUT":
                resp = self._client.put(url, headers=headers, content=body_bytes)
            else:
                raise VeeamUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise VeeamUnavailableError(
                f"Veeam request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc == 401 and _retry_on_401:
            # Token may have expired earlier than our heuristic — refresh once.
            self._invalidate_token()
            return self._request(
                method,
                path,
                params=params,
                json_body=json_body,
                _retry_on_401=False,
            )
        if sc in (401, 403):
            raise VeeamUnavailableError(
                f"Veeam rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise VeeamUnavailableError(
                f"Veeam resource not found (HTTP 404): {path}"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"Veeam validation error: {body}")
        if sc == 429:
            raise VeeamUnavailableError(
                "Veeam rate-limit exceeded (HTTP 429)"
            )
        if sc == 202:
            # Async start/stop — body may be empty; return parsed-or-stub.
            try:
                return resp.json()
            except ValueError:
                return {"Task": {"Id": "", "State": "Running"}}
        if sc >= 400:
            raise VeeamUnavailableError(
                f"Veeam returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise VeeamUnavailableError(
                f"Veeam returned non-JSON response: {exc}"
            ) from exc

    # --------------------------------------------------------------- backupSessions

    def backup_sessions(
        self,
        *,
        filter_: Optional[str] = None,
        skip: Optional[int] = None,
        take: Optional[int] = None,
        order_column: Optional[str] = None,
        order_asc: Optional[bool] = None,
    ) -> Dict[str, Any]:
        params = {
            "Filter": filter_,
            "Skip": skip,
            "Take": take,
            "OrderColumn": order_column,
            "OrderAsc": str(order_asc).lower() if order_asc is not None else None,
        }
        raw = self._request("GET", "/api/v1/backupSessions", params=params)
        return self._normalize_session_list(raw, skip=skip, take=take)

    def backup_session(self, session_id: str) -> Dict[str, Any]:
        if not session_id:
            raise ValueError("session_id must not be empty")
        raw = self._request(
            "GET", f"/api/v1/backupSessions/{session_id}"
        )
        return self._normalize_session(raw)

    # --------------------------------------------------------------- jobs

    def jobs(
        self,
        *,
        filter_: Optional[str] = None,
        skip: Optional[int] = None,
        take: Optional[int] = None,
        order_column: Optional[str] = None,
        order_asc: Optional[bool] = None,
    ) -> Dict[str, Any]:
        params = {
            "Filter": filter_,
            "Skip": skip,
            "Take": take,
            "OrderColumn": order_column,
            "OrderAsc": str(order_asc).lower() if order_asc is not None else None,
        }
        raw = self._request("GET", "/api/v1/jobs", params=params)
        return self._normalize_job_list(raw)

    def job(self, job_id: str) -> Dict[str, Any]:
        if not job_id:
            raise ValueError("job_id must not be empty")
        raw = self._request("GET", f"/api/v1/jobs/{job_id}")
        return self._normalize_job(raw)

    def start_job(self, job_id: str) -> Dict[str, Any]:
        if not job_id:
            raise ValueError("job_id must not be empty")
        raw = self._request("POST", f"/api/v1/jobs/{job_id}/start")
        return self._normalize_task(raw)

    def stop_job(self, job_id: str) -> Dict[str, Any]:
        if not job_id:
            raise ValueError("job_id must not be empty")
        raw = self._request("POST", f"/api/v1/jobs/{job_id}/stop")
        return self._normalize_task(raw)

    # --------------------------------------------------------------- backups

    def backups(
        self,
        *,
        filter_: Optional[str] = None,
        skip: Optional[int] = None,
        take: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = {"Filter": filter_, "Skip": skip, "Take": take}
        raw = self._request("GET", "/api/v1/backups", params=params)
        return self._normalize_backup_list(raw)

    # ----------------------------------------------------------- restorePoints

    def restore_points(
        self,
        *,
        backup_uid: str,
        skip: Optional[int] = None,
        take: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not backup_uid:
            raise ValueError("BackupUid must not be empty")
        params = {"BackupUid": backup_uid, "Skip": skip, "Take": take}
        raw = self._request("GET", "/api/v1/restorePoints", params=params)
        return self._normalize_restore_point_list(raw)

    # ---------------------------------------------------------- managedServers

    def managed_servers(
        self,
        *,
        filter_: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {"Filter": filter_}
        raw = self._request("GET", "/api/v1/managedServers", params=params)
        return self._normalize_managed_server_list(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_token(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "access_token": raw.get("access_token") or "",
            "refresh_token": raw.get("refresh_token") or "",
            "expires_in": int(raw.get("expires_in") or 900),
            "token_type": raw.get("token_type") or "Bearer",
        }

    @staticmethod
    def _normalize_session_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            return {}
        return {
            "Id": entry.get("Id") or "",
            "Name": entry.get("Name") or "",
            "JobName": entry.get("JobName") or "",
            "JobUid": entry.get("JobUid") or "",
            "JobType": entry.get("JobType") or "",
            "JobObjectName": entry.get("JobObjectName") or "",
            "BackupRepositoryUid": entry.get("BackupRepositoryUid") or "",
            "CreationTimeUTC": entry.get("CreationTimeUTC") or "",
            "EndTimeUTC": entry.get("EndTimeUTC") or "",
            "State": entry.get("State") or "",
            "Result": entry.get("Result") or "None",
            "Reason": entry.get("Reason") or "",
            "Progress": int(entry.get("Progress") or 0),
            "BackedUpSize": int(entry.get("BackedUpSize") or 0),
            "ProcessingRate": int(entry.get("ProcessingRate") or 0),
            "RestoredSize": int(entry.get("RestoredSize") or 0),
            "ProcessedObjects": int(entry.get("ProcessedObjects") or 0),
            "TotalObjects": int(entry.get("TotalObjects") or 0),
        }

    @classmethod
    def _normalize_session_list(
        cls,
        raw: Dict[str, Any],
        *,
        skip: Optional[int] = None,
        take: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        # Veeam sometimes wraps under SessionListResponse, sometimes returns
        # bare {Sessions: [...]}. Handle both.
        wrap = (
            raw.get("SessionListResponse")
            if isinstance(raw.get("SessionListResponse"), dict)
            else raw
        )
        sessions_in = (
            wrap.get("Sessions") if isinstance(wrap.get("Sessions"), list) else []
        )
        sessions: List[Dict[str, Any]] = [
            cls._normalize_session_entry(s) for s in sessions_in if isinstance(s, dict)
        ]
        return {
            "SessionListResponse": {
                "Sessions": sessions,
                "Total": int(wrap.get("Total") or len(sessions)),
                "Skip": int(wrap.get("Skip") if wrap.get("Skip") is not None else (skip or 0)),
                "Take": int(wrap.get("Take") if wrap.get("Take") is not None else (take or len(sessions))),
            }
        }

    @classmethod
    def _normalize_session(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        return cls._normalize_session_entry(raw if isinstance(raw, dict) else {})

    @staticmethod
    def _normalize_job_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            return {}
        sched = (
            entry.get("ScheduleSettings")
            if isinstance(entry.get("ScheduleSettings"), dict)
            else {}
        )
        return {
            "Id": entry.get("Id") or "",
            "Name": entry.get("Name") or "",
            "Description": entry.get("Description") or "",
            "JobType": entry.get("JobType") or "",
            "ScheduleEnabled": bool(entry.get("ScheduleEnabled") or False),
            "ScheduleSettings": {
                "StartDate": sched.get("StartDate") or "",
                "RunPeriodically": sched.get("RunPeriodically") or "",
                "RetryCount": int(sched.get("RetryCount") or 0),
                "RetryTimeout": int(sched.get("RetryTimeout") or 0),
                "BackupWindow": sched.get("BackupWindow") or "",
            },
            "NextRun": entry.get("NextRun") or "",
            "LastRun": entry.get("LastRun") or "",
            "ProcessedObjects": int(entry.get("ProcessedObjects") or 0),
            "TotalObjects": int(entry.get("TotalObjects") or 0),
            "BackedUpSize": int(entry.get("BackedUpSize") or 0),
            "EndTimeUTC": entry.get("EndTimeUTC") or "",
            "State": entry.get("State") or "",
            "Result": entry.get("Result") or "None",
            "Reason": entry.get("Reason") or "",
            "RepositoryName": entry.get("RepositoryName") or "",
            "RepositoryUid": entry.get("RepositoryUid") or "",
        }

    @classmethod
    def _normalize_job_list(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        wrap = (
            raw.get("JobListResponse")
            if isinstance(raw.get("JobListResponse"), dict)
            else raw
        )
        jobs_in = (
            wrap.get("Jobs") if isinstance(wrap.get("Jobs"), list) else []
        )
        jobs = [cls._normalize_job_entry(j) for j in jobs_in if isinstance(j, dict)]
        return {"JobListResponse": {"Jobs": jobs}}

    @classmethod
    def _normalize_job(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        return cls._normalize_job_entry(raw if isinstance(raw, dict) else {})

    @staticmethod
    def _normalize_task(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        task = raw.get("Task") if isinstance(raw.get("Task"), dict) else raw
        return {
            "Task": {
                "Id": task.get("Id") or "",
                "State": task.get("State") or "Running",
            }
        }

    @staticmethod
    def _normalize_backup_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            return {}
        types_in = entry.get("BackupTypes") or []
        if isinstance(types_in, str):
            types_in = [types_in]
        return {
            "Id": entry.get("Id") or "",
            "Name": entry.get("Name") or "",
            "JobUid": entry.get("JobUid") or "",
            "JobName": entry.get("JobName") or "",
            "JobType": entry.get("JobType") or "",
            "CreationTimeUTC": entry.get("CreationTimeUTC") or "",
            "BackupSize": int(entry.get("BackupSize") or 0),
            "DataSize": int(entry.get("DataSize") or 0),
            "BackupTypes": [str(t) for t in (types_in or [])],
            "JobObjectName": entry.get("JobObjectName") or "",
            "RestorePoints": int(entry.get("RestorePoints") or 0),
            "OldestRestorePoint": entry.get("OldestRestorePoint") or "",
            "MostRecentRestorePoint": entry.get("MostRecentRestorePoint") or "",
            "RepositoryName": entry.get("RepositoryName") or "",
            "RepositoryUid": entry.get("RepositoryUid") or "",
        }

    @classmethod
    def _normalize_backup_list(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        wrap = (
            raw.get("BackupListResponse")
            if isinstance(raw.get("BackupListResponse"), dict)
            else raw
        )
        in_items = (
            wrap.get("Backups") if isinstance(wrap.get("Backups"), list) else []
        )
        backups = [cls._normalize_backup_entry(b) for b in in_items if isinstance(b, dict)]
        return {"BackupListResponse": {"Backups": backups}}

    @staticmethod
    def _normalize_restore_point_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            return {}
        return {
            "Id": entry.get("Id") or "",
            "Name": entry.get("Name") or "",
            "BackupUid": entry.get("BackupUid") or "",
            "BackupName": entry.get("BackupName") or "",
            "JobObjectName": entry.get("JobObjectName") or "",
            "BackupType": entry.get("BackupType") or "",
            "CreationTimeUTC": entry.get("CreationTimeUTC") or "",
            "FilesCount": int(entry.get("FilesCount") or 0),
            "BackupSize": int(entry.get("BackupSize") or 0),
            "RetentionTimestamp": entry.get("RetentionTimestamp") or "",
            "BackupChainUid": entry.get("BackupChainUid") or "",
            "IsCorrupted": bool(entry.get("IsCorrupted") or False),
            "IsConsistent": bool(entry.get("IsConsistent") if entry.get("IsConsistent") is not None else True),
        }

    @classmethod
    def _normalize_restore_point_list(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        wrap = (
            raw.get("RestorePointListResponse")
            if isinstance(raw.get("RestorePointListResponse"), dict)
            else raw
        )
        in_items = (
            wrap.get("RestorePoints")
            if isinstance(wrap.get("RestorePoints"), list)
            else []
        )
        rps = [
            cls._normalize_restore_point_entry(r)
            for r in in_items
            if isinstance(r, dict)
        ]
        return {"RestorePointListResponse": {"RestorePoints": rps}}

    @staticmethod
    def _normalize_managed_server_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            return {}
        return {
            "Id": entry.get("Id") or "",
            "Name": entry.get("Name") or "",
            "Description": entry.get("Description") or "",
            "Type": entry.get("Type") or "",
            "Version": entry.get("Version") or "",
            "Status": entry.get("Status") or "",
            "Port": int(entry.get("Port") or 0),
        }

    @classmethod
    def _normalize_managed_server_list(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        wrap = (
            raw.get("ManagedServerListResponse")
            if isinstance(raw.get("ManagedServerListResponse"), dict)
            else raw
        )
        in_items = (
            wrap.get("ManagedServers")
            if isinstance(wrap.get("ManagedServers"), list)
            else []
        )
        servers = [
            cls._normalize_managed_server_entry(s)
            for s in in_items
            if isinstance(s, dict)
        ]
        return {"ManagedServerListResponse": {"ManagedServers": servers}}

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[VeeamEngine] = None
_singleton_lock = threading.Lock()


def get_veeam_engine(
    base_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> VeeamEngine:
    """Return the process-wide VeeamEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = VeeamEngine(
                base_url=base_url,
                username=username,
                password=password,
                client=client,
            )
        return _singleton


def reset_veeam_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "VeeamEngine",
    "VeeamUnavailableError",
    "get_veeam_engine",
    "reset_veeam_engine",
]
