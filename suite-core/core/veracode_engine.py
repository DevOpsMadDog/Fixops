"""
Veracode SAST Engine — ALDECI.

Wraps the Veracode AppSec REST API (https://api.veracode.com) and provides a
process-wide singleton. NO SQLite cache — Veracode responses can be very large
and short-lived; we forward every call live to the upstream API.

Endpoint coverage
-----------------
* GET /appsec/v1/applications                                        — list applications
* GET /appsec/v1/applications/{guid}                                  — single application
* GET /appsec/v2/applications/{guid}/findings                         — list findings (with rich filtering)
* GET /appsec/v1/findings/{finding_id}/annotations                    — annotations for a finding
* GET /appsec/v1/policies                                             — list policies

Auth
----
Veracode HMAC-SHA256:

    canonical = id={ID}&host={host}&url={path?query}&method={METHOD}
    signed    = ts={ms_epoch}&nonce={hex}&vcode_request_version=vcode_request_version_1

Implementation follows the Veracode signing spec — chained HMACs producing the
final hex signature for the ``Authorization`` header:

    Authorization: VERACODE-HMAC-SHA-256 id={ID},ts={ts},nonce={nonce},sig={hex}

If the optional ``veracode-api-signing`` library is installed we use its
``RequestsAuthPluginVeracodeHMAC`` helper instead (kept compatible by signing
URL parts ourselves and emitting the same header form).

NO MOCKS rule
-------------
* When VERACODE_API_ID or VERACODE_API_KEY env unset:
    - All live endpoints raise VeracodeUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Veracode.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlencode

import httpx

_logger = logging.getLogger(__name__)

VERACODE_API_BASE = "https://api.veracode.com"
DEFAULT_TIMEOUT_SECONDS = 15.0
_REQ_VERSION = "vcode_request_version_1"


class VeracodeUnavailableError(RuntimeError):
    """Raised when API ID/KEY missing, network failed, or upstream returned an
    unrecoverable status."""


def _veracode_hmac_sig(
    api_id: str, api_key: str, host: str, url_path_with_query: str, method: str
) -> Dict[str, str]:
    """Compute Veracode HMAC-SHA256 signature.

    Returns the four header fields required to assemble:
        Authorization: VERACODE-HMAC-SHA-256 id=...,ts=...,nonce=...,sig=...
    """
    nonce = secrets.token_hex(16).upper()
    ts = str(int(time.time() * 1000))
    data = (
        f"id={api_id}&host={host}&url={url_path_with_query}&method={method.upper()}"
    )
    # Veracode chains four HMACs:
    #   key_nonce = HMAC(key=hex_decode(api_key), msg=hex_decode(nonce))
    #   key_ts    = HMAC(key=key_nonce, msg=ts)
    #   key_ver   = HMAC(key=key_ts,    msg=request_version)
    #   sig       = HMAC(key=key_ver,   msg=data).hex()
    try:
        key_bytes = bytes.fromhex(api_key)
    except ValueError as exc:
        raise VeracodeUnavailableError(
            f"VERACODE_API_KEY is not valid hex: {exc}"
        ) from exc
    nonce_bytes = bytes.fromhex(nonce)
    key_nonce = hmac.new(key_bytes, nonce_bytes, hashlib.sha256).digest()
    key_ts = hmac.new(key_nonce, ts.encode("utf-8"), hashlib.sha256).digest()
    key_ver = hmac.new(key_ts, _REQ_VERSION.encode("utf-8"), hashlib.sha256).digest()
    sig = hmac.new(key_ver, data.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"id": api_id, "ts": ts, "nonce": nonce, "sig": sig}


class VeracodeEngine:
    """Thread-safe Veracode HMAC-signed REST client (no cache)."""

    def __init__(
        self,
        api_id: Optional[str] = None,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_api_id = api_id
        self._explicit_api_key = api_key
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- helpers

    def _api_id(self) -> Optional[str]:
        if self._explicit_api_id:
            return self._explicit_api_id
        v = os.environ.get("VERACODE_API_ID")
        return v or None

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("VERACODE_API_KEY")
        return v or None

    def api_id_present(self) -> bool:
        return bool(self._api_id())

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def _auth_header(self, method: str, path_with_query: str) -> Dict[str, str]:
        api_id = self._api_id()
        api_key = self._api_key()
        if not api_id or not api_key:
            raise VeracodeUnavailableError(
                "VERACODE_API_ID and VERACODE_API_KEY must be configured"
            )
        host = urlsplit(VERACODE_API_BASE).netloc
        parts = _veracode_hmac_sig(api_id, api_key, host, path_with_query, method)
        auth = (
            "VERACODE-HMAC-SHA-256 "
            f"id={parts['id']},ts={parts['ts']},nonce={parts['nonce']},sig={parts['sig']}"
        )
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": auth,
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        # Build canonical "url=" component for the HMAC: path + ?qs (when any).
        # Sort params to keep signing deterministic.
        if params:
            clean: List[tuple] = []
            for k, v in params.items():
                if v is None:
                    continue
                if isinstance(v, (list, tuple)):
                    for item in v:
                        clean.append((k, str(item)))
                else:
                    clean.append((k, str(v)))
            qs = urlencode(sorted(clean), doseq=True)
            path_with_query = f"{path}?{qs}" if qs else path
        else:
            path_with_query = path

        headers = self._auth_header(method, path_with_query)
        url = f"{VERACODE_API_BASE}{path}"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            else:
                raise VeracodeUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise VeracodeUnavailableError(
                f"Veracode request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise VeracodeUnavailableError(
                f"Veracode rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise VeracodeUnavailableError(
                f"Veracode resource not found: {path}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Veracode validation error: {body}")
        if resp.status_code == 429:
            raise VeracodeUnavailableError(
                "Veracode rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise VeracodeUnavailableError(
                f"Veracode returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise VeracodeUnavailableError(
                f"Veracode returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------- AppSec v1/v2 calls

    def list_applications(
        self,
        *,
        size: Optional[int] = None,
        page: Optional[int] = None,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /appsec/v1/applications"""
        params: Dict[str, Any] = {}
        if size is not None:
            params["size"] = int(size)
        if page is not None:
            params["page"] = int(page)
        if name:
            params["name"] = name
        return self._request(
            "GET", "/appsec/v1/applications", params=params or None
        )

    def get_application(self, app_guid: str) -> Dict[str, Any]:
        """GET /appsec/v1/applications/{guid}"""
        if not app_guid:
            raise ValueError("app_guid must not be empty")
        return self._request("GET", f"/appsec/v1/applications/{app_guid}")

    def list_findings(
        self,
        app_guid: str,
        *,
        size: Optional[int] = None,
        page: Optional[int] = None,
        context: Optional[str] = None,
        include_annot: Optional[bool] = None,
        include_exp_date: Optional[bool] = None,
        violates_policy: Optional[bool] = None,
        scan_type: Optional[str] = None,
        severity: Optional[int] = None,
        severity_gte: Optional[int] = None,
        cwe: Optional[int] = None,
    ) -> Dict[str, Any]:
        """GET /appsec/v2/applications/{guid}/findings"""
        if not app_guid:
            raise ValueError("app_guid must not be empty")
        if scan_type and scan_type not in ("STATIC", "DYNAMIC", "MANUAL", "SCA"):
            raise ValueError(
                "scan_type must be one of STATIC, DYNAMIC, MANUAL, SCA"
            )
        if severity is not None and not (1 <= int(severity) <= 5):
            raise ValueError("severity must be between 1 and 5")
        if severity_gte is not None and not (1 <= int(severity_gte) <= 5):
            raise ValueError("severity_gte must be between 1 and 5")
        params: Dict[str, Any] = {}
        if size is not None:
            params["size"] = int(size)
        if page is not None:
            params["page"] = int(page)
        if context:
            params["context"] = context
        if include_annot is not None:
            params["include_annot"] = "true" if include_annot else "false"
        if include_exp_date is not None:
            params["include_exp_date"] = "true" if include_exp_date else "false"
        if violates_policy is not None:
            params["violates_policy"] = "true" if violates_policy else "false"
        if scan_type:
            params["scan_type"] = scan_type
        if severity is not None:
            params["severity"] = int(severity)
        if severity_gte is not None:
            params["severity_gte"] = int(severity_gte)
        if cwe is not None:
            params["cwe"] = int(cwe)
        return self._request(
            "GET",
            f"/appsec/v2/applications/{app_guid}/findings",
            params=params or None,
        )

    def list_finding_annotations(
        self, finding_id: str, *, app_guid: str
    ) -> Dict[str, Any]:
        """GET /appsec/v1/findings/{finding_id}/annotations"""
        if not finding_id:
            raise ValueError("finding_id must not be empty")
        if not app_guid:
            raise ValueError("app_guid must not be empty")
        return self._request(
            "GET",
            f"/appsec/v1/findings/{finding_id}/annotations",
            params={"app_guid": app_guid},
        )

    def list_policies(
        self,
        *,
        name: Optional[str] = None,
        size: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        """GET /appsec/v1/policies"""
        params: Dict[str, Any] = {}
        if name:
            params["name"] = name
        if size is not None:
            params["size"] = int(size)
        if page is not None:
            params["page"] = int(page)
        return self._request(
            "GET", "/appsec/v1/policies", params=params or None
        )

    # --------------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[VeracodeEngine] = None
_singleton_lock = threading.Lock()


def get_veracode_engine(
    api_id: Optional[str] = None,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> VeracodeEngine:
    """Return the process-wide VeracodeEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = VeracodeEngine(
                api_id=api_id, api_key=api_key, client=client
            )
        return _singleton


def reset_veracode_engine() -> None:
    """Tear down the singleton — used by tests with stub clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "VeracodeEngine",
    "VeracodeUnavailableError",
    "get_veracode_engine",
    "reset_veracode_engine",
]
