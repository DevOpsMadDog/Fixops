"""
Mimecast Email Security Engine — ALDECI.

Wraps the Mimecast REST API (https://api.mimecast.com) with HMAC-SHA1 request
signing per Mimecast's "MC" auth scheme. Provides a process-wide singleton
and exposes the seven endpoint families wired by the router:

  * /api/ttp/url/decode-url
  * /api/gateway/get-hold-message-list
  * /api/gateway/release-hold-message
  * /api/ttp/threat-intel/get-feed
  * /api/audit/get-siem-logs
  * /api/managedsender/get-managed-senders
  * /api/policy/anti-spoofing/get-policy

NO MOCKS rule
-------------
* Any of MIMECAST_BASE_URL / MIMECAST_APP_ID / MIMECAST_APP_KEY /
  MIMECAST_ACCESS_KEY / MIMECAST_SECRET_KEY env unset:
    - All live calls raise MimecastUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response is whatever Mimecast returned.

Mimecast HMAC-SHA1 signing (per Mimecast docs):
    signed_string = "{x-mc-date}:{x-mc-req-id}:{uri_path}:{app_key}"
    secret_bytes  = base64.b64decode(secret_key)
    signature     = base64.b64encode(hmac_sha1(secret_bytes, signed_string))
    headers:
        Authorization: MC {access_key}:{signature}
        x-mc-app-id:   {app_id}
        x-mc-date:     {RFC2822 datetime}
        x-mc-req-id:   {uuid4}
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Any, Dict, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0


class MimecastUnavailableError(RuntimeError):
    """Raised when Mimecast credentials are missing, network failed,
    or upstream returned an unrecoverable status."""


class MimecastEmailEngine:
    """Thread-safe Mimecast REST client with HMAC-SHA1 request signing."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        app_id: Optional[str] = None,
        app_key: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_base_url = base_url
        self._explicit_app_id = app_id
        self._explicit_app_key = app_key
        self._explicit_access_key = access_key
        self._explicit_secret_key = secret_key

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ------------------------------------------------------------ env

    def _base_url(self) -> Optional[str]:
        return self._explicit_base_url or os.environ.get("MIMECAST_BASE_URL") or None

    def _app_id(self) -> Optional[str]:
        return self._explicit_app_id or os.environ.get("MIMECAST_APP_ID") or None

    def _app_key(self) -> Optional[str]:
        return self._explicit_app_key or os.environ.get("MIMECAST_APP_KEY") or None

    def _access_key(self) -> Optional[str]:
        return self._explicit_access_key or os.environ.get("MIMECAST_ACCESS_KEY") or None

    def _secret_key(self) -> Optional[str]:
        return self._explicit_secret_key or os.environ.get("MIMECAST_SECRET_KEY") or None

    def app_id_present(self) -> bool:
        return bool(self._app_id())

    def app_key_present(self) -> bool:
        return bool(self._app_key())

    def access_key_present(self) -> bool:
        return bool(self._access_key())

    def secret_key_present(self) -> bool:
        return bool(self._secret_key())

    def credentials_present(self) -> bool:
        return all(
            [
                self._base_url(),
                self._app_id(),
                self._app_key(),
                self._access_key(),
                self._secret_key(),
            ]
        )

    # ------------------------------------------------------------ signing

    def _build_headers(self, uri_path: str) -> Dict[str, str]:
        app_id = self._app_id()
        app_key = self._app_key()
        access_key = self._access_key()
        secret_key = self._secret_key()
        if not (app_id and app_key and access_key and secret_key):
            raise MimecastUnavailableError(
                "Mimecast credentials are not fully configured "
                "(MIMECAST_APP_ID/APP_KEY/ACCESS_KEY/SECRET_KEY required)"
            )

        req_id = str(uuid.uuid4())
        date_hdr = format_datetime(datetime.now(timezone.utc))

        # Mimecast canonical string: "{date}:{req_id}:{uri}:{app_key}"
        signed_string = f"{date_hdr}:{req_id}:{uri_path}:{app_key}"
        try:
            secret_bytes = base64.b64decode(secret_key)
        except Exception as exc:
            raise MimecastUnavailableError(
                f"MIMECAST_SECRET_KEY is not valid base64: {exc}"
            ) from exc
        digest = hmac.new(
            secret_bytes, signed_string.encode("utf-8"), hashlib.sha1
        ).digest()
        signature = base64.b64encode(digest).decode("ascii")

        return {
            "Authorization": f"MC {access_key}:{signature}",
            "x-mc-app-id": app_id,
            "x-mc-date": date_hdr,
            "x-mc-req-id": req_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------ request

    def _request(
        self,
        uri_path: str,
        body: Optional[Dict[str, Any]] = None,
        *,
        binary: bool = False,
    ) -> Any:
        if not self.credentials_present():
            raise MimecastUnavailableError(
                "Mimecast credentials are not fully configured "
                "(set MIMECAST_BASE_URL + MIMECAST_APP_ID + MIMECAST_APP_KEY + "
                "MIMECAST_ACCESS_KEY + MIMECAST_SECRET_KEY)"
            )
        headers = self._build_headers(uri_path)
        url = f"{self._base_url().rstrip('/')}{uri_path}"
        try:
            resp = self._client.post(
                url,
                headers=headers,
                json=body if body is not None else {"data": []},
            )
        except httpx.HTTPError as exc:
            raise MimecastUnavailableError(
                f"Mimecast request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise MimecastUnavailableError(
                f"Mimecast rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 429:
            raise MimecastUnavailableError(
                "Mimecast rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise MimecastUnavailableError(
                f"Mimecast returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        if binary:
            # Threat-intel feed downloads return file bytes (csv/stix/misp).
            content_type = resp.headers.get("content-type", "application/octet-stream")
            return {
                "content_type": content_type,
                "content_length": len(resp.content),
                "content_b64": base64.b64encode(resp.content).decode("ascii"),
            }

        try:
            return resp.json()
        except ValueError as exc:
            raise MimecastUnavailableError(
                f"Mimecast returned non-JSON response: {exc}"
            ) from exc

    # ------------------------------------------------------------ endpoints

    def decode_url(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("/api/ttp/url/decode-url", body)

    def get_hold_message_list(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("/api/gateway/get-hold-message-list", body)

    def release_hold_message(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("/api/gateway/release-hold-message", body)

    def get_threat_intel_feed(self, body: Dict[str, Any]) -> Dict[str, Any]:
        # Feed downloads can be very large binaries; we return base64 envelope.
        return self._request(
            "/api/ttp/threat-intel/get-feed", body, binary=True
        )

    def get_siem_logs(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("/api/audit/get-siem-logs", body)

    def get_managed_senders(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("/api/managedsender/get-managed-senders", body)

    def get_anti_spoofing_policy(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("/api/policy/anti-spoofing/get-policy", body)

    # ------------------------------------------------------------ cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[MimecastEmailEngine] = None
_singleton_lock = threading.Lock()


def get_mimecast_email_engine(
    base_url: Optional[str] = None,
    app_id: Optional[str] = None,
    app_key: Optional[str] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> MimecastEmailEngine:
    """Return the process-wide MimecastEmailEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = MimecastEmailEngine(
                base_url=base_url,
                app_id=app_id,
                app_key=app_key,
                access_key=access_key,
                secret_key=secret_key,
                client=client,
            )
        return _singleton


def reset_mimecast_email_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "MimecastEmailEngine",
    "MimecastUnavailableError",
    "get_mimecast_email_engine",
    "reset_mimecast_email_engine",
]
