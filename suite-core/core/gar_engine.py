"""ALDECI Google Artifact Registry (GAR) Engine.

Thin pass-through client for the **Google Artifact Registry v1 REST API** —
project locations, repositories, packages, versions, docker images, files, and
IAM policy introspection. Designed for direct registry introspection from
ALDECI personas (DevSecOps, container-platform owner, supply-chain auditor,
SBOM/provenance gatekeeper).

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required ``GOOGLE_APPLICATION_CREDENTIALS`` env var is unset (or the file is
unreadable / invalid) the engine reports ``status="unavailable"`` and lookup
endpoints return HTTP 503.

Authentication is performed via the OAuth2 **JWT-bearer flow** against
``oauth2.googleapis.com`` — the credentials JSON is loaded from disk, a JWT is
signed with the service-account private key (RS256), exchanged for an access
token scoped to ``https://www.googleapis.com/auth/cloud-platform``, and cached
in-memory until ~60s before expiry.

Environment variables
---------------------
GOOGLE_APPLICATION_CREDENTIALS — path to a service-account JSON keyfile
                                  (``type``, ``client_email``, ``private_key``,
                                  ``token_uri`` are required).

The engine is a process-level singleton accessible via :func:`get_gar_engine`.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/v1/projects/{p}/locations",
    "/v1/projects/{p}/locations/{loc}/repositories",
    "/v1/projects/{p}/locations/{loc}/repositories/{repo}/packages",
    "/v1/projects/{p}/locations/{loc}/repositories/{repo}/packages/{pkg}/versions",
    "/v1/projects/{p}/locations/{loc}/repositories/{repo}/dockerImages",
]

_DEFAULT_BASE = "https://artifactregistry.googleapis.com"
_DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token"
_DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_TOKEN_TTL_SAFETY_S = 60  # refresh 60s before expiry


class GARUnavailable(RuntimeError):
    """Raised when GOOGLE_APPLICATION_CREDENTIALS is unset / unreadable / invalid."""


class GARHTTPError(RuntimeError):
    """Raised when GAR returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (401/403/404/409/422/429 surfaced verbatim, everything else
    collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


def _b64url(data: bytes) -> str:
    """Base64-url encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class GAREngine:
    """Pass-through GAR v1 client backed by ``httpx.Client`` + JWT-bearer auth."""

    def __init__(
        self,
        credentials_path: Optional[str] = None,
        base_url: str = _DEFAULT_BASE,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
        scope: str = _DEFAULT_SCOPE,
    ) -> None:
        self._credentials_path = (
            credentials_path
            if credentials_path is not None
            else os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
        ).strip()
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._scope = scope
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        # Lazy-loaded cred fields
        self._creds: Optional[Dict[str, Any]] = None
        self._creds_load_attempted = False
        # Cached access token
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._token_lock = Lock()

    # ------------------------------------------------------------------ status

    @property
    def google_app_creds_present(self) -> bool:
        return bool(self._credentials_path)

    def _try_load_creds(self) -> None:
        """Attempt to read + parse the keyfile; cache result. Idempotent."""
        if self._creds_load_attempted:
            return
        self._creds_load_attempted = True
        if not self._credentials_path:
            return
        try:
            with open(self._credentials_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError) as exc:
            logger.warning(
                "GAR credentials file unreadable or invalid (%s): %s",
                self._credentials_path,
                type(exc).__name__,
            )
            return
        required = {"client_email", "private_key", "token_uri"}
        if not isinstance(raw, dict) or not required.issubset(raw.keys()):
            logger.warning(
                "GAR credentials JSON missing required fields: %s",
                sorted(required - set(raw.keys() if isinstance(raw, dict) else [])),
            )
            return
        self._creds = raw

    @property
    def configured(self) -> bool:
        self._try_load_creds()
        return self._creds is not None

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Google Artifact Registry",
            "endpoints": list(_ENDPOINT_CATALOG),
            "google_app_creds_present": self.google_app_creds_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ auth

    def _require_configured(self) -> None:
        if not self.configured:
            raise GARUnavailable(
                "GOOGLE_APPLICATION_CREDENTIALS must be set (and point to a "
                "valid service-account JSON keyfile) to call GAR endpoints"
            )

    def _sign_jwt(self) -> str:
        """Sign a JWT-bearer assertion with the service-account RSA private key."""
        assert self._creds is not None  # _require_configured guarantees
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": self._creds["client_email"],
            "scope": self._scope,
            "aud": self._creds.get("token_uri", _DEFAULT_TOKEN_URI),
            "iat": now,
            "exp": now + 3600,
        }
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
            + "."
            + _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        )
        # Sign with RS256 — try cryptography (preferred), fall back to a clear error
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError as exc:  # pragma: no cover - cryptography is a hard dep
            raise GARHTTPError(
                500,
                "cryptography package is required to sign GAR JWT-bearer assertions",
            ) from exc

        private_key_pem = self._creds["private_key"].encode("utf-8")
        try:
            key = serialization.load_pem_private_key(private_key_pem, password=None)
        except Exception as exc:  # noqa: BLE001 - any pem error is fatal here
            raise GARHTTPError(
                500, f"GAR private key is not a valid PEM RSA key: {type(exc).__name__}"
            ) from exc
        signature = key.sign(
            signing_input.encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return signing_input + "." + _b64url(signature)

    def _exchange_jwt_for_token(self, assertion: str) -> Dict[str, Any]:
        token_uri = (self._creds or {}).get("token_uri", _DEFAULT_TOKEN_URI)
        try:
            resp = self._client.request(
                "POST",
                token_uri,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise GARHTTPError(
                502,
                f"OAuth2 token exchange failed: {type(exc).__name__}",
            ) from exc
        if 200 <= resp.status_code < 300:
            try:
                return resp.json()
            except ValueError as exc:
                raise GARHTTPError(
                    502, "OAuth2 token exchange returned non-JSON body"
                ) from exc
        # Surface upstream error
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise GARHTTPError(
            resp.status_code,
            f"OAuth2 token exchange returned {resp.status_code}",
            payload,
        )

    def _get_access_token(self) -> str:
        """Return a cached or freshly-minted OAuth2 access token."""
        self._require_configured()
        with self._token_lock:
            now = time.time()
            if (
                self._access_token
                and self._token_expires_at - _TOKEN_TTL_SAFETY_S > now
            ):
                return self._access_token
            assertion = self._sign_jwt()
            body = self._exchange_jwt_for_token(assertion)
            tok = body.get("access_token")
            if not isinstance(tok, str) or not tok:
                raise GARHTTPError(
                    502, "OAuth2 token exchange did not return an access_token"
                )
            ttl = int(body.get("expires_in", 3600))
            self._access_token = tok
            self._token_expires_at = now + ttl
            return tok

    # ------------------------------------------------------------------ http

    def _url(self, path: str) -> str:
        return self._base_url + "/" + path.lstrip("/")

    def _headers(self) -> Dict[str, str]:
        token = self._get_access_token()
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        self._require_configured()
        headers = self._headers()
        url = self._url(path)
        try:
            resp = self._client.request(
                method,
                url,
                params=params,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "GAR upstream error %s %s: %s", method, path, type(exc).__name__
            )
            raise GARHTTPError(
                502, f"Upstream GAR request failed: {type(exc).__name__}"
            ) from exc

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        # Non-2xx: surface upstream payload when JSON
        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise GARHTTPError(
            resp.status_code, f"GAR returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ ops

    @staticmethod
    def _q(value: str) -> str:
        return quote(value, safe="")

    @staticmethod
    def _qpath(value: str) -> str:
        """Quote a path-style identifier — `/` allowed (repo, package, version names)."""
        return quote(value, safe="/")

    def _paged_params(
        self,
        *,
        page_size: Optional[int],
        page_token: Optional[str],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        if extra:
            for k, v in extra.items():
                if v is not None:
                    params[k] = v
        return params

    def list_locations(self, project: str) -> Dict[str, Any]:
        body = (
            self._request("GET", f"v1/projects/{self._q(project)}/locations") or {}
        )
        if isinstance(body, dict):
            return body
        return {"locations": body if isinstance(body, list) else []}

    def list_repositories(
        self,
        project: str,
        location: str,
        *,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._paged_params(page_size=page_size, page_token=page_token)
        body = (
            self._request(
                "GET",
                f"v1/projects/{self._q(project)}/locations/{self._q(location)}/repositories",
                params=params,
            )
            or {}
        )
        return body if isinstance(body, dict) else {}

    def list_packages(
        self,
        project: str,
        location: str,
        repository: str,
        *,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        filter_: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._paged_params(
            page_size=page_size,
            page_token=page_token,
            extra={"filter": filter_, "orderBy": order_by},
        )
        body = (
            self._request(
                "GET",
                f"v1/projects/{self._q(project)}/locations/{self._q(location)}"
                f"/repositories/{self._qpath(repository)}/packages",
                params=params,
            )
            or {}
        )
        return body if isinstance(body, dict) else {}

    def list_versions(
        self,
        project: str,
        location: str,
        repository: str,
        package: str,
        *,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        view: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._paged_params(
            page_size=page_size,
            page_token=page_token,
            extra={"view": view, "orderBy": order_by},
        )
        body = (
            self._request(
                "GET",
                f"v1/projects/{self._q(project)}/locations/{self._q(location)}"
                f"/repositories/{self._qpath(repository)}/packages/{self._qpath(package)}/versions",
                params=params,
            )
            or {}
        )
        return body if isinstance(body, dict) else {}

    def list_docker_images(
        self,
        project: str,
        location: str,
        repository: str,
        *,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        order_by: Optional[str] = None,
        filter_: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._paged_params(
            page_size=page_size,
            page_token=page_token,
            extra={"orderBy": order_by, "filter": filter_},
        )
        body = (
            self._request(
                "GET",
                f"v1/projects/{self._q(project)}/locations/{self._q(location)}"
                f"/repositories/{self._qpath(repository)}/dockerImages",
                params=params,
            )
            or {}
        )
        return body if isinstance(body, dict) else {}

    def get_iam_policy(
        self,
        project: str,
        location: str,
        repository: str,
        *,
        requested_policy_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if requested_policy_version is not None:
            params["options.requestedPolicyVersion"] = requested_policy_version
        body = (
            self._request(
                "GET",
                f"v1/projects/{self._q(project)}/locations/{self._q(location)}"
                f"/repositories/{self._qpath(repository)}:getIamPolicy",
                params=params or None,
            )
            or {}
        )
        return body if isinstance(body, dict) else {}

    def list_files(
        self,
        project: str,
        location: str,
        repository: str,
        *,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        filter_: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._paged_params(
            page_size=page_size,
            page_token=page_token,
            extra={"filter": filter_, "orderBy": order_by},
        )
        body = (
            self._request(
                "GET",
                f"v1/projects/{self._q(project)}/locations/{self._q(location)}"
                f"/repositories/{self._qpath(repository)}/files",
                params=params,
            )
            or {}
        )
        return body if isinstance(body, dict) else {}

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:  # pragma: no cover - defensive
                pass


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[GAREngine] = None
_engine_lock = Lock()


def get_gar_engine() -> GAREngine:
    """Return (or create) the process-wide GAREngine singleton.

    Picks up ``GOOGLE_APPLICATION_CREDENTIALS`` lazily from the environment so
    tests that monkeypatch env vars before first call get a fresh, env-aligned
    engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = GAREngine()
    return _engine


def reset_gar_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
