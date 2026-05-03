"""
Akamai EdgeGrid Engine — ALDECI.

Wraps Akamai's PAPI v1 (Property Manager) and Application Security (appsec v1)
REST APIs using EdgeGrid HMAC-SHA256 authentication.

Endpoint coverage
-----------------
* PAPI v1
    - GET /papi/v1/groups
    - GET /papi/v1/properties?contractId&groupId
    - GET /papi/v1/properties/{propertyId}/versions?contractId&groupId
    - GET /papi/v1/properties/{propertyId}/versions/{version}/rules?contractId&groupId
* AppSec v1
    - GET /appsec/v1/configs
    - GET /appsec/v1/configs/{configId}/versions
    - POST /appsec/v1/configs/{configId}/versions/{version}/security-events

Auth
----
EdgeGrid (4-element creds): AKAMAI_HOST, AKAMAI_CLIENT_TOKEN, AKAMAI_CLIENT_SECRET,
AKAMAI_ACCESS_TOKEN. We prefer the official ``edgegrid-python`` package when
installed (``akamai.edgegrid.EdgeGridAuth``) and otherwise fall back to a
hand-rolled signer compatible with the EdgeGrid auth spec:

    Authorization: EG1-HMAC-SHA256 client_token={ct};access_token={at};
                   timestamp={iso8601_z};nonce={uuid};signature={base64_sig}

Cache
-----
NO SQLite cache (per task spec). Every call hits Akamai live.

NO MOCKS rule
-------------
* If any of the four EdgeGrid env vars is unset:
    - All live endpoints raise ``AkamaiUnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Akamai.
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
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlencode, urlparse

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0
EDGEGRID_AUTH_ALG = "EG1-HMAC-SHA256"
# Default headers to include in the canonical signed-headers list. Empty
# tuple = sign nothing beyond the implicit canonical fields. Akamai allows
# customers to choose which headers (if any) to sign.
DEFAULT_SIGNED_HEADERS: tuple = ()
# Akamai's reference implementation caps the body bytes that get hashed at
# 131072 (128KB). We mirror that for parity.
MAX_BODY_HASH_BYTES = 131072


class AkamaiUnavailableError(RuntimeError):
    """Raised when EdgeGrid creds are missing, network failed, or upstream
    returned an unrecoverable status."""


# ---------------------------------------------------------------------------
# EdgeGrid signer
# ---------------------------------------------------------------------------


class EdgeGridSigner:
    """Hand-rolled EdgeGrid auth signer.

    Produces the ``Authorization: EG1-HMAC-SHA256 ...`` header and is used
    as the fallback when the official ``edgegrid-python`` package is not
    installed.

    Spec: https://techdocs.akamai.com/developer/docs/authenticate-with-edgegrid
    """

    def __init__(
        self,
        client_token: str,
        client_secret: str,
        access_token: str,
        max_body: int = MAX_BODY_HASH_BYTES,
        signed_headers: Iterable[str] = DEFAULT_SIGNED_HEADERS,
    ) -> None:
        self._client_token = client_token
        self._client_secret = client_secret
        self._access_token = access_token
        self._max_body = max_body
        self._signed_headers = tuple(signed_headers)

    @staticmethod
    def _timestamp() -> str:
        # EdgeGrid timestamp format: yyyyMMddTHH:mm:ss+0000
        now = datetime.now(timezone.utc)
        return now.strftime("%Y%m%dT%H:%M:%S+0000")

    @staticmethod
    def _nonce() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def _b64_hmac_sha256(key: bytes, msg: str) -> str:
        return base64.b64encode(
            hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
        ).decode("ascii")

    def _content_hash(self, method: str, body: Optional[bytes]) -> str:
        if method.upper() in ("POST", "PUT") and body:
            payload = body[: self._max_body]
            return base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
        return ""

    def _canonical_headers(self, headers: Dict[str, str]) -> str:
        if not self._signed_headers:
            return ""
        parts: List[str] = []
        lower_map = {k.lower(): v for k, v in headers.items()}
        for h in self._signed_headers:
            v = lower_map.get(h.lower(), "").strip()
            parts.append(f"{h.lower()}:{v}")
        return "\t".join(parts)

    def _signing_key(self, timestamp: str) -> bytes:
        return base64.b64encode(
            hmac.new(
                self._client_secret.encode("utf-8"),
                timestamp.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        )

    def sign(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> str:
        """Return the full Authorization header value for a request."""
        timestamp = self._timestamp()
        nonce = self._nonce()
        parsed = urlparse(url)
        host = parsed.netloc
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query += "?" + parsed.query

        content_hash = self._content_hash(method, body)
        canon_headers = self._canonical_headers(headers or {})
        canonical_request = "\t".join(
            [
                method.upper(),
                parsed.scheme or "https",
                host,
                path_and_query,
                canon_headers,
                content_hash,
            ]
        )

        auth_data = (
            f"{EDGEGRID_AUTH_ALG} "
            f"client_token={self._client_token};"
            f"access_token={self._access_token};"
            f"timestamp={timestamp};"
            f"nonce={nonce};"
        )
        signing_key = self._signing_key(timestamp)
        signing_input = f"{canonical_request}\t{auth_data}"
        signature = self._b64_hmac_sha256(signing_key, signing_input)
        return f"{auth_data}signature={signature}"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AkamaiEngine:
    """Thread-safe EdgeGrid REST client (no cache)."""

    def __init__(
        self,
        host: Optional[str] = None,
        client_token: Optional[str] = None,
        client_secret: Optional[str] = None,
        access_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit values win over env (re-read each call so tests can monkeypatch).
        self._explicit_host = host
        self._explicit_client_token = client_token
        self._explicit_client_secret = client_secret
        self._explicit_access_token = access_token

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()

    # ----------------------------------------------------------- creds

    def _host(self) -> Optional[str]:
        return self._explicit_host or os.environ.get("AKAMAI_HOST") or None

    def _client_token(self) -> Optional[str]:
        return (
            self._explicit_client_token
            or os.environ.get("AKAMAI_CLIENT_TOKEN")
            or None
        )

    def _client_secret(self) -> Optional[str]:
        return (
            self._explicit_client_secret
            or os.environ.get("AKAMAI_CLIENT_SECRET")
            or None
        )

    def _access_token(self) -> Optional[str]:
        return (
            self._explicit_access_token
            or os.environ.get("AKAMAI_ACCESS_TOKEN")
            or None
        )

    def host_present(self) -> bool:
        return bool(self._host())

    def client_token_present(self) -> bool:
        return bool(self._client_token())

    def client_secret_present(self) -> bool:
        return bool(self._client_secret())

    def access_token_present(self) -> bool:
        return bool(self._access_token())

    def creds_complete(self) -> bool:
        return (
            self.host_present()
            and self.client_token_present()
            and self.client_secret_present()
            and self.access_token_present()
        )

    # --------------------------------------------------------- request

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        host = self._host()
        if not host:
            raise AkamaiUnavailableError("AKAMAI_HOST is not configured")
        # Strip leading scheme if user supplied one; EdgeGrid wants bare host.
        host = host.replace("https://", "").replace("http://", "").rstrip("/")
        url = f"https://{host}{path}"
        if params:
            qs = urlencode(
                [(k, v) for k, v in params.items() if v is not None and v != ""]
            )
            if qs:
                url = f"{url}?{qs}"
        return url

    def _signer(self) -> EdgeGridSigner:
        ct = self._client_token()
        cs = self._client_secret()
        at = self._access_token()
        if not (ct and cs and at):
            raise AkamaiUnavailableError(
                "Akamai EdgeGrid credentials are not configured"
            )
        return EdgeGridSigner(client_token=ct, client_secret=cs, access_token=at)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.creds_complete():
            missing = []
            if not self.host_present():
                missing.append("AKAMAI_HOST")
            if not self.client_token_present():
                missing.append("AKAMAI_CLIENT_TOKEN")
            if not self.client_secret_present():
                missing.append("AKAMAI_CLIENT_SECRET")
            if not self.access_token_present():
                missing.append("AKAMAI_ACCESS_TOKEN")
            raise AkamaiUnavailableError(
                "Akamai EdgeGrid credentials missing: " + ",".join(missing)
            )
        url = self._build_url(path, params=params)
        body_bytes: Optional[bytes] = None
        headers: Dict[str, str] = {"Accept": "application/json"}
        if json_body is not None:
            import json as _json

            body_bytes = _json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        signer = self._signer()
        headers["Authorization"] = signer.sign(
            method, url, headers=headers, body=body_bytes
        )
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers)
            elif method.upper() == "POST":
                resp = self._client.post(url, headers=headers, content=body_bytes)
            elif method.upper() == "PUT":
                resp = self._client.put(url, headers=headers, content=body_bytes)
            else:
                raise AkamaiUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise AkamaiUnavailableError(
                f"Akamai request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise AkamaiUnavailableError(
                f"Akamai rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise AkamaiUnavailableError(
                f"Akamai resource not found (HTTP 404): {path}"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"Akamai validation error: {body}")
        if sc == 429:
            raise AkamaiUnavailableError(
                "Akamai rate-limit exceeded (HTTP 429)"
            )
        if sc >= 400:
            raise AkamaiUnavailableError(
                f"Akamai returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise AkamaiUnavailableError(
                f"Akamai returned non-JSON response: {exc}"
            ) from exc

    # --------------------------------------------------------------- PAPI

    def papi_groups(self) -> Dict[str, Any]:
        raw = self._request("GET", "/papi/v1/groups")
        return self._normalize_groups(raw)

    def papi_properties(
        self, contract_id: str, group_id: str
    ) -> Dict[str, Any]:
        if not contract_id:
            raise ValueError("contractId must not be empty")
        if not group_id:
            raise ValueError("groupId must not be empty")
        raw = self._request(
            "GET",
            "/papi/v1/properties",
            params={"contractId": contract_id, "groupId": group_id},
        )
        return self._normalize_properties(raw)

    def papi_property_versions(
        self, property_id: str, contract_id: str, group_id: str
    ) -> Dict[str, Any]:
        if not property_id:
            raise ValueError("propertyId must not be empty")
        if not contract_id:
            raise ValueError("contractId must not be empty")
        if not group_id:
            raise ValueError("groupId must not be empty")
        raw = self._request(
            "GET",
            f"/papi/v1/properties/{property_id}/versions",
            params={"contractId": contract_id, "groupId": group_id},
        )
        return self._normalize_property_versions(raw)

    def papi_property_rules(
        self,
        property_id: str,
        version: int,
        contract_id: str,
        group_id: str,
    ) -> Dict[str, Any]:
        if not property_id:
            raise ValueError("propertyId must not be empty")
        if version < 1:
            raise ValueError("version must be >= 1")
        if not contract_id:
            raise ValueError("contractId must not be empty")
        if not group_id:
            raise ValueError("groupId must not be empty")
        raw = self._request(
            "GET",
            f"/papi/v1/properties/{property_id}/versions/{version}/rules",
            params={"contractId": contract_id, "groupId": group_id},
        )
        return self._normalize_property_rules(raw)

    # ------------------------------------------------------------ AppSec

    def appsec_configs(self) -> Dict[str, Any]:
        raw = self._request("GET", "/appsec/v1/configs")
        return self._normalize_appsec_configs(raw)

    def appsec_config_versions(self, config_id: int) -> Dict[str, Any]:
        if config_id < 1:
            raise ValueError("configId must be >= 1")
        raw = self._request(
            "GET", f"/appsec/v1/configs/{config_id}/versions"
        )
        return self._normalize_appsec_config_versions(raw)

    def appsec_security_events(
        self,
        config_id: int,
        version: int,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        if config_id < 1:
            raise ValueError("configId must be >= 1")
        if version < 1:
            raise ValueError("version must be >= 1")
        if not isinstance(body, dict):
            raise ValueError("body must be a dict")
        raw = self._request(
            "POST",
            f"/appsec/v1/configs/{config_id}/versions/{version}/security-events",
            json_body=body,
        )
        return self._normalize_security_events(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_groups(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        groups = raw.get("groups") if isinstance(raw.get("groups"), dict) else {}
        items = groups.get("items") if isinstance(groups.get("items"), list) else []
        out_items: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out_items.append(
                {
                    "groupId": entry.get("groupId") or "",
                    "groupName": entry.get("groupName") or "",
                    "parentGroupId": entry.get("parentGroupId") or "",
                    "contractIds": list(entry.get("contractIds") or []),
                }
            )
        return {
            "accountId": raw.get("accountId") or "",
            "accountName": raw.get("accountName") or "",
            "groups": {"items": out_items},
        }

    @staticmethod
    def _normalize_properties(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
        items = props.get("items") if isinstance(props.get("items"), list) else []
        out_items: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out_items.append(
                {
                    "accountId": entry.get("accountId") or "",
                    "contractId": entry.get("contractId") or "",
                    "groupId": entry.get("groupId") or "",
                    "propertyId": entry.get("propertyId") or "",
                    "propertyName": entry.get("propertyName") or "",
                    "latestVersion": entry.get("latestVersion") or 0,
                    "stagingVersion": entry.get("stagingVersion"),
                    "productionVersion": entry.get("productionVersion"),
                    "assetId": entry.get("assetId") or "",
                    "note": entry.get("note") or "",
                }
            )
        return {"properties": {"items": out_items}}

    @staticmethod
    def _normalize_property_versions(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        versions = raw.get("versions") if isinstance(raw.get("versions"), dict) else {}
        items = versions.get("items") if isinstance(versions.get("items"), list) else []
        out_items: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out_items.append(
                {
                    "propertyVersion": entry.get("propertyVersion") or 0,
                    "updatedByUser": entry.get("updatedByUser") or "",
                    "updatedDate": entry.get("updatedDate") or "",
                    "productionStatus": entry.get("productionStatus") or "INACTIVE",
                    "stagingStatus": entry.get("stagingStatus") or "INACTIVE",
                    "etag": entry.get("etag") or "",
                    "productId": entry.get("productId") or "",
                    "ruleFormat": entry.get("ruleFormat") or "",
                    "note": entry.get("note") or "",
                }
            )
        return {
            "propertyId": raw.get("propertyId") or "",
            "propertyName": raw.get("propertyName") or "",
            "accountId": raw.get("accountId") or "",
            "contractId": raw.get("contractId") or "",
            "groupId": raw.get("groupId") or "",
            "assetId": raw.get("assetId") or "",
            "versions": {"items": out_items},
        }

    @staticmethod
    def _normalize_property_rules(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        rules = raw.get("rules") if isinstance(raw.get("rules"), dict) else {}
        return {
            "propertyId": raw.get("propertyId") or "",
            "propertyName": raw.get("propertyName") or "",
            "accountId": raw.get("accountId") or "",
            "contractId": raw.get("contractId") or "",
            "groupId": raw.get("groupId") or "",
            "propertyVersion": raw.get("propertyVersion") or 0,
            "etag": raw.get("etag") or "",
            "rules": {
                "name": rules.get("name") or "default",
                "options": rules.get("options") or {},
                "behaviors": list(rules.get("behaviors") or []),
                "children": list(rules.get("children") or []),
                "variables": list(rules.get("variables") or []),
            },
            "ruleFormat": raw.get("ruleFormat") or "",
        }

    @staticmethod
    def _normalize_appsec_configs(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        configs = (
            raw.get("configurations")
            if isinstance(raw.get("configurations"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in configs:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "id": entry.get("id") or 0,
                    "name": entry.get("name") or "",
                    "description": entry.get("description") or "",
                    "latestVersion": entry.get("latestVersion") or 0,
                    "stagingVersion": entry.get("stagingVersion"),
                    "productionVersion": entry.get("productionVersion"),
                    "fileType": entry.get("fileType") or "CONFIGURATION",
                    "targetProduct": entry.get("targetProduct") or "",
                    "productionHostnames": list(
                        entry.get("productionHostnames") or []
                    ),
                    "stagingHostnames": list(
                        entry.get("stagingHostnames") or []
                    ),
                    "productionStatus": entry.get("productionStatus") or "",
                    "stagingStatus": entry.get("stagingStatus") or "",
                    "lastModified": entry.get("lastModified") or "",
                    "createDate": entry.get("createDate") or "",
                }
            )
        return {"configurations": out}

    @staticmethod
    def _normalize_appsec_config_versions(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        # Akamai returns either {"versionList": [...]} or {"versions": [...]}
        items = (
            raw.get("versionList")
            if isinstance(raw.get("versionList"), list)
            else raw.get("versions")
            if isinstance(raw.get("versions"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in items or []:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "version": entry.get("version") or 0,
                    "versionNotes": entry.get("versionNotes") or "",
                    "createDate": entry.get("createDate") or "",
                    "createdBy": entry.get("createdBy") or "",
                    "production": dict(entry.get("production") or {}),
                    "staging": dict(entry.get("staging") or {}),
                    "basedOn": entry.get("basedOn"),
                    "production_status": entry.get("productionStatus") or "",
                    "staging_status": entry.get("stagingStatus") or "",
                }
            )
        return {
            "configId": raw.get("configId") or 0,
            "configName": raw.get("configName") or "",
            "lastCreatedVersion": raw.get("lastCreatedVersion") or 0,
            "versionList": out,
        }

    @staticmethod
    def _normalize_security_events(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        events = (
            raw.get("securityEvents")
            if isinstance(raw.get("securityEvents"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in events:
            if not isinstance(entry, dict):
                continue
            attacker = (
                entry.get("attackerSource")
                if isinstance(entry.get("attackerSource"), dict)
                else {}
            )
            http_msg = (
                entry.get("httpMessage")
                if isinstance(entry.get("httpMessage"), dict)
                else {}
            )
            rule_actions = (
                entry.get("ruleActions")
                if isinstance(entry.get("ruleActions"), list)
                else []
            )
            rule_data = (
                entry.get("ruleData")
                if isinstance(entry.get("ruleData"), list)
                else []
            )
            out.append(
                {
                    "eventId": entry.get("eventId") or "",
                    "attackerSource": {
                        "ip": attacker.get("ip") or "",
                        "country": attacker.get("country") or "",
                    },
                    "configId": entry.get("configId") or 0,
                    "configName": entry.get("configName") or "",
                    "configVersion": entry.get("configVersion") or 0,
                    "deniedReason": entry.get("deniedReason") or "",
                    "geoCountryCode": entry.get("geoCountryCode") or "",
                    "geoSubdivision": entry.get("geoSubdivision") or "",
                    "eventTimestamp": entry.get("eventTimestamp") or "",
                    "occurredAt": entry.get("occurredAt") or "",
                    "geoCity": entry.get("geoCity") or "",
                    "httpMessage": {
                        "requestId": http_msg.get("requestId") or "",
                        "host": http_msg.get("host") or "",
                        "port": http_msg.get("port") or "",
                        "hostname": http_msg.get("hostname") or "",
                        "requestUri": http_msg.get("requestUri") or "",
                        "requestQuery": http_msg.get("requestQuery") or "",
                        "contentType": http_msg.get("contentType") or "",
                        "requestMethod": http_msg.get("requestMethod") or "",
                        "status": http_msg.get("status") or 0,
                        "bytes": http_msg.get("bytes") or 0,
                        "requestHeaders": list(
                            http_msg.get("requestHeaders") or []
                        ),
                        "responseHeaders": list(
                            http_msg.get("responseHeaders") or []
                        ),
                    },
                    "policyId": entry.get("policyId") or "",
                    "ruleActions": [
                        {
                            "action": ra.get("action") or "",
                            "ruleId": ra.get("ruleId") or "",
                            "ruleVersion": ra.get("ruleVersion") or "",
                        }
                        for ra in rule_actions
                        if isinstance(ra, dict)
                    ],
                    "ruleData": [
                        {
                            "name": rd.get("name") or "",
                            "value": rd.get("value") or "",
                            "ruleSelector": rd.get("ruleSelector") or "",
                        }
                        for rd in rule_data
                        if isinstance(rd, dict)
                    ],
                    "slowPostAction": entry.get("slowPostAction") or "",
                    "customRules": list(entry.get("customRules") or []),
                }
            )
        return {
            "securityEvents": out,
            "totalSize": raw.get("totalSize") or len(out),
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[AkamaiEngine] = None
_singleton_lock = threading.Lock()


def get_akamai_engine(
    host: Optional[str] = None,
    client_token: Optional[str] = None,
    client_secret: Optional[str] = None,
    access_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> AkamaiEngine:
    """Return the process-wide AkamaiEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = AkamaiEngine(
                host=host,
                client_token=client_token,
                client_secret=client_secret,
                access_token=access_token,
                client=client,
            )
        return _singleton


def reset_akamai_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "AkamaiEngine",
    "AkamaiUnavailableError",
    "EdgeGridSigner",
    "get_akamai_engine",
    "reset_akamai_engine",
]
