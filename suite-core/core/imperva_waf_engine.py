"""
Imperva Cloud WAF Engine — ALDECI.

Wraps the two Imperva REST API surfaces:

  1. Legacy Provisioning v1 / Incidents v1 (https://my.imperva.com)
     - POST /api/prov/v1/sites/list                     (form-encoded; api_id+api_key in body)
     - POST /api/prov/v1/sites/status                   (form-encoded; api_id+api_key in body)
     - POST /api/prov/v1/sites/configure/security       (form-encoded; api_id+api_key in body)
     - GET  /api/incidents/v1/incidents                 (form-encoded auth in body for Imperva
                                                         legacy; for /incidents we pass
                                                         credentials as headers x-API-Id / x-API-Key
                                                         which Imperva also accepts on this surface)

  2. Modern Cloud Application Security v3 (https://api.imperva.com)
     - GET  /policies/v3/policies?accountId=...         (headers x-API-Id + x-API-Key)
     - GET  /sites/v3/sites/{site_id}                   (headers x-API-Id + x-API-Key)

Credentials are read fresh from env each call so tests can monkeypatch:
  * IMPERVA_API_ID
  * IMPERVA_API_KEY

NO MOCKS rule
-------------
* When credentials are unset every live endpoint raises ImpervaUnavailableError
  (the router translates to HTTP 503).
* Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response is shaped from the real upstream body.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

LEGACY_BASE = "https://my.imperva.com"
MODERN_BASE = "https://api.imperva.com"
DEFAULT_TIMEOUT_SECONDS = 8.0


class ImpervaUnavailableError(RuntimeError):
    """Raised when Imperva credentials are missing, network failed,
    or upstream returned an unrecoverable status."""


class ImpervaWAFEngine:
    """Thread-safe Imperva Cloud WAF REST client (legacy v1 + modern v3)."""

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

    # ----------------------------------------------------------- creds

    def _api_id(self) -> Optional[str]:
        if self._explicit_api_id:
            return self._explicit_api_id
        v = os.environ.get("IMPERVA_API_ID")
        return v or None

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("IMPERVA_API_KEY")
        return v or None

    def api_id_present(self) -> bool:
        return bool(self._api_id())

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def credentials_present(self) -> bool:
        return self.api_id_present() and self.api_key_present()

    # --------------------------------------------------------- transport

    def _post_legacy(
        self,
        path: str,
        *,
        data: Dict[str, Any],
        api_id: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST to legacy https://my.imperva.com — credentials in form body."""
        eff_id = api_id or self._api_id()
        eff_key = api_key or self._api_key()
        if not eff_id or not eff_key:
            raise ImpervaUnavailableError(
                "IMPERVA_API_ID / IMPERVA_API_KEY are not configured"
            )
        body = {
            "api_id": eff_id,
            "api_key": eff_key,
            **{k: v for k, v in (data or {}).items() if v is not None and v != ""},
        }
        url = f"{LEGACY_BASE}{path}"
        try:
            resp = self._client.post(
                url,
                data=body,
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ImpervaUnavailableError(
                f"Imperva legacy request failed: {exc}"
            ) from exc
        return self._handle_response(resp)

    def _get_modern(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """GET against https://api.imperva.com using x-API-Id / x-API-Key headers."""
        eff_id = self._api_id()
        eff_key = self._api_key()
        if not eff_id or not eff_key:
            raise ImpervaUnavailableError(
                "IMPERVA_API_ID / IMPERVA_API_KEY are not configured"
            )
        url = f"{MODERN_BASE}{path}"
        headers = {
            "Accept": "application/json",
            "x-API-Id": eff_id,
            "x-API-Key": eff_key,
        }
        try:
            resp = self._client.get(url, headers=headers, params=params or {})
        except httpx.HTTPError as exc:
            raise ImpervaUnavailableError(
                f"Imperva modern request failed: {exc}"
            ) from exc
        return self._handle_response(resp)

    def _get_legacy(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """GET against https://my.imperva.com using x-API-Id / x-API-Key headers
        (used for /api/incidents/v1/incidents)."""
        eff_id = self._api_id()
        eff_key = self._api_key()
        if not eff_id or not eff_key:
            raise ImpervaUnavailableError(
                "IMPERVA_API_ID / IMPERVA_API_KEY are not configured"
            )
        url = f"{LEGACY_BASE}{path}"
        headers = {
            "Accept": "application/json",
            "x-API-Id": eff_id,
            "x-API-Key": eff_key,
        }
        try:
            resp = self._client.get(url, headers=headers, params=params or {})
        except httpx.HTTPError as exc:
            raise ImpervaUnavailableError(
                f"Imperva incidents request failed: {exc}"
            ) from exc
        return self._handle_response(resp)

    @staticmethod
    def _handle_response(resp: Any) -> Dict[str, Any]:
        status_code = getattr(resp, "status_code", 0)
        text = getattr(resp, "text", "") or ""
        if status_code in (401, 403):
            raise ImpervaUnavailableError(
                f"Imperva rejected credentials (HTTP {status_code})"
            )
        if status_code == 422:
            try:
                body = resp.json()
            except Exception:
                body = {"error": text[:200]}
            raise ValueError(f"Imperva validation error: {body}")
        if status_code == 429:
            raise ImpervaUnavailableError(
                "Imperva rate-limit exceeded (HTTP 429)"
            )
        if status_code >= 400:
            raise ImpervaUnavailableError(
                f"Imperva returned HTTP {status_code}: {text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise ImpervaUnavailableError(
                f"Imperva returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- legacy

    def sites_list(
        self,
        api_id: Optional[str] = None,
        api_key: Optional[str] = None,
        account_id: Optional[str] = None,
        page_size: Optional[int] = None,
        page_num: Optional[int] = None,
    ) -> Dict[str, Any]:
        """POST /api/prov/v1/sites/list — list managed sites."""
        data: Dict[str, Any] = {}
        if account_id:
            data["account_id"] = str(account_id)
        if page_size is not None:
            data["page_size"] = str(int(page_size))
        if page_num is not None:
            data["page_num"] = str(int(page_num))
        raw = self._post_legacy(
            "/api/prov/v1/sites/list",
            data=data,
            api_id=api_id,
            api_key=api_key,
        )
        return self._normalize_sites_list(raw)

    def sites_status(
        self,
        site_id: str,
        api_id: Optional[str] = None,
        api_key: Optional[str] = None,
        tests: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """POST /api/prov/v1/sites/status — get one site's full status."""
        if not site_id:
            raise ValueError("site_id must not be empty")
        data: Dict[str, Any] = {"site_id": str(site_id)}
        if tests:
            data["tests"] = ",".join(tests)
        raw = self._post_legacy(
            "/api/prov/v1/sites/status",
            data=data,
            api_id=api_id,
            api_key=api_key,
        )
        return self._normalize_site_status(raw)

    def sites_configure_security(
        self,
        site_id: str,
        rule_id: str,
        security_rule_action: str,
        api_id: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/prov/v1/sites/configure/security — change a WAF rule action."""
        if not site_id:
            raise ValueError("site_id must not be empty")
        if not rule_id:
            raise ValueError("rule_id must not be empty")
        if not security_rule_action:
            raise ValueError("security_rule_action must not be empty")
        data: Dict[str, Any] = {
            "site_id": str(site_id),
            "rule_id": str(rule_id),
            "security_rule_action": str(security_rule_action),
        }
        raw = self._post_legacy(
            "/api/prov/v1/sites/configure/security",
            data=data,
            api_id=api_id,
            api_key=api_key,
        )
        return self._normalize_simple_res(raw)

    # ----------------------------------------------------------- modern v3

    def list_policies(self, account_id: str) -> Dict[str, Any]:
        """GET /policies/v3/policies?accountId=... — list policies for account."""
        if not account_id:
            raise ValueError("accountId must not be empty")
        raw = self._get_modern(
            "/policies/v3/policies",
            params={"accountId": str(account_id)},
        )
        return self._normalize_policies(raw)

    def get_site(self, site_id: str) -> Dict[str, Any]:
        """GET /sites/v3/sites/{site_id} — modern site detail."""
        if not site_id:
            raise ValueError("site_id must not be empty")
        raw = self._get_modern(f"/sites/v3/sites/{site_id}")
        return self._normalize_site_v3(raw)

    # ----------------------------------------------------------- incidents

    def list_incidents(
        self,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        account_id: Optional[str] = None,
        page_size: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """GET /api/incidents/v1/incidents — list customer incidents."""
        params: Dict[str, Any] = {}
        if from_time:
            params["from_time"] = from_time
        if to_time:
            params["to_time"] = to_time
        if account_id:
            params["accountId"] = str(account_id)
        if page_size is not None:
            params["pageSize"] = str(int(page_size))
        if offset is not None:
            params["offset"] = str(int(offset))
        raw = self._get_legacy("/api/incidents/v1/incidents", params=params)
        return self._normalize_incidents(raw)

    # ----------------------------------------------------------- normalize

    @staticmethod
    def _normalize_sites_list(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        sites_in = raw.get("sites") if isinstance(raw.get("sites"), list) else []
        sites_out: List[Dict[str, Any]] = []
        for s in sites_in:
            if not isinstance(s, dict):
                continue
            sites_out.append(ImpervaWAFEngine._site_shape(s))
        return {
            "res": int(raw.get("res") or 0),
            "res_message": raw.get("res_message") or "",
            "sites": sites_out,
            "total_count": int(raw.get("total_count") or len(sites_out)),
            "total_pages": int(raw.get("total_pages") or 0),
        }

    @staticmethod
    def _normalize_site_status(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        out = ImpervaWAFEngine._site_shape(raw)
        out["res"] = int(raw.get("res") or 0)
        out["res_message"] = raw.get("res_message") or ""
        return out

    @staticmethod
    def _normalize_simple_res(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "res": int(raw.get("res") or 0),
            "res_message": raw.get("res_message") or "",
        }

    @staticmethod
    def _site_shape(s: Dict[str, Any]) -> Dict[str, Any]:
        ips = s.get("ips") if isinstance(s.get("ips"), list) else []
        dns = s.get("dns") if isinstance(s.get("dns"), list) else []
        ssl = s.get("ssl") if isinstance(s.get("ssl"), dict) else {}
        original_dns = s.get("original_dns_records") \
            if isinstance(s.get("original_dns_records"), list) else []
        warnings = s.get("warnings") if isinstance(s.get("warnings"), list) else []
        security = s.get("security") if isinstance(s.get("security"), dict) else {}
        seal = s.get("sealLocation") if isinstance(s.get("sealLocation"), dict) else {}
        login = s.get("login_protect") if isinstance(s.get("login_protect"), dict) else {}
        perf = s.get("performance_configuration") \
            if isinstance(s.get("performance_configuration"), dict) else {}
        ext_ddos = s.get("extended_ddos") \
            if isinstance(s.get("extended_ddos"), dict) else {}
        # security.waf
        waf = security.get("waf") if isinstance(security.get("waf"), dict) else {}
        rules_in = waf.get("rules") if isinstance(waf.get("rules"), list) else []
        rules_out: List[Dict[str, Any]] = []
        for r in rules_in:
            if not isinstance(r, dict):
                continue
            rules_out.append({
                "action": r.get("action") or "",
                "action_text": r.get("action_text") or "",
                "id": r.get("id") or "",
                "name": r.get("name") or "",
            })
        owasp_v2 = security.get("owasp_v2") \
            if isinstance(security.get("owasp_v2"), dict) else {}
        hacker_protect = security.get("hackerProtect") \
            if isinstance(security.get("hackerProtect"), dict) else {}
        return {
            "site_id": s.get("site_id") or "",
            "status": s.get("status") or "",
            "domain": s.get("domain") or "",
            "account_id": s.get("account_id") or "",
            "acceleration_level": s.get("acceleration_level") or "",
            "site_creation_date": s.get("site_creation_date") or "",
            "ips": [str(ip) for ip in ips],
            "dns": dns,
            "ssl": {
                "custom_certificate": (
                    ssl.get("custom_certificate")
                    if isinstance(ssl.get("custom_certificate"), dict)
                    else {"active": False}
                ),
                "generated_certificate": (
                    ssl.get("generated_certificate")
                    if isinstance(ssl.get("generated_certificate"), dict)
                    else {
                        "ca": "",
                        "validation_method": "",
                        "validation_data": "",
                        "san": [],
                        "generation_time": "",
                    }
                ),
            },
            "original_dns_records": original_dns,
            "warnings": warnings,
            "log_level": s.get("log_level") or "",
            "security": {
                "waf": {"rules": rules_out},
                "owasp_v2": owasp_v2,
                "hackerProtect": hacker_protect,
            },
            "sealLocation": {
                "id": seal.get("id") or "",
                "name": seal.get("name") or "",
            },
            "ssl_safe_browsing_id": s.get("ssl_safe_browsing_id") or "",
            "login_protect": {
                "enabled": bool(login.get("enabled", False)),
                "specific_users_list": (
                    login.get("specific_users_list")
                    if isinstance(login.get("specific_users_list"), list)
                    else []
                ),
                "send_lp_notifications": bool(login.get("send_lp_notifications", False)),
                "allow_all_users": bool(login.get("allow_all_users", False)),
                "sms_enabled": bool(login.get("sms_enabled", False)),
                "allowed_users": (
                    login.get("allowed_users")
                    if isinstance(login.get("allowed_users"), list)
                    else []
                ),
            },
            "performance_configuration": perf,
            "extended_ddos": ext_ddos,
        }

    @staticmethod
    def _normalize_policies(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        data_in = raw.get("data") if isinstance(raw.get("data"), list) else []
        out: List[Dict[str, Any]] = []
        for p in data_in:
            if not isinstance(p, dict):
                continue
            settings_in = p.get("policySettings") \
                if isinstance(p.get("policySettings"), list) else []
            settings_out: List[Dict[str, Any]] = []
            for st in settings_in:
                if not isinstance(st, dict):
                    continue
                settings_out.append({
                    "settingsAction": st.get("settingsAction") or "",
                    "policySettingType": st.get("policySettingType") or "",
                    "data": st.get("data") if isinstance(st.get("data"), list) else [],
                })
            out.append({
                "id": p.get("id") or "",
                "type": p.get("type") or "",
                "name": p.get("name") or "",
                "description": p.get("description") or "",
                "enabled": bool(p.get("enabled", False)),
                "default": bool(p.get("default", False)),
                "source": p.get("source") or "",
                "accountId": p.get("accountId") or "",
                "lastModified": p.get("lastModified") or "",
                "lastModifiedBy": p.get("lastModifiedBy") or "",
                "ratePolicyDefinition": (
                    p.get("ratePolicyDefinition")
                    if isinstance(p.get("ratePolicyDefinition"), dict) else {}
                ),
                "aclPolicyDefinition": (
                    p.get("aclPolicyDefinition")
                    if isinstance(p.get("aclPolicyDefinition"), dict) else {}
                ),
                "exceptions": (
                    p.get("exceptions") if isinstance(p.get("exceptions"), list) else []
                ),
                "policySettings": settings_out,
            })
        return {"data": out}

    @staticmethod
    def _normalize_site_v3(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        d = raw.get("data") if isinstance(raw.get("data"), dict) else raw
        inh = d.get("accountInheritance") \
            if isinstance(d.get("accountInheritance"), dict) else {}
        return {
            "data": {
                "id": d.get("id") or "",
                "name": d.get("name") or "",
                "type": d.get("type") or "",
                "accountId": d.get("accountId") or "",
                "refId": d.get("refId") or "",
                "accountInheritance": {
                    "accountInheritedFromTier1": bool(
                        inh.get("accountInheritedFromTier1", False)
                    ),
                    "accountInheritedFromTier2": bool(
                        inh.get("accountInheritedFromTier2", False)
                    ),
                    "accountInheritedFromTier3": bool(
                        inh.get("accountInheritedFromTier3", False)
                    ),
                },
            }
        }

    @staticmethod
    def _normalize_incidents(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("incidents") if isinstance(raw.get("incidents"), list) else []
        out: List[Dict[str, Any]] = []
        for i in items:
            if not isinstance(i, dict):
                continue
            sites = i.get("sites") if isinstance(i.get("sites"), list) else []
            sites_out: List[Dict[str, Any]] = []
            for s in sites:
                if not isinstance(s, dict):
                    continue
                sites_out.append({
                    "siteId": s.get("siteId") or "",
                    "siteName": s.get("siteName") or "",
                })
            out.append({
                "id": i.get("id") or "",
                "accountId": i.get("accountId") or "",
                "accountName": i.get("accountName") or "",
                "severity": i.get("severity") or "",
                "status": i.get("status") or "",
                "type": i.get("type") or "",
                "openedAt": i.get("openedAt") or "",
                "closedAt": i.get("closedAt") or "",
                "lastUpdatedAt": i.get("lastUpdatedAt") or "",
                "sites": sites_out,
                "assetId": i.get("assetId") or "",
                "ddosVolume": i.get("ddosVolume") or 0,
                "ddosTotalRequests": i.get("ddosTotalRequests") or 0,
                "mitigationActions": (
                    i.get("mitigationActions")
                    if isinstance(i.get("mitigationActions"), list) else []
                ),
                "description": i.get("description") or "",
                "recommendation": i.get("recommendation") or "",
                "attackVector": i.get("attackVector") or "",
            })
        return {
            "incidents": out,
            "totalIncidents": int(raw.get("totalIncidents") or len(out)),
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[ImpervaWAFEngine] = None
_singleton_lock = threading.Lock()


def get_imperva_waf_engine(
    api_id: Optional[str] = None,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ImpervaWAFEngine:
    """Return the process-wide ImpervaWAFEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ImpervaWAFEngine(
                api_id=api_id, api_key=api_key, client=client
            )
        return _singleton


def reset_imperva_waf_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ImpervaWAFEngine",
    "ImpervaUnavailableError",
    "get_imperva_waf_engine",
    "reset_imperva_waf_engine",
]
