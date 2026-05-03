"""Tanium Endpoint Platform — REAL session-token REST API client.

Live integration with Tanium's Server REST API (`/api/v2/...`). Two-phase
auth: POST /api/v2/sessions with username+password (and optional domain)
returns a session token that is sent as the `session` header on
subsequent calls. Tokens default to ~50 minutes of validity per Tanium
docs and are cached in-memory.

Endpoints wrapped:
  POST /api/v2/sessions             open session (returns session token)
  GET  /api/v2/system_status        cluster + dependent-cluster health
  POST /api/v2/parse_question       NLP-style question parser
  POST /api/v2/questions            issue a Tanium question
  GET  /api/v2/result_data          fetch result rows for a question id
  GET  /api/v2/sensors              list sensors (definitions + scripts)
  GET  /api/v2/saved_questions      list saved-question library

NO MOCKS rule:
  * If TANIUM_URL / TANIUM_USER / TANIUM_PASSWORD are unset the engine
    reports `api_credentials_present()=False` and EVERY live call raises
    TaniumUnavailableError (router translates to HTTP 503).
  * No fabricated cluster status, sensors, rows, or saved questions.

Token cache is in-memory only (Tanium recommends ~50 min lifetime).

References:
  https://docs.tanium.com/platform_user/platform_user/console_using_rest_api.html
  https://developer.tanium.com/site/global/apis/rest_api/index.gsp
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
TOKEN_TTL_SECONDS = 50 * 60          # Tanium sessions ~50 min by default
TOKEN_REFRESH_GRACE = 60             # refresh 60s before expiry


class TaniumUnavailableError(RuntimeError):
    """Raised when Tanium credentials are missing or upstream call fails."""


class TaniumEndpointEngine:
    """Live Tanium REST API client.

    Stateless except for an in-memory session-token cache. Designed to be
    used as a process-wide singleton via ``get_tanium_endpoint_engine()``.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._url = (url if url is not None else os.getenv("TANIUM_URL") or "").rstrip("/")
        self._user = user if user is not None else os.getenv("TANIUM_USER")
        self._password = password if password is not None else os.getenv("TANIUM_PASSWORD")
        self._domain = domain if domain is not None else os.getenv("TANIUM_DOMAIN")
        self._client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)
        self._owns_client = client is None
        self._session_token: Optional[str] = None
        self._session_expires_at: float = 0.0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------
    def url_present(self) -> bool:
        return bool(self._url and str(self._url).strip())

    def user_present(self) -> bool:
        return bool(self._user and str(self._user).strip())

    def password_present(self) -> bool:
        return bool(self._password and str(self._password).strip())

    def api_credentials_present(self) -> bool:
        return self.url_present() and self.user_present() and self.password_present()

    # ------------------------------------------------------------------
    # Session-token management (POST /api/v2/sessions)
    # ------------------------------------------------------------------
    def _ensure_session(self) -> str:
        if not self.api_credentials_present():
            raise TaniumUnavailableError(
                "TANIUM_URL, TANIUM_USER and TANIUM_PASSWORD must be set"
            )
        with self._lock:
            now = time.time()
            if self._session_token and now < (self._session_expires_at - TOKEN_REFRESH_GRACE):
                return self._session_token
            url = f"{self._url}/api/v2/sessions"
            body: Dict[str, Any] = {
                "username": self._user,
                "password": self._password,
            }
            if self._domain:
                body["domain"] = self._domain
            try:
                resp = self._client.post(
                    url,
                    json=body,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
            except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
                raise TaniumUnavailableError(f"sessions request failed: {exc}") from exc
            status = getattr(resp, "status_code", 500)
            if status != 200:
                detail = getattr(resp, "text", "")[:200]
                raise TaniumUnavailableError(
                    f"sessions rejected (status={status}): {detail}"
                )
            try:
                payload = resp.json() or {}
            except (ValueError, TypeError) as exc:
                raise TaniumUnavailableError(f"sessions JSON malformed: {exc}") from exc
            data = payload.get("data") or {}
            token = data.get("session")
            if not token:
                raise TaniumUnavailableError("sessions response missing data.session")
            self._session_token = str(token)
            self._session_expires_at = now + TOKEN_TTL_SECONDS
            return self._session_token

    def open_session(
        self, username: str, password: str, domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """Explicit POST /api/v2/sessions for the router endpoint.

        Uses caller-supplied credentials (allows API consumers to test
        alternate accounts without rewriting env). Does NOT update the
        cached singleton session — call sites that want the cached token
        should use ``_ensure_session()`` instead.
        """
        if not username or not password:
            raise ValueError("username and password are required")
        if not self.url_present():
            raise TaniumUnavailableError("TANIUM_URL must be set")
        url = f"{self._url}/api/v2/sessions"
        body: Dict[str, Any] = {"username": username, "password": password}
        if domain:
            body["domain"] = domain
        try:
            resp = self._client.post(
                url,
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
            raise TaniumUnavailableError(f"sessions request failed: {exc}") from exc
        status = getattr(resp, "status_code", 500)
        if status != 200:
            detail = getattr(resp, "text", "")[:200]
            raise TaniumUnavailableError(
                f"sessions rejected (status={status}): {detail}"
            )
        try:
            payload = resp.json() or {}
        except (ValueError, TypeError) as exc:
            raise TaniumUnavailableError(f"sessions JSON malformed: {exc}") from exc
        data = payload.get("data") or {}
        token = data.get("session")
        if not token:
            raise TaniumUnavailableError("sessions response missing data.session")
        return {
            "data": {
                "session": str(token),
                "expiration": data.get("expiration") or "",
                "persistent": bool(data.get("persistent", False)),
            }
        }

    # ------------------------------------------------------------------
    # Auth header for cached session calls
    # ------------------------------------------------------------------
    def _auth_headers(self) -> Dict[str, str]:
        return {
            "session": self._ensure_session(),
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # REST helpers
    # ------------------------------------------------------------------
    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self._url}{path}"
        try:
            resp = self._client.get(url, params=params or {}, headers=self._auth_headers())
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
            raise TaniumUnavailableError(f"GET {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    def _post(self, path: str, json_body: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self._url}{path}"
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        try:
            resp = self._client.post(url, json=json_body, headers=headers)
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
            raise TaniumUnavailableError(f"POST {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    @staticmethod
    def _unwrap(resp: Any, path: str) -> Dict[str, Any]:
        status = getattr(resp, "status_code", 500)
        if status >= 400:
            text = getattr(resp, "text", "")[:300]
            raise TaniumUnavailableError(f"{path} returned {status}: {text}")
        try:
            data = resp.json()
        except (ValueError, TypeError) as exc:
            raise TaniumUnavailableError(f"{path} returned non-JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise TaniumUnavailableError(f"{path} returned non-object payload")
        return data

    # ------------------------------------------------------------------
    # System status
    # ------------------------------------------------------------------
    def system_status(self) -> Dict[str, Any]:
        """GET /api/v2/system_status — cluster + dependent cluster health."""
        data = self._get("/api/v2/system_status")
        body = data.get("data") or {}
        clusters_in = body.get("server_clusters") or []
        deps_in = body.get("dependent_clusters") or []
        clusters_out: List[Dict[str, Any]] = []
        for raw in clusters_in:
            if not isinstance(raw, dict):
                continue
            clusters_out.append({
                "name":   str(raw.get("name") or ""),
                "ip":     str(raw.get("ip") or raw.get("address") or ""),
                "status": str(raw.get("status") or ""),
            })
        deps_out: List[Dict[str, Any]] = []
        for raw in deps_in:
            if not isinstance(raw, dict):
                continue
            deps_out.append({
                "name":   str(raw.get("name") or ""),
                "ip":     str(raw.get("ip") or ""),
                "status": str(raw.get("status") or ""),
            })
        return {"data": {"server_clusters": clusters_out, "dependent_clusters": deps_out}}

    # ------------------------------------------------------------------
    # Parse question
    # ------------------------------------------------------------------
    def parse_question(self, text: str) -> Dict[str, Any]:
        """POST /api/v2/parse_question — NLP-style question parser."""
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text must be a non-empty string")
        data = self._post("/api/v2/parse_question", {"text": text.strip()})
        items_in = data.get("data") or []
        items_out: List[Dict[str, Any]] = []
        for raw in items_in:
            if not isinstance(raw, dict):
                continue
            sensors_out: List[Dict[str, Any]] = []
            for s in (raw.get("sensor_references") or []):
                if not isinstance(s, dict):
                    continue
                sensors_out.append({
                    "name":         str(s.get("name") or ""),
                    "real_ms_avg":  s.get("real_ms_avg") or 0,
                    "source_hash":  str(s.get("source_hash") or ""),
                })
            groups_out: List[Dict[str, Any]] = []
            for g in (raw.get("result_groups") or []):
                if not isinstance(g, dict):
                    continue
                selects_out: List[Dict[str, Any]] = []
                for sel in (g.get("select") or []):
                    if not isinstance(sel, dict):
                        continue
                    sensor = sel.get("sensor") or {}
                    selects_out.append({
                        "aggregation":          str(sel.get("aggregation") or ""),
                        "max_data_age_seconds": sel.get("max_data_age_seconds") or 0,
                        "sensor": {
                            "name":         str(sensor.get("name") or ""),
                            "source_hash":  str(sensor.get("source_hash") or ""),
                        },
                    })
                groups_out.append({"select": selects_out})
            items_out.append({
                "from_canonical_text":   bool(raw.get("from_canonical_text", False)),
                "parameter_values":      raw.get("parameter_values") or [],
                "picked_intrinsic_type": str(raw.get("picked_intrinsic_type") or ""),
                "question_text":         str(raw.get("question_text") or ""),
                "parsed_text":           str(raw.get("parsed_text") or ""),
                "sensor_references":     sensors_out,
                "result_groups":         groups_out,
                "score":                 raw.get("score") or 0,
                "source":                str(raw.get("source") or ""),
            })
        return {"data": items_out}

    # ------------------------------------------------------------------
    # Questions
    # ------------------------------------------------------------------
    def issue_question(
        self,
        query_text: str,
        expire_seconds: Optional[int] = None,
        force_computer_id_flag: Optional[bool] = None,
        expiration: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/v2/questions — issue a Tanium question."""
        if not isinstance(query_text, str) or not query_text.strip():
            raise ValueError("query_text must be a non-empty string")
        body: Dict[str, Any] = {"query_text": query_text.strip()}
        if expire_seconds is not None:
            body["expire_seconds"] = int(expire_seconds)
        if force_computer_id_flag is not None:
            body["force_computer_id_flag"] = bool(force_computer_id_flag)
        if expiration:
            body["expiration"] = str(expiration)
        data = self._post("/api/v2/questions", body)
        d = data.get("data") or {}
        return {
            "data": {
                "id":                    d.get("id") or 0,
                "query_text":            str(d.get("query_text") or ""),
                "action_tracking_flag":  bool(d.get("action_tracking_flag", False)),
                "expiration":            str(d.get("expiration") or ""),
                "expire_seconds":        d.get("expire_seconds") or 0,
                "question_id":           d.get("question_id") or d.get("id") or 0,
                **{k: v for k, v in d.items()
                   if k not in {"id", "query_text", "action_tracking_flag",
                                "expiration", "expire_seconds", "question_id"}},
            }
        }

    # ------------------------------------------------------------------
    # Result data
    # ------------------------------------------------------------------
    def get_result_data(
        self, question_id: int, hide_no_results_flag: int = 1
    ) -> Dict[str, Any]:
        """GET /api/v2/result_data — fetch result rows for a question id."""
        try:
            qid = int(question_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("question_id must be an integer") from exc
        params = {
            "question_id":          qid,
            "hide_no_results_flag": int(hide_no_results_flag),
        }
        data = self._get("/api/v2/result_data", params=params)
        body = data.get("data") or {}
        sets_in = body.get("result_sets") or []
        sets_out: List[Dict[str, Any]] = []
        for raw in sets_in:
            if not isinstance(raw, dict):
                continue
            cols_out = []
            for c in (raw.get("columns") or []):
                if not isinstance(c, dict):
                    continue
                cols_out.append({
                    "name": str(c.get("name") or ""),
                    "hash": str(c.get("hash") or ""),
                    "type": str(c.get("type") or ""),
                })
            rows_out = []
            for r in (raw.get("rows") or []):
                if not isinstance(r, dict):
                    continue
                rows_out.append({
                    "id":   r.get("id") or 0,
                    "cid":  r.get("cid") or 0,
                    "data": r.get("data") or [],
                })
            sets_out.append({
                "age":                  raw.get("age") or 0,
                "archived_question_id": raw.get("archived_question_id") or 0,
                "cache_id":             str(raw.get("cache_id") or ""),
                "error_count":          raw.get("error_count") or 0,
                "estimated_total":      raw.get("estimated_total") or 0,
                "expiration":           raw.get("expiration") or 0,
                "columns":              cols_out,
                "rows":                 rows_out,
                "no_results_count":     raw.get("no_results_count") or 0,
                "mr_passed":            raw.get("mr_passed") or 0,
                "mr_tested":            raw.get("mr_tested") or 0,
                "passed":               raw.get("passed") or 0,
                "tested":               raw.get("tested") or 0,
                "question_id":          raw.get("question_id") or qid,
                "report_count":         raw.get("report_count") or 0,
                "row_count":            raw.get("row_count") or len(rows_out),
                "saved_question_id":    raw.get("saved_question_id") or 0,
                "seconds_since_issued": raw.get("seconds_since_issued") or 0,
                "select_count":         raw.get("select_count") or 0,
            })
        return {"data": {"result_sets": sets_out}}

    # ------------------------------------------------------------------
    # Sensors
    # ------------------------------------------------------------------
    def list_sensors(self, max_age_seconds: Optional[int] = None) -> Dict[str, Any]:
        """GET /api/v2/sensors — list sensors (definitions + scripts)."""
        params: Dict[str, Any] = {}
        if max_age_seconds is not None:
            params["max_age_seconds"] = int(max_age_seconds)
        data = self._get("/api/v2/sensors", params=params)
        items_in = data.get("data") or []
        items_out: List[Dict[str, Any]] = []
        for raw in items_in:
            if not isinstance(raw, dict):
                continue
            queries_out = []
            for q in (raw.get("queries") or []):
                if not isinstance(q, dict):
                    continue
                queries_out.append({
                    "platform":    str(q.get("platform") or ""),
                    "script":      str(q.get("script") or ""),
                    "script_type": str(q.get("script_type") or ""),
                    "signature":   str(q.get("signature") or ""),
                })
            params_out = []
            for p in (raw.get("parameters") or []):
                if not isinstance(p, dict):
                    continue
                params_out.append({
                    "key":                       str(p.get("key") or ""),
                    "default_value":             p.get("default_value") if p.get("default_value") is not None else "",
                    "type":                      str(p.get("type") or ""),
                    "label":                     str(p.get("label") or ""),
                    "value_type":                str(p.get("value_type") or ""),
                    "allow_set_multiple_flags":  bool(p.get("allow_set_multiple_flags", False)),
                })
            items_out.append({
                "id":                       raw.get("id") or 0,
                "name":                     str(raw.get("name") or ""),
                "hash":                     str(raw.get("hash") or ""),
                "source_hash":              str(raw.get("source_hash") or ""),
                "source_id":                raw.get("source_id") or 0,
                "max_age_seconds":          raw.get("max_age_seconds") or 0,
                "hidden_flag":              bool(raw.get("hidden_flag", False)),
                "ignore_case_flag":         bool(raw.get("ignore_case_flag", False)),
                "exclude_from_parse_flag":  bool(raw.get("exclude_from_parse_flag", False)),
                "value_type":               str(raw.get("value_type") or ""),
                "queries":                  queries_out,
                "parameters":               params_out,
                "category":                 str(raw.get("category") or ""),
            })
        return {"data": items_out}

    # ------------------------------------------------------------------
    # Saved questions
    # ------------------------------------------------------------------
    def list_saved_questions(self, max_age_seconds: Optional[int] = None) -> Dict[str, Any]:
        """GET /api/v2/saved_questions — saved-question library."""
        params: Dict[str, Any] = {}
        if max_age_seconds is not None:
            params["max_age_seconds"] = int(max_age_seconds)
        data = self._get("/api/v2/saved_questions", params=params)
        items_in = data.get("data") or []
        items_out: List[Dict[str, Any]] = []
        for raw in items_in:
            if not isinstance(raw, dict):
                continue
            items_out.append({
                "id":                    raw.get("id") or 0,
                "name":                  str(raw.get("name") or ""),
                "query_text":            str(raw.get("query_text") or ""),
                "action_tracking_flag":  bool(raw.get("action_tracking_flag", False)),
                "archive_enabled_flag":  bool(raw.get("archive_enabled_flag", False)),
                "expire_seconds":        raw.get("expire_seconds") or 0,
                "hidden_flag":           bool(raw.get("hidden_flag", False)),
                "public_flag":           bool(raw.get("public_flag", False)),
            })
        return {"data": items_out}

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except (RuntimeError, OSError):
                pass


# --------------------------------------------------------------- singleton
_singleton: Optional[TaniumEndpointEngine] = None
_singleton_lock = threading.Lock()


def get_tanium_endpoint_engine(
    url: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> TaniumEndpointEngine:
    """Return the process-wide TaniumEndpointEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = TaniumEndpointEngine(
                url=url,
                user=user,
                password=password,
                domain=domain,
                client=client,
            )
        return _singleton


def reset_tanium_endpoint_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "TaniumEndpointEngine",
    "TaniumUnavailableError",
    "get_tanium_endpoint_engine",
    "reset_tanium_endpoint_engine",
]
