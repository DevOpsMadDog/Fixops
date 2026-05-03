"""JupiterOne Asset Graph Engine — ALDECI.

Wraps the JupiterOne v1 REST + GraphQL surfaces and provides a process-wide
singleton. Endpoint coverage:

* POST /graphql                                              — J1QL queries
* GET  /persister/synchronization/jobs                       — list sync jobs
* POST /persister/synchronization/jobs                       — create sync job
* POST /persister/synchronization/jobs/{job_id}/upload       — upload entities/edges
* POST /persister/synchronization/jobs/{job_id}/finalize     — finalize sync job
* GET  /alerts                                               — list alert instances
* GET  /alerts/{instance_id}                                 — single alert detail
* POST /alerts/{instance_id}/dismiss                         — dismiss alert
* POST /alerts/{instance_id}/snooze                          — snooze alert
* GET  /accounts/{account_id}/integrations                   — list enabled integrations

NO MOCKS rule
-------------
* JUPITERONE_API_KEY or JUPITERONE_ACCOUNT unset:
    - All live endpoints raise JupiterOneUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No SQLite cache. No fabricated payloads.

Auth headers per call
---------------------
* ``Authorization: Bearer <JUPITERONE_API_KEY>``
* ``JupiterOne-Account: <JUPITERONE_ACCOUNT>``

Base URL defaults to ``https://api.us.jupiterone.io``; override with
``JUPITERONE_BASE_URL`` env (e.g. ``https://api.eu.jupiterone.io``).
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.us.jupiterone.io"
DEFAULT_TIMEOUT_SECONDS = 15.0


class JupiterOneUnavailableError(RuntimeError):
    """Raised when JupiterOne API key/account is missing, network failed,
    or upstream returned an unrecoverable status."""


class JupiterOneEngine:
    """Thread-safe JupiterOne REST + GraphQL client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        account: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_api_key = api_key
        self._explicit_account = account
        self._explicit_base_url = base_url
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- env
    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("JUPITERONE_API_KEY")
        return v or None

    def _account(self) -> Optional[str]:
        if self._explicit_account:
            return self._explicit_account
        v = os.environ.get("JUPITERONE_ACCOUNT")
        return v or None

    def _base_url(self) -> str:
        if self._explicit_base_url:
            return self._explicit_base_url.rstrip("/")
        v = os.environ.get("JUPITERONE_BASE_URL")
        return (v or DEFAULT_BASE_URL).rstrip("/")

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def account_present(self) -> bool:
        return bool(self._account())

    def configured(self) -> bool:
        return self.api_key_present() and self.account_present()

    # ------------------------------------------------------------- request
    def _headers(self) -> Dict[str, str]:
        api_key = self._api_key()
        account = self._account()
        if not api_key:
            raise JupiterOneUnavailableError(
                "JUPITERONE_API_KEY is not configured"
            )
        if not account:
            raise JupiterOneUnavailableError(
                "JUPITERONE_ACCOUNT is not configured"
            )
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "JupiterOne-Account": account,
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        files: Optional[Any] = None,
        data: Optional[Any] = None,
        expect_json: bool = True,
    ) -> Any:
        headers = self._headers()
        url = f"{self._base_url()}{path}"
        method_upper = method.upper()
        # Multipart uploads: drop json content-type so httpx sets boundary.
        send_headers = dict(headers)
        if files is not None or data is not None and json_body is None:
            send_headers.pop("Content-Type", None)

        try:
            if method_upper == "GET":
                resp = self._client.get(url, headers=send_headers, params=params)
            elif method_upper == "POST":
                if files is not None:
                    resp = self._client.post(
                        url,
                        headers=send_headers,
                        params=params,
                        files=files,
                        data=data,
                    )
                else:
                    resp = self._client.post(
                        url,
                        headers=send_headers,
                        params=params,
                        json=json_body,
                    )
            elif method_upper == "PUT":
                resp = self._client.put(
                    url,
                    headers=send_headers,
                    params=params,
                    json=json_body,
                )
            else:
                raise JupiterOneUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise JupiterOneUnavailableError(
                f"JupiterOne request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise JupiterOneUnavailableError(
                f"JupiterOne rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise JupiterOneUnavailableError(
                f"JupiterOne returned HTTP 404: {resp.text[:200]}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"JupiterOne validation error: {body}")
        if resp.status_code == 429:
            raise JupiterOneUnavailableError(
                "JupiterOne rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise JupiterOneUnavailableError(
                f"JupiterOne returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        if not expect_json:
            return {"ok": True, "status_code": resp.status_code}
        try:
            return resp.json()
        except ValueError as exc:
            raise JupiterOneUnavailableError(
                f"JupiterOne returned non-JSON response: {exc}"
            ) from exc

    # ------------------------------------------------------------- GraphQL
    def graphql(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        include_deleted: Optional[bool] = None,
        scope_filters: Optional[List[Dict[str, Any]]] = None,
        deferred_response: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a J1QL query via the GraphQL endpoint.

        Returns the raw GraphQL envelope ``{"data": {...}, "errors": [...]}``.
        """
        if not query or not isinstance(query, str):
            raise ValueError("query must be a non-empty string")
        body: Dict[str, Any] = {"query": query}
        if variables is not None:
            body["variables"] = variables
        if include_deleted is not None:
            body.setdefault("variables", {})["includeDeleted"] = bool(include_deleted)
        if scope_filters is not None:
            body.setdefault("variables", {})["scopeFilters"] = list(scope_filters)
        if deferred_response is not None:
            if deferred_response not in ("DISABLED", "FORCE"):
                raise ValueError(
                    "deferredResponse must be DISABLED or FORCE"
                )
            body.setdefault("variables", {})["deferredResponse"] = deferred_response
        raw = self._request("POST", "/graphql", json_body=body)
        return self._normalize_graphql(raw)

    @staticmethod
    def _normalize_graphql(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"data": None, "errors": []}
        out: Dict[str, Any] = {}
        out["data"] = raw.get("data") if isinstance(raw.get("data"), dict) else (
            {"queryV1": raw.get("data")} if raw.get("data") is not None else None
        )
        errs = raw.get("errors") if isinstance(raw.get("errors"), list) else []
        out["errors"] = []
        for e in errs:
            if not isinstance(e, dict):
                continue
            out["errors"].append(
                {
                    "message": e.get("message") or "",
                    "locations": e.get("locations") or [],
                    "path": e.get("path") or [],
                }
            )
        return out

    # --------------------------------------------------- synchronization
    def list_sync_jobs(
        self,
        from_iso: Optional[str] = None,
        size: Optional[int] = None,
        page_number: Optional[int] = None,
        type_: Optional[str] = None,
        source: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if from_iso is not None:
            params["from"] = from_iso
        if size is not None:
            params["size"] = int(size)
        if page_number is not None:
            params["pageNumber"] = int(page_number)
        if type_ is not None:
            params["type"] = type_
        if source is not None:
            params["source"] = source
        if scope is not None:
            params["scope"] = scope
        raw = self._request(
            "GET",
            "/persister/synchronization/jobs",
            params=params or None,
        )
        return self._normalize_sync_jobs(raw)

    @staticmethod
    def _normalize_sync_jobs(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"jobs": []}
        jobs_in = raw.get("jobs") if isinstance(raw.get("jobs"), list) else (
            raw.get("data") if isinstance(raw.get("data"), list) else []
        )
        jobs: List[Dict[str, Any]] = []
        for j in jobs_in:
            if not isinstance(j, dict):
                continue
            partial = j.get("partialDatasets") if isinstance(
                j.get("partialDatasets"), dict
            ) else {}
            int_def = j.get("integrationDefinitionDescription") if isinstance(
                j.get("integrationDefinitionDescription"), dict
            ) else {}
            jobs.append(
                {
                    "id": j.get("id") or "",
                    "type": j.get("type") or "",
                    "source": j.get("source") or "",
                    "scope": j.get("scope") or "",
                    "status": j.get("status") or "",
                    "partialDatasets": {
                        "deletedTypes": partial.get("deletedTypes") or [],
                        "updatedEntities": partial.get("updatedEntities") or [],
                        "createdEntities": partial.get("createdEntities") or [],
                    },
                    "integrationInstanceId": j.get("integrationInstanceId") or "",
                    "integrationJobId": j.get("integrationJobId") or "",
                    "syncMode": j.get("syncMode") or "",
                    "createDate": j.get("createDate") or "",
                    "lastModifyDate": j.get("lastModifyDate") or "",
                    "finishDate": j.get("finishDate") or "",
                    "etcdEpoch": j.get("etcdEpoch") or 0,
                    "integrationDefinitionId": j.get("integrationDefinitionId") or "",
                    "batchSize": j.get("batchSize") or 0,
                    "integrationDefinitionDescription": {
                        "name": int_def.get("name") or "",
                        "type": int_def.get("type") or "",
                        "integrationClass": int_def.get("integrationClass") or "",
                        "integrationCategory": int_def.get("integrationCategory") or [],
                    },
                    "jobMetadata": j.get("jobMetadata") or {},
                }
            )
        return {"jobs": jobs}

    def create_sync_job(
        self,
        source: str,
        scope: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if source not in ("integration-managed", "api-managed"):
            raise ValueError(
                "source must be 'integration-managed' or 'api-managed'"
            )
        if not scope:
            raise ValueError("scope must not be empty")
        body: Dict[str, Any] = {"source": source, "scope": scope}
        if properties is not None:
            body["properties"] = properties
        raw = self._request(
            "POST",
            "/persister/synchronization/jobs",
            json_body=body,
        )
        return self._normalize_sync_job_envelope(raw)

    @staticmethod
    def _normalize_sync_job_envelope(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"job": {}}
        job = raw.get("job") if isinstance(raw.get("job"), dict) else raw
        normalized = JupiterOneEngine._normalize_sync_jobs({"jobs": [job]})
        return {"job": normalized["jobs"][0] if normalized["jobs"] else {}}

    def upload_sync_job(
        self,
        job_id: str,
        entities: Optional[List[Dict[str, Any]]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if not job_id:
            raise ValueError("job_id must not be empty")
        body: Dict[str, Any] = {
            "entities": list(entities or []),
            "relationships": list(relationships or []),
        }
        return self._request(
            "POST",
            f"/persister/synchronization/jobs/{job_id}/upload",
            json_body=body,
            expect_json=False,
        )

    def finalize_sync_job(self, job_id: str) -> Dict[str, Any]:
        if not job_id:
            raise ValueError("job_id must not be empty")
        return self._request(
            "POST",
            f"/persister/synchronization/jobs/{job_id}/finalize",
            json_body={},
            expect_json=False,
        )

    # --------------------------------------------------------------- alerts
    def list_alerts(
        self,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        question_id: Optional[str] = None,
        page_number: Optional[int] = None,
        page_size: Optional[int] = None,
        statuses: Optional[Iterable[str]] = None,
        severities: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if from_date is not None:
            params["fromDate"] = from_date
        if to_date is not None:
            params["toDate"] = to_date
        if question_id is not None:
            params["questionId"] = question_id
        if page_number is not None:
            params["pageNumber"] = int(page_number)
        if page_size is not None:
            params["pageSize"] = int(page_size)
        if statuses is not None:
            params["statuses"] = ",".join(statuses)
        if severities is not None:
            params["severities"] = ",".join(severities)
        raw = self._request("GET", "/alerts", params=params or None)
        return self._normalize_alerts(raw)

    @staticmethod
    def _normalize_alert(a: Any) -> Dict[str, Any]:
        if not isinstance(a, dict):
            return {}
        last_eval = a.get("lastEvaluationResult") if isinstance(
            a.get("lastEvaluationResult"), dict
        ) else {}
        descriptors = last_eval.get("rawDataDescriptors") if isinstance(
            last_eval.get("rawDataDescriptors"), list
        ) else []
        norm_descriptors = []
        for d in descriptors:
            if not isinstance(d, dict):
                continue
            norm_descriptors.append(
                {
                    "name": d.get("name") or "",
                    "query": d.get("query") or "",
                    "persist": bool(d.get("persist", False)),
                }
            )
        qri = a.get("questionRuleInstance") if isinstance(
            a.get("questionRuleInstance"), dict
        ) else {}
        question = qri.get("question") if isinstance(qri.get("question"), dict) else {}
        queries = question.get("queries") if isinstance(question.get("queries"), list) else []
        norm_queries = []
        for q in queries:
            if not isinstance(q, dict):
                continue
            norm_queries.append(
                {"name": q.get("name") or "", "query": q.get("query") or ""}
            )
        return {
            "id": a.get("id") or "",
            "accountId": a.get("accountId") or "",
            "ruleId": a.get("ruleId") or "",
            "ruleName": a.get("ruleName") or "",
            "ruleVersion": a.get("ruleVersion") or 0,
            "ruleSpec": a.get("ruleSpec") or {},
            "level": a.get("level") or "",
            "type": a.get("type") or "",
            "status": a.get("status") or "",
            "lastEvaluationStartOn": a.get("lastEvaluationStartOn") or "",
            "lastEvaluationEndOn": a.get("lastEvaluationEndOn") or "",
            "lastEvaluationResult": {"rawDataDescriptors": norm_descriptors},
            "dismissedOn": a.get("dismissedOn") or "",
            "dismissedReason": a.get("dismissedReason") or "",
            "mutedUntil": a.get("mutedUntil") or "",
            "alertedAt": a.get("alertedAt") or "",
            "resolvedAt": a.get("resolvedAt") or "",
            "questionRuleInstance": {
                "question": {"queries": norm_queries},
            },
        }

    @staticmethod
    def _normalize_alerts(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"alerts": [], "totalCount": 0, "cursor": ""}
        alerts_in = raw.get("alerts") if isinstance(raw.get("alerts"), list) else (
            raw.get("data") if isinstance(raw.get("data"), list) else []
        )
        return {
            "alerts": [JupiterOneEngine._normalize_alert(a) for a in alerts_in],
            "totalCount": int(raw.get("totalCount") or len(alerts_in) or 0),
            "cursor": raw.get("cursor") or "",
        }

    def get_alert(self, instance_id: str) -> Dict[str, Any]:
        if not instance_id:
            raise ValueError("instance_id must not be empty")
        raw = self._request("GET", f"/alerts/{instance_id}")
        if isinstance(raw, dict) and "alert" in raw:
            return {"alert": self._normalize_alert(raw.get("alert"))}
        return {"alert": self._normalize_alert(raw)}

    def dismiss_alert(self, instance_id: str, reason: str) -> Dict[str, Any]:
        if not instance_id:
            raise ValueError("instance_id must not be empty")
        if not reason:
            raise ValueError("reason must not be empty")
        return self._request(
            "POST",
            f"/alerts/{instance_id}/dismiss",
            json_body={"reason": reason},
            expect_json=False,
        )

    def snooze_alert(self, instance_id: str, until: str) -> Dict[str, Any]:
        if not instance_id:
            raise ValueError("instance_id must not be empty")
        if not until:
            raise ValueError("until must not be empty")
        return self._request(
            "POST",
            f"/alerts/{instance_id}/snooze",
            json_body={"until": until},
            expect_json=False,
        )

    # ----------------------------------------------------- integrations
    def list_integrations(
        self,
        account_id: str,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
        type_: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not account_id:
            raise ValueError("account_id must not be empty")
        params: Dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor
        if limit is not None:
            params["limit"] = int(limit)
        if type_ is not None:
            params["type"] = type_
        raw = self._request(
            "GET",
            f"/accounts/{account_id}/integrations",
            params=params or None,
        )
        return self._normalize_integrations(raw)

    @staticmethod
    def _normalize_integrations(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"integrations": [], "cursor": ""}
        integ_in = raw.get("integrations") if isinstance(
            raw.get("integrations"), list
        ) else (
            raw.get("data") if isinstance(raw.get("data"), list) else []
        )
        out: List[Dict[str, Any]] = []
        for i in integ_in:
            if not isinstance(i, dict):
                continue
            out.append(
                {
                    "id": i.get("id") or "",
                    "name": i.get("name") or "",
                    "type": i.get("type") or "",
                    "accountId": i.get("accountId") or "",
                    "definitionId": i.get("definitionId") or "",
                    "config": i.get("config") or {},
                    "enabled": bool(i.get("enabled", True)),
                    "createdAt": i.get("createdAt") or "",
                    "updatedAt": i.get("updatedAt") or "",
                }
            )
        return {"integrations": out, "cursor": raw.get("cursor") or ""}

    # ------------------------------------------------------------- cleanup
    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton
_singleton: Optional[JupiterOneEngine] = None
_singleton_lock = threading.Lock()


def get_jupiterone_engine(
    api_key: Optional[str] = None,
    account: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> JupiterOneEngine:
    """Return the process-wide JupiterOneEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = JupiterOneEngine(
                api_key=api_key,
                account=account,
                base_url=base_url,
                client=client,
            )
        return _singleton


def reset_jupiterone_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "JupiterOneEngine",
    "JupiterOneUnavailableError",
    "get_jupiterone_engine",
    "reset_jupiterone_engine",
]
