"""
Braintrust LLM-Eval Engine — ALDECI.

Wraps the Braintrust REST API (https://api.braintrust.dev) and provides a
process-wide singleton.  No SQLite cache (Braintrust is the system of record
for experiments / datasets / projects — caching would yield stale rows).

Endpoint coverage
-----------------
* /v1/experiment       (GET, POST)        — list / create experiments
* /v1/experiment/{id}  (GET)              — fetch single experiment
* /v1/experiment/{id}/insert (POST)       — append events / scores
* /v1/dataset          (GET)              — list datasets
* /v1/dataset/{id}     (GET)              — fetch single dataset
* /v1/dataset/{id}/insert (POST)          — append dataset rows
* /v1/project          (GET)              — list projects
* /v1/score            (GET)              — list scoring functions

NO MOCKS rule
-------------
* BRAINTRUST_API_KEY env unset:
    - All live endpoints raise BraintrustUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response is the upstream JSON.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_BRAINTRUST_API_URL = "https://api.braintrust.dev"
DEFAULT_TIMEOUT_SECONDS = 8.0


class BraintrustUnavailableError(RuntimeError):
    """Raised when Braintrust API key is missing, network failed, or upstream
    returned an unrecoverable status."""


class BraintrustEngine:
    """Thread-safe Braintrust REST client (no local cache)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_api_key = api_key
        self._explicit_api_url = api_url
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("BRAINTRUST_API_KEY")
        return v or None

    def _api_url(self) -> str:
        if self._explicit_api_url:
            return self._explicit_api_url.rstrip("/")
        v = os.environ.get("BRAINTRUST_API_URL")
        return (v or DEFAULT_BRAINTRUST_API_URL).rstrip("/")

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        api_key = self._api_key()
        if not api_key:
            raise BraintrustUnavailableError(
                "BRAINTRUST_API_KEY is not configured"
            )
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        url = f"{self._api_url()}{path}"
        # Filter None query params so we don't send "key=None".
        clean_params = (
            {k: v for k, v in params.items() if v is not None}
            if params
            else None
        )
        try:
            method_u = method.upper()
            if method_u == "GET":
                resp = self._client.get(url, headers=headers, params=clean_params)
            elif method_u == "POST":
                resp = self._client.post(
                    url, headers=headers, params=clean_params, json=json_body
                )
            else:
                raise BraintrustUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise BraintrustUnavailableError(
                f"Braintrust request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise BraintrustUnavailableError(
                f"Braintrust rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code in (400, 422):
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Braintrust validation error: {body}")
        if resp.status_code == 429:
            raise BraintrustUnavailableError(
                "Braintrust rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code == 404:
            raise BraintrustUnavailableError(
                f"Braintrust returned 404 for {path}"
            )
        if resp.status_code >= 400:
            raise BraintrustUnavailableError(
                f"Braintrust returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise BraintrustUnavailableError(
                f"Braintrust returned non-JSON response: {exc}"
            ) from exc

    # ------------------------------------------------------- experiment

    def list_experiments(
        self,
        *,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
        starting_after: Optional[str] = None,
        ending_before: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        raw = self._request(
            "GET",
            "/v1/experiment",
            params={
                "project_id": project_id,
                "project_name": project_name,
                "starting_after": starting_after,
                "ending_before": ending_before,
                "limit": str(limit) if limit is not None else None,
            },
        )
        return self._normalize_listing(raw)

    def get_experiment(self, exp_id: str) -> Dict[str, Any]:
        if not exp_id:
            raise ValueError("exp_id must not be empty")
        raw = self._request("GET", f"/v1/experiment/{exp_id}")
        return raw if isinstance(raw, dict) else {}

    def create_experiment(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(body, dict):
            raise ValueError("body must be a dict")
        if not body.get("project_id"):
            raise ValueError("project_id is required")
        if not body.get("name"):
            raise ValueError("name is required")
        raw = self._request("POST", "/v1/experiment", json_body=body)
        return raw if isinstance(raw, dict) else {}

    def insert_experiment_events(
        self, exp_id: str, events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not exp_id:
            raise ValueError("exp_id must not be empty")
        if not isinstance(events, list) or not events:
            raise ValueError("events must be a non-empty list")
        raw = self._request(
            "POST",
            f"/v1/experiment/{exp_id}/insert",
            json_body={"events": events},
        )
        if not isinstance(raw, dict):
            return {"row_ids": []}
        row_ids = raw.get("row_ids") if isinstance(raw.get("row_ids"), list) else []
        return {"row_ids": row_ids}

    # ----------------------------------------------------------- dataset

    def list_datasets(
        self,
        *,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
        starting_after: Optional[str] = None,
        ending_before: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        raw = self._request(
            "GET",
            "/v1/dataset",
            params={
                "project_id": project_id,
                "project_name": project_name,
                "starting_after": starting_after,
                "ending_before": ending_before,
                "limit": str(limit) if limit is not None else None,
            },
        )
        return self._normalize_listing(raw)

    def get_dataset(self, ds_id: str) -> Dict[str, Any]:
        if not ds_id:
            raise ValueError("ds_id must not be empty")
        raw = self._request("GET", f"/v1/dataset/{ds_id}")
        return raw if isinstance(raw, dict) else {}

    def insert_dataset_events(
        self, ds_id: str, events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not ds_id:
            raise ValueError("ds_id must not be empty")
        if not isinstance(events, list) or not events:
            raise ValueError("events must be a non-empty list")
        raw = self._request(
            "POST",
            f"/v1/dataset/{ds_id}/insert",
            json_body={"events": events},
        )
        if not isinstance(raw, dict):
            return {"row_ids": []}
        row_ids = raw.get("row_ids") if isinstance(raw.get("row_ids"), list) else []
        return {"row_ids": row_ids}

    # ----------------------------------------------------------- project

    def list_projects(
        self,
        *,
        org_name: Optional[str] = None,
        starting_after: Optional[str] = None,
        ending_before: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        raw = self._request(
            "GET",
            "/v1/project",
            params={
                "org_name": org_name,
                "starting_after": starting_after,
                "ending_before": ending_before,
                "limit": str(limit) if limit is not None else None,
            },
        )
        return self._normalize_listing(raw)

    # ------------------------------------------------------------- score

    def list_scores(self) -> Dict[str, Any]:
        raw = self._request("GET", "/v1/score")
        return self._normalize_listing(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_listing(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"objects": [], "cursor": None}
        objects = raw.get("objects")
        if not isinstance(objects, list):
            objects = []
        cursor = raw.get("cursor")
        return {"objects": objects, "cursor": cursor}

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[BraintrustEngine] = None
_singleton_lock = threading.Lock()


def get_braintrust_engine(
    api_key: Optional[str] = None,
    api_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> BraintrustEngine:
    """Return the process-wide BraintrustEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = BraintrustEngine(
                api_key=api_key, api_url=api_url, client=client
            )
        return _singleton


def reset_braintrust_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "BraintrustEngine",
    "BraintrustUnavailableError",
    "get_braintrust_engine",
    "reset_braintrust_engine",
]
