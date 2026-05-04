"""LangSmith LLM Observability Engine — ALDECI.

Wraps the LangSmith REST API (https://api.smith.langchain.com) and provides a
process-wide singleton. Used to surface trace-level LLM observability
(runs, datasets, examples, feedback, sessions) for the council loop, the
distillation pipeline, and the brain pipeline.

Endpoint coverage
-----------------
* /api/v1/runs                 (GET)  — list runs (filterable by session/run_type/error)
* /api/v1/runs/{run_id}        (GET)  — single run detail
* /api/v1/datasets             (GET)  — list datasets (filterable by data_type/name)
* /api/v1/datasets/{id}        (GET)  — single dataset detail
* /api/v1/datasets/{id}/examples (GET/POST) — list / bulk-create examples
* /api/v1/feedback             (POST) — attach feedback (score / value / comment) to a run
* /api/v1/sessions             (GET)  — list sessions / projects

NO MOCKS rule
-------------
* LANGSMITH_API_KEY env unset:
    - All live endpoints raise LangSmithUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No SQLite cache — observability calls go straight upstream to surface the
  freshest run/feedback rows.
* No fabricated payloads — everything we return came from the LangSmith API.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Iterable, List, Optional

import httpx

_logger = logging.getLogger(__name__)

LANGSMITH_DEFAULT_ENDPOINT = "https://api.smith.langchain.com"
DEFAULT_TIMEOUT_SECONDS = 8.0


class LangSmithUnavailableError(RuntimeError):
    """Raised when LANGSMITH_API_KEY is missing, network failed, or the
    upstream API returned an unrecoverable status."""


class LangSmithEngine:
    """Thread-safe LangSmith REST client (no local cache)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit values win over env (re-read each call so tests can monkeypatch).
        self._explicit_api_key = api_key
        self._explicit_endpoint = endpoint
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("LANGSMITH_API_KEY")
        return v or None

    def endpoint(self) -> str:
        if self._explicit_endpoint:
            return self._explicit_endpoint.rstrip("/")
        v = os.environ.get("LANGSMITH_ENDPOINT")
        return (v or LANGSMITH_DEFAULT_ENDPOINT).rstrip("/")

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
    ) -> Any:
        api_key = self._api_key()
        if not api_key:
            raise LangSmithUnavailableError(
                "LANGSMITH_API_KEY is not configured"
            )
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "x-api-key": api_key,
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        url = f"{self.endpoint()}{path}"
        # Strip None-valued query params so we don't send "?session_id=None".
        if params is not None:
            params = {k: v for k, v in params.items() if v is not None}
        try:
            method_u = method.upper()
            if method_u == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method_u == "POST":
                resp = self._client.post(
                    url, headers=headers, params=params, json=json_body
                )
            else:
                raise LangSmithUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise LangSmithUnavailableError(
                f"LangSmith request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise LangSmithUnavailableError(
                f"LangSmith rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise LangSmithUnavailableError(
                f"LangSmith resource not found (HTTP 404): {path}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"LangSmith validation error: {body}")
        if resp.status_code == 429:
            raise LangSmithUnavailableError(
                "LangSmith rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise LangSmithUnavailableError(
                f"LangSmith returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise LangSmithUnavailableError(
                f"LangSmith returned non-JSON response: {exc}"
            ) from exc

    # ---------------------------------------------------------- runs

    def list_runs(
        self,
        *,
        session_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        run_type: Optional[str] = None,
        error: Optional[bool] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if run_type is not None and run_type not in {
            "llm", "chain", "tool", "retriever", "embedding", "prompt", "parser"
        }:
            raise ValueError(
                "run_type must be one of llm|chain|tool|retriever|embedding|prompt|parser"
            )
        params: Dict[str, Any] = {
            "session_id": session_id,
            "start_time": start_time,
            "end_time": end_time,
            "run_type": run_type,
            "limit": limit,
            "cursor": cursor,
        }
        if error is not None:
            params["error"] = "true" if error else "false"
        raw = self._request("GET", "/api/v1/runs", params=params)
        return self._normalize_runs(raw)

    def get_run(self, run_id: str) -> Dict[str, Any]:
        if not run_id:
            raise ValueError("run_id must not be empty")
        raw = self._request("GET", f"/api/v1/runs/{run_id}")
        return self._normalize_single_run(raw)

    # ------------------------------------------------------- datasets

    def list_datasets(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        data_type: Optional[str] = None,
        dataset_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if data_type is not None and data_type not in {"kv", "llm", "chat"}:
            raise ValueError("data_type must be one of kv|llm|chat")
        params: Dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "data_type": data_type,
            "name": dataset_name,
        }
        raw = self._request("GET", "/api/v1/datasets", params=params)
        return self._normalize_datasets(raw)

    def get_dataset(self, dataset_id: str) -> Dict[str, Any]:
        if not dataset_id:
            raise ValueError("dataset_id must not be empty")
        raw = self._request("GET", f"/api/v1/datasets/{dataset_id}")
        return self._normalize_single_dataset(raw)

    # ------------------------------------------------------- examples

    def list_examples(
        self,
        dataset_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if not dataset_id:
            raise ValueError("dataset_id must not be empty")
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        params = {
            "dataset_id": dataset_id,
            "limit": limit,
            "offset": offset,
        }
        raw = self._request("GET", "/api/v1/examples", params=params)
        return self._normalize_examples(raw)

    def create_examples(
        self,
        dataset_id: str,
        examples: Iterable[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not dataset_id:
            raise ValueError("dataset_id must not be empty")
        body: List[Dict[str, Any]] = []
        for ex in examples:
            if not isinstance(ex, dict):
                raise ValueError("each example must be an object")
            inputs = ex.get("inputs")
            if not isinstance(inputs, dict):
                raise ValueError("example.inputs must be an object")
            row: Dict[str, Any] = {
                "dataset_id": dataset_id,
                "inputs": inputs,
            }
            if isinstance(ex.get("outputs"), dict):
                row["outputs"] = ex["outputs"]
            if isinstance(ex.get("metadata"), dict):
                row["metadata"] = ex["metadata"]
            if ex.get("source_run_id"):
                row["source_run_id"] = ex["source_run_id"]
            body.append(row)
        if not body:
            raise ValueError("examples must contain at least one entry")
        raw = self._request(
            "POST",
            f"/api/v1/datasets/{dataset_id}/examples",
            json_body=body,
        )
        return self._normalize_create_examples(dataset_id, raw)

    # ------------------------------------------------------- feedback

    def create_feedback(
        self,
        *,
        run_id: str,
        key: str,
        score: Optional[float] = None,
        value: Any = None,
        comment: Optional[str] = None,
        correction: Any = None,
        feedback_source: Optional[Dict[str, Any]] = None,
        source_run_id: Optional[str] = None,
        target_run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not run_id:
            raise ValueError("run_id must not be empty")
        if not key:
            raise ValueError("key must not be empty")
        body: Dict[str, Any] = {"run_id": run_id, "key": key}
        if score is not None:
            body["score"] = score
        if value is not None:
            body["value"] = value
        if comment is not None:
            body["comment"] = comment
        if correction is not None:
            body["correction"] = correction
        if feedback_source is not None:
            body["feedback_source"] = feedback_source
        if source_run_id is not None:
            body["source_run_id"] = source_run_id
        if target_run_id is not None:
            body["target_run_id"] = target_run_id
        raw = self._request("POST", "/api/v1/feedback", json_body=body)
        return self._normalize_feedback(raw, run_id, key)

    # ------------------------------------------------------- sessions

    def list_sessions(
        self,
        *,
        reference_dataset: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        params = {
            "reference_dataset": reference_dataset,
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit,
            "cursor": cursor,
        }
        raw = self._request("GET", "/api/v1/sessions", params=params)
        return self._normalize_sessions(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _safe_str(v: Any) -> str:
        if v is None:
            return ""
        return str(v)

    @staticmethod
    def _safe_int(v: Any) -> int:
        try:
            return int(v) if v is not None else 0
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_float(v: Any) -> float:
        try:
            return float(v) if v is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    @classmethod
    def _normalize_run_row(cls, run: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(run, dict):
            return {}
        return {
            "id": cls._safe_str(run.get("id")),
            "name": cls._safe_str(run.get("name")),
            "run_type": cls._safe_str(run.get("run_type")),
            "start_time": cls._safe_str(run.get("start_time")),
            "end_time": cls._safe_str(run.get("end_time")),
            "extra": run.get("extra") if isinstance(run.get("extra"), dict) else {},
            "error": run.get("error"),
            "serialized": (
                run.get("serialized") if isinstance(run.get("serialized"), dict) else {}
            ),
            "events": run.get("events") if isinstance(run.get("events"), list) else [],
            "inputs": run.get("inputs") if isinstance(run.get("inputs"), dict) else {},
            "outputs": run.get("outputs") if isinstance(run.get("outputs"), dict) else {},
            "reference_example_id": run.get("reference_example_id"),
            "parent_run_id": run.get("parent_run_id"),
            "child_run_ids": (
                run.get("child_run_ids") if isinstance(run.get("child_run_ids"), list) else []
            ),
            "session_id": cls._safe_str(run.get("session_id")),
            "total_tokens": cls._safe_int(run.get("total_tokens")),
            "prompt_tokens": cls._safe_int(run.get("prompt_tokens")),
            "completion_tokens": cls._safe_int(run.get("completion_tokens")),
            "total_cost": cls._safe_float(run.get("total_cost")),
            "prompt_cost": cls._safe_float(run.get("prompt_cost")),
            "completion_cost": cls._safe_float(run.get("completion_cost")),
            "child_runs": (
                run.get("child_runs") if isinstance(run.get("child_runs"), list) else []
            ),
            "feedback_stats": (
                run.get("feedback_stats")
                if isinstance(run.get("feedback_stats"), dict)
                else {}
            ),
            "app_path": cls._safe_str(run.get("app_path")),
            "status": cls._safe_str(run.get("status")),
            "completed_at": cls._safe_str(run.get("completed_at")),
            "latency": cls._safe_float(run.get("latency")),
            "manifest_id": run.get("manifest_id"),
            "manifest_s3_id": run.get("manifest_s3_id"),
            "attachments": (
                run.get("attachments") if isinstance(run.get("attachments"), list) else []
            ),
            "execution_order": cls._safe_int(run.get("execution_order")),
            "in_dataset": bool(run.get("in_dataset", False)),
            "parent_run_ids": (
                run.get("parent_run_ids")
                if isinstance(run.get("parent_run_ids"), list)
                else []
            ),
            "trace_id": cls._safe_str(run.get("trace_id")),
            "dotted_order": cls._safe_str(run.get("dotted_order")),
        }

    @classmethod
    def _normalize_runs(cls, raw: Any) -> Dict[str, Any]:
        runs_list: List[Dict[str, Any]] = []
        cursor = ""
        if isinstance(raw, list):
            runs_list = [cls._normalize_run_row(r) for r in raw]
        elif isinstance(raw, dict):
            data = raw.get("runs") or raw.get("data") or []
            if isinstance(data, list):
                runs_list = [cls._normalize_run_row(r) for r in data]
            cursor = cls._safe_str(raw.get("cursor"))
        return {"runs": runs_list, "cursor": cursor}

    @classmethod
    def _normalize_single_run(cls, raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return cls._normalize_run_row(raw)
        return {}

    @classmethod
    def _normalize_dataset_row(cls, ds: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ds, dict):
            return {}
        return {
            "id": cls._safe_str(ds.get("id")),
            "name": cls._safe_str(ds.get("name")),
            "description": cls._safe_str(ds.get("description")),
            "created_at": cls._safe_str(ds.get("created_at")),
            "modified_at": cls._safe_str(ds.get("modified_at")),
            "data_type": cls._safe_str(ds.get("data_type")),
            "example_count": cls._safe_int(ds.get("example_count")),
            "session_count": cls._safe_int(ds.get("session_count")),
            "last_session_start_time": cls._safe_str(ds.get("last_session_start_time")),
            "inputs_schema_definition": ds.get("inputs_schema_definition"),
            "outputs_schema_definition": ds.get("outputs_schema_definition"),
            "externally_managed": bool(ds.get("externally_managed", False)),
            "transformations": (
                ds.get("transformations")
                if isinstance(ds.get("transformations"), list)
                else []
            ),
            "tenant_id": cls._safe_str(ds.get("tenant_id")),
        }

    @classmethod
    def _normalize_datasets(cls, raw: Any) -> List[Dict[str, Any]]:
        if isinstance(raw, list):
            return [cls._normalize_dataset_row(r) for r in raw]
        if isinstance(raw, dict):
            data = raw.get("datasets") or raw.get("data") or []
            if isinstance(data, list):
                return [cls._normalize_dataset_row(r) for r in data]
        return []

    @classmethod
    def _normalize_single_dataset(cls, raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return cls._normalize_dataset_row(raw)
        return {}

    @classmethod
    def _normalize_example_row(cls, ex: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ex, dict):
            return {}
        return {
            "id": cls._safe_str(ex.get("id")),
            "dataset_id": cls._safe_str(ex.get("dataset_id")),
            "inputs": ex.get("inputs") if isinstance(ex.get("inputs"), dict) else {},
            "outputs": ex.get("outputs") if isinstance(ex.get("outputs"), dict) else {},
            "metadata": (
                ex.get("metadata") if isinstance(ex.get("metadata"), dict) else {}
            ),
            "source_run_id": ex.get("source_run_id"),
            "created_at": cls._safe_str(ex.get("created_at")),
            "modified_at": cls._safe_str(ex.get("modified_at")),
        }

    @classmethod
    def _normalize_examples(cls, raw: Any) -> List[Dict[str, Any]]:
        if isinstance(raw, list):
            return [cls._normalize_example_row(r) for r in raw]
        if isinstance(raw, dict):
            data = raw.get("examples") or raw.get("data") or []
            if isinstance(data, list):
                return [cls._normalize_example_row(r) for r in data]
        return []

    @classmethod
    def _normalize_create_examples(
        cls, dataset_id: str, raw: Any
    ) -> Dict[str, Any]:
        ids: List[str] = []
        created_at = ""
        modified_at = ""
        if isinstance(raw, dict):
            created_at = cls._safe_str(raw.get("created_at"))
            modified_at = cls._safe_str(raw.get("modified_at"))
            raw_ids = raw.get("ids") or raw.get("example_ids") or []
            if isinstance(raw_ids, list):
                ids = [cls._safe_str(i) for i in raw_ids]
            elif isinstance(raw.get("examples"), list):
                ids = [cls._safe_str(e.get("id")) for e in raw["examples"]
                       if isinstance(e, dict)]
        elif isinstance(raw, list):
            ids = [cls._safe_str(e.get("id")) for e in raw if isinstance(e, dict)]
        return {
            "created_at": created_at,
            "modified_at": modified_at,
            "dataset_id": dataset_id,
            "ids": ids,
        }

    @classmethod
    def _normalize_feedback(
        cls, raw: Any, run_id: str, key: str
    ) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "id": cls._safe_str(raw.get("id")),
            "created_at": cls._safe_str(raw.get("created_at")),
            "modified_at": cls._safe_str(raw.get("modified_at")),
            "run_id": cls._safe_str(raw.get("run_id") or run_id),
            "key": cls._safe_str(raw.get("key") or key),
            "score": raw.get("score"),
            "value": raw.get("value"),
            "comment": raw.get("comment"),
            "correction": raw.get("correction"),
            "feedback_source": (
                raw.get("feedback_source")
                if isinstance(raw.get("feedback_source"), dict)
                else None
            ),
            "session_id": cls._safe_str(raw.get("session_id")),
            "comparative_experiment_id": raw.get("comparative_experiment_id"),
            "feedback_group_id": raw.get("feedback_group_id"),
            "comparative_experiment_run_id": raw.get("comparative_experiment_run_id"),
            "extra": raw.get("extra") if isinstance(raw.get("extra"), dict) else {},
            "trace_id": cls._safe_str(raw.get("trace_id")),
        }

    @classmethod
    def _normalize_session_row(cls, s: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(s, dict):
            return {}
        return {
            "id": cls._safe_str(s.get("id")),
            "name": cls._safe_str(s.get("name")),
            "description": cls._safe_str(s.get("description")),
            "start_time": cls._safe_str(s.get("start_time")),
            "end_time": cls._safe_str(s.get("end_time")),
            "extra": s.get("extra") if isinstance(s.get("extra"), dict) else {},
            "tenant_id": cls._safe_str(s.get("tenant_id")),
            "reference_dataset_id": s.get("reference_dataset_id"),
            "run_count": cls._safe_int(s.get("run_count")),
            "latency_p50": cls._safe_float(s.get("latency_p50")),
            "latency_p99": cls._safe_float(s.get("latency_p99")),
            "total_tokens": cls._safe_int(s.get("total_tokens")),
            "prompt_tokens": cls._safe_int(s.get("prompt_tokens")),
            "completion_tokens": cls._safe_int(s.get("completion_tokens")),
            "total_cost": cls._safe_float(s.get("total_cost")),
            "prompt_cost": cls._safe_float(s.get("prompt_cost")),
            "completion_cost": cls._safe_float(s.get("completion_cost")),
            "error_rate": cls._safe_float(s.get("error_rate")),
            "feedback_stats": (
                s.get("feedback_stats") if isinstance(s.get("feedback_stats"), dict) else {}
            ),
        }

    @classmethod
    def _normalize_sessions(cls, raw: Any) -> Dict[str, Any]:
        sessions: List[Dict[str, Any]] = []
        cursor = ""
        if isinstance(raw, list):
            sessions = [cls._normalize_session_row(r) for r in raw]
        elif isinstance(raw, dict):
            data = raw.get("sessions") or raw.get("data") or []
            if isinstance(data, list):
                sessions = [cls._normalize_session_row(r) for r in data]
            cursor = cls._safe_str(raw.get("cursor"))
        return {"sessions": sessions, "cursor": cursor}

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[LangSmithEngine] = None
_singleton_lock = threading.Lock()


def get_langsmith_engine(
    api_key: Optional[str] = None,
    endpoint: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> LangSmithEngine:
    """Return the process-wide LangSmithEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = LangSmithEngine(
                api_key=api_key, endpoint=endpoint, client=client
            )
        return _singleton


def reset_langsmith_engine() -> None:
    """Tear down the singleton — used by tests with stub clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "LangSmithEngine",
    "LangSmithUnavailableError",
    "LANGSMITH_DEFAULT_ENDPOINT",
    "get_langsmith_engine",
    "reset_langsmith_engine",
]
