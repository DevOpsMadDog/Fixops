"""
Guardrails AI Engine — ALDECI.

Wraps the Guardrails AI hosted server REST API (https://api.guardrailsai.com)
plus the equivalent self-hosted Guardrails Server surface so ALDECI callers
can validate LLM inputs / outputs against named guards (profanity-free,
toxic-language, valid-json, valid-python, valid-sql, secrets-present,
hallucination-detection, guardrails-pii, ...).

Endpoint coverage (Guardrails Server REST surface)
--------------------------------------------------
* POST /validate                                    — single ad-hoc validate
* GET  /specs                                       — list registered specs
* GET  /specs/{spec_name}                           — single spec detail
* POST /spec                                        — register custom spec
* POST /guards/{guard_name}/validate                — validate against a guard
* POST /openai/chat/completions                     — guarded OpenAI passthrough
* GET  /health                                      — upstream health probe

NO MOCKS rule
-------------
* GUARDRAILS_API_KEY env unset:
    - All live methods raise GuardrailsUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* Guardrails Server unreachable / non-2xx → GuardrailsUnavailableError → 503.
* No fabricated payloads.
* No SQLite cache (hosted Guardrails responses depend on live LLM state and
  must not be cached locally — per task spec).
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

GUARDRAILS_DEFAULT_BASE_URL = "https://api.guardrailsai.com"
DEFAULT_TIMEOUT_SECONDS = 15.0


class GuardrailsUnavailableError(RuntimeError):
    """Raised when GUARDRAILS_API_KEY is missing, network failed, or upstream
    returned an unrecoverable status."""


class GuardrailsEngine:
    """Thread-safe Guardrails AI REST client (no on-disk cache)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit api_key/base_url win over env (re-read each call so tests
        # can monkeypatch).
        self._explicit_api_key = api_key
        self._explicit_base_url = base_url

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("GUARDRAILS_API_KEY")
        return v or None

    def _base_url(self) -> str:
        if self._explicit_base_url:
            return self._explicit_base_url.rstrip("/")
        v = os.environ.get("GUARDRAILS_BASE_URL")
        return (v or GUARDRAILS_DEFAULT_BASE_URL).rstrip("/")

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def base_url(self) -> str:
        return self._base_url()

    # ---------------------------------------------------------------- net

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        api_key = self._api_key()
        if not api_key:
            raise GuardrailsUnavailableError(
                "GUARDRAILS_API_KEY is not configured"
            )
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        url = f"{self._base_url()}{path}"
        try:
            method_upper = method.upper()
            if method_upper == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method_upper == "POST":
                resp = self._client.post(
                    url, headers=headers, params=params, json=json_body
                )
            else:
                raise GuardrailsUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise GuardrailsUnavailableError(
                f"Guardrails request failed: {exc}"
            ) from exc

        status = resp.status_code
        if status in (401, 403):
            raise GuardrailsUnavailableError(
                f"Guardrails rejected credentials (HTTP {status})"
            )
        if status == 404:
            raise GuardrailsUnavailableError(
                f"Guardrails resource not found at {path} (HTTP 404)"
            )
        if status == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Guardrails validation error: {body}")
        if status == 429:
            raise GuardrailsUnavailableError(
                "Guardrails rate-limit exceeded (HTTP 429)"
            )
        if status >= 400:
            raise GuardrailsUnavailableError(
                f"Guardrails returned HTTP {status}: {resp.text[:200]}"
            )
        # 201 created (POST /spec) returns JSON too — treat same as 200.
        try:
            return resp.json()
        except ValueError as exc:
            raise GuardrailsUnavailableError(
                f"Guardrails returned non-JSON response: {exc}"
            ) from exc

    # --------------------------------------------------------- operations

    def validate(
        self,
        prompt: str,
        guards: List[Dict[str, Any]],
        *,
        response: Optional[str] = None,
        llm_callable: Optional[str] = None,
        llm_kwargs: Optional[Dict[str, Any]] = None,
        num_reasks: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not isinstance(prompt, str):
            raise ValueError("prompt must be a string")
        if not isinstance(guards, list) or not guards:
            raise ValueError("guards must be a non-empty list")
        body: Dict[str, Any] = {"prompt": prompt, "guards": guards}
        if response is not None:
            body["response"] = response
        if llm_callable is not None:
            body["llm_callable"] = llm_callable
        if llm_kwargs is not None:
            body["llm_kwargs"] = llm_kwargs
        if num_reasks is not None:
            body["num_reasks"] = int(num_reasks)
        return self._request("POST", "/v1/validate", json_body=body)

    def list_specs(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/specs")

    def get_spec(self, spec_name: str) -> Dict[str, Any]:
        if not spec_name:
            raise ValueError("spec_name must not be empty")
        return self._request("GET", f"/v1/specs/{spec_name}")

    def create_spec(
        self,
        name: str,
        description: str,
        guards: List[Dict[str, Any]],
        *,
        schema: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not name:
            raise ValueError("name must not be empty")
        if not isinstance(guards, list) or not guards:
            raise ValueError("guards must be a non-empty list")
        body: Dict[str, Any] = {
            "name": name,
            "description": description or "",
            "guards": guards,
        }
        if schema is not None:
            body["schema"] = schema
        return self._request("POST", "/v1/spec", json_body=body)

    def validate_guard(
        self,
        guard_name: str,
        value: Any,
        *,
        kwargs: Optional[Dict[str, Any]] = None,
        num_reasks: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not guard_name:
            raise ValueError("guard_name must not be empty")
        if value is None:
            raise ValueError("value must not be None")
        body: Dict[str, Any] = {"value": value}
        if kwargs is not None:
            body["kwargs"] = kwargs
        if num_reasks is not None:
            body["num_reasks"] = int(num_reasks)
        return self._request(
            "POST", f"/v1/guards/{guard_name}/validate", json_body=body
        )

    def openai_chat_completions(
        self,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not isinstance(body, dict) or "messages" not in body:
            raise ValueError("body must be a chat-completion dict with 'messages'")
        return self._request(
            "POST", "/v1/openai/chat/completions", json_body=body
        )

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/health")

    # ----------------------------------------------------------- lifecycle

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:  # pragma: no cover
                pass


# ---------------------------------------------------------------- singleton

_singleton: Optional[GuardrailsEngine] = None
_singleton_lock = threading.Lock()


def get_guardrails_engine(
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> GuardrailsEngine:
    """Process-wide singleton accessor."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = GuardrailsEngine(
                api_key=api_key, base_url=base_url, client=client
            )
        return _singleton


def reset_guardrails_engine() -> None:
    """Reset the process-wide singleton (used by tests)."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None
