"""ALDECI PyRIT Engine.

Thin pass-through client for **Microsoft PyRIT** (Python Risk Identification
Tool for AI) — invoked via a separate Python service (the *PyRIT runner*)
because PyRIT itself requires GPU + heavy ML deps and is not embedded in
ALDECI's primary process.

The runner exposes a small REST API the ALDECI router calls into. This
engine is a thin httpx wrapper around it.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env var is unset the engine reports ``status="unavailable"`` and
all action endpoints return HTTP 503.

Environment variables
---------------------
PYRIT_RUNNER_URL  — base URL of the PyRIT runner service,
                    e.g. ``http://pyrit-runner:8090``
PYRIT_API_KEY     — optional bearer token for the runner

The engine is a process-level singleton accessible via
:func:`get_pyrit_engine`.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)


_ENDPOINT_CATALOG: List[str] = [
    "/api/v1/attacks/run",
    "/api/v1/converters",
    "/api/v1/scorers",
    "/api/v1/orchestrators",
    "/api/v1/runs/{run_id}/results",
    "/api/v1/datasets/seed-prompts",
]

# Built-in catalogs surfaced when the runner is unavailable so that
# /converters, /scorers, /orchestrators still return a structurally valid
# (but informational) catalog. The runner — when configured — replaces these
# with the live, version-accurate catalog.
_BUILTIN_ORCHESTRATORS: List[Dict[str, Any]] = [
    {
        "name": "PromptSendingOrchestrator",
        "description": "Sends single-turn prompts to the target with optional converters/scorers.",
        "parameters": [],
        "requires_attack_strategy": False,
        "supports_multi_turn": False,
    },
    {
        "name": "RedTeamingOrchestrator",
        "description": "Multi-turn adversarial dialogue driven by a red-team chat target.",
        "parameters": [
            {"name": "attack_strategy", "type": "str", "default": None, "required": True},
            {"name": "max_turns", "type": "int", "default": 5, "required": False},
        ],
        "requires_attack_strategy": True,
        "supports_multi_turn": True,
    },
    {
        "name": "XPIAOrchestrator",
        "description": "Cross-domain prompt injection attack orchestrator.",
        "parameters": [],
        "requires_attack_strategy": True,
        "supports_multi_turn": False,
    },
    {
        "name": "ScoringOrchestrator",
        "description": "Re-scores prior conversations with new scorers.",
        "parameters": [],
        "requires_attack_strategy": False,
        "supports_multi_turn": False,
    },
    {
        "name": "TreeOfAttacksOrchestrator",
        "description": "Tree-of-Attacks-with-Pruning (TAP) jailbreak search.",
        "parameters": [
            {"name": "branching_factor", "type": "int", "default": 3, "required": False},
            {"name": "depth", "type": "int", "default": 5, "required": False},
        ],
        "requires_attack_strategy": True,
        "supports_multi_turn": True,
    },
    {
        "name": "FuzzerOrchestrator",
        "description": "Genetic-algorithm jailbreak fuzzer (GPTFuzzer-style).",
        "parameters": [],
        "requires_attack_strategy": False,
        "supports_multi_turn": False,
    },
    {
        "name": "CrescendoOrchestrator",
        "description": "Multi-turn Crescendo attack — gradually escalates harmful intent.",
        "parameters": [
            {"name": "max_turns", "type": "int", "default": 10, "required": False},
        ],
        "requires_attack_strategy": True,
        "supports_multi_turn": True,
    },
    {
        "name": "PAIROrchestrator",
        "description": "Prompt Automatic Iterative Refinement jailbreak.",
        "parameters": [
            {"name": "n_streams", "type": "int", "default": 5, "required": False},
            {"name": "max_iterations", "type": "int", "default": 5, "required": False},
        ],
        "requires_attack_strategy": True,
        "supports_multi_turn": True,
    },
]

_BUILTIN_CONVERTERS: List[Dict[str, Any]] = [
    {"name": "Base64Converter", "description": "Base64-encode the prompt.", "parameters": [], "category": "encoding"},
    {"name": "StringJoinConverter", "description": "Join string with a separator (e.g. spaces, dashes).", "parameters": [{"name": "join_value", "type": "str", "default": "-", "required": False}], "category": "formatting"},
    {"name": "ROT13Converter", "description": "Apply ROT13 cipher.", "parameters": [], "category": "encoding"},
    {"name": "RandomCapitalLettersConverter", "description": "Randomly capitalize letters to evade keyword filters.", "parameters": [{"name": "percentage", "type": "float", "default": 0.5, "required": False}], "category": "formatting"},
    {"name": "UnicodeSubstitutionConverter", "description": "Substitute Latin chars with Unicode look-alikes.", "parameters": [], "category": "adversarial"},
    {"name": "ToxicSentenceGeneratorConverter", "description": "Augment prompt with adversarial toxic sentence.", "parameters": [], "category": "adversarial"},
    {"name": "TenseConverter", "description": "Rewrite prompt in a different tense.", "parameters": [{"name": "tense", "type": "str", "default": "past", "required": False}], "category": "persuasion"},
    {"name": "TranslationConverter", "description": "Translate prompt into a target language.", "parameters": [{"name": "language", "type": "str", "default": "fr", "required": True}], "category": "translation"},
    {"name": "VariationConverter", "description": "Generate semantic variations using an LLM.", "parameters": [], "category": "adversarial"},
    {"name": "PersuasionConverter", "description": "Rephrase as a persuasive appeal.", "parameters": [{"name": "persuasion_technique", "type": "str", "default": "authority", "required": False}], "category": "persuasion"},
    {"name": "SearchReplaceConverter", "description": "Search & replace tokens in the prompt.", "parameters": [{"name": "old_value", "type": "str", "default": None, "required": True}, {"name": "new_value", "type": "str", "default": None, "required": True}], "category": "formatting"},
    {"name": "TextToHexConverter", "description": "Hex-encode the prompt text.", "parameters": [], "category": "encoding"},
    {"name": "UnicodeReplacementConverter", "description": "Replace tokens with confusable Unicode.", "parameters": [], "category": "adversarial"},
    {"name": "MaliciousQuestionGeneratorConverter", "description": "Generate adversarial follow-up questions.", "parameters": [], "category": "jailbreak"},
    {"name": "SuffixAppendConverter", "description": "Append a known jailbreak suffix.", "parameters": [{"name": "suffix", "type": "str", "default": "", "required": True}], "category": "jailbreak"},
]

_BUILTIN_SCORERS: List[Dict[str, Any]] = [
    {"name": "SelfAskTrueFalseScorer", "description": "LLM scorer returning bool via self-ask.", "parameters": [{"name": "true_false_question", "type": "str", "default": None, "required": True}], "output_type": "bool"},
    {"name": "SubStringScorer", "description": "Returns true if substring appears in response.", "parameters": [{"name": "substring", "type": "str", "default": None, "required": True}], "output_type": "bool"},
    {"name": "HumanInTheLoopScorer", "description": "Pause for human reviewer.", "parameters": [], "output_type": "bool"},
    {"name": "SelfAskCategoryScorer", "description": "LLM scorer returning a category label.", "parameters": [{"name": "categories", "type": "list", "default": [], "required": True}], "output_type": "category"},
    {"name": "SelfAskScaleScorer", "description": "LLM scorer returning a numeric scale.", "parameters": [{"name": "min_value", "type": "float", "default": 0.0, "required": False}, {"name": "max_value", "type": "float", "default": 1.0, "required": False}], "output_type": "float"},
    {"name": "MarkdownInjectionScorer", "description": "Detects markdown-injection payloads in responses.", "parameters": [], "output_type": "bool"},
    {"name": "FloatScaleThresholdScorer", "description": "Wraps a float scorer + threshold to bool.", "parameters": [{"name": "threshold", "type": "float", "default": 0.5, "required": True}], "output_type": "bool"},
    {"name": "GandalfScorer", "description": "Lakera Gandalf challenge scorer.", "parameters": [{"name": "level", "type": "int", "default": 1, "required": False}], "output_type": "bool"},
]


class PyRITUnavailable(RuntimeError):
    """Raised when PYRIT_RUNNER_URL is not configured."""


class PyRITHTTPError(RuntimeError):
    """Raised when the PyRIT runner returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (400/401/403/404/409/422/429 pass through; everything
    else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class PyRITEngine:
    """Pass-through PyRIT runner client backed by ``httpx.Client``."""

    def __init__(
        self,
        runner_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 60.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._url = (
            runner_url if runner_url is not None else os.environ.get("PYRIT_RUNNER_URL", "")
        ).strip()
        self._api_key = (
            api_key if api_key is not None else os.environ.get("PYRIT_API_KEY", "")
        ).strip()
        self._timeout = timeout
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def runner_url_present(self) -> bool:
        return bool(self._url)

    @property
    def configured(self) -> bool:
        return self.runner_url_present

    def status(self) -> str:
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Microsoft PyRIT",
            "endpoints": list(_ENDPOINT_CATALOG),
            "pyrit_runner_url_present": self.runner_url_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise PyRITUnavailable(
                "PYRIT_RUNNER_URL must be set to invoke PyRIT runner endpoints"
            )

    def _build_url(self, path: str) -> str:
        base = self._url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        self._require_configured()
        url = self._build_url(path)
        try:
            resp = self._client.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "pyrit upstream error %s %s: %s",
                method,
                path,
                type(exc).__name__,
            )
            raise PyRITHTTPError(
                502, f"Upstream PyRIT runner request failed: {type(exc).__name__}"
            ) from exc

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise PyRITHTTPError(
            resp.status_code, f"PyRIT runner returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ ops

    def submit_attack(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "api/v1/attacks/run", json_body=body) or {}

    def get_run(self, run_id: str) -> Dict[str, Any]:
        return self._request("GET", f"api/v1/runs/{run_id}") or {}

    def get_run_results(
        self,
        run_id: str,
        include_history: bool = False,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"include_history": str(bool(include_history)).lower()}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        return self._request(
            "GET", f"api/v1/runs/{run_id}/results", params=params
        ) or {"results": [], "total": 0}

    def list_converters(self) -> Dict[str, Any]:
        if not self.configured:
            return {"converters": list(_BUILTIN_CONVERTERS)}
        try:
            return self._request("GET", "api/v1/converters") or {
                "converters": list(_BUILTIN_CONVERTERS)
            }
        except PyRITUnavailable:
            return {"converters": list(_BUILTIN_CONVERTERS)}

    def list_scorers(self) -> Dict[str, Any]:
        if not self.configured:
            return {"scorers": list(_BUILTIN_SCORERS)}
        try:
            return self._request("GET", "api/v1/scorers") or {
                "scorers": list(_BUILTIN_SCORERS)
            }
        except PyRITUnavailable:
            return {"scorers": list(_BUILTIN_SCORERS)}

    def list_orchestrators(self) -> Dict[str, Any]:
        if not self.configured:
            return {"orchestrators": list(_BUILTIN_ORCHESTRATORS)}
        try:
            return self._request("GET", "api/v1/orchestrators") or {
                "orchestrators": list(_BUILTIN_ORCHESTRATORS)
            }
        except PyRITUnavailable:
            return {"orchestrators": list(_BUILTIN_ORCHESTRATORS)}

    def list_seed_prompts(
        self,
        dataset_name: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if dataset_name is not None:
            params["dataset_name"] = dataset_name
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        return self._request(
            "GET", "api/v1/datasets/seed-prompts", params=params or None
        ) or {"prompts": [], "total": 0, "dataset_name": dataset_name}

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

_engine: Optional[PyRITEngine] = None
_engine_lock = Lock()


def get_pyrit_engine() -> PyRITEngine:
    """Return (or create) the process-wide PyRITEngine singleton.

    Lazily reads PYRIT_RUNNER_URL / PYRIT_API_KEY so tests that monkeypatch
    env before first call get a fresh engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = PyRITEngine()
    return _engine


def reset_pyrit_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
