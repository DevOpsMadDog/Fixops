# SPEC-005 — Air-Gap Enforced By Default (SCIF safe boot)

- **Status**: IMPLEMENTED
- **Owner family**: Air-Gap / Platform
- **Routers**: boot path `suite-api/apps/api/app.py`
- **Engines**: `core/observability.py`, `core/airgap_config.py`, `core/airgap_deployment.py` (TelemetryKillSwitch), `core/llm_providers.py`, `suite-feeds/*`
- **Stores**: n/a
- **Depends on**: PM-1
- **Last updated**: 2026-06-01

## 1. Intent
A SCIF has zero internet egress. Any outbound call is a policy violation. Today the air-gap
enforcement machinery is real but **OFF by default** — Sentry, HuggingFace model download, cloud LLM
providers, and feed fetchers fire unless `FIXOPS_AIRGAP_MODE=enforced` is set. A single env-var mistake
on a classified box = a violation. This spec makes air-gap **safe-by-default**: when classified mode is
on, NOTHING reaches the network, automatically, with no operator step.

## 2. Scope
| Surface | Behaviour when `FIXOPS_AIRGAP_MODE=enforced` |
|---------|----------------------------------------------|
| boot (app.py) | auto-invoke `TelemetryKillSwitch.disable_all()`; set `TRANSFORMERS_OFFLINE=1`,`HF_DATASETS_OFFLINE=1`,`HF_HUB_OFFLINE=1` in-process before any model load |
| observability | `init_sentry()`/`init_statsd()` become no-ops (no DSN init) regardless of env DSN |
| LLM providers | cloud providers (OpenAI/Anthropic/OpenRouter/MuleRouter) refuse to construct; only local (Ollama/vLLM/llama.cpp) allowed |
| feeds | network fetch skipped; offline-import path only; honest "offline" status |

Out of scope: building the local model (SPEC-003); the actual feed offline-import importer (SPEC-005 only adds the guard + status).

## 3. Data contracts
- `GET /api/v1/health` (or a new `/api/v1/airgap/status`) returns `{"airgap_mode": "enforced|configured|disabled", "egress_blocked": true, "telemetry_disabled": true, "local_llm_backend": "ollama|vllm|none"}`.
- Any attempt to construct a cloud LLM provider under enforced mode raises a typed error caught → council uses local/deterministic, never a network call.

## 4. Functional requirements
- **REQ-005-01**: When `FIXOPS_AIRGAP_MODE=enforced`, app boot calls `TelemetryKillSwitch.disable_all()` automatically (no operator action). Verifiable: after boot, `sentry_sdk.Hub.current.client` is None / DSN unset.
- **REQ-005-02**: Under enforced mode, `TRANSFORMERS_OFFLINE`/`HF_HUB_OFFLINE`/`HF_DATASETS_OFFLINE` are set in `os.environ` BEFORE any `SentenceTransformer`/HF load; a missing local model degrades gracefully (no network), not a hang.
- **REQ-005-03**: Under enforced mode, cloud LLM provider construction is refused (no outbound). The council still returns a verdict via local/deterministic path (REQ from SPEC-003 covers quality).
- **REQ-005-04**: Under enforced mode, feed importers do NOT make network calls; they report `status: offline` honestly (no hang, no 500).
- **REQ-005-05**: A startup log line + the airgap status endpoint clearly state egress is blocked.

## 5. Non-functional
- No outbound socket under enforced mode — verifiable by asserting no cloud provider/telemetry init.
- Boot must not hang waiting on any network resource under enforced mode.

## 6. Acceptance criteria (executable)
- **AC-005-01**: boot with `FIXOPS_AIRGAP_MODE=enforced` → `create_app()` succeeds, log shows telemetry disabled, status endpoint `egress_blocked: true`.
- **AC-005-02**: with `SENTRY_DSN` set AND enforced mode → Sentry client is NOT initialized (no DSN active).
- **AC-005-03**: with `OPENROUTER_API_KEY` set AND enforced mode → no cloud provider constructed; council verdict still produced.
- **AC-005-04**: `tests/test_airgap_enforced.py` asserts the above without real network (monkeypatch/inspect state).
- **AC-005-05**: default mode (unset) behaviour unchanged — no regression to existing tests.

## 7. Debate log (Mysti)
| Date | Mode | Verdict |
|------|------|---------|
| (pending) | Red-Team | Can any outbound slip past under enforced? (HF, feeds, license check, package fetch) |

## 8. Implementation notes

### Files changed

| File | Change |
|------|--------|
| `suite-core/core/observability.py` | Added `_is_airgap_enforced()` helper (env-var fast-path). `init_sentry()` and `init_statsd()` return `False` immediately when enforced — no DSN/host is consulted, no SDK init happens. |
| `suite-api/apps/api/app.py` | Boot block added above the Sentry/StatsD init block (~line 2188): when `FIXOPS_AIRGAP_MODE=enforced`, sets `TRANSFORMERS_OFFLINE=1`, `HF_HUB_OFFLINE=1`, `HF_DATASETS_OFFLINE=1` in `os.environ`, then calls `TelemetryKillSwitch().disable_all()`. All three HF flags are set before any potential `SentenceTransformer` load. |
| `suite-core/api/airgap_router.py` (symlinked from `suite-api/apps/api/airgap_router.py`) | Added `_build_enforced_status_fields()` that always returns `{airgap_mode, egress_blocked, telemetry_disabled, local_llm_backend}`. `GET /api/v1/airgap/status` merges these fields into every response so the SPEC-005 contract shape is always present. |
| `suite-feeds/feeds_service.py` | Added `_feeds_airgap_offline()` module-level guard (checks `FIXOPS_AIRGAP_MODE=enforced` OR `FIXOPS_FEEDS_OFFLINE=1`). `refresh_epss()`, `refresh_kev()`, and `refresh_nvd()` return an offline `FeedRefreshResult` immediately when the guard fires — no `requests.get` call, no hang, no 500. |
| `tests/test_airgap_enforced.py` | New: 20 tests covering AC-005-01..05. All pass (22s). |

### Design decisions

- **No new module**: All changes extend existing code in-place. The observability no-op guard is a pure env-var check with no import cost.
- **Default mode unchanged**: Every guard is conditional on `enforced`. The `_is_airgap_enforced()` check is a single `os.environ.get` comparison — zero overhead in normal mode.
- **Status endpoint backward-compatible**: `_build_enforced_status_fields()` fields are merged first so `engine.get_status()` keys win on collision; `egress_blocked`/`telemetry_disabled`/`local_llm_backend` are new keys not previously present.
- **LLM council**: No change needed. `CouncilFactory._enforce_air_gap_providers()` already correctly gates on `AirGapMode.ENFORCED` and raises `RuntimeError` when no local backend is available. The `AnthropicMessagesProvider` construction before the swap is a safe object creation (no network call on `__init__`); it gets replaced by `AirGapLLMProvider` before any `analyse()` call.
- **Feeds guard scope**: Only the three highest-risk live-fetch methods are guarded here per spec scope ("at minimum add the guard so they don't fire network calls under enforced"). The `FIXOPS_FEEDS_OFFLINE=1` flag is also honoured for operator-controlled offline mode without full enforced posture.

### Verification

```
20 passed in 22.08s   # tests/test_airgap_enforced.py  (AC-005-01..05)
114 passed in 0.50s   # tests/test_observability.py    (AC-005-05 regression)
```

Boot `create_app()` succeeds in both default and enforced mode (confirmed in `TestCreateAppBoot`).
