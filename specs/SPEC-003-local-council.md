# SPEC-003 — Local LLM Council (real air-gap inference, not heuristics)

- **Status**: IMPLEMENTED
- **Owner family**: Council / Learning
- **Engines**: `core/llm_council.py`, `core/llm_providers.py` (AirGapLLMProvider), `core/airgap_config.py` (LocalLLMRouter), `core/llm_learning_loop.py`, `scripts/llm_distill_train.py`
- **Depends on**: SPEC-005 (air-gap), PM-1/PM-4
- **Last updated**: 2026-06-01

## 1. Intent
In a SCIF (no cloud), today the council falls back to `DeterministicLLMProvider` = a CVSS→action lookup
(cost_usd=0, confidence 0.5). That is not worth $100K. This spec makes the air-gap council do **real
local inference** against a local backend (Ollama / vLLM / llama.cpp) when one is present, so verdicts
are genuine model reasoning — and honestly degrade (clearly-labelled heuristic) when no local model is
available. Also: lower the distillation trigger + make the training entrypoint runnable so a customer
can produce their own fine-tuned model (the training RUN is operator infra; the WIRING is this spec).

## 2. Scope
- `AirGapLLMProvider.analyse()` performs REAL inference via the detected local backend (LocalLLMRouter).
- Council uses AirGapLLMProvider (not DeterministicLLMProvider) when a local backend responds.
- Honest labelling: every verdict carries `source` = `local_model:<backend>:<model>` | `heuristic` and
  `is_real_inference: bool`. Heuristic only when NO local backend.
- Distillation: lower threshold (5k), `scripts/llm_distill_train.py` documented runnable; learning loop
  default-on in non-airgap; honest about "no trained adapter yet".
Out of scope: actually executing a GPU training run (operator infra); shipping a model file.

## 3. Data contracts
Council verdict gains: `{"source": "local_model:ollama:qwen2.5|heuristic", "is_real_inference": bool, "model": str|null}`.
- local backend present → real inference, `is_real_inference: true`.
- none → heuristic, `is_real_inference: false`, reasoning explicitly says "heuristic, no local model".

## 4. Functional requirements
- **REQ-003-01**: When LocalLLMRouter.detect_available_backend() finds Ollama/vLLM/llama.cpp, AirGapLLMProvider.analyse() calls it for a REAL completion (prompt → model → parsed verdict), not the heuristic table.
- **REQ-003-02**: Council selects AirGapLLMProvider over Deterministic when a local backend is available (air-gap enforced or not).
- **REQ-003-03**: Every verdict is HONESTLY labelled: is_real_inference + source + model. A heuristic verdict must NOT claim to be a model verdict.
- **REQ-003-04**: No local backend → graceful, clearly-labelled heuristic (current behaviour, but labelled honestly) — never a hang, never a fake "model" claim.
- **REQ-003-05**: Distillation threshold lowered to a runnable value + `scripts/llm_distill_train.py` documents the exact command; learning loop captures real pairs (cost_usd>0 guard stays).
- **REQ-003-06**: Air-gap safe — local inference makes no internet call.

## 5. Non-functional
- Local inference timeout-bounded; backend-down → heuristic fallback, never hang.
- No fabricated confidence — heuristic confidence labelled as such.

## 6. Acceptance criteria (executable)
- **AC-003-01**: with a STUB local backend (monkeypatch LocalLLMRouter to return a fake Ollama client returning a canned completion), council verdict has `is_real_inference: true`, `source: local_model:...`, and reasoning from the stubbed completion (proves the inference path).
- **AC-003-02**: with NO backend, verdict has `is_real_inference: false`, `source: heuristic`, reasoning explicitly labelled heuristic — and a verdict is still produced (no hang).
- **AC-003-03**: council prefers the local provider when a backend is present (assert provider selection).
- **AC-003-04**: `scripts/llm_distill_train.py --help` (or dry-run) runs; threshold constant lowered + documented.
- **AC-003-05**: `tests/test_local_council.py` covers AC-003-01..03; boot create_app() succeeds; no regression in tests/test_phase3_llm_council.py.

## 7. Debate log (internal role-debate)
| Date | Mode | Verdict |
|------|------|---------|
| (after build) | Red-Team | can a heuristic verdict masquerade as real inference? can local inference be coerced to call out? |

## 8. Implementation notes

### Files changed

| File | Change |
|------|--------|
| `suite-core/core/llm_providers.py` | `LLMResponse` dataclass gains `source: str`, `is_real_inference: bool`, `model: Optional[str]`. `BaseLLMProvider.analyse()` (heuristic path) sets `is_real_inference=False`, `source="heuristic"`, and embeds `[heuristic: no local or cloud model available]` in reasoning. `AirGapLLMProvider.analyse()` success path sets `is_real_inference=True`, `source=local_model:<backend>:<model>`, `model=<model>`. Failure/timeout path keeps `is_real_inference=False` and labels reasoning with `[heuristic: local model unavailable — <ExcType>]`. `_response_from_payload()` infers provenance from metadata `mode` key for cloud providers that don't explicitly inject it. |
| `suite-core/core/llm_council.py` | `CouncilFactory` gains `_try_build_airgap_provider()` and `_build_local_council_if_available()`. The latter probes `LocalLLMRouter.detect_available_backend()` and returns a 1-or-2-member `LLMCouncilEngine` using `AirGapLLMProvider` when a backend is found. `create_security_council()` (auto preset) calls this before any cloud/key-based selection — satisfying REQ-003-02 without disrupting cloud paths. `_query_member()` now copies `source` and `is_real_inference` from `LLMResponse` into `MemberAnalysis.metadata` so the provenance is visible at the verdict layer. |
| `suite-core/core/llm_learning_loop.py` | Added `DISTILLATION_THRESHOLD: int = 5000` constant (lowered from 10 000) with explanatory comment. The existing `cost_usd > 0` guard in `_on_event()` remains unchanged — it still rejects `$0` heuristic verdicts before they reach the training set. |
| `scripts/nightly_progress_check.sh` | `THRESHOLD=5000` (was 10000), annotated with SPEC-003 REQ-003-05 reference. |
| `tests/test_local_council.py` | New: covers AC-003-01 (stub Ollama → real inference verdict), AC-003-02 (no backend → labelled heuristic), AC-003-03 (factory prefers local), AC-003-04 (threshold + dry-run), and honest-labelling invariant tests. 18/18 pass. |

### Design decisions

**REQ-003-01 — Real inference path**: Rather than building a new HTTP client, `AirGapLLMProvider` already had a `chat()` method that calls the local backend. The only gap was that the success path did not populate `is_real_inference`/`source` on `LLMResponse`. Those fields were added to the dataclass and the two code paths (success / exception) now set them correctly.

**REQ-003-03/04 — Honest labelling**: The label is embedded in both `LLMResponse.source` (machine-readable) and in `LLMResponse.reasoning` (human-readable). This dual approach means the label survives serialisation — even if a consumer only logs `reasoning`, the heuristic origin is visible. A heuristic verdict can **never** carry `is_real_inference=True` because the only place that field is set True is the non-exception success path of `AirGapLLMProvider.analyse()`, which only runs after a real HTTP response is received and parsed.

**REQ-003-02 — Provider selection**: Added as an explicit early-return in `create_security_council()` before the cloud-key logic. The probe is fast (one HTTP GET to `localhost:11434/api/tags` with a 1.5 s timeout). When no backend is found, `_try_build_airgap_provider()` returns `None` and the existing selection logic runs unchanged — no regression for cloud deployments.

**REQ-003-05 — Threshold**: The constant lives in `llm_learning_loop.py` (the authoritative Python module for the learning loop) and in `nightly_progress_check.sh` (the bash operator script). Both updated to 5000. The `scripts/llm_distill_train.py` docstring already documents `--dry-run`; `--help` exits 0 by default via `argparse`.

**REQ-003-06 — No internet from AirGap**: Enforced by construction — `AirGapLLMProvider.chat()` calls only the URL produced by `LocalLLMRouter.build_chat_payload()`, which always generates a `localhost`/LAN endpoint. The AC-003 test `test_no_internet_call_from_airgap_provider` asserts all POSTed URLs contain `localhost`.

### Verification

```
PYTHONPATH=".:suite-core:..." pytest tests/test_local_council.py -v --timeout=30
# 18 passed in 2.06s

PYTHONPATH=".:suite-core:..." pytest tests/test_phase3_llm_council.py -v --timeout=30
# all passed (no regression)
```
