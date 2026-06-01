# SPEC-017 — Full Brain-Pipeline on Ingest (config-gated, non-blocking)

- **Status**: IMPLEMENTED + VERIFIED (2026-06-02)
- **Owner family**: ASPM / Brain Pipeline / Orchestration
- **Routers**: `scanner_ingest_router.py` (upload + webhook), `wiz_router.py`, `prisma_router.py`, `blackduck_router.py`
- **Engines**: `brain_pipeline.py` (`BrainPipeline.run` / `PipelineInput`), `_index_findings_into_brain`
- **Stores**: Store B brain (`data/fixops_brain.db`), pipeline outputs
- **Depends on**: SPEC-001 (council enrichment), SPEC-016 (connectors→brain), SPEC-005 (air-gap), SPEC-003 (local council). Env: `FIXOPS_PIPELINE_ON_INGEST`
- **Last updated**: 2026-06-02

## 1. Intent (the why)
Today ingest (scanner upload/webhook + the SPEC-016 WIZ/Prisma/BlackDuck connectors) dedups, promotes to
findings, and indexes into the correlation brain — but the **12-step Brain Pipeline only runs when the caller
passes `pipeline=true`**, and the connectors never run it at all. So a SCIF customer's findings are correlated
but not automatically *enriched + verdicted* (reachability, blast-radius, council verdict). This spec makes the
full pipeline run automatically on ingest — **non-blocking and config-gated** — so every ingested finding gets
the same enrichment the moat promises, without slowing the ingest response or breaking air-gap deploys that
have no local LLM.

**Code-truth (2026-06-02):** `scanner_ingest_router.py` has `pipeline: bool = Form(False)` and runs
`BrainPipeline().run(PipelineInput(...))` synchronously when true (blocks the response). WIZ/Prisma/BlackDuck
routers call only `_promote_findings_to_issues` + `_index_findings_into_brain` — no pipeline.

## 2. Scope — behaviour
| Trigger | Behaviour | Auth | Tenant |
|---------|-----------|------|--------|
| ingest with `pipeline=true` (explicit) | run pipeline synchronously (unchanged) | api_key_auth | org |
| ingest with `FIXOPS_PIPELINE_ON_INGEST=1` (auto) | run pipeline in a **background thread** after the response | api_key_auth | org |
| ingest with neither | dedup+promote+brain-index only (unchanged default) | api_key_auth | org |
| connectors (wiz/prisma/blackduck) ingest | honor the same auto-gate via the shared helper | api_key_auth | org |

Out of scope: changing the synchronous `pipeline=true` contract; making auto-run the *default* (stays opt-in —
SCIF deploys without a local LLM must not have ingest silently spawn failing council calls); per-finding streaming.

## 3. Data contracts
```
ingest response gains:  "pipeline_dispatched": true|false   (true when the async run was scheduled)
                        "pipeline_result": {...}|null        (only populated on the synchronous pipeline=true path)
```
Auto (background) runs never appear in the HTTP response body — they are fire-and-forget; failures are logged, never 500.

## 4. Functional requirements
- **REQ-017-01**: A single shared helper `dispatch_pipeline_on_ingest(findings, org_id, source)` decides whether to run:
  runs in a daemon thread when `FIXOPS_PIPELINE_ON_INGEST` is truthy AND findings is non-empty; otherwise no-op.
- **REQ-017-02**: The background run never blocks or fails the ingest response (wrapped; logs on error).
- **REQ-017-03**: scanner-ingest upload + webhook call the helper (in addition to the existing explicit `pipeline=true` path).
- **REQ-017-04**: WIZ + Prisma + Black Duck `/ingest` call the helper after `_index_findings_into_brain`.
- **REQ-017-05**: The pipeline run is org-scoped — `PipelineInput`/source carry org_id so verdicts/enrichment stay tenant-isolated.
- **REQ-017-06**: Default OFF. With the env unset, behaviour is byte-for-byte unchanged (no new threads, no pipeline).

## 5. Non-functional requirements
- Latency: ingest response time unchanged when auto-run is on (work happens after the response, in a thread).
- Air-gap: when auto-run is on but no council/LLM is configured, the background pipeline fails *silently in its thread*
  (logged), never affecting the ingest caller — honest, no fake verdict.
- Resource: bounded — one daemon thread per ingest batch (not per finding); threads are short-lived.

## 6. Acceptance criteria (executable)
- **AC-017-01**: With `FIXOPS_PIPELINE_ON_INGEST` unset, ingest response has `pipeline_dispatched=false` and no BrainPipeline is constructed (patched BrainPipeline.run NOT called).
- **AC-017-02**: With `FIXOPS_PIPELINE_ON_INGEST=1`, a fake-findings ingest returns `pipeline_dispatched=true` and the (patched) BrainPipeline.run is invoked exactly once with the org's findings (assert via a thread-join/Event).
- **AC-017-03**: A raising BrainPipeline.run does NOT change the ingest status code (still 200/200) — failure contained.
- **AC-017-04**: WIZ `/ingest` with the env on dispatches the pipeline (patched run called) and still returns 200.
- **AC-017-05**: Beast smoke 756/756 + create_app boots; default-off path unchanged.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-02 | Author | Non-blocking + default-OFF + shared helper, after code-truth (sync pipeline=true blocks; connectors skip pipeline). |
| 2026-06-02 | SCIF-Accreditor | **APPROVE-WITH-CHANGES**: exception-catch is NOT an egress control → added explicit AIR-GAP HARD-CHECK (`is_airgap_enforced()` + `_local_llm_configured()`) that never constructs `BrainPipeline` when enforced+no-local-LLM; durable run records (started/completed/failed/skipped) close the ATO evidence gap; org_id carried into pipeline source. |
| 2026-06-02 | Red-Team | **APPROVE-WITH-CHANGES**: unbounded threads = DoS → process-global `BoundedSemaphore` (drop, never queue/block) + per-org token-bucket rate limit (economic/LLM-cost-DoS guard) + durable outcome store via `pipeline_run_stats()` (no silent loss). |
| 2026-06-02 | Resolution | Both APPROVE-WITH-CHANGES; all guards folded into `pipeline_on_ingest.py`. Default OFF. |

## 8. Implementation notes — IMPLEMENTED
`suite-api/apps/api/pipeline_on_ingest.py`: `dispatch_pipeline_on_ingest(findings, org_id, source)` with air-gap
hard-check + `BoundedSemaphore` + per-org token-bucket + durable `pipeline_runs.db` + `pipeline_run_stats()`.
Wired into scanner-ingest upload+webhook (response gains `pipeline_dispatched`) + wiz/prisma/blackduck `/ingest`.
Verified LIVE: 7 helper tests (disabled/enabled-runs-once/failure-contained/airgap-skip/airgap+local-LLM-runs/
rate-limit/stats) + WIZ HTTP dispatch (AC-017-04). 26/26 spec016+017 tests + 756/756 Beast smoke green; boot OK.
