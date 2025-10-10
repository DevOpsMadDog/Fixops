# Work-in-Progress Archive

The `WIP/` directory quarantines legacy or experimental surfaces that are no longer part of the unified stage-run workflow but are retained for reference. The table below summarises what moved and the rationale.

| New location | Previous path | Notes |
| --- | --- | --- |
| `WIP/code/backend_legacy/` | `backend/` | Historical Flask demo backend superseded by the canonical `core` + `apps` pipelines. |
| `WIP/code/enterprise_legacy/` | `enterprise/` | Full enterprise stack (API, DB, UI) retained for documentation but replaced by the streamlined blended services. |
| `WIP/code/fastapi_legacy/` | `fastapi/` | Early FastAPI experiments; keep isolated to avoid conflicting imports. |
| `WIP/code/perf_experiments/` | `perf/` | Performance benchmarks and notes that are not part of supported runtime paths. |
| `WIP/code/prototype_decision_api/` | `new_backend/` | Prototype decision API superseded by the new stage runner + ingest API flow. |
| `WIP/code/prototypes/` | `prototypes/` | Miscellaneous proof-of-concept pipelines; archived until individually reviewed. |
| `WIP/scripts/run_demo_steps_legacy.py` | `scripts/run_demo_steps.py` | Legacy multi-stage runner replaced by `python -m core.cli stage-run`. |
| `WIP/ui/frontend_akido_public/` | `frontend-akido-public/` | Marketing UI build not aligned with the current CLI/API demo experience. |
| `WIP/vendor/pydantic_stub/` | `pydantic/` | Local stub module for earlier experiments—kept out of import path. |
| `WIP/vendor/torch_stub/` | `torch/` | Lightweight torch placeholder used only in archived notebooks. |

By parking these assets under `WIP/`, we avoid accidental imports (enforced by `tests/test_no_wip_imports.py`) while keeping the material available for future reference or incremental migration work.
