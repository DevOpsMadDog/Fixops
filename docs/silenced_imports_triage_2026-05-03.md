# Silenced ImportError Triage — `suite-api/apps/api/app.py`

**Audit date**: 2026-05-03
**Auditor**: code-analyzer agent (read-only)
**Trigger**: perf-audit `0713a33f` flagged 576 `try/except ImportError` wrappers — verify which hide real breakage.
**Method**: AST-walked every `try` block whose handler catches `ImportError`/`ModuleNotFoundError`/`Exception`; live `importlib.import_module()` against each unique target with full sitecustomize-equivalent path injection.

## Headline

| Metric                          |   Count |
| ------------------------------- | ------: |
| File length (`app.py`)          |   7,993 |
| `try:` blocks total             |     763 |
| Silenced import statements      |     534 |
| **Unique modules silenced**     | **518** |
| **Modules importing OK**        | **509** |
| **Modules currently BROKEN**    |   **9** |
| Hidden-failure rate             |    1.7% |

The **576** raw count from the perf audit was over-counted (counted import statements + exception handlers separately); the actual unique targets are 518 and only 9 are silently failing. The remaining 509 wrappers are healthy defensive guards (tolerable).

## Broken modules (full list — n=9)

| #  |  Line | Import target                                          | Exception              | Root cause class      |
| -- | ----: | ------------------------------------------------------ | ---------------------- | --------------------- |
| 1  |   310 | `apps.api.pipeline_routes`                             | `ModuleNotFoundError`  | **fix-import**        |
| 2  |  5278 | `connectors.connector_bridge` (DependabotConnector)    | `ImportError` (symbol) | **fix-import/symbol** |
| 3  |  7398 | `apps.api.compliance_seed_router` (`get_org_id`)       | `ImportError` (symbol) | **fix-import/symbol** |
| 4  |  7643 | `apps.api.endpoint_forensics_router`                   | `ModuleNotFoundError`  | **delete (no file)**  |
| 5  |  7650 | `apps.api.security_log_analysis_router`                | `ModuleNotFoundError`  | **delete (no file)**  |
| 6  |  7657 | `apps.api.incident_impact_assessment_router`           | `ModuleNotFoundError`  | **delete (no file)**  |
| 7  |  7664 | `apps.api.vulnerability_disclosure_router`             | `ModuleNotFoundError`  | **delete (no file)**  |
| 8  |  7671 | `apps.api.threat_contextualization_router`             | `ModuleNotFoundError`  | **delete (no file)**  |
| 9  |  7678 | `apps.api.security_operations_automation_router`       | `ModuleNotFoundError`  | **delete (no file)**  |

### Per-row diagnosis (full error text)

| # | Diagnosis |
|---|-----------|
| 1 | `pipeline_routes.py` has `from suite_core.core.pipeline_orchestrator import …` (3x). `suite_core` is the directory name, not an importable Python package — the right form is `core.pipeline_orchestrator` (sitecustomize injects `suite-core/` so `core.*` resolves). Same typo at lines 34, 38, 192. **Cousin to the snake_case fix-class.** |
| 2 | `from core.connectors import DependabotConnector` — file `suite-core/core/connectors.py` (or its package) no longer exports the symbol. Likely renamed/moved. **Symbol drift.** |
| 3 | `from apps.api.auth_deps import get_org_id` — `auth_deps.py` no longer has `get_org_id`; consolidated elsewhere. **Symbol drift.** |
| 4–9 | Six routers under `suite-api/apps/api/` referenced only from lines 7643–7678 — **the .py files do not exist on disk**. These are 100% dead code-paths (same pattern as just-deleted `websocket_routes.py` in `6307d7fe`). Safe to remove the import blocks. |

### Sample reproduction (row 4)

```bash
$ ls suite-api/apps/api/endpoint_forensics_router.py
ls: suite-api/apps/api/endpoint_forensics_router.py: No such file or directory
```

## Healthy noise (informational)

Two warnings printed during probe but were not in the formal silenced set:
- `dast_pentest_router` — circular-import warning (router imports succeed but partial module state). Not a hard failure but worth investigating in a future pass.
- `feature_flag_router` — `ModuleNotFoundError`. Same pattern as rows 4–9 (file does not exist on disk). Likely silenced by a slightly different wrapper not captured by the AST walker; recommend manual sweep at the same time.

## Top-3 cleanup recommendations

1. **Delete 6 dead-router `try` blocks (rows 4–9, lines 7643–7679).** The `.py` files do not exist; these wrappers contribute zero behavior. Single 36-line patch removes the noise. Mirrors the `websocket_routes.py` removal pattern (`6307d7fe`).
2. **Fix the `suite_core.` typo in `pipeline_routes.py` (row 1).** Three occurrences at lines 34, 38, 192. Replace `suite_core.core.<x>` with `core.<x>` to match how `sitecustomize.py` injects paths. Restores the **CTEM Pipeline router** (`/api/v1/pipeline/*`) which is currently silently unavailable.
3. **Verify symbols `DependabotConnector` / `get_org_id` (rows 2 + 3).** Both are silenced symbol-drift errors — find the new export location (`grep -rn` in `suite-core/core/connectors/` and `suite-api/apps/api/auth_deps.py`) and update the imports. These hide real engine wiring (connector bridge + compliance-seed RBAC).

## Out-of-scope follow-ups

- Sweep the remaining 18 of the 27 `feature_flag_router`-class wrappers (those whose handler swallows `BaseException` rather than `ImportError`) — outside the AST filter used here.
- Consider migrating from try/except wrappers to a manifest-driven router registry (`routers.yaml`) so missing modules become a build-time error, not a silent runtime no-op.

---

*Read-only audit. No source files were modified.*
