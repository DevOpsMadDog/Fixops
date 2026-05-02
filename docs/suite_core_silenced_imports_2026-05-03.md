# suite-core/core Silenced-Imports Triage — 2026-05-03

Read-only follow-up to the `app.py` triage in `60a8ea9e`. AST-walked every
`try / except (ImportError|ModuleNotFoundError|Exception)` block in
`suite-core/core/*.py` and attempted each guarded `import` / `from … import …`
in isolation against the project's real `sys.path` (sitecustomize-augmented).

## Scope

| Metric | Count |
|---|---|
| `.py` files scanned in `suite-core/core/` | **728** |
| Total silenced imports (raw) | **1,164** |
| Unique import statements | **344** |
| OK (resolves cleanly today) | **297** |
| Broken unique statements | **47** |

Categories of breakage:

| Category | Count | Meaning |
|---|---|---|
| `ModuleNotFoundError` (third-party not installed) | 20 | Optional dep — guard is correct, but unused if dep never lands |
| `ModuleNotFoundError` (internal module missing) | 7 | DEAD code path — module was deleted/moved and guard now hides bitrot |
| `AttributeError` (symbol missing from real module) | 18 | Module exists, but the imported name was renamed/removed |
| `TYPO` (wrong package prefix) | 2 | Same class as `c96dba09` — `suite_core.X` vs `core.X` |

## Top broken (sorted by occurrence)

| # | Hits | File:line | Statement | Bucket |
|---|---|---|---|---|
| 1 | 3 | `report_generator.py:L337` | `from core.compliance_engine import ComplianceEngine` | ATTR — class renamed/removed |
| 2 | 2 | `intelligent_security_engine.py:L810` | `from feeds.feeds_service import FeedsService` | DEAD — module gone |
| 3 | 2 | `task_queue.py:L439` | `from core.micro_pentest import MicroPentestEngine` | ATTR — symbol gone |
| 4 | 2 | `quantum_crypto.py:L276` | `import dilithium` | MISSING DEP — PQ crypto SDK |
| 5 | 2 | `quantum_crypto.py:L286` | `import oqs` | MISSING DEP — liboqs Python |
| 6 | 2 | `unified_dashboard.py:L198` | `from core.threat_intel_aggregator import ThreatIntelAggregator` | DEAD — module gone |
| 7 | 2 | `graphql_schema.py:L593` | `from core.compliance_automation import get_compliance_automation` | ATTR — fn gone |
| 8 | 1 | `cli.py:L3946` | `from risk.reachability.models import GitRepository` | DEAD — submodule gone |
| 9 | 1 | `unified_dashboard.py:L121` | `from core.sla_tracker import SLATracker` | DEAD |
| 10 | 1 | `unified_dashboard.py:L181` | `from core.incident_tracker import IncidentTracker` | DEAD |
| 11 | 1 | `report_scheduler.py:L474` | `from core.security_posture_advisor import SecurityPostureAdvisor` | DEAD |
| 12 | 1 | `deployment_manager.py:L583` | `from trustgraph.store import KnowledgeStore` | DEAD — `trustgraph.store` not present (now `trustgraph.knowledge_store`?) |
| 13 | 1 | `compliance_engine.py:L958` | `from core.scanner_parsers import get_latest_summary` | ATTR — helper renamed |
| 14 | 1 | `aws_security_hub.py:L422` | `from core.scanner_parsers import SecurityHubNormalizer` | ATTR — class gone |
| 15 | 1 | `pipeline_orchestrator.py:L655` | `from risk.forecasting import compute_exploit_probability` | ATTR — fn renamed |
| 16 | 1 | `feed_correlator.py:L293` | `from feeds.abuseipdb.importer import get_by_cve` | ATTR — fn renamed |
| 17 | 1 | `feed_correlator.py:L306` | `from feeds.otx.importer import get_by_cve` | ATTR — fn renamed |
| 18 | 1 | `autofix_engine.py:L1283` | `from core.material_change_detector import get_velocity_tracker, get_detector` | ATTR |
| 19 | 1 | `air_gap_bundle_engine.py:L76` | `from core.trustgraph_event_bus import EmitEvent as _EmitEvent` | ATTR — `EmitEvent` renamed (likely `emit_event`) |
| 20 | 1 | `brain_pipeline.py:L881` | `from core.attack_path_engine import blast_radius as _blast_radius` | ATTR — fn renamed |

(See `/tmp/import_audit_categorized.json` for the full 47-entry list.)

## Recommendations (3 actionable buckets)

### 1. DELETE (7 statements, ~10 lines saved across 5 files)

Internal modules that never resolve under any sys.path. The guarded fallback is
permanent, so the `try` arm is unreachable code. Safe to remove the `try` arm
and unindent the `except` body, identical pattern to Wave-A in `60a8ea9e`.

Targets: `unified_dashboard.py` (4 entries), `intelligent_security_engine.py`,
`report_scheduler.py`, `deployment_manager.py`, `cli.py`.

### 2. FIX-IMPORT (18 statements — symbol renamed)

Module exists, the imported *name* changed. Each is a 1-line edit (or delete if
the consumer no longer uses the symbol). High-value fixes:

- `core.compliance_engine.ComplianceEngine` (3 callers) — likely renamed; grep public API.
- `core.scanner_parsers.{get_latest_summary, SecurityHubNormalizer}` — parsers refactor.
- `core.trustgraph_event_bus.EmitEvent` — case-mismatch on the publish helper.
- `core.attack_path_engine.blast_radius` — Brain Pipeline step 11 reachability.
- `risk.forecasting.compute_exploit_probability` — risk-scoring callsite.

### 3. INSTALL DEP or REMOVE FEATURE (20 statements)

Real optional features. Decide per feature whether to ship the dep or retire the path:

- **Quantum crypto** (`dilithium`, `oqs`, `dilithium_py`) — 4 sites in `quantum_crypto.py` + `crypto.py`. Either pin the deps in `requirements.txt` or retire the PQ-signature claim.
- **Celery/task_queue** — 1 site. Project uses in-process queues; recommend deleting the celery branch.
- **chromadb / pomegranate / mchmm / river / headroom** — vector store and probabilistic-ML alts. Retire (not used elsewhere) or add to requirements.
- **llm_guard** — 4 import sites in `llm_guard_service.py`. We already ship our own guards via `core.aidefence_*`; recommend retiring the llm_guard fallback.
- **google.cloud.{storage, securitycenter}**, **google.oauth2.service_account** — GCP connectors. Already gated by feature flag; safe to leave.
- **sentry_sdk** — observability. Optional; leave guard.

## Top-3 priority moves

1. **Fix `core.trustgraph_event_bus.EmitEvent`** in `air_gap_bundle_engine.py:L76` — the rest of the codebase publishes via `emit_event` lowercase, so airgap bundles are silently NOT broadcasting to TrustGraph today (matches the 38.4% wired number from CLAUDE.md).
2. **Fix `core.attack_path_engine.blast_radius`** in `brain_pipeline.py:L881` — Step-11 reachability falls back silently. Pipeline still runs but loses blast-radius scoring.
3. **Delete 7 DEAD internal imports** (Wave-D-ready, ~30-line PR, zero risk) — kills the bitrot warnings already emitted by `unified_dashboard.py` and friends.

Everything else is sprint-able alongside the 29 deferred empty-endpoints in
`docs/empty_endpoints_triage_2026-04-26.md`.
