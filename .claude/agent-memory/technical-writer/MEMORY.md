# Technical Writer Memory

## Key File Paths
- API entry point: `suite-api/apps/api/app.py` (2,742 LOC, 34 router mounts)
- Router files: `**/*_router.py` + non-standard across 6 suite directories (72 total router files)
- Brain Pipeline: `suite-core/core/brain_pipeline.py` (1,161 LOC, 12 steps)
- AutoFix Engine: `suite-core/core/autofix_engine.py` (1,260 LOC, 10 fix types)
- MPTE Engine: `suite-core/core/micro_pentest.py` (2,054 LOC, 19 phases)
- Scanner Parsers: `suite-core/core/scanner_parsers.py` (700 LOC, 15 normalizers)
- Identity doc: `docs/CTEM_PLUS_IDENTITY.md` (canonical reference)
- CEO Vision: `docs/CEO_VISION.md` (north-star)

## API Surface (Updated 2026-03-03 v4.0, VERIFIED via grep)
- 781 endpoints mounted total (764 @router + 8 sandbox_router + 5 logs_router + 25 @app - 21 unmounted)
- 802 total in codebase (781 mounted + 21 unmounted mpte_integration.py)
- 72 router files + 2 dynamic routers (sandbox_verifier.py, detailed_logging.py)
- 77+ unique route prefixes
- 6 suites (VERIFIED via grep 2026-03-03): suite-api (238 mounted), suite-core (253), suite-attack (106), suite-feeds (31), suite-evidence-risk (56), suite-integrations (59)
- Dynamic routers: sandbox_verifier.py creates sandbox_router (8 endpoints), detailed_logging.py creates logs_router (5 endpoints)
- Non-standard routers (in @router count): decisions.py (6), nerve_center.py (9), business_context_enhanced.py (6), oss_tools.py (8)
- THESE FILES EXIST: health.py (4), routes/enhanced.py (4), reachability/api.py (7) — all mounted
- Unmounted standalone: suite-api/apps/mpte_integration.py (21 endpoints, NOT in app.py)
- Auth: API Key (X-API-Key) + JWT Bearer + role scopes

## Document Organization
- API docs grouped by CTEM lifecycle: Discover → Validate → Remediate → Comply → Intelligence → Platform → Vision Engines
- Vision Engines section: Self-Learning V8 (19ep), Quantum Crypto V6 (6ep), Zero-Gravity V9 (7ep), AI Agent V4 (7ep)
- Architecture uses Mermaid diagrams (system overview, data flow, integration)
- README hero must reflect CTEM+ positioning with scanner/parser/endpoint counts
- CHANGELOG uses Keep a Changelog format with Day 1/Day 2/Day 3 sub-sections per sprint
- API_REFERENCE.md v4.0: 2,420 lines, 41 curl examples, 17 major sections + 4 appendices (v4.0 is current on disk)

## Router Files That Are Often Undercounted (VERIFIED v3.1)
- attack_sim_router.py: 13 endpoints (often documented as 5)
- vuln_discovery_router.py: 11 endpoints (often documented as 5)
- deduplication_router.py: 20 endpoints (often documented as 4)
- exposure_case_router.py: 10 endpoints (often documented as 5)
- predictions_router.py: 10 endpoints (often documented as 4)
- algorithmic_router.py: 11 endpoints (often documented as 3)
- agents_router.py: 32 endpoints (largest router)
- collaboration_router.py: 23 endpoints (often documented as 3 — WORST gap found v3.1)
- bulk_router.py: 13 endpoints (often documented as 3)
- marketplace_router.py: 14 endpoints (often documented as 4)
- reports_router.py: 14 endpoints (often documented as 4)
- audit_router.py: 14 endpoints (often documented as 4)
- policies_router.py: 11 endpoints (often documented as 5)
- fail_router.py: 10 endpoints — USES /score paths NOT /scenarios
- mpte_orchestrator_router.py: 8 endpoints (often completely omitted)
- teams_router.py: 8 endpoints (often documented as 5)

## Conventions
- Always verify endpoint paths against actual router files (grep for @router decorators)
- app.py mounts routers with prefix overrides — check both router prefix AND app.py mount
- Evidence routers get `/api/v1` prefix override in app.py mount
- Scanner routers require `attack:execute` scope
- Evidence routers require `read:evidence` scope
- Every router has both /health and /status endpoints (added Sprint 2 Day 2)
- Backend-hardener adds security fixes that need documenting — check their status file
- reachability router is conditionally mounted (try/except in app.py)

## Document Catalog (Complete as of Sprint 2 Day 3)
- `docs/API_REFERENCE.md` — v4.0, 2,420 lines, 781 endpoints, 41 curl examples
- `docs/ARCHITECTURE.md` — 304 lines, Mermaid diagrams, 6-suite architecture
- `docs/USER_GUIDE.md` — v1.0, 1,022 lines, 15 sections (quickstart thru troubleshooting)
- `docs/INVESTOR_BRIEF.md` — v1.0, 323 lines (exec summary, TAM/SAM/SOM, competitor matrix)
- `docs/CTEM_PLUS_IDENTITY.md` — Canonical identity doc (8 scanners, 12-step pipeline)
- `docs/CEO_VISION.md` — North-star (10 pillars, business model)
- `CHANGELOG.md` — Keep a Changelog format, Sprint 1 + Sprint 2 Day 1-3
- `README.md` — 1,074 lines, CTEM+ hero, 781 endpoint badge, documentation table

## Sprint Board Location
- `.claude/team-state/sprint-board.json` — update status after completing tasks
- Always append to `decisions.log` and `context_log.md` after runs

## Endpoint Count Method (Updated v4.0)
- `grep -r '@router\.\(get\|post\|put\|delete\|patch\)' --include="*.py"` across all suite dirs → 764
- Also check: `sandbox_verifier.py` uses `@sandbox_router.` → 8 endpoints
- Also check: `detailed_logging.py` uses `@logs_router.` → 5 endpoints
- Add @app endpoints from app.py separately → 25 endpoints
- Non-standard files to check: decisions.py, nerve_center.py, business_context_enhanced.py, oss_tools.py
- Files that DO exist: health.py (4), routes/enhanced.py (4), reachability/api.py (7) — ALL are mounted
- mpte_integration.py exists but is NOT mounted — subtract 21 from total
- suite-evidence-risk has 56 @router endpoints (corrected from 53 in v3.1)
- Total formula: 764 + 8 + 5 + 25 - 21 = 781 mounted endpoints
