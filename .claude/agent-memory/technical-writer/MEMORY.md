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

## API Surface (Updated 2026-03-02 v3.1, VERIFIED)
- 780 endpoints total (755 @router + 25 @app)
- 72 router files across 6 suites (verified via find)
- 77+ unique route prefixes
- 6 suites (VERIFIED via grep): suite-api (258), suite-core (248), suite-attack (106), suite-feeds (31), suite-evidence-risk (53), suite-integrations (59)
- NOTE: Other agents may report different counts — the grep-verified numbers above are authoritative
- Non-standard routers (INCLUDED in 755 count): decisions.py (6), nerve_center.py (9), business_context_enhanced.py (6), oss_tools.py (8)
- Non-existent files: health.py, routes/enhanced.py, reachability/api.py — DO NOT reference these
- Unmounted standalone: suite-api/apps/mpte_integration.py (21 endpoints, NOT in app.py)
- Auth: API Key (X-API-Key) + JWT Bearer + role scopes

## Document Organization
- API docs grouped by CTEM lifecycle: Discover → Validate → Remediate → Comply → Intelligence → Platform → Vision Engines
- Vision Engines section: Self-Learning V8 (18ep), Quantum Crypto V6 (5ep), Zero-Gravity V9 (6ep), AI Agent V4 (6ep)
- Architecture uses Mermaid diagrams (system overview, data flow, integration)
- README hero must reflect CTEM+ positioning with scanner/parser/endpoint counts
- CHANGELOG uses Keep a Changelog format with Day 1/Day 2/Day 3 sub-sections per sprint
- API_REFERENCE.md v3.1: 2,351 lines, 35+ curl examples, 85+ sections, 11 main + 4 appendices (v3.1 is current on disk)

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

## Document Catalog (Complete as of Sprint 2 Day 4)
- `docs/API_REFERENCE.md` — v3.2, 2,321 lines, 780 endpoints, 34+ curl examples
- `docs/ARCHITECTURE.md` — 304 lines, Mermaid diagrams, 6-suite architecture
- `docs/USER_GUIDE.md` — v1.0, 1,022 lines, 15 sections (quickstart thru troubleshooting)
- `docs/INVESTOR_BRIEF.md` — v1.0, 323 lines (exec summary, TAM/SAM/SOM, competitor matrix)
- `docs/CTEM_PLUS_IDENTITY.md` — Canonical identity doc (8 scanners, 12-step pipeline)
- `docs/CEO_VISION.md` — North-star (10 pillars, business model)
- `CHANGELOG.md` — Keep a Changelog format, Sprint 1 + Sprint 2 Day 1-4
- `README.md` — 1,074 lines, CTEM+ hero, 780 endpoint badge, documentation table

## Sprint Board Location
- `.claude/team-state/sprint-board.json` — update status after completing tasks
- Always append to `decisions.log` and `context_log.md` after runs

## Endpoint Count Method
- `grep -r '@router\.\(get\|post\|put\|delete\|patch\)' --include="*.py"` across all suite dirs
- Add @app endpoints from app.py separately (25 endpoints)
- Non-standard files to check: decisions.py, nerve_center.py, business_context_enhanced.py, oss_tools.py
- Files that DON'T exist: health.py, routes/enhanced.py, reachability/api.py (previously listed in error)
- mpte_integration.py exists but is NOT mounted — don't count in live API total
- suite-evidence-risk has 53 @router endpoints (was documented as 60 — corrected)
