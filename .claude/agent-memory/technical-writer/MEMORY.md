# Technical Writer Memory

## Key File Paths
- API entry point: `suite-api/apps/api/app.py` (2,742 LOC, 34 router mounts)
- Router files: `**/*_router.py` across 6 suite directories (68 total router files)
- Brain Pipeline: `suite-core/core/brain_pipeline.py` (1,161 LOC, 12 steps)
- AutoFix Engine: `suite-core/core/autofix_engine.py` (1,260 LOC, 10 fix types)
- MPTE Engine: `suite-core/core/micro_pentest.py` (2,054 LOC, 19 phases)
- Scanner Parsers: `suite-core/core/scanner_parsers.py` (700 LOC, 15 normalizers)
- Identity doc: `docs/CTEM_PLUS_IDENTITY.md` (canonical reference)
- CEO Vision: `docs/CEO_VISION.md` (north-star)

## API Surface (Updated 2026-03-02)
- 769 endpoints verified E2E (719 @router + 25 @app + health/status additions)
- 68 router files + non-standard endpoint files across 6 suites
- 77 unique route prefixes
- 6 suites: suite-api (217), suite-core (256), suite-attack (106), suite-feeds (31), suite-evidence-risk (46), suite-integrations (59)
- Non-standard routers: decisions.py, nerve_center.py, business_context*.py, oss_tools.py
- Auth: API Key (X-API-Key) + JWT Bearer + role scopes

## Document Organization
- API docs grouped by CTEM lifecycle: Discover → Validate → Remediate → Comply → Intelligence → Platform → Vision Engines
- Vision Engines section (added v2.2): Self-Learning V8 (18ep), Quantum Crypto V6 (5ep), Zero-Gravity V9 (6ep), AI Agent V4 (6ep)
- Architecture uses Mermaid diagrams (system overview, data flow, integration)
- README hero must reflect CTEM+ positioning with scanner/parser/endpoint counts
- CHANGELOG uses Keep a Changelog format with Day 1/Day 2 sub-sections per sprint
- API_REFERENCE.md v2.2: 1,969 lines, 28 curl examples, 77 sections, 11 main + appendices

## Conventions
- Always verify endpoint paths against actual router files (grep for @router decorators)
- app.py mounts routers with prefix overrides — check both router prefix AND app.py mount
- Evidence routers get `/api/v1` prefix override in app.py mount
- Scanner routers require `attack:execute` scope
- Evidence routers require `read:evidence` scope
- Every router has both /health and /status endpoints (added Sprint 2 Day 2)
- Backend-hardener adds security fixes that need documenting — check their status file

## Sprint Board Location
- `.claude/team-state/sprint-board.json` — update status after completing tasks
- Always append to `decisions.log` and `context_log.md` after runs

## Endpoint Count Method
- `grep -r '@router\.\(get\|post\|put\|delete\|patch\)' --include="*.py"` across all suite dirs
- Add @app endpoints from app.py separately
- Live count may differ slightly due to dynamic route registration and health/status additions
