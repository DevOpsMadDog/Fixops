# Technical Writer Memory

## Key File Paths
- API entry point: `suite-api/apps/api/app.py` (2,737 LOC, 34 router mounts)
- Router files: `**/*_router.py` across 6 suite directories
- Brain Pipeline: `suite-core/core/brain_pipeline.py` (1,000 LOC, 12 steps)
- AutoFix Engine: `suite-core/core/autofix_engine.py` (1,260 LOC, 10 fix types)
- MPTE Engine: `suite-core/core/micro_pentest.py` (2,054 LOC, 19 phases)
- Scanner Parsers: `suite-core/core/scanner_parsers.py` (700 LOC, 15 normalizers)
- Identity doc: `docs/CTEM_PLUS_IDENTITY.md` (canonical reference)
- CEO Vision: `docs/CEO_VISION.md` (north-star)

## API Surface
- 704 endpoints across 64 router files + inline app.py definitions
- 6 suites: suite-api, suite-core, suite-attack, suite-feeds, suite-evidence-risk, suite-integrations
- Non-standard routers: decisions.py, nerve_center.py, business_context*.py
- Auth: API Key (X-API-Key) + JWT Bearer + role scopes

## Document Organization
- API docs grouped by CTEM lifecycle: Discover → Validate → Remediate → Comply → Intelligence → Platform
- Architecture uses Mermaid diagrams (system overview, data flow, integration)
- README hero must reflect CTEM+ positioning with scanner/parser/endpoint counts

## Conventions
- Always verify endpoint paths against actual router files (grep for @router decorators)
- app.py mounts routers with prefix overrides — check both router prefix AND app.py mount
- Evidence routers get `/api/v1` prefix override in app.py mount
- Scanner routers require `attack:execute` scope
- Evidence routers require `read:evidence` scope

## Sprint Board Location
- `.claude/team-state/sprint-board.json` — update status after completing tasks
- Always append to `decisions.log` and `context_log.md` after runs
