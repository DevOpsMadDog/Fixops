# Sales Engineer Agent Memory

## Key Demo Endpoints (verified working 2026-02-27)
- FAIL Engine: POST /api/v1/fail/score (FAILScoreRequest schema in fail_router.py:48)
- FAIL Batch: POST /api/v1/fail/score/batch
- MPTE Verify: POST /api/v1/mpte/verify (VerifyVulnerabilityModel: finding_id, target_url, vulnerability_type, evidence)
- MCP Stats: GET /api/v1/mcp/stats
- MCP Tools: GET /api/v1/mcp/tools (supports ?category=, ?tag=, ?search=, ?limit=, ?offset=)
- Analytics Overview: GET /api/v1/analytics/dashboard/overview
- Evidence Bundles: GET /evidence/bundles (note: no /api/v1 prefix)
- Connectors: GET /api/v1/connectors

## API Authentication
- Header: X-API-Key
- Default demo key: "demo-key" (set via FIXOPS_API_TOKEN env var)
- Health endpoint at /health does NOT require auth

## Demo Script Patterns
- Always include fallback data for every API call -- demos cannot fail
- Use --dry-run mode for rehearsal, --check for pre-flight only
- The api_call() pattern: try real API, check HTTP code, fall back silently
- Colors: CYAN for demo commands, GREEN for talk track, DIM for notes

## Key Numbers (from CEO_VISION.md)
- 11,300 findings --> 340 exposure cases = 97% noise reduction
- $4,200 per vuln --> $840 per vuln = 80% cost reduction
- $110K+ annual savings per enterprise
- 537 MCP tools (auto-discovered from FastAPI routes)
- 19 MPTE phases (Recon 1-2, Identification 3-5, Exploit 6-8, Attack 9-12, Post 13-15, Lateral 16-17, Cleanup 18, Report 19)
- 8 native scanners for air-gapped

## Competitive Positioning
- vs Snyk: "We make Snyk 10x more useful" (ingest + FAIL + MPTE on top)
- vs Wiz/Orca: "Different category -- they do CSPM, we do AppSec decision intelligence"
- vs Vulcan Cyber: "We add AI consensus + MPTE + MCP"
- vs Semgrep: "We have our own SAST AND ingest Semgrep"
- NEVER say "replaces" -- ALWAYS say "makes X more useful" or "works with"

## Files Created
- /scripts/investor-demo-15min.sh (928 LOC, executable)
- /docs/INVESTOR_DEMO_SCRIPT.md (751 LOC)

## Sprint Board
- SPRINT1-010 completed 2026-02-27 (marked done in sprint-board.json)
