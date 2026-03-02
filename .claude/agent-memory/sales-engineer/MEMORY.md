# Sales Engineer Agent Memory

## Verified API Routes (2026-03-02)
37/40 GET endpoints return 200 OK. 3 broken (see below).
POST schemas fully validated with Python urllib against running API.
API key from `.env` file: `FIXOPS_API_TOKEN` — use X-API-Key header.

## CRITICAL: POST Schema Corrections (2026-03-02)
These schemas are DIFFERENT from what docs suggest. Always use these:
- `POST /mpte/verify`: `{finding_id, target_url, vulnerability_type, evidence}` (NOT target, context)
- `POST /ai-agent/decide`: `{finding: {dict}, context: {dict}}` (NOT finding_id) — BUT returns 500
- `POST /knowledge-graph/attack-paths`: `{source_id, target_id, max_depth}` (NOT source, target)
- `POST /autofix/apply`: `{fix_id, repository, create_pr, auto_merge}` — repository is REQUIRED
- `POST /compliance-engine/map-findings`: `{findings: [array], framework: "SOC2"}` — findings is REQUIRED
- `POST /sandbox/verify`: `{language, code, cve_id, finding_id, expected_indicators, timeout_seconds}`
- `POST /sandbox/verify-finding`: `{finding: {dict}, target_url}`

## Broken Endpoints (AVOID in demos) — as of 2026-03-02
- `GET /compliance-engine/gaps` → 500 NoneType
- `GET /compliance-engine/audit-bundle` → 500 NoneType
- `POST /ai-agent/decide` → 500 ConsensusDecision attribute
- `POST /compliance-engine/assess` → 500 str attribute
- `POST /compliance-engine/assess-all` → 500 binding error
- `GET /evidence/chain-of-custody` → 404 not found
Use alternatives: /compliance-engine/frameworks, /evidence/, /audit/logs/export, /audit/decision-trail

## Key Demo Files
- Primary: `docs/DEMO_PERSONA_SCRIPTS.md` (5 personas + 2 MOAT demos, 31 endpoints, v2.0)
- Shell: `.claude/team-state/sales/demo-scripts/` (5 scripts)
- Battle cards: `.claude/team-state/sales/battle-cards.md` (6 competitors)
- Sales: `.claude/team-state/sales/` (objections v2, tracker v2, POC v2, battle cards)
- Existing: `scripts/aldeci-demo-runner.sh`, `scripts/investor-demo-15min.sh`

## Persona → Space Mapping
- CISO: Mission Control + Comply
- DevSecOps: Discover + Validate + Remediate
- Auditor: Comply
- Developer: Remediate
- CTO: Discover (Knowledge Graph) + Mission Control

## Demo Sequence (Sales Psychology)
1. CISO (business value) → 2. DevSecOps (differentiation) → 3. Developer (experience) → 4. Auditor (compliance close) → 5. CTO (architecture wow)

## Key Differentiators (Memorize)
1. 8 native scanners (air-gapped, no external tools)
2. 19-phase MPTE exploit verification
3. 12-step Brain Pipeline (full CTEM lifecycle)
4. 10 AutoFix types with confidence-based auto-apply
5. MCP gateway (650+ tools, first in AppSec)
6. "Switzerland" — ingests ALL scanners, replaces NONE
7. 25 scanner parsers — zero rip-and-replace
8. Sandbox PoC verification — prove exploitability in Docker

## Competitor Kill Shots
- vs Aggregators (Vulcan/ArmorCode/Seemplicity): "Can they scan without Snyk? No. We can."
- vs Snyk/Semgrep: "We ingest them AND run our own scanners"
- vs Wiz/Prisma: "We work air-gapped. They don't."
- vs DeepAudit: "Same sandbox PoC, plus 12-step pipeline + compliance + AutoFix"
- vs Checkmarx: "We make Checkmarx smarter, not replace it. Zero vendor lock-in."

## Sprint Board Location
`.claude/team-state/sprint-board.json` — always update after completing work.

## Postman Collections (7)
`suite-integrations/postman/enterprise/ALdeci-{1-7}-*.postman_collection.json`

## Shell Quoting Warning
API_KEY with special chars (e.g., `--`) breaks in bash single quotes.
Use Python urllib for reliable endpoint validation, or `source .env` first.
