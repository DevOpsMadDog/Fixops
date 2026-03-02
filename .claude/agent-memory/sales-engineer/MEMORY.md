# Sales Engineer Agent Memory

## Verified API Routes (2026-03-02 08:01 UTC)
33/33 GET endpoints return 200. 9/11 POST verified live (per QA v6.1).
API key from `.env` file: `FIXOPS_API_TOKEN` — use X-API-Key header.
ai-agent/decide improved to 422 (was 500) — schema validation works but NOT demo-safe.
Postman: 475/475 assertions passing (was 411/411).

## CRITICAL: POST Schema Corrections (VERIFIED 2026-03-02)
These schemas are DIFFERENT from what docs suggest. Always use these:
- `POST /mpte/verify`: `{finding_id, target_url, vulnerability_type, evidence}` — evidence is STRING not dict!
- `POST /autofix/generate`: `{finding: {id, title, severity, cwe, code_snippet}}` — returns fix with confidence_score
- `POST /autofix/apply`: `{fix_id, repository, create_pr, auto_merge}` — repository REQUIRED, needs GH token
- `POST /knowledge-graph/attack-paths`: `{source_id, target_id, max_depth}` (NOT source, target)
- `POST /compliance-engine/map-findings`: `{findings: [array], framework: "SOC2"}` — NOW RETURNS REAL MAPPINGS!
- `POST /sandbox/verify`: `{language, code, cve_id, finding_id, expected_indicators, timeout_seconds}`
- `POST /sandbox/verify-finding`: `{finding: {dict}, target_url}`
- `POST /evidence/export`: `{framework: "SOC2", findings: [array]}` — returns RSA-SHA256 signed bundle!
- `POST /sast/scan/code`: `{code: "...", language: "python"}` — sub-millisecond, finds SQLi as CRITICAL
- `POST /ai-agent/decide` → STILL BROKEN (500) — DO NOT USE

## Broken Endpoints (AVOID in demos) — verified 2026-03-02 05:51
- `GET /compliance-engine/gaps` → 500
- `GET /compliance-engine/audit-bundle` → 500
- `POST /ai-agent/decide` → 500
- `POST /compliance-engine/assess` → 500
- `GET /evidence/chain-of-custody` → 404
- `GET /agents/status` → 404
- `GET /brain/pipeline/steps` → 404
- `GET /brain/decisions` → 404 (use /audit/decision-trail)
- `GET /brain/history` → 404 (use /brain/stats)
- `GET /self-learning/health` → 404
- `GET /zero-gravity/health` → 404

## Key Demo Files
- Primary: `docs/DEMO_PERSONA_SCRIPTS.md` (5 personas + 2 MOAT demos, 26 endpoints, v6.1)
- Shell: `.claude/team-state/sales/demo-scripts/` (5 persona + enterprise-demo-all.sh v6.1 + 4 other)
- Battle cards: `.claude/team-state/sales/battle-cards.md` (9 competitors, v5.0)
- Objections: `.claude/team-state/sales/objection-handling.md` (v5.0, 7 tiers)
- Tracker: `.claude/team-state/sales/competitive-tracker.json` (v5.0)
- POC: `.claude/team-state/sales/poc-templates/enterprise-poc-plan.md` (v3.1)
- Onboarding: `docs/ONBOARDING_GUIDE.md` (v4.1)
- Existing scripts: `scripts/aldeci-demo-runner.sh`, `scripts/investor-demo-15min.sh`

## Live API Response Data (2026-03-02 08:01)
- Dashboard: {total_findings: 1000, open_findings: 719, critical_findings: 273}
- MPTE: {total_requests: 235, confirmed_exploitable: 4}
- Brain: {total_nodes: 1512, total_edges: 1447, node_types: 9 (finding:812, cve:206, attack:145)}
- MCP: 100 tools (via /mcp/tools) — NOT 650! Always say 100.
- Compliance: 4 frameworks (SOC2=19/22, PCI_DSS=20/22, ISO_27001=16/21, NIST_800_53=29/30)
- Scanner-ingest: 25 parsers across 7 categories
- AutoFix: 10 fix types, confidence scoring (HIGH>85%, MEDIUM 60-85%, LOW<60%), avg 87.65%
- SAST: Returns CRITICAL severity for SQL injection, 0.36ms scan, has taint flows
- Evidence: RSA-SHA256 signature, 684 bytes, content hash verified

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
5. MCP gateway (100 tools verified, first in AppSec)
6. "Switzerland" — ingests ALL scanners, replaces NONE
7. 25 scanner parsers — zero rip-and-replace
8. Sandbox PoC verification — prove exploitability in Docker
9. REAL CWE→control mapping (PCI-DSS, NIST, ISO auto-maps)

## Competitor Kill Shots
- vs Aggregators (Vulcan/ArmorCode/Seemplicity): "Can they scan without Snyk? No. We can."
- vs Snyk/Semgrep: "We ingest them AND run our own scanners"
- vs Wiz/Prisma: "We work air-gapped. They don't."
- vs DeepAudit: "Same sandbox PoC, plus 12-step pipeline + compliance + AutoFix"
- vs Checkmarx: "We make Checkmarx smarter, not replace it. Zero vendor lock-in."
- vs Claude Code Security: "Claude finds. ALdeci decides."

## Shell Quoting Warning
API_KEY with special chars (e.g., `--`) breaks in bash single quotes.
Use `source .env` first, then reference ${FIXOPS_API_TOKEN} in double-quotes.

## V6.0 Sprint 2 Day 2 Learnings
- compliance-engine/map-findings improved dramatically — use CWE-89 and CWE-798 in demos for best mappings
- SAST scan with multi-vuln code snippet finds 7 findings with taint flows — excellent wow factor
- enterprise-demo-all.sh supports per-persona mode: `./enterprise-demo-all.sh url key ciso`
- Always source .env before running shell scripts (API key has special chars)
- AutoFix generate needs 30s timeout (LLM-powered) — shell scripts updated
- Data is growing live: findings 999→1000, nodes 1507→1512, MPTE 231→235
- QA agent auto-updates DEMO_PERSONA_SCRIPTS.md — coordinate, don't overwrite
- Postman tests grew from 411 to 475 (QA added more)
