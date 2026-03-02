# Sales Engineer Agent Memory

## Verified API Routes (2026-03-03 15:48 UTC)
34/36 GET endpoints return 200. 7/7 POST verified live.
API key from `.env` file: `FIXOPS_API_TOKEN` — use X-API-Key header.
ai-agent/decide still 422 (schema validation) — NOT demo-safe.
Postman: 475/475 assertions passing (10th consecutive green). Moat: 95.60%.

## CRITICAL: POST Schema Corrections (VERIFIED 2026-03-03)
These schemas are DIFFERENT from what docs suggest. Always use these:
- `POST /mpte/verify`: `{finding_id, target_url, vulnerability_type, evidence}` — evidence is STRING not dict!
- `POST /autofix/generate`: `{finding: {id, title, severity, cwe, code_snippet}}` — returns fix with confidence_score (93%)
- `POST /autofix/apply`: `{fix_id, repository, create_pr, auto_merge}` — repository REQUIRED, needs GH token
- `POST /knowledge-graph/attack-paths`: `{source_id, target_id, max_depth}` (NOT source, target)
- `POST /compliance-engine/map-findings`: `{findings: [array], framework: "SOC2"}` — REAL CWE→control mappings!
- `POST /sandbox/verify`: `{language, code, cve_id, finding_id, expected_indicators, timeout_seconds}`
- `POST /sandbox/verify-finding`: `{finding: {dict}, target_url}`
- `POST /evidence/export`: `{framework: "SOC2", findings: [array]}` — returns RSA-SHA256 signed bundle!
- `POST /sast/scan/code`: `{code: "...", language: "python"}` — sub-millisecond, finds SQLi as CRITICAL
- `POST /ai-agent/decide` → STILL 422 — DO NOT USE

## Broken Endpoints (AVOID in demos) — verified 2026-03-03 15:48
- `GET /compliance-engine/gaps` → 500
- `GET /compliance-engine/audit-bundle` → 500
- `POST /ai-agent/decide` → 422 (improved from 500, still not demo-safe)
- `POST /compliance-engine/assess` → 500
- `GET /evidence/chain-of-custody` → 404
- `GET /agents/status` → 404
- `GET /brain/pipeline/steps` → 404
- `GET /brain/decisions` → 404 (use /audit/decision-trail)
- `GET /brain/history` → 404 (use /brain/stats)
- `GET /self-learning/health` → 404
- `GET /zero-gravity/health` → 404
- `GET /knowledge-graph/nodes` → 404 (use /brain/stats for node data)
- `GET /scanner-ingest/parsers` → 404 (use /scanner-ingest/supported)

## Key Demo Files
- Primary: `docs/DEMO_PERSONA_SCRIPTS.md` (5 personas + 2 MOAT demos, 26 endpoints, v7.0)
- Shell: `.claude/team-state/sales/demo-scripts/` (5 persona + enterprise-demo-all.sh v7.0 + 6 other)
- Battle cards: `.claude/team-state/sales/battle-cards.md` (9 competitors, v7.0)
- Objections: `.claude/team-state/sales/objection-handling.md` (v6.0, 8 tiers)
- Tracker: `.claude/team-state/sales/competitive-tracker.json` (v7.0)
- POC: `.claude/team-state/sales/poc-templates/enterprise-poc-plan.md` (v4.0)
- Onboarding: `docs/ONBOARDING_GUIDE.md` (v5.0)
- Readiness: `.claude/team-state/sales/demo-readiness-day3.md`
- Existing scripts: `scripts/aldeci-demo-runner.sh`, `scripts/investor-demo-15min.sh`

## Live API Response Data (2026-03-03 15:48)
- Dashboard: {total_findings: 1203, open_findings: 865, critical_findings: 319, recent_30d: 1183}
- MPTE: {total_requests: 277, confirmed_exploitable: 4, likely_exploitable: 2}
- Brain: {total_nodes: 1717, total_edges: 1664, node_types: 9 (finding:1038, exposure_case:258, cve:222, attack:101)}
- MCP: 100 tools (via /mcp/tools) — NOT 650! Always say 100.
- Compliance: 4 frameworks (SOC2=19/22, PCI_DSS=20/22, ISO_27001=16/21, NIST_800_53=29/30)
- Scanner-ingest: 25 parsers, 7 categories, endpoint is /supported (NOT /parsers!)
- AutoFix: 10 fix types, confidence 93.26%, all HIGH, auto-apply eligible. ML model gives recommendation.
- SAST: 2 findings for simple SQLi, 7 findings for multi-vuln snippet, <1ms scan
- Evidence: EVB-2026-3A61D5, RSA-SHA256 signature, 684 chars, tamper-proof

## Persona → Space Mapping
- CISO: Mission Control + Comply
- DevSecOps: Discover + Validate + Remediate
- Auditor: Comply
- Developer: Remediate
- CTO: Discover (Knowledge Graph) + Mission Control

## Demo Sequence (Sales Psychology)
1. CISO (business value) → 2. DevSecOps (differentiation) → 3. Developer (experience) → 4. Auditor (compliance close) → 5. CTO (architecture wow)
Alt for technical: DevSecOps → CTO → Developer (skip CISO/Auditor)
Alt for compliance: Auditor → CISO (evidence-first)

## Key Differentiators (Memorize)
1. 8 native scanners (air-gapped, no external tools)
2. 19-phase MPTE exploit verification
3. 12-step Brain Pipeline (full CTEM lifecycle)
4. 10 AutoFix types with confidence-based auto-apply (93%)
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
API_KEY with special chars (e.g., `--`) breaks in bash single/double quotes.
MUST use `source .env` first or `export $(grep -E '^FIXOPS_API_TOKEN=' .env | head -1)`.

## Sprint 2 Day 3 Learnings
- Data growing steadily: findings 1000→1203 (+20%), nodes 1512→1717 (+14%), MPTE 235→277 (+18%)
- AutoFix confidence jumped to 93.26% (was 87.65%) — ML confidence model working well
- scanner-ingest/parsers endpoint is gone — use /supported instead
- knowledge-graph/nodes endpoint is gone — brain/stats has all node data
- AutoFix generate returns ML confidence details: classification, interval, feature_contributions, recommendation
- Always test with `export $(grep...)` pattern, not direct key pasting
- Postman stable at 475/475 for 10 consecutive runs — no regressions
- Moat coverage 95.60% — all 19 scenarios above 80% threshold
