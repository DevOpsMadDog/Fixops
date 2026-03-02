# Marketing Head — Persistent Memory

## Verified Technical Claims (2026-03-02, Run 4 — ALL UNCHANGED FROM RUN 3)
- Brain Pipeline: 1,533 LOC (`suite-core/core/brain_pipeline.py`) ← was 1,354 in Run 2
- SAST Engine: 1,622 LOC, DAST: 633 LOC, Secrets: 848 LOC, Container: 445 LOC, CSPM: 609 LOC
- AutoFix: 1,428 LOC, MPTE: 2,054 LOC, MPTE Advanced: 1,089 LOC, FAIL: 711 LOC, MCP: 978 LOC
- Crypto: 582 LOC, Quantum Crypto: 666 LOC
- Scanner Parsers: 1,238 LOC (`suite-core/core/scanner_parsers.py`) — 15 tool-specific parsers
- Ingestion: 2,114 LOC (`suite-api/apps/api/ingestion.py`) — 10 format parsers
- **TOTAL scanner parser LOC: 3,352** (1,238 + 2,114)
- **TOTAL scanner engine LOC: 4,757+** (1,622+633+848+445+609+~600 inline)
- Security Connectors: 1,335 LOC, Workflow Connectors: 3,005 LOC
- API Route Decorators: 796 across 78 router files
- Total Python codebase: 401,992 LOC (grew from 372,501 in Run 2)
- Tests collected: 13,221 (grew from 10,356 in Run 2)
- Sprint 2: 11/12 done (91.7%). Postman 411/411 (100%).
- **Run 4 note**: LOC counts were STABLE between Run 3 and Run 4. No engineering changes to marketing-cited files.

## CRITICAL CORRECTION LOG
- **ingestion.py location**: `suite-api/apps/api/ingestion.py` NOT `suite-core/core/ingestion.py`
- **Router file count**: `grep -rl "@router\.\|@app\." --include="*.py" suite-*/ | wc -l` = 78
- **LOC grows every sprint** — always re-verify before publishing. v4→v5 delta was 29,491 LOC!
- **Run 3→4 LOC was stable** — but this is atypical (Day 2 of sprint, less eng activity on Sunday)

## Key Patterns
- Always `wc -l` on actual files before citing LOC — numbers change EVERY sprint
- AI Researcher pulse: `.claude/team-state/research/pulse-YYYY-MM-DD.md`
- CTEM_PLUS_IDENTITY.md LOC counts are STALE — always verify against actual files
- Route count: `grep -rc "@router\.\|@app\." --include="*.py" suite-*/ | awk -F: '{sum+=$2} END {print sum}'`
- Full project LOC: `find . -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv/*" -exec cat {} + | wc -l`

## Competitor Positioning (as of Mar 2, 2026, Run 4 — no new movements)
- **Pentagon-Anthropic crisis** (Feb 27): Claude blacklisted. OpenAI Pentagon deal. Multi-model = geopolitical resilience.
- **Claude Code Security** (Feb 20): NOT a competitor — scanner integration. "Claude finds. ALdeci decides."
- Wiz: Google acquisition closing MID-MARCH 2026. CISPE alarmed. Switzerland at peak value.
- Semgrep: RSA 2026 Booth #1743. "AI Detection" product. 75M scans, 740K autofixes. Single-model risk.
- Checkmarx: Acquired Tromzo. AWS Kiro IDE. Sale stalled ~$1.5B.
- Endor Labs: 97% noise reduction (SCA only). Acquired Autonomous Plane.
- ArmorCode: Beta MCP server. Endor Labs integration. 320+ integrations. Zero native scanners.
- Snyk: $3.7B (down from $8.5B). Growth 12%. IPO or acquisition in 2026.
- CrowdStrike: FalconID GA. Fal.Con Gov Mar 18. 27-second breakout. Complementary.

## Messaging (Mar 2, 2026 — v5.1, 3-Tier Hierarchy)
- **TIER 1**: Core value (always use):
  - "ALdeci turns 10,000 security findings into 10 actionable decisions."
  - "Claude finds. ALdeci decides."
  - "3 models voting beats 1 model guessing."
- **TIER 2**: Situational (current events):
  - "Your security AI shouldn't be one executive order away from shutdown."
  - "Google bought Wiz. The Pentagon banned Claude. Independence matters."
  - "27 seconds to breach. Can your team triage 500 new vulns that fast?"
- **TIER 3**: Audience-specific:
  - "The only security platform that works when the internet doesn't." (gov)
  - "NIST says secure your AI agents. We already do." (regulatory)

## Content Strategy
- Pentagon-Anthropic angle is TIME-SENSITIVE — publish before RSA Conference (Mar 23)
- Lead with multi-AI consensus (strongest differentiator + geopolitical validation)
- 3-tier messaging hierarchy: Core → Situational → Audience-specific
- Founder's voice: technical, direct, no marketing fluff
- Always link claims to verified file paths
- **Enterprise demo emails**: pre-demo (3 variants) + post-demo (4 variants) now ready

## File Locations
- Marketing output: `.claude/team-state/marketing/`
- Research input: `.claude/team-state/research/`
- Identity doc: `docs/CTEM_PLUS_IDENTITY.md`
- CEO Vision: `docs/CEO_VISION.md`
- Ingestion parsers: `suite-api/apps/api/ingestion.py` (NOT suite-core)
- Scanner parsers: `suite-core/core/scanner_parsers.py`

## Sprint 2 Content Inventory (as of Mar 2 Run 4)
- enterprise-demo-talking-points.md: v5.1 ✅
- positioning.md: v5.1 ✅
- investor-narrative.md: v5.1 ✅
- content/one-pager-enterprise-product.md: v1.0 ✅
- content/demo-video-script-5min.md: DONE ✅ (was in-progress, now complete)
- content/email-pre-demo-enterprise.md: NEW v1.0 ✅ (3 variants)
- content/email-post-demo-followup.md: NEW v1.0 ✅ (4 variants)
- content/blog-multi-ai-consensus.md: ✅
- content/blog-claude-finds-aldeci-decides.md: ✅
- content/blog-pentagon-multi-model-resilience.md: ✅
- content/linkedin-11300-finding-problem.md: ✅
- content/linkedin-500-more-zero-days.md: ✅
- content/linkedin-pentagon-proves-multi-model.md: ✅
- battlecards: 6 competitors ✅
- Content calendar: 11/15 done, 0 in-progress, 4 planned (73.3%)
