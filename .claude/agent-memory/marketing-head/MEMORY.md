# Marketing Head — Persistent Memory

## Verified Technical Claims (2026-03-03, Run 6)
- Brain Pipeline: **1,663 LOC** (`suite-core/core/brain_pipeline.py`) ← was 1,533 in Run 5 (+130)
- SAST Engine: 1,622 LOC, DAST: 633 LOC, Secrets: 848 LOC, Container: 445 LOC, CSPM: 609 LOC
- AutoFix: **1,515 LOC** ← was 1,428 in Run 5 (+87), MPTE: 2,054 LOC, MPTE Advanced: 1,089 LOC, FAIL: 711 LOC, MCP: 978 LOC
- Crypto: 582 LOC, Quantum Crypto: 666 LOC
- Scanner Parsers: 1,238 LOC (`suite-core/core/scanner_parsers.py`) — 15 tool-specific parsers
- Ingestion: 2,114 LOC (`suite-api/apps/api/ingestion.py`) — 10 format parsers
- **TOTAL scanner parser LOC: 3,352** (1,238 + 2,114)
- **TOTAL scanner engine LOC: 4,757+** (1,622+633+848+445+609+~600 inline)
- Security Connectors: 1,335 LOC, Workflow Connectors: 3,005 LOC
- API Route Decorators: **805** across 78 router files ← was 796 in Run 5 (+9)
- Total Python codebase: **~416,778 LOC** ← was 401,993 in Run 5 (+14,785)
- Tests collected: **13,674** ← was 13,221 in Run 5 (+453)
- Sprint 2: 11/12 done (91.7%). Postman 475/475 (100%) — 9th consecutive green.
- Knowledge Graph: 73 nodes, 110 edges, 10+ attack paths (DEMO-010 complete)
- **Run 6 note**: brain_pipeline and autofix grew (backend-hardener enhancements). Route count grew +9. Total LOC jumped +14,785 (Day 2→3 engineering activity). Scanner engines STABLE.

## CRITICAL CORRECTION LOG
- **ingestion.py location**: `suite-api/apps/api/ingestion.py` NOT `suite-core/core/ingestion.py`
- **Router file count**: `grep -rl "@router\.\|@app\." --include="*.py" suite-*/ | wc -l` = 78
- **LOC grows every sprint** — always re-verify before publishing. v5→v6 delta was 14,785 LOC!
- **Snyk valuation**: CORRECTED to $8.5B (was incorrectly stated as $3.7B in Runs 1-5). Source: BankInfoSecurity, Tracxn. At $343M ARR = 25x multiple.

## Key Patterns
- Always `wc -l` on actual files before citing LOC — numbers change EVERY sprint
- AI Researcher pulse: `.claude/team-state/research/pulse-YYYY-MM-DD.md`
- CTEM_PLUS_IDENTITY.md LOC counts are STALE — always verify against actual files
- Route count: `grep -rc "@router\.\|@app\." --include="*.py" suite-*/ | awk -F: '{sum+=$2} END {print sum}'`
- Full project LOC: `find . -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv/*" -exec cat {} + | wc -l`

## Competitor Positioning (as of Mar 3, 2026, Run 6)
- **Claude weaponized** (Mar 1): Hacker breached 10 Mexican govt agencies using Claude Code + GPT-4.1. 1,000+ prompts. AI is now attack vector AND defense tool.
- **Pentagon-Anthropic crisis** (Feb 27): Claude blacklisted. OpenAI Pentagon deal. Anthropic preparing legal challenge. Multi-model = geopolitical resilience.
- **Chinese lab abuse**: DeepSeek, Moonshot AI, MiniMax — 24K accounts, 16M interactions on Claude platform.
- **Claude Code Security** (Feb 20): NOT a competitor — scanner integration. "Claude finds. ALdeci decides."
- Wiz: Google acquisition closing MID-MARCH 2026. CISPE alarmed. Switzerland at peak value.
- Semgrep: RSA 2026 Booth #1743. Managed Scans GA. PHP reachability. Single-model risk.
- Checkmarx: Acquired Tromzo. AWS Kiro IDE. Sale stalled ~$1.5B.
- Endor Labs: Full-stack reachability (Autonomous Plane). $188M funded. SCA-only.
- ArmorCode: Beta MCP server. 320+ integrations. Zero native scanners.
- **Snyk: $8.5B valuation** (CORRECTED), $343M ARR, 12% growth. IPO "increasingly unlikely prospect."
- CrowdStrike: Q4 earnings Mar 3 (TODAY). SGNL ($740M) + Seraphic ($420M). 27-second breakout.
- Tenable: 70% orgs have MCP packages, 86% with critical vulns. Validates V7.

## Messaging (Mar 3, 2026 — v6.0, 3-Tier Hierarchy)
- **TIER 1**: Core value (always use):
  - "ALdeci turns 10,000 security findings into 10 actionable decisions."
  - "Claude finds. ALdeci decides."
  - "3 models voting beats 1 model guessing."
- **TIER 2**: Situational (current events):
  - "Your security AI shouldn't be one executive order away from shutdown."
  - "AI agents are the new attack surface. We test them." (NEW — Claude weaponization)
  - "Google bought Wiz. The Pentagon banned Claude. Independence matters."
  - "27 seconds to breach. Can your team triage 500 new vulns that fast?"
- **TIER 3**: Audience-specific:
  - "The only security platform that works when the internet doesn't." (gov)
  - "NIST says secure your AI agents. We already do." (regulatory)
  - "70% of organizations have MCP packages with critical vulns. We secure them." (MCP/V7)

## Content Strategy
- Claude weaponization angle is FRESH — publish this week (before RSA)
- Pentagon-Anthropic angle still TIME-SENSITIVE — RSA Conference Mar 23
- Lead with multi-AI consensus (strongest differentiator + geopolitical validation)
- 3-tier messaging hierarchy: Core → Situational → Audience-specific
- Founder's voice: technical, direct, no marketing fluff
- Always link claims to verified file paths
- **Enterprise demo emails**: pre-demo (3 variants) + post-demo (4 variants) ready

## File Locations
- Marketing output: `.claude/team-state/marketing/`
- Research input: `.claude/team-state/research/`
- Identity doc: `docs/CTEM_PLUS_IDENTITY.md`
- CEO Vision: `docs/CEO_VISION.md`
- Ingestion parsers: `suite-api/apps/api/ingestion.py` (NOT suite-core)
- Scanner parsers: `suite-core/core/scanner_parsers.py`

## Sprint 2 Content Inventory (as of Mar 3 Run 6)
- enterprise-demo-talking-points.md: **v6.0** ✅ (Run 6)
- positioning.md: **v6.0** ✅ (Run 6)
- investor-narrative.md: **v6.0** ✅ (Run 6)
- content/one-pager-enterprise-product.md: v1.0 ✅
- content/one-pager-investor-preseed.md: v1.0 ✅
- content/demo-video-script-5min.md: v1.0 ✅
- content/email-pre-demo-enterprise.md: v1.0 ✅ (3 variants)
- content/email-post-demo-followup.md: v1.0 ✅ (4 variants)
- content/blog-multi-ai-consensus.md: ✅
- content/blog-claude-finds-aldeci-decides.md: ✅
- content/blog-pentagon-multi-model-resilience.md: ✅
- content/linkedin-11300-finding-problem.md: ✅
- content/linkedin-500-more-zero-days.md: ✅
- content/linkedin-pentagon-proves-multi-model.md: ✅
- content/twitter-thread-mpte-19-phases.md: ✅ (15 tweets, V5)
- battlecards: 6 competitors ✅
- Content calendar: 13/15 done, 0 in-progress, 2 planned (86.7%)
- **Total content pieces: 17**
