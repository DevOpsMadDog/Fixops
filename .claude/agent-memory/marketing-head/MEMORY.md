# Marketing Head — Persistent Memory

## Verified Technical Claims (2026-03-02, Run 2)
- Brain Pipeline: 1,354 LOC (`suite-core/core/brain_pipeline.py`)
- SAST Engine: 1,577 LOC, DAST: 629 LOC, Secrets: 850 LOC, Container: 445 LOC, CSPM: 593 LOC
- AutoFix: 1,418 LOC, MPTE: 2,054 LOC, MPTE Advanced: 1,089 LOC, FAIL: 713 LOC, MCP: 979 LOC
- Crypto: 582 LOC, Quantum Crypto: 666 LOC
- Scanner Parsers: 1,217 LOC (`suite-core/core/scanner_parsers.py`) — 15 tool-specific parsers
- Ingestion: 2,114 LOC (`suite-api/apps/api/ingestion.py`) — 10 format parsers (SARIF, CycloneDX, SPDX, VEX, Trivy, Grype, Semgrep, Dependabot, CNAPP, dark-web)
- **TOTAL scanner parser LOC: 3,331** (was incorrectly cited as 1,088+ in v3.0 docs — FIXED in v4.0)
- API Route Decorators: 796 across 78 router files
- Total Python codebase: 372,501 LOC (grew from 372,351)
- Tests collected: 10,356

## CRITICAL CORRECTION LOG
- **ingestion.py location**: `suite-api/apps/api/ingestion.py` NOT `suite-core/core/ingestion.py` (the latter doesn't exist)
- **Router file count**: `grep -rl "@router\.\|@app\." --include="*.py" suite-*/ | wc -l` = 78 (use BOTH patterns)
- **Router file count (router only)**: `grep -rl "@router\." --include="*.py" suite-*/ | wc -l` = 73 (DON'T use this — misses @app. files)

## Key Patterns
- Always `wc -l` on actual files before citing LOC — numbers change EVERY sprint
- AI Researcher pulse: `.claude/team-state/research/pulse-YYYY-MM-DD.md`
- CTEM_PLUS_IDENTITY.md LOC counts are STALE — always verify against actual files
- Route count: `grep -rc "@router\.\|@app\." --include="*.py" suite-*/ | awk -F: '{sum+=$2} END {print sum}'`
- Router file count: `grep -rl "@router\.\|@app\." --include="*.py" suite-*/ | wc -l` (INCLUDE @app. pattern!)

## Competitor Positioning (as of Mar 2, 2026)
- **Claude Code Security** (NEW Feb 20): NOT a competitor — scanner integration. "Claude finds. ALdeci decides."
- Wiz: Google acquisition closing March 2026. Dazz ($450M) integrated. MCP with Gemini. Switzerland peak.
- Semgrep: "multimodal engine" (Feb 25) = SAST + single LLM. Counter with multi-model consensus.
- Checkmarx: Acquired Tromzo. Sale stalled ~$1.5B. GovInfoSecurity names them as Claude-threatened.
- Endor Labs: 97% noise reduction collision. Acquired Autonomous Plane. Differentiate: "across ALL scanners."
- ArmorCode: Closest ASPM competitor. Zero native scanners. Beta MCP. We have 796 tools.
- Snyk: $3.7B (down from $8.5B). Growth 12%. Published Claude embrace blog — PR spin.

## Messaging (Mar 2, 2026)
- PRIMARY: "ALdeci turns 10,000 security findings into 10 actionable decisions."
- BACKUP: "Claude finds the vulnerabilities. ALdeci decides what to DO about them."
- URGENCY: "27 seconds to breach. Can your team triage 500 new vulns that fast?"
- AIR-GAP: "The only security platform that works when the internet doesn't."
- SWITZERLAND: "Google bought Wiz. Your security shouldn't belong to any cloud vendor."

## Content Strategy
- Lead with multi-AI consensus (strongest unique differentiator, zero competitors)
- Time-sensitive: Claude Code Security response content should publish ASAP
- Blog > LinkedIn > Twitter order for content pipeline
- Founder's voice: technical, direct, no marketing fluff
- Always link claims to verified file paths

## File Locations
- Marketing output: `.claude/team-state/marketing/`
- Research input: `.claude/team-state/research/`
- Codebase map: `.claude/team-state/codebase-map.json`
- Identity doc: `docs/CTEM_PLUS_IDENTITY.md`
- CEO Vision: `docs/CEO_VISION.md`
- Ingestion parsers: `suite-api/apps/api/ingestion.py` (NOT suite-core)
- Scanner parsers: `suite-core/core/scanner_parsers.py`

## Sprint 2 Content Inventory (as of Mar 2 Run 2)
- enterprise-demo-talking-points.md: v4.0 ✅
- positioning.md: v4.0 ✅
- investor-narrative.md: v4.0 ✅
- content/one-pager-enterprise-product.md: NEW ✅
- content/demo-video-script-5min.md: NEW ✅
- content/blog-multi-ai-consensus.md: ✅
- content/blog-claude-finds-aldeci-decides.md: ✅
- content/linkedin-11300-finding-problem.md: ✅
- content/linkedin-500-more-zero-days.md: ✅
- battlecards: 6 competitors (snyk, wiz, semgrep, checkmarx, armorcode, endorlabs) ✅
- Content calendar: 6/12 done, 1 in-progress, 5 planned (50%)
