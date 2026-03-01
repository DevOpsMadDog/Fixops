# Marketing Head — Persistent Memory

## Verified Technical Claims (2026-03-01)
- Brain Pipeline: 1,161 LOC (was 1,000 in CLAUDE.md, was 864 in CTEM_PLUS_IDENTITY.md — file has grown)
- SAST Engine: 1,577 LOC (was 465 in CTEM_PLUS_IDENTITY.md — major growth)
- Secrets Scanner: 845 LOC (was 775 in CTEM_PLUS_IDENTITY.md)
- AutoFix: 1,259 LOC, MPTE: 2,054 LOC, FAIL: 713 LOC, MCP: 979 LOC
- Crypto: 582 LOC, Quantum Crypto: 666 LOC
- API Endpoints: 723 (up from 704 in CLAUDE.md) across 97 router files
- Scanner Parsers: 15 in scanner_parsers.py + 10 in ingestion.py = 25+ total
- Total codebase: 355,805 LOC

## Key Patterns
- Always grep codebase before citing LOC — numbers change between sprints
- AI Researcher pulse is at `.claude/team-state/research/pulse-YYYY-MM-DD.md`
- pitch-data.json has structured competitor data for easy reference
- CTEM_PLUS_IDENTITY.md LOC counts may be stale — verify against actual files
- Endpoint count: use `grep -c "@router\." ... | awk` across all suites

## Competitor Positioning (as of Mar 2026)
- Wiz: Google acquisition closing. BIGGEST "Switzerland" opportunity ever.
- Semgrep: "multimodal engine" (Feb 25 announcement) = SAST + single LLM. Counter with multi-model.
- Checkmarx: Acquired Tromzo. "We ship what they just acquired."
- Endor Labs: 97% noise reduction collision. Differentiate with "across ALL scanners, not just SCA."
- ArmorCode: Closest ASPM competitor. Zero native scanners. Beta MCP. We have 723 tools.
- Snyk: Valuation collapsed ($8.5B → $3.7B). Growth at 12%. Market commoditizing.

## Content Strategy
- Lead with multi-AI consensus (strongest unique differentiator, zero competitors)
- Blog > LinkedIn > Twitter order for content pipeline
- Founder's voice: technical, direct, no marketing fluff
- Always link claims to verified file paths

## File Locations
- Marketing output: `.claude/team-state/marketing/`
- Research input: `.claude/team-state/research/`
- Codebase map: `.claude/team-state/codebase-map.json`
- Identity doc: `docs/CTEM_PLUS_IDENTITY.md`
- CEO Vision: `docs/CEO_VISION.md`
