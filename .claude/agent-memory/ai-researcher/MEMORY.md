# AI Researcher Agent Memory

## Key Market Intelligence (Updated 2026-03-07, Post-Demo Day 1)

### 🔴 CRITICAL: OpenAI Codex Security — LAUNCHED Mar 6
- Evolved from Aardvark. Powered by GPT-5.2-Codex (new model).
- Project-specific threat models, agentic vuln search, sandbox validation, architectural fixes.
- Beta: 800 critical + 10,500 high findings. 50% FP reduction, 90% severity over-report reduction.
- Research preview: Enterprise/Business/Edu, free first month.
- THREAT to V3+V5: Single-repo scanning, not org-wide CTEM. No MPTE, no FAIL, no multi-LLM.
- Message: "OpenAI scans repos. We orchestrate security postures."

### 🔴 CRITICAL: Claude Opus 4.6 Finds 22 Firefox CVEs
- Anthropic Red Team + Mozilla. 6,000 C++ files in 2 weeks.
- 112 reports → 22 CVEs (14 HIGH). Fixed in Firefox 148 (Feb 24).
- VALIDATES AI-powered security auditing. Supports our V5 MPTE narrative.
- Message: "Claude finds bugs. ALdeci proves they're exploitable and fixes them."

### 🔴 CRITICAL: Anthropic–Pentagon Crisis — Still Evolving (Mar 7)
- Feb 28: Blacklisted. OpenAI took deal within hours.
- Mar 3: Altman admits "opportunistic and sloppy." 900+ employees support Anthropic.
- Mar 5: Amodei back at negotiating table (FT/CNBC). Legal challenge looming.
- ALdeci V9 air-gap = geopolitical hedge. No vendor dependency.

### 🔴 CRITICAL: Triple CVSS 10.0 Week (Mar 4-7)
- CVE-2026-20079: Cisco FMC auth bypass → root. Unauth.
- CVE-2026-20131: Cisco FMC Java deser → RCE as root. Unauth.
- CVE-2026-29000: pac4j-jwt auth bypass. Forge admin tokens with public key only. PoC published.
- 15 total critical CVEs in 4 days. 48 CVEs in Cisco's March 4 advisory.
- pac4j-jwt = perfect MPTE demo target for RSA.

### Competitor Landscape (Updated 2026-03-07)
- **Wiz**: Google $32B closing mid-to-end March. EU cleared Feb 10. All major regulators done.
- **Snyk**: $8.5B. Credentials Manager (Mar 6). Reachability improvements JS/Java/Python.
- **Semgrep**: 5.3M AI triage decisions, 95% agreement, 740K auto-fixes. 18K orgs. RSA Booth #1743.
- **Endor Labs**: AURI launched Mar 3 — agentic reasoning + deterministic. Closest to Brain Pipeline.
- **Checkmarx**: Archipelo partnership (DevSPM). Sale stalled. Partnering = struggle signal.
- **CrowdStrike**: Day Zero Summit call for papers. 35 startups in accelerator.
- **ArmorCode**: MCP Server. 320+ integrations. Anya AI 80% MTTR reduction.
- **Orca Security**: No March 2026 news. Declining mindshare.
- **Tenable**: EXPOSURE 2026 conference. Exposure management for AI era.

### Market Metrics (Updated Mar 7)
- VC 2025: $13.97B (+47%). All-stage: ~$21B (820 deals). Early-stage: $7.5B at A/B (+63%).
- M&A 2025: $84B+, 426 deals. Jan 2026: 38 deals (477/yr pace).
- Cloud Native Security: $129.23B by 2035.
- AI-focused cyber VC: >50% of all cyber deals.
- CISA KEV: 1,536 total (v2026.03.05). +7 since Mar 3.
- EPSS: 318,989 CVEs scored (+1,131 since Mar 3).

### Positioning Insights (Top 17)
1. "Your security AI shouldn't be one executive order away from shutdown." [V3][V9]
2. "AI agents are the new attack surface. We test them." [V5]
3. "Claude finds. ALdeci decides." [V3]
4. "Google bought your security vendor." [V3]
5. "3 models voting beats 1 model guessing." [V3]
6. "70% of orgs have MCP packages with critical vulns." [V7]
7. "Gartner says CTEM = 3x fewer breaches. We're CTEM+." [V3][V10]
8. "The only security platform that works when the internet doesn't." [V9]
9. "705 AI-consumable security tools. ArmorCode has 1." [V7]
10. "87% of orgs experienced AI-driven attacks. We simulate all of them." [V5]
11. "One AI finding bugs is useful. Three AIs voting on what to fix is intelligence." [V3]
12. "AWS tests AWS. ALdeci tests everything." [V5]
13. "OpenAI scans repos. We orchestrate security postures." [V3] — NEW (Codex Security)
14. "22 Firefox CVEs proves AI works. We prove they're exploitable." [V5] — NEW
15. "3 CVSS-10 vulns in one week. Now what? ALdeci decides." [V3] — NEW
16. "When the Pentagon blacklists your AI vendor, ALdeci keeps running." [V9] — NEW
17. "Endor Labs calls it 'agentic reasoning.' We call it a 12-step Brain Pipeline." [V3] — NEW

### API Patterns
- NVD API: pubStartDate/pubEndDate for ranges. 15 critical CVEs for Mar 4-7.
- CISA KEV: Sort by dateAdded descending for recent. Catalog v2026.03.05.
- EPSS API: `order=!epss` for highest. `days=1` for latest day only. New CVEs start LOW.
- HackerNews: 9/40 relevant on Mar 7 (22.5% rate, consistent with 20-27% range).

### Technology Research
- **vLLM**: 12,500 TPS on H100. Async scheduling +30.8% throughput. WebSocket Realtime API.
- **SGLang**: 16,200 TPS on H100 (29% faster than vLLM). v26.01 (Feb 2026). Recommend for Sprint 3.
- **LMDeploy**: Matching SGLang at ~16,200 TPS. Rising challenger.
- **Sarvam 105B**: First competitive Indian open-source LLM. Potential vLLM candidate.
- Tree-sitter: Sprint 3. ChromaDB RAG: Sprint 4+.

### Upcoming Events
- Mar 9: NIST CAISI agentic AI RFI deadline
- Mar 11: Archipelo + Checkmarx webinar
- Mar 15: Microsoft PAT deprecation
- Mar 18: Fal.Con Gov 2026 (DC)
- Mar 20: RSA registration close
- Mar 23: RSA Innovation Sandbox (9:30 AM PT)
- Mar 23-26: RSA 2026 (Moscone SF) — 16 DAYS
- End of March: Wiz-Google close
- Aug 30-Sep 1: CrowdStrike Fal.Con 2026 + Day Zero Summit (Las Vegas)

### DEMO-010 Knowledge
- KnowledgeGraphEngine: NetworkX in-memory. Singleton.
- Seed demo: 73 nodes, 110 edges, 10+ attack paths. 75/75 tests.
- Blast radius from Log4Shell: 41 affected nodes, 9.1x risk multiplier.
- Enterprise Demo: COMPLETED Mar 6.
