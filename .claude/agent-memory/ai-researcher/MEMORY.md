# AI Researcher Agent Memory

## Key Market Intelligence (Updated 2026-03-02, Pass 3)

### 🔴 CRITICAL: Anthropic-Pentagon Standoff (Feb 27, 2026)
- Pentagon blacklisted Anthropic as "supply chain risk" after Dario Amodei refused to remove AI safety guardrails (mass surveillance, autonomous weapons)
- Claude hit #1 on US App Store overtaking ChatGPT. Daily signups at all-time records. Free users +60%, paid subs 2x in 2026
- OpenAI struck Pentagon deal within hours — positioning as "patriotic" AI
- Pentagon contract (~$200M) being severed, 6-month wind-down
- ALdeci positioning: Multi-LLM + air-gap = GEOPOLITICAL resilience. New messaging: "Your security AI shouldn't be one executive order away from shutdown."
- vLLM integration UPGRADED to P1 — self-hosted LLM now critical for DoD/IC customers

### CRITICAL: Claude Code Security (Feb 20, 2026)
- 500+ zero-days found in production OSS code. Cyber stocks dropped.
- ALdeci: COMPLEMENTARY — "Claude finds. ALdeci decides."
- Pentagon standoff amplifies Claude popularity → more findings → more need for ALdeci decision layer

### Competitor Landscape
- **Wiz**: Google $32B closing **MID-MARCH 2026**. EU approved. DOJ cleared. Orca lawsuit settled (Jan 2026, dismissed with prejudice). CISPE alarmed. Switzerland PEAK.
- **Snyk**: IPO uncertain. $3.7B. Reachability expanded Mar 9 (JS/Java/Python). Package Health Check for agentic dev.
- **Endor Labs**: $188M. Autonomous Plane acquisition (Feb 11). 6 OpenClaw zero-days. RSA 2026 exhibitor.
- **Checkmarx**: Sale stalled ~$1.5B. AWS Kiro IDE integration (90% rework reduction claim). Tromzo agents launching as Checkmarx Assist.
- **Semgrep**: $100M Series D. RSA 2026 Booth #1743. AI Detection product. 18K orgs, 75M scans, 740K autofixes, 95% agreement.
- **CrowdStrike**: FalconID GA (phishing-resistant MFA, FIDO2). SGNL ($740M) + Seraphic ($420M). Fal.Con Gov Mar 18. 27-sec breakout.
- **Orca Security**: Lost patent battle vs Wiz (PTAB invalidated 3/6 patents). Mindshare declining 4.0%→2.6%. Settlement Jan 2026.
- **ArmorCode**: MCP Server validates V7. Anya agentic AI GA. 320+ integrations. Endor Labs integration.
- **Cyera**: $9B valuation. DSPM category (different market).

### Market Metrics
- Cybersecurity VC 2025: $13.97B (+47% YoY)
- M&A 2025: $84B+, 426 deals. Jan 2026: 34-38 deals (~477/year pace)
- CISA KEV 2026 pace: 45 in Jan-Feb (~270/year). 1,529 total entries.
- EPSS: 317,858 CVEs. 1,339 >90% exploitation probability.
- RSA 2026: Mar 23-26, Moscone SF. Ardern, Horowitz, Savage keynotes.
- NIST CAISI: Agentic AI security RFI deadline Mar 9.

### Positioning Insights (Ordered by Urgency)
1. "Your security AI shouldn't be one executive order away from shutdown." — geopolitical resilience [NEW]
2. "Claude finds. ALdeci decides." — decision layer above scanners
3. "Google bought your security vendor." — Switzerland peak (Wiz mid-March)
4. "3 models voting beats 1 model guessing." — validated by Pentagon crisis + market share shifts
5. "The only security platform that works when the internet doesn't" — vLLM air-gap (P1 urgency)
6. "27 seconds to breach." — speed urgency (CrowdStrike data)
7. "NIST says secure your AI agents. We already do." — regulatory positioning
8. "97% noise reduction across ALL scanners" vs. Endor Labs SCA-only

### API Patterns
- NVD API: Weekend gaps normal (0 critical CVEs Mar 1-2). Filter by pubStartDate.
- CISA KEV: Old CVEs being retroactively added (2008, 2020, 2021 CVEs in 2026).
- EPSS API: `order=!epss` for highest. New CVEs have very low EPSS (too new for exploitation data).
- HackerNews: Top stories reliably have security/AI content. 18/60 relevant on typical day.

### Technology Research
- **vLLM**: v0.16.0. P1 priority (was P2). Most mature production ecosystem.
- **SGLang**: 400K+ GPU deployments globally. "De facto standard." 16,200 TPS. Evaluate Sprint 4.
- **Trend Micro cybersecurity LLM**: Open-weight Llama 3. Evaluate for AutoFix.
- **WebMCP**: Chrome early preview. Browser-native MCP integration.
- Tree-sitter SAST: DEFER to Sprint 3. LiteLLM: DEPRIORITIZED. ChromaDB RAG: Sprint 4+.

### DEMO-010 Knowledge
- KnowledgeGraphEngine: NetworkX in-memory. Singleton for state persistence.
- Seed demo: 73 nodes, 110 edges, 10+ attack paths. 75/75 tests passing.
- Blast radius from Log4Shell: 41 affected nodes, 9.1x risk multiplier.
