# AI Researcher Agent Memory

## Key Market Intelligence (Updated 2026-03-02, Pass 5 FINAL)

### 🔴 CRITICAL: Claude Weaponized in Mexican Govt Attack (NEW — Pass 5)
- Hacker used 1,000+ Claude Code prompts + GPT-4.1 to breach **10 Mexican government agencies + 1 financial institution**
- Started December 2025, discovered March 2026
- Kali Linux now integrating Claude AI via MCP for automated pen testing
- ALdeci messaging: "AI agents are the new attack surface. We test them." + "Claude finds. ALdeci decides. And prevents weaponization."
- Validates MPTE for AI-assisted attack chain testing and LLM Monitor scanner
- Sources: SecurityWeek, Security Boulevard

### 🔴 CRITICAL: Anthropic-Pentagon — Legal Battle (Feb 27-28, 2026)
- Pentagon blacklisted Anthropic as "supply chain risk" — Amodei refused surveillance/weapons guardrails removal
- Anthropic suing Pentagon (Feb 28) — "legally unsound," "dangerous precedent." Bloomberg confirms filing.
- Claude #1 on US App Store. All-time record signups. Free +60%, paid subs 2x
- Chinese labs (DeepSeek, Moonshot AI, MiniMax): 24,000+ fraudulent accounts, 16M+ interactions
- Court outcome shapes AI governance. vLLM = P1 priority.

### 🔴 CRITICAL: MCP Security Crisis
- 30 CVEs in MCP ecosystem in ~15 months. Auth optional, encryption not required.
- 70% of orgs have MCP packages (Tenable), 86% contain critical vulns
- Microsoft MarkItDown MCP: severe SSRF (AWS key theft)
- ALdeci differentiator: "One-third of MCP servers are vulnerable. Ours isn't."

### Competitor Landscape (Updated Pass 5)
- **Wiz**: Google $32B closing **MID-MARCH 2026**. Staff getting $2-2.5B. $3M closing party. Switzerland PEAK.
- **Snyk**: **$8.5B valuation** (CORRECTED from $3.7B). ARR $343M (+12%). IPO dimming. DeepCode AI focus.
- **Endor Labs**: $188M. Autonomous Plane. AI agents for PR review. RSA 2026.
- **Checkmarx**: Sale stalled ~$1.5B. Returning to M&A mode. 7th Gartner MQ leader. $150M+ ARR.
- **Semgrep**: **Managed Scans GA**. PHP Reachability (11th lang). First-time Gartner MQ. RSA Booth #1743.
- **CrowdStrike**: **Q4 earnings March 3**. SGNL($740M)+Seraphic($420M)+Pangea+Onum acquired. $1.16B in Jan alone.
- **Orca Security**: **Forrester Strong Performer CNAPP Q1 2026**. Hybrid cloud pivot. Mindshare 4.0%→2.6%.
- **ArmorCode**: MCP Server. Anya AI 80% MTTR reduction. 320+ integrations.
- **Cyera**: $9B. DSPM (different market).

### Market Metrics
- VC 2025: $13.97B (+47%). Total $18-21B across 820 deals.
- M&A 2025: $84B+, 426 deals. Jan 2026: 34-38 (~477/year pace).
- CISA KEV: 1,529 total. 2026 pace: ~270/year.
- EPSS: 317,858 CVEs. **7,079 >50% exploitation probability**.
- Top EPSS: CVE-2025-64446 (89%), CVE-2026-24061 (78% — highest 2026 CVE).
- Gartner CTEM: "3x less likely to suffer breach"
- Shadow AI: 47% personal accounts, data violations doubled (Netskope).
- n8n CVE-2026-21858: CVSS 10.0, ~100K servers.

### Positioning Insights (Top 10)
1. "Your security AI shouldn't be one executive order away from shutdown." [V3][V9]
2. "AI agents are the new attack surface. We test them." [V5] — Claude weaponized
3. "Claude finds. ALdeci decides." [V3]
4. "Google bought your security vendor." [V3] — Wiz mid-March
5. "3 models voting beats 1 model guessing." [V3]
6. "70% of orgs have MCP packages with critical vulns. We secure them." [V7] — Tenable
7. "Gartner says CTEM = 3x fewer breaches. We're CTEM+." [V3][V10]
8. "The only security platform that works when the internet doesn't." [V9]
9. "27 seconds to breach." [V5]
10. "NIST says secure your AI agents. We already do." [V5][V7]

### API Patterns
- NVD API: 3 critical CVEs found for Mar 1-2 (corrected from "0" in Pass 3). Use pubStartDate filter.
- CISA KEV: Old CVEs retroactively added. Catalog version date in JSON.
- EPSS API: `order=!epss` for highest. Use `epss[gt]=0.5` for >50% exploitation. Newest CVEs have very low EPSS.
- HackerNews: 15-17/40 relevant on typical day. Score >300 is high-interest.

### Technology Research
- **vLLM**: v0.16.0. P1. WebSocket Realtime API. Best hardware flexibility (AMD+NVIDIA).
- **SGLang**: v0.5.8. RadixAttention: 5x faster for agent workflows. 400K+ GPUs. Sprint 4.
- **Trend Micro cybersec LLM**: Open-weight Llama 3. Evaluate for AutoFix.
- **Logira**: eBPF runtime auditing for AI agents (HN 20pts). Monitor agentic AI at OS level.
- Tree-sitter: Sprint 3. LiteLLM: DEPRIORITIZED. ChromaDB RAG: Sprint 4+.

### Upcoming Events
- Mar 3: CrowdStrike Q4 earnings
- Mar 9: NIST CAISI agentic AI RFI deadline
- Mar 15: Microsoft PAT deprecation
- Mar 18: Fal.Con Gov 2026 (DC)
- Mar 23-26: RSA 2026 (Moscone SF)
- Mar 24: CrowdStrike/AWS/NVIDIA startup pitch
- Mid-March: Wiz-Google close

### DEMO-010 Knowledge
- KnowledgeGraphEngine: NetworkX in-memory. Singleton.
- Seed demo: 73 nodes, 110 edges, 10+ attack paths. 75/75 tests.
- Blast radius from Log4Shell: 41 affected nodes, 9.1x risk multiplier.
