# AI Researcher Agent Memory

## Key Market Intelligence (Updated 2026-03-03, Day 3)

### 🔴 CRITICAL: Claude Code Security Launch (Feb 20, 2026)
- Anthropic launched AI-powered vulnerability scanning in Claude Code
- Found 500+ bugs in production open-source code — undetected for decades
- Multi-stage verification, reasoning-based (not pattern matching), uses Opus 4.6
- Cybersecurity stocks plunged on announcement. Snyk responded publicly.
- ALdeci position: "Claude finds. ALdeci decides." — integrate as 9th scanner input in Sprint 3
- Sources: TheHackerNews, VentureBeat, The Register

### 🔴 CRITICAL: Claude Weaponized in Mexican Govt Attack
- 1,000+ Claude Code prompts + GPT-4.1 → 10 Mexican govt agencies + 1 financial institution breached
- 150GB stolen incl. 195M taxpayer records. Started Dec 2025, discovered Mar 2026.
- AI-enhanced attacks +72% YoY. 87% of orgs experienced AI-driven incidents.
- ALdeci: "AI agents are the new attack surface. We test them." Validates MPTE + LLM Monitor.

### 🔴 CRITICAL: MCP Security Crisis Deepening
- Tenable: 70% of orgs have MCP packages, 86% contain critical vulns
- JFrog: CVE-2025-6514 in mcp-remote (437K downloads, command injection, supply chain backdoor)
- Unit42: New MCP sampling attacks — resource theft, conversation hijacking, covert tool invocation
- Protocol design flaws: session IDs in URLs, no required auth, no message signing
- WebMCP in Chrome early preview (340pts HN) — MCP going browser-native

### Competitor Landscape (Updated 2026-03-03)
- **Wiz**: Google $32B closing **MID-MARCH**. EU cleared unconditionally Feb 10. Staff $2-2.5B. Switzerland PEAK.
- **Snyk**: $8.5B. **AI Security Fabric** (Feb 3): Delta Findings + Agent Fix + Evo agentic. 288% ROI (Forrester). IPO dimming.
- **CrowdStrike**: Q4 FY26 earnings **TODAY Mar 3**. Expected $1.30B rev (+22.6%), $4.92B ARR (+23%), EPS $1.10. $1.16B acquisitions Jan.
- **ArmorCode**: **MCP Server** for LLM querying (MEDIUM-HIGH threat). Anya Code Insights. 80% MTTR reduction. 40B+ findings. 320+ integrations.
- **Semgrep**: Managed Scans 1M+/week. 96% researcher agreement. Gartner MQ. RSA Booth #1743.
- **Endor Labs**: OpenClaw 6 vulns disclosed. Rising in Cyber (CISOs+VCs). $188M.
- **Checkmarx**: Sale stalled ~$1.5B. 7th Gartner MQ. $150M+ ARR. Mindshare 1.7%.
- **Orca Security**: Forrester Strong Performer CNAPP. Mindshare declining 4.0%→2.6%.
- **Cyera**: $9B. DSPM (different market).

### Market Metrics
- VC 2025: $13.97B (+47%). Early-stage: $7.5B at A/B (+63%). AI+security highest conviction.
- M&A 2025: $84B+, 426 deals. CrowdStrike $1.16B in Jan 2026 alone.
- CISA KEV: 1,529 total. 2026 pace: ~270/year.
- EPSS: 7,073 CVEs >50% exploitation. Top: CVE-2025-8943 (81.6%), CVE-2026-24061 (77.9%).
- NEW EPSS: CVE-2026-27180 (61.8%), CVE-2026-27174 (60.3%) — first appearance Mar 3.
- NVD critical Mar 1-3: 3 CVEs (CVE-2026-2999/3000 IDExpert RCE, CVE-2026-3422 U-Office deser.)
- Funding: Vega $120M Series B, Noma Security $100M Series B, Irregular $80M Series A.

### Positioning Insights (Top 10)
1. "Your security AI shouldn't be one executive order away from shutdown." [V3][V9]
2. "AI agents are the new attack surface. We test them." [V5]
3. "Claude finds. ALdeci decides." [V3] — Claude Code Security launch
4. "Google bought your security vendor." [V3] — Wiz mid-March
5. "3 models voting beats 1 model guessing." [V3]
6. "70% of orgs have MCP packages with critical vulns. We secure them." [V7]
7. "Gartner says CTEM = 3x fewer breaches. We're CTEM+." [V3][V10]
8. "The only security platform that works when the internet doesn't." [V9]
9. "705 AI-consumable security tools. ArmorCode has 1." [V7] — NEW
10. "87% of orgs experienced AI-driven attacks. We simulate all of them." [V5] — NEW

### API Patterns
- NVD API: Use pubStartDate/pubEndDate for date range. 3 critical CVEs for Mar 1-3 confirmed.
- CISA KEV: Latest additions often retroactive (old CVEs). Catalog version date in JSON.
- EPSS API: `order=!epss` for highest. `epss-gt=0.5` for >50%. Newest CVEs have very low EPSS initially.
- HackerNews: 11/40 relevant on Mar 3 (27.5% rate). Score >300 = high-interest.

### Technology Research
- **vLLM**: v0.16.0 (Feb 8). 30.8% throughput improvement. WebSocket Realtime API. AMD+NVIDIA+Ascend NPU. P1 Sprint 3.
- **SGLang**: v0.5.8. 400K+ GPUs. RadixAttention 5x for agents. Sprint 4.
- **llmfit**: HN 224pts — right-sizes LLM models to RAM/CPU/GPU. Useful for V9 air-gapped sizing.
- Tree-sitter: Sprint 3. ChromaDB RAG: Sprint 4+.

### Upcoming Events
- **Mar 3**: CrowdStrike Q4 earnings (TODAY)
- Mar 6: **ALdeci Enterprise Demo**
- Mar 9: NIST CAISI agentic AI RFI deadline
- Mar 15: Microsoft PAT deprecation
- Mar 18: Fal.Con Gov 2026 (DC)
- Mar 20: RSA 2026 registration close
- Mar 23-26: RSA 2026 (Moscone SF) — Innovation Sandbox Top 10
- Mar 24: CrowdStrike/AWS/NVIDIA startup pitch
- Mid-March: Wiz-Google close

### DEMO-010 Knowledge
- KnowledgeGraphEngine: NetworkX in-memory. Singleton.
- Seed demo: 73 nodes, 110 edges, 10+ attack paths. 75/75 tests.
- Blast radius from Log4Shell: 41 affected nodes, 9.1x risk multiplier.
