# AI Researcher Agent Memory

## Key Market Intelligence (Updated 2026-03-02)

### CRITICAL: Claude Code Security (Feb 20, 2026)
- Anthropic launched Claude Code Security — found 500+ zero-days in production OSS code
- Cyber stocks dropped (Bloomberg). Veracode, Checkmarx, Snyk, Black Duck threatened.
- ALdeci positioning: COMPLEMENTARY — "Claude finds. ALdeci decides."
- Integration play: Claude findings -> brain pipeline -> MPTE -> AutoFix -> evidence
- Snyk published "embrace" blog post — classic PR strategy
- Available as limited research preview for Enterprise/Team customers

### Competitor Landscape
- **Wiz**: Google acquisition $32B closing END OF MARCH 2026. Switzerland moment NOW. Dazz ($450M) integrated into Wiz Code. MCP integration with Gemini Code Assist.
- **Snyk**: IPO uncertain — growth ~12%, valuation $3.7B. ARR ~$300-340M. Ruby 4.0 + Package Health Check. Embracing Claude Code Security.
- **Endor Labs**: $188M funded, acquired Autonomous Plane (Feb 11). 30x ARR growth, 166% NRR. 6 OpenClaw zero-days found. Rising in Cyber. ArmorCode integration.
- **Checkmarx**: Acquired Tromzo (Dec 2025). Sale stalled ~$1.5B. Directly threatened by Claude Code Security. Checkmarx Assist (AI agents) launching.
- **Semgrep**: $100M Series D. "Multimodal AppSec engine" (SAST+LLM). StackHawk DAST integration. 95% single-model rate. Inc. Best AI Implementation.
- **CrowdStrike**: SGNL ($740M) + Seraphic acquisitions. 27-second eCrime breakout. AI adversary ops +89% YoY. Fal.Con Gov (Mar 18, DC).
- **Orca Security**: Forrester Strong Performer. Agentless reachability (90% reduction). $1.8B valuation. Cloud-only.
- **ArmorCode**: Anya agentic AI GA. 320+ integrations, 40B findings. MCP Server — validates V7. Endor Labs integration.
- **Cyera**: $9B valuation (Series F, $400M, Jan 2026). DSPM category (different market).
- **Tenable**: 2026 Cloud/AI Risk Report — "zero-margin AI exposure gap." Predicts automated remediation go-ahead.

### Market Metrics
- Cybersecurity VC 2025: $13.97B across 392 rounds (+47% YoY)
- Cybersecurity M&A 2025: $84B+, 426 deals, 8 >$1B
- 77% of orgs running GenAI in security stacks, 67% using agentic AI
- 92% of security professionals concerned about AI agent risks
- eCrime breakout: 29 min avg, 27 sec fastest (CrowdStrike 2026)
- Gartner CTEM prediction: 3x breach reduction for adopters by 2026
- MCP adoption: 30% of enterprise vendors will launch MCP servers in 2026 (Forrester)
- vLLM v0.16: 793 TPS (19x Ollama), de facto standard for self-hosted inference
- EPSS database: 317,833 CVEs. CISA KEV: 1,529 entries (v2026.02.26)

### Positioning Insights
- "Claude finds. ALdeci decides." — primary messaging against Claude Code Security
- "500 more vulns? You need a brain, not another dashboard." — noise reduction story
- "27 seconds to breach. Can your team triage 500 new vulns that fast?" — urgency
- "Switzerland" — peak value as Wiz goes Google this month
- "97% noise reduction across ALL scanners" vs. Endor Labs SCA-only
- "Multi-model consensus beats single-model" vs. Semgrep's 95%
- "We ship what they just acquired" — vs. Checkmarx/Tromzo
- "The only security platform that works when the internet doesn't" — vLLM air-gap

### API Patterns
- NVD API: Filter by pubStartDate. Weekend publishing gaps are normal (0 on weekends).
- CISA KEV: Sort by dateAdded desc for latest. 1,529 entries as of v2026.02.26.
- EPSS API: `order=!epss` for highest scores. Newest CVEs have very low scores.
- HackerNews: Filter top 60 stories by 30+ security/AI keywords — yields 15-18 items.

### Technology Research
- vLLM v0.16: READY FOR IMPLEMENTATION. deepseek-coder-v2:16b or qwen2.5-coder:32b for AutoFix.
- Tree-sitter AST for SAST: DEFER to Sprint 3. sast_engine.py already 1,577 LOC.
- LiteLLM: DEPRIORITIZED — vLLM has OpenAI-compatible API directly.
- MCP security: Document gateway security for demo.

### DEMO-010 Knowledge
- KnowledgeGraphEngine uses NetworkX in-memory backend (FalkorDB fallback)
- Engine must be singleton for state persistence across requests
- Seed demo: 73 nodes, 110 edges, 10+ attack paths
- Blast radius from Log4Shell: 41 affected nodes, 9.1x risk multiplier
- Top attack path risk score: 9.2 (SQLi -> Payment Processor)
