# AI Researcher Agent Memory

## Key Market Intelligence (Updated 2026-03-01)

### Competitor Landscape
- **Wiz**: Google acquisition $32B closing March 2026. EU approved Feb 10. Creates Switzerland opportunity.
- **Snyk**: IPO uncertain — growth decelerated ~12%, valuation dropped to $3.7B. ARR ~$300-340M. Ruby 4.0 support + Package Health Check (Feb 2026).
- **Endor Labs**: $188M funded, acquired Autonomous Plane (Feb 11, 2026). 30x ARR growth, 166% NRR. 97% noise reduction claim — SCA-only (differentiate from our full-CTEM).
- **Checkmarx**: Acquired Tromzo (Dec 2025) for AI agents. Sale process stalled at ~$1.5B (target was $2.5B). Checkmarx One >$150M ARR. Gartner Leader 7x.
- **Semgrep**: Launched "multimodal AppSec engine" (SAST+LLM). 18K orgs, 740K auto-fixes. 95% single-model agreement rate. Our multi-LLM is superior.
- **CrowdStrike**: SGNL ($740M) + Seraphic (browser security) acquisitions Jan 2026. AI adversary ops up 89% YoY.
- **Orca Security**: Forrester Strong Performer. Agentless reachability analysis (90% vuln reduction claim). $1.8B valuation. Settled with Wiz.
- **ArmorCode**: Anya agentic AI GA. 320+ integrations, 40B findings. MCP Server launched — validates our V7 strategy.
- **Cyera**: $9B valuation (Series F, $400M, Jan 2026). Different market (DSPM). $1.7B total raised.

### Market Metrics
- Cybersecurity VC 2025: $20.7B across 820 deals (52% YoY growth)
- Cybersecurity M&A 2025: $84B+ disclosed, 426 deals
- M&A January 2026: 38 deals (3rd highest monthly count ever)
- Gartner CTEM prediction: 3x breach reduction for adopters by 2026
- MCP adoption: Forrester says 30% of enterprise vendors will launch MCP servers in 2026
- Agentic AI: 100% of security leaders have it on roadmap
- AI adversary ops: 89% YoY increase (CrowdStrike 2026 Threat Report)

### API Patterns
- NVD API: Filter by pubStartDate for recent CVEs. 136 critical CVEs in 10-day window.
- CISA KEV: 1,529 entries as of v2026.02.26. Feed sorted by date added (oldest first).
- EPSS API: use `order=!epss` for highest scores first. 317,833 CVEs in database.
- EPSS data for newest CVEs has very low scores — not useful for "trending" view.
- HackerNews: Filter top 50 stories by security/AI keywords — typically yields 10-14 relevant items.

### Positioning Insights
- "97% noise reduction" differentiate: "across ALL scanner types" vs. Endor Labs' SCA-only
- "Multi-model consensus" vs. Semgrep's single-model 95% rate — frame as "less biased"
- "We ship what they just acquired" — vs. Checkmarx/Tromzo for AI agents
- "Switzerland" post-Wiz: "Your security platform shouldn't be owned by a cloud vendor"
- ArmorCode MCP Server validates V7 — emphasize first-mover with 650+ auto-discovered tools

### DEMO-010 Knowledge
- KnowledgeGraphEngine uses NetworkX in-memory backend (FalkorDB fallback when unavailable)
- Router bugs fixed: ingest_findings return type, private attr access, dataclass serialization
- Engine must be singleton for state persistence across requests
- Seed demo creates: 73 nodes, 110 edges, 10+ attack paths
- Blast radius from Log4Shell: 41 affected nodes, 9.1x risk multiplier
- Top attack path risk score: 9.2 (SQLi → Payment Processor)
