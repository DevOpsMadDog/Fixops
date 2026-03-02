# Competitive Battlecard: ALdeci vs. Checkmarx

**Updated**: 2026-03-02 | **Source**: AI Researcher Pulse (Mar 2) + Codebase Verification
**Pillars**: [V3] Decision Intelligence, [V5] MPTE

---

## Checkmarx Profile
- **Category**: Enterprise AST (Application Security Testing)
- **Funding**: PE-backed (Hellman & Friedman, $1.15B acquisition in 2020)
- **Valuation**: $1.5-2.5B (reportedly for sale, process stalled)
- **ARR**: $150M+ (Checkmarx One platform)
- **Status**: 7x Gartner Magic Quadrant Leader for AST. Acquired Tromzo (Dec 2025) for AI agents. 75% on cloud-native platform. Sale process unclear.

## What Checkmarx Does
- SAST, DAST, SCA, IaC scanning (Checkmarx One)
- Checkmarx Assist — AI agents via Tromzo acquisition (early 2026 launch)
- Supply chain security
- API security testing
- 7x Gartner Leader — strong enterprise brand

## Where Checkmarx Is Weak
1. **Just acquired AI agents**: Tromzo deal closed Dec 2025. Integration is early-stage — not proven at scale.
2. **No multi-model consensus**: Tromzo uses single-model AI agents.
3. **No exploit verification**: Detects and prioritizes, never proves exploitability.
4. **Expensive and slow**: Enterprise AST is legacy pricing. $250K+ deals, long sales cycles.
5. **For sale**: H&F has been trying to sell. Uncertainty about long-term investment and roadmap.
6. **No chaos engineering**: No FAIL Engine equivalent.
7. **No quantum-secure evidence**: Standard compliance reports.

## ALdeci Advantage
| Dimension | Checkmarx | ALdeci |
|-----------|-----------|--------|
| AI agents | Tromzo (just acquired, early 2026 launch) | Brain Pipeline + AutoFix (shipping, 12 steps) |
| AI models | Single model (Tromzo) | 3+ models (85% consensus) |
| Exploit verification | None | 19-phase MPTE |
| Scanner neutrality | Own scanners only | 25+ formats + 8 native |
| Air-gapped | Partial | Full |
| Pricing | $250K+ enterprise | $36-180K/year (per-app) |
| MCP | None | 796 auto-discovered tools |
| Company stability | For sale | Growing startup |

## Talking Points

**When prospect asks "Why not Checkmarx?":**
> "Checkmarx is the enterprise incumbent — 7x Gartner Leader. They just acquired Tromzo for AI agent capabilities. We already ship what Tromzo promises: a 12-step Brain Pipeline with multi-AI consensus, 10-type AutoFix, and MPTE exploit verification. They're integrating an acquisition; we're shipping production code — 372K+ LOC, 796 API endpoints. GovInfoSecurity names Checkmarx as directly threatened by Claude Code Security — the market is shifting to AI-native."

**On the Tromzo acquisition:**
> "Checkmarx buying Tromzo validates AI-native security agents as a category. That's good for us — it proves the market exists. The difference: they acquired a startup and are now integrating it. We built the capability natively into our CTEM pipeline from day one."

**On Checkmarx's enterprise brand:**
> "Checkmarx has earned their Gartner position. But the market is shifting from 'test everything' to 'decide and act.' Their strength is scanning breadth; ours is decision intelligence. We can sit on top of Checkmarx and make their findings actionable — or replace the scanning layer entirely in air-gapped environments."
