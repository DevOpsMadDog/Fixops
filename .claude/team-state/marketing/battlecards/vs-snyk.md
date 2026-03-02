# Competitive Battlecard: ALdeci vs. Snyk

**Updated**: 2026-03-02 | **Source**: AI Researcher Pulse (Mar 2) + Codebase Verification
**Pillars**: [V3] Decision Intelligence, [V5] MPTE

---

## Snyk Profile
- **Category**: SCA + SAST (expanding to "developer security platform")
- **Funding**: $1.3B+ raised
- **Valuation**: $3.7B (down from $8.5B peak — BlackRock markdown)
- **ARR**: $300-340M (estimated)
- **Status**: IPO uncertain. Growth decelerated to ~12% in Q2 2025. Exploring PE deals with 3+ firms.
- **NEW (Feb 2026)**: Ruby 4.0 support for Snyk Code; Package Health Check for Snyk Studio.
- **Claude Code Security response**: Published positive blog post framing it as "great news for the industry" — classic "embrace" PR strategy to avoid looking threatened.

## What Snyk Does
- SCA (Software Composition Analysis) — dependency vulnerability detection
- SAST (Snyk Code) — IDE-integrated static analysis
- Snyk Container — container image scanning
- Snyk IaC — infrastructure-as-code scanning
- Snyk Studio — agentic developer platform (new)
- Package Health Check — dependency quality scoring (new, Feb 2026)

## Where Snyk Is Weak
1. **No decision layer**: Finds vulnerabilities but doesn't decide what to do. The analyst still triages.
2. **Single-model AI**: Snyk DeepCode uses one AI model for triage. No multi-model consensus.
3. **No exploit verification**: Detects but never proves exploitability. All findings are theoretical.
4. **No CTEM lifecycle**: Scanner + dashboard, not a complete threat exposure management loop.
5. **No air-gapped mode**: Requires cloud connectivity for AI features and vulnerability database.
6. **Limited fix types**: Auto-fix covers dependency updates and some code fixes (~2 types vs. our 10).
7. **No compliance evidence**: No cryptographic signing, no evidence bundles, no audit-ready output.
8. **Claude Code Security "embrace"**: Snyk is positioning Claude as complementary — but Claude can cannibalize Snyk Code (SAST). ALdeci benefits either way because we sit ABOVE both.

## ALdeci Advantage
| Dimension | Snyk | ALdeci |
|-----------|------|--------|
| Decision intelligence | None | 12-step Brain Pipeline (1,354 LOC) |
| AI models | 1 (DeepCode) | 3+ (multi-LLM consensus, 85% threshold) |
| Exploit verification | None | 19-phase MPTE (2,054 LOC) |
| Auto-fix types | ~2 | 10 (1,418 LOC) |
| Scanner formats ingested | Own scanners only | 25+ third-party + 8 native |
| Air-gapped | No | Yes, full capability |
| Compliance evidence | Basic reports | Quantum-secure signed evidence bundles (1,248 LOC) |
| Chaos engineering | None | FAIL Engine (713 LOC) |
| MCP tools | None | 796 auto-discovered |
| Claude integration | Blog post | Ingestion pipeline for Claude findings |

## Talking Points

**When prospect asks "Why not Snyk?":**
> "Snyk finds vulnerable dependencies — and they're excellent at it. We actually use Snyk as one of our 25+ input sources. The question is: what happens after Snyk finds 3,000 dependency vulnerabilities? Someone has to decide which ones matter, verify which ones are exploitable, fix them, and prove to auditors that it was handled. That's what ALdeci does. We don't replace Snyk — we make it intelligent."

**When prospect is a Snyk customer:**
> "Keep Snyk. We ingest Snyk output natively (SnykNormalizer in our parser library). Add ALdeci on top and you go from 'here are your vulnerabilities' to 'here are the 10 that are actually exploitable, here are the auto-generated fixes, and here's the signed evidence for your auditor.'"

**On Snyk's declining valuation:**
> (Use carefully, only if prospect raises it) "The SCA/SAST market is commoditizing — Claude Code Security just proved a single LLM can find vulnerabilities traditional SAST tools miss. Snyk's growth decelerated from 100%+ to 12%. The value is moving upstream — from detection to decision intelligence. That's where ALdeci lives."

**On Claude Code Security:**
> "Snyk published a blog calling Claude Code Security 'great news.' That's PR spin — Claude can replace Snyk Code for SAST. ALdeci sits above both: Claude finds, Snyk finds, ALdeci decides what to DO about it."
