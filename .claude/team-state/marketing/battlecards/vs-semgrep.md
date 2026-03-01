# Competitive Battlecard: ALdeci vs. Semgrep

**Updated**: 2026-03-01 | **Source**: AI Researcher Pulse + Codebase Verification
**Pillars**: [V3] Decision Intelligence, [V5] MPTE

---

## Semgrep Profile
- **Category**: SAST + AI-Assisted Triage
- **Funding**: $100M+ raised
- **Valuation**: Unknown (private)
- **Metrics**: 18K orgs, 75M scans, 5.3M AI triage decisions (95% agreement rate), 740K auto-fixed vulns
- **Status**: Growing. "Semgrep Secure 2026" event (Feb 25). Claims "first multimodal AppSec engine." Partnership with Palo Alto Networks. StackHawk DAST integration.

## What Semgrep Does
- Rule-based SAST (open-source and commercial)
- "Multimodal AppSec engine" — SAST + single LLM reasoning (announced Feb 25, 2026)
- AI triage with "95% agreement rate" (single model)
- AI-assisted auto-fix (code patches)
- StackHawk integration for SAST+DAST correlation
- Claims "zero false positives" with multimodal engine

## Where Semgrep Is Weak
1. **Single-model AI**: "95% agreement rate" is one model's self-consistency — not multi-model consensus. Systematic biases go undetected.
2. **SAST-only scope**: Core strength is static analysis. DAST is a partnership (StackHawk), not native.
3. **No exploit verification**: Confidence scores are estimates, not proof of exploitability.
4. **No CTEM lifecycle**: Scanner + triage, not a complete threat exposure management pipeline.
5. **No knowledge graph**: Each finding is analyzed independently. No cross-finding correlation or blast radius analysis.
6. **No compliance evidence**: No cryptographic signing, no evidence bundles.
7. **Limited remediation**: Auto-fix for code patches only (~1 type vs. our 10).

## ALdeci Advantage
| Dimension | Semgrep | ALdeci |
|-----------|---------|--------|
| AI approach | 1 model ("95% agreement") | 3+ models (85% consensus threshold) |
| Scope | SAST (+DAST via partnership) | Full CTEM (8 scanners + 25 parsers) |
| Exploit verification | None (confidence scores) | 19-phase MPTE (proof) |
| Knowledge graph | None | FalkorDB with attack paths & blast radius |
| Auto-fix types | ~1 (code patches) | 10 types (code, deps, config, IaC, secrets, etc.) |
| Air-gapped | Partial (rules work offline) | Full (all scanners + AI) |
| Compliance evidence | None | Quantum-secure signed bundles |
| Chaos engineering | None | FAIL Engine |

## Talking Points

**When prospect asks "Why not Semgrep?":**
> "Semgrep is the best open-source SAST engine. We actually ingest Semgrep output natively (SemgrepNormalizer in our parser library). The difference: Semgrep uses one model for triage. We use three models with a consensus threshold. When those models disagree, it's often a signal that the finding is genuinely ambiguous — and we route it to MPTE for exploit verification instead of guessing."

**On their "95% agreement rate":**
> "95% agreement rate sounds impressive — but it's one model agreeing with itself. Our approach uses three independent models and requires 85% consensus. When GPT-4 says 'critical' and Claude says 'medium,' that disagreement is valuable information. Single-model systems can't detect their own blind spots."

**On their "zero false positives" claim:**
> "Zero false positives in SAST is a strong claim. We take it further — we don't just classify; we verify. MPTE proves exploitability through controlled exploitation. Even if the AI says it's a false positive, the pentester confirms. Evidence, not estimates."
