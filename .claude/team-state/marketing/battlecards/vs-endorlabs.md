# Competitive Battlecard: ALdeci vs. Endor Labs

**Updated**: 2026-03-01 | **Source**: AI Researcher Pulse + Codebase Verification
**Pillars**: [V3] Decision Intelligence, [V5] MPTE

---

## Endor Labs Profile
- **Category**: SCA + OSS Security
- **Funding**: $188M total ($93M Series B, Apr 2025)
- **Valuation**: Unknown (private)
- **Growth**: 30x ARR growth, 166% NRR
- **Status**: Acquired Autonomous Plane (DockerSlim creator, Feb 2026). Strong growth. Claims "97% noise reduction." Citi Ventures backed.

## What Endor Labs Does
- SCA with reachability analysis (dependency vulnerability filtering)
- Container security (via Autonomous Plane acquisition)
- Supply chain security
- "97% noise reduction" via reachability analysis
- License compliance

## Where Endor Labs Is Weak
1. **SCA-only noise reduction**: Their 97% claim applies to dependency vulnerabilities only — reachability analysis doesn't work for SAST, DAST, secrets, IaC, or cloud findings.
2. **No AI decision engine**: Rules-based reachability, not AI-powered triage.
3. **No exploit verification**: Static reachability analysis ≠ proof of exploitability.
4. **No remediation engine**: Flags what to fix but doesn't generate fixes.
5. **No compliance evidence**: No cryptographic signing or evidence bundles.
6. **No air-gapped mode**: Cloud-native SaaS.
7. **SCA scope**: Expanding into containers (Autonomous Plane) but still focused on dependency management.

## ALdeci Advantage
| Dimension | Endor Labs | ALdeci |
|-----------|-----------|--------|
| Noise reduction | 97% (SCA-only) | 97% (all scanner types) |
| Method | Static reachability | Multi-AI consensus + MPTE verification |
| Scope | SCA + containers | Full CTEM (8 scanners + 25 parsers) |
| AI models | None (rules-based) | 3+ models (85% consensus) |
| Exploit verification | None | 19-phase MPTE |
| Auto-fix | None | 10 fix types |
| Air-gapped | No | Yes |
| Evidence | None | Quantum-secure signed bundles |

## Talking Points

**When prospect asks "Why not Endor Labs?":**
> "Endor Labs does excellent SCA reachability analysis — 97% noise reduction for dependency vulnerabilities. We achieve the same 97% noise reduction, but across ALL scanner types: SAST, DAST, secrets, containers, IaC, APIs, and cloud findings. Our method combines multi-AI consensus with MPTE exploit verification. Reachability tells you a function is called. MPTE tells you it's exploitable."

**On their "97% noise reduction" claim (messaging collision):**
> "Same number, different scope. Endor Labs reduces noise from dependency vulnerabilities using reachability analysis — excellent for SCA. ALdeci reduces noise from 11,300+ findings across your entire scanner fleet using a 12-step Brain Pipeline with multi-AI consensus. One is a scalpel for dependencies; the other is a decision engine for your entire security posture."

**On their growth metrics:**
> "30x ARR growth and 166% NRR are impressive for SCA. The market is moving toward complete CTEM — Gartner says CTEM adopters see 3x fewer breaches. ALdeci delivers the full CTEM lifecycle; Endor Labs delivers one step (SCA detection + filtering)."
