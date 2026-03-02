# Competitive Battlecard: ALdeci vs. Wiz

**Updated**: 2026-03-02 | **Source**: AI Researcher Pulse (Mar 2) + Codebase Verification
**Pillars**: [V3] Decision Intelligence, [V7] MCP-Native

---

## Wiz Profile
- **Category**: CNAPP (Cloud-Native Application Protection Platform)
- **Funding**: $1.9B+ raised
- **Valuation**: $32B (Google/Alphabet acquisition price)
- **ARR**: $500M+ (estimated)
- **Status**: Google acquisition closing March 2026. EU unconditionally approved (Feb 10). DOJ cleared (Nov 2025).
- **Dazz acquisition ($450M, Nov 2024)**: Fully integrated into Wiz Code — risk remediation from cloud to code. Now ingesting vulns from external sources (Checkmarx initial partner).
- **MCP**: Has MCP integration with Gemini Code Assist — competing on V7 territory.

## What Wiz Does
- Agentless cloud scanning (AWS, Azure, GCP)
- CSPM (Cloud Security Posture Management)
- DSPM (Data Security Posture Management)
- CDR (Cloud Detection & Response)
- Wiz Code — code scanning with MCP integration (Gemini Code Assist)
- Container security, CIEM, runtime protection

## Where Wiz Is Weak
1. **Google lock-in imminent**: Once acquired, Wiz becomes a Google product. Enterprises on AWS/Azure face vendor conflict of interest.
2. **Cloud-only**: No AppSec decision intelligence. Cloud workload scanning, not application-level CTEM.
3. **No multi-LLM consensus**: Single AI model (likely Gemini post-acquisition). No independent model voting.
4. **No exploit verification**: Agentless scanning = detection only. No MPTE-style proof of exploitability.
5. **No air-gapped deployment**: Cloud-native architecture requires internet connectivity.
6. **No AutoFix**: Detection and prioritization only. No automated code remediation.
7. **No compliance evidence bundles**: Generates reports, not cryptographically signed evidence.

## ALdeci Advantage
| Dimension | Wiz | ALdeci |
|-----------|-----|--------|
| Vendor independence | Google-owned (March 2026) | Independent, scanner-neutral |
| Focus | Cloud workloads | Application security (full lifecycle) |
| Decision intelligence | None | 12-step Brain Pipeline |
| Exploit verification | None (agentless) | 19-phase MPTE |
| Auto-remediation | None | 10 fix types, confidence-based |
| Air-gapped | No | Yes, full capability |
| MCP tools | Gemini Code Assist only | 796 auto-discovered (any LLM) |
| Scanner integration | Own scanners | 25+ formats + 8 native |

## Talking Points

**When prospect asks "Why not Wiz?":**
> "Wiz is excellent at cloud workload scanning. But it's about to become a Google product. If you're running AWS or Azure, your cloud security platform will be owned by a competitor. ALdeci is scanner-neutral — we integrate with Wiz and every other tool. We're the Switzerland of AppSec."

**When prospect is a Wiz customer:**
> "Keep Wiz for cloud scanning — we actually have a native Wiz connector (one of our 10 security tool connectors). But your application security needs a decision layer that's independent of any cloud vendor. ALdeci sits above Wiz and correlates its findings with your SAST, DAST, SCA, and container results."

**On the Google acquisition:**
> "When Google bought Wiz for $32B, it validated cloud security as a critical category. But it also created the biggest 'Switzerland opportunity' in security history. Every enterprise on AWS and Azure is now rethinking their Wiz dependency. ALdeci is vendor-neutral by design — we work with all clouds, all scanners, no lock-in."
